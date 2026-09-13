//! Regimen de funcionamiento y decision de contencion.
//!
//! Dos detalles separan un umbral de juguete de uno que se puede desplegar en
//! una flota:
//!
//! 1. **Histeresis.** Un umbral simple hace oscilar al agente en la frontera:
//!    suelta cache, baja del umbral, la vuelve a llenar, sube, la suelta otra
//!    vez. El bandazo gasta mas CPU que el estado del que se huia. Para subir de
//!    regimen basta cruzar; para bajar hay que caer un margen por debajo.
//! 2. **Confirmacion antes de matar.** Reiniciar el EDR es en si mismo un evento
//!    de seguridad: abre una ventana sin proteccion, y un atacante que sepa
//!    provocar picos de memoria tendria ahi un interruptor para apagar la
//!    vigilancia a voluntad. Una sola muestra sobre el techo no reinicia nada;
//!    hacen falta varias seguidas.

use crate::medida::Uso;
use crate::perfil::Presupuesto;

/// Margen que hay que bajar para volver al regimen anterior, en centesimas.
///
/// Un 12 % es suficiente para que el bandazo no se sostenga y bastante poco
/// como para que el agente recupere capacidad en cuanto el pico pasa de verdad.
pub const HISTERESIS: u64 = 1200;

/// Muestras seguidas sobre el techo antes de dar el proceso por perdido.
pub const MUESTRAS_PARA_REINICIO: u32 = 3;

/// Donde esta el agente respecto de su presupuesto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Regimen {
    /// Por debajo del reposo. Todo lo elastico puede crecer.
    Holgado,
    /// Entre reposo y pico. Trabajo pesado legitimo en curso.
    ///
    /// No se suelta nada todavia: para esto esta el pico. Soltar aqui seria
    /// impedir el escaneo que justifica el pico.
    Presion,
    /// Entre pico y techo. El pico se ha quedado y ya no es transitorio.
    ///
    /// Se suelta lo elastico de forma agresiva y se rechaza trabajo nuevo que
    /// reserve memoria, pero **se sigue detectando**: un EDR que deja de mirar
    /// para ahorrar memoria no esta ahorrando, esta fallando en silencio.
    Contencion,
    /// Sobre el techo. El agente es un riesgo para el host que protege.
    Excedido,
}

impl Regimen {
    /// Nombre estable para logs y metricas.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Regimen::Holgado => "holgado",
            Regimen::Presion => "presion",
            Regimen::Contencion => "contencion",
            Regimen::Excedido => "excedido",
        }
    }

    /// Parte de la cuota **en reposo** que un componente elastico puede retener,
    /// en centesimas.
    ///
    /// [`Regimen::Presion`] es el caso aparte: ahi no se mide contra el reposo
    /// sino contra la cuota de pico, porque presion es trabajo pesado legitimo y
    /// encoger seria impedir el escaneo que justifica el pico. Quien quiera la
    /// cifra final y no el dial que use [`Vigilante::permitido`], que ya elige la
    /// base correcta.
    #[must_use]
    pub fn elastico_permitido(self) -> u64 {
        match self {
            Regimen::Holgado | Regimen::Presion => 100,
            Regimen::Contencion => 25,
            Regimen::Excedido => 0,
        }
    }

    /// Si se admite trabajo nuevo que reserve memoria de forma apreciable.
    ///
    /// Un desempaquetado o una detonacion pueden esperar; la telemetria no.
    #[must_use]
    pub fn admite_trabajo_pesado(self) -> bool {
        matches!(self, Regimen::Holgado | Regimen::Presion)
    }
}

/// Que hacer con el proceso vigilado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Veredicto {
    /// Dentro de lo previsto.
    Seguir,
    /// Sobre el techo, pero aun sin confirmar.
    Vigilar {
        /// Muestras seguidas sobre el techo acumuladas hasta ahora.
        seguidas: u32,
    },
    /// Sobre el techo de forma sostenida: hay que reiniciarlo.
    Reiniciar {
        /// Consumo observado en la ultima muestra, en bytes.
        observado: u64,
        /// Techo que se ha superado, en bytes.
        techo: u64,
    },
}

/// Sigue el consumo de un proceso contra su presupuesto.
///
/// Lo usa el agente sobre si mismo para decidir contencion, y el watchdog sobre
/// el agente para decidir reinicio. Es la misma logica a proposito: que las dos
/// mitades discrepen sobre si hay un problema es peor que cualquiera de las dos
/// decisiones.
#[derive(Debug, Clone)]
pub struct Vigilante {
    presupuesto: Presupuesto,
    regimen: Regimen,
    seguidas: u32,
    muestras: u64,
    maximo: u64,
}

impl Vigilante {
    /// Crea un vigilante para un presupuesto dado.
    #[must_use]
    pub fn nuevo(presupuesto: Presupuesto) -> Self {
        Self {
            presupuesto,
            regimen: Regimen::Holgado,
            seguidas: 0,
            muestras: 0,
            maximo: 0,
        }
    }

    /// El presupuesto que vigila.
    #[must_use]
    pub fn presupuesto(&self) -> Presupuesto {
        self.presupuesto
    }

    /// Regimen actual.
    #[must_use]
    pub fn regimen(&self) -> Regimen {
        self.regimen
    }

    /// Muestras observadas desde el arranque.
    #[must_use]
    pub fn muestras(&self) -> u64 {
        self.muestras
    }

    /// Maximo consumo anonimo observado, en bytes.
    ///
    /// Es el numero que hay que ensenar cuando alguien pregunta cuanto gasta el
    /// agente de verdad: la media esconde justo el pico que decide si cabe.
    #[must_use]
    pub fn maximo(&self) -> u64 {
        self.maximo
    }

    /// Incorpora una medida y devuelve el regimen resultante.
    pub fn observar(&mut self, uso: &Uso) -> Regimen {
        self.observar_bytes(uso.anonima)
    }

    /// Incorpora una medida en bytes y devuelve el regimen resultante.
    pub fn observar_bytes(&mut self, anonima: u64) -> Regimen {
        self.muestras += 1;
        self.maximo = self.maximo.max(anonima);

        let crudo = self.regimen_crudo(anonima);
        // Subir es inmediato: ante un pico real hay que reaccionar en la misma
        // muestra que lo ve. Bajar exige caer por debajo del umbral del regimen
        // actual con margen, que es lo que corta el bandazo en la frontera.
        let sube = crudo > self.regimen;
        let baja = crudo < self.regimen && anonima <= self.umbral_de_salida(self.regimen);
        if sube || baja {
            self.regimen = crudo;
        }

        if anonima > self.presupuesto.techo {
            self.seguidas = self.seguidas.saturating_add(1);
        } else {
            self.seguidas = 0;
        }
        self.regimen
    }

    fn regimen_crudo(&self, anonima: u64) -> Regimen {
        if anonima > self.presupuesto.techo {
            Regimen::Excedido
        } else if anonima > self.presupuesto.pico {
            Regimen::Contencion
        } else if anonima > self.presupuesto.reposo {
            Regimen::Presion
        } else {
            Regimen::Holgado
        }
    }

    /// Umbral por debajo del cual se abandona un regimen, con histeresis.
    fn umbral_de_salida(&self, regimen: Regimen) -> u64 {
        let entrada = match regimen {
            Regimen::Holgado => return 0,
            Regimen::Presion => self.presupuesto.reposo,
            Regimen::Contencion => self.presupuesto.pico,
            Regimen::Excedido => self.presupuesto.techo,
        };
        entrada - (entrada * HISTERESIS / 10_000)
    }

    /// Veredicto para el supervisor.
    #[must_use]
    pub fn veredicto(&self) -> Veredicto {
        if self.seguidas >= MUESTRAS_PARA_REINICIO {
            Veredicto::Reiniciar {
                observado: self.maximo,
                techo: self.presupuesto.techo,
            }
        } else if self.seguidas > 0 {
            Veredicto::Vigilar {
                seguidas: self.seguidas,
            }
        } else {
            Veredicto::Seguir
        }
    }

    /// Bytes que un componente elastico puede retener ahora mismo.
    ///
    /// Es `cuota x elastico_permitido`, y es la unica cifra que un cache deberia
    /// consultar: recoge a la vez el reparto por host y la presion del momento.
    #[must_use]
    pub fn permitido(&self, componente: crate::reparto::Componente) -> u64 {
        if componente.es_fijo() {
            return self.presupuesto.cuota(componente);
        }
        match self.regimen {
            // Trabajo pesado legitimo: crece hasta su cuota de pico.
            Regimen::Presion => self.presupuesto.cuota_en_pico(componente),
            // El resto se mide contra la cuota de reposo. Medirlo contra la de
            // pico dejaria que la contencion permitiese MAS que el reposo —el
            // 25 % de una cuota de pico grande pasa de una cuota de reposo
            // pequena— y la contencion dejaria de contener.
            otro => self.presupuesto.cuota(componente) * otro.elastico_permitido() / 100,
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::reparto::Componente;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    fn vigilante() -> Vigilante {
        Vigilante::nuevo(Presupuesto::para(16 * GIB))
    }

    #[test]
    fn los_cuatro_regimenes_se_alcanzan() {
        let mut v = vigilante();
        let p = v.presupuesto();
        assert_eq!(v.observar_bytes(p.reposo / 2), Regimen::Holgado);
        assert_eq!(v.observar_bytes(p.reposo + 1), Regimen::Presion);
        assert_eq!(v.observar_bytes(p.pico + 1), Regimen::Contencion);
        assert_eq!(v.observar_bytes(p.techo + 1), Regimen::Excedido);
    }

    #[test]
    fn la_histeresis_corta_el_bandazo() {
        let mut v = vigilante();
        let p = v.presupuesto();
        v.observar_bytes(p.pico + 1);
        assert_eq!(v.regimen(), Regimen::Contencion);
        // Justo por debajo del pico no basta: seria volver a llenar para volver
        // a soltar en la siguiente muestra.
        assert_eq!(v.observar_bytes(p.pico - 1), Regimen::Contencion);
        assert_eq!(v.observar_bytes(p.pico * 95 / 100), Regimen::Contencion);
        // Con el margen completo si se baja.
        assert_eq!(v.observar_bytes(p.pico * 85 / 100), Regimen::Presion);
    }

    #[test]
    fn subir_de_regimen_es_inmediato() {
        // La histeresis solo frena la bajada: ante un pico real hay que
        // reaccionar en la misma muestra que lo ve.
        let mut v = vigilante();
        let p = v.presupuesto();
        v.observar_bytes(0);
        assert_eq!(v.observar_bytes(p.techo + 1), Regimen::Excedido);
    }

    #[test]
    fn una_muestra_sobre_el_techo_no_reinicia_el_edr() {
        let mut v = vigilante();
        let p = v.presupuesto();
        v.observar_bytes(p.techo + MIB);
        assert_eq!(v.veredicto(), Veredicto::Vigilar { seguidas: 1 });
        v.observar_bytes(p.techo + MIB);
        assert_eq!(v.veredicto(), Veredicto::Vigilar { seguidas: 2 });
        // Y un respiro borra la cuenta: el pico era transitorio.
        v.observar_bytes(p.reposo);
        assert_eq!(v.veredicto(), Veredicto::Seguir);
    }

    #[test]
    fn una_fuga_sostenida_si_reinicia() {
        let mut v = vigilante();
        let p = v.presupuesto();
        for _ in 0..MUESTRAS_PARA_REINICIO {
            v.observar_bytes(p.techo + 10 * MIB);
        }
        match v.veredicto() {
            Veredicto::Reiniciar { observado, techo } => {
                assert_eq!(techo, p.techo);
                assert_eq!(observado, p.techo + 10 * MIB);
            }
            otro => panic!("se esperaba reinicio, hubo {otro:?}"),
        }
    }

    #[test]
    fn la_contencion_suelta_lo_elastico_pero_no_lo_fijo() {
        let mut v = vigilante();
        let p = v.presupuesto();
        let corpus_holgado = v.permitido(Componente::Corpus);
        let nucleo_holgado = v.permitido(Componente::Nucleo);

        v.observar_bytes(p.pico + 1);
        assert_eq!(v.regimen(), Regimen::Contencion);
        assert!(v.permitido(Componente::Corpus) < corpus_holgado);
        assert_eq!(v.permitido(Componente::Nucleo), nucleo_holgado);
        assert!(!v.regimen().admite_trabajo_pesado());
    }

    #[test]
    fn en_presion_lo_elastico_crece_hasta_su_cuota_de_pico() {
        // Presion es escaneo legitimo: soltar aqui impediria el escaneo que
        // justifica el pico, asi que lo elastico crece en vez de encoger.
        let mut v = vigilante();
        let p = v.presupuesto();
        let en_reposo = v.permitido(Componente::Yara);
        v.observar_bytes(p.reposo + 1);
        assert_eq!(v.regimen(), Regimen::Presion);
        assert!(v.permitido(Componente::Yara) > en_reposo);
        assert!(v.regimen().admite_trabajo_pesado());
    }

    #[test]
    fn excedido_no_deja_nada_elastico() {
        let mut v = vigilante();
        let p = v.presupuesto();
        v.observar_bytes(p.techo + 1);
        assert_eq!(v.permitido(Componente::Corpus), 0);
        assert_eq!(v.permitido(Componente::Yara), 0);
        // Pero el nucleo sigue: dejar de detectar para ahorrar memoria es
        // fallar en silencio, no ahorrar.
        assert!(v.permitido(Componente::Nucleo) > 0);
    }

    #[test]
    fn contener_siempre_permite_menos_que_estar_holgado() {
        // La invariante que se salto el primer diseno: escalaba la cuota de
        // pico, y el 25 % de una cuota de pico grande pasa de la cuota de
        // reposo entera. La contencion permitia mas que el reposo.
        for memoria in [GIB, 4 * GIB, 16 * GIB, 64 * GIB, 768 * GIB] {
            let p = Presupuesto::para(memoria);
            for c in [Componente::Yara, Componente::Red, Componente::Corpus] {
                let mut v = Vigilante::nuevo(p);
                v.observar_bytes(0);
                let holgado = v.permitido(c);
                v.observar_bytes(p.reposo + 1);
                let presion = v.permitido(c);
                v.observar_bytes(p.pico + 1);
                let contencion = v.permitido(c);
                v.observar_bytes(p.techo + 1);
                let excedido = v.permitido(c);

                assert!(
                    excedido <= contencion && contencion <= holgado && holgado <= presion,
                    "{memoria} {}: excedido {excedido}, contencion {contencion}, \
                     holgado {holgado}, presion {presion}",
                    c.nombre()
                );
            }
        }
    }

    #[test]
    fn el_maximo_se_recuerda_aunque_se_baje() {
        let mut v = vigilante();
        v.observar_bytes(300 * MIB);
        v.observar_bytes(MIB);
        assert_eq!(v.maximo(), 300 * MIB);
        assert_eq!(v.muestras(), 2);
    }

    #[test]
    fn no_hay_desbordamiento_con_un_consumo_absurdo() {
        let mut v = vigilante();
        assert_eq!(v.observar_bytes(u64::MAX), Regimen::Excedido);
        assert_eq!(v.maximo(), u64::MAX);
    }
}
