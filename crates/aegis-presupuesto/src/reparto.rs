//! Reparto del presupuesto entre componentes.
//!
//! El README prometia un presupuesto «repartido por componente y medido». Esto
//! es ese reparto en codigo, para que el que pide memoria pregunte cuanta le
//! toca en vez de llevar una constante inventada en su propio fichero.
//!
//! El reparto distingue dos naturalezas que el modelo antiguo mezclaba:
//!
//! - **Coste fijo**: lo que ocupa si o si. El modelo ONNX cuantizado pesa lo que
//!   pesa, y el nucleo del agente tiene un suelo medido. Una fraccion del host
//!   no tiene sentido aqui: en una maquina pequena no puede encoger, y en una
//!   grande no tiene por que crecer.
//! - **Coste elastico**: caches, tablas de flujos, firmas residentes. Aqui si
//!   tiene sentido escalar con el host, porque mas residencia compra menos
//!   disco, y es exactamente la parte que hay que soltar bajo presion.
//!
//! Lo que se reparte por fracciones, por tanto, es **lo que queda despues de lo
//! fijo**, no el total.

use crate::perfil::Presupuesto;

/// Consumidor de memoria con cuota propia.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Componente {
    /// Colector de eventos, correlacion y grafo de procesos. Coste fijo.
    Nucleo,
    /// Modelo ONNX cuantizado a int8. Coste fijo.
    Modelo,
    /// Reglas YARA compiladas y residentes. Elastico.
    Yara,
    /// Reensamblado TCP, tablas de flujo y buferes de aplicacion. Elastico.
    ///
    /// Es el componente que un atacante puede empujar a voluntad: elige el
    /// numero de flujos. Su cuota es un techo global, no una cota por flujo.
    Red,
    /// Indice de firmas residente del corpus. Elastico.
    ///
    /// Lo que no cabe aqui no se pierde: vive en disco y se pagina a demanda.
    /// Por eso es el primero en soltarse cuando aprieta.
    Corpus,
    /// Reserva sin asignar. Elastico.
    ///
    /// No es desperdicio: es lo que absorbe la fragmentacion del asignador y
    /// los picos cortos que no justifican entrar en contencion.
    Margen,
}

/// Coste fijo del nucleo del agente.
///
/// No es una estimacion: es lo que mide `make ci` arrancando el binario de
/// release con el blindaje activo y el canal de control embebido, redondeado
/// hacia arriba al MiB.
pub const FIJO_NUCLEO: u64 = 24 * 1024 * 1024;
/// Coste fijo del modelo ONNX cuantizado a int8.
pub const FIJO_MODELO: u64 = 6 * 1024 * 1024;
/// Suma de los costes fijos.
pub const FIJO_TOTAL: u64 = FIJO_NUCLEO + FIJO_MODELO;

/// Linea base de arranque: lo que el agente ocupa recien levantado y ocioso.
///
/// No es lo mismo que [`Presupuesto::reposo`] y las dos puertas hacen falta:
///
/// - El **presupuesto** es el compromiso con el cliente y escala con el host.
///   En un servidor grande vale 384 MiB, asi que como unica comprobacion de CI
///   seria inutil: un componente podria decuplicar su huella y seguir pasando.
/// - La **linea base** no escala con nada. Es el numero medido, con margen, y su
///   trabajo es cazar la regresion: si el agente arranca ocupando el doble que
///   ayer, eso es un bug atribuible aunque quepa de sobra en el presupuesto.
///
/// El valor sale de la medida real de `make ci` (~22 MiB arrancando el binario
/// de release con el blindaje activo y el canal de control embebido), con margen
/// para que no oscile con la version del asignador o del kernel.
pub const LINEA_BASE_ARRANQUE: u64 = 32 * 1024 * 1024;

/// Partes de lo elastico que se lleva YARA.
pub const PARTES_YARA: u64 = 30;
/// Partes de lo elastico que se lleva la red.
pub const PARTES_RED: u64 = 25;
/// Partes de lo elastico que se lleva el corpus.
pub const PARTES_CORPUS: u64 = 30;
/// Partes de lo elastico que quedan sin asignar.
pub const PARTES_MARGEN: u64 = 15;
/// Suma de las partes elasticas.
pub const PARTES_TOTAL: u64 = PARTES_YARA + PARTES_RED + PARTES_CORPUS + PARTES_MARGEN;

impl Componente {
    /// Nombre estable para logs y metricas.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Componente::Nucleo => "nucleo",
            Componente::Modelo => "modelo",
            Componente::Yara => "yara",
            Componente::Red => "red",
            Componente::Corpus => "corpus",
            Componente::Margen => "margen",
        }
    }

    /// Si su coste es fijo (no escala con el host ni se suelta bajo presion).
    #[must_use]
    pub fn es_fijo(self) -> bool {
        matches!(self, Componente::Nucleo | Componente::Modelo)
    }

    /// Todos los componentes, en orden estable.
    #[must_use]
    pub fn todos() -> [Componente; 6] {
        [
            Componente::Nucleo,
            Componente::Modelo,
            Componente::Yara,
            Componente::Red,
            Componente::Corpus,
            Componente::Margen,
        ]
    }
}

impl Presupuesto {
    /// Memoria elastica disponible en reposo: el reposo menos lo fijo.
    ///
    /// Puede ser cero en un host minimo, y ese caso no es un error sino la
    /// respuesta correcta: no queda nada que repartir y todo lo elastico
    /// trabaja contra disco.
    #[must_use]
    pub fn elastico(&self) -> u64 {
        self.reposo.saturating_sub(FIJO_TOTAL)
    }

    /// Cuota en reposo de un componente, en bytes.
    ///
    /// La suma de las cuotas de [`Componente::todos`] nunca pasa de
    /// [`Presupuesto::reposo`]; lo comprueba una prueba por barrido.
    #[must_use]
    pub fn cuota(&self, componente: Componente) -> u64 {
        let elastico = self.elastico();
        let parte = |partes: u64| {
            (u128::from(elastico) * u128::from(partes) / u128::from(PARTES_TOTAL)) as u64
        };
        match componente {
            // Lo fijo se acota por el reposo: en un host donde el reposo no
            // llega ni a lo fijo, el nucleo se queda con lo que hay y el modelo
            // sencillamente no se carga. Prometer 24 MiB donde hay 20 seria
            // devolver un numero que nadie puede cumplir.
            Componente::Nucleo => FIJO_NUCLEO.min(self.reposo),
            Componente::Modelo => FIJO_MODELO.min(self.reposo.saturating_sub(FIJO_NUCLEO)),
            Componente::Yara => parte(PARTES_YARA),
            Componente::Red => parte(PARTES_RED),
            Componente::Corpus => parte(PARTES_CORPUS),
            // El margen recoge el resto de la division entera ademas de su
            // parte, para que el reparto sea exacto y no se pierdan bytes por
            // redondeo en cada consulta.
            Componente::Margen => {
                elastico - parte(PARTES_YARA) - parte(PARTES_RED) - parte(PARTES_CORPUS)
            }
        }
    }

    /// Cuota de un componente cuando el agente esta en pico (escaneo, recarga).
    ///
    /// Lo fijo no crece; todo el margen entre reposo y pico va a lo elastico,
    /// que es lo que de verdad necesita sitio durante un escaneo completo.
    #[must_use]
    pub fn cuota_en_pico(&self, componente: Componente) -> u64 {
        if componente.es_fijo() {
            return self.cuota(componente);
        }
        let elastico_pico = self.pico.saturating_sub(FIJO_TOTAL);
        let partes = match componente {
            Componente::Yara => PARTES_YARA,
            Componente::Red => PARTES_RED,
            Componente::Corpus => PARTES_CORPUS,
            _ => PARTES_MARGEN,
        };
        (u128::from(elastico_pico) * u128::from(partes) / u128::from(PARTES_TOTAL)) as u64
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::perfil::Perfil;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    #[test]
    fn el_reparto_nunca_pasa_del_reposo() {
        for exponente in 0..42u32 {
            for factor in [1u64, 3, 7] {
                let memoria = (1u64 << exponente).saturating_mul(factor);
                let p = Presupuesto::para(memoria);
                let suma: u64 = Componente::todos().iter().map(|c| p.cuota(*c)).sum();
                assert!(
                    suma <= p.reposo,
                    "{memoria}: el reparto suma {suma} sobre un reposo de {}",
                    p.reposo
                );
            }
        }
    }

    #[test]
    fn el_reparto_es_exacto_cuando_lo_fijo_cabe() {
        // Sin perdida por redondeo: el margen recoge el resto de la division.
        for memoria in [4 * GIB, 8 * GIB, 16 * GIB, 64 * GIB, 512 * GIB] {
            let p = Presupuesto::para(memoria);
            let suma: u64 = Componente::todos().iter().map(|c| p.cuota(*c)).sum();
            assert_eq!(suma, p.reposo, "{memoria}: reparto inexacto");
        }
    }

    #[test]
    fn en_pasarela_el_elastico_es_lo_que_sobra_de_lo_fijo() {
        let p = Presupuesto::para(GIB);
        assert_eq!(p.reposo, 48 * MIB);
        assert_eq!(p.elastico(), 48 * MIB - FIJO_TOTAL); // 18 MiB
        assert_eq!(p.cuota(Componente::Nucleo), FIJO_NUCLEO);
        assert_eq!(p.cuota(Componente::Modelo), FIJO_MODELO);
        // 18 MiB repartidos: YARA 30 %, red 25 %, corpus 30 %, margen 15 %.
        assert_eq!(p.cuota(Componente::Yara), 18 * MIB * 30 / 100);
        assert_eq!(p.cuota(Componente::Corpus), 18 * MIB * 30 / 100);
    }

    #[test]
    fn el_servidor_mantiene_mucho_mas_corpus_residente() {
        let pasarela = Presupuesto::para(GIB).cuota(Componente::Corpus);
        let estacion = Presupuesto::para(16 * GIB).cuota(Componente::Corpus);
        let servidor = Presupuesto::para(768 * GIB).cuota(Componente::Corpus);
        assert!(estacion > pasarela * 2, "{estacion} vs {pasarela}");
        assert!(servidor > estacion * 4, "{servidor} vs {estacion}");
        // Y en el servidor son mas de 100 MiB de firmas sin tocar disco.
        assert!(servidor > 100 * MIB, "{servidor}");
    }

    #[test]
    fn el_pico_solo_engorda_lo_elastico() {
        let p = Presupuesto::para(16 * GIB);
        assert_eq!(
            p.cuota_en_pico(Componente::Nucleo),
            p.cuota(Componente::Nucleo)
        );
        assert_eq!(
            p.cuota_en_pico(Componente::Modelo),
            p.cuota(Componente::Modelo)
        );
        assert!(p.cuota_en_pico(Componente::Yara) > p.cuota(Componente::Yara));
        assert!(p.cuota_en_pico(Componente::Corpus) > p.cuota(Componente::Corpus));
    }

    #[test]
    fn el_reparto_en_pico_tampoco_se_pasa() {
        for memoria in [GIB, 4 * GIB, 16 * GIB, 64 * GIB, 768 * GIB] {
            let p = Presupuesto::para(memoria);
            let suma: u64 = Componente::todos()
                .iter()
                .map(|c| p.cuota_en_pico(*c))
                .sum();
            assert!(
                suma <= p.pico,
                "{memoria}: pico repartido {suma} sobre {}",
                p.pico
            );
        }
    }

    #[test]
    fn host_ridiculo_no_promete_lo_que_no_tiene() {
        // Un perfil forzado por debajo de lo fijo: el nucleo se queda con lo
        // que hay, el modelo no se carga, y nada de lo elastico existe.
        let p = Presupuesto::forzando(Perfil::Incrustado, 20 * MIB);
        assert!(p.cuota(Componente::Nucleo) <= p.reposo);
        assert_eq!(p.elastico(), p.reposo.saturating_sub(FIJO_TOTAL));
        let suma: u64 = Componente::todos().iter().map(|c| p.cuota(*c)).sum();
        assert!(suma <= p.reposo);
    }

    #[test]
    fn las_partes_suman_cien() {
        assert_eq!(PARTES_TOTAL, 100);
    }
}
