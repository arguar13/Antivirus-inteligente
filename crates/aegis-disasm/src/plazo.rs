//! La cota de tiempo, y la cobertura que se declara al agotarla.
//!
//! # Por que un analisis estatico necesita una cota dura
//!
//! El desensamblado recursivo sobre un binario construido para eso no termina en
//! un tiempo razonable: basta con un grafo denso, una tabla de saltos enorme o
//! un millon de funciones de dos instrucciones. Y esto corre **en el agente**,
//! dentro de su presupuesto, en una maquina que ademas tiene que trabajar.
//!
//! Asi que el analisis se corta. La pregunta no es si se corta, es **que dice
//! cuando lo hace**.
//!
//! # La unica respuesta que no vale
//!
//! Devolver la lista de capacidades encontradas hasta el corte, sin mas. Quien
//! la lea —un analista, un informe, otro motor— entiende «esto es lo que hay», y
//! lo que hay de verdad es «esto es lo que dio tiempo a mirar». La diferencia
//! entre las dos frases es un incidente.
//!
//! Por eso todo resultado de este crate viaja con su [`Cobertura`], y
//! [`Cobertura::completa`] es lo unico que autoriza a leer una lista vacia como
//! «no hay nada».

use std::time::{Duration, Instant};

/// Cota de tiempo y de trabajo para un analisis ENTERO.
///
/// Lleva las dos porque una sola no basta: el tiempo protege de un binario que
/// tarda, y el tope de trabajo protege de una maquina tan rapida que el reloj no
/// salta pero la memoria se llena. Se agota la primera que llegue.
///
/// # Cubre TODAS las fases
///
/// Al principio solo lo consultaba la construccion del grafo de flujo: el grafo
/// de llamadas, la propagacion de constantes y las reglas corrian despues sin
/// cota. Sobre `python3` —un ejecutable corriente de 7 MiB— eso eran 21 s y
/// 600 MiB, con un plazo declarado de 500 ms (FASE 1 del MP-16, medido en el
/// trabajador confinado, que lo mato por memoria). Ahora cada fase cobra su
/// trabajo aqui —instrucciones decodificadas, instrucciones recorridas,
/// elementos examinados— con [`Plazo::sigue`] o [`Plazo::cobrar`], y al
/// agotarse para y lo declara en la [`Cobertura`].
#[derive(Debug, Clone)]
pub struct Plazo {
    limite: Duration,
    tope_instrucciones: u64,
    inicio: Instant,
    gastadas: u64,
    /// Cada cuantas instrucciones se mira el reloj.
    ///
    /// Consultar `Instant::now()` por instruccion cuesta mas que decodificarla.
    /// Se mira cada 4096, que a cualquier velocidad real es una fraccion de
    /// milisegundo de sobrepaso: la cota sigue siendo dura en la practica y el
    /// coste de medirla deja de dominar.
    periodo: u64,
}

/// Plazo por defecto: lo que cabe en el presupuesto del agente.
pub const PLAZO_POR_DEFECTO: Duration = Duration::from_millis(500);

/// Tope de instrucciones por defecto.
pub const TOPE_POR_DEFECTO: u64 = 2_000_000;

impl Default for Plazo {
    fn default() -> Self {
        Plazo::nuevo(PLAZO_POR_DEFECTO, TOPE_POR_DEFECTO)
    }
}

impl Plazo {
    /// Abre un plazo.
    pub fn nuevo(limite: Duration, tope_instrucciones: u64) -> Plazo {
        Plazo {
            limite,
            tope_instrucciones,
            inicio: Instant::now(),
            gastadas: 0,
            periodo: 4096,
        }
    }

    /// Anota una instruccion analizada y dice si se puede seguir.
    pub fn sigue(&mut self) -> bool {
        self.gastadas += 1;
        if self.gastadas > self.tope_instrucciones {
            return false;
        }
        if self.gastadas % self.periodo == 0 && self.inicio.elapsed() >= self.limite {
            return false;
        }
        true
    }

    /// Cobra `n` unidades de trabajo de golpe y dice si se puede seguir.
    ///
    /// Para las fases que recorren algo cuyo tamaño ya se conoce (todas las
    /// instrucciones del grafo, todas las aristas): cobrar de una vez evita
    /// pagar la comprobacion por elemento, y el sobrepaso queda acotado por ese
    /// `n`, que el propio tope ya limito en la fase anterior.
    pub fn cobrar(&mut self, n: u64) -> bool {
        self.gastadas = self.gastadas.saturating_add(n);
        self.gastadas <= self.tope_instrucciones && self.inicio.elapsed() < self.limite
    }

    /// Un plazo sin cota: solo para herramientas y pruebas que analizan un
    /// fichero de confianza. El camino de produccion usa siempre un tope.
    pub fn sin_cota() -> Plazo {
        Plazo::nuevo(Duration::MAX, u64::MAX)
    }

    /// Si se agoto por tiempo.
    pub fn agotado_por_tiempo(&self) -> bool {
        self.inicio.elapsed() >= self.limite
    }

    /// Si se agoto por numero de instrucciones.
    pub fn agotado_por_tope(&self) -> bool {
        self.gastadas > self.tope_instrucciones
    }

    /// Instrucciones analizadas.
    pub fn gastadas(&self) -> u64 {
        self.gastadas
    }

    /// Tiempo consumido.
    pub fn transcurrido(&self) -> Duration {
        self.inicio.elapsed()
    }
}

/// Que se llego a mirar, y que no.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cobertura {
    /// Instrucciones decodificadas.
    pub instrucciones: u64,
    /// Bytes de codigo que el analisis llego a cubrir.
    pub bytes_cubiertos: u64,
    /// Bytes de codigo que habia.
    pub bytes_totales: u64,
    /// Funciones descubiertas.
    pub funciones: usize,
    /// Transferencias de control cuyo destino no se pudo determinar.
    ///
    /// Es el limite honesto del analisis estatico: cada una es una rama del
    /// programa que no se siguio. Se cuenta y se dice.
    pub transferencias_indirectas: usize,
    /// Direcciones en las que no se pudo decodificar.
    ///
    /// En un binario real hay datos entre funciones, asi que un numero pequeno
    /// es normal; uno grande significa que se estaba desensamblando algo que no
    /// era codigo.
    pub no_decodificables: usize,
    /// El analisis se corto al llegar al plazo.
    pub cortado_por_plazo: bool,
    /// El analisis se corto al llegar al tope de instrucciones.
    pub cortado_por_tope: bool,
}

impl Cobertura {
    /// Si el analisis llego hasta el final.
    ///
    /// **Es lo unico que autoriza a leer una lista de capacidades vacia como
    /// «no hay nada».** Con esto en `false`, la lista significa «esto es lo que
    /// dio tiempo a mirar», que es otra frase.
    pub fn completa(&self) -> bool {
        !self.cortado_por_plazo && !self.cortado_por_tope
    }

    /// Fraccion de los bytes de codigo que se llego a cubrir, en centesimas.
    ///
    /// Devuelve `None` cuando no habia codigo que cubrir: un cero por division
    /// entre cero se leeria como «no se cubrio nada», que es lo contrario de la
    /// verdad.
    pub fn fraccion_cubierta(&self) -> Option<u8> {
        if self.bytes_totales == 0 {
            return None;
        }
        let f = self.bytes_cubiertos.saturating_mul(100) / self.bytes_totales;
        Some(f.min(100) as u8)
    }

    /// La frase con la que esta cobertura aparece en un informe.
    pub fn frase(&self) -> String {
        let cubierto = match self.fraccion_cubierta() {
            Some(f) => format!("{f}% del codigo"),
            None => "un binario sin codigo".to_owned(),
        };
        let mut s = format!(
            "se analizaron {} instrucciones en {} funciones, cubriendo {cubierto}",
            self.instrucciones, self.funciones
        );
        if self.transferencias_indirectas > 0 {
            s.push_str(&format!(
                "; {} transferencias de control no se pudieron seguir porque su destino \
                 se calcula en ejecucion",
                self.transferencias_indirectas
            ));
        }
        if self.cortado_por_plazo {
            s.push_str(
                ". EL ANALISIS SE CORTO AL AGOTAR SU PLAZO: lo que no aparece aqui puede \
                 ser que no exista o puede ser que no se llegara a mirar",
            );
        } else if self.cortado_por_tope {
            s.push_str(
                ". EL ANALISIS SE CORTO AL LLEGAR A SU TOPE DE INSTRUCCIONES: lo que no \
                 aparece aqui puede ser que no exista o puede ser que no se llegara a mirar",
            );
        }
        s
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_plazo_se_agota_por_numero_de_instrucciones() {
        let mut p = Plazo::nuevo(Duration::from_secs(3600), 10);
        for _ in 0..10 {
            assert!(p.sigue());
        }
        assert!(!p.sigue(), "la once pasa del tope");
        assert!(p.agotado_por_tope());
        assert!(!p.agotado_por_tiempo());
    }

    #[test]
    fn un_plazo_se_agota_por_tiempo() {
        let mut p = Plazo::nuevo(Duration::from_millis(1), u64::MAX);
        std::thread::sleep(Duration::from_millis(5));
        // El reloj se mira cada 4096 instrucciones: hay que llegar a esa marca.
        let mut cortado = false;
        for _ in 0..5000 {
            if !p.sigue() {
                cortado = true;
                break;
            }
        }
        assert!(cortado, "el plazo de un milisegundo ya paso");
        assert!(p.agotado_por_tiempo());
    }

    #[test]
    fn una_cobertura_cortada_no_es_completa() {
        // La propiedad que separa «no hay nada» de «no dio tiempo a mirar».
        let c = Cobertura {
            cortado_por_plazo: true,
            ..Default::default()
        };
        assert!(!c.completa());
        assert!(c.frase().contains("SE CORTO"), "{}", c.frase());
    }

    #[test]
    fn una_cobertura_entera_si_es_completa() {
        let c = Cobertura {
            instrucciones: 1000,
            bytes_cubiertos: 4000,
            bytes_totales: 4000,
            funciones: 12,
            ..Default::default()
        };
        assert!(c.completa());
        assert_eq!(c.fraccion_cubierta(), Some(100));
        assert!(!c.frase().contains("SE CORTO"));
    }

    #[test]
    fn un_binario_sin_codigo_no_reporta_cero_por_ciento() {
        // Cero por division entre cero se leeria como «no se cubrio nada», que
        // es lo contrario de la verdad: no habia nada que cubrir.
        let c = Cobertura::default();
        assert_eq!(c.fraccion_cubierta(), None);
        assert!(c.frase().contains("sin codigo"), "{}", c.frase());
    }

    #[test]
    fn las_transferencias_indirectas_se_dicen_en_la_frase() {
        // Cada una es una rama del programa que no se siguio. Callarlas haria
        // que un analisis parcial pareciera exhaustivo.
        let c = Cobertura {
            instrucciones: 100,
            bytes_cubiertos: 1,
            bytes_totales: 2,
            funciones: 1,
            transferencias_indirectas: 7,
            ..Default::default()
        };
        assert!(c.frase().contains("7 transferencias"), "{}", c.frase());
    }

    #[test]
    fn la_fraccion_no_pasa_de_cien_aunque_los_contadores_se_solapen() {
        // Un bloque alcanzado por dos caminos podria contarse dos veces; la
        // fraccion no puede salir 130%, que ademas de falso parece un error de
        // otro sitio.
        let c = Cobertura {
            bytes_cubiertos: 500,
            bytes_totales: 100,
            ..Default::default()
        };
        assert_eq!(c.fraccion_cubierta(), Some(100));
    }
}
