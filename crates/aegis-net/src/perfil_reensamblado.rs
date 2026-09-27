//! Reensamblado por PERFIL DE DESTINO REAL, y desambiguacion preguntando al
//! endpoint (FASE 106).
//!
//! # La superioridad estructural que ningun IDS sin agente puede tener
//!
//! Cuando dos segmentos TCP se solapan con contenido distinto, cada sistema
//! operativo resuelve el solape a su manera. El evasor lo explota: fabrica un flujo
//! que el IDS reensambla de una forma y el destino de otra, y lo malo viaja en la
//! interpretacion que el IDS no ve. Suricata ADIVINA el sistema del destino por
//! configuracion o por huella. AegisCore LO SABE: el endpoint es suyo y le dice su
//! sistema. El perfil de reensamblado se elige con ese dato, no con una suposicion.
//!
//! Y cuando el flujo es AMBIGUO —dos interpretaciones posibles, que es justo lo que
//! busca el evasor—, no hay que adivinar: el agente del destino DICE que bytes
//! entrego de verdad a la aplicacion, y esa es la verdad. Nadie en el mundo abierto
//! puede hacer esto, porque nadie mas tiene los dos lados con el mismo modelo.
//!
//! Aqui esta la capa de PERFIL (target-based reassembly): la resolucion de solapes
//! parametrizada por el sistema del destino. La diseccion semantica del flujo
//! (HTTP, DNS, TLS...) vive en `aegis-wire` (FASE 70) y no se duplica.

use std::collections::BTreeMap;

/// La politica con la que un sistema operativo resuelve un solape de segmentos.
/// Son las clasicas del reensamblado dirigido por destino (target-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PoliticaSolape {
    /// El PRIMER segmento que ocupo un byte gana; los solapes posteriores no lo
    /// reescriben. Es el mas seguro y el de BSD/Linux moderno para el caso comun.
    Primero,
    /// El ULTIMO gana: un solape posterior reescribe. Windows antiguo.
    Ultimo,
    /// BSD: gana el segmento cuyo numero de secuencia de inicio es MENOR (empezo
    /// antes en el espacio de secuencia), llegara cuando llegara.
    Bsd,
    /// Linux: el nuevo gana cuando empieza en el mismo sitio o antes que el que
    /// escribio el byte; si empieza despues, no reescribe.
    Linux,
    /// Solaris/HP: el solape por la DERECHA favorece al nuevo (gana el que empieza
    /// mas tarde), al reves que BSD.
    Solaris,
}

impl PoliticaSolape {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            PoliticaSolape::Primero => "primero",
            PoliticaSolape::Ultimo => "ultimo",
            PoliticaSolape::Bsd => "bsd",
            PoliticaSolape::Linux => "linux",
            PoliticaSolape::Solaris => "solaris",
        }
    }

    /// Las cinco politicas.
    #[must_use]
    pub fn todas() -> [PoliticaSolape; 5] {
        [
            PoliticaSolape::Primero,
            PoliticaSolape::Ultimo,
            PoliticaSolape::Bsd,
            PoliticaSolape::Linux,
            PoliticaSolape::Solaris,
        ]
    }

    /// Si un segmento entrante, cuyo inicio es `seq_entrante`, reescribe un byte ya
    /// escrito por un segmento cuyo inicio fue `seq_escritor`.
    fn reescribe(self, seq_entrante: u32, seq_escritor: u32) -> bool {
        match self {
            PoliticaSolape::Primero => false,
            PoliticaSolape::Ultimo => true,
            PoliticaSolape::Bsd => seq_entrante < seq_escritor,
            PoliticaSolape::Linux => seq_entrante <= seq_escritor,
            PoliticaSolape::Solaris => seq_entrante > seq_escritor,
        }
    }
}

/// El perfil de reensamblado del DESTINO, elegido por su sistema operativo real
/// —el que el propio endpoint reporta, no una huella adivinada—.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerfilReensamblado {
    politica: PoliticaSolape,
}

impl PerfilReensamblado {
    /// Construye un perfil a partir de la politica.
    #[must_use]
    pub fn nuevo(politica: PoliticaSolape) -> PerfilReensamblado {
        PerfilReensamblado { politica }
    }

    /// Elige el perfil por el sistema operativo del destino. AegisCore lo SABE
    /// porque el endpoint es suyo; el `so` viene del propio agente del destino, no
    /// de una huella. Un sistema no reconocido cae en `Primero` —el mas seguro—,
    /// y eso se dice, no se adivina otra cosa.
    #[must_use]
    pub fn para_sistema(so: &str) -> PerfilReensamblado {
        let s = so.to_ascii_lowercase();
        let politica = if s.contains("windows") {
            PoliticaSolape::Ultimo
        } else if s.contains("solaris") || s.contains("hp-ux") || s.contains("hpux") {
            PoliticaSolape::Solaris
        } else if s.contains("linux") {
            PoliticaSolape::Linux
        } else if s.contains("bsd") || s.contains("macos") || s.contains("darwin") {
            PoliticaSolape::Bsd
        } else {
            PoliticaSolape::Primero
        };
        PerfilReensamblado { politica }
    }

    /// La politica del perfil.
    #[must_use]
    pub fn politica(self) -> PoliticaSolape {
        self.politica
    }
}

/// Un segmento TCP: su numero de secuencia de inicio (relativo) y sus bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segmento {
    /// Numero de secuencia de inicio (offset relativo al ISN; sin envoltura en
    /// esta capa de perfil, que la envoltura la maneja `aegis-wire`).
    pub seq: u32,
    /// Los bytes del segmento.
    pub datos: Vec<u8>,
}

impl Segmento {
    /// Un segmento.
    #[must_use]
    pub fn nuevo(seq: u32, datos: &[u8]) -> Segmento {
        Segmento {
            seq,
            datos: datos.to_vec(),
        }
    }
}

/// Por que no se pudo incorporar un segmento.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorReensamblado {
    /// Se alcanzo el techo de bytes o de segmentos del flujo. El reensamblador no
    /// crece sin cota: un atacante no puede agotar la memoria con millones de
    /// segmentos a medio abrir. El flujo se marca desbordado y se DICE.
    #[error("techo del reensamblado alcanzado: el flujo se desborda y se declara")]
    Techo,
}

/// Un reensamblador por perfil: acumula segmentos y los reensambla segun la
/// politica del destino, con cotas duras contra el agotamiento.
#[derive(Debug, Clone)]
pub struct ReensambladorPerfil {
    perfil: PerfilReensamblado,
    segmentos: Vec<Segmento>,
    bytes: usize,
    max_bytes: usize,
    max_segmentos: usize,
}

impl ReensambladorPerfil {
    /// Cotas por defecto: 256 KiB y 4096 segmentos por flujo.
    pub const MAX_BYTES: usize = 256 * 1024;
    /// Tope de segmentos por flujo.
    pub const MAX_SEGMENTOS: usize = 4096;

    /// Un reensamblador para un perfil de destino, con las cotas por defecto.
    #[must_use]
    pub fn nuevo(perfil: PerfilReensamblado) -> ReensambladorPerfil {
        ReensambladorPerfil {
            perfil,
            segmentos: Vec::new(),
            bytes: 0,
            max_bytes: Self::MAX_BYTES,
            max_segmentos: Self::MAX_SEGMENTOS,
        }
    }

    /// Un reensamblador con cotas explicitas (para pruebas de agotamiento).
    #[must_use]
    pub fn con_cotas(
        perfil: PerfilReensamblado,
        max_bytes: usize,
        max_segmentos: usize,
    ) -> ReensambladorPerfil {
        ReensambladorPerfil {
            perfil,
            segmentos: Vec::new(),
            bytes: 0,
            max_bytes,
            max_segmentos,
        }
    }

    /// Incorpora un segmento. Rechaza si se pasaria del techo: fallar cerrado es
    /// no crecer sin cota.
    pub fn incorporar(&mut self, seg: Segmento) -> Result<(), ErrorReensamblado> {
        if self.segmentos.len() >= self.max_segmentos
            || self.bytes.saturating_add(seg.datos.len()) > self.max_bytes
        {
            return Err(ErrorReensamblado::Techo);
        }
        self.bytes += seg.datos.len();
        self.segmentos.push(seg);
        Ok(())
    }

    /// Los bytes acumulados (para respetar el techo global del sensor).
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Reensambla segun el perfil del destino.
    #[must_use]
    pub fn reensamblar(&self) -> Vec<u8> {
        reensamblar_con(&self.segmentos, self.perfil.politica())
    }

    /// Reensambla como lo haria una politica concreta (para comparar
    /// interpretaciones).
    #[must_use]
    pub fn reensamblar_como(&self, politica: PoliticaSolape) -> Vec<u8> {
        reensamblar_con(&self.segmentos, politica)
    }

    /// Si el flujo es AMBIGUO: al menos dos politicas producen resultados
    /// distintos. Es justo lo que busca el evasor, y la senal de que hay que
    /// preguntarle al endpoint en vez de adivinar.
    #[must_use]
    pub fn es_ambiguo(&self) -> bool {
        let mut vistos: Option<Vec<u8>> = None;
        for pol in PoliticaSolape::todas() {
            let r = reensamblar_con(&self.segmentos, pol);
            match &vistos {
                None => vistos = Some(r),
                Some(v) if *v != r => return true,
                _ => {}
            }
        }
        false
    }

    /// Desambigua PREGUNTANDO AL ENDPOINT: dado lo que el destino entrego de verdad
    /// a la aplicacion, devuelve que politica coincide con esa verdad —o `None` si
    /// ninguna de las cinco la explica, que es en si un hecho a reportar—.
    #[must_use]
    pub fn politica_segun_endpoint(&self, entregado: &[u8]) -> Option<PoliticaSolape> {
        PoliticaSolape::todas()
            .into_iter()
            .find(|&pol| reensamblar_con(&self.segmentos, pol) == entregado)
    }
}

/// Reensambla una lista de segmentos con una politica, resolviendo solapes byte a
/// byte, y devuelve el tramo CONTIGUO desde el offset minimo. Un hueco corta el
/// tramo: lo que hay detras de un hueco no se ha recibido aun.
#[must_use]
pub fn reensamblar_con(segmentos: &[Segmento], politica: PoliticaSolape) -> Vec<u8> {
    // offset -> (byte, seq de inicio del segmento que lo escribio)
    let mut mapa: BTreeMap<u32, (u8, u32)> = BTreeMap::new();
    for seg in segmentos {
        for (i, &b) in seg.datos.iter().enumerate() {
            let pos = seg.seq.wrapping_add(i as u32);
            match mapa.get(&pos) {
                None => {
                    mapa.insert(pos, (b, seg.seq));
                }
                Some(&(_, seq_escritor)) => {
                    if politica.reescribe(seg.seq, seq_escritor) {
                        mapa.insert(pos, (b, seg.seq));
                    }
                }
            }
        }
    }
    // Tramo contiguo desde el offset minimo presente.
    let Some((&inicio, _)) = mapa.iter().next() else {
        return Vec::new();
    };
    let mut salida = Vec::new();
    let mut pos = inicio;
    while let Some(&(b, _)) = mapa.get(&pos) {
        salida.push(b);
        pos = pos.wrapping_add(1);
    }
    salida
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // Un solape clasico: [0..4]="AAAA" y luego [2..6]="BBBB". Los bytes 2 y 3
    // estan en disputa. Primero -> "AAAABB"; Ultimo -> "AABBBB".
    fn flujo_solapado() -> Vec<Segmento> {
        vec![Segmento::nuevo(0, b"AAAA"), Segmento::nuevo(2, b"BBBB")]
    }

    #[test]
    fn la_misma_evasion_se_reensambla_distinto_segun_el_destino() {
        let segs = flujo_solapado();
        assert_eq!(reensamblar_con(&segs, PoliticaSolape::Primero), b"AAAABB");
        assert_eq!(reensamblar_con(&segs, PoliticaSolape::Ultimo), b"AABBBB");
        // Bsd: gana el seq menor -> el primer segmento (seq 0) conserva 2 y 3.
        assert_eq!(reensamblar_con(&segs, PoliticaSolape::Bsd), b"AAAABB");
        // Solaris: gana el seq mayor por la derecha -> el segundo (seq 2).
        assert_eq!(reensamblar_con(&segs, PoliticaSolape::Solaris), b"AABBBB");
    }

    #[test]
    fn el_perfil_se_elige_por_el_sistema_real_del_destino() {
        assert_eq!(
            PerfilReensamblado::para_sistema("Windows Server 2022").politica(),
            PoliticaSolape::Ultimo
        );
        assert_eq!(
            PerfilReensamblado::para_sistema("Ubuntu Linux 22.04").politica(),
            PoliticaSolape::Linux
        );
        // Desconocido: cae en el mas seguro, y no adivina otra cosa.
        assert_eq!(
            PerfilReensamblado::para_sistema("PalmOS").politica(),
            PoliticaSolape::Primero
        );
    }

    #[test]
    fn un_ids_que_adivina_falla_donde_aegiscore_acierta_porque_pregunto() {
        // El destino es Windows (ultimo gana): la app vio "AABBBB".
        let mut r = ReensambladorPerfil::nuevo(PerfilReensamblado::para_sistema("Windows 10"));
        for s in flujo_solapado() {
            r.incorporar(s).unwrap();
        }
        assert!(
            r.es_ambiguo(),
            "el flujo es ambiguo: hay que preguntar, no adivinar"
        );
        // AegisCore, con el perfil del destino real, acierta.
        assert_eq!(r.reensamblar(), b"AABBBB");
        // Y un IDS que adivinara "primero" (lo comun) se equivocaria.
        assert_eq!(r.reensamblar_como(PoliticaSolape::Primero), b"AAAABB");
        // Preguntando al endpoint por lo que ENTREGO, se confirma la politica.
        assert_eq!(
            r.politica_segun_endpoint(b"AABBBB"),
            Some(PoliticaSolape::Ultimo)
        );
    }

    #[test]
    fn segmentos_fuera_de_orden_y_huecos() {
        // Fuera de orden: [4..8] antes que [0..4]. Reensambla contiguo.
        let segs = vec![Segmento::nuevo(4, b"DDDD"), Segmento::nuevo(0, b"CCCC")];
        assert_eq!(reensamblar_con(&segs, PoliticaSolape::Primero), b"CCCCDDDD");
        // Con un hueco (falta [4..8]), solo el tramo contiguo desde el minimo.
        let con_hueco = vec![Segmento::nuevo(0, b"CCCC"), Segmento::nuevo(8, b"EEEE")];
        assert_eq!(
            reensamblar_con(&con_hueco, PoliticaSolape::Primero),
            b"CCCC"
        );
    }

    #[test]
    fn el_reensamblador_no_se_puede_agotar() {
        // Techo de 16 bytes: un atacante que inunda con segmentos es rechazado, no
        // agota la memoria.
        let mut r = ReensambladorPerfil::con_cotas(
            PerfilReensamblado::nuevo(PoliticaSolape::Primero),
            16,
            100,
        );
        assert!(r.incorporar(Segmento::nuevo(0, b"0123456789")).is_ok());
        // El siguiente pasaria de 16 bytes: rechazado.
        assert_eq!(
            r.incorporar(Segmento::nuevo(10, b"0123456789")),
            Err(ErrorReensamblado::Techo)
        );
        assert!(r.bytes() <= 16);
    }
}
