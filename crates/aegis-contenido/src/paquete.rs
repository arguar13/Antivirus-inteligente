//! El paquete de contenido: lo que se firma y lo que viaja.
//!
//! # Forma
//!
//! ```text
//!   sellado  = cuenta(cuerpo) cuerpo cuenta(firma) firma
//!   cuerpo   = MAGIA VERSION canal epoca generado_ns anillo escalera revierte_a entradas
//!   entrada  = id tipo modo activa coste medicion fuente dispara* no_dispara*
//! ```
//!
//! La firma cubre el cuerpo ENTERO bajo [`CTX_CONTENIDO`]. Antes de verificarla
//! solo se leen dos longitudes: el analizador del cuerpo no ve nunca bytes que no
//! esten firmados.
//!
//! # Por que cada regla lleva sus muestras
//!
//! Cada entrada lleva al menos una muestra que la dispara y una que no. La
//! puerta de publicacion las usa para demostrar que la regla funciona y cuanto
//! cuesta, y el agente las vuelve a pasar al cargar: si el motor del agente no
//! se comporta como el del publicador (otra version del compilador de reglas),
//! el paquete se rechaza en el propio equipo en vez de cargarse roto.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::anillo::{comprobar_escalera, Anillo, Peldano, MAX_PELDANOS};
use crate::codificacion::{ErrorFormato, Escritor, Lector};

/// Marca del cuerpo de un paquete.
pub const MAGIA: &[u8; 8] = b"AEGISCNT";
/// Version del formato.
pub const VERSION: u32 = 1;
/// Contexto de dominio de la firma de un paquete.
///
/// Cambiarlo invalida todas las firmas anteriores a proposito: es la palanca
/// para retirar de golpe lo firmado con una clave comprometida.
pub const CTX_CONTENIDO: &[u8] = b"aegiscore/contenido/v1";

/// Tamaño maximo de un paquete sellado.
pub const MAX_SELLADO: usize = 64 << 20;
/// Tamaño maximo de una firma (la hibrida ocupa 3374 bytes).
pub const MAX_FIRMA: usize = 8192;
/// Entradas como mucho.
pub const MAX_ENTRADAS: usize = 4096;
/// Largo maximo de un identificador de regla.
pub const MAX_ID: usize = 128;
/// Largo maximo del nombre del canal.
pub const MAX_CANAL: usize = 64;
/// Tamaño maximo de la fuente de una regla o de un modelo.
pub const MAX_FUENTE: usize = 16 << 20;
/// Tamaño maximo de una muestra.
pub const MAX_MUESTRA: usize = 64 << 10;
/// Muestras como mucho por regla y por lado.
pub const MAX_MUESTRAS: usize = 16;

/// Muestras benignas minimas para que una regla pueda imponer.
pub const MIN_MUESTRAS_IMPONER: u64 = 100_000;
/// Falsos positivos por millon, como mucho, para imponer (1e-5).
pub const FP_POR_MILLON_MAX: u64 = 10;

/// Que clase de contenido es una entrada.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tipo {
    /// Una regla YARA, para `aegis-patron`.
    Yara,
    /// Una regla Sigma.
    Sigma,
    /// Un modelo de clasificacion.
    Modelo,
}

impl Tipo {
    /// Nombre estable (tambien el del directorio en el arbol fuente).
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Tipo::Yara => "yara",
            Tipo::Sigma => "sigma",
            Tipo::Modelo => "modelo",
        }
    }

    /// Todos, en orden.
    pub const TODOS: [Tipo; 3] = [Tipo::Yara, Tipo::Sigma, Tipo::Modelo];

    fn codigo(self) -> u8 {
        match self {
            Tipo::Yara => 1,
            Tipo::Sigma => 2,
            Tipo::Modelo => 3,
        }
    }

    fn de_codigo(c: u8) -> Option<Tipo> {
        match c {
            1 => Some(Tipo::Yara),
            2 => Some(Tipo::Sigma),
            3 => Some(Tipo::Modelo),
            _ => None,
        }
    }
}

/// Que hace el agente cuando la regla casa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Modo {
    /// Detecta y lo dice; no actua. Es como nace todo (regla 4 del MP-16).
    Auditoria,
    /// Puede ordenar una respuesta. Exige [`Medicion::permite_imponer`].
    Imponer,
}

impl Modo {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Modo::Auditoria => "auditoria",
            Modo::Imponer => "imponer",
        }
    }

    /// Lee el nombre.
    #[must_use]
    pub fn parsear(s: &str) -> Option<Modo> {
        match s {
            "auditoria" => Some(Modo::Auditoria),
            "imponer" => Some(Modo::Imponer),
            _ => None,
        }
    }

    fn codigo(self) -> u8 {
        match self {
            Modo::Auditoria => 0,
            Modo::Imponer => 1,
        }
    }

    fn de_codigo(c: u8) -> Option<Modo> {
        match c {
            0 => Some(Modo::Auditoria),
            1 => Some(Modo::Imponer),
            _ => None,
        }
    }
}

/// Lo medido de una regla sobre software legitimo (el corpus de la FASE 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Medicion {
    /// Muestras benignas contra las que se midio.
    pub muestras_benignas: u64,
    /// Cuantas de ellas disparo la regla.
    pub falsos_positivos: u64,
}

impl Medicion {
    /// Si los numeros bastan para que la regla imponga.
    ///
    /// Sin medicion (cero muestras) nunca: un aval sin prueba es peor que
    /// ningun aval.
    #[must_use]
    pub fn permite_imponer(&self) -> bool {
        self.muestras_benignas >= MIN_MUESTRAS_IMPONER
            && u128::from(self.falsos_positivos) * 1_000_000
                <= u128::from(FP_POR_MILLON_MAX) * u128::from(self.muestras_benignas)
    }
}

/// Presupuesto de coste declarado de una regla.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Coste {
    /// Cota determinista de pasos del motor por byte de entrada
    /// ([`crate::validar`] dice como se calcula).
    pub pasos_por_byte: u64,
    /// Tiempo maximo, en microsegundos, de escanear 64 KiB con la regla sola
    /// (compilacion optimizada).
    pub micros_por_64k: u32,
}

/// Una regla (o un modelo) del paquete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrada {
    /// Identificador unico en el paquete. En YARA, el nombre de la regla.
    pub id: String,
    /// Clase de contenido.
    pub tipo: Tipo,
    /// Modo publicado.
    pub modo: Modo,
    /// Si esta encendida en esta publicacion.
    pub activa: bool,
    /// Presupuesto de coste.
    pub coste: Coste,
    /// Lo medido sobre benignos.
    pub medicion: Medicion,
    /// La fuente (texto de la regla, bytes del modelo).
    pub fuente: Vec<u8>,
    /// Muestras que la disparan.
    pub dispara: Vec<Vec<u8>>,
    /// Muestras que no la disparan.
    pub no_dispara: Vec<Vec<u8>>,
}

impl Entrada {
    fn codificar(&self, e: &mut Escritor) {
        e.texto(&self.id);
        e.u8(self.tipo.codigo());
        e.u8(self.modo.codigo());
        e.booleano(self.activa);
        e.u64(self.coste.pasos_por_byte);
        e.u32(self.coste.micros_por_64k);
        e.u64(self.medicion.muestras_benignas);
        e.u64(self.medicion.falsos_positivos);
        e.bytes(&self.fuente);
        e.cuenta(self.dispara.len());
        for m in &self.dispara {
            e.bytes(m);
        }
        e.cuenta(self.no_dispara.len());
        for m in &self.no_dispara {
            e.bytes(m);
        }
    }

    fn decodificar(l: &mut Lector<'_>) -> Result<Entrada, ErrorFormato> {
        let id = l.texto(MAX_ID, "id de regla")?.to_string();
        let tipo = l.u8()?;
        let tipo = Tipo::de_codigo(tipo)
            .ok_or_else(|| ErrorFormato(format!("tipo desconocido: {tipo}")))?;
        let modo = l.u8()?;
        let modo = Modo::de_codigo(modo)
            .ok_or_else(|| ErrorFormato(format!("modo desconocido: {modo}")))?;
        let activa = l.booleano("activa")?;
        let coste = Coste {
            pasos_por_byte: l.u64()?,
            micros_por_64k: l.u32()?,
        };
        let medicion = Medicion {
            muestras_benignas: l.u64()?,
            falsos_positivos: l.u64()?,
        };
        let fuente = l.bytes(MAX_FUENTE, "fuente")?.to_vec();
        let mut lado = |que: &str| -> Result<Vec<Vec<u8>>, ErrorFormato> {
            let n = l.cuenta(MAX_MUESTRAS, que)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(l.bytes(MAX_MUESTRA, que)?.to_vec());
            }
            Ok(v)
        };
        let dispara = lado("muestras que disparan")?;
        let no_dispara = lado("muestras que no disparan")?;
        Ok(Entrada {
            id,
            tipo,
            modo,
            activa,
            coste,
            medicion,
            fuente,
            dispara,
            no_dispara,
        })
    }
}

/// Si un identificador (de regla o de canal) es valido.
#[must_use]
pub fn id_valido(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// El cuerpo firmado de un paquete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifiesto {
    /// Canal (p. ej. «estable»). Un agente solo acepta el suyo.
    pub canal: String,
    /// Epoca monotona del canal. La 0 es la de un equipo sin contenido.
    pub epoca: u64,
    /// Cuando se genero. Informativo: no decide nada (el reloj se mueve).
    pub generado_ns: u64,
    /// A quien va.
    pub anillo: Anillo,
    /// Por donde paso este mismo contenido antes.
    pub escalera: Vec<Peldano>,
    /// Si es una reversion, la epoca a cuyo contenido vuelve; 0 si no.
    pub revierte_a: u64,
    /// Las reglas.
    pub entradas: Vec<Entrada>,
}

/// SHA-256 de unos bytes.
#[must_use]
pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

impl Manifiesto {
    /// Codificacion canonica: los bytes exactos que se firman.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut e = Escritor::nuevo();
        e.fijo(MAGIA);
        e.u32(VERSION);
        e.texto(&self.canal);
        e.u64(self.epoca);
        e.u64(self.generado_ns);
        self.anillo.codificar(&mut e);
        e.cuenta(self.escalera.len());
        for p in &self.escalera {
            p.codificar(&mut e);
        }
        e.u64(self.revierte_a);
        codificar_entradas(&mut e, &self.entradas);
        e.fin()
    }

    /// Huella del CONTENIDO (solo las entradas): es la misma en el canario, en el
    /// 5 % y en la flota, y es la que casa la escalera y las reversiones.
    #[must_use]
    pub fn sha_contenido(&self) -> [u8; 32] {
        let mut e = Escritor::nuevo();
        codificar_entradas(&mut e, &self.entradas);
        sha256(&e.fin())
    }

    /// Lee un cuerpo.
    ///
    /// # Errores
    /// [`ErrorFormato`] si no es un cuerpo de esta version o no es canonico.
    pub fn de_bytes(b: &[u8]) -> Result<Manifiesto, ErrorFormato> {
        let mut l = Lector::nuevo(b);
        if l.fijo(8).ok() != Some(&MAGIA[..]) {
            return Err(ErrorFormato(
                "no es un paquete de contenido de AegisCore".into(),
            ));
        }
        let version = l.u32()?;
        if version != VERSION {
            return Err(ErrorFormato(format!(
                "paquete de la version {version}; este agente entiende la {VERSION}"
            )));
        }
        let canal = l.texto(MAX_CANAL, "canal")?.to_string();
        let epoca = l.u64()?;
        let generado_ns = l.u64()?;
        let anillo = Anillo::decodificar(&mut l)?;
        let n = l.cuenta(MAX_PELDANOS, "peldaños")?;
        let mut escalera = Vec::with_capacity(n);
        for _ in 0..n {
            escalera.push(Peldano::decodificar(&mut l)?);
        }
        let revierte_a = l.u64()?;
        let n = l.cuenta(MAX_ENTRADAS, "entradas")?;
        let mut entradas = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            entradas.push(Entrada::decodificar(&mut l)?);
        }
        l.terminar()?;
        Ok(Manifiesto {
            canal,
            epoca,
            generado_ns,
            anillo,
            escalera,
            revierte_a,
            entradas,
        })
    }

    /// Las reglas del canal que no dependen de ejecutar nada: identificadores,
    /// limites, anillo, escalera y que nadie imponga sin numeros.
    ///
    /// # Errores
    /// El primer motivo encontrado, en texto.
    pub fn comprobar_estructura(&self) -> Result<(), String> {
        if !id_valido(&self.canal) || self.canal.len() > MAX_CANAL {
            return Err(format!("canal «{}» invalido", self.canal));
        }
        if self.epoca == 0 {
            return Err("la epoca 0 esta reservada: es la de un equipo sin contenido".into());
        }
        self.anillo.comprobar()?;
        comprobar_escalera(&self.anillo, &self.escalera, self.epoca, self.revierte_a)?;
        if self.entradas.is_empty() {
            return Err(
                "paquete sin entradas: vaciar el contenido de la flota no se hace por accidente"
                    .into(),
            );
        }
        if self.entradas.len() > MAX_ENTRADAS {
            return Err(format!(
                "{} entradas (maximo {MAX_ENTRADAS})",
                self.entradas.len()
            ));
        }
        let mut vistos = BTreeSet::new();
        for e in &self.entradas {
            if !id_valido(&e.id) {
                return Err(format!("identificador de regla «{}» invalido", e.id));
            }
            if !vistos.insert(e.id.as_str()) {
                return Err(format!("regla «{}» repetida", e.id));
            }
            if e.fuente.len() > MAX_FUENTE {
                return Err(format!("«{}»: fuente de {} bytes", e.id, e.fuente.len()));
            }
            for lado in [&e.dispara, &e.no_dispara] {
                if lado.len() > MAX_MUESTRAS {
                    return Err(format!("«{}»: {} muestras en un lado", e.id, lado.len()));
                }
                if lado.iter().any(|m| m.is_empty() || m.len() > MAX_MUESTRA) {
                    return Err(format!(
                        "«{}»: muestra vacia o de mas de {MAX_MUESTRA} bytes",
                        e.id
                    ));
                }
            }
            if e.modo == Modo::Imponer && !e.medicion.permite_imponer() {
                return Err(format!(
                    "«{}» pide imponer sin numeros: {} muestras benignas y {} falso(s) \
                     positivo(s); hacen falta al menos {MIN_MUESTRAS_IMPONER} muestras y no mas \
                     de {FP_POR_MILLON_MAX} por millon",
                    e.id, e.medicion.muestras_benignas, e.medicion.falsos_positivos
                ));
            }
        }
        Ok(())
    }
}

fn codificar_entradas(e: &mut Escritor, entradas: &[Entrada]) {
    e.cuenta(entradas.len());
    for x in entradas {
        x.codificar(e);
    }
}

/// Un paquete sellado: el cuerpo y su firma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sellado {
    /// El cuerpo ([`Manifiesto::a_bytes`]).
    pub cuerpo: Vec<u8>,
    /// Firma hibrida del cuerpo bajo su contexto.
    pub firma: Vec<u8>,
}

impl Sellado {
    /// Los bytes que viajan y se guardan.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut e = Escritor::nuevo();
        e.bytes(&self.cuerpo);
        e.bytes(&self.firma);
        e.fin()
    }

    /// Separa cuerpo y firma. No interpreta el cuerpo: eso va despues de la firma.
    ///
    /// # Errores
    /// [`ErrorFormato`] si las longitudes no cuadran o pasan de los limites.
    pub fn de_bytes(b: &[u8]) -> Result<Sellado, ErrorFormato> {
        if b.len() > MAX_SELLADO {
            return Err(ErrorFormato(format!(
                "{} bytes: mas que el maximo de un paquete ({MAX_SELLADO})",
                b.len()
            )));
        }
        let mut l = Lector::nuevo(b);
        let cuerpo = l.bytes(MAX_SELLADO, "cuerpo")?.to_vec();
        let firma = l.bytes(MAX_FIRMA, "firma")?.to_vec();
        l.terminar()?;
        Ok(Sellado { cuerpo, firma })
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn entrada(id: &str) -> Entrada {
        Entrada {
            id: id.into(),
            tipo: Tipo::Yara,
            modo: Modo::Auditoria,
            activa: true,
            coste: Coste {
                pasos_por_byte: 4,
                micros_por_64k: 2000,
            },
            medicion: Medicion::default(),
            fuente: b"rule x { condition: true }".to_vec(),
            dispara: vec![b"a".to_vec()],
            no_dispara: vec![b"b".to_vec()],
        }
    }

    fn manifiesto() -> Manifiesto {
        Manifiesto {
            canal: "estable".into(),
            epoca: 3,
            generado_ns: 1,
            anillo: Anillo::canario(&["equipo-1"]),
            escalera: Vec::new(),
            revierte_a: 0,
            entradas: vec![entrada("R1"), entrada("R2")],
        }
    }

    #[test]
    fn el_manifiesto_va_y_vuelve() {
        let m = manifiesto();
        assert_eq!(Manifiesto::de_bytes(&m.a_bytes()).unwrap(), m);
        m.comprobar_estructura().unwrap();
    }

    #[test]
    fn la_huella_del_contenido_no_depende_del_anillo() {
        let a = manifiesto();
        let mut b = a.clone();
        b.anillo = Anillo::Flota;
        b.epoca = 9;
        assert_eq!(a.sha_contenido(), b.sha_contenido());
        assert_ne!(a.a_bytes(), b.a_bytes());
    }

    #[test]
    fn imponer_sin_numeros_no_se_admite() {
        let mut m = manifiesto();
        m.entradas[0].modo = Modo::Imponer;
        assert!(m
            .comprobar_estructura()
            .unwrap_err()
            .contains("sin numeros"));
        m.entradas[0].medicion = Medicion {
            muestras_benignas: MIN_MUESTRAS_IMPONER,
            falsos_positivos: 1,
        };
        m.comprobar_estructura().unwrap();
        m.entradas[0].medicion.falsos_positivos = 2;
        assert!(m.comprobar_estructura().is_err());
    }

    #[test]
    fn ids_repetidos_o_invalidos_no_se_admiten() {
        let mut m = manifiesto();
        m.entradas[1].id = "R1".into();
        assert!(m.comprobar_estructura().is_err());
        m.entradas[1].id = "con espacio".into();
        assert!(m.comprobar_estructura().is_err());
    }

    #[test]
    fn el_sellado_va_y_vuelve_y_rechaza_colas() {
        let s = Sellado {
            cuerpo: vec![1, 2, 3],
            firma: vec![9; 10],
        };
        let mut b = s.a_bytes();
        assert_eq!(Sellado::de_bytes(&b).unwrap(), s);
        b.push(0);
        assert!(Sellado::de_bytes(&b).is_err());
    }
}
