//! AML: el codigo que el firmware le da al sistema operativo para que lo ejecute.
//!
//! # Por que un auditor de firmware tiene que leer AML
//!
//! La DSDT y las SSDT no son solo descripciones: llevan **metodos** en un
//! bytecode (AML) que el interprete ACPI del kernel ejecuta con privilegio de
//! kernel. Algunos los ejecuta **solo, sin que nadie lo pida**: `_INI` y `_STA`
//! de cada dispositivo al arrancar, `_REG` al conectar una region, `_PTS` y
//! `_WAK` en cada suspension, los manejadores de eventos `_Lxx`/`_Exx`. Un metodo
//! de esos que lee y escribe memoria fisica, que dispara un SMI o que carga una
//! tabla nueva desde una region de memoria es una forma de ejecutar codigo en el
//! kernel **desde el firmware** en cada arranque, sin un solo fichero en disco.
//!
//! CHIPSEC no lee AML. `iasl` lo desensambla para que lo lea una persona. Aqui se
//! desensambla para **inventariar lo que se ejecuta solo** y compararlo contra una
//! linea base, igual que los ficheros FFS de la ROM.
//!
//! # La ambiguedad de AML, y como se resuelve
//!
//! En AML, una invocacion de metodo es un nombre seguido de sus argumentos, y el
//! bytecode **no dice cuantos**: hay que saber del espacio de nombres cuantos
//! declara ese metodo. Por eso el analisis va en dos pasadas:
//!
//! 1. **Registro**: se recorre la estructura (ambitos, dispositivos, bloques
//!    `If` de nivel de tabla) sin entrar en los cuerpos de los metodos, y se
//!    apunta cada definicion con su numero de argumentos. Las declaraciones
//!    `External` aportan el suyo.
//! 2. **Analisis**: se decodifica todo, cuerpos incluidos, con el espacio de
//!    nombres completo. Una llamada a un nombre que no esta en ningun sitio se
//!    decodifica con cero argumentos y se CUENTA como sin resolver.
//!
//! # Robustez, porque la entrada la escribe quien se audita
//!
//! Cada `PkgLength` se comprueba contra el final de su contenedor; hay un
//! presupuesto de operaciones y una profundidad maxima. Un error dentro de un
//! contenedor con longitud conocida se ANOTA y el recorrido sigue despues de el:
//! un metodo mal formado no tapa los doscientos siguientes. Y lo que no se pudo
//! decodificar se DICE: la cobertura es parte del resultado.
//!
//! # Estatico frente a cargado
//!
//! Buena parte de las definiciones viven dentro de bloques `If` que el interprete
//! resuelve al cargar la tabla. El analisis estatico las ve todas —es lo que ve
//! `iasl -d`— y marca como **condicionales** las que dependen de un `If`. Lo que
//! acaba cargado depende de valores de la maquina viva, y no se adivina.

use std::collections::{BTreeMap, BTreeSet};

use aegis_firmware::report::CheckState;
use sha2::{Digest, Sha256};

use crate::acpi::ConjuntoTablas;
use crate::comprobacion::{Comprobacion, Naturaleza, Superficie};
use crate::linea_base::LineaBase;

/// Presupuesto de operaciones por analisis completo.
pub const PRESUPUESTO_OPERACIONES: u64 = 20_000_000;
/// Profundidad maxima de anidamiento.
pub const PROFUNDIDAD_MAXIMA: u32 = 128;
/// Tope de errores que se conservan con detalle.
pub const MAX_ERRORES: usize = 256;

/// Espacio de direccion de una region de operacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EspacioRegion {
    /// Memoria fisica del sistema.
    MemoriaSistema,
    /// Puertos de E/S.
    EntradaSalida,
    /// Configuracion PCI.
    ConfigPci,
    /// Controlador embebido.
    ControladorEmbebido,
    /// SMBus.
    SmBus,
    /// CMOS.
    Cmos,
    /// Otro espacio, con su numero.
    Otro(u8),
}

impl EspacioRegion {
    /// Del byte de la especificacion.
    #[must_use]
    pub const fn de_byte(b: u8) -> EspacioRegion {
        match b {
            0 => EspacioRegion::MemoriaSistema,
            1 => EspacioRegion::EntradaSalida,
            2 => EspacioRegion::ConfigPci,
            3 => EspacioRegion::ControladorEmbebido,
            4 => EspacioRegion::SmBus,
            5 => EspacioRegion::Cmos,
            o => EspacioRegion::Otro(o),
        }
    }
}

/// Lo que hace un metodo con consecuencias fuera del interprete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capacidad {
    /// Lee memoria fisica a traves de un campo.
    LeeMemoria,
    /// Escribe memoria fisica a traves de un campo.
    EscribeMemoria,
    /// Lee puertos de E/S.
    LeePuertos,
    /// Escribe puertos de E/S.
    EscribePuertos,
    /// Escribe en el puerto `SMI_CMD` de la FADT: dispara codigo de SMM.
    DisparaSmi,
    /// Accede a la configuracion PCI.
    ConfigPci,
    /// Carga una tabla (`Load`, `LoadTable`): codigo AML nuevo.
    CargaCodigo,
    /// Crea una region de operacion dentro del metodo, con direccion calculada.
    RegionDinamica,
    /// Detiene el sistema (`Fatal`).
    Fatal,
}

impl Capacidad {
    /// Nombre estable.
    #[must_use]
    pub const fn nombre(self) -> &'static str {
        match self {
            Capacidad::LeeMemoria => "lee-memoria",
            Capacidad::EscribeMemoria => "escribe-memoria",
            Capacidad::LeePuertos => "lee-puertos",
            Capacidad::EscribePuertos => "escribe-puertos",
            Capacidad::DisparaSmi => "dispara-smi",
            Capacidad::ConfigPci => "config-pci",
            Capacidad::CargaCodigo => "carga-codigo",
            Capacidad::RegionDinamica => "region-dinamica",
            Capacidad::Fatal => "fatal",
        }
    }
}

/// Cuando se ejecuta un metodo sin que nadie lo invoque explicitamente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Momento {
    /// Al enumerar y arrancar (`_INI`, `_STA`, `_REG`, `_OSC`, `_PIC`).
    Arranque,
    /// Al suspender o despertar (`_PTS`, `_WAK`, `_TTS`, `_BFS`, `_GTS`, `_SWS`).
    Suspension,
    /// Ante un evento de hardware (`_Lxx`, `_Exx`, `_Qxx`).
    Evento,
    /// Solo cuando alguien lo llama.
    BajoDemanda,
}

/// Un metodo AML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metodo {
    /// Ruta completa (`\_SB_.PCI0._INI`).
    pub ruta: String,
    /// Tabla donde esta.
    pub tabla: String,
    /// Numero de argumentos.
    pub argumentos: u8,
    /// Si es serializado.
    pub serializado: bool,
    /// Si su definicion depende de un `If` o un `While`.
    pub condicional: bool,
    /// Desplazamiento dentro del AML de la tabla.
    pub desplazamiento: usize,
    /// Tamano del cuerpo (banderas incluidas).
    pub largo: usize,
    /// SHA-256 del cuerpo: lo que se compara contra la linea base.
    pub sha256: [u8; 32],
    /// Si el cuerpo se decodifico entero.
    pub decodificado: bool,
    /// Lo que hace.
    pub capacidades: BTreeSet<Capacidad>,
}

impl Metodo {
    /// La ruta como la escriben `iasl` y `acpiexec` (`\_SB.PCI0._INI`).
    #[must_use]
    pub fn ruta_legible(&self) -> String {
        legible(&self.ruta)
    }

    /// El ultimo segmento, sin relleno.
    #[must_use]
    pub fn nombre(&self) -> String {
        let s = self.ruta.rsplit(['.', '\\']).next().unwrap_or("");
        recortar(s)
    }

    /// Cuando se ejecuta solo.
    #[must_use]
    pub fn momento(&self) -> Momento {
        let seg = self.ruta.rsplit(['.', '\\']).next().unwrap_or("");
        match seg {
            "_INI" | "_STA" | "_REG" | "_OSC" | "_PIC" => Momento::Arranque,
            "_PTS" | "_WAK" | "_TTS" | "_BFS" | "_GTS" | "_SWS" => Momento::Suspension,
            s if s.len() == 4
                && (s.starts_with("_L") || s.starts_with("_E") || s.starts_with("_Q"))
                && s[2..].chars().all(|c| c.is_ascii_hexdigit()) =>
            {
                Momento::Evento
            }
            _ => Momento::BajoDemanda,
        }
    }

    /// El hash en hexadecimal.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        self.sha256.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Una region de operacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    /// Ruta.
    pub ruta: String,
    /// Espacio.
    pub espacio: EspacioRegion,
    /// Direccion, si es constante.
    pub direccion: Option<u64>,
    /// Longitud, si es constante.
    pub longitud: Option<u64>,
    /// Si se define dentro de un metodo (direccion calculada en ejecucion).
    pub dinamica: bool,
}

#[derive(Debug, Clone)]
struct Campo {
    region: Option<String>,
    bit: u64,
}

/// Un error de decodificacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorAml {
    /// Tabla.
    pub tabla: String,
    /// Desplazamiento.
    pub posicion: usize,
    /// Que paso.
    pub motivo: String,
}

type Res<T> = Result<T, ErrorAml>;

/// El resultado del analisis de todas las tablas AML.
#[derive(Debug, Clone, Default)]
pub struct Espacio {
    /// Los metodos, ordenados por ruta y tabla.
    pub metodos: Vec<Metodo>,
    /// Las regiones de operacion.
    pub regiones: Vec<Region>,
    /// Dispositivos definidos.
    pub dispositivos: usize,
    /// Objetos con nombre definidos, incluidos los que crean los metodos.
    pub objetos: usize,
    /// Errores de decodificacion.
    pub errores: Vec<ErrorAml>,
    /// Errores que no se conservaron por el tope.
    pub errores_omitidos: usize,
    /// Nombres referenciados que no estan definidos en ninguna tabla.
    pub sin_resolver: usize,
    /// Si se agoto el presupuesto de operaciones.
    pub presupuesto_agotado: bool,
    /// Tablas analizadas.
    pub tablas: Vec<String>,
}

impl Espacio {
    /// Metodos que el sistema ejecuta solo.
    #[must_use]
    pub fn automaticos(&self) -> Vec<&Metodo> {
        self.metodos
            .iter()
            .filter(|m| m.momento() != Momento::BajoDemanda)
            .collect()
    }

    /// Cuantos metodos se decodificaron enteros.
    #[must_use]
    pub fn decodificados(&self) -> usize {
        self.metodos.iter().filter(|m| m.decodificado).count()
    }

    /// Si todo se decodifico.
    #[must_use]
    pub fn completo(&self) -> bool {
        self.errores.is_empty() && self.errores_omitidos == 0 && !self.presupuesto_agotado
    }
}

/// Quita el relleno `_` final de un segmento (`_SB_` → `_SB`).
fn recortar(seg: &str) -> String {
    let t = seg.trim_end_matches('_');
    if t.is_empty() {
        seg.to_string()
    } else {
        t.to_string()
    }
}

/// Una ruta interna a la forma de `iasl`.
#[must_use]
pub fn legible(ruta: &str) -> String {
    let resto = ruta.strip_prefix('\\').unwrap_or(ruta);
    if resto.is_empty() {
        return "\\".into();
    }
    format!(
        "\\{}",
        resto.split('.').map(recortar).collect::<Vec<_>>().join(".")
    )
}

fn segs_de(ruta: &str) -> Vec<String> {
    let r = ruta.strip_prefix('\\').unwrap_or(ruta);
    if r.is_empty() {
        Vec::new()
    } else {
        r.split('.').map(str::to_string).collect()
    }
}

fn ruta_de(segs: &[String]) -> String {
    format!("\\{}", segs.join("."))
}

#[derive(Debug, Clone)]
struct Nombre {
    absoluto: bool,
    arriba: usize,
    segs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fase {
    Registro,
    Analisis,
}

#[derive(Debug, Clone)]
struct Ctx {
    ambito: Vec<String>,
    metodo: Option<usize>,
    condicional: bool,
    profundidad: u32,
}

impl Ctx {
    fn hijo(&self, ambito: Vec<String>) -> Res<Ctx> {
        Ok(Ctx {
            ambito,
            metodo: self.metodo,
            condicional: self.condicional,
            profundidad: self.profundidad + 1,
        })
    }
}

#[derive(Debug, Default)]
struct Estado {
    nombres: BTreeSet<String>,
    argumentos: BTreeMap<String, u8>,
    campos: BTreeMap<String, Campo>,
    regiones: BTreeMap<String, Region>,
    metodos: Vec<Metodo>,
    dispositivos: usize,
    errores: Vec<ErrorAml>,
    errores_omitidos: usize,
    sin_resolver: BTreeSet<String>,
    operaciones: u64,
    agotado: bool,
    smi_cmd: Option<u32>,
}

struct Dec<'a, 'e> {
    b: &'a [u8],
    tabla: &'a str,
    fase: Fase,
    e: &'e mut Estado,
}

/// Uso de un nombre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Uso {
    /// En posicion de argumento: si es un metodo, se invoca.
    Invocar,
    /// Referencia que se lee (sin invocar).
    Leer,
    /// Referencia que se escribe.
    Escribir,
}

impl Dec<'_, '_> {
    fn error(&self, posicion: usize, motivo: impl Into<String>) -> ErrorAml {
        ErrorAml {
            tabla: self.tabla.to_string(),
            posicion,
            motivo: motivo.into(),
        }
    }

    fn anotar(&mut self, err: ErrorAml, cx: &Ctx) {
        if let Some(i) = cx.metodo {
            if let Some(m) = self.e.metodos.get_mut(i) {
                m.decodificado = false;
            }
        }
        // Solo la fase de analisis anota: la de registro ve lo mismo y contarlo
        // dos veces inflaria la cifra de errores.
        if self.fase == Fase::Analisis {
            if self.e.errores.len() < MAX_ERRORES {
                self.e.errores.push(err);
            } else {
                self.e.errores_omitidos += 1;
            }
        }
    }

    fn byte(&self, p: usize, fin: usize) -> Res<u8> {
        if p >= fin {
            return Err(self.error(p, "fin del contenedor antes de lo esperado"));
        }
        self.b
            .get(p)
            .copied()
            .ok_or_else(|| self.error(p, "fin de la tabla"))
    }

    fn saltar(&self, p: usize, n: usize, fin: usize) -> Res<usize> {
        let q = p
            .checked_add(n)
            .ok_or_else(|| self.error(p, "desbordamiento"))?;
        if q > fin {
            return Err(self.error(p, format!("faltan {} bytes", q - fin)));
        }
        Ok(q)
    }

    /// `PkgLength`: devuelve el final absoluto del paquete y la posicion tras la
    /// codificacion.
    fn paquete(&self, p: usize, fin: usize) -> Res<(usize, usize)> {
        let (valor, usados) = self.longitud(p, fin)?;
        let final_ = p
            .checked_add(valor)
            .ok_or_else(|| self.error(p, "PkgLength desborda"))?;
        if final_ > fin {
            return Err(self.error(p, format!("PkgLength {valor} se sale del contenedor")));
        }
        if final_ < p + usados {
            return Err(self.error(p, "PkgLength menor que su propia codificacion"));
        }
        Ok((final_, p + usados))
    }

    /// La codificacion de `PkgLength`, sin interpretarla como final.
    fn longitud(&self, p: usize, fin: usize) -> Res<(usize, usize)> {
        let lead = self.byte(p, fin)?;
        let n = (lead >> 6) as usize;
        if n == 0 {
            return Ok(((lead & 0x3F) as usize, 1));
        }
        if lead & 0x30 != 0 {
            return Err(self.error(p, "PkgLength con bits reservados"));
        }
        let mut v = (lead & 0x0F) as usize;
        for i in 1..=n {
            v |= (self.byte(p + i, fin)? as usize) << (4 + 8 * (i - 1));
        }
        Ok((v, n + 1))
    }

    fn seg(&self, p: usize, fin: usize) -> Res<String> {
        let s = self
            .b
            .get(p..self.saltar(p, 4, fin)?)
            .ok_or_else(|| self.error(p, "NameSeg truncado"))?;
        let valido = (s[0].is_ascii_uppercase() || s[0] == b'_')
            && s[1..]
                .iter()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_');
        if !valido {
            return Err(self.error(p, format!("NameSeg invalido {s:02x?}")));
        }
        Ok(String::from_utf8_lossy(s).to_string())
    }

    fn nombre(&self, mut p: usize, fin: usize) -> Res<(Nombre, usize)> {
        let mut n = Nombre {
            absoluto: false,
            arriba: 0,
            segs: Vec::new(),
        };
        if self.byte(p, fin)? == b'\\' {
            n.absoluto = true;
            p += 1;
        } else {
            while self.byte(p, fin)? == b'^' {
                n.arriba += 1;
                p += 1;
            }
        }
        match self.byte(p, fin)? {
            0x00 => Ok((n, p + 1)),
            0x2E => {
                n.segs.push(self.seg(p + 1, fin)?);
                n.segs.push(self.seg(p + 5, fin)?);
                Ok((n, p + 9))
            }
            0x2F => {
                let c = self.byte(p + 1, fin)? as usize;
                let mut q = p + 2;
                for _ in 0..c {
                    n.segs.push(self.seg(q, fin)?);
                    q += 4;
                }
                Ok((n, q))
            }
            _ => {
                n.segs.push(self.seg(p, fin)?);
                Ok((n, p + 4))
            }
        }
    }

    /// La ruta que DEFINE un nombre en un ambito (sin busqueda).
    fn definir(ambito: &[String], n: &Nombre) -> Vec<String> {
        let mut base: Vec<String> = if n.absoluto {
            Vec::new()
        } else {
            let hasta = ambito.len().saturating_sub(n.arriba);
            ambito[..hasta].to_vec()
        };
        base.extend(n.segs.iter().cloned());
        base
    }

    /// La ruta a la que se REFIERE un nombre: los nombres de un segmento sin
    /// prefijo se buscan hacia arriba, ambito a ambito, como manda la norma.
    fn resolver(&self, ambito: &[String], n: &Nombre) -> String {
        if !n.absoluto && n.arriba == 0 && n.segs.len() == 1 {
            for i in (0..=ambito.len()).rev() {
                let mut c = ambito[..i].to_vec();
                c.push(n.segs[0].clone());
                let r = ruta_de(&c);
                if self.e.nombres.contains(&r) {
                    return r;
                }
            }
        }
        ruta_de(&Self::definir(ambito, n))
    }

    /// Apunta una definicion. En las dos pasadas: la segunda es la unica que
    /// entra en los cuerpos de los metodos, y los nombres que un metodo crea al
    /// ejecutarse (los `_T_n` con los que `iasl` compila un `Switch`, por
    /// ejemplo) tienen que existir para lo que viene detras en ese mismo cuerpo.
    /// Sin esto se contarian como «sin resolver» nombres que estan ahi.
    fn registrar(&mut self, ruta: &str) {
        self.e.nombres.insert(ruta.to_string());
    }

    fn marcar(&mut self, cx: &Ctx, c: Capacidad) {
        if self.fase != Fase::Analisis {
            return;
        }
        if let Some(m) = cx.metodo.and_then(|i| self.e.metodos.get_mut(i)) {
            m.capacidades.insert(c);
        }
    }

    fn gastar(&mut self, p: usize) -> Res<()> {
        self.e.operaciones += 1;
        if self.e.operaciones > PRESUPUESTO_OPERACIONES {
            self.e.agotado = true;
            return Err(self.error(p, "presupuesto de operaciones agotado"));
        }
        Ok(())
    }

    fn lista(&mut self, mut p: usize, fin: usize, cx: &Ctx) -> Res<()> {
        while p < fin {
            p = self.termino(p, fin, cx)?;
        }
        Ok(())
    }

    /// Decodifica el cuerpo de un contenedor de final conocido; si falla, anota el
    /// error y devuelve el final: un contenedor mal formado no tapa a sus vecinos.
    fn contenedor(&mut self, p: usize, fin: usize, cx: &Ctx) -> usize {
        if let Err(e) = self.lista(p, fin, cx) {
            let agotado = self.e.agotado;
            self.anotar(e, cx);
            if agotado {
                return fin;
            }
        }
        fin
    }

    fn constante(&self, p: usize) -> Option<u64> {
        let b = self.b;
        match *b.get(p)? {
            0x00 => Some(0),
            0x01 => Some(1),
            0xFF => Some(u64::MAX),
            0x0A => b.get(p + 1).map(|x| u64::from(*x)),
            0x0B => b
                .get(p + 1..p + 3)
                .map(|s| u64::from(u16::from_le_bytes([s[0], s[1]]))),
            0x0C => b
                .get(p + 1..p + 5)
                .map(|s| u64::from(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))),
            0x0E => b
                .get(p + 1..p + 9)
                .and_then(|s| s.try_into().ok())
                .map(u64::from_le_bytes),
            _ => None,
        }
    }

    fn es_inicio_nombre(op: u8) -> bool {
        matches!(op, b'\\' | b'^' | 0x2E | 0x2F | b'A'..=b'Z' | b'_')
    }

    /// Un nombre en uso: resuelve, anota capacidades si es un campo, e invoca si
    /// es un metodo y el uso lo pide.
    fn referencia(&mut self, p: usize, fin: usize, cx: &Ctx, uso: Uso) -> Res<usize> {
        let (n, mut q) = self.nombre(p, fin)?;
        let ruta = self.resolver(&cx.ambito, &n);
        if self.fase == Fase::Analisis
            && !self.e.nombres.contains(&ruta)
            && !self.e.argumentos.contains_key(&ruta)
            && !n.segs.is_empty()
        {
            self.e.sin_resolver.insert(ruta.clone());
        }
        if let Some(campo) = self.e.campos.get(&ruta).cloned() {
            if let Some(region) = campo.region.and_then(|r| self.e.regiones.get(&r).cloned()) {
                let escribe = uso == Uso::Escribir;
                match region.espacio {
                    EspacioRegion::MemoriaSistema => self.marcar(
                        cx,
                        if escribe {
                            Capacidad::EscribeMemoria
                        } else {
                            Capacidad::LeeMemoria
                        },
                    ),
                    EspacioRegion::EntradaSalida => {
                        self.marcar(
                            cx,
                            if escribe {
                                Capacidad::EscribePuertos
                            } else {
                                Capacidad::LeePuertos
                            },
                        );
                        let puerto = region.direccion.map(|d| d + campo.bit / 8);
                        if escribe && puerto.is_some() && puerto == self.e.smi_cmd.map(u64::from) {
                            self.marcar(cx, Capacidad::DisparaSmi);
                        }
                    }
                    EspacioRegion::ConfigPci => self.marcar(cx, Capacidad::ConfigPci),
                    _ => {}
                }
            }
        }
        if uso == Uso::Invocar {
            let args = self.e.argumentos.get(&ruta).copied().unwrap_or(0);
            for _ in 0..args {
                q = self.termino(q, fin, cx)?;
            }
        }
        Ok(q)
    }

    fn supernombre(&mut self, p: usize, fin: usize, cx: &Ctx, uso: Uso) -> Res<usize> {
        let op = self.byte(p, fin)?;
        match op {
            0x60..=0x6E => Ok(p + 1),
            0x5B if self.byte(p + 1, fin)? == 0x31 => Ok(p + 2),
            0x71 | 0x83 | 0x88 => self.termino(p, fin, cx),
            op if Self::es_inicio_nombre(op) => self.referencia(p, fin, cx, uso),
            op => Err(self.error(p, format!("se esperaba un SuperName y llego {op:#04x}"))),
        }
    }

    fn destino(&mut self, p: usize, fin: usize, cx: &Ctx) -> Res<usize> {
        if self.byte(p, fin)? == 0x00 {
            return Ok(p + 1);
        }
        self.supernombre(p, fin, cx, Uso::Escribir)
    }

    fn args(&mut self, mut p: usize, fin: usize, cx: &Ctx, n: usize) -> Res<usize> {
        for _ in 0..n {
            p = self.termino(p, fin, cx)?;
        }
        Ok(p)
    }

    fn definicion(&mut self, p: usize, fin: usize, cx: &Ctx) -> Res<(String, usize)> {
        let (n, q) = self.nombre(p, fin)?;
        let ruta = ruta_de(&Self::definir(&cx.ambito, &n));
        self.registrar(&ruta);
        Ok((ruta, q))
    }

    fn termino(&mut self, p: usize, fin: usize, cx: &Ctx) -> Res<usize> {
        self.gastar(p)?;
        if cx.profundidad > PROFUNDIDAD_MAXIMA {
            return Err(self.error(p, "anidamiento demasiado profundo"));
        }
        let op = self.byte(p, fin)?;
        match op {
            0x00 | 0x01 | 0xFF | 0x60..=0x6E | 0x9F | 0xA3 | 0xA5 | 0xCC => Ok(p + 1),
            0x0A => self.saltar(p, 2, fin),
            0x0B => self.saltar(p, 3, fin),
            0x0C => self.saltar(p, 5, fin),
            0x0E => self.saltar(p, 9, fin),
            0x0D => {
                let resto = self.b.get(p + 1..fin).unwrap_or(&[]);
                let n = resto
                    .iter()
                    .position(|c| *c == 0)
                    .ok_or_else(|| self.error(p, "cadena sin terminador"))?;
                Ok(p + 2 + n)
            }
            0x06 => {
                let (_, q) = self.nombre(p + 1, fin)?;
                let (_, r) = self.definicion(q, fin, cx)?;
                Ok(r)
            }
            0x08 => {
                let (_, q) = self.definicion(p + 1, fin, cx)?;
                self.dato(q, fin, cx)
            }
            0x10 => {
                let (final_, q) = self.paquete(p + 1, fin)?;
                let (n, r) = self.nombre(q, final_)?;
                let ruta = self.resolver(&cx.ambito, &n);
                let hijo = cx.hijo(segs_de(&ruta))?;
                Ok(self.contenedor(r, final_, &hijo))
            }
            0x11 => {
                let (final_, q) = self.paquete(p + 1, fin)?;
                self.termino(q, final_, cx)?;
                Ok(final_)
            }
            0x12 | 0x13 => {
                let (final_, q) = self.paquete(p + 1, fin)?;
                let mut r = if op == 0x12 {
                    self.saltar(q, 1, final_)?
                } else {
                    self.termino(q, final_, cx)?
                };
                while r < final_ {
                    r = self.dato(r, final_, cx)?;
                }
                Ok(final_)
            }
            0x14 => self.metodo(p, fin, cx),
            0x15 => {
                let (n, q) = self.nombre(p + 1, fin)?;
                let tipo = self.byte(q, fin)?;
                let args = self.byte(q + 1, fin)?;
                let ruta = ruta_de(&Self::definir(&cx.ambito, &n));
                if tipo == 8 && self.fase == Fase::Registro {
                    self.e.argumentos.entry(ruta).or_insert(args & 0x7);
                }
                Ok(q + 2)
            }
            op if Self::es_inicio_nombre(op) => self.referencia(p, fin, cx, Uso::Invocar),
            0x5B => self.extendido(p, fin, cx),
            0x70 => {
                let q = self.termino(p + 1, fin, cx)?;
                self.destino(q, fin, cx)
            }
            0x71 | 0x87 | 0x8E => self.supernombre(p + 1, fin, cx, Uso::Leer),
            0x75 | 0x76 => self.supernombre(p + 1, fin, cx, Uso::Escribir),
            0x72..=0x74 | 0x77 | 0x79..=0x7F | 0x84 | 0x85 | 0x88 => {
                let q = self.args(p + 1, fin, cx, 2)?;
                self.destino(q, fin, cx)
            }
            0x78 => {
                let q = self.args(p + 1, fin, cx, 2)?;
                let r = self.destino(q, fin, cx)?;
                self.destino(r, fin, cx)
            }
            0x80..=0x82 | 0x96..=0x99 => {
                let q = self.termino(p + 1, fin, cx)?;
                self.destino(q, fin, cx)
            }
            0x83 | 0x92 | 0xA4 => self.termino(p + 1, fin, cx),
            0x86 => {
                let q = self.supernombre(p + 1, fin, cx, Uso::Leer)?;
                self.termino(q, fin, cx)
            }
            0x89 => {
                let q = self.termino(p + 1, fin, cx)?;
                let q = self.saltar(q, 1, fin)?;
                let q = self.termino(q, fin, cx)?;
                let q = self.saltar(q, 1, fin)?;
                self.args(q, fin, cx, 2)
            }
            0x8A..=0x8D | 0x8F => {
                let q = self.args(p + 1, fin, cx, 2)?;
                let (_, r) = self.definicion(q, fin, cx)?;
                Ok(r)
            }
            0x90 | 0x91 | 0x93..=0x95 => self.args(p + 1, fin, cx, 2),
            0x9C => {
                let q = self.args(p + 1, fin, cx, 2)?;
                self.destino(q, fin, cx)
            }
            0x9D => {
                let q = self.termino(p + 1, fin, cx)?;
                self.supernombre(q, fin, cx, Uso::Escribir)
            }
            0x9E => {
                let q = self.args(p + 1, fin, cx, 3)?;
                self.destino(q, fin, cx)
            }
            0xA0 | 0xA2 => {
                let (final_, q) = self.paquete(p + 1, fin)?;
                let mut hijo = cx.hijo(cx.ambito.clone())?;
                hijo.condicional = true;
                match self.termino(q, final_, &hijo) {
                    Ok(r) => Ok(self.contenedor(r, final_, &hijo)),
                    Err(e) => {
                        self.anotar(e, &hijo);
                        Ok(final_)
                    }
                }
            }
            0xA1 => {
                let (final_, q) = self.paquete(p + 1, fin)?;
                let mut hijo = cx.hijo(cx.ambito.clone())?;
                hijo.condicional = true;
                Ok(self.contenedor(q, final_, &hijo))
            }
            op => Err(self.error(p, format!("opcode desconocido {op:#04x}"))),
        }
    }

    /// Un elemento de datos: en un `Package` un nombre es una referencia, no una
    /// invocacion.
    fn dato(&mut self, p: usize, fin: usize, cx: &Ctx) -> Res<usize> {
        let op = self.byte(p, fin)?;
        if Self::es_inicio_nombre(op) {
            self.referencia(p, fin, cx, Uso::Leer)
        } else {
            self.termino(p, fin, cx)
        }
    }

    fn metodo(&mut self, p: usize, fin: usize, cx: &Ctx) -> Res<usize> {
        let (final_, q) = self.paquete(p + 1, fin)?;
        let (n, r) = self.nombre(q, final_)?;
        let banderas = self.byte(r, final_)?;
        let ruta = ruta_de(&Self::definir(&cx.ambito, &n));
        if self.fase == Fase::Registro {
            self.e.nombres.insert(ruta.clone());
            self.e.argumentos.insert(ruta, banderas & 0x7);
            return Ok(final_);
        }
        let cuerpo = &self.b[r..final_];
        let indice = self.e.metodos.len();
        self.e.metodos.push(Metodo {
            ruta: ruta.clone(),
            tabla: self.tabla.to_string(),
            argumentos: banderas & 0x7,
            serializado: banderas & 0x8 != 0,
            condicional: cx.condicional,
            desplazamiento: p,
            largo: cuerpo.len(),
            sha256: Sha256::digest(cuerpo).into(),
            decodificado: true,
            capacidades: BTreeSet::new(),
        });
        let hijo = Ctx {
            ambito: segs_de(&ruta),
            metodo: Some(indice),
            condicional: cx.condicional,
            profundidad: cx.profundidad + 1,
        };
        Ok(self.contenedor(r + 1, final_, &hijo))
    }

    fn lista_campos(
        &mut self,
        mut p: usize,
        fin: usize,
        cx: &Ctx,
        region: Option<String>,
    ) -> Res<()> {
        let mut bit = 0u64;
        while p < fin {
            self.gastar(p)?;
            match self.byte(p, fin)? {
                0x00 => {
                    let (v, u) = self.longitud(p + 1, fin)?;
                    bit += v as u64;
                    p += 1 + u;
                }
                0x01 => p = self.saltar(p, 3, fin)?,
                0x02 => {
                    p = if self.byte(p + 1, fin)? == 0x11 {
                        self.termino(p + 1, fin, cx)?
                    } else {
                        self.nombre(p + 1, fin)?.1
                    };
                }
                0x03 => p = self.saltar(p, 4, fin)?,
                _ => {
                    let seg = self.seg(p, fin)?;
                    let (bits, u) = self.longitud(p + 4, fin)?;
                    let mut ruta = cx.ambito.clone();
                    ruta.push(seg);
                    let ruta = ruta_de(&ruta);
                    self.registrar(&ruta);
                    self.e.campos.insert(
                        ruta,
                        Campo {
                            region: region.clone(),
                            bit,
                        },
                    );
                    bit += bits as u64;
                    p += 4 + u;
                }
            }
        }
        Ok(())
    }

    fn extendido(&mut self, p: usize, fin: usize, cx: &Ctx) -> Res<usize> {
        let ext = self.byte(p + 1, fin)?;
        let q = p + 2;
        match ext {
            0x30 | 0x31 | 0x33 => Ok(q),
            0x01 => {
                let (_, r) = self.definicion(q, fin, cx)?;
                self.saltar(r, 1, fin)
            }
            0x02 => Ok(self.definicion(q, fin, cx)?.1),
            0x12 => {
                let r = self.supernombre(q, fin, cx, Uso::Leer)?;
                self.destino(r, fin, cx)
            }
            0x13 => {
                let r = self.args(q, fin, cx, 3)?;
                Ok(self.definicion(r, fin, cx)?.1)
            }
            0x1F => {
                self.marcar(cx, Capacidad::CargaCodigo);
                self.args(q, fin, cx, 6)
            }
            0x20 => {
                self.marcar(cx, Capacidad::CargaCodigo);
                let (_, r) = self.nombre(q, fin)?;
                self.destino(r, fin, cx)
            }
            0x21 | 0x22 => self.termino(q, fin, cx),
            0x23 => {
                let r = self.supernombre(q, fin, cx, Uso::Leer)?;
                self.saltar(r, 2, fin)
            }
            0x24 | 0x26 | 0x27 | 0x2A => self.supernombre(q, fin, cx, Uso::Leer),
            0x25 => {
                let r = self.supernombre(q, fin, cx, Uso::Leer)?;
                self.termino(r, fin, cx)
            }
            0x28 | 0x29 => {
                let r = self.termino(q, fin, cx)?;
                self.destino(r, fin, cx)
            }
            0x32 => {
                self.marcar(cx, Capacidad::Fatal);
                let r = self.saltar(q, 5, fin)?;
                self.termino(r, fin, cx)
            }
            0x80 => {
                let (ruta, r) = self.definicion(q, fin, cx)?;
                let espacio = EspacioRegion::de_byte(self.byte(r, fin)?);
                let direccion = self.constante(r + 1);
                let s = self.termino(r + 1, fin, cx)?;
                let longitud = self.constante(s);
                let t = self.termino(s, fin, cx)?;
                let dinamica = cx.metodo.is_some();
                if dinamica {
                    self.marcar(cx, Capacidad::RegionDinamica);
                }
                self.e.regiones.insert(
                    ruta.clone(),
                    Region {
                        ruta,
                        espacio,
                        direccion,
                        longitud,
                        dinamica,
                    },
                );
                Ok(t)
            }
            0x81 => {
                let (final_, r) = self.paquete(q, fin)?;
                let (n, s) = self.nombre(r, final_)?;
                let region = self.resolver(&cx.ambito, &n);
                let t = self.saltar(s, 1, final_)?;
                if let Err(e) = self.lista_campos(t, final_, cx, Some(region)) {
                    self.anotar(e, cx);
                }
                Ok(final_)
            }
            0x86 => {
                let (final_, r) = self.paquete(q, fin)?;
                let (_, s) = self.nombre(r, final_)?;
                let (_, t) = self.nombre(s, final_)?;
                let u = self.saltar(t, 1, final_)?;
                if let Err(e) = self.lista_campos(u, final_, cx, None) {
                    self.anotar(e, cx);
                }
                Ok(final_)
            }
            0x87 => {
                let (final_, r) = self.paquete(q, fin)?;
                let (n, s) = self.nombre(r, final_)?;
                let region = self.resolver(&cx.ambito, &n);
                let (_, t) = self.nombre(s, final_)?;
                let u = self.termino(t, final_, cx)?;
                let v = self.saltar(u, 1, final_)?;
                if let Err(e) = self.lista_campos(v, final_, cx, Some(region)) {
                    self.anotar(e, cx);
                }
                Ok(final_)
            }
            0x88 => {
                let (_, r) = self.definicion(q, fin, cx)?;
                self.args(r, fin, cx, 3)
            }
            0x82..=0x85 => {
                let (final_, r) = self.paquete(q, fin)?;
                let (ruta, s) = self.definicion(r, final_, cx)?;
                if ext == 0x82 && self.fase == Fase::Registro {
                    self.e.dispositivos += 1;
                }
                let cuerpo = match ext {
                    0x83 => self.saltar(s, 6, final_)?,
                    0x84 => self.saltar(s, 3, final_)?,
                    _ => s,
                };
                let hijo = cx.hijo(segs_de(&ruta))?;
                Ok(self.contenedor(cuerpo, final_, &hijo))
            }
            otro => Err(self.error(p, format!("opcode extendido desconocido 0x5b {otro:#04x}"))),
        }
    }
}

/// Analiza el AML de un conjunto de tablas (el cuerpo, sin la cabecera de 36
/// bytes), que comparten espacio de nombres.
#[must_use]
pub fn analizar(tablas: &[(String, &[u8])], smi_cmd: Option<u32>) -> Espacio {
    let mut e = Estado {
        smi_cmd: smi_cmd.filter(|p| *p != 0),
        ..Default::default()
    };
    // Nombres que el propio sistema define antes de cargar ninguna tabla.
    for (ruta, args) in [("\\_OSI", 1u8), ("\\_OS_", 0), ("\\_REV", 0), ("\\_GL_", 0)] {
        e.nombres.insert(ruta.into());
        if ruta == "\\_OSI" {
            e.argumentos.insert(ruta.into(), args);
        }
    }
    for ruta in ["\\_SB_", "\\_GPE", "\\_PR_", "\\_TZ_", "\\_SI_"] {
        e.nombres.insert(ruta.into());
    }
    let raiz = Ctx {
        ambito: Vec::new(),
        metodo: None,
        condicional: false,
        profundidad: 0,
    };
    for fase in [Fase::Registro, Fase::Analisis] {
        for (nombre, aml) in tablas {
            let mut d = Dec {
                b: aml,
                tabla: nombre,
                fase,
                e: &mut e,
            };
            d.contenedor(0, aml.len(), &raiz);
        }
    }
    let objetos = e.nombres.len();
    let mut metodos = e.metodos;
    metodos.sort_by(|a, b| {
        a.ruta
            .cmp(&b.ruta)
            .then(a.tabla.cmp(&b.tabla))
            .then(a.desplazamiento.cmp(&b.desplazamiento))
    });
    let mut regiones: Vec<Region> = e.regiones.into_values().collect();
    regiones.sort_by(|a, b| a.ruta.cmp(&b.ruta));
    Espacio {
        metodos,
        regiones,
        dispositivos: e.dispositivos,
        objetos,
        errores: e.errores,
        errores_omitidos: e.errores_omitidos,
        sin_resolver: e.sin_resolver.len(),
        presupuesto_agotado: e.agotado,
        tablas: tablas.iter().map(|(n, _)| n.clone()).collect(),
    }
}

/// Analiza las DSDT y SSDT de un conjunto de tablas.
#[must_use]
pub fn analizar_conjunto(c: &ConjuntoTablas, smi_cmd: Option<u32>) -> Espacio {
    let tablas: Vec<(String, &[u8])> = c
        .tablas
        .iter()
        .filter(|t| &t.cabecera.firma == b"DSDT" || &t.cabecera.firma == b"SSDT")
        .map(|t| (t.ruta.display().to_string(), t.cuerpo()))
        .collect();
    analizar(&tablas, smi_cmd)
}

/// Las comprobaciones de AML.
#[must_use]
pub fn evaluar(esp: &Espacio, base: &LineaBase) -> Vec<Comprobacion> {
    let mut v = Vec::new();
    let decod = if esp.tablas.is_empty() {
        CheckState::NoAplicable("no hay DSDT ni SSDT".into())
    } else if esp.completo() {
        CheckState::Ok
    } else {
        let primero = esp
            .errores
            .first()
            .map(|e| format!(" Primero: {} @{:#x}: {}", e.tabla, e.posicion, e.motivo))
            .unwrap_or_default();
        CheckState::Indeterminado(format!(
            "{} de {} metodos no se decodificaron enteros ({} error(es){}).{primero}",
            esp.metodos.len() - esp.decodificados(),
            esp.metodos.len(),
            esp.errores.len() + esp.errores_omitidos,
            if esp.presupuesto_agotado {
                ", presupuesto agotado"
            } else {
                ""
            }
        ))
    };
    v.push(Comprobacion::nueva(
        "aml-decodificacion",
        Superficie::Aml,
        Naturaleza::Compromiso,
        decod,
    ));

    let auto = esp.automaticos();
    let estado = if esp.tablas.is_empty() {
        CheckState::NoAplicable("no hay DSDT ni SSDT".into())
    } else if base.metodos_aml.is_empty() && base.revocados.is_empty() {
        let carga = auto
            .iter()
            .filter(|m| m.capacidades.contains(&Capacidad::CargaCodigo))
            .count();
        let smi = auto
            .iter()
            .filter(|m| m.capacidades.contains(&Capacidad::DisparaSmi))
            .count();
        let mem = auto
            .iter()
            .filter(|m| m.capacidades.contains(&Capacidad::EscribeMemoria))
            .count();
        CheckState::Indeterminado(format!(
            "sin linea base de AML: {} metodo(s) que el sistema ejecuta solo ({carga} cargan \
             codigo, {smi} disparan SMI, {mem} escriben memoria fisica) inventariados, pero no \
             se puede decir si son los que deberian",
            auto.len()
        ))
    } else {
        let mut alterados = Vec::new();
        let mut revocados = Vec::new();
        for m in &auto {
            if let Some(n) = base.revocados.get(&m.sha256) {
                revocados.push(format!("{} = {n}", m.ruta_legible()));
            } else if let Some(entradas) = base.metodos_aml.get(&m.ruta_legible()) {
                if !entradas.iter().any(|e| e.sha256 == m.sha256) {
                    alterados.push(m.ruta_legible());
                }
            }
        }
        if revocados.is_empty() && alterados.is_empty() {
            CheckState::Ok
        } else {
            let mut partes = Vec::new();
            if !revocados.is_empty() {
                partes.push(format!(
                    "coinciden con AML malicioso conocido: {}",
                    revocados.join(", ")
                ));
            }
            if !alterados.is_empty() {
                partes.push(format!(
                    "metodos que el sistema ejecuta solo y cuyo cuerpo NO es el de la linea base: {}",
                    alterados.join(", ")
                ));
            }
            CheckState::Fallo(partes.join("; "))
        }
    };
    v.push(Comprobacion::nueva(
        "aml-metodos-automaticos",
        Superficie::Aml,
        Naturaleza::Compromiso,
        estado,
    ));
    v
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;

    /// Codifica un `PkgLength` que cubre `contenido` bytes MAS su propia
    /// codificacion, como exige la especificacion.
    pub(crate) fn pkg(contenido: usize) -> Vec<u8> {
        for n in 1..=4usize {
            let total = contenido + n;
            let cabe = match n {
                1 => total < 0x40,
                2 => total < 0x1000,
                3 => total < 0x10_0000,
                _ => total < 0x1000_0000,
            };
            if cabe {
                if n == 1 {
                    return vec![total as u8];
                }
                let mut v = vec![(((n - 1) as u8) << 6) | (total & 0xF) as u8];
                for i in 1..n {
                    v.push((total >> (4 + 8 * (i - 1))) as u8);
                }
                return v;
            }
        }
        unreachable!("contenido demasiado grande para una prueba")
    }

    pub(crate) fn con_pkg(op: &[u8], resto: &[u8]) -> Vec<u8> {
        let mut v = op.to_vec();
        v.extend(pkg(resto.len()));
        v.extend_from_slice(resto);
        v
    }

    pub(crate) fn metodo(nombre: &[u8; 4], args: u8, cuerpo: &[u8]) -> Vec<u8> {
        let mut r = nombre.to_vec();
        r.push(args);
        r.extend_from_slice(cuerpo);
        con_pkg(&[0x14], &r)
    }

    fn scope(nombre: &[u8], cuerpo: &[u8]) -> Vec<u8> {
        let mut r = nombre.to_vec();
        r.extend_from_slice(cuerpo);
        con_pkg(&[0x10], &r)
    }

    fn dispositivo(nombre: &[u8; 4], cuerpo: &[u8]) -> Vec<u8> {
        let mut r = nombre.to_vec();
        r.extend_from_slice(cuerpo);
        con_pkg(&[0x5B, 0x82], &r)
    }

    fn region(nombre: &[u8; 4], espacio: u8, dir: u32, largo: u8) -> Vec<u8> {
        let mut v = vec![0x5B, 0x80];
        v.extend_from_slice(nombre);
        v.push(espacio);
        v.push(0x0C);
        v.extend_from_slice(&dir.to_le_bytes());
        v.extend_from_slice(&[0x0A, largo]);
        v
    }

    fn campo(region: &[u8; 4], campos: &[(&[u8; 4], u8)]) -> Vec<u8> {
        let mut r = region.to_vec();
        r.push(0x01);
        for (n, bits) in campos {
            r.extend_from_slice(*n);
            r.push(*bits);
        }
        con_pkg(&[0x5B, 0x81], &r)
    }

    #[test]
    fn el_pkglength_se_codifica_y_decodifica_en_los_cuatro_tamanos() {
        for c in [0usize, 10, 62, 63, 100, 4000, 5000, 70_000, 2_000_000] {
            let mut aml = pkg(c);
            let usados = aml.len();
            aml.resize(usados + c, 0);
            let mut e = Estado::default();
            let d = Dec {
                b: &aml,
                tabla: "t",
                fase: Fase::Analisis,
                e: &mut e,
            };
            let (fin, q) = d.paquete(0, aml.len()).expect("valido");
            assert_eq!(fin, aml.len(), "contenido {c}");
            assert_eq!(q, usados);
        }
    }

    /// Una DSDT pequena pero con todo lo que importa: un _INI que escribe en el
    /// puerto SMI, un _STA que lee memoria, un metodo dentro de un If, un Load,
    /// y una invocacion con argumentos a un metodo definido DESPUES.
    fn dsdt() -> Vec<u8> {
        let mut aml = region(b"SMIP", 1, 0xB2, 1);
        aml.extend(region(b"MEMR", 0, 0x1FF000, 0xFF));
        aml.extend(campo(b"SMIP", &[(b"SMIC", 8)]));
        aml.extend(campo(b"MEMR", &[(b"BID0", 32)]));
        // \_SB.DEV0 { _INI: Store(0x42, SMIC); ADDR(1,2)  _STA: Return(BID0) }
        let ini = metodo(
            b"_INI",
            0,
            &[
                0x70, 0x0A, 0x42, b'S', b'M', b'I', b'C', b'A', b'D', b'D', b'R', 0x01, 0x0A, 0x02,
            ],
        );
        let sta = metodo(b"_STA", 0, &[0xA4, b'B', b'I', b'D', b'0']);
        let mut dev = ini;
        dev.extend(sta);
        let mut sb = dispositivo(b"DEV0", &dev);
        sb.extend(metodo(b"ADDR", 2, &[0xA4, 0x68]));
        aml.extend(scope(b"_SB_", &sb));
        // If (One) { Method (COND) { Load (MEMR, Local0) } }
        let cond = metodo(b"COND", 0, &[0x5B, 0x20, b'M', b'E', b'M', b'R', 0x60]);
        let mut si = vec![0x01];
        si.extend(cond);
        aml.extend(con_pkg(&[0xA0], &si));
        aml
    }

    fn por_ruta<'a>(e: &'a Espacio, ruta: &str) -> &'a Metodo {
        e.metodos
            .iter()
            .find(|m| m.ruta_legible() == ruta)
            .unwrap_or_else(|| {
                panic!(
                    "{ruta}: {:?}",
                    e.metodos
                        .iter()
                        .map(Metodo::ruta_legible)
                        .collect::<Vec<_>>()
                )
            })
    }

    #[test]
    fn una_dsdt_construida_segun_la_norma_se_decodifica_entera() {
        let aml = dsdt();
        let e = analizar(&[("DSDT".into(), &aml)], Some(0xB2));
        assert!(e.completo(), "{:?}", e.errores);
        assert_eq!(e.metodos.len(), 4);
        assert_eq!(e.dispositivos, 1);
        assert_eq!(e.sin_resolver, 0);

        let ini = por_ruta(&e, "\\_SB.DEV0._INI");
        assert_eq!(ini.momento(), Momento::Arranque);
        assert!(ini.capacidades.contains(&Capacidad::EscribePuertos));
        assert!(
            ini.capacidades.contains(&Capacidad::DisparaSmi),
            "escribe en SMI_CMD: {:?}",
            ini.capacidades
        );
        assert!(!ini.condicional);

        let sta = por_ruta(&e, "\\_SB.DEV0._STA");
        assert!(sta.capacidades.contains(&Capacidad::LeeMemoria));
        assert!(!sta.capacidades.contains(&Capacidad::EscribeMemoria));

        let cond = por_ruta(&e, "\\COND");
        assert!(cond.condicional, "definido dentro de un If");
        assert!(cond.capacidades.contains(&Capacidad::CargaCodigo));

        let addr = por_ruta(&e, "\\_SB.ADDR");
        assert_eq!(addr.argumentos, 2);
        assert_eq!(e.regiones.len(), 2);
        assert_eq!(e.automaticos().len(), 2);
    }

    /// LA AMBIGUEDAD DE AML. Si _INI se decodificara sin saber que ADDR lleva dos
    /// argumentos, sus bytes se tomarian por terminos sueltos y el resto del
    /// metodo se desalinearia. La primera pasada existe para esto.
    #[test]
    fn una_invocacion_se_decodifica_con_los_argumentos_de_su_definicion() {
        let aml = dsdt();
        let e = analizar(&[("DSDT".into(), &aml)], None);
        assert!(e.completo(), "{:?}", e.errores);
        // Sin SMI_CMD conocido, escribir el puerto 0xB2 no es «disparar SMI».
        assert!(!por_ruta(&e, "\\_SB.DEV0._INI")
            .capacidades
            .contains(&Capacidad::DisparaSmi));
    }

    #[test]
    fn un_metodo_roto_no_tapa_a_sus_vecinos_y_se_cuenta() {
        let mut aml = metodo(b"MALO", 0, &[0xA4, 0x5B, 0xEE]);
        aml.extend(metodo(b"BUEN", 0, &[0xA4, 0x01]));
        let e = analizar(&[("DSDT".into(), &aml)], None);
        assert_eq!(e.metodos.len(), 2);
        assert!(!por_ruta(&e, "\\MALO").decodificado);
        assert!(por_ruta(&e, "\\BUEN").decodificado);
        assert_eq!(e.errores.len(), 1);
        assert!(!e.completo());
        let c = evaluar(&e, &LineaBase::default());
        assert!(
            matches!(c[0].estado, CheckState::Indeterminado(_)),
            "{:?}",
            c[0]
        );
    }

    #[test]
    fn el_hash_del_cuerpo_cambia_si_cambia_un_byte() {
        let a = analizar(&[("D".into(), &metodo(b"_INI", 0, &[0xA4, 0x01]))], None);
        let b = analizar(&[("D".into(), &metodo(b"_INI", 0, &[0xA4, 0x00]))], None);
        assert_ne!(a.metodos[0].sha256, b.metodos[0].sha256);
    }

    #[test]
    fn un_metodo_de_arranque_alterado_frente_a_la_linea_base_es_compromiso() {
        let bueno = analizar(&[("D".into(), &metodo(b"_INI", 0, &[0xA4, 0x01]))], None);
        let base = LineaBase::analizar(&format!(
            "version 1\naml \\_INI {} placa-x\n",
            bueno.metodos[0].sha256_hex()
        ))
        .expect("base");
        assert_eq!(evaluar(&bueno, &base)[1].estado, CheckState::Ok);
        let malo = analizar(&[("D".into(), &metodo(b"_INI", 0, &[0xA4, 0x00]))], None);
        let c = &evaluar(&malo, &base)[1];
        assert_eq!(c.naturaleza, Naturaleza::Compromiso);
        assert!(format!("{:?}", c.estado).contains("\\_INI"), "{c:?}");
        // Sin base: inventario, no veredicto.
        assert!(matches!(
            evaluar(&malo, &LineaBase::default())[1].estado,
            CheckState::Indeterminado(_)
        ));
    }

    #[test]
    fn los_momentos_se_reconocen_por_el_nombre() {
        let m = |r: &str| Metodo {
            ruta: r.into(),
            tabla: String::new(),
            argumentos: 0,
            serializado: false,
            condicional: false,
            desplazamiento: 0,
            largo: 0,
            sha256: [0; 32],
            decodificado: true,
            capacidades: BTreeSet::new(),
        };
        assert_eq!(m("\\_GPE._L6F").momento(), Momento::Evento);
        assert_eq!(m("\\_SB_.PCI0.LPCB.EC0_._Q1A").momento(), Momento::Evento);
        assert_eq!(m("\\_WAK").momento(), Momento::Suspension);
        assert_eq!(m("\\_SB_.PCI0._REG").momento(), Momento::Arranque);
        assert_eq!(
            m("\\_SB_.PCI0._EJ0").momento(),
            Momento::BajoDemanda,
            "EJ0 no es un evento: la J no es hexadecimal"
        );
        assert_eq!(m("\\_SB_.PCI0._CRS").momento(), Momento::BajoDemanda);
        assert_eq!(legible("\\_SB_.PCI0._INI"), "\\_SB.PCI0._INI");
    }

    /// AUTOATAQUE: el desensamblador como superficie. Bytes arbitrarios,
    /// anidamiento patologico y longitudes mentirosas. Ni panico, ni cuelgue, ni
    /// reserva sin acotar.
    #[test]
    fn la_entrada_hostil_no_tumba_el_desensamblador() {
        // 1. Anidamiento de If a mil niveles.
        let mut aml = vec![0x01];
        for _ in 0..1000 {
            aml = con_pkg(&[0xA0], &[&[0x01u8][..], &aml].concat());
        }
        let e = analizar(&[("D".into(), &aml)], None);
        assert!(!e.completo(), "a mil niveles tiene que cortar y decirlo");
        // 2. Barrido de basura determinista.
        let mut semilla = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..300 {
            let n = (semilla % 4096) as usize;
            let mut b = Vec::with_capacity(n);
            for _ in 0..n {
                semilla ^= semilla << 13;
                semilla ^= semilla >> 7;
                semilla ^= semilla << 17;
                b.push(semilla as u8);
            }
            let _ = analizar(&[("D".into(), &b)], Some(0xB2));
        }
        // 3. Un PkgLength que promete mas de lo que hay.
        let _ = analizar(
            &[("D".into(), &[0x10, 0xFF, 0xFF, 0xFF, 0x0F, b'_'][..])],
            None,
        );
        // 4. Un MultiNamePrefix con 255 segmentos y nada detras.
        let _ = analizar(&[("D".into(), &[0x70, 0x01, 0x2F, 0xFF][..])], None);
    }

    /// LA DSDT REAL DE ESTA MAQUINA, decodificada entera.
    #[test]
    fn la_dsdt_real_de_esta_maquina_se_decodifica_entera() {
        let c = crate::acpi::leer_tablas_del_sistema();
        if c.por_firma(b"DSDT").is_none() {
            eprintln!("NO APLICABLE: sin DSDT");
            return;
        }
        let smi = crate::tablas::decodificar(&c).fadt.map(|f| f.smi_cmd);
        let inicio = std::time::Instant::now();
        let e = analizar_conjunto(&c, smi);
        let condicionales = e.metodos.iter().filter(|m| m.condicional).count();
        eprintln!(
            "AML real: {} tabla(s), {} metodos ({} condicionales, {} incondicionales), {} decodificados, \
             {} dispositivos, {} regiones, {} objetos, {} nombres sin resolver, {} errores, en {:?}",
            e.tablas.len(),
            e.metodos.len(),
            condicionales,
            e.metodos.len() - condicionales,
            e.decodificados(),
            e.dispositivos,
            e.regiones.len(),
            e.objetos,
            e.sin_resolver,
            e.errores.len(),
            inicio.elapsed()
        );
        for err in e.errores.iter().take(5) {
            eprintln!("  error: {err:?}");
        }
        let auto = e.automaticos();
        eprintln!("  metodos automaticos: {}", auto.len());
        for m in auto.iter().filter(|m| !m.condicional).take(20) {
            eprintln!(
                "    {} {:?} {:?}",
                m.ruta_legible(),
                m.momento(),
                m.capacidades.iter().map(|c| c.nombre()).collect::<Vec<_>>()
            );
        }
        assert!(
            e.completo(),
            "la DSDT real de esta maquina tiene que decodificarse entera: {:?}",
            e.errores.first()
        );
        assert!(!e.metodos.is_empty());
    }
}
