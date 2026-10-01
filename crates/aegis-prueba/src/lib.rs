//! Apoyo a las pruebas: la omision que se dice, se cuenta y, cuando se exige,
//! falla.
//!
//! # Por que existe (hallazgos H-10 y H-20)
//!
//! Muchas pruebas de AegisCore necesitan algo que no controlan: un PostgreSQL y
//! un Redis reales (plano de control), root, un kernel con BTF, Landlock o
//! seccomp, unas tablas ACPI, una herramienta externa como testigo (`clang`,
//! `lld-link`, `nft`, `llvm-readobj`) o un conjunto de datos (MITRE ATT&CK).
//! Sin ello se omitian con `eprintln!("OMITIDA: ...")` y `return`. La intencion
//! era honrada; el efecto no: `cargo test` CAPTURA la salida de las pruebas que
//! pasan, asi que una prueba omitida salia como `ok`, `make ci` daba verde sin
//! haberla ejecutado, y no lo decia en ningun sitio.
//!
//! Aqui una omision tiene tres salidas, y ninguna es el silencio:
//!
//! 1. Si el requisito se EXIGE (variable `AEGIS_EXIGIR`), la prueba falla con
//!    un mensaje que dice que falta y como obtenerlo.
//! 2. Si no, escribe `OMITIDA: ...` en stderr, como antes: los verificadores
//!    de `tools/` buscan esa cadena en las pruebas que corren con
//!    `--nocapture`.
//! 3. Y ademas la anota en el fichero de `AEGIS_OMISIONES`, si lo hay: una
//!    linea por omision, que la tanda cuenta al final aunque cargo haya
//!    capturado la salida (`tools/ci/omisiones.py`). Una omision que no se
//!    puede anotar hace fallar la prueba: contarla es la mitad de la garantia.
//!
//! # `AEGIS_EXIGIR`
//!
//! Lista separada por comas o espacios. Cada elemento es la clave de un
//! requisito (`postgresql`, `root`, `ebpf`, `herramienta`...), una clave con su
//! detalle (`herramienta:clang`, `sonda:aegis_tp_openat`), una clase
//! (`servicios`, `privilegios`, `kernel`, `hardware`, `herramientas`, `red`,
//! `datos`, `medidas`, `entorno`) o `todo`. `make ci` exporta
//! `AEGIS_EXIGIR=servicios,privilegios,kernel`: la tanda corre como root, sobre
//! un kernel con BTF, Landlock y seccomp, y con PostgreSQL y Redis arrancados,
//! asi que su falta es un fallo del entorno y se dice como tal. Lo demas no se
//! exige: se anota, y una omision que no este declarada en
//! `tools/config/omisiones.toml` hace fallar la tanda al final.
//!
//! # Uso
//!
//! ```no_run
//! use aegis_prueba::{omitir, Requisito};
//!
//! fn compilador() -> Option<String> {
//!     None
//! }
//!
//! let Some(_cc) = compilador() else {
//!     omitir("no hay compilador de C", Requisito::Herramienta("cc"));
//!     return;
//! };
//! ```

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::panic::Location;
use std::path::Path;

/// Variable de entorno con la lista de requisitos que se exigen.
pub const VAR_EXIGIR: &str = "AEGIS_EXIGIR";

/// Variable de entorno con el fichero donde se anotan las omisiones.
pub const VAR_OMISIONES: &str = "AEGIS_OMISIONES";

/// Como se obtiene el PostgreSQL de las pruebas.
const COMO_POSTGRESQL: &str = "arranca PostgreSQL y su base: tools/ci/servicios.sh --arrancar";

/// Como se obtiene el Redis de las pruebas.
const COMO_REDIS: &str = "arranca Redis: tools/ci/servicios.sh --arrancar";

/// Como se obtiene ATT&CK.
const COMO_ATTACK: &str = "descargalo con tools/verificar-conocimiento.sh";

/// Lo que le falta a una prueba para poder ejercerse.
///
/// Cada variante tiene una clave (la de `AEGIS_EXIGIR` y la de
/// `tools/config/omisiones.toml`) y una clase. Las tres primeras clases
/// (`servicios`, `privilegios`, `kernel`) las exige `make ci`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requisito {
    /// Servicio: el PostgreSQL de pruebas (`AEGIS_TEST_PG_URL`).
    Postgresql,
    /// Servicio: el Redis de pruebas (`AEGIS_TEST_REDIS_URL`).
    Redis,
    /// Red: un corredor de Apache Kafka real (`AEGIS_KAFKA_CORREDORES`).
    Kafka,
    /// Datos: MITRE ATT&CK en STIX 2.1, en `/opt/aegis-comparativa/attack`.
    Attack,
    /// Medida bajo demanda: solo corre con la variable nombrada puesta.
    Medida(&'static str),
    /// Medida de tiempo que solo se juzga sobre el binario optimizado
    /// (`--release`).
    Optimizado,
    /// Privilegios: root, o las capacidades que solo tiene root en el runner.
    Root,
    /// Privilegios: trazar o leer la memoria de otro proceso
    /// (`CAP_SYS_PTRACE`, Yama).
    Ptrace,
    /// Kernel: cargar programas eBPF (BTF, tracefs, ring buffer y `CAP_BPF`).
    Ebpf,
    /// Kernel: la informacion de tipos del kernel (`/sys/kernel/btf/vmlinux`).
    Btf,
    /// Version del kernel: los kfuncs de tareas (`bpf_iter_task_*`,
    /// `bpf_task_from_pid`) que la verificacion cruzada necesita. Dependen de
    /// la version, no de como este configurado el runner: no se exigen en el,
    /// y los ejerce la matriz de kernels en las imagenes que los traen.
    KfuncsTareas,
    /// Kernel: Landlock (`CONFIG_SECURITY_LANDLOCK`).
    Landlock,
    /// Kernel: seccomp con filtros y notificacion a espacio de usuario.
    Seccomp,
    /// Kernel: una sonda eBPF concreta que el plan de capacidades declara
    /// inactiva en este kernel.
    Sonda(&'static str),
    /// Hardware: tablas ACPI legibles.
    Acpi,
    /// Hardware: un bus PCI legible en `/sys/bus/pci`.
    Pci,
    /// Hardware: registros de depuracion (puntos de ruptura por hardware).
    RegistrosDepuracion,
    /// Una herramienta o biblioteca del sistema que la prueba usa como testigo
    /// o como material: `cc`, `clang`, `lld-link`, `nft`, `python3`...
    Herramienta(&'static str),
    /// Una condicion de la maquina que la prueba no controla (un fichero del
    /// sistema, una carrera con un proceso hijo...). Nunca se exige en bloque:
    /// en `make ci`, sin declarar, hace fallar la tanda al final.
    Entorno,
}

impl Requisito {
    /// Nombre corto del requisito: el de `AEGIS_EXIGIR` y el de
    /// `tools/config/omisiones.toml`.
    pub fn clave(self) -> &'static str {
        match self {
            Requisito::Postgresql => "postgresql",
            Requisito::Redis => "redis",
            Requisito::Kafka => "kafka",
            Requisito::Attack => "attack",
            Requisito::Medida(_) => "medida",
            Requisito::Optimizado => "optimizado",
            Requisito::Root => "root",
            Requisito::Ptrace => "ptrace",
            Requisito::Ebpf => "ebpf",
            Requisito::Btf => "btf",
            Requisito::KfuncsTareas => "kfuncs-tareas",
            Requisito::Landlock => "landlock",
            Requisito::Seccomp => "seccomp",
            Requisito::Sonda(_) => "sonda",
            Requisito::Acpi => "acpi",
            Requisito::Pci => "pci",
            Requisito::RegistrosDepuracion => "drx",
            Requisito::Herramienta(_) => "herramienta",
            Requisito::Entorno => "entorno",
        }
    }

    /// El detalle de los requisitos que lo llevan: la variable de una medida,
    /// el nombre de una sonda o el de una herramienta.
    pub fn detalle(self) -> Option<&'static str> {
        match self {
            Requisito::Medida(d) | Requisito::Sonda(d) | Requisito::Herramienta(d) => Some(d),
            _ => None,
        }
    }

    /// La clave con su detalle (`herramienta:clang`), o la clave sola.
    pub fn nombre(self) -> String {
        match self.detalle() {
            Some(d) => format!("{}:{d}", self.clave()),
            None => self.clave().to_string(),
        }
    }

    /// Clase del requisito.
    pub fn clase(self) -> &'static str {
        match self {
            Requisito::Postgresql | Requisito::Redis => "servicios",
            Requisito::Kafka => "red",
            Requisito::Attack => "datos",
            Requisito::Medida(_) | Requisito::Optimizado => "medidas",
            Requisito::Root | Requisito::Ptrace => "privilegios",
            Requisito::Ebpf
            | Requisito::Btf
            | Requisito::Landlock
            | Requisito::Seccomp
            | Requisito::Sonda(_) => "kernel",
            Requisito::KfuncsTareas => "version-kernel",
            Requisito::Acpi | Requisito::Pci | Requisito::RegistrosDepuracion => "hardware",
            Requisito::Herramienta(_) => "herramientas",
            Requisito::Entorno => "entorno",
        }
    }

    /// Como se obtiene lo que falta, dicho para quien lee el fallo.
    pub fn como_obtenerlo(self) -> String {
        match self {
            Requisito::Postgresql => COMO_POSTGRESQL.to_string(),
            Requisito::Redis => COMO_REDIS.to_string(),
            Requisito::Kafka => "levanta uno con tools/verificar-kafka.sh (Java y salida a \
                                 archive.apache.org) o exporta AEGIS_KAFKA=host:puerto"
                .to_string(),
            Requisito::Attack => COMO_ATTACK.to_string(),
            Requisito::Medida(variable) => format!("exporta {variable}=1 para medir"),
            Requisito::Optimizado => {
                "ejecutala con cargo test --release (su grupo de make ci lo hace)".to_string()
            }
            Requisito::Root => {
                "ejecuta las pruebas como root, como las ejecuta make ci".to_string()
            }
            Requisito::Ptrace => {
                "ejecuta como root o con CAP_SYS_PTRACE, y con kernel.yama.ptrace_scope < 3"
                    .to_string()
            }
            Requisito::Ebpf => "hace falta root (CAP_BPF) y un kernel con BTF, tracefs y ring \
                                buffer: mira `aegis-agent --capacidades`"
                .to_string(),
            Requisito::Btf => {
                "un kernel con CONFIG_DEBUG_INFO_BTF (/sys/kernel/btf/vmlinux)".to_string()
            }
            Requisito::KfuncsTareas => "un kernel con los kfuncs de tareas admitidos para el \
                                        programa (lo ejerce la matriz: nucleo-en-vivo)"
                .to_string(),
            Requisito::Landlock => {
                "un kernel con CONFIG_SECURITY_LANDLOCK y landlock en `lsm=`".to_string()
            }
            Requisito::Seccomp => "un kernel con CONFIG_SECCOMP_FILTER".to_string(),
            Requisito::Sonda(sonda) => format!(
                "el plan de capacidades declara inactiva la sonda {sonda} en este kernel: \
                 mira `aegis-agent --capacidades`"
            ),
            Requisito::Acpi => {
                "tablas ACPI legibles en /sys/firmware/acpi/tables (como root)".to_string()
            }
            Requisito::Pci => "un bus PCI legible en /sys/bus/pci".to_string(),
            Requisito::RegistrosDepuracion => "puntos de ruptura por hardware \
                                               (perf_event_open, PERF_TYPE_BREAKPOINT); en una \
                                               VM, que el hipervisor los exponga"
                .to_string(),
            Requisito::Herramienta(nombre) => {
                format!("instala {nombre} (deploy/ci/instalar-runner.sh lo instala en el runner)")
            }
            Requisito::Entorno => "la maquina no dio la condicion que la prueba necesita (ver \
                                   el motivo); en make ci solo se admite declarada en \
                                   tools/config/omisiones.toml"
                .to_string(),
        }
    }
}

/// Una omision: que falta, donde y por que.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Omision {
    /// Lo que falta.
    pub requisito: Requisito,
    /// Fichero fuente de la llamada, tal cual lo da el compilador (relativo a
    /// la raiz de su workspace).
    pub fichero: String,
    /// Linea de la llamada.
    pub linea: u32,
    /// Nombre de la prueba: el del hilo que la ejecuta.
    pub prueba: String,
    /// Por que se omite.
    pub motivo: String,
}

impl Omision {
    /// La linea que se anota en `AEGIS_OMISIONES`: cinco campos separados por
    /// tabuladores (clave del requisito, fichero, linea, prueba y motivo), sin
    /// tabuladores ni saltos de linea dentro de ninguno, y terminada en `\n`.
    /// El detalle del requisito, si lo tiene, va al principio del motivo.
    pub fn anotacion(&self) -> String {
        let motivo = match self.requisito.detalle() {
            Some(d) => format!("[{d}] {}", self.motivo),
            None => self.motivo.clone(),
        };
        let campos = [
            self.requisito.clave().to_string(),
            limpio(&self.fichero),
            self.linea.to_string(),
            limpio(&self.prueba),
            limpio(&motivo),
        ];
        format!("{}\n", campos.join("\t"))
    }
}

/// Si `lista` (el valor de `AEGIS_EXIGIR`) exige `requisito`.
pub fn exigido(lista: &str, requisito: Requisito) -> bool {
    let nombre = requisito.nombre();
    lista
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
        .any(|t| t == "todo" || t == requisito.clave() || t == requisito.clase() || t == nombre)
}

/// Omite la prueba en curso porque le falta `requisito`, o la hace fallar si
/// ese requisito se exige.
///
/// Despues de llamarla, la prueba tiene que volver (`return`) sin comprobar
/// nada mas: esto decide COMO se omite, no la termina.
///
/// # Panics
///
/// Si `AEGIS_EXIGIR` exige el requisito, o si `AEGIS_OMISIONES` apunta a un
/// fichero en el que no se puede escribir.
#[track_caller]
pub fn omitir(motivo: &str, requisito: Requisito) {
    let donde = Location::caller();
    let hilo = std::thread::current();
    let omision = Omision {
        requisito,
        fichero: donde.file().to_string(),
        linea: donde.line(),
        prueba: hilo.name().unwrap_or("?").to_string(),
        motivo: motivo.to_string(),
    };
    let lista = std::env::var(VAR_EXIGIR).unwrap_or_default();
    if exigido(&lista, requisito) {
        panic!("{}", mensaje_exigido(&omision, &lista));
    }
    eprintln!(
        "OMITIDA: {motivo} [falta {}; {}:{}]",
        requisito.nombre(),
        omision.fichero,
        omision.linea
    );
    let Some(ruta) = std::env::var_os(VAR_OMISIONES).filter(|r| !r.is_empty()) else {
        return;
    };
    if let Err(e) = anotar(Path::new(&ruta), &omision) {
        panic!(
            "OMITIDA y sin anotar: {VAR_OMISIONES}={} no se puede escribir ({e}); \
             una omision que no se cuenta es un verde falso",
            Path::new(&ruta).display()
        );
    }
}

/// Anade la omision al fichero, en una sola escritura en modo de adicion: las
/// pruebas corren en paralelo y una linea no puede quedar partida.
fn anotar(ruta: &Path, omision: &Omision) -> std::io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(ruta)?;
    f.write_all(omision.anotacion().as_bytes())
}

/// El mensaje de una omision exigida: que falta, donde y como obtenerlo.
fn mensaje_exigido(o: &Omision, lista: &str) -> String {
    format!(
        "FALTA {nombre}, y aqui se exige ({VAR_EXIGIR}={lista})\n  \
         motivo: {motivo}\n  \
         prueba: {prueba} ({fichero}:{linea})\n  \
         como obtenerlo: {como}\n  \
         para omitirla en vez de fallar (solo en local): quita {clave} y {clase} de {VAR_EXIGIR}",
        nombre = o.requisito.nombre(),
        clave = o.requisito.clave(),
        clase = o.requisito.clase(),
        motivo = o.motivo,
        prueba = o.prueba,
        fichero = o.fichero,
        linea = o.linea,
        como = o.requisito.como_obtenerlo(),
    )
}

/// Un campo sin tabuladores ni saltos de linea: el fichero es de una linea por
/// omision y de campos separados por tabuladores.
fn limpio(texto: &str) -> String {
    texto.replace(['\t', '\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Todas las variantes, para las comprobaciones que recorren el catalogo.
    const TODAS: [Requisito; 18] = [
        Requisito::Postgresql,
        Requisito::Redis,
        Requisito::Kafka,
        Requisito::Attack,
        Requisito::Medida("X"),
        Requisito::Optimizado,
        Requisito::Root,
        Requisito::Ptrace,
        Requisito::Ebpf,
        Requisito::Btf,
        Requisito::Landlock,
        Requisito::Seccomp,
        Requisito::Sonda("s"),
        Requisito::Acpi,
        Requisito::Pci,
        Requisito::RegistrosDepuracion,
        Requisito::Herramienta("cc"),
        Requisito::Entorno,
    ];

    #[test]
    fn sin_lista_no_se_exige_nada() {
        assert!(!exigido("", Requisito::Postgresql));
        assert!(!exigido(" , ", Requisito::Redis));
        assert!(!exigido("", Requisito::Root));
    }

    #[test]
    fn la_clase_exige_a_todos_los_suyos_y_a_nadie_mas() {
        assert!(exigido("servicios", Requisito::Postgresql));
        assert!(exigido("servicios", Requisito::Redis));
        assert!(!exigido("servicios", Requisito::Attack));
        assert!(!exigido("servicios", Requisito::Medida("X")));
        assert!(!exigido("servicios", Requisito::Kafka));
        assert!(exigido("kernel", Requisito::Landlock));
        assert!(exigido("kernel", Requisito::Sonda("s")));
        assert!(!exigido("kernel", Requisito::Root));
        assert!(exigido("privilegios", Requisito::Ptrace));
    }

    #[test]
    fn la_clave_y_todo_se_entienden_dentro_de_una_lista() {
        assert!(exigido("servicios,attack", Requisito::Attack));
        assert!(exigido("redis attack", Requisito::Redis));
        assert!(!exigido("redis", Requisito::Postgresql));
        assert!(exigido("todo", Requisito::Medida("X")));
        assert!(exigido("todo", Requisito::Entorno));
    }

    #[test]
    fn la_clave_con_detalle_exige_solo_esa_herramienta() {
        assert!(exigido(
            "herramienta:clang",
            Requisito::Herramienta("clang")
        ));
        assert!(!exigido("herramienta:clang", Requisito::Herramienta("nft")));
        assert!(exigido("herramienta", Requisito::Herramienta("nft")));
        assert!(exigido("herramientas", Requisito::Herramienta("nft")));
    }

    #[test]
    fn lo_que_exige_make_ci_no_alcanza_a_lo_que_se_declara() {
        // make ci exporta servicios,privilegios,kernel. Lo que se puede
        // DECLARAR como omision admisible tiene que quedar fuera: si se
        // exigiera, fallaria antes de poder anotarse.
        let ci = "servicios,privilegios,kernel";
        for r in TODAS {
            let exigida = matches!(r.clase(), "servicios" | "privilegios" | "kernel");
            assert_eq!(exigido(ci, r), exigida, "{r:?}");
        }
    }

    #[test]
    fn cada_requisito_dice_como_obtenerse() {
        for r in TODAS {
            assert!(!r.como_obtenerlo().is_empty(), "{r:?}");
            assert!(!r.clave().contains(':'), "{r:?}");
        }
    }

    #[test]
    fn la_anotacion_es_una_linea_de_cinco_campos_limpios() {
        let o = Omision {
            requisito: Requisito::Attack,
            fichero: "crates/x/tests/a.rs".to_string(),
            linea: 7,
            prueba: "una\tprueba".to_string(),
            motivo: "no esta\n/opt/a".to_string(),
        };
        let a = o.anotacion();
        assert!(a.ends_with('\n'));
        let campos: Vec<&str> = a.trim_end_matches('\n').split('\t').collect();
        assert_eq!(campos.len(), 5);
        assert_eq!(campos[0], "attack");
        assert_eq!(campos[2], "7");
        assert_eq!(campos[3], "una prueba");
        assert_eq!(campos[4], "no esta /opt/a");
    }

    #[test]
    fn el_detalle_va_en_el_motivo_y_no_en_la_clave() {
        let o = Omision {
            requisito: Requisito::Herramienta("nft"),
            fichero: "crates/x/tests/a.rs".to_string(),
            linea: 1,
            prueba: "p".to_string(),
            motivo: "no hay nft".to_string(),
        };
        let a = o.anotacion();
        let campos: Vec<&str> = a.trim_end_matches('\n').split('\t').collect();
        assert_eq!(campos[0], "herramienta");
        assert_eq!(campos[4], "[nft] no hay nft");
    }

    #[test]
    fn el_mensaje_exigido_dice_que_falta_y_como_obtenerlo() {
        let o = Omision {
            requisito: Requisito::Postgresql,
            fichero: "crates/x/tests/a.rs".to_string(),
            linea: 3,
            prueba: "p".to_string(),
            motivo: "no hay PostgreSQL".to_string(),
        };
        let m = mensaje_exigido(&o, "servicios");
        assert!(m.starts_with("FALTA postgresql"));
        assert!(m.contains("tools/ci/servicios.sh --arrancar"));
        assert!(m.contains("crates/x/tests/a.rs:3"));

        let o = Omision {
            requisito: Requisito::Herramienta("lld-link"),
            ..o
        };
        let m = mensaje_exigido(&o, "herramientas");
        assert!(m.starts_with("FALTA herramienta:lld-link"));
        assert!(m.contains("instala lld-link"));
    }
}
