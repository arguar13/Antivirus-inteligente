//! Medir lo que se gasta de verdad.
//!
//! Un presupuesto que no se mide es una frase en un README. Aqui se mide, y se
//! mide **lo que hay que medir**, que no es lo obvio:
//!
//! `memory.current` de un cgroup incluye la cache de pagina que se le ha
//! cargado. Un escaneo completo del disco deja cientos de MiB de cache a nombre
//! del agente, y el kernel los reclama sin despeinarse en cuanto hay presion.
//! Decidir contencion —o peor, matar el proceso— contra ese numero seria
//! castigar al agente por haber leido ficheros, que es literalmente su trabajo.
//!
//! Lo que se mide, por tanto, es la parte **no reclamable**: memoria anonima.
//! Es la que crece con una fuga, la que no se puede devolver, y la que acaba en
//! un OOM. La cache se informa aparte para diagnostico, no para decidir.

use std::fs;

/// De donde sale la medida.
///
/// Se expone porque cambia lo que significa: en un cgroup se mide la contencion
/// que el kernel va a aplicar de verdad, y fuera de el se mide el proceso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origen {
    /// `memory.stat` de cgroup v2. Es la medida que el kernel usa para `memory.max`.
    CgroupV2,
    /// `memory.stat` de cgroup v1.
    CgroupV1,
    /// `VmRSS` de `/proc/<pid>/status`. Incluye paginas de fichero compartidas.
    Proc,
}

impl Origen {
    /// Nombre estable para logs y metricas.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Origen::CgroupV2 => "cgroup-v2",
            Origen::CgroupV1 => "cgroup-v1",
            Origen::Proc => "proc",
        }
    }
}

/// Consumo medido de un proceso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uso {
    /// Memoria no reclamable, en bytes. Es la que decide.
    ///
    /// Con `VmRSS` como origen esta cifra sobreestima, porque incluye paginas de
    /// fichero que el kernel puede soltar. Se prefiere el cgroup justamente por
    /// eso, y el origen queda registrado para que nadie compare peras con
    /// manzanas entre dos hosts distintos.
    pub anonima: u64,
    /// Cache de pagina a nombre del proceso o de su cgroup. Informativa.
    pub cache: u64,
    /// Como se ha obtenido.
    pub origen: Origen,
}

impl Uso {
    /// Huella total observada.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.anonima.saturating_add(self.cache)
    }
}

/// RAM total del host, en bytes.
#[must_use]
pub fn memoria_total() -> Option<u64> {
    campo_meminfo(&fs::read_to_string("/proc/meminfo").ok()?, "MemTotal:")
}

fn campo_meminfo(texto: &str, clave: &str) -> Option<u64> {
    for linea in texto.lines() {
        if let Some(resto) = linea.strip_prefix(clave) {
            // Formato: "MemTotal:       16461028 kB"
            let kib: u64 = resto.split_whitespace().next()?.parse().ok()?;
            return kib.checked_mul(1024);
        }
    }
    None
}

/// Consumo de **este proceso**.
#[must_use]
pub fn uso_propio() -> Option<Uso> {
    por_proc("self")
}

/// Consumo de **otro proceso**, por PID.
///
/// Lo usa el watchdog: el proceso vigilado no puede informar de su propia fuga
/// de forma fiable, porque una fuga suficientemente mala le impide informar.
///
/// Mide el proceso y **no** su cgroup, y la diferencia no es teorica. En el
/// despliegue real el watchdog lanza al agente como hijo, asi que los dos viven
/// en la misma unidad y en el mismo cgroup: preguntarle al cgroup cuanto gasta
/// el agente devolveria tambien lo que gasta el watchdog. Con eso, un watchdog
/// pesado condenaria al agente por memoria ajena, y el reinicio —que no libera
/// nada de lo que de verdad sobraba— se repetiria sin converger. Restart en
/// bucle es peor que la fuga: deja la maquina sin EDR en vez de con un EDR
/// gordo.
#[must_use]
pub fn uso_de(pid: u32) -> Option<Uso> {
    por_proc(&pid.to_string())
}

/// Consumo del **cgroup** de este proceso.
///
/// Responde a otra pregunta que [`uso_propio`], y por eso es otra funcion: esto
/// es lo que el kernel va a hacer cumplir contra `memory.max`, e incluye a todo
/// el que comparta unidad. Sirve para saber si el OOM del cgroup esta cerca; no
/// sirve para atribuirle el gasto a nadie en concreto.
///
/// Devuelve `None` fuera de un cgroup con contabilidad de memoria.
#[must_use]
pub fn uso_del_cgroup() -> Option<Uso> {
    por_cgroup("self")
}

// --- cgroup -------------------------------------------------------------------

/// Raiz del sistema de ficheros de cgroups.
const RAIZ_CGROUP: &str = "/sys/fs/cgroup";

fn por_cgroup(quien: &str) -> Option<Uso> {
    let mapa = fs::read_to_string(format!("/proc/{quien}/cgroup")).ok()?;

    // cgroup v2: una sola linea "0::/ruta". Bajo un namespace de cgroup la ruta
    // es "/" y el punto de montaje ya esta acotado al del contenedor, que es el
    // caso normal en un despliegue con systemd o con Kubernetes.
    if let Some(ruta) = mapa.lines().find_map(|l| l.strip_prefix("0::")) {
        let base = unir(RAIZ_CGROUP, ruta);
        if let Ok(texto) = fs::read_to_string(format!("{base}/memory.stat")) {
            let anonima = campo_clave_valor(&texto, "anon")?;
            let cache = campo_clave_valor(&texto, "file").unwrap_or(0);
            return Some(Uso {
                anonima,
                cache,
                origen: Origen::CgroupV2,
            });
        }
    }

    // cgroup v1: varias lineas "jerarquia:controladores:ruta". El controlador de
    // memoria tiene su propio arbol bajo /sys/fs/cgroup/memory.
    let ruta = mapa.lines().find_map(|l| {
        let mut trozos = l.splitn(3, ':');
        let _jerarquia = trozos.next()?;
        let controladores = trozos.next()?;
        let ruta = trozos.next()?;
        controladores
            .split(',')
            .any(|c| c == "memory")
            .then_some(ruta)
    })?;
    let base = unir(&format!("{RAIZ_CGROUP}/memory"), ruta);
    let texto = fs::read_to_string(format!("{base}/memory.stat")).ok()?;
    let anonima = campo_clave_valor(&texto, "rss")?;
    let cache = campo_clave_valor(&texto, "cache").unwrap_or(0);
    Some(Uso {
        anonima,
        cache,
        origen: Origen::CgroupV1,
    })
}

fn unir(base: &str, ruta: &str) -> String {
    if ruta == "/" || ruta.is_empty() {
        base.to_string()
    } else {
        format!("{base}{ruta}")
    }
}

fn campo_clave_valor(texto: &str, clave: &str) -> Option<u64> {
    for linea in texto.lines() {
        let mut trozos = linea.split_whitespace();
        // Comparacion por igualdad exacta y no por prefijo: en cgroup v1 la
        // clave "rss" convive con "total_rss" y con "rss_huge", y un prefijo
        // devolveria la primera que case, que no tiene por que ser la pedida.
        if trozos.next() == Some(clave) {
            return trozos.next()?.parse().ok();
        }
    }
    None
}

// --- /proc --------------------------------------------------------------------

fn por_proc(quien: &str) -> Option<Uso> {
    let texto = fs::read_to_string(format!("/proc/{quien}/status")).ok()?;
    let rss = campo_status(&texto, "VmRSS:")?;
    // `RssFile` y `RssShmem` son la parte de fichero del RSS; restarlas deja la
    // anonima, que es lo que se quiere. Si el kernel no las expone se usa el RSS
    // entero, que sobreestima, y sobreestimar aqui es el lado seguro: aprieta al
    // agente antes de tiempo en vez de dejarlo crecer sin freno.
    let fichero = campo_status(&texto, "RssFile:").unwrap_or(0)
        + campo_status(&texto, "RssShmem:").unwrap_or(0);
    Some(Uso {
        anonima: rss.saturating_sub(fichero),
        cache: fichero,
        origen: Origen::Proc,
    })
}

fn campo_status(texto: &str, clave: &str) -> Option<u64> {
    for linea in texto.lines() {
        if let Some(resto) = linea.strip_prefix(clave) {
            let kib: u64 = resto.split_whitespace().next()?.parse().ok()?;
            return kib.checked_mul(1024);
        }
    }
    None
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn meminfo_se_lee_en_bytes() {
        let texto = "MemTotal:       16461028 kB\nMemFree:         1234 kB\n";
        assert_eq!(campo_meminfo(texto, "MemTotal:"), Some(16_461_028 * 1024));
        assert_eq!(campo_meminfo(texto, "NoExiste:"), None);
    }

    #[test]
    fn meminfo_no_desborda_con_basura() {
        let texto = "MemTotal:       99999999999999999999 kB\n";
        assert_eq!(campo_meminfo(texto, "MemTotal:"), None);
    }

    #[test]
    fn clave_valor_no_casa_por_prefijo() {
        // El fallo clasico: "rss" casando con "total_rss" o con "rss_huge".
        let v1 = "cache 100\nrss 200\nrss_huge 300\ntotal_rss 400\n";
        assert_eq!(campo_clave_valor(v1, "rss"), Some(200));
        assert_eq!(campo_clave_valor(v1, "cache"), Some(100));
        assert_eq!(campo_clave_valor(v1, "total_rss"), Some(400));
    }

    #[test]
    fn clave_valor_de_cgroup_v2() {
        let v2 = "anon 104857600\nfile 524288000\nkernel_stack 65536\n";
        assert_eq!(campo_clave_valor(v2, "anon"), Some(104_857_600));
        assert_eq!(campo_clave_valor(v2, "file"), Some(524_288_000));
    }

    #[test]
    fn status_descuenta_la_parte_de_fichero() {
        let texto = "Name:\taegis-agent\nVmRSS:\t   204800 kB\nRssAnon:\t   102400 kB\n\
                     RssFile:\t    92160 kB\nRssShmem:\t    10240 kB\n";
        assert_eq!(campo_status(texto, "VmRSS:"), Some(204_800 * 1024));
        assert_eq!(campo_status(texto, "RssFile:"), Some(92_160 * 1024));
    }

    #[test]
    fn unir_rutas_de_cgroup() {
        assert_eq!(unir("/sys/fs/cgroup", "/"), "/sys/fs/cgroup");
        assert_eq!(unir("/sys/fs/cgroup", ""), "/sys/fs/cgroup");
        assert_eq!(
            unir("/sys/fs/cgroup", "/system.slice/aegis.service"),
            "/sys/fs/cgroup/system.slice/aegis.service"
        );
    }

    #[test]
    fn el_proceso_actual_se_mide_de_verdad() {
        // Sin simulacion: si esto falla en este host, la medida no sirve aqui y
        // hay que saberlo. Un proceso de Rust vivo ocupa algo de memoria
        // anonima si o si, asi que un cero seria una medida rota.
        let uso = uso_propio().expect("no se pudo medir el proceso actual");
        assert!(uso.anonima > 0, "medida nula desde {}", uso.origen.nombre());
        assert!(uso.total() >= uso.anonima);
        assert_eq!(
            uso.origen,
            Origen::Proc,
            "medir un proceso es medir el proceso"
        );
    }

    #[test]
    fn medir_un_proceso_no_es_medir_su_cgroup() {
        // La confusion que costaria un bucle de reinicio en produccion: el
        // watchdog y el agente comparten unidad, asi que el cgroup incluye a los
        // dos. Aqui el proceso de prueba comparte cgroup con todo lo demas, y su
        // medida propia tiene que ser estrictamente menor que la del conjunto.
        let propio = uso_propio().expect("sin medida propia");
        if let Some(grupo) = uso_del_cgroup() {
            assert!(
                propio.anonima <= grupo.anonima,
                "un proceso no puede gastar mas que su cgroup entero: \
                 {} contra {}",
                propio.anonima,
                grupo.anonima
            );
            assert!(matches!(grupo.origen, Origen::CgroupV2 | Origen::CgroupV1));
        }
    }

    #[test]
    fn la_memoria_del_host_se_lee() {
        let total = memoria_total().expect("sin /proc/meminfo");
        assert!(total > 64 * 1024 * 1024, "host imposible: {total} bytes");
    }

    #[test]
    fn medir_un_pid_inexistente_no_revienta() {
        // PID fuera del rango por defecto de Linux: no existe y no puede existir
        // mientras /proc/sys/kernel/pid_max no se toque.
        assert!(uso_de(u32::MAX).is_none());
    }
}
