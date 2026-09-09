//! Pruebas de integracion del escaner contra arboles de ficheros sinteticos.
//!
//! Construir un sistema de ficheros falso permite ejercitar los caminos que en
//! una maquina sana no ocurren nunca: un /etc/shadow legible por todos, una
//! segunda cuenta con UID 0, un binario setuid en /tmp. Sin esto, esas ramas
//! del escaner no se probarian jamas.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use aegis_vuln::{Category, CveFeed, Scanner, Severity};

/// Raiz temporal que se borra sola.
struct RaizFalsa(PathBuf);

impl RaizFalsa {
    fn nueva(nombre: &str) -> RaizFalsa {
        let p =
            std::env::temp_dir().join(format!("aegis-vuln-test-{nombre}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("crear raiz de prueba");
        RaizFalsa(p)
    }

    fn escribir(&self, rel: &str, contenido: &str, modo: u32) {
        let ruta = self.0.join(rel.trim_start_matches('/'));
        fs::create_dir_all(ruta.parent().unwrap()).expect("crear directorios");
        fs::write(&ruta, contenido).expect("escribir fichero");
        fs::set_permissions(&ruta, fs::Permissions::from_mode(modo)).expect("fijar permisos");
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for RaizFalsa {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tiene(informe: &aegis_vuln::ScanReport, id_parcial: &str) -> bool {
    informe.findings.iter().any(|f| f.id.contains(id_parcial))
}

fn buscar<'a>(
    informe: &'a aegis_vuln::ScanReport,
    id_parcial: &str,
) -> Option<&'a aegis_vuln::Finding> {
    informe.findings.iter().find(|f| f.id.contains(id_parcial))
}

#[test]
fn detecta_shadow_legible_por_todos() {
    let r = RaizFalsa::nueva("shadow");
    // 0644: cualquier usuario local se lleva todos los hashes de la maquina.
    r.escribir("/etc/shadow", "root:$6$abc$def:19000:0:99999:7:::\n", 0o644);

    let informe = Scanner::new().scan(r.path());
    let h = buscar(&informe, "AEGIS-PERM-etc-shadow").expect("debe detectarse");
    assert_eq!(h.severity, Severity::Critical);
    assert_eq!(h.category, Category::Permissions);
    assert!(h.evidence.contains("0644"), "evidencia: {}", h.evidence);
    assert!(!h.remediation.is_empty(), "todo hallazgo lleva remediacion");
}

#[test]
fn no_reporta_permisos_correctos() {
    let r = RaizFalsa::nueva("shadow-ok");
    r.escribir("/etc/shadow", "root:*:19000:0:99999:7:::\n", 0o640);
    r.escribir("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", 0o644);

    let informe = Scanner::new().scan(r.path());
    assert!(!tiene(&informe, "AEGIS-PERM-etc-shadow"));
    assert!(!tiene(&informe, "AEGIS-PERM-etc-passwd"));
}

#[test]
fn detecta_ld_so_preload_con_contenido() {
    let r = RaizFalsa::nueva("preload");
    r.escribir("/etc/ld.so.preload", "# comentario\n/tmp/.hide.so\n", 0o644);

    let informe = Scanner::new().scan(r.path());
    let h = buscar(&informe, "AEGIS-LDPRELOAD").expect("debe detectarse");
    assert_eq!(h.severity, Severity::Critical);
    assert_eq!(h.category, Category::Persistence);
    assert!(h.evidence.contains("/tmp/.hide.so"));
}

#[test]
fn un_ld_so_preload_vacio_o_solo_comentarios_no_alerta() {
    let r = RaizFalsa::nueva("preload-vacio");
    r.escribir("/etc/ld.so.preload", "# nada activo\n\n", 0o644);
    let informe = Scanner::new().scan(r.path());
    assert!(!tiene(&informe, "AEGIS-LDPRELOAD"));
}

#[test]
fn detecta_configuracion_de_ssh_insegura() {
    let r = RaizFalsa::nueva("ssh");
    r.escribir(
        "/etc/ssh/sshd_config",
        "# config\nPermitRootLogin no\nPermitEmptyPasswords yes\nPermitRootLogin yes\nPasswordAuthentication yes\n",
        0o600,
    );

    let informe = Scanner::new().scan(r.path());
    // La ultima directiva gana, como en sshd: el 'yes' del final debe detectarse
    // pese al 'no' anterior.
    let root_login = buscar(&informe, "AEGIS-SSH-001").expect("PermitRootLogin yes");
    assert_eq!(root_login.severity, Severity::High);
    assert_eq!(
        buscar(&informe, "AEGIS-SSH-003").unwrap().severity,
        Severity::Critical
    );
    assert!(tiene(&informe, "AEGIS-SSH-004"));
}

#[test]
fn detecta_aslr_desactivado() {
    let r = RaizFalsa::nueva("aslr");
    r.escribir("/proc/sys/kernel/randomize_va_space", "0\n", 0o644);
    r.escribir("/proc/sys/kernel/yama/ptrace_scope", "0\n", 0o644);

    let informe = Scanner::new().scan(r.path());
    let aslr = buscar(&informe, "randomize_va_space").expect("ASLR debe detectarse");
    assert_eq!(aslr.severity, Severity::High);
    assert!(aslr.remediation.contains("sysctl -w"));

    let yama = buscar(&informe, "ptrace_scope").expect("ptrace_scope debe detectarse");
    assert_eq!(yama.severity, Severity::High);
}

#[test]
fn aslr_completo_no_genera_hallazgo() {
    let r = RaizFalsa::nueva("aslr-ok");
    r.escribir("/proc/sys/kernel/randomize_va_space", "2\n", 0o644);
    let informe = Scanner::new().scan(r.path());
    assert!(!tiene(&informe, "randomize_va_space"));
}

#[test]
fn suid_dumpable_se_evalua_al_reves_que_el_resto() {
    // Es el unico sysctl de la lista donde el valor SEGURO es el minimo.
    let malo = RaizFalsa::nueva("dumpable-malo");
    malo.escribir("/proc/sys/fs/suid_dumpable", "2\n", 0o644);
    assert!(tiene(&Scanner::new().scan(malo.path()), "suid_dumpable"));

    let bueno = RaizFalsa::nueva("dumpable-bueno");
    bueno.escribir("/proc/sys/fs/suid_dumpable", "0\n", 0o644);
    assert!(!tiene(&Scanner::new().scan(bueno.path()), "suid_dumpable"));
}

#[test]
fn detecta_segunda_cuenta_con_uid_cero() {
    let r = RaizFalsa::nueva("uid0");
    r.escribir(
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n\
         puerta:x:0:0:backdoor:/root:/bin/bash\n\
         ana:x:1000:1000::/home/ana:/bin/bash\n",
        0o644,
    );

    let informe = Scanner::new().scan(r.path());
    let h = buscar(&informe, "AEGIS-ACCT-UID0-puerta").expect("debe detectarse");
    assert_eq!(h.severity, Severity::Critical);
    // root con UID 0 es lo normal y no debe reportarse.
    assert!(!tiene(&informe, "AEGIS-ACCT-UID0-root"));
}

#[test]
fn detecta_hash_de_contrasena_vacio() {
    let r = RaizFalsa::nueva("nopass");
    r.escribir(
        "/etc/shadow",
        "root:$6$x$y:19000::::::\nabierta::19000::::::\n",
        0o640,
    );
    let informe = Scanner::new().scan(r.path());
    let h = buscar(&informe, "AEGIS-SHADOW-NOPASS-abierta").expect("debe detectarse");
    assert_eq!(h.severity, Severity::Critical);
    assert!(!tiene(&informe, "AEGIS-SHADOW-NOPASS-root"));
}

#[test]
fn detecta_binario_setuid_en_directorio_temporal() {
    let r = RaizFalsa::nueva("suidtmp");
    r.escribir("/tmp/.rootshell", "#!/bin/sh\n", 0o4755);

    let informe = Scanner::new().scan(r.path());
    let h = buscar(&informe, "AEGIS-SUIDTMP").expect("debe detectarse");
    assert_eq!(h.severity, Severity::Critical);
    assert_eq!(h.category, Category::Persistence);
}

#[test]
fn detecta_binario_escribible_por_todos_en_el_path() {
    let r = RaizFalsa::nueva("worldwrite");
    r.escribir("/usr/bin/servicio", "#!/bin/sh\n", 0o777);

    let informe = Scanner::new().scan(r.path());
    let h = buscar(&informe, "AEGIS-WW-servicio").expect("debe detectarse");
    assert_eq!(h.severity, Severity::Critical);
}

#[test]
fn cruza_el_inventario_contra_el_feed() {
    let r = RaizFalsa::nueva("cve");
    r.escribir(
        "/var/lib/dpkg/status",
        "Package: xz-utils\nStatus: install ok installed\nVersion: 5.6.1-1\n\n\
         Package: openssl\nStatus: install ok installed\nVersion: 3.0.8-1\n\n\
         Package: curl\nStatus: install ok installed\nVersion: 8.5.0-1\n",
        0o644,
    );

    let feed = CveFeed::parse(
        "CVE-2024-3094|xz-utils|5.6.0|5.6.2|critical|10.0|Puerta trasera\n\
         CVE-2022-3602|openssl|3.0.0|3.0.7|high|7.5|Desbordamiento punycode\n\
         CVE-2023-38545|curl|7.69.0|8.4.0|high|8.8|Desbordamiento SOCKS5\n",
    )
    .expect("feed valido");

    let informe = Scanner::with_feed(feed).scan(r.path());

    // xz 5.6.1 esta dentro de [5.6.0, 5.6.2): vulnerable.
    let xz = buscar(&informe, "CVE-2024-3094").expect("xz debe salir");
    assert_eq!(xz.severity, Severity::Critical);
    assert_eq!(xz.category, Category::Vulnerability);
    assert!(xz.evidence.contains("5.6.1-1"));
    assert!(xz.remediation.contains("5.6.2"));

    // openssl 3.0.8 >= 3.0.7: ya corregido, NO debe salir.
    assert!(
        !tiene(&informe, "CVE-2022-3602"),
        "reportar una version ya parcheada ensena al operador a ignorar el informe"
    );
    // curl 8.5.0 >= 8.4.0: corregido.
    assert!(!tiene(&informe, "CVE-2023-38545"));
}

#[test]
fn sin_feed_no_hay_hallazgos_de_vulnerabilidad() {
    let r = RaizFalsa::nueva("sinfeed");
    r.escribir(
        "/var/lib/dpkg/status",
        "Package: xz-utils\nStatus: install ok installed\nVersion: 5.6.1-1\n",
        0o644,
    );
    let informe = Scanner::new().scan(r.path());
    assert_eq!(informe.feed_records, 0);
    assert!(!informe
        .findings
        .iter()
        .any(|f| f.category == Category::Vulnerability));
}

#[test]
fn el_informe_sale_ordenado_por_gravedad_descendente() {
    let r = RaizFalsa::nueva("orden");
    r.escribir("/etc/shadow", "root:x:1::::::\n", 0o644); // critico
    r.escribir("/etc/group", "root:x:0:\n", 0o666); // bajo
    r.escribir("/proc/sys/kernel/dmesg_restrict", "0\n", 0o644); // bajo

    let informe = Scanner::new().scan(r.path());
    assert!(informe.findings.len() >= 2);
    for par in informe.findings.windows(2) {
        assert!(
            par[0].severity >= par[1].severity,
            "el informe debe ir de mayor a menor gravedad: {:?} antes que {:?}",
            par[0].severity,
            par[1].severity
        );
    }
}

#[test]
fn el_escaneo_es_determinista() {
    let r = RaizFalsa::nueva("determinista");
    r.escribir("/etc/shadow", "root:x:1::::::\n", 0o644);
    r.escribir(
        "/var/lib/dpkg/status",
        "Package: b\nStatus: install ok installed\nVersion: 1.0\n\n\
         Package: a\nStatus: install ok installed\nVersion: 1.0\n",
        0o644,
    );

    let s = Scanner::new();
    let ids1: Vec<String> = s
        .scan(r.path())
        .findings
        .iter()
        .map(|f| f.id.clone())
        .collect();
    let ids2: Vec<String> = s
        .scan(r.path())
        .findings
        .iter()
        .map(|f| f.id.clone())
        .collect();
    // Un informe cuyo orden cambia entre ejecuciones es imposible de comparar
    // con el anterior, y comparar con el anterior es como se ve si algo mejoro.
    assert_eq!(ids1, ids2);
}

#[test]
fn has_actionable_distingue_lo_grave_de_lo_informativo() {
    let leve = RaizFalsa::nueva("leve");
    leve.escribir("/proc/sys/kernel/dmesg_restrict", "0\n", 0o644);
    assert!(!Scanner::new().scan(leve.path()).has_actionable());

    let grave = RaizFalsa::nueva("grave");
    grave.escribir("/etc/shadow", "root:x:1::::::\n", 0o666);
    assert!(Scanner::new().scan(grave.path()).has_actionable());
}

#[test]
fn el_feed_que_se_distribuye_es_valido() {
    // El feed que acompaña al producto tiene que analizarse sin errores: si se
    // rompe, el escaner arranca sin datos de CVE y el informe dice "limpio".
    let texto = include_str!("../data/cve-feed.txt");
    let feed = CveFeed::parse(texto).expect("el feed distribuido debe ser valido");
    assert!(feed.len() >= 10, "solo {} registros", feed.len());
    assert!(feed.covered_packages() >= 10);
}
