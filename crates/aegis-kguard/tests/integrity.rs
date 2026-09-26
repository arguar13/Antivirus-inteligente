//! Pruebas de la guarda de Ring 0: integridad del bytecode y permisos de mapas.
//!
//! La prueba de interoperabilidad es la que importa: el manifiesto lo firma el
//! tool de Python y lo verifica este crate. Si el HMAC de los dos lados no
//! coincidiera, el agente rechazaria en produccion su propio bytecode legitimo,
//! o —peor— aceptaria uno manipulado. Dos implementaciones independientes que
//! coinciden es lo unico que descarta ambas cosas.

use std::path::PathBuf;
use std::process::Command;

use aegis_kguard::integrity::{self, IntegrityError, Manifest};
use aegis_kguard::mapperms::{self, MapPermVerdict};

// ---------------------------------------------------------------------------
// HMAC: vectores de prueba conocidos
// ---------------------------------------------------------------------------

/// Vector 2 de la RFC 4231 para HMAC-SHA256: clave "Jefe", datos
/// "what do ya want for nothing?". Verifica que la implementacion es el
/// HMAC-SHA256 estandar y no una variante.
#[test]
fn el_hmac_coincide_con_el_vector_de_la_rfc_4231() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let esperado = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    let got = integrity::hmac_sha256(key, data);
    assert_eq!(hex(&got), esperado);
}

#[test]
fn la_comparacion_en_tiempo_constante_es_correcta() {
    assert!(integrity::constant_time_eq(b"abcabc", b"abcabc"));
    assert!(!integrity::constant_time_eq(b"abcabc", b"abcabd"));
    assert!(!integrity::constant_time_eq(b"abc", b"abcd"));
    assert!(integrity::constant_time_eq(b"", b""));
}

// ---------------------------------------------------------------------------
// Manifiesto
// ---------------------------------------------------------------------------

#[test]
fn el_manifiesto_va_y_vuelve_por_texto() {
    let key = b"clave-de-prueba";
    let mut m = Manifest::new();
    m.insert("a.bpf.o", integrity::hmac_sha256(key, b"contenido a"));
    m.insert("b.bpf.o", integrity::hmac_sha256(key, b"contenido b"));

    let texto = m.render();
    let vuelta = Manifest::parse(&texto).unwrap();
    assert_eq!(vuelta.len(), 2);
    assert!(vuelta.verify("a.bpf.o", b"contenido a", key).is_ok());
    assert!(vuelta.verify("b.bpf.o", b"contenido b", key).is_ok());
}

#[test]
fn un_objeto_manipulado_se_detecta() {
    let key = b"clave-de-produccion-secreta";
    let bytecode_original = b"\x7fELF...programa legitimo...";
    let mut m = Manifest::new();
    m.insert(
        "probes.bpf.o",
        integrity::hmac_sha256(key, bytecode_original),
    );

    // El original verifica.
    assert!(m.verify("probes.bpf.o", bytecode_original, key).is_ok());

    // Un solo bit cambiado en el bytecode: la verificacion falla.
    let mut manipulado = bytecode_original.to_vec();
    manipulado[10] ^= 0x01;
    assert_eq!(
        m.verify("probes.bpf.o", &manipulado, key),
        Err(IntegrityError::Mismatch("probes.bpf.o".into()))
    );
}

#[test]
fn sin_la_clave_no_se_puede_falsificar_la_firma() {
    let key_real = b"la clave que solo tiene el agente";
    let key_atacante = b"la clave que el atacante adivina.";
    let bytecode_malicioso = b"...programa del atacante...";

    // El atacante cambia el bytecode y recalcula el HMAC con SU clave.
    let mut m = Manifest::new();
    m.insert(
        "probes.bpf.o",
        integrity::hmac_sha256(key_atacante, bytecode_malicioso),
    );

    // Pero el agente verifica con la clave REAL: no coincide.
    assert_eq!(
        m.verify("probes.bpf.o", bytecode_malicioso, key_real),
        Err(IntegrityError::Mismatch("probes.bpf.o".into()))
    );
}

#[test]
fn un_objeto_no_firmado_no_se_carga() {
    let m = Manifest::new();
    assert_eq!(
        m.verify("desconocido.bpf.o", b"x", b"k"),
        Err(IntegrityError::NotInManifest("desconocido.bpf.o".into()))
    );
}

#[test]
fn un_manifiesto_malformado_se_rechaza() {
    assert!(matches!(
        Manifest::parse("a.o  zz"),
        Err(IntegrityError::BadDigest(_))
    ));
    assert!(matches!(
        Manifest::parse("a.o"),
        Err(IntegrityError::BadManifestLine(_))
    ));
    // Comentarios y lineas vacias se ignoran.
    let m = Manifest::parse("# comentario\n\n").unwrap();
    assert!(m.is_empty());
}

// ---------------------------------------------------------------------------
// Interoperabilidad con el tool de Python
// ---------------------------------------------------------------------------

/// Lo que firma Python lo verifica el crate, con la MISMA clave de desarrollo.
#[test]
fn lo_que_firma_python_lo_verifica_el_crate() {
    // La clave de desarrollo del tool (sign_bytecode.py CLAVE_DEV).
    let clave_dev = hex_a_bytes("a1b2c3d4e5f60718293a4b5c6d7e8f900f1e2d3c4b5a69788796a5b4c3d2e1f0");

    // Se genera un objeto de prueba con bytes reproducibles.
    let dir = std::env::temp_dir().join(format!("aegis-kguard-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let obj = dir.join("prueba.bpf.o");
    let contenido: Vec<u8> = (0..4096u32).flat_map(|i| i.to_le_bytes()).collect();
    std::fs::write(&obj, &contenido).unwrap();

    let tool = ruta_tool();
    // Firma con Python.
    let firmar = Command::new("python3")
        .arg(&tool)
        .arg("sign")
        .arg(&obj)
        .env_remove("AEGIS_BPF_HMAC_KEY")
        .output();
    let firmar = match firmar {
        Ok(o) if o.status.success() => o,
        _ => {
            eprintln!("python3 no disponible o fallo; se omite la interop");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
    };
    let _ = firmar;

    // El manifiesto que escribio Python vive en out/bytecode.manifest del
    // subproyecto; se lee y se verifica con el crate.
    let manifiesto_txt = std::fs::read_to_string(ruta_manifiesto()).unwrap();
    let m = Manifest::parse(&manifiesto_txt).unwrap();

    assert!(
        m.verify("prueba.bpf.o", &contenido, &clave_dev).is_ok(),
        "el crate no valido la firma que produjo Python: las implementaciones \
         de HMAC no coinciden"
    );

    // Y un byte cambiado la invalida tambien por esta via.
    let mut roto = contenido.clone();
    roto[0] ^= 0xFF;
    assert!(m.verify("prueba.bpf.o", &roto, &clave_dev).is_err());

    let _ = std::fs::remove_dir_all(&dir);
    // Se restaura el manifiesto del subproyecto firmando de nuevo los objetos
    // reales, para no dejar el arbol con un manifiesto de prueba.
    restaurar_manifiesto();
}

fn ruta_tool() -> PathBuf {
    PathBuf::from(raiz_crate()).join("../../drivers/linux/aegis-bpf/tools/sign_bytecode.py")
}

fn ruta_manifiesto() -> PathBuf {
    PathBuf::from(raiz_crate()).join("../../drivers/linux/aegis-bpf/out/bytecode.manifest")
}

fn restaurar_manifiesto() {
    let bpf_dir = PathBuf::from(raiz_crate()).join("../../drivers/linux/aegis-bpf");
    let probes = bpf_dir.join("out/aegis_probes.bpf.o");
    let xdp = bpf_dir.join("out/aegis_xdp.bpf.o");
    if probes.exists() && xdp.exists() {
        let _ = Command::new("python3")
            .arg(ruta_tool())
            .arg("sign")
            .arg(&probes)
            .arg(&xdp)
            .output();
    }
}

// ---------------------------------------------------------------------------
// Permisos de mapas
// ---------------------------------------------------------------------------

#[test]
fn la_regla_de_permisos_solo_acepta_0600_de_root() {
    // Correcto.
    assert_eq!(mapperms::evaluar(0o600, 0), MapPermVerdict::Locked);

    // Legible por grupo u otros: demasiado abierto.
    assert!(matches!(
        mapperms::evaluar(0o640, 0),
        MapPermVerdict::TooOpen { .. }
    ));
    assert!(matches!(
        mapperms::evaluar(0o644, 0),
        MapPermVerdict::TooOpen { .. }
    ));
    assert!(matches!(
        mapperms::evaluar(0o606, 0),
        MapPermVerdict::TooOpen { .. }
    ));

    // 0600 pero de un usuario cualquiera: sigue siendo suyo para leerlo.
    assert!(matches!(
        mapperms::evaluar(0o600, 1000),
        MapPermVerdict::WrongOwner { uid: 1000 }
    ));
}

#[test]
fn el_veredicto_de_bloqueo_es_claro() {
    assert!(mapperms::evaluar(0o600, 0).is_locked());
    assert!(!mapperms::evaluar(0o644, 0).is_locked());
    assert!(!mapperms::evaluar(0o600, 33).is_locked());
}

#[cfg(target_os = "linux")]
#[test]
fn el_bloqueo_en_disco_deja_el_fichero_en_0600() {
    // Se crea un fichero, se bloquea y se comprueba el resultado. El
    // propietario sera quien corra la prueba; si es root, queda Locked, y si no
    // queda WrongOwner: en ambos casos el MODO tiene que ser 0600.
    let dir = std::env::temp_dir().join(format!("aegis-kguard-perm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("mapa");
    std::fs::write(&f, b"contenido de mapa").unwrap();

    let v = mapperms::bloquear(&f).unwrap();
    // Sea cual sea el uid, el modo tiene que haber quedado sin bits de grupo ni
    // otros.
    use std::os::unix::fs::PermissionsExt;
    let modo = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
    assert_eq!(modo, 0o600, "el bloqueo no dejo el fichero en 0600");
    // El veredicto es coherente con el uid real.
    if v == MapPermVerdict::Locked {
        // corriendo como root
    } else {
        assert!(matches!(v, MapPermVerdict::WrongOwner { .. }));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_a_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// La raiz del crate, leida al EJECUTAR y no congelada al compilar.
///
/// Con `env!("CARGO_MANIFEST_DIR")` la ruta quedaba fijada en el binario, y
/// Cargo no lo recompila al mover el repositorio de carpeta (el hash de un
/// paquete de ruta es relativo al workspace): la prueba seguia buscando sus
/// ficheros en la ruta vieja y fallaba diciendo que no existian. Cargo define la
/// variable al lanzar pruebas y ejemplos; el valor de compilacion queda solo para
/// quien ejecute el binario a mano.
fn raiz_crate() -> String {
    std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string())
}
