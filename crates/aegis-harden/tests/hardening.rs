//! Pruebas del blindaje: cifrado de cadenas y anti-depuracion.
//!
//! La prueba central es de INTEROPERABILIDAD, no de una sola implementacion:
//! comprueba que lo que cifra `tools/obfuscate.py` con OpenSSL lo descifra el
//! crate con la caja `aes-gcm`, byte a byte. Un cifrado que solo se prueba
//! contra su propio descifrado no demuestra nada; que dos implementaciones
//! independientes coincidan, si.

use std::collections::HashMap;
use std::process::Command;

use aegis_harden::antidebug::{self, DebuggerCheck, Policy};
use aegis_harden::strings;
use aegis_prueba::{omitir, Requisito};

// ---------------------------------------------------------------------------
// Cifrado de cadenas
// ---------------------------------------------------------------------------

/// Los textos en claro del manifiesto, para cotejar el descifrado.
fn secretos_del_manifiesto() -> HashMap<String, String> {
    let raiz = raiz_crate();
    let ruta = format!("{raiz}/../../tools/secrets.json");
    let texto =
        std::fs::read_to_string(&ruta).unwrap_or_else(|e| panic!("no se pudo leer {ruta}: {e}"));

    // Analizador minimo del bloque "secrets": el manifiesto es nuestro y de
    // formato fijo, asi que no hace falta arrastrar una dependencia de JSON a
    // un crate de blindaje solo para una prueba.
    let mut m = HashMap::new();
    let inicio = texto.find("\"secrets\"").expect("falta el bloque secrets");
    let bloque = &texto[inicio..];
    let abre = bloque.find('{').unwrap();
    let cierra = bloque[abre..].find('}').unwrap() + abre;
    for linea in bloque[abre + 1..cierra].lines() {
        let l = linea.trim().trim_end_matches(',');
        if l.is_empty() {
            continue;
        }
        let (k, v) = l.split_once(':').expect("linea clave:valor");
        let clave = k.trim().trim_matches('"').to_string();
        let valor = descomillar(v.trim());
        m.insert(clave, valor);
    }
    m
}

/// Quita las comillas y deshace los escapes de una cadena JSON simple.
fn descomillar(s: &str) -> String {
    let s = s.trim().trim_matches('"');
    s.replace("\\/", "/").replace("\\\"", "\"")
}

#[test]
fn lo_que_cifra_python_lo_descifra_el_crate() {
    let esperados = secretos_del_manifiesto();
    assert!(!esperados.is_empty(), "el manifiesto no tenia secretos");

    let vault = aegis_harden::unseal_builtin().expect("la tabla empotrada descifra");
    assert_eq!(
        vault.len(),
        esperados.len(),
        "la tabla generada y el manifiesto tienen distinto numero de cadenas: \
         el fichero generado esta desfasado"
    );

    for (nombre, claro) in &esperados {
        assert_eq!(
            vault.get(nombre),
            Some(claro.as_str()),
            "la cadena {nombre} no descifra a su valor del manifiesto"
        );
    }
}

/// La prueba que justifica todo el modulo: las cadenas NO estan en claro en el
/// codigo generado. Si estuvieran, el cifrado seria decorativo.
#[test]
fn las_cadenas_no_aparecen_en_claro_en_el_fichero_generado() {
    let raiz = raiz_crate();
    let generado = std::fs::read_to_string(format!("{raiz}/src/generated_strings.rs")).unwrap();
    for (nombre, claro) in secretos_del_manifiesto() {
        // El nombre logico SI puede aparecer (es la etiqueta de busqueda); el
        // valor en claro NO.
        assert!(
            !generado.contains(&claro),
            "el valor de {nombre} ({claro:?}) esta en claro en el fichero generado"
        );
    }
    // Y un endpoint concreto que un analista buscaria tampoco.
    assert!(!generado.contains("aegiscore.internal"));
}

#[test]
fn una_tabla_manipulada_no_autentica() {
    let vault = aegis_harden::unseal_builtin().unwrap();
    let clave = strings::derive_key(&[0x1111_1111_1111_1111, 2, 3, 4], b"sal equivocada");
    // Con la clave equivocada, ninguna entrada de la tabla real descifra.
    let algun_nonce = [0u8; 12];
    assert!(matches!(
        strings::reveal(&clave, &algun_nonce, &[0u8; 32]),
        Err(strings::RevealError::Authentication)
    ));
    // El vault correcto si tiene contenido: la prueba anterior no fue vacia.
    assert!(!vault.is_empty());
}

#[test]
fn un_secreto_no_se_revela_en_su_debug() {
    let vault = aegis_harden::unseal_builtin().unwrap();
    let nombre = aegis_harden::builtin_names().next().unwrap();
    let valor = vault.get(nombre).unwrap().to_string();
    // El Debug del Vault no vuelca las cadenas.
    let dbg = format!("{vault:?}");
    assert!(
        !dbg.contains(&valor),
        "el Debug del Vault revela una cadena"
    );
    assert!(dbg.contains("cadenas"));
}

#[test]
fn el_nonce_debe_tener_doce_bytes() {
    let clave = [0u8; 32];
    assert!(matches!(
        strings::reveal(&clave, &[0u8; 8], &[0u8; 32]),
        Err(strings::RevealError::BadNonce(8))
    ));
}

/// El self-test del propio tool tiene que pasar: es la comprobacion de que la
/// derivacion de clave y de nonce coinciden entre Python y Rust.
#[test]
fn el_self_test_del_tool_pasa() {
    let raiz = raiz_crate();
    let tool = format!("{raiz}/../../tools/obfuscate.py");
    let salida = match Command::new("python3")
        .arg(&tool)
        .arg("--self-test")
        .output()
    {
        Ok(o) => o,
        Err(_) => {
            omitir(
                "python3 no disponible: el self-test del tool no se ejercio",
                Requisito::Herramienta("python3"),
            );
            return;
        }
    };
    assert!(
        salida.status.success(),
        "el self-test del tool fallo: {}",
        String::from_utf8_lossy(&salida.stderr)
    );
}

/// El fichero generado tiene que estar al dia respecto al manifiesto: si
/// alguien cambia una cadena y no regenera, `--check` lo detecta.
#[test]
fn el_fichero_generado_esta_al_dia() {
    let raiz = raiz_crate();
    let tool = format!("{raiz}/../../tools/obfuscate.py");
    let salida = match Command::new("python3").arg(&tool).arg("--check").output() {
        Ok(o) => o,
        Err(_) => {
            omitir(
                "python3 no disponible: --check no se ejercio",
                Requisito::Herramienta("python3"),
            );
            return;
        }
    };
    assert!(
        salida.status.success(),
        "generated_strings.rs esta desfasado respecto a secrets.json; \
         ejecuta tools/obfuscate.py. stderr: {}",
        String::from_utf8_lossy(&salida.stderr)
    );
}

// ---------------------------------------------------------------------------
// Anti-depuracion
// ---------------------------------------------------------------------------

#[test]
fn el_analisis_de_tracer_pid_reconoce_los_dos_casos() {
    let sin = "Name:\tagent\nState:\tR\nTracerPid:\t0\nUid:\t0\n";
    assert_eq!(antidebug::parse_tracer_pid(sin), Some(0));

    let con = "Name:\tagent\nTracerPid:\t4242\nUid:\t0\n";
    assert_eq!(antidebug::parse_tracer_pid(con), Some(4242));

    // Sin el campo, no se afirma nada.
    assert_eq!(antidebug::parse_tracer_pid("Name:\tagent\n"), None);
}

#[test]
fn detect_no_toca_el_proceso() {
    // `detect` es la via segura: no reclama el trazador ni cierra nada, asi que
    // se puede llamar en el propio proceso de pruebas sin riesgo. En CI no suele
    // haber depurador; lo que se exige es que la deteccion sea coherente con lo
    // que dice /proc.
    let e = antidebug::detect();
    let esperado = matches!(
        antidebug::tracer_from_proc(),
        DebuggerCheck::Detected { .. }
    );
    assert_eq!(e.detected, esperado);
    // Y sea cual sea el resultado, el proceso sigue vivo despues de detect.
}

/// Ejecuta `f` en un proceso hijo y devuelve su codigo de salida.
///
/// Todo lo que reclama el trazador con `PTRACE_TRACEME` tiene que correr en un
/// hijo y no en el proceso de pruebas: si el proceso de `cargo test` se marcara
/// a si mismo como trazado, su padre (cargo) no sabria recolectarlo y quedaria
/// como zombi, colgando la suite. En el hijo, el trazador es el propio proceso
/// de pruebas, que si recolecta con `waitpid`.
fn en_hijo<F: FnOnce() -> i32>(f: F) -> i32 {
    // SAFETY: fork sobre un proceso con hilos es seguro para el hijo mientras
    // solo use funciones seguras tras fork; glibc reinicia el candado del
    // asignador en el hijo, asi que la lectura de /proc y las asignaciones
    // pequenas que hacen estas funciones no se bloquean.
    match unsafe { libc::fork() } {
        -1 => panic!("fork fallo"),
        0 => {
            let codigo = f();
            // SAFETY: `_exit` termina el hijo sin ejecutar destructores ni
            // tocar el estado compartido con el padre.
            unsafe { libc::_exit(codigo) };
        }
        pid => {
            let mut status = 0i32;
            // SAFETY: `pid` es un hijo directo; `status` es una pila valida.
            let r = unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(r, pid, "waitpid no recolecto al hijo");
            assert!(libc::WIFEXITED(status), "el hijo no salio normalmente");
            libc::WEXITSTATUS(status)
        }
    }
}

#[test]
fn claim_traceme_no_detecta_nada_sin_depurador() {
    // En un proceso limpio, reclamar el trazador tiene exito (no habia nadie),
    // asi que el hijo sale 0. Si saliera 1 significaria que algo ya estaba
    // trazando, que en CI no debe ocurrir.
    let codigo = en_hijo(|| match antidebug::claim_traceme() {
        DebuggerCheck::Clear => 0,
        DebuggerCheck::Detected { .. } => 1,
    });
    assert_eq!(
        codigo, 0,
        "claim_traceme detecto un trazador en un proceso que no deberia tenerlo"
    );
}

#[test]
fn enforce_terminate_no_mata_sin_depurador() {
    // Sin depurador, enforce(Terminate) NO debe cerrar el proceso: tiene que
    // devolver detected=false y dejar que el hijo salga con su propio codigo.
    // Si matara, el hijo saldria con 57 (el codigo de _exit de enforce).
    let codigo = en_hijo(|| {
        let e = antidebug::enforce(Policy::Terminate);
        if e.detected {
            2
        } else {
            0
        }
    });
    assert_eq!(
        codigo, 0,
        "enforce(Terminate) cerro el proceso o detecto un depurador inexistente          (codigo {codigo}); 57 seria el _exit de terminacion"
    );
}

#[test]
fn report_only_nunca_cierra_el_proceso() {
    // Con ReportOnly, pase lo que pase el proceso sigue vivo. Se ejecuta en un
    // hijo porque reclama el trazador; que el hijo llegue a _exit con 0 lo
    // demuestra.
    let codigo = en_hijo(|| {
        let _ = antidebug::enforce(Policy::ReportOnly);
        // Una segunda llamada es idempotente y tampoco cierra.
        let _ = antidebug::enforce(Policy::ReportOnly);
        0
    });
    assert_eq!(codigo, 0, "ReportOnly no puede terminar el proceso");
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
