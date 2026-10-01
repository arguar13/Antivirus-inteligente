//! AegisPosture contra la maquina real.
//!
//! # Por que contra la maquina y no contra ficheros de prueba
//!
//! Un inventario validado con una base de datos de dpkg escrita a mano encuentra
//! exactamente lo que quien la escribio creia que habia. Aqui se coteja con las
//! herramientas del propio sistema —`dpkg-query`, `objcopy`, el `zlib` de
//! Python— y la alcanzabilidad se prueba con procesos de verdad, compilados en la
//! prueba, cuyos mapas de memoria y sockets los pone el nucleo.
//!
//! # Que pasa si falta algo
//!
//! Cada prueba que depende de una herramienta del sistema se salta Y LO DICE
//! (`OMITIDA: ...`). Una prueba que se salta en silencio cuenta como verde sin
//! haber comprobado nada.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use aegis_prueba::{omitir, Requisito};
use aegis_sbom::binario::{self, Metadatos};
use aegis_sbom::componente::{Componente, Ecosistema, Procedencia};
use aegis_sbom::telemetria::DelSistema;
use aegis_sbom::{sistema, Evaluador};

fn hay(programa: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {programa}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn tmp(n: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("aegis-sbom-real-{n}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn el_inventario_de_paquetes_coincide_con_dpkg_query() {
    if !Path::new("/var/lib/dpkg/status").exists() || !hay("dpkg-query") {
        omitir(
            "la maquina no usa dpkg: el cotejo con el gestor no se hizo",
            Requisito::Herramienta("dpkg"),
        );
        return;
    }
    let salida = Command::new("dpkg-query")
        .args(["-W", "-f", "${Package}\t${Version}\t${db:Status-Abbrev}\n"])
        .output()
        .expect("dpkg-query");
    let texto = String::from_utf8_lossy(&salida.stdout);
    // El segundo caracter de la abreviatura es el estado: `i` es instalado.
    let del_gestor: BTreeSet<(String, String)> = texto
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split('\t').collect();
            (c.len() == 3 && c[2].as_bytes().get(1) == Some(&b'i'))
                .then(|| (c[0].to_string(), c[1].to_string()))
        })
        .collect();
    let (comps, _) = sistema::paquetes(Path::new("/"));
    let nuestros: BTreeSet<(String, String)> = comps
        .iter()
        .filter(|c| c.ecosistema == Ecosistema::Deb)
        .map(|c| (c.nombre.clone(), c.version.clone()))
        .collect();
    let sobran: Vec<_> = nuestros.difference(&del_gestor).take(5).collect();
    let faltan: Vec<_> = del_gestor.difference(&nuestros).take(5).collect();
    eprintln!(
        "dpkg-query: {} instalados; inventario: {} paquetes deb",
        del_gestor.len(),
        nuestros.len()
    );
    assert!(
        sobran.is_empty() && faltan.is_empty(),
        "el inventario no coincide con el gestor de paquetes: sobran {sobran:?}, faltan {faltan:?}"
    );
    // Y los ficheros proyectables: la biblioteca de la libc tiene que estar.
    let libc = comps
        .iter()
        .find(|c| c.nombre == "libc6" || c.nombre.starts_with("libc6:"))
        .expect("libc6");
    assert_eq!(libc.nombre_fuente(), "glibc");
    assert!(
        libc.ficheros
            .iter()
            .any(|f| f.to_string_lossy().contains("libc.so.6")),
        "los ficheros de libc6 incluyen libc.so.6"
    );
}

#[test]
fn los_metadatos_de_cargo_auditable_coinciden_con_una_lectura_independiente() {
    let binario = Path::new("/usr/bin/sudo");
    let tiene =
        binario::secciones(binario).is_some_and(|s| s.iter().any(|x| x.nombre == ".dep-v0"));
    if !tiene || !hay("objcopy") || !hay("python3") {
        omitir(
            "no hay un binario con .dep-v0 (sudo-rs), objcopy o python3",
            Requisito::Herramienta("sudo-rs"),
        );
        return;
    }
    let d = tmp("auditable");
    let seccion = d.join("dep.bin");
    // `--dump-section` y no `-O binary`: `.dep-v0` no se carga en memoria (no
    // tiene SHF_ALLOC), y `-O binary` solo vuelca las secciones que si. La
    // primera version de esta prueba lo hacia asi y comparaba contra un fichero
    // vacio.
    let ok = Command::new("objcopy")
        .arg(format!("--dump-section=.dep-v0={}", seccion.display()))
        .arg(binario)
        .arg(d.join("copia-descartada"))
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "objcopy extrae la seccion");
    let py = "import zlib,json,sys\n\
              d=json.loads(zlib.decompress(open(sys.argv[1],'rb').read()))\n\
              print('\\n'.join(p['name']+' '+p['version'] for p in d['packages'] if p.get('kind')!='build'))";
    let out = Command::new("python3")
        .args(["-c", py])
        .arg(&seccion)
        .output()
        .unwrap();
    // La lectura independiente tiene que haber funcionado: comparar contra una
    // salida vacia de un script que fallo no coteja nada.
    assert!(
        out.status.success() && !out.stdout.is_empty(),
        "python3 lee la seccion: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let de_python: BTreeSet<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    let Metadatos::Leidos(v) = binario::metadatos(binario) else {
        panic!("se leen los metadatos de {}", binario.display());
    };
    let nuestros: BTreeSet<String> = v
        .iter()
        .map(|c| format!("{} {}", c.nombre, c.version))
        .collect();
    eprintln!("{}: {} crates", binario.display(), nuestros.len());
    assert_eq!(
        nuestros, de_python,
        "cargo-auditable, leido por dos implementaciones"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn la_firma_de_openssl_coincide_con_la_version_de_su_paquete() {
    let (comps, _) = sistema::paquetes(Path::new("/"));
    let Some((pkg, lib)) = comps.iter().find_map(|c| {
        c.ficheros
            .iter()
            .find(|f| f.to_string_lossy().contains("libcrypto.so.3"))
            .map(|f| (c, f.clone()))
    }) else {
        omitir(
            "no hay libcrypto.so.3 de un paquete",
            Requisito::Herramienta("libssl3"),
        );
        return;
    };
    let bytes = std::fs::read(std::fs::canonicalize(&lib).unwrap()).unwrap();
    let firmas = binario::firmas_en(&bytes);
    let upstream = pkg
        .version
        .split(':')
        .next_back()
        .unwrap()
        .split(['-', '+', '~'])
        .next()
        .unwrap()
        .to_string();
    eprintln!(
        "{}: firmas {:?}; paquete {} {}",
        lib.display(),
        firmas.iter().map(|f| &f.1).collect::<Vec<_>>(),
        pkg.nombre,
        pkg.version
    );
    assert!(
        firmas.iter().any(|(_, v)| *v == upstream),
        "la firma de OpenSSL de la biblioteca real da la version del paquete ({upstream})"
    );
}

// --- Alcanzabilidad con procesos reales ---------------------------------------

const BIBLIOTECA: &str = r#"
int vulnerable_viva(int x) { return x + 1; }
int vulnerable_muerta(int x) { return x * 2; }
"#;

const NO_CARGADA: &str = r#"
int vulnerable_nocargada(int x) { return x; }
"#;

const PROGRAMA: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
int vulnerable_viva(int);
int vulnerable_muerta(int);
/* No se llama nunca y su direccion no se toma en ningun sitio. */
int funcion_muerta(int x) { return vulnerable_muerta(x); }
static int trabajo(int x) { return vulnerable_viva(x); }
int main(int argc, char **argv) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = 0;
    a.sin_addr.s_addr = htonl((argc > 1 && strcmp(argv[1], "local") == 0) ? INADDR_LOOPBACK : INADDR_ANY);
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 4) != 0) return 2;
    printf("listo %s %d\n", zlibVersion(), trabajo(1));
    fflush(stdout);
    pause();
    return 0;
}
"#;

/// El escenario: una biblioteca cargada por un proceso que escucha, y otra que
/// no carga nadie.
struct Escenario {
    dir: PathBuf,
    hijo: Child,
    cargada: PathBuf,
    no_cargada: PathBuf,
}

impl Drop for Escenario {
    fn drop(&mut self) {
        let _ = self.hijo.kill();
        let _ = self.hijo.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn escenario(nombre: &str, modo: &str) -> Option<Escenario> {
    if !hay("gcc") || !Path::new("/usr/include/zlib.h").exists() {
        omitir(
            "sin gcc o sin cabeceras de zlib: la alcanzabilidad real no se probo",
            Requisito::Herramienta("zlib1g-dev"),
        );
        return None;
    }
    let dir = tmp(nombre);
    std::fs::write(dir.join("b.c"), BIBLIOTECA).unwrap();
    std::fs::write(dir.join("n.c"), NO_CARGADA).unwrap();
    std::fs::write(dir.join("p.c"), PROGRAMA).unwrap();
    let cargada = dir.join(format!("libaegis{nombre}.so"));
    let no_cargada = dir.join(format!("libaegisno{nombre}.so"));
    let gcc = |args: &[&str]| {
        let st = Command::new("gcc")
            .current_dir(&dir)
            .args(args)
            .status()
            .unwrap();
        assert!(st.success(), "gcc {args:?}");
    };
    gcc(&[
        "-O0",
        "-shared",
        "-fPIC",
        "-o",
        cargada.to_str().unwrap(),
        "b.c",
    ]);
    gcc(&[
        "-O0",
        "-shared",
        "-fPIC",
        "-o",
        no_cargada.to_str().unwrap(),
        "n.c",
    ]);
    let rpath = format!("-Wl,-rpath,{}", dir.display());
    let enlace = format!("-laegis{nombre}");
    gcc(&[
        "-O0",
        "-o",
        "programa",
        "p.c",
        "-L",
        dir.to_str().unwrap(),
        &enlace,
        "-lz",
        &rpath,
    ]);
    let mut hijo = Command::new(dir.join("programa"))
        .arg(modo)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut linea = String::new();
    BufReader::new(hijo.stdout.take().unwrap())
        .read_line(&mut linea)
        .unwrap();
    assert!(linea.starts_with("listo"), "el programa arranca: {linea:?}");
    Some(Escenario {
        dir,
        hijo,
        cargada,
        no_cargada,
    })
}

fn comp(nombre: &str, f: &Path) -> Componente {
    let mut c = Componente::nuevo(
        Ecosistema::Generico,
        nombre,
        "1.0",
        Procedencia::Firma {
            fichero: f.to_path_buf(),
            firma: "prueba",
        },
    );
    c.ficheros = vec![f.to_path_buf()];
    c
}

#[test]
fn una_biblioteca_cargada_y_otra_no_dan_respuestas_distintas_y_se_ve_por_que() {
    let Some(e) = escenario("red", "red") else {
        return;
    };
    let pid = e.hijo.id();
    let ev = Evaluador::nuevo(&DelSistema);
    let (leidos, no_leidos) = ev.cobertura();
    eprintln!("procesos: {leidos} leidos, {no_leidos} no leidos");

    // LA CARGADA: el proceso la tiene proyectada, llama a la funcion vulnerable
    // desde main y escucha en todas las interfaces.
    let a = ev.evaluar(&comp("aegisred", &e.cargada), &["vulnerable_viva".into()]);
    eprintln!("cargada, funcion viva: {a:#?}");
    assert!(a.cargado.es_si() && a.procesos.contains(&pid), "{a:?}");
    assert!(
        a.alcanzable.es_si(),
        "main -> trabajo -> vulnerable_viva: {a:?}"
    );
    assert!(a.expuesto.es_si(), "escucha en 0.0.0.0: {a:?}");

    // La misma biblioteca, otra funcion: se importa, pero solo la llama una
    // funcion a la que no llega nadie. Cargada y expuesta, y NO alcanzable.
    let b = ev.evaluar(&comp("aegisred", &e.cargada), &["vulnerable_muerta".into()]);
    eprintln!("cargada, funcion muerta: {:?}", b.alcanzable);
    assert!(b.cargado.es_si());
    assert!(b.alcanzable.es_no(), "{b:?}");

    // LA NO CARGADA: ningun proceso la tiene. Si se pudieron leer todos los
    // procesos, eso es un «No» comprobado; si no, es «sin datos», y no otra cosa.
    let c = ev.evaluar(
        &comp("aegisnored", &e.no_cargada),
        &["vulnerable_nocargada".into()],
    );
    eprintln!("no cargada: {c:#?}");
    if no_leidos == 0 {
        assert!(c.cargado.es_no(), "{c:?}");
        assert!(c.alcanzable.es_no());
        assert!(c.expuesto.es_no());
    } else {
        assert_eq!(c.cargado.nombre(), "sin-datos", "{c:?}");
    }
    assert_ne!(
        a.prioridad(),
        c.prioridad(),
        "las respuestas distintas ordenan distinto"
    );
}

#[test]
fn un_servicio_que_solo_escucha_en_bucle_local_no_esta_expuesto() {
    let Some(e) = escenario("local", "local") else {
        return;
    };
    let ev = Evaluador::nuevo(&DelSistema);
    let a = ev.evaluar(&comp("aegislocal", &e.cargada), &["vulnerable_viva".into()]);
    eprintln!("{:?}", a.expuesto);
    assert!(a.cargado.es_si());
    assert!(a.expuesto.es_no(), "{a:?}");
    assert!(a.expuesto.porque().contains("127.0.0.1"));
}
