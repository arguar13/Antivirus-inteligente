//! Proveedores de las tablas de contenedores.
//!
//! # De donde salen los datos
//!
//! Del NUCLEO, no del runtime. La justificacion completa esta en la cabecera de
//! `aegis_parser::esquema::contenedores`, y se resume en que hablar con el
//! socket de Docker exige un permiso que equivale a ser root del anfitrion: un
//! EDR que lo necesita para leer una tabla se ha concedido a si mismo la
//! escalada que deberia estar vigilando.
//!
//! Lo que se lee, entonces, es `/proc/<pid>/cgroup` y `/proc/<pid>/ns/*`, que
//! son estado del nucleo y no requieren nada. Lo que de verdad SOLO sabe el
//! runtime —el nombre legible de una imagen, los volumenes declarados— se lee de
//! sus ficheros de estado cuando son legibles, y se declara como hueco cuando no.

use std::collections::BTreeMap;

use aegis_parser::esquema::{contenedores as esq, Coste, Tabla as Esquema};

use crate::contexto::Contexto;
use crate::procesos::nombre_de_capacidad;
use crate::tabla::{Constructor, Filas, Filtro, MotivoNoLeible, Tabla};

/// Capacidades que permiten salir de un contenedor.
///
/// No es una lista de «capacidades importantes»: cada una de estas es, por si
/// sola, una via documentada de escape. `CAP_SYS_MODULE` carga un modulo en el
/// nucleo DEL ANFITRION; `CAP_SYS_ADMIN` permite montar; `CAP_SYS_PTRACE`
/// permite entrar en procesos de fuera si se comparte el espacio de PID.
pub const CAPACIDADES_DE_ESCAPE: &[&str] = &[
    "CAP_SYS_ADMIN",
    "CAP_SYS_MODULE",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_BOOT",
    "CAP_DAC_READ_SEARCH",
    "CAP_NET_ADMIN",
    "CAP_BPF",
];

/// Rutas del anfitrion cuyo montaje dentro de un contenedor es una via de salida.
pub const MONTAJES_DE_ESCAPE: &[&str] = &[
    "/",
    "/proc",
    "/sys",
    "/dev",
    "/etc",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/containerd/containerd.sock",
    "/run/containerd/containerd.sock",
    "/var/lib/kubelet",
];

/// Identidad de un contenedor deducida de la ruta de su cgroup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identidad {
    /// Identificador.
    pub id: String,
    /// Runtime que lo creo.
    pub runtime: &'static str,
}

/// Deduce el contenedor a partir de la ruta de un cgroup.
///
/// Cada runtime escribe la ruta a su manera, y esta funcion las conoce todas:
///
/// ```text
/// docker      /docker/<id64>                 o /system.slice/docker-<id64>.scope
/// containerd  /kubepods/.../<id64>           o /system.slice/containerd.service/...
/// crio        /crio-<id64>.scope
/// podman      /machine.slice/libpod-<id64>.scope
/// lxc         /lxc/<nombre>
/// ```
///
/// Devuelve `None` para los procesos del anfitrion, que es la mayoria: un cgroup
/// de systemd normal no es un contenedor, y tratar cualquier cgroup como tal
/// llenaria la tabla con el sistema entero.
pub fn identidad_de_cgroup(ruta: &str) -> Option<Identidad> {
    /// Un identificador de contenedor es hexadecimal y largo.
    fn es_id(s: &str) -> bool {
        s.len() >= 12 && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    for segmento in ruta.split('/') {
        let limpio = segmento.trim_end_matches(".scope");

        for (prefijo, runtime) in [
            ("docker-", "docker"),
            ("crio-", "crio"),
            ("libpod-", "podman"),
            ("cri-containerd-", "containerd"),
            ("containerd-", "containerd"),
        ] {
            if let Some(resto) = limpio.strip_prefix(prefijo) {
                if es_id(resto) {
                    return Some(Identidad {
                        id: resto.to_string(),
                        runtime,
                    });
                }
            }
        }

        // `/docker/<id>` y `/kubepods/.../<id>`: el identificador va suelto.
        if es_id(limpio) {
            let runtime = if ruta.contains("kubepods") {
                "containerd"
            } else if ruta.contains("docker") {
                "docker"
            } else {
                "unknown"
            };
            return Some(Identidad {
                id: limpio.to_string(),
                runtime,
            });
        }
    }

    // LXC no usa identificadores hexadecimales, sino el nombre del contenedor.
    if let Some(resto) = ruta.strip_prefix("/lxc/") {
        let nombre = resto.split('/').next().unwrap_or(resto);
        if !nombre.is_empty() {
            return Some(Identidad {
                id: nombre.to_string(),
                runtime: "lxc",
            });
        }
    }
    None
}

/// Declara que en esta maquina no hay ningun contenedor del que informar.
///
/// Las tres tablas que recorren contenedores comparten este hueco, y comparten
/// tambien la razon de declararlo: cero filas mudas se leen como «ningun
/// contenedor tiene esta propiedad», que es una afirmacion sobre contenedores
/// que no se han examinado porque no los hay. Tenerlo en una sola funcion evita
/// que una de las tres se olvide, que es como se cuelan estos huecos.
fn avisar_sin_contenedores(salida: &mut Filas, que_se_buscaba: &str) {
    salida.avisar(
        que_se_buscaba.to_string(),
        MotivoNoLeible::FuenteAusente {
            ruta: "ningun proceso de esta maquina corre dentro de un contenedor".to_string(),
        },
    );
}

/// Inodo de un espacio de nombres de un proceso.
fn inodo_de_ns(pid: u32, clase: &str) -> Option<u64> {
    let destino = std::fs::read_link(format!("/proc/{pid}/ns/{clase}")).ok()?;
    let texto = destino.to_string_lossy();
    let (_, resto) = texto.split_once(":[")?;
    resto.trim_end_matches(']').parse().ok()
}

// ---------------------------------------------------------------------------
// containers
// ---------------------------------------------------------------------------

/// Los procesos que corren dentro de contenedores.
#[derive(Debug, Clone, Copy, Default)]
pub struct Contenedores;

impl Tabla for Contenedores {
    fn esquema(&self) -> &'static Esquema {
        &esq::CONTAINERS
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        if !ctx.es_el_sistema_real() {
            return Err(MotivoNoLeible::NoAplicaEnEstaPlataforma {
                interfaz: "los cgroups del nucleo real; no se pueden redirigir a otra raiz",
            });
        }
        let procesos = ctx.procesos()?;
        // Los espacios del proceso 1: son la referencia del anfitrion.
        let ns_init_pid = inodo_de_ns(1, "pid");
        let ns_init_net = inodo_de_ns(1, "net");

        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for p in procesos {
            let pid = p.key.pid;
            salida.examinadas += 1;
            let Ok(cgroup) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
                continue;
            };
            // Se mira cada jerarquia: en cgroup v1 el contenedor puede aparecer
            // en una y no en otra.
            let Some((identidad, ruta)) = cgroup.lines().find_map(|l| {
                let ruta = l.splitn(3, ':').nth(2)?;
                identidad_de_cgroup(ruta).map(|i| (i, ruta.to_string()))
            }) else {
                continue;
            };

            let ns_pid = inodo_de_ns(pid, "pid");
            let ns_net = inodo_de_ns(pid, "net");

            c.texto("id", identidad.id);
            c.texto("runtime", identidad.runtime);
            c.entero("pid", i64::from(pid));
            c.texto_opcional("process", p.image_name());
            c.texto("cgroup_path", ruta);
            if let Some(n) = ns_pid {
                c.entero("pid_namespace", i64::try_from(n).unwrap_or(i64::MAX));
            }
            // Solo se afirma «comparte» cuando se han podido leer LOS DOS
            // inodos. Sin uno de ellos no se sabe, y `false` diria que esta
            // aislado, que es la conclusion tranquilizadora sin comprobar.
            match (ns_pid, ns_init_pid) {
                (Some(a), Some(b)) => {
                    c.booleano("shares_host_pid", a == b);
                }
                _ => {
                    c.pon("shares_host_pid", aegis_parser::valor::Valor::Ausente);
                }
            }
            match (ns_net, ns_init_net) {
                (Some(a), Some(b)) => {
                    c.booleano("shares_host_net", a == b);
                }
                _ => {
                    c.pon("shares_host_net", aegis_parser::valor::Valor::Ausente);
                }
            }
            salida.filas.push(c.fin());
        }

        if salida.filas.is_empty() {
            avisar_sin_contenedores(&mut salida, "los cgroups de todos los procesos");
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// container_images
// ---------------------------------------------------------------------------

/// Las imagenes de contenedor presentes.
#[derive(Debug, Clone, Copy, Default)]
pub struct Imagenes;

impl Tabla for Imagenes {
    fn esquema(&self) -> &'static Esquema {
        &esq::CONTAINER_IMAGES
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        // El repositorio de imagenes de Docker lleva un fichero con el nombre de
        // cada una. Es legible sin hablar con el demonio, que es el punto.
        let fuentes = [
            "var/lib/docker/image/overlay2/repositories.json",
            "var/lib/docker/image/overlay/repositories.json",
        ];
        let mut hubo = false;
        for f in fuentes {
            let Ok(texto) = ctx.leer_texto(f) else {
                continue;
            };
            hubo = true;
            for (referencia, id) in referencias_de_repositories(&texto) {
                salida.examinadas += 1;
                c.texto("id", id);
                c.texto("reference", referencia);
                c.texto("runtime", "docker");
                c.texto("source", f);
                salida.filas.push(c.fin());
            }
        }

        if !hubo {
            // EL MURO, dicho: sin acceso al estado del runtime no se pueden
            // enumerar las imagenes, y eso NO es lo mismo que no haber ninguna.
            salida.avisar(
                "el inventario de imagenes",
                MotivoNoLeible::SinPrivilegios {
                    operacion: "leer el estado del runtime de contenedores",
                    necesita: "acceso de lectura a /var/lib/docker o al estado de containerd",
                },
            );
        }
        Ok(salida)
    }
}

/// Extrae los pares referencia/identificador del `repositories.json` de Docker.
///
/// Se analiza sin biblioteca de JSON a proposito: el fichero tiene una forma
/// conocida y fija —`{"Repositories":{"nombre":{"nombre:tag":"sha256:..."}}}`—
/// y anadir un analizador de JSON completo al arbol del agente por un fichero de
/// inventario no se justifica. Lo que se busca son las cadenas
/// `"<referencia>": "sha256:<id>"`, que es lo unico que este fichero contiene.
pub fn referencias_de_repositories(texto: &str) -> Vec<(String, String)> {
    let mut salida = Vec::new();
    // Se recorre buscando `"algo":"sha256:...."`, sin construir un arbol.
    let bytes: Vec<char> = texto.chars().collect();
    let mut i = 0;
    let mut ultima_clave = String::new();
    while i < bytes.len() {
        if bytes[i] != '"' {
            i += 1;
            continue;
        }
        let inicio = i + 1;
        let mut j = inicio;
        while j < bytes.len() && bytes[j] != '"' {
            // Una comilla escapada no cierra la cadena.
            if bytes[j] == '\\' {
                j += 1;
            }
            j += 1;
        }
        if j >= bytes.len() {
            break;
        }
        let cadena: String = bytes[inicio..j].iter().collect();
        if let Some(id) = cadena.strip_prefix("sha256:") {
            if !ultima_clave.is_empty() && ultima_clave.contains(':') {
                salida.push((ultima_clave.clone(), id.to_string()));
            }
        } else {
            ultima_clave = cadena;
        }
        i = j + 1;
    }
    salida.sort();
    salida.dedup();
    salida
}

// ---------------------------------------------------------------------------
// container_mounts
// ---------------------------------------------------------------------------

/// Los montajes del anfitrion dentro de contenedores.
#[derive(Debug, Clone, Copy, Default)]
pub struct MontajesDeContenedor;

/// Indica si montar esta ruta del anfitrion es una via de escape.
pub fn es_montaje_de_escape(origen: &str) -> bool {
    MONTAJES_DE_ESCAPE
        .iter()
        .any(|m| origen == *m || origen.starts_with(&format!("{m}/")))
}

impl Tabla for MontajesDeContenedor {
    fn esquema(&self) -> &'static Esquema {
        &esq::CONTAINER_MOUNTS
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        if !ctx.es_el_sistema_real() {
            return Err(MotivoNoLeible::NoAplicaEnEstaPlataforma {
                interfaz: "el mountinfo de los procesos reales",
            });
        }
        let procesos = ctx.procesos()?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());
        // Un contenedor tiene muchos procesos con el mismo mountinfo: se lee uno
        // por contenedor y no uno por proceso.
        let mut vistos: BTreeMap<String, ()> = BTreeMap::new();

        for p in procesos {
            let pid = p.key.pid;
            let Ok(cgroup) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
                continue;
            };
            let Some(identidad) = cgroup
                .lines()
                .find_map(|l| identidad_de_cgroup(l.splitn(3, ':').nth(2)?))
            else {
                continue;
            };
            if vistos.insert(identidad.id.clone(), ()).is_some() {
                continue;
            }
            salida.examinadas += 1;
            let Ok(texto) = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")) else {
                continue;
            };

            for m in crate::ficheros::analizar_mountinfo(&texto) {
                // Solo los montajes que vienen del anfitrion: el sistema de
                // ficheros propio del contenedor no es un montaje del anfitrion.
                if m.tipo == "overlay" || m.tipo.starts_with("proc") || m.tipo.starts_with("sysfs")
                {
                    continue;
                }
                if m.raiz == "/" && !es_montaje_de_escape(&m.raiz) {
                    continue;
                }
                c.texto("container_id", identidad.id.clone());
                c.texto("source", m.raiz.clone());
                c.texto("destination", m.punto);
                c.booleano("writable", !m.opciones.split(',').any(|o| o == "ro"));
                c.booleano("escapes_container", es_montaje_de_escape(&m.raiz));
                salida.filas.push(c.fin());
            }
        }

        // Sin contenedores no hay montajes de contenedor, y eso hay que DECIRLO:
        // cero filas mudas se leerian como «ningun contenedor monta nada del
        // anfitrion», que es una afirmacion tranquilizadora sobre una maquina
        // donde en realidad no se ha comprobado ninguna.
        if vistos.is_empty() {
            avisar_sin_contenedores(&mut salida, "los montajes de contenedor");
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// container_capabilities
// ---------------------------------------------------------------------------

/// Las capacidades que conservan los procesos de un contenedor.
#[derive(Debug, Clone, Copy, Default)]
pub struct CapacidadesDeContenedor;

impl Tabla for CapacidadesDeContenedor {
    fn esquema(&self) -> &'static Esquema {
        &esq::CONTAINER_CAPABILITIES
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        if !ctx.es_el_sistema_real() {
            return Err(MotivoNoLeible::NoAplicaEnEstaPlataforma {
                interfaz: "el status de los procesos reales",
            });
        }
        let procesos = ctx.procesos()?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for p in procesos {
            let pid = p.key.pid;
            let Ok(cgroup) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
                continue;
            };
            let Some(identidad) = cgroup
                .lines()
                .find_map(|l| identidad_de_cgroup(l.splitn(3, ':').nth(2)?))
            else {
                continue;
            };
            salida.examinadas += 1;
            let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
                continue;
            };
            // Se mira el conjunto EFECTIVO: es el que decide lo que el proceso
            // puede hacer ahora mismo, no lo que podria llegar a tener.
            let Some(linea) = status.lines().find(|l| l.starts_with("CapEff:")) else {
                continue;
            };
            let Ok(mascara) = u64::from_str_radix(linea["CapEff:".len()..].trim(), 16) else {
                continue;
            };

            for bit in 0..64u32 {
                if mascara & (1u64 << bit) == 0 {
                    continue;
                }
                let nombre = nombre_de_capacidad(bit);
                c.texto("container_id", identidad.id.clone());
                c.entero("pid", i64::from(pid));
                c.booleano(
                    "dangerous",
                    CAPACIDADES_DE_ESCAPE.contains(&nombre.as_str()),
                );
                c.texto("capability", nombre);
                salida.filas.push(c.fin());
            }
        }

        if salida.filas.is_empty() {
            avisar_sin_contenedores(&mut salida, "las capacidades de los contenedores");
        }
        Ok(salida)
    }
}

/// Las cuatro tablas de esta familia, para el catalogo.
pub fn tablas() -> Vec<Box<dyn Tabla>> {
    vec![
        Box::new(Contenedores),
        Box::new(Imagenes),
        Box::new(MontajesDeContenedor),
        Box::new(CapacidadesDeContenedor),
    ]
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ctx() -> Contexto {
        Contexto::del_sistema(aegis_entidad::entidad::maquina("prueba"), 0, 0)
    }

    #[test]
    fn se_reconocen_las_rutas_de_cgroup_de_los_cinco_runtimes() {
        let casos = [
            (
                "/docker/3f4a2b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a",
                "docker",
            ),
            (
                "/system.slice/docker-3f4a2b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a.scope",
                "docker",
            ),
            (
                "/machine.slice/libpod-3f4a2b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a.scope",
                "podman",
            ),
            (
                "/crio-3f4a2b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a.scope",
                "crio",
            ),
            (
                "/kubepods/besteffort/pod123/3f4a2b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a",
                "containerd",
            ),
        ];
        for (ruta, runtime) in casos {
            let i = identidad_de_cgroup(ruta).unwrap_or_else(|| panic!("no se reconocio {ruta}"));
            assert_eq!(i.runtime, runtime, "runtime mal deducido en {ruta}");
            assert!(i.id.len() >= 12, "identificador corto en {ruta}");
        }
    }

    #[test]
    fn lxc_usa_el_nombre_y_no_un_hexadecimal() {
        let i = identidad_de_cgroup("/lxc/mi-contenedor").expect("lxc");
        assert_eq!(i.runtime, "lxc");
        assert_eq!(i.id, "mi-contenedor");
    }

    #[test]
    fn un_cgroup_normal_del_anfitrion_no_es_un_contenedor() {
        // Si cualquier cgroup contara como contenedor, la tabla se llenaria con
        // el sistema entero y no diria nada.
        assert!(identidad_de_cgroup("/").is_none());
        assert!(identidad_de_cgroup("/user.slice/user-1000.slice").is_none());
        assert!(identidad_de_cgroup("/system.slice/sshd.service").is_none());
        assert!(identidad_de_cgroup("").is_none());
    }

    #[test]
    fn un_identificador_demasiado_corto_no_cuela() {
        // Doce caracteres hexadecimales es el minimo; menos seria confundir
        // cualquier nombre corto con un contenedor.
        assert!(identidad_de_cgroup("/system.slice/docker-abc.scope").is_none());
        assert!(identidad_de_cgroup("/deadbeef").is_none());
    }

    #[test]
    fn se_reconocen_los_montajes_que_permiten_escapar() {
        assert!(es_montaje_de_escape("/"));
        assert!(es_montaje_de_escape("/var/run/docker.sock"));
        assert!(es_montaje_de_escape("/proc"));
        assert!(es_montaje_de_escape("/etc/shadow"), "cuelga de /etc");
        // Un volumen de datos normal no lo es.
        assert!(!es_montaje_de_escape("/srv/datos"));
        assert!(!es_montaje_de_escape("/home/usuario/proyecto"));
    }

    #[test]
    fn las_capacidades_de_escape_incluyen_las_que_de_verdad_sacan() {
        assert!(CAPACIDADES_DE_ESCAPE.contains(&"CAP_SYS_ADMIN"));
        assert!(CAPACIDADES_DE_ESCAPE.contains(&"CAP_SYS_MODULE"));
        // Una capacidad normal de un servicio en contenedor no se marca.
        assert!(!CAPACIDADES_DE_ESCAPE.contains(&"CAP_NET_BIND_SERVICE"));
        assert!(!CAPACIDADES_DE_ESCAPE.contains(&"CAP_CHOWN"));
    }

    #[test]
    fn el_repositories_json_se_lee_sin_analizador_de_json() {
        let texto = r#"{"Repositories":{"nginx":{"nginx:latest":"sha256:abc123def456","nginx@sha256:xyz":"sha256:abc123def456"},"registro.empresa.local/app":{"registro.empresa.local/app:1.2":"sha256:fed987"}}}"#;
        let rs = referencias_de_repositories(texto);
        assert!(
            rs.iter()
                .any(|(r, i)| r == "nginx:latest" && i == "abc123def456"),
            "{rs:?}"
        );
        assert!(
            rs.iter()
                .any(|(r, _)| r == "registro.empresa.local/app:1.2"),
            "el registro de origen tiene que conservarse: {rs:?}"
        );
    }

    #[test]
    fn un_repositories_json_roto_no_rompe_el_analisis() {
        assert!(referencias_de_repositories("").is_empty());
        assert!(referencias_de_repositories("{").is_empty());
        assert!(referencias_de_repositories(r#"{"a":"b"}"#).is_empty());
        // Una cadena sin cerrar no puede colgar el bucle.
        let _ = referencias_de_repositories(r#"{"sin cerrar"#);
    }

    #[test]
    fn las_cuatro_tablas_dan_respuesta_o_motivo_en_esta_maquina() {
        let c = ctx();
        for t in tablas() {
            match t.leer(&c, &Filtro::ninguno()) {
                Ok(f) => {
                    if f.filas.is_empty() {
                        assert!(
                            f.examinadas > 0 || !f.avisos.is_empty(),
                            "{} devolvio vacio sin explicar nada",
                            t.nombre()
                        );
                    }
                }
                Err(m) => assert!(!m.frase().is_empty(), "{} sin frase", t.nombre()),
            }
        }
    }

    #[test]
    fn sobre_una_raiz_de_prueba_las_tablas_del_nucleo_se_niegan() {
        let c = ctx().con_raiz("/tmp/aegis-raiz-contenedores");
        let _ = std::fs::create_dir_all("/tmp/aegis-raiz-contenedores");
        for t in [
            Box::new(Contenedores) as Box<dyn Tabla>,
            Box::new(MontajesDeContenedor),
            Box::new(CapacidadesDeContenedor),
        ] {
            match t.leer(&c, &Filtro::ninguno()) {
                Err(MotivoNoLeible::NoAplicaEnEstaPlataforma { .. }) => {}
                otro => panic!("{} no rechazo la raiz de prueba: {otro:?}", t.nombre()),
            }
        }
        let _ = std::fs::remove_dir_all("/tmp/aegis-raiz-contenedores");
    }
}
