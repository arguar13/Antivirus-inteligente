//! Proveedores de las tablas de ficheros.
//!
//! # El recorrido, que es lo unico delicado de este modulo
//!
//! Tres de estas tablas necesitan recorrer el arbol de ficheros, y un recorrido
//! sobre el disco de un cliente tiene cuatro formas conocidas de acabar mal:
//!
//!   1. **No termina.** Un enlace simbolico a un ancestro crea un ciclo
//!      infinito. Se evita NO SIGUIENDO enlaces nunca: el recorrido usa
//!      `symlink_metadata`, mira los enlaces y no entra en ellos.
//!   2. **Sale del sitio.** Un enlace dentro de `/tmp` que apunta a `/` haria
//!      que una consulta acotada a `/tmp` recorriera la maquina entera. Misma
//!      defensa: no se siguen.
//!   3. **Cruza a otro sistema de ficheros.** Recorrer `/` sin mas entra en
//!      `/proc`, en `/sys`, en el NFS de la empresa y en el disco USB que
//!      alguien acaba de enchufar. Se evita con [`DIRECTORIOS_QUE_NO_SE_RECORREN`].
//!   4. **No acaba nunca a tiempo.** Aunque termine, puede tardar horas. Se
//!      evita con el presupuesto del contexto y con el tope de filas, y
//!      DECLARANDO el truncamiento cuando ocurre.
//!
//! Las cuatro defensas estan en [`recorrer`], que es la unica funcion del crate
//! que anda por el disco. Que sea una sola es deliberado: son cuatro fallos que
//! hay que evitar bien una vez, no tres veces regular.

use std::path::{Path, PathBuf};

use aegis_entidad::{entidad, Clase};
use aegis_parser::esquema::{ficheros as esq, Coste, Tabla as Esquema};
use aegis_scal::linux::xattr;
use sha2::{Digest, Sha256};

use crate::contexto::{desde_io, Contexto, TOPE_DE_FILAS};
use crate::procesos::nombre_de_capacidad;
use crate::tabla::{Constructor, Filas, Filtro, MotivoNoLeible, Tabla};

/// Sistemas de ficheros virtuales y de red en los que un recorrido no entra.
///
/// `/proc` y `/sys` no son ficheros: son ventanas al nucleo, y recorrerlos
/// produce millones de entradas sin sentido —y algunas lecturas que bloquean—.
/// `/run` y `/dev` son parecidos. Las rutas de red no estan aqui porque no
/// tienen nombre fijo; para esas vale el corte por dispositivo, que hace
/// [`recorrer`] al no cruzar de sistema de ficheros.
pub const DIRECTORIOS_QUE_NO_SE_RECORREN: &[&str] =
    &["/proc", "/sys", "/dev", "/run", "/tmp/.X11-unix"];

/// Profundidad maxima de un recorrido.
///
/// Un arbol mas hondo que esto casi siempre es una anomalia o un ataque de
/// agotamiento; en cualquier caso, el recorrido lo declara truncado en vez de
/// seguir bajando.
pub const PROFUNDIDAD_MAXIMA: usize = 24;

/// Tamano maximo que se hashea.
///
/// Por encima, la columna `sha256` queda AUSENTE con su aviso. Un hash parcial
/// no es una alternativa: seria un valor con forma de hash que no coincide con
/// el de nadie, y que haria concluir que un fichero conocido es desconocido.
pub const TAMANO_MAXIMO_HASH: u64 = 512 * 1024 * 1024;

/// Indica si una ruta cae dentro de un arbol que no se recorre.
///
/// Compara por PREFIJO y no por igualdad, y la diferencia no es cosmetica: una
/// consulta acotada a `/proc/self/` empieza DENTRO de `/proc`, asi que con una
/// comparacion por igualdad se colaba entera. `/proc` no es un arbol de
/// ficheros —es una ventana al nucleo, con enlaces que apuntan a cualquier
/// sitio, directorios por hilo y ficheros cuya lectura puede bloquear—, y
/// recorrerlo cuelga la consulta.
///
/// Lo encontro la prueba del catalogo, que lee las cuarenta y siete tablas
/// seguidas: la tabla sola, con una raiz normal, nunca lo habria enseñado.
pub fn esta_prohibido(ruta: &Path) -> bool {
    DIRECTORIOS_QUE_NO_SE_RECORREN.iter().any(|p| {
        let prohibido = Path::new(p);
        ruta == prohibido || ruta.starts_with(prohibido)
    })
}

/// Lo que el recorrido encontro en una ruta.
#[derive(Debug, Clone)]
pub struct Entrada {
    /// Ruta absoluta.
    pub ruta: PathBuf,
    /// Metadatos SIN seguir enlaces.
    pub md: std::fs::Metadata,
}

/// Recorre el arbol bajo `raices`, con las cuatro defensas de la cabecera.
///
/// El `cb` decide que hacer con cada entrada; devolver `false` detiene el
/// recorrido, que es como las tablas aplican su tope de filas.
///
/// Devuelve si el recorrido termino entero, y SUS PROPIOS avisos —directorios
/// que no se pudieron abrir, ramas demasiado hondas—. Los devuelve en vez de
/// escribir en una lista prestada porque el `cb` tambien tiene avisos que dar, y
/// las dos cosas no pueden tomar el mismo prestamo mutable a la vez. Separarlos
/// ademas deja claro de quien es cada hueco: del recorrido o de la tabla.
fn recorrer(
    ctx: &Contexto,
    raices: &[PathBuf],
    cb: &mut impl FnMut(Entrada) -> bool,
) -> (bool, Vec<(String, MotivoNoLeible)>) {
    let mut avisos: Vec<(String, MotivoNoLeible)> = Vec::new();
    let mut pendientes: Vec<(PathBuf, usize)> = raices.iter().map(|r| (r.clone(), 0)).collect();
    // Dispositivo de cada raiz: no se cruza a otro sistema de ficheros.
    let dispositivos: Vec<u64> = raices
        .iter()
        .filter_map(|r| {
            use std::os::unix::fs::MetadataExt;
            std::fs::symlink_metadata(r).ok().map(|m| m.dev())
        })
        .collect();

    while let Some((dir, profundidad)) = pendientes.pop() {
        if ctx.agotado() {
            return (false, avisos);
        }
        if profundidad > PROFUNDIDAD_MAXIMA {
            avisos.push((
                dir.display().to_string(),
                MotivoNoLeible::ErrorDelSistema {
                    operacion: "recorrer el arbol",
                    detalle: format!("mas hondo que {PROFUNDIDAD_MAXIMA} niveles"),
                },
            ));
            continue;
        }
        if esta_prohibido(&dir) {
            continue;
        }

        let entradas = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                avisos.push((
                    dir.display().to_string(),
                    desde_io(e, &dir, "enumerar el directorio"),
                ));
                continue;
            }
        };
        // Ordenado: el determinismo de la respuesta depende de esto.
        let mut hijos: Vec<PathBuf> = entradas.flatten().map(|e| e.path()).collect();
        hijos.sort();

        for hijo in hijos {
            // `symlink_metadata` NO sigue enlaces: es la defensa 1 y la 2.
            let Ok(md) = std::fs::symlink_metadata(&hijo) else {
                continue;
            };
            if md.is_dir() {
                use std::os::unix::fs::MetadataExt;
                // Defensa 3: no se cruza de sistema de ficheros.
                if !dispositivos.is_empty() && !dispositivos.contains(&md.dev()) {
                    continue;
                }
                pendientes.push((hijo.clone(), profundidad + 1));
            }
            if !cb(Entrada { ruta: hijo, md }) {
                return (false, avisos);
            }
        }
    }
    (true, avisos)
}

/// Las raices que hay que recorrer segun lo que diga el filtro.
///
/// Es el empuje de predicados de esta familia: un `path = '/bin/sh'` no recorre
/// nada, y un `path LIKE '/tmp/%'` recorre solo `/tmp`.
///
/// Devuelve el motivo cuando el filtro no acota —la tabla peligrosa se niega a
/// leerse— y tambien cuando lo que acota cae dentro de un arbol que no se
/// recorre. Las dos comprobaciones viven AQUI, en el unico sitio por el que
/// pasan las cuatro tablas peligrosas de la familia, para que ninguna pueda
/// olvidarse de una de ellas.
fn raices_segun_filtro(
    ctx: &Contexto,
    filtro: &Filtro,
    acotan: &'static [&'static str],
) -> Result<Vec<PathBuf>, MotivoNoLeible> {
    let raices =
        raices_crudas(ctx, filtro).ok_or(MotivoNoLeible::RequiereFiltro { columnas: acotan })?;
    if raices.iter().all(|r| esta_prohibido(r)) {
        return Err(MotivoNoLeible::NoAplicaEnEstaPlataforma {
            interfaz: "/proc, /sys, /dev y /run no son arboles de ficheros que recorrer",
        });
    }
    Ok(raices)
}

/// Las raices que pide el filtro, sin comprobar nada mas.
fn raices_crudas(ctx: &Contexto, filtro: &Filtro) -> Option<Vec<PathBuf>> {
    if let Some(exacta) = filtro.texto("path") {
        return Some(vec![ctx.ruta(exacta)]);
    }
    if let Some(prefijo) = filtro.prefijo("path") {
        // El prefijo de un LIKE puede cortar a mitad de un nombre
        // (`/usr/bi%`), asi que se recorre desde su DIRECTORIO padre y el
        // ejecutor filtra el resto. Recortar mas seria perder filas.
        let ruta = ctx.ruta(prefijo);
        let desde = if prefijo.ends_with('/') {
            ruta
        } else {
            ruta.parent().map(Path::to_path_buf).unwrap_or(ruta)
        };
        return Some(vec![desde]);
    }
    None
}

/// Tipo de una entrada del sistema de ficheros, por su nombre estable.
fn clase_de(md: &std::fs::Metadata) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    let t = md.file_type();
    if t.is_file() {
        "file"
    } else if t.is_dir() {
        "dir"
    } else if t.is_symlink() {
        "symlink"
    } else if t.is_socket() {
        "socket"
    } else if t.is_fifo() {
        "fifo"
    } else if t.is_char_device() {
        "char"
    } else if t.is_block_device() {
        "block"
    } else {
        "other"
    }
}

/// SHA-256 del contenido de un fichero, por bloques.
///
/// Por bloques y no de una vez: leer entero un fichero de cuatro gigas para
/// hashearlo son cuatro gigas de residencia en un agente cuya linea base son
/// treinta y dos megas.
pub fn sha256_de(ruta: &Path) -> Result<String, MotivoNoLeible> {
    use std::io::Read;
    let mut f = std::fs::File::open(ruta).map_err(|e| desde_io(e, ruta, "abrir para hashear"))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let leidos = f
            .read(&mut buffer)
            .map_err(|e| desde_io(e, ruta, "leer para hashear"))?;
        if leidos == 0 {
            break;
        }
        hasher.update(&buffer[..leidos]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Hexadecimal de unos bytes.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// files
// ---------------------------------------------------------------------------

/// Los ficheros del disco.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ficheros;

impl Tabla for Ficheros {
    fn esquema(&self) -> &'static Esquema {
        &esq::FILES
    }

    fn coste(&self) -> Coste {
        Coste::Peligroso
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Ubicacion)
    }

    fn columnas_que_acotan(&self) -> &'static [&'static str] {
        &["path"]
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        self.exige_cota(filtro)?;
        let raices = raices_segun_filtro(ctx, filtro, self.columnas_que_acotan())?;
        // El hash solo si la consulta lo pide. Hashear cada fichero de un
        // recorrido «por si acaso» convierte una consulta de metadatos en horas
        // de E/S sobre el disco del cliente.
        let quiere_hash = filtro.necesita("sha256");
        let mut salida = Filas::default();
        let mut avisos = Vec::new();
        let mut c = Constructor::nuevo(self.esquema());

        // Un `path` exacto no recorre nada: se mira ese fichero y ya.
        if let Some(exacta) = filtro.texto("path") {
            let ruta = ctx.ruta(exacta);
            let md = std::fs::symlink_metadata(&ruta)
                .map_err(|e| desde_io(e, &ruta, "leer los metadatos"))?;
            salida.examinadas = 1;
            salida.filas.push(fila_de_fichero(
                ctx,
                &mut c,
                &ruta,
                &md,
                quiere_hash,
                &mut avisos,
            ));
            for (sujeto, motivo) in avisos {
                salida.avisar(sujeto, motivo);
            }
            return Ok(salida);
        }

        let (completo, del_recorrido) = recorrer(ctx, &raices, &mut |e| {
            salida.examinadas += 1;
            if salida.filas.len() >= TOPE_DE_FILAS {
                return false;
            }
            let fila = fila_de_fichero(ctx, &mut c, &e.ruta, &e.md, quiere_hash, &mut avisos);
            salida.filas.push(fila);
            true
        });
        salida.truncada = !completo || salida.filas.len() >= TOPE_DE_FILAS;
        avisos.extend(del_recorrido);
        for (sujeto, motivo) in avisos {
            salida.avisar(sujeto, motivo);
        }
        Ok(salida)
    }
}

/// Construye la fila de un fichero.
fn fila_de_fichero(
    ctx: &Contexto,
    c: &mut Constructor,
    ruta: &Path,
    md: &std::fs::Metadata,
    quiere_hash: bool,
    avisos: &mut Vec<(String, MotivoNoLeible)>,
) -> crate::tabla::Fila {
    use std::os::unix::fs::MetadataExt;
    let texto = ruta.display().to_string();

    c.texto("path", texto.clone());
    c.texto_opcional("directory", ruta.parent().map(|p| p.display().to_string()));
    c.texto_opcional(
        "filename",
        ruta.file_name().map(|n| n.to_string_lossy().to_string()),
    );
    c.entero("size", i64::try_from(md.size()).unwrap_or(i64::MAX));
    c.entero("mode", i64::from(md.mode() & 0o7777));
    c.entero("uid", i64::from(md.uid()));
    c.entero("gid", i64::from(md.gid()));
    c.entero("inode", i64::try_from(md.ino()).unwrap_or(i64::MAX));
    c.entero("hard_links", i64::try_from(md.nlink()).unwrap_or(i64::MAX));
    c.entero("mtime", md.mtime());
    c.entero("ctime", md.ctime());
    c.entero("atime", md.atime());
    c.texto("kind", clase_de(md));
    c.booleano("setuid", md.mode() & 0o4000 != 0);
    c.booleano("setgid", md.mode() & 0o2000 != 0);

    if md.file_type().is_symlink() {
        c.texto_opcional(
            "symlink_target",
            std::fs::read_link(ruta)
                .ok()
                .map(|d| d.display().to_string()),
        );
    }

    // El hash solo de ficheros normales y por debajo del tope. Un hash de un
    // directorio o de un socket no significa nada, y uno parcial es peor que
    // ninguno.
    if quiere_hash && md.is_file() {
        if md.size() > TAMANO_MAXIMO_HASH {
            avisos.push((
                texto.clone(),
                MotivoNoLeible::ErrorDelSistema {
                    operacion: "hashear el fichero",
                    detalle: format!(
                        "son {} bytes, mas del tope de {TAMANO_MAXIMO_HASH}",
                        md.size()
                    ),
                },
            ));
        } else {
            match sha256_de(ruta) {
                Ok(h) => {
                    c.texto("sha256", h.clone());
                    // La entidad de un fichero es su UBICACION; su contenido es
                    // otra entidad distinta, y tenerlas separadas es lo que
                    // permite decir "este binario conocido aparecio en esta ruta
                    // nueva".
                    c.entidad(entidad::ubicacion(ctx.maquina(), &texto));
                    let _ = entidad::contenido(&h);
                }
                Err(m) => avisos.push((texto.clone(), m)),
            }
        }
    }
    if c.entidad_puesta() {
        // ya la lleva
    } else {
        c.entidad(entidad::ubicacion(ctx.maquina(), &texto));
    }
    c.fin()
}

// ---------------------------------------------------------------------------
// file_xattrs
// ---------------------------------------------------------------------------

/// Los atributos extendidos de un fichero.
#[derive(Debug, Clone, Copy, Default)]
pub struct Xattrs;

impl Tabla for Xattrs {
    fn esquema(&self) -> &'static Esquema {
        &esq::FILE_XATTRS
    }

    fn coste(&self) -> Coste {
        Coste::Peligroso
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Ubicacion)
    }

    fn columnas_que_acotan(&self) -> &'static [&'static str] {
        &["path"]
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        self.exige_cota(filtro)?;
        let raices = raices_segun_filtro(ctx, filtro, self.columnas_que_acotan())?;
        let nombre_buscado = filtro.texto("name");
        let mut salida = Filas::default();
        let mut avisos = Vec::new();
        let mut c = Constructor::nuevo(self.esquema());

        let anadir = |ruta: &Path,
                      salida: &mut Filas,
                      c: &mut Constructor,
                      avisos: &mut Vec<(String, MotivoNoLeible)>| {
            let nombres = match xattr::nombres(ruta) {
                Ok(n) => n,
                Err(e) => {
                    avisos.push((ruta.display().to_string(), desde_xattr(e)));
                    return;
                }
            };
            for nombre in nombres {
                if let Some(b) = nombre_buscado {
                    if nombre != b {
                        continue;
                    }
                }
                let valor = xattr::valor(ruta, &nombre).unwrap_or_default();
                c.texto("path", ruta.display().to_string());
                c.texto("name", nombre.clone());
                c.texto("value_hex", hex(&valor));
                c.entero("size", i64::try_from(valor.len()).unwrap_or(i64::MAX));
                c.booleano("sensitive", xattr::es_sensible(&nombre));
                c.entidad(entidad::ubicacion(
                    ctx.maquina(),
                    &ruta.display().to_string(),
                ));
                salida.filas.push(c.fin());
            }
        };

        if let Some(exacta) = filtro.texto("path") {
            let ruta = ctx.ruta(exacta);
            salida.examinadas = 1;
            anadir(&ruta, &mut salida, &mut c, &mut avisos);
        } else {
            let (completo, del_recorrido) = recorrer(ctx, &raices, &mut |e| {
                salida.examinadas += 1;
                if salida.filas.len() >= TOPE_DE_FILAS {
                    return false;
                }
                anadir(&e.ruta, &mut salida, &mut c, &mut avisos);
                true
            });
            salida.truncada = !completo || salida.filas.len() >= TOPE_DE_FILAS;
            avisos.extend(del_recorrido);
        }
        for (sujeto, motivo) in avisos {
            salida.avisar(sujeto, motivo);
        }
        Ok(salida)
    }
}

/// Traduce un error de atributos extendidos a un motivo del analista.
fn desde_xattr(e: xattr::XattrError) -> MotivoNoLeible {
    match e {
        xattr::XattrError::NoSoportado => MotivoNoLeible::NoExisteEnEsteNucleo {
            interfaz: "atributos extendidos en este sistema de ficheros",
        },
        xattr::XattrError::SinPermiso => MotivoNoLeible::SinPrivilegios {
            operacion: "leer los atributos extendidos",
            necesita: "CAP_DAC_READ_SEARCH o ser el dueno",
        },
        xattr::XattrError::NoExiste => MotivoNoLeible::FuenteAusente {
            ruta: "el fichero desaparecio durante la lectura".to_string(),
        },
        xattr::XattrError::RutaInvalida => MotivoNoLeible::ErrorDelSistema {
            operacion: "pasar la ruta al sistema",
            detalle: "la ruta lleva un byte nulo".to_string(),
        },
        xattr::XattrError::Sistema(n) => MotivoNoLeible::ErrorDelSistema {
            operacion: "leer los atributos extendidos",
            detalle: format!("errno {n}"),
        },
    }
}

// ---------------------------------------------------------------------------
// file_acls
// ---------------------------------------------------------------------------

/// Las ACL POSIX de un fichero.
#[derive(Debug, Clone, Copy, Default)]
pub struct Acls;

impl Tabla for Acls {
    fn esquema(&self) -> &'static Esquema {
        &esq::FILE_ACLS
    }

    fn coste(&self) -> Coste {
        Coste::Peligroso
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Ubicacion)
    }

    fn columnas_que_acotan(&self) -> &'static [&'static str] {
        &["path"]
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        self.exige_cota(filtro)?;
        let raices = raices_segun_filtro(ctx, filtro, self.columnas_que_acotan())?;
        let mut salida = Filas::default();
        let mut avisos = Vec::new();
        let mut c = Constructor::nuevo(self.esquema());

        let anadir = |ruta: &Path, salida: &mut Filas, c: &mut Constructor| {
            for (atributo, clase) in [
                (xattr::ACL_ACCESO, "access"),
                (xattr::ACL_DEFECTO, "default"),
            ] {
                let Ok(bytes) = xattr::valor(ruta, atributo) else {
                    continue;
                };
                // Una ACL malformada no se interpreta a medias: o entera o nada.
                let Some(entradas) = xattr::decodificar_acl(&bytes) else {
                    continue;
                };
                for e in entradas {
                    c.texto("path", ruta.display().to_string());
                    c.texto("kind", clase);
                    c.texto("who", e.quien());
                    c.texto("perms", e.rwx());
                    c.entidad(entidad::ubicacion(
                        ctx.maquina(),
                        &ruta.display().to_string(),
                    ));
                    salida.filas.push(c.fin());
                }
            }
        };

        if let Some(exacta) = filtro.texto("path") {
            let ruta = ctx.ruta(exacta);
            salida.examinadas = 1;
            anadir(&ruta, &mut salida, &mut c);
        } else {
            let (completo, del_recorrido) = recorrer(ctx, &raices, &mut |e| {
                salida.examinadas += 1;
                if salida.filas.len() >= TOPE_DE_FILAS {
                    return false;
                }
                anadir(&e.ruta, &mut salida, &mut c);
                true
            });
            salida.truncada = !completo || salida.filas.len() >= TOPE_DE_FILAS;
            avisos.extend(del_recorrido);
        }
        for (sujeto, motivo) in avisos {
            salida.avisar(sujeto, motivo);
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// suid_binaries
// ---------------------------------------------------------------------------

/// Los binarios con setuid o setgid.
#[derive(Debug, Clone, Copy, Default)]
pub struct Suid;

impl Tabla for Suid {
    fn esquema(&self) -> &'static Esquema {
        &esq::SUID_BINARIES
    }

    fn coste(&self) -> Coste {
        Coste::Peligroso
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Ubicacion)
    }

    fn columnas_que_acotan(&self) -> &'static [&'static str] {
        &["path"]
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        self.exige_cota(filtro)?;
        let raices = raices_segun_filtro(ctx, filtro, self.columnas_que_acotan())?;
        let mut salida = Filas::default();
        let mut avisos = Vec::new();
        let mut c = Constructor::nuevo(self.esquema());

        let (completo, del_recorrido) = recorrer(ctx, &raices, &mut |e| {
            use std::os::unix::fs::MetadataExt;
            salida.examinadas += 1;
            if salida.filas.len() >= TOPE_DE_FILAS {
                return false;
            }
            let modo = e.md.mode();
            let setuid = modo & 0o4000 != 0;
            let setgid = modo & 0o2000 != 0;
            // Solo ficheros normales: el bit setgid en un DIRECTORIO significa
            // otra cosa (herencia de grupo) y no es una via de escalada.
            if !e.md.is_file() || (!setuid && !setgid) {
                return true;
            }
            c.texto("path", e.ruta.display().to_string());
            c.entero("mode", i64::from(modo & 0o7777));
            c.entero("uid", i64::from(e.md.uid()));
            c.entero("gid", i64::from(e.md.gid()));
            c.booleano("setuid", setuid);
            c.booleano("setgid", setgid);
            c.entero("size", i64::try_from(e.md.size()).unwrap_or(i64::MAX));
            if e.md.size() <= TAMANO_MAXIMO_HASH {
                match sha256_de(&e.ruta) {
                    Ok(h) => {
                        c.texto("sha256", h);
                    }
                    Err(m) => avisos.push((e.ruta.display().to_string(), m)),
                }
            }
            c.entidad(entidad::ubicacion(
                ctx.maquina(),
                &e.ruta.display().to_string(),
            ));
            salida.filas.push(c.fin());
            true
        });
        salida.truncada = !completo || salida.filas.len() >= TOPE_DE_FILAS;
        avisos.extend(del_recorrido);
        for (sujeto, motivo) in avisos {
            salida.avisar(sujeto, motivo);
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// file_capabilities
// ---------------------------------------------------------------------------

/// Las capacidades concedidas a ejecutables por su atributo extendido.
#[derive(Debug, Clone, Copy, Default)]
pub struct CapacidadesDeFichero;

impl Tabla for CapacidadesDeFichero {
    fn esquema(&self) -> &'static Esquema {
        &esq::FILE_CAPABILITIES
    }

    fn coste(&self) -> Coste {
        Coste::Peligroso
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Ubicacion)
    }

    fn columnas_que_acotan(&self) -> &'static [&'static str] {
        &["path"]
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        self.exige_cota(filtro)?;
        let raices = raices_segun_filtro(ctx, filtro, self.columnas_que_acotan())?;
        let mut salida = Filas::default();
        let mut avisos = Vec::new();
        let mut c = Constructor::nuevo(self.esquema());

        let anadir = |ruta: &Path, salida: &mut Filas, c: &mut Constructor| {
            let Ok(bytes) = xattr::valor(ruta, xattr::CAPACIDADES) else {
                return;
            };
            let Some(caps) = xattr::decodificar_capacidades(&bytes) else {
                return;
            };
            for (mascara, conjunto) in [
                (caps.permitidas, "permitted"),
                (caps.heredables, "inheritable"),
            ] {
                for bit in 0..64u32 {
                    if mascara & (1u64 << bit) == 0 {
                        continue;
                    }
                    c.texto("path", ruta.display().to_string());
                    c.texto("capability", nombre_de_capacidad(bit));
                    c.texto("set", conjunto);
                    c.booleano("effective", caps.efectivas);
                    c.entidad(entidad::ubicacion(
                        ctx.maquina(),
                        &ruta.display().to_string(),
                    ));
                    salida.filas.push(c.fin());
                }
            }
        };

        if let Some(exacta) = filtro.texto("path") {
            let ruta = ctx.ruta(exacta);
            salida.examinadas = 1;
            anadir(&ruta, &mut salida, &mut c);
        } else {
            let (completo, del_recorrido) = recorrer(ctx, &raices, &mut |e| {
                salida.examinadas += 1;
                if salida.filas.len() >= TOPE_DE_FILAS {
                    return false;
                }
                if e.md.is_file() {
                    anadir(&e.ruta, &mut salida, &mut c);
                }
                true
            });
            salida.truncada = !completo || salida.filas.len() >= TOPE_DE_FILAS;
            avisos.extend(del_recorrido);
        }
        for (sujeto, motivo) in avisos {
            salida.avisar(sujeto, motivo);
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// mounts y superblocks
// ---------------------------------------------------------------------------

/// Una linea de `/proc/self/mountinfo`, ya descompuesta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Montaje {
    /// Identificador del montaje.
    pub id: i64,
    /// Numero mayor de dispositivo.
    pub major: i64,
    /// Numero menor de dispositivo.
    pub minor: i64,
    /// Que parte del origen se monto.
    pub raiz: String,
    /// Donde esta montado.
    pub punto: String,
    /// Opciones del montaje.
    pub opciones: String,
    /// Propagacion: shared, master, slave o private.
    pub propagacion: String,
    /// Tipo de sistema de ficheros.
    pub tipo: String,
    /// Origen.
    pub origen: String,
    /// Opciones del superbloque.
    pub opciones_super: String,
}

/// Analiza `/proc/self/mountinfo`.
///
/// El formato tiene una trampa que hace fallar a casi todo el que lo analiza por
/// primera vez: entre los campos fijos y los tres ultimos hay un numero VARIABLE
/// de campos opcionales, terminados por un `-` solitario. Partir por columnas
/// fijas da el tipo de sistema de ficheros equivocado en cuanto un montaje tiene
/// propagacion.
///
/// Los espacios, tabuladores y barras invertidas de las rutas vienen escapados en
/// octal (`\040` es un espacio), y se deshacen aqui: una ruta con un espacio sin
/// desescapar no casa con la que devuelve cualquier otra tabla.
pub fn analizar_mountinfo(texto: &str) -> Vec<Montaje> {
    let mut salida = Vec::new();
    for linea in texto.lines() {
        let campos: Vec<&str> = linea.split_whitespace().collect();
        // Minimo: id, padre, major:minor, raiz, punto, opciones, `-`, tipo, origen, opciones_super.
        if campos.len() < 10 {
            continue;
        }
        let Some(separador) = campos.iter().position(|c| *c == "-") else {
            continue;
        };
        if separador + 3 >= campos.len() || separador < 6 {
            continue;
        }
        let Some((major, minor)) = campos[2].split_once(':') else {
            continue;
        };
        salida.push(Montaje {
            id: campos[0].parse().unwrap_or(-1),
            major: major.parse().unwrap_or(-1),
            minor: minor.parse().unwrap_or(-1),
            raiz: desescapar(campos[3]),
            punto: desescapar(campos[4]),
            opciones: campos[5].to_string(),
            // Los campos opcionales son las etiquetas de propagacion.
            propagacion: campos[6..separador].join(" "),
            tipo: campos[separador + 1].to_string(),
            origen: desescapar(campos[separador + 2]),
            opciones_super: campos[separador + 3].to_string(),
        });
    }
    salida
}

/// Deshace los escapes octales de una ruta de `mountinfo`.
fn desescapar(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut salida = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let octal = &s[i + 1..i + 4];
            if let Ok(n) = u8::from_str_radix(octal, 8) {
                salida.push(n as char);
                i += 4;
                continue;
            }
        }
        salida.push(bytes[i] as char);
        i += 1;
    }
    salida
}

/// Indica si una lista de opciones separadas por comas contiene una.
fn tiene_opcion(opciones: &str, cual: &str) -> bool {
    opciones.split(',').any(|o| o == cual)
}

/// Los montajes del sistema de ficheros.
#[derive(Debug, Clone, Copy, Default)]
pub struct Montajes;

impl Tabla for Montajes {
    fn esquema(&self) -> &'static Esquema {
        &esq::MOUNTS
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let texto = ctx.leer_texto("proc/self/mountinfo")?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for m in analizar_mountinfo(&texto) {
            salida.examinadas += 1;
            c.texto("mountpoint", m.punto);
            c.texto("device", m.origen);
            c.texto("fstype", m.tipo);
            c.texto("options", m.opciones.clone());
            c.texto("propagation", m.propagacion);
            c.texto("root", m.raiz);
            c.entero("major", m.major);
            c.entero("minor", m.minor);
            c.entero("mount_id", m.id);
            c.booleano("writable", !tiene_opcion(&m.opciones, "ro"));
            c.booleano("executable", !tiene_opcion(&m.opciones, "noexec"));
            c.booleano("setuid_allowed", !tiene_opcion(&m.opciones, "nosuid"));
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

/// Los superbloques, agrupando los montajes que comparten dispositivo.
#[derive(Debug, Clone, Copy, Default)]
pub struct Superbloques;

impl Tabla for Superbloques {
    fn esquema(&self) -> &'static Esquema {
        &esq::SUPERBLOCKS
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let texto = ctx.leer_texto("proc/self/mountinfo")?;
        let montajes = analizar_mountinfo(&texto);

        // Agrupados por dispositivo: un superbloque montado en cinco sitios es
        // UNO, y esa es toda la diferencia con la tabla de montajes.
        let mut por_dispositivo: std::collections::BTreeMap<(i64, i64), (Montaje, u32)> =
            std::collections::BTreeMap::new();
        for m in montajes {
            let clave = (m.major, m.minor);
            por_dispositivo
                .entry(clave)
                .and_modify(|(_, n)| *n += 1)
                .or_insert((m, 1));
        }

        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());
        for ((major, minor), (m, cuantos)) in por_dispositivo {
            salida.examinadas += 1;
            c.texto("device", m.origen);
            c.texto("fstype", m.tipo);
            c.texto("options", m.opciones_super);
            c.entero("major", major);
            c.entero("minor", minor);
            c.entero("mountpoints", i64::from(cuantos));
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

/// Las siete tablas de esta familia, para el catalogo.
pub fn tablas() -> Vec<Box<dyn Tabla>> {
    vec![
        Box::new(Ficheros),
        Box::new(Xattrs),
        Box::new(Acls),
        Box::new(Suid),
        Box::new(CapacidadesDeFichero),
        Box::new(Montajes),
        Box::new(Superbloques),
    ]
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_parser::ast::Literal;
    use std::io::Write;

    fn ctx() -> Contexto {
        Contexto::del_sistema(entidad::maquina("prueba"), 0, 0)
    }

    fn columna(t: &dyn Tabla, nombre: &str) -> usize {
        t.esquema()
            .columnas
            .iter()
            .position(|c| c.nombre == nombre)
            .unwrap_or_else(|| panic!("falta la columna {nombre} en {}", t.nombre()))
    }

    #[test]
    fn las_tablas_peligrosas_se_niegan_sin_filtro() {
        let c = ctx();
        for t in tablas() {
            if t.coste() != Coste::Peligroso {
                continue;
            }
            match t.leer(&c, &Filtro::ninguno()) {
                Err(MotivoNoLeible::RequiereFiltro { columnas }) => {
                    assert!(columnas.contains(&"path"), "{}", t.nombre());
                }
                otro => panic!("{} no exigio filtro: {otro:?}", t.nombre()),
            }
        }
    }

    #[test]
    fn un_fichero_concreto_se_lee_sin_recorrer_nada() {
        let c = ctx();
        let f = Filtro::ninguno().con_igualdad("path", Literal::Texto("/etc/hostname".into()));
        let r = Ficheros.leer(&c, &f);
        // Puede no existir en un contenedor minimo: las dos salidas son validas
        // y ninguna es "cero filas en silencio".
        match r {
            Ok(filas) => {
                assert_eq!(filas.examinadas, 1, "se recorrio de mas");
                assert_eq!(filas.filas.len(), 1);
            }
            Err(MotivoNoLeible::FuenteAusente { .. }) => {}
            Err(otro) => panic!("motivo inesperado: {otro:?}"),
        }
    }

    #[test]
    fn el_hash_de_un_fichero_conocido_es_el_correcto() {
        // SHA-256 de la cadena vacia, que es un vector de prueba universal.
        let ruta = "/tmp/aegis-estado-vacio";
        std::fs::File::create(ruta).unwrap();
        assert_eq!(
            sha256_de(Path::new(ruta)).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let _ = std::fs::remove_file(ruta);
    }

    #[test]
    fn el_hash_por_bloques_coincide_con_el_de_una_vez() {
        // Mas grande que el buffer de 64 KiB, para ejercer el bucle.
        let ruta = "/tmp/aegis-estado-grande";
        let datos = vec![0xABu8; 200 * 1024];
        std::fs::write(ruta, &datos).unwrap();
        let esperado: String = Sha256::digest(&datos)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(sha256_de(Path::new(ruta)).unwrap(), esperado);
        let _ = std::fs::remove_file(ruta);
    }

    #[test]
    fn el_recorrido_no_sigue_enlaces_simbolicos() {
        // LA defensa que impide que una consulta acotada a /tmp recorra la
        // maquina entera porque alguien dejo un enlace a "/".
        let base = "/tmp/aegis-estado-enlaces";
        let _ = std::fs::remove_dir_all(base);
        std::fs::create_dir_all(format!("{base}/dentro")).unwrap();
        std::fs::write(format!("{base}/dentro/fichero"), b"x").unwrap();
        std::os::unix::fs::symlink("/", format!("{base}/salida")).unwrap();

        let c = ctx();
        let f = Filtro::ninguno().con_prefijo("path", format!("{base}/"));
        let r = Ficheros.leer(&c, &f).expect("recorrer /tmp/...");
        let i_path = columna(&Ficheros, "path");
        let rutas: Vec<String> = r.filas.iter().map(|f| f.valor(i_path).a_texto()).collect();

        assert!(rutas.iter().any(|p| p.ends_with("/dentro/fichero")));
        assert!(
            rutas.iter().any(|p| p.ends_with("/salida")),
            "el enlace se lista"
        );
        // Pero NO se entra en el: nada de /etc aparece.
        assert!(
            !rutas.iter().any(|p| p.starts_with("/etc/")),
            "el recorrido siguio el enlace y se escapo: {rutas:?}"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn el_recorrido_no_entra_en_proc_ni_en_sys() {
        // Recorrer / entero pasaria por /proc y produciria millones de entradas
        // sin sentido, ademas de lecturas que bloquean.
        assert!(DIRECTORIOS_QUE_NO_SE_RECORREN.contains(&"/proc"));
        assert!(DIRECTORIOS_QUE_NO_SE_RECORREN.contains(&"/sys"));
    }

    #[test]
    fn un_binario_setuid_aparece_en_su_tabla() {
        let base = "/tmp/aegis-estado-suid";
        let _ = std::fs::remove_dir_all(base);
        std::fs::create_dir_all(base).unwrap();
        let ruta = format!("{base}/elevado");
        std::fs::write(&ruta, b"#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ruta, std::fs::Permissions::from_mode(0o4755)).unwrap();

        let c = ctx();
        let f = Filtro::ninguno().con_prefijo("path", format!("{base}/"));
        let r = Suid.leer(&c, &f).expect("leer suid");
        let i_path = columna(&Suid, "path");
        let i_setuid = columna(&Suid, "setuid");
        assert_eq!(r.filas.len(), 1, "solo hay un binario setuid ahi");
        assert!(r.filas[0].valor(i_path).a_texto().ends_with("/elevado"));
        assert_eq!(
            r.filas[0].valor(i_setuid),
            &aegis_parser::valor::Valor::Booleano(true)
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn un_fichero_sin_setuid_no_aparece() {
        let base = "/tmp/aegis-estado-sinsuid";
        let _ = std::fs::remove_dir_all(base);
        std::fs::create_dir_all(base).unwrap();
        std::fs::write(format!("{base}/normal"), b"x").unwrap();

        let c = ctx();
        let f = Filtro::ninguno().con_prefijo("path", format!("{base}/"));
        let r = Suid.leer(&c, &f).expect("leer suid");
        assert!(r.filas.is_empty(), "no hay setuid y devolvio filas");
        // Pero SI se examino: la tabla vacia es un hecho, no un hueco.
        assert!(r.examinadas > 0);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn los_montajes_de_esta_maquina_se_leen() {
        let c = ctx();
        let r = Montajes
            .leer(&c, &Filtro::ninguno())
            .expect("leer montajes");
        assert!(!r.filas.is_empty(), "toda maquina tiene montajes");
        let i_punto = columna(&Montajes, "mountpoint");
        let puntos: Vec<String> = r.filas.iter().map(|f| f.valor(i_punto).a_texto()).collect();
        assert!(puntos.iter().any(|p| p == "/"), "falta la raiz: {puntos:?}");
    }

    #[test]
    fn el_mountinfo_se_analiza_con_campos_opcionales_variables() {
        // La trampa del formato: el numero de campos entre `opciones` y `-` es
        // VARIABLE. Partir por columnas fijas da el fstype equivocado.
        let texto = "\
23 28 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
24 28 0:23 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw
25 28 259:1 /datos /mnt/bind rw,relatime shared:5 master:3 - ext4 /dev/nvme0n1p1 rw,errors=remount-ro";
        let ms = analizar_mountinfo(texto);
        assert_eq!(ms.len(), 3);

        assert_eq!(ms[0].tipo, "proc");
        assert_eq!(ms[0].propagacion, "shared:12");

        // Sin campos opcionales: la propagacion queda vacia y el tipo sigue bien.
        assert_eq!(ms[1].tipo, "sysfs");
        assert_eq!(ms[1].propagacion, "");

        // Dos campos opcionales y un bind mount: `root` no es "/".
        assert_eq!(ms[2].tipo, "ext4");
        assert_eq!(ms[2].propagacion, "shared:5 master:3");
        assert_eq!(ms[2].raiz, "/datos");
        assert_eq!(ms[2].origen, "/dev/nvme0n1p1");
        assert_eq!(ms[2].opciones_super, "rw,errors=remount-ro");
        assert_eq!((ms[2].major, ms[2].minor), (259, 1));
    }

    #[test]
    fn las_rutas_con_espacios_se_desescapan() {
        // `mountinfo` escribe los espacios como `\040`. Sin desescapar, la ruta
        // no casa con la que devuelve ninguna otra tabla.
        let texto = "36 28 0:31 / /mnt/disco\\040externo rw,relatime - ext4 /dev/sdb1 rw";
        let ms = analizar_mountinfo(texto);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].punto, "/mnt/disco externo");
    }

    #[test]
    fn una_linea_truncada_se_salta_sin_panico() {
        assert!(analizar_mountinfo("23 28 0:22 / /proc rw -").is_empty());
        assert!(analizar_mountinfo("basura").is_empty());
        assert!(analizar_mountinfo("").is_empty());
    }

    #[test]
    fn las_opciones_de_montaje_se_leen_como_banderas() {
        let texto = "23 28 0:22 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw";
        let ms = analizar_mountinfo(texto);
        assert!(!tiene_opcion(&ms[0].opciones, "ro"));
        assert!(tiene_opcion(&ms[0].opciones, "noexec"));
        assert!(tiene_opcion(&ms[0].opciones, "nosuid"));
        // `nodev` no es `dev`: la comparacion es por elemento, no por substring.
        assert!(!tiene_opcion(&ms[0].opciones, "dev"));
    }

    #[test]
    fn un_superbloque_montado_dos_veces_cuenta_una_vez() {
        let texto = "\
23 28 259:1 / /a rw,relatime - ext4 /dev/nvme0n1p1 rw
24 28 259:1 /sub /b rw,relatime - ext4 /dev/nvme0n1p1 rw";
        let ms = analizar_mountinfo(texto);
        assert_eq!(ms.len(), 2, "son dos montajes");
        // Y un solo superbloque, con dos puntos de montaje.
        let mut por_dispositivo = std::collections::BTreeSet::new();
        for m in &ms {
            por_dispositivo.insert((m.major, m.minor));
        }
        assert_eq!(por_dispositivo.len(), 1);
    }

    #[test]
    fn los_superbloques_de_esta_maquina_se_leen() {
        let c = ctx();
        let r = Superbloques
            .leer(&c, &Filtro::ninguno())
            .expect("leer superbloques");
        assert!(!r.filas.is_empty());
        let i_n = columna(&Superbloques, "mountpoints");
        for f in &r.filas {
            match f.valor(i_n) {
                aegis_parser::valor::Valor::Entero(n) => assert!(*n >= 1),
                otro => panic!("mountpoints no es entero: {otro:?}"),
            }
        }
    }

    #[test]
    fn los_atributos_de_un_fichero_sin_ellos_son_cero_filas_y_no_un_error() {
        let ruta = "/tmp/aegis-estado-sin-xattr";
        let mut f = std::fs::File::create(ruta).unwrap();
        writeln!(f, "x").unwrap();
        let c = ctx();
        let filtro = Filtro::ninguno().con_igualdad("path", Literal::Texto(ruta.into()));
        let r = Xattrs.leer(&c, &filtro).expect("leer xattrs");
        assert!(r.filas.is_empty());
        let _ = std::fs::remove_file(ruta);
    }

    #[test]
    fn las_filas_de_ficheros_llevan_entidad_de_ubicacion() {
        let c = ctx();
        let base = "/tmp/aegis-estado-eid";
        let _ = std::fs::remove_dir_all(base);
        std::fs::create_dir_all(base).unwrap();
        std::fs::write(format!("{base}/x"), b"y").unwrap();

        let f = Filtro::ninguno().con_prefijo("path", format!("{base}/"));
        let r = Ficheros.leer(&c, &f).expect("leer");
        assert!(!r.filas.is_empty());
        for fila in &r.filas {
            assert_eq!(
                fila.entidad().map(|e| e.clase()),
                Some(Clase::Ubicacion),
                "una fila de fichero sin entidad de ubicacion"
            );
        }
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn el_presupuesto_agotado_trunca_el_recorrido() {
        let c = ctx().con_presupuesto(std::time::Duration::from_nanos(1));
        std::thread::sleep(std::time::Duration::from_millis(2));
        let f = Filtro::ninguno().con_prefijo("path", "/usr/");
        let r = Ficheros.leer(&c, &f).expect("no falla");
        assert!(r.truncada, "un recorrido cortado tiene que decirlo");
    }
}
