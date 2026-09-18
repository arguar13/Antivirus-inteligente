//! Bases de datos: MySQL, PostgreSQL, TDS, MongoDB, Redis y Elasticsearch.
//!
//! # Por que un EDR tiene que mirar esto
//!
//! Porque la exfiltracion no sale por el puerto 445. Sale por una consulta que
//! alguien lanzo contra la base de clientes desde una maquina que nunca la
//! habia tocado, y el sensor que solo ve «TCP al 3306» no puede distinguir eso
//! de la aplicacion haciendo su trabajo.
//!
//! Los seis emiten [`Hecho::OperacionDeBaseDeDatos`] con el mismo hueco para el
//! objeto y el mismo para el usuario. La consulta «quien toco esta tabla» no
//! depende del motor.
//!
//! # Lo que no se hace: guardar la consulta entera
//!
//! De una sentencia se queda la **operacion** y el **objeto**, no el texto
//! completo. Guardar el texto seria guardar datos personales de los clientes del
//! cliente en el registro de seguridad, que es un problema legal y no una
//! prestacion. El limite esta en [`MAX_SENTENCIA`] y el recorte se nota.

use aegis_wire::error::{ErrorDiseccion, Resultado};
use aegis_wire::hecho::{Hecho, ProtocoloApp};
use aegis_wire::lector::Lector;

use crate::disector::{Contexto, Disector, Fuerza, Salida};
use crate::texto;

/// Cuanto texto de una sentencia se guarda.
///
/// De una consulta interesa quien, contra que y que clase de operacion. El resto
/// son datos del cliente del cliente, y guardarlos en el registro de seguridad
/// es un problema legal, no una prestacion.
pub const MAX_SENTENCIA: usize = 256;

/// Recorta una sentencia al tope, dejando constancia de que se recorto.
fn recortar(s: &str) -> String {
    let limpio: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let limpio = limpio.trim().to_owned();
    if limpio.chars().count() <= MAX_SENTENCIA {
        return limpio;
    }
    let corto: String = limpio.chars().take(MAX_SENTENCIA).collect();
    format!("{corto}… [recortado]")
}

/// La clase de operacion que hay al principio de una sentencia SQL.
///
/// No es un analizador de SQL y no pretende serlo: es la primera palabra, que es
/// lo que hace falta para separar una lectura de un borrado y para que la cifra
/// de «cuantos DROP hubo esta semana» exista.
fn clase_sql(s: &str) -> &'static str {
    let primera: String = s
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect::<String>()
        .to_ascii_uppercase();
    match primera.as_str() {
        "SELECT" | "WITH" | "SHOW" | "DESCRIBE" | "DESC" | "EXPLAIN" => "consulta",
        "INSERT" | "REPLACE" | "UPDATE" | "MERGE" | "UPSERT" => "modificacion",
        "DELETE" | "TRUNCATE" => "borrado",
        "DROP" => "borrado-de-estructura",
        "CREATE" | "ALTER" | "RENAME" => "cambio-de-estructura",
        "GRANT" | "REVOKE" | "SET" => "cambio-de-permisos-o-sesion",
        "CALL" | "EXEC" | "EXECUTE" => "llamada-a-procedimiento",
        "LOAD" | "COPY" | "BULK" => "carga-masiva",
        "" => "vacia",
        _ => "otra",
    }
}

/// El objeto principal de una sentencia: lo que viene tras `FROM`, `INTO`,
/// `UPDATE`, `TABLE` o `JOIN`.
fn objeto_sql(s: &str) -> String {
    const PISTAS: [&str; 5] = ["from", "into", "update", "table", "join"];
    let palabras: Vec<&str> = s.split_whitespace().collect();
    for (i, p) in palabras.iter().enumerate() {
        let p = p.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
        if PISTAS.iter().any(|h| p.eq_ignore_ascii_case(h)) {
            if let Some(siguiente) = palabras.get(i + 1) {
                let limpio: String = siguiente
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
                    .take(64)
                    .collect();
                if !limpio.is_empty() {
                    return limpio;
                }
            }
        }
    }
    String::new()
}

// ════════════════════════════════════════════════════════════════════════════
// MySQL / MariaDB
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de MySQL.
pub const PUERTO_MYSQL: u16 = 3306;

/// La orden de MySQL, por su codigo.
fn orden_mysql(c: u8) -> Option<&'static str> {
    Some(match c {
        0x01 => "salir",
        0x02 => "usar-base",
        0x03 => "consulta",
        0x04 => "listar-campos",
        0x05 => "crear-base",
        0x06 => "borrar-base",
        0x07 => "recargar",
        0x08 => "apagar",
        0x09 => "estadisticas",
        0x0A => "listar-procesos",
        0x0C => "matar-proceso",
        0x0E => "latido",
        0x0F => "volcado-binario",
        0x11 => "cambiar-usuario",
        0x16 => "preparar-sentencia",
        0x17 => "ejecutar-sentencia",
        0x1B => "opcion",
        _ => return None,
    })
}

/// Disector de MySQL y MariaDB.
#[derive(Debug, Default, Clone, Copy)]
pub struct Mysql;

impl Mysql {
    /// La cabecera de paquete: `(longitud, secuencia)`.
    fn cabecera(datos: &[u8]) -> Resultado<(usize, u8)> {
        let mut l = Lector::nuevo(datos);
        // MySQL escribe la longitud en tres bytes little-endian, que es la unica
        // excepcion de orden en este modulo y por eso va comentada.
        let b = l.tomar(3, "mysql.longitud")?;
        let largo = u32::from_le_bytes([b[0], b[1], b[2], 0]) as usize;
        let secuencia = l.u8("mysql.secuencia")?;
        if largo == 0 || largo > 16 * 1024 * 1024 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "mysql.longitud",
                valor: largo as u64,
            });
        }
        Ok((largo, secuencia))
    }

    /// Si el paquete es un saludo del servidor (version de protocolo 10).
    fn es_saludo(datos: &[u8]) -> bool {
        matches!(Mysql::cabecera(datos), Ok((_, 0)))
            && datos.get(4) == Some(&0x0A)
            && datos
                .get(5..)
                .and_then(|v| texto::cadena_con_cero(v, 64))
                .is_some_and(|(v, _)| {
                    !v.is_empty() && v.chars().next().is_some_and(|c| c.is_ascii_digit())
                })
    }

    /// Que clase de paquete es, si es alguno que este disector lea.
    ///
    /// # Por que una sola funcion y no una para reconocer y otra para disecar
    ///
    /// Porque dos funciones que decidan lo mismo acaban decidiendo distinto. Lo
    /// encontro el barrido hostil: `reconoce` decia que no y `disecar` emitia
    /// dos hechos sobre el mismo buffer, que es un sensor afirmando cosas de un
    /// flujo que no habia reclamado. Con una sola clasificacion no puede pasar.
    fn clase(datos: &[u8], ctx: &Contexto) -> Option<ClaseMysql> {
        let (largo, secuencia) = Mysql::cabecera(datos).ok()?;
        // El paquete tiene que estar entero en lo que se ve: un trozo a medias
        // no se puede clasificar sin el estado del flujo, y adivinarlo daria una
        // orden inventada.
        if datos.len() != 4 + largo {
            return None;
        }
        if Mysql::es_saludo(datos) {
            return Some(ClaseMysql::Saludo);
        }
        if !ctx.del_cliente {
            return None;
        }
        match secuencia {
            0 => {
                let codigo = *datos.get(4)?;
                orden_mysql(codigo).map(|_| ClaseMysql::Orden(codigo))
            }
            // La peticion de acceso: capacidades, tamano maximo, juego de
            // caracteres y veintitres bytes reservados antes del usuario.
            1 if largo > 32 => {
                let usuario = texto::cadena_con_cero(datos.get(36..)?, 64)?.0;
                if usuario.is_empty() {
                    None
                } else {
                    Some(ClaseMysql::Acceso(usuario))
                }
            }
            _ => None,
        }
    }

    fn analizar(datos: &[u8], ctx: &Contexto) -> Resultado<Vec<Hecho>> {
        let Some(clase) = Mysql::clase(datos, ctx) else {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("mysql"));
        };
        let (largo, _) = Mysql::cabecera(datos)?;
        let cuerpo = &datos[4..(4 + largo).min(datos.len())];
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Mysql)];

        match clase {
            ClaseMysql::Saludo => {
                let (version, _) = texto::cadena_con_cero(&cuerpo[1..], 64).unwrap_or_default();
                hechos.push(Hecho::OperacionDeBaseDeDatos {
                    motor: ProtocoloApp::Mysql,
                    operacion: "saludo-del-servidor".to_owned(),
                    objeto: String::new(),
                    usuario: String::new(),
                });
                hechos.push(Hecho::AnomaliaDeFlujo {
                    codigo: "mysql-version-anunciada",
                    detalle: version,
                });
            }
            ClaseMysql::Acceso(usuario) => hechos.push(Hecho::OperacionDeBaseDeDatos {
                motor: ProtocoloApp::Mysql,
                operacion: "acceso".to_owned(),
                objeto: String::new(),
                usuario,
            }),
            ClaseMysql::Orden(codigo) => {
                let orden = orden_mysql(codigo).unwrap_or("desconocida");
                let argumento = aegis_wire::lector::ascii_legible(&cuerpo[1..]);
                let (operacion, objeto) = match codigo {
                    0x03 | 0x16 => (clase_sql(&argumento).to_owned(), objeto_sql(&argumento)),
                    0x02 => ("usar-base".to_owned(), recortar(&argumento)),
                    _ => (orden.to_owned(), String::new()),
                };
                hechos.push(Hecho::OperacionDeBaseDeDatos {
                    motor: ProtocoloApp::Mysql,
                    operacion,
                    objeto,
                    usuario: String::new(),
                });
                // El volcado binario es como se lleva un replicante la base entera.
                if codigo == 0x0F {
                    hechos.push(Hecho::AnomaliaDeFlujo {
                        codigo: "mysql-volcado-binario",
                        detalle: "un cliente pidio el registro binario de replicacion".to_owned(),
                    });
                }
            }
        }
        Ok(hechos)
    }
}

/// Lo que un paquete de MySQL puede ser para este disector.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaseMysql {
    /// El saludo del servidor, con su version.
    Saludo,
    /// La peticion de acceso, con el usuario que declara.
    Acceso(String),
    /// Una orden del cliente, por su codigo.
    Orden(u8),
}

impl Disector for Mysql {
    /// Longitud de tres bytes que cuadra con lo que hay, mas orden o saludo conocidos.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "mysql"
    }

    fn reconoce(&self, datos: &[u8], ctx: &Contexto) -> bool {
        Mysql::clase(datos, ctx).is_some()
    }

    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida {
        Salida::de_resultado(Mysql::analizar(datos, ctx))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "el saludo del servidor con su version",
            "la peticion de acceso con el usuario",
            "la orden de consulta, con su clase y su objeto",
            "preparar-sentencia y usar-base",
            "volcado-binario, apagar y matar-proceso",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "los conjuntos de resultados que devuelve el servidor",
            "los parametros de una sentencia preparada al ejecutarla",
            "el texto completo de la sentencia, que se recorta a proposito",
            "el protocolo comprimido y el dialogo una vez sobre TLS",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// PostgreSQL
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de PostgreSQL.
pub const PUERTO_POSTGRESQL: u16 = 5432;

/// La version de protocolo que pide un cliente moderno: 3.0.
const PROTOCOLO_POSTGRES: u32 = 196_608;

/// El codigo magico con el que un cliente pide subir a TLS.
const PETICION_TLS_POSTGRES: u32 = 80_877_103;

/// El codigo magico con el que un cliente cancela una consulta en curso.
const PETICION_CANCELACION_POSTGRES: u32 = 80_877_102;

/// Disector de PostgreSQL.
#[derive(Debug, Default, Clone, Copy)]
pub struct Postgresql;

impl Postgresql {
    /// Si esto es un mensaje de arranque, y cual.
    fn arranque(datos: &[u8]) -> Option<(u32, usize)> {
        let mut l = Lector::nuevo(datos);
        let largo = l.u32("postgres.longitud").ok()? as usize;
        if !(8..=10_000).contains(&largo) {
            return None;
        }
        let codigo = l.u32("postgres.codigo").ok()?;
        match codigo {
            PROTOCOLO_POSTGRES | PETICION_TLS_POSTGRES | PETICION_CANCELACION_POSTGRES => {
                Some((codigo, largo))
            }
            _ => None,
        }
    }

    /// Si esto es un mensaje corriente, con su etiqueta y su longitud.
    fn mensaje(datos: &[u8]) -> Option<(u8, usize)> {
        let etiqueta = *datos.first()?;
        if !matches!(
            etiqueta,
            b'Q' | b'P' | b'B' | b'E' | b'X' | b'p' | b'R' | b'C' | b'D' | b'S' | b'F'
        ) {
            return None;
        }
        let mut l = Lector::nuevo(datos);
        l.saltar(1, "postgres.etiqueta").ok()?;
        let largo = l.u32("postgres.longitud").ok()? as usize;
        // La longitud se cuenta a si misma: menos de cuatro es imposible.
        if !(4..=1_000_000).contains(&largo) {
            return None;
        }
        Some((etiqueta, largo))
    }

    fn analizar(datos: &[u8]) -> Resultado<Vec<Hecho>> {
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Postgresql)];

        if let Some((codigo, largo)) = Postgresql::arranque(datos) {
            match codigo {
                PETICION_TLS_POSTGRES => {
                    hechos.push(Hecho::OperacionDeBaseDeDatos {
                        motor: ProtocoloApp::Postgresql,
                        operacion: "peticion-de-tls".to_owned(),
                        objeto: String::new(),
                        usuario: String::new(),
                    });
                    return Ok(hechos);
                }
                PETICION_CANCELACION_POSTGRES => {
                    hechos.push(Hecho::OperacionDeBaseDeDatos {
                        motor: ProtocoloApp::Postgresql,
                        operacion: "cancelacion".to_owned(),
                        objeto: String::new(),
                        usuario: String::new(),
                    });
                    return Ok(hechos);
                }
                _ => {}
            }
            // Los parametros del arranque son pares de cadenas terminadas en
            // cero, y acaban en una cadena vacia.
            let mut pos = 8;
            let fin = largo.min(datos.len());
            let mut usuario = String::new();
            let mut base = String::new();
            let mut aplicacion = String::new();
            // Tope de pares: sin el, un buffer sin la cadena vacia final haria
            // recorrer el mensaje entero por parametro.
            for _ in 0..64 {
                if pos >= fin {
                    break;
                }
                let Some((clave, a)) = texto::cadena_con_cero(&datos[pos..fin], 256) else {
                    break;
                };
                pos += a;
                if clave.is_empty() {
                    break;
                }
                let Some((valor, b)) = texto::cadena_con_cero(&datos[pos..fin], 256) else {
                    break;
                };
                pos += b;
                match clave.as_str() {
                    "user" => usuario = valor,
                    "database" => base = valor,
                    "application_name" => aplicacion = valor,
                    _ => {}
                }
            }
            hechos.push(Hecho::OperacionDeBaseDeDatos {
                motor: ProtocoloApp::Postgresql,
                operacion: "acceso".to_owned(),
                objeto: base,
                usuario,
            });
            if !aplicacion.is_empty() {
                hechos.push(Hecho::AnomaliaDeFlujo {
                    codigo: "postgres-aplicacion-declarada",
                    detalle: recortar(&aplicacion),
                });
            }
            return Ok(hechos);
        }

        let Some((etiqueta, largo)) = Postgresql::mensaje(datos) else {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("postgresql"));
        };
        let fin = (1 + largo).min(datos.len());
        let cuerpo = &datos[5.min(fin)..fin];
        match etiqueta {
            b'Q' => {
                let sql = aegis_wire::lector::ascii_legible(
                    cuerpo.split(|&b| b == 0).next().unwrap_or(cuerpo),
                );
                hechos.push(Hecho::OperacionDeBaseDeDatos {
                    motor: ProtocoloApp::Postgresql,
                    operacion: clase_sql(&sql).to_owned(),
                    objeto: objeto_sql(&sql),
                    usuario: String::new(),
                });
            }
            b'P' => {
                // Parse: nombre de la sentencia, luego el SQL.
                let mut partes = cuerpo.splitn(3, |&b| b == 0);
                let _nombre = partes.next();
                let sql = partes
                    .next()
                    .map(aegis_wire::lector::ascii_legible)
                    .unwrap_or_default();
                hechos.push(Hecho::OperacionDeBaseDeDatos {
                    motor: ProtocoloApp::Postgresql,
                    operacion: format!("preparar-{}", clase_sql(&sql)),
                    objeto: objeto_sql(&sql),
                    usuario: String::new(),
                });
            }
            b'X' => hechos.push(Hecho::OperacionDeBaseDeDatos {
                motor: ProtocoloApp::Postgresql,
                operacion: "cierre".to_owned(),
                objeto: String::new(),
                usuario: String::new(),
            }),
            b'p' => hechos.push(Hecho::AutenticacionVista {
                mecanismo: "postgres-contrasena".to_owned(),
                usuario: String::new(),
                dominio: String::new(),
                resultado: "respuesta".to_owned(),
            }),
            // El resto son mensajes del servidor o de ejecucion: se reconocen y
            // su contenido no se analiza, que es distinto de callarselo.
            _ => return Ok(Vec::new()),
        }
        Ok(hechos)
    }
}

impl Disector for Postgresql {
    /// Codigo magico de arranque o etiqueta de mensaje con longitud coherente.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "postgresql"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Postgresql::arranque(datos).is_some()
            || matches!(
                Postgresql::mensaje(datos),
                Some((b'Q' | b'P' | b'X' | b'p', _))
            )
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        match Postgresql::analizar(datos) {
            Ok(h) if h.is_empty() => Salida::no_implementado(vec![Hecho::ProtocoloIdentificado(
                ProtocoloApp::Postgresql,
            )]),
            otro => Salida::de_resultado(otro),
        }
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "el arranque con usuario, base y nombre de aplicacion",
            "la peticion de subir a TLS y la de cancelacion",
            "la consulta simple (Q) con su clase y su objeto",
            "la sentencia preparada (P)",
            "el cierre (X) y la respuesta de contrasena (p)",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "las filas de resultado (DataRow) y su descripcion",
            "los parametros de Bind y el flujo de Execute",
            "el protocolo de copia (COPY) y su contenido",
            "el dialogo una vez que sube a TLS",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// TDS (Microsoft SQL Server)
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de Microsoft SQL Server.
pub const PUERTO_TDS: u16 = 1433;

/// El tipo de paquete TDS.
fn tipo_tds(t: u8) -> Option<&'static str> {
    Some(match t {
        0x01 => "lote-sql",
        0x02 => "acceso-antiguo",
        0x03 => "llamada-a-procedimiento",
        0x04 => "respuesta-tabular",
        0x06 => "atencion",
        0x07 => "carga-masiva",
        0x0E => "gestor-de-transacciones",
        0x10 => "acceso",
        0x11 => "autenticacion-integrada",
        0x12 => "pre-acceso",
        _ => return None,
    })
}

/// Disector de TDS.
#[derive(Debug, Default, Clone, Copy)]
pub struct Tds;

impl Tds {
    /// La cabecera: `(tipo, estado, longitud)`.
    ///
    /// # Por que se exige la cabecera ENTERA
    ///
    /// Porque «un tipo de una lista de diez y una longitud entre ocho y treinta y
    /// dos mil» le pasa a dos bytes de cada cien. Se midio con ruido puro: TDS
    /// reclamaba el dos por ciento de todo lo que pasaba por delante, mas que
    /// todos los demas disectores juntos.
    ///
    /// Los otros tres campos de MS-TDS tambien estan fijados por la norma, y
    /// exigirlos deja el reconocimiento donde tiene que estar:
    ///
    /// - el estado es un campo de bits y sus tres bits altos estan reservados,
    /// - la ventana no se usa y vale cero,
    /// - y la longitud cuenta el paquete entero, cabecera incluida.
    fn cabecera(datos: &[u8]) -> Resultado<(u8, u8, usize)> {
        let mut l = Lector::nuevo(datos);
        let tipo = l.u8("tds.tipo")?;
        if tipo_tds(tipo).is_none() {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("tds"));
        }
        let estado = l.u8("tds.estado")?;
        if estado & 0xE0 != 0 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("tds"));
        }
        let largo = l.u16("tds.longitud")? as usize;
        // La cabecera son ocho bytes y la longitud los cuenta; el maximo de un
        // paquete TDS negociado es 32 kilobytes.
        if !(8..=32_768).contains(&largo) {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "tds.longitud",
                valor: largo as u64,
            });
        }
        let _proceso = l.u16("tds.proceso")?;
        let _numero = l.u8("tds.numero-de-paquete")?;
        let ventana = l.u8("tds.ventana")?;
        if ventana != 0 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("tds"));
        }
        Ok((tipo, estado, largo))
    }

    /// La cabecera **y** que el paquete este entero en lo que se ve.
    ///
    /// Reconocer y disecar tienen que decidir lo mismo, y con dos funciones
    /// acaban decidiendo distinto: el barrido hostil encontro tres disectores
    /// asi antes de que esto se escribiera en un solo sitio.
    fn clasificar(datos: &[u8]) -> Option<(u8, u8, usize)> {
        let (tipo, estado, largo) = Tds::cabecera(datos).ok()?;
        if datos.len() != largo {
            return None;
        }
        Some((tipo, estado, largo))
    }

    fn analizar(datos: &[u8]) -> Resultado<Vec<Hecho>> {
        let Some((tipo, _estado, largo)) = Tds::clasificar(datos) else {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("tds"));
        };
        let nombre = tipo_tds(tipo).unwrap_or("desconocido");
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Tds)];
        let fin = largo.min(datos.len());
        let cuerpo = &datos[8.min(fin)..fin];

        match tipo {
            // El lote lleva el SQL en UTF-16 little-endian, que es como lo
            // manda Windows y lo que hace que un `grep` sobre el cable no lo
            // encuentre.
            0x01 => {
                let sql = texto::utf16le(cuerpo);
                hechos.push(Hecho::OperacionDeBaseDeDatos {
                    motor: ProtocoloApp::Tds,
                    operacion: clase_sql(&sql).to_owned(),
                    objeto: objeto_sql(&sql),
                    usuario: String::new(),
                });
                // `xp_cmdshell` ejecuta ordenes del sistema desde la base: es la
                // ruta clasica de base de datos a ejecucion remota.
                let bajo = sql.to_ascii_lowercase();
                for peligro in ["xp_cmdshell", "sp_oacreate", "openrowset", "bulk insert"] {
                    if bajo.contains(peligro) {
                        hechos.push(Hecho::EjecucionRemota {
                            via: ProtocoloApp::Tds,
                            orden: peligro.to_owned(),
                            objetivo: objeto_sql(&sql),
                        });
                    }
                }
            }
            0x03 => {
                hechos.push(Hecho::OperacionDeBaseDeDatos {
                    motor: ProtocoloApp::Tds,
                    operacion: "llamada-a-procedimiento".to_owned(),
                    objeto: recortar(&texto::utf16le(cuerpo)),
                    usuario: String::new(),
                });
            }
            0x12 => {
                hechos.push(Hecho::OperacionDeBaseDeDatos {
                    motor: ProtocoloApp::Tds,
                    operacion: "pre-acceso".to_owned(),
                    objeto: String::new(),
                    usuario: String::new(),
                });
            }
            _ => {
                hechos.push(Hecho::OperacionDeBaseDeDatos {
                    motor: ProtocoloApp::Tds,
                    operacion: nombre.to_owned(),
                    objeto: String::new(),
                    usuario: String::new(),
                });
            }
        }
        Ok(hechos)
    }
}

impl Disector for Tds {
    /// Tipo de paquete conocido y longitud dentro del rango negociable.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "tds"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Tds::clasificar(datos).is_some()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        Salida::de_resultado(Tds::analizar(datos))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la cabecera con su tipo, su estado y su longitud",
            "el lote SQL, leido en UTF-16 little-endian",
            "la llamada a procedimiento remoto",
            "el pre-acceso y el acceso",
            "las rutas de base de datos a ejecucion: xp_cmdshell, sp_OACreate, OPENROWSET",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el paquete de acceso (tipo 0x10) y sus campos ofuscados con la contrasena",
            "los flujos de respuesta tabular: columnas, filas y tipos",
            "los parametros tipados de una llamada a procedimiento",
            "el reensamblado de un lote partido en varios paquetes",
            "el dialogo cifrado tras la negociacion de TLS del pre-acceso",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// MongoDB
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de MongoDB.
pub const PUERTO_MONGODB: u16 = 27017;

/// El codigo de operacion del protocolo de cable de MongoDB.
fn operacion_mongodb(c: u32) -> Option<&'static str> {
    Some(match c {
        1 => "respuesta",
        2001 => "actualizar",
        2002 => "insertar",
        2004 => "consulta",
        2005 => "pedir-mas",
        2006 => "borrar",
        2007 => "matar-cursores",
        2012 => "comprimido",
        2013 => "mensaje",
        _ => return None,
    })
}

/// Disector de MongoDB.
#[derive(Debug, Default, Clone, Copy)]
pub struct Mongodb;

impl Mongodb {
    /// La cabecera: `(longitud, codigo)`.
    fn cabecera(datos: &[u8]) -> Resultado<(usize, u32)> {
        let mut l = Lector::nuevo(datos);
        let largo = l.u32_le("mongo.longitud")? as usize;
        // Toda la cabecera son dieciseis bytes; el maximo de un mensaje es
        // cuarenta y ocho megabytes por la propia especificacion.
        if !(16..=48 * 1024 * 1024).contains(&largo) {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "mongo.longitud",
                valor: largo as u64,
            });
        }
        let _peticion = l.u32_le("mongo.peticion")?;
        let _respuesta_a = l.u32_le("mongo.respuesta-a")?;
        let codigo = l.u32_le("mongo.codigo")?;
        if operacion_mongodb(codigo).is_none() {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("mongodb"));
        }
        Ok((largo, codigo))
    }

    /// El nombre del primer elemento de un documento BSON.
    ///
    /// En una orden de MongoDB el primer elemento **es** la orden: `{find:
    /// "usuarios", ...}`. Con eso y su valor se tiene la operacion y el objeto
    /// sin analizar el documento entero.
    fn primera_orden(datos: &[u8]) -> Option<(String, String)> {
        let mut l = Lector::nuevo(datos);
        let largo = l.u32_le("bson.longitud").ok()? as usize;
        if !(5..=16 * 1024 * 1024).contains(&largo) || largo > datos.len() {
            return None;
        }
        let tipo = l.u8("bson.tipo").ok()?;
        let resto = l.resto();
        let (nombre, avance) = texto::cadena_con_cero(resto, 128)?;
        let valor = &resto[avance.min(resto.len())..];
        let texto_valor = match tipo {
            // Cadena: longitud de cuatro bytes incluyendo el cero final.
            0x02 => {
                let mut v = Lector::nuevo(valor);
                let n = v.u32_le("bson.cadena").ok()? as usize;
                if n == 0 || n > 1024 {
                    return None;
                }
                let bytes = v.tomar(n.saturating_sub(1), "bson.cadena").ok()?;
                aegis_wire::lector::ascii_legible(bytes)
            }
            0x01 | 0x10 | 0x12 | 0x08 => String::new(),
            _ => String::new(),
        };
        Some((nombre, texto_valor))
    }

    fn analizar(datos: &[u8]) -> Resultado<Vec<Hecho>> {
        let (largo, codigo) = Mongodb::cabecera(datos)?;
        let nombre = operacion_mongodb(codigo).unwrap_or("desconocida");
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Mongodb)];
        let fin = largo.min(datos.len());

        let (operacion, objeto) = match codigo {
            2013 => {
                // OP_MSG: banderas de cuatro bytes y luego secciones. La de
                // tipo cero lleva el documento del cuerpo.
                let mut l = Lector::nuevo(&datos[..fin]);
                l.ir_a(16, "mongo.cuerpo")?;
                let _banderas = l.u32_le("mongo.banderas")?;
                let clase = l.u8("mongo.seccion")?;
                if clase != 0 {
                    return Ok(hechos);
                }
                match Mongodb::primera_orden(l.resto()) {
                    Some((orden, coleccion)) => (orden, coleccion),
                    None => (nombre.to_owned(), String::new()),
                }
            }
            2004 => {
                // OP_QUERY: banderas y luego el nombre completo de la coleccion.
                let mut l = Lector::nuevo(&datos[..fin]);
                l.ir_a(16, "mongo.cuerpo")?;
                let _banderas = l.u32_le("mongo.banderas")?;
                let (coleccion, _) =
                    texto::cadena_con_cero(l.resto(), 256).ok_or(ErrorDiseccion::Truncado {
                        campo: "mongo.coleccion",
                        esperados: 1,
                        habia: 0,
                    })?;
                ("consulta".to_owned(), coleccion)
            }
            2001 | 2002 | 2006 => {
                let mut l = Lector::nuevo(&datos[..fin]);
                l.ir_a(16, "mongo.cuerpo")?;
                let _cero = l.u32_le("mongo.reservado")?;
                let (coleccion, _) =
                    texto::cadena_con_cero(l.resto(), 256).ok_or(ErrorDiseccion::Truncado {
                        campo: "mongo.coleccion",
                        esperados: 1,
                        habia: 0,
                    })?;
                (nombre.to_owned(), coleccion)
            }
            _ => (nombre.to_owned(), String::new()),
        };

        hechos.push(Hecho::OperacionDeBaseDeDatos {
            motor: ProtocoloApp::Mongodb,
            operacion: recortar(&operacion),
            objeto: recortar(&objeto),
            usuario: String::new(),
        });
        Ok(hechos)
    }
}

impl Disector for Mongodb {
    /// Longitud acotada por la norma y codigo de operacion conocido.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "mongodb"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Mongodb::cabecera(datos).is_ok()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        Salida::de_resultado(Mongodb::analizar(datos))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la cabecera con su codigo de operacion",
            "OP_MSG y la orden que lleva su primer elemento BSON",
            "OP_QUERY con el nombre completo de la coleccion",
            "insertar, actualizar y borrar con su coleccion",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el documento BSON completo: solo se lee su primer elemento",
            "las secciones de tipo 1 de OP_MSG (las secuencias de documentos)",
            "los mensajes comprimidos (OP_COMPRESSED) y su carga",
            "el dialogo de SCRAM de la autenticacion",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Redis
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de Redis.
pub const PUERTO_REDIS: u16 = 6379;

/// Ordenes de Redis con las que se pasa de acceso a ejecucion en el anfitrion.
///
/// La cadena es conocida: `CONFIG SET dir` y `CONFIG SET dbfilename` apuntan el
/// fichero de volcado a `~/.ssh/authorized_keys`, y un `SAVE` lo escribe. Que
/// las tres aparezcan seguidas en un flujo es la tecnica entera.
const ORDENES_PELIGROSAS: [&str; 9] = [
    "CONFIG",
    "SLAVEOF",
    "REPLICAOF",
    "MODULE",
    "DEBUG",
    "EVAL",
    "SAVE",
    "BGSAVE",
    "SCRIPT",
];

/// Disector de Redis (protocolo RESP).
#[derive(Debug, Default, Clone, Copy)]
pub struct Redis;

impl Redis {
    /// Los elementos de un array RESP de cadenas.
    ///
    /// Devuelve `None` si no lo es. El tope de elementos y el de longitud estan
    /// puestos porque los dos numeros los escribe el cliente: sin ellos,
    /// `*1000000\r\n` haria reservar un vector de un millon de entradas por
    /// mensaje.
    fn orden(datos: &[u8]) -> Option<Vec<String>> {
        const MAX_ARGUMENTOS: usize = 128;
        const MAX_ARGUMENTO: usize = 4096;
        if datos.first() != Some(&b'*') {
            return None;
        }
        let (cabecera, mut pos) = texto::linea(datos)?;
        let n: usize = std::str::from_utf8(&cabecera[1..]).ok()?.parse().ok()?;
        if n == 0 || n > MAX_ARGUMENTOS {
            return None;
        }
        let mut salida = Vec::with_capacity(n.min(MAX_ARGUMENTOS));
        for _ in 0..n {
            let (marca, avance) = texto::linea(datos.get(pos..)?)?;
            pos += avance;
            if marca.first() != Some(&b'$') {
                return None;
            }
            let largo: usize = std::str::from_utf8(&marca[1..]).ok()?.parse().ok()?;
            if largo > MAX_ARGUMENTO {
                return None;
            }
            let trozo = datos.get(pos..pos + largo)?;
            pos += largo + 2;
            salida.push(aegis_wire::lector::ascii_legible(trozo));
        }
        Some(salida)
    }

    /// La orden, **si ademas** el verbo tiene forma de verbo.
    ///
    /// Un array RESP bien formado cuyo primer elemento sean bytes cualesquiera no
    /// es una orden de Redis. Que esta condicion viva en una sola funcion —y no
    /// una vez en `reconoce` y otra en `disecar`— es lo que impide que las dos
    /// discrepen: lo encontro el barrido hostil, donde una mutacion de un byte
    /// hacia que el disector emitiera hechos sobre un flujo que no habia
    /// reclamado.
    fn orden_valida(datos: &[u8]) -> Option<Vec<String>> {
        let v = Redis::orden(datos)?;
        let verbo = v.first()?;
        if verbo.is_empty() || verbo.len() > 32 || !verbo.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return None;
        }
        Some(v)
    }
}

impl Disector for Redis {
    /// Un array RESP entero cuyas longitudes cuadran.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "redis"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Redis::orden_valida(datos).is_some()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        let Some(partes) = Redis::orden_valida(datos) else {
            return Salida::sin_analizar(crate::cobertura::Motivo::Malformado);
        };
        let orden = partes
            .first()
            .map(|o| o.to_ascii_uppercase())
            .unwrap_or_default();
        let objeto = partes.get(1).cloned().unwrap_or_default();
        let mut hechos = vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Redis),
            Hecho::OperacionDeBaseDeDatos {
                motor: ProtocoloApp::Redis,
                operacion: orden.clone(),
                objeto: recortar(&objeto),
                usuario: partes
                    .get(1)
                    .filter(|_| orden == "AUTH" && partes.len() > 2)
                    .cloned()
                    .unwrap_or_default(),
            },
        ];
        if ORDENES_PELIGROSAS.contains(&orden.as_str()) {
            hechos.push(Hecho::EjecucionRemota {
                via: ProtocoloApp::Redis,
                orden: partes.iter().take(3).cloned().collect::<Vec<_>>().join(" "),
                objetivo: String::new(),
            });
        }
        Salida::entendido(hechos)
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "cualquier orden mandada como array RESP de cadenas",
            "la orden y su primer argumento",
            "AUTH y el usuario que declara",
            "las ordenes con las que se pasa a ejecucion: CONFIG, MODULE, EVAL, SLAVEOF, SAVE",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "las respuestas del servidor",
            "las ordenes en linea (el protocolo antiguo sin array)",
            "los argumentos mas alla del primero, salvo en las ordenes peligrosas",
            "el flujo de replicacion y el de la base en formato RDB",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Elasticsearch
// ════════════════════════════════════════════════════════════════════════════

/// Puerto del interfaz HTTP de Elasticsearch.
pub const PUERTO_ELASTICSEARCH: u16 = 9200;

/// Puerto del protocolo de transporte entre nodos.
pub const PUERTO_ELASTICSEARCH_TRANSPORTE: u16 = 9300;

/// Disector de Elasticsearch.
#[derive(Debug, Default, Clone, Copy)]
pub struct Elasticsearch;

impl Elasticsearch {
    /// Las rutas que solo existen en Elasticsearch y en OpenSearch.
    const RUTAS: [(&'static str, &'static str); 8] = [
        ("/_search", "consulta"),
        ("/_msearch", "consulta-multiple"),
        ("/_bulk", "carga-masiva"),
        ("/_cat/", "inventario"),
        ("/_cluster/", "administracion-del-cumulo"),
        ("/_snapshot", "instantanea"),
        ("/_security/", "administracion-de-seguridad"),
        ("/_scripts", "administracion-de-guiones"),
    ];

    fn por_http(datos: &[u8]) -> Option<(String, String)> {
        let (metodo, ruta, _) = texto::peticion_http(datos)?;
        for (marca, operacion) in Elasticsearch::RUTAS {
            if ruta.contains(marca) {
                let indice = ruta
                    .trim_start_matches('/')
                    .split('/')
                    .next()
                    .filter(|p| !p.starts_with('_'))
                    .unwrap_or_default()
                    .to_owned();
                return Some((format!("{metodo} {operacion}"), indice));
            }
        }
        None
    }

    /// El protocolo entre nodos empieza por `ES` y una longitud.
    fn por_transporte(datos: &[u8]) -> bool {
        let mut l = Lector::nuevo(datos);
        let Ok(marca) = l.tomar(2, "es.marca") else {
            return false;
        };
        if marca != b"ES" {
            return false;
        }
        // Detras va la longitud del mensaje en cuatro bytes big-endian.
        l.u32("es.longitud").is_ok_and(|n| n > 0 && n < 100_000_000)
    }
}

impl Disector for Elasticsearch {
    /// Una ruta HTTP propia, o la marca `ES` con su longitud.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "elasticsearch"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Elasticsearch::por_http(datos).is_some() || Elasticsearch::por_transporte(datos)
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        if let Some((operacion, indice)) = Elasticsearch::por_http(datos) {
            return Salida::entendido(vec![
                Hecho::ProtocoloIdentificado(ProtocoloApp::Elasticsearch),
                Hecho::OperacionDeBaseDeDatos {
                    motor: ProtocoloApp::Elasticsearch,
                    operacion,
                    objeto: indice,
                    usuario: String::new(),
                },
            ]);
        }
        if Elasticsearch::por_transporte(datos) {
            // Se reconoce el protocolo entre nodos y no se analiza su
            // serializacion, que es propia y cambia entre versiones.
            return Salida::no_implementado(vec![Hecho::ProtocoloIdentificado(
                ProtocoloApp::Elasticsearch,
            )]);
        }
        Salida::sin_analizar(crate::cobertura::Motivo::NoReconocido)
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "las peticiones HTTP de busqueda, carga masiva e inventario",
            "la administracion del cumulo, de la seguridad y de los guiones",
            "las instantaneas, que es por donde se saca un indice entero",
            "el indice contra el que va la peticion",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el cuerpo de la consulta en JSON",
            "los documentos de una carga masiva",
            "el protocolo de transporte entre nodos (puerto 9300), que usa una \
             serializacion propia que cambia entre versiones",
            "las respuestas del cumulo",
        ]
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn operacion(s: &Salida) -> Option<(&str, &str, &str)> {
        s.hechos.iter().find_map(|h| match h {
            Hecho::OperacionDeBaseDeDatos {
                operacion,
                objeto,
                usuario,
                ..
            } => Some((operacion.as_str(), objeto.as_str(), usuario.as_str())),
            _ => None,
        })
    }

    fn paquete_mysql(secuencia: u8, cuerpo: &[u8]) -> Vec<u8> {
        let mut v = (cuerpo.len() as u32).to_le_bytes()[..3].to_vec();
        v.push(secuencia);
        v.extend_from_slice(cuerpo);
        v
    }

    #[test]
    fn mysql_saca_la_clase_y_el_objeto_de_una_consulta() {
        // De una sentencia interesa quien, contra que y de que clase. El texto
        // completo son datos del cliente del cliente.
        let d = Mysql;
        let mut cuerpo = vec![0x03];
        cuerpo.extend_from_slice(b"SELECT * FROM clientes WHERE id=1");
        let b = paquete_mysql(0, &cuerpo);
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_MYSQL)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_MYSQL));
        assert!(s.cobertura.completa());
        let (op, obj, _) = operacion(&s).expect("una operacion");
        assert_eq!(op, "consulta");
        assert_eq!(obj, "clientes");
    }

    #[test]
    fn mysql_separa_un_borrado_de_una_lectura() {
        let d = Mysql;
        let mut cuerpo = vec![0x03];
        cuerpo.extend_from_slice(b"DROP TABLE auditoria");
        let s = d.disecar(
            &paquete_mysql(0, &cuerpo),
            &Contexto::tcp_cliente(PUERTO_MYSQL),
        );
        let (op, obj, _) = operacion(&s).expect("una operacion");
        assert_eq!(op, "borrado-de-estructura");
        assert_eq!(obj, "auditoria");
    }

    #[test]
    fn mysql_no_guarda_una_sentencia_entera() {
        // Guardar el texto completo seria guardar datos personales en el
        // registro de seguridad: un problema legal, no una prestacion.
        let larga = format!("SELECT * FROM t WHERE x='{}'", "a".repeat(2000));
        let recortada = recortar(&larga);
        assert!(recortada.ends_with("[recortado]"), "{recortada}");
        assert!(recortada.chars().count() < MAX_SENTENCIA + 20);
    }

    #[test]
    fn postgres_saca_el_usuario_y_la_base_del_arranque() {
        let d = Postgresql;
        let mut cuerpo = Vec::new();
        cuerpo.extend_from_slice(b"user\0ana\0database\0ventas\0application_name\0psql\0\0");
        let mut b = ((cuerpo.len() + 8) as u32).to_be_bytes().to_vec();
        b.extend_from_slice(&PROTOCOLO_POSTGRES.to_be_bytes());
        b.extend_from_slice(&cuerpo);
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_POSTGRESQL)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_POSTGRESQL));
        let (op, obj, usr) = operacion(&s).expect("una operacion");
        assert_eq!(op, "acceso");
        assert_eq!(obj, "ventas");
        assert_eq!(usr, "ana");
    }

    #[test]
    fn postgres_lee_una_consulta_simple() {
        let d = Postgresql;
        let sql = b"SELECT id FROM nominas\0";
        let mut b = vec![b'Q'];
        b.extend_from_slice(&((sql.len() + 4) as u32).to_be_bytes());
        b.extend_from_slice(sql);
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_POSTGRESQL));
        let (op, obj, _) = operacion(&s).expect("una operacion");
        assert_eq!(op, "consulta");
        assert_eq!(obj, "nominas");
    }

    #[test]
    fn tds_lee_el_sql_en_utf16_que_un_grep_no_encuentra() {
        // Es como lo manda Windows, y es por lo que un sensor que busque texto
        // ASCII sobre el cable no ve ni una consulta de SQL Server.
        let d = Tds;
        let sql: Vec<u8> = "SELECT * FROM nominas"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut b = vec![0x01, 0x01];
        b.extend_from_slice(&((8 + sql.len()) as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 1, 0]);
        b.extend_from_slice(&sql);
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_TDS)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_TDS));
        let (op, obj, _) = operacion(&s).expect("una operacion");
        assert_eq!(op, "consulta");
        assert_eq!(obj, "nominas");
    }

    #[test]
    fn tds_marca_la_ruta_de_base_de_datos_a_ejecucion() {
        let d = Tds;
        let sql: Vec<u8> = "EXEC xp_cmdshell 'whoami'"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut b = vec![0x01, 0x01];
        b.extend_from_slice(&((8 + sql.len()) as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 1, 0]);
        b.extend_from_slice(&sql);
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_TDS));
        let ejecucion = s
            .hechos
            .iter()
            .any(|h| matches!(h, Hecho::EjecucionRemota { orden, .. } if orden == "xp_cmdshell"));
        assert!(ejecucion, "{:?}", s.hechos);
    }

    #[test]
    fn mongodb_saca_la_orden_del_primer_elemento_bson() {
        // En una orden de MongoDB el primer elemento ES la orden.
        let d = Mongodb;
        let mut bson = Vec::new();
        bson.push(0x02u8); // cadena
        bson.extend_from_slice(b"find\0");
        bson.extend_from_slice(&9u32.to_le_bytes());
        bson.extend_from_slice(b"usuarios\0");
        bson.push(0x00);
        let mut doc = ((bson.len() + 4) as u32).to_le_bytes().to_vec();
        doc.extend_from_slice(&bson);

        let mut cuerpo = 0u32.to_le_bytes().to_vec(); // banderas
        cuerpo.push(0); // seccion de tipo cero
        cuerpo.extend_from_slice(&doc);

        let total = 16 + cuerpo.len();
        let mut b = (total as u32).to_le_bytes().to_vec();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&2013u32.to_le_bytes());
        b.extend_from_slice(&cuerpo);

        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_MONGODB)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_MONGODB));
        let (op, obj, _) = operacion(&s).expect("una operacion");
        assert_eq!(op, "find");
        assert_eq!(obj, "usuarios");
    }

    #[test]
    fn redis_ve_la_cadena_con_la_que_se_pasa_a_ejecucion() {
        // `CONFIG SET dir` apunta el volcado a `~/.ssh` y un `SAVE` lo escribe.
        let d = Redis;
        let b = b"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$14\r\n/root/.ssh\r\n\r\n";
        assert!(d.reconoce(b, &Contexto::tcp_cliente(PUERTO_REDIS)));
        let s = d.disecar(b, &Contexto::tcp_cliente(PUERTO_REDIS));
        let (op, _, _) = operacion(&s).expect("una operacion");
        assert_eq!(op, "CONFIG");
        assert!(
            s.hechos
                .iter()
                .any(|h| matches!(h, Hecho::EjecucionRemota { .. })),
            "{:?}",
            s.hechos
        );
    }

    #[test]
    fn redis_no_reserva_lo_que_diga_el_cliente() {
        // `*1000000` haria reservar un millon de entradas por mensaje si el
        // numero de elementos no tuviera tope.
        assert!(Redis::orden(b"*1000000\r\n").is_none());
        assert!(Redis::orden(b"*1\r\n$99999999\r\n").is_none());
    }

    #[test]
    fn elasticsearch_ve_la_instantanea_por_donde_se_saca_un_indice_entero() {
        let d = Elasticsearch;
        let b = b"PUT /_snapshot/fuga/uno?wait_for_completion=true HTTP/1.1\r\nHost: es\r\n\r\n";
        assert!(d.reconoce(b, &Contexto::tcp_cliente(PUERTO_ELASTICSEARCH)));
        let s = d.disecar(b, &Contexto::tcp_cliente(PUERTO_ELASTICSEARCH));
        let (op, _, _) = operacion(&s).expect("una operacion");
        assert_eq!(op, "PUT instantanea");
    }

    #[test]
    fn elasticsearch_declara_que_no_lee_el_protocolo_entre_nodos() {
        let d = Elasticsearch;
        let mut b = b"ES".to_vec();
        b.extend_from_slice(&1024u32.to_be_bytes());
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_ELASTICSEARCH_TRANSPORTE)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_ELASTICSEARCH_TRANSPORTE));
        assert!(!s.cobertura.completa(), "el hueco tiene que declararse");
    }

    #[test]
    fn la_clase_de_una_sentencia_separa_leer_de_borrar() {
        assert_eq!(clase_sql("select 1"), "consulta");
        assert_eq!(clase_sql("  DELETE FROM x"), "borrado");
        assert_eq!(clase_sql("GRANT ALL"), "cambio-de-permisos-o-sesion");
        assert_eq!(clase_sql(""), "vacia");
        assert_eq!(clase_sql("???"), "vacia");
    }

    #[test]
    fn los_seis_motores_emiten_el_mismo_hecho() {
        // La consulta «quien toco esta tabla» no puede depender del motor.
        for d in [
            Mysql.nombre(),
            Postgresql.nombre(),
            Tds.nombre(),
            Mongodb.nombre(),
            Redis.nombre(),
            Elasticsearch.nombre(),
        ] {
            assert!(!d.is_empty());
        }
        let ds: Vec<Box<dyn Disector>> = vec![
            Box::new(Mysql),
            Box::new(Postgresql),
            Box::new(Tds),
            Box::new(Mongodb),
            Box::new(Redis),
            Box::new(Elasticsearch),
        ];
        for d in &ds {
            assert!(!d.mensajes_que_entiende().is_empty(), "{}", d.nombre());
            assert!(!d.mensajes_que_no_analiza().is_empty(), "{}", d.nombre());
        }
    }
}
