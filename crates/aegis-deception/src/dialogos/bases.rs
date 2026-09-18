//! Senuelos de bases de datos: MySQL, PostgreSQL, MSSQL, Redis y MongoDB.
//!
//! # Lo que una base senuelo saca y un puerto cerrado no
//!
//! Las bases de datos expuestas son el objetivo mas rentable que hay: una sola da
//! el contenido entero de la organizacion. Por eso quien busca no se limita a ver
//! si el puerto responde; **intenta autenticarse** y, si entra, **consulta**.
//!
//! Cada uno de esos dos pasos entrega algo distinto:
//!
//! - La autenticacion trae el usuario y la base que espera encontrar. «`root` en
//!   `mysql`» es un barrido; «`svc_facturacion` en `contabilidad`» es alguien que
//!   ya ha estado dentro y sabe como se llaman las cosas aqui.
//! - La consulta dice **que venia a llevarse**, y si venia a llevarse o a cambiar.
//!
//! Redis y MongoDB tienen ademas la propiedad de que, historicamente, se exponen
//! **sin contrasena**, asi que su senuelo no tiene que fingir un fallo de acceso:
//! puede dejar entrar, que es lo que el atacante espera, y servir datos con
//! tokens atribuibles dentro.

use crate::dialogo::{primeros, recortado, Dialogo, Paso, Revelacion};
use crate::dialogos::acceso::tam_revelacion;
use crate::limitador::Transporte;

const MAX_CAMPO: usize = 256;

// ─────────────────────────────────────────────────────────────────────────────
// MySQL
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de MySQL.
///
/// Manda el saludo inicial —version, capacidades y los veinte bytes de sal— y
/// recoge del `HandshakeResponse` el **usuario y la base** que el cliente pide.
/// La respuesta de autenticacion es un hash contra la sal; como la sal es fija y
/// conocida, se guarda igual que el reto de VNC y de SMB.
#[derive(Debug, Default)]
pub struct Mysql {
    dicho: Vec<Revelacion>,
    saludado: bool,
}

/// La sal del saludo de MySQL, **fija y conocida**, por lo mismo que los otros
/// retos: con ella se puede trabajar despues el hash que mande el cliente.
pub const SAL_MYSQL: [u8; 20] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54,
];

impl Mysql {
    /// Un senuelo de MySQL nuevo.
    #[must_use]
    pub fn nuevo() -> Mysql {
        Mysql::default()
    }

    /// El paquete de saludo, con su cabecera de cuatro bytes.
    fn saludo_inicial() -> Vec<u8> {
        let mut c = Vec::new();
        c.push(10); // protocolo 10
        c.extend_from_slice(b"8.0.35-0ubuntu0.22.04.1\0");
        c.extend_from_slice(&7u32.to_le_bytes()); // id de conexion
        c.extend_from_slice(&SAL_MYSQL[..8]);
        c.push(0);
        c.extend_from_slice(&0xf7ffu16.to_le_bytes()); // capacidades bajas
        c.push(0x21); // conjunto de caracteres
        c.extend_from_slice(&0x0002u16.to_le_bytes()); // estado
        c.extend_from_slice(&0x81ffu16.to_le_bytes()); // capacidades altas
        c.push(21); // largo de la sal
        c.extend_from_slice(&[0u8; 10]); // reservado
        c.extend_from_slice(&SAL_MYSQL[8..]);
        c.push(0);
        c.extend_from_slice(b"caching_sha2_password\0");
        con_cabecera_mysql(&c, 0)
    }

    /// Saca usuario y base de un `HandshakeResponse41`.
    ///
    /// Tras 32 bytes fijos viene el usuario terminado en nulo, despues la
    /// respuesta de autenticacion (con su longitud delante) y despues la base.
    #[must_use]
    pub fn usuario_y_base(datos: &[u8]) -> Option<(String, String)> {
        let c = datos.get(4..)?; // se salta la cabecera del paquete
        let cuerpo = c.get(32..)?;
        let fin = cuerpo.iter().position(|&b| b == 0)?;
        if fin > MAX_CAMPO {
            return None;
        }
        let usuario = String::from_utf8_lossy(&cuerpo[..fin]).to_string();
        let resto = cuerpo.get(fin + 1..)?;
        let n = *resto.first()? as usize;
        let tras_auth = resto.get(1 + n..)?;
        let base = match tras_auth.iter().position(|&b| b == 0) {
            Some(f) if f <= MAX_CAMPO => String::from_utf8_lossy(&tras_auth[..f]).to_string(),
            _ => String::new(),
        };
        Some((usuario, base))
    }
}

/// Antepone la cabecera de MySQL: tres bytes de longitud y uno de secuencia.
fn con_cabecera_mysql(cuerpo: &[u8], secuencia: u8) -> Vec<u8> {
    let n = cuerpo.len() as u32;
    let mut v = Vec::with_capacity(4 + cuerpo.len());
    v.extend_from_slice(&n.to_le_bytes()[..3]);
    v.push(secuencia);
    v.extend_from_slice(cuerpo);
    v
}

/// Un paquete de error de MySQL.
fn error_mysql(codigo: u16, estado: &str, texto: &str, secuencia: u8) -> Vec<u8> {
    let mut c = vec![0xff];
    c.extend_from_slice(&codigo.to_le_bytes());
    c.push(b'#');
    c.extend_from_slice(estado.as_bytes());
    c.extend_from_slice(texto.as_bytes());
    con_cabecera_mysql(&c, secuencia)
}

impl Dialogo for Mysql {
    fn servicio(&self) -> &'static str {
        "mysql"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn saludo(&mut self) -> Option<Vec<u8>> {
        self.saludado = true;
        Some(Mysql::saludo_inicial())
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        if entrada.len() < 5 {
            return Paso::Cierra;
        }
        if let Some((usuario, base)) = Mysql::usuario_y_base(entrada) {
            if !usuario.is_empty() {
                self.dicho.push(Revelacion::Credencial {
                    usuario: usuario.clone(),
                    clave: "hash contra la sal fija del saludo".to_owned(),
                });
                if !base.is_empty() {
                    self.dicho.push(Revelacion::Peticion {
                        que: format!("queria la base «{base}»"),
                    });
                }
                return Paso::RespondeYCierra(error_mysql(
                    1045,
                    "28000",
                    &format!("Access denied for user '{usuario}'@'10.0.0.5' (using password: YES)"),
                    2,
                ));
            }
        }
        Paso::RespondeYCierra(error_mysql(1043, "08S01", "Bad handshake", 1))
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.dicho.iter().map(tam_revelacion).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PostgreSQL
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de PostgreSQL.
///
/// El `StartupMessage` viene en claro y trae **usuario, base y aplicacion** como
/// pares de texto. El nombre de la aplicacion es especialmente util: lo pone la
/// biblioteca cliente (`psql`, `psycopg2`, `DBeaver`, `sqlmap`) y dice con que
/// estan mirando.
#[derive(Debug, Default)]
pub struct Postgres {
    dicho: Vec<Revelacion>,
}

impl Postgres {
    /// Un senuelo de PostgreSQL nuevo.
    #[must_use]
    pub fn nuevo() -> Postgres {
        Postgres::default()
    }

    /// Los pares del `StartupMessage`.
    #[must_use]
    pub fn parametros(datos: &[u8]) -> Option<Vec<(String, String)>> {
        if datos.len() < 8 {
            return None;
        }
        let largo = u32::from_be_bytes([datos[0], datos[1], datos[2], datos[3]]) as usize;
        // El largo lo escribe el cliente: se acota a lo que de verdad hay.
        let fin = largo.min(datos.len());
        let version = u32::from_be_bytes([datos[4], datos[5], datos[6], datos[7]]);
        if version != 196_608 {
            return None; // 3.0; otra cosa es SSLRequest o basura
        }
        let mut pares = Vec::new();
        let mut i = 8usize;
        while i < fin {
            let f = datos[i..fin].iter().position(|&b| b == 0)? + i;
            if f == i {
                break;
            }
            let clave = String::from_utf8_lossy(&datos[i..f.min(i + MAX_CAMPO)]).to_string();
            i = f + 1;
            let f = datos[i..fin].iter().position(|&b| b == 0).map(|p| p + i)?;
            let valor = String::from_utf8_lossy(&datos[i..f.min(i + MAX_CAMPO)]).to_string();
            i = f + 1;
            pares.push((clave, valor));
            if pares.len() >= 16 {
                break;
            }
        }
        Some(pares)
    }
}

impl Dialogo for Postgres {
    fn servicio(&self) -> &'static str {
        "postgres"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        // `SSLRequest`: ocho bytes con el codigo 80877103. Se contesta que no, que
        // es lo que hace un servidor sin TLS, y el cliente reintenta en claro.
        if entrada.len() == 8
            && u32::from_be_bytes([entrada[4], entrada[5], entrada[6], entrada[7]]) == 80_877_103
        {
            return Paso::Responde(b"N".to_vec());
        }
        match Postgres::parametros(entrada) {
            Some(pares) if !pares.is_empty() => {
                let busca = |k: &str| {
                    pares
                        .iter()
                        .find(|(c, _)| c == k)
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default()
                };
                let usuario = busca("user");
                let base = busca("database");
                let app = busca("application_name");
                if !usuario.is_empty() {
                    self.dicho.push(Revelacion::Credencial {
                        usuario: usuario.clone(),
                        clave: "(postgres no manda la clave en el arranque)".to_owned(),
                    });
                }
                if !base.is_empty() {
                    self.dicho.push(Revelacion::Peticion {
                        que: format!("queria la base «{base}»"),
                    });
                }
                if !app.is_empty() {
                    self.dicho.push(Revelacion::Herramienta { texto: app });
                }
                // Error de autenticacion, con el formato de campos del protocolo.
                let texto = format!("password authentication failed for user \"{usuario}\"");
                let mut c = vec![b'E'];
                let mut campos = Vec::new();
                campos.extend_from_slice(b"SFATAL\0");
                campos.extend_from_slice(b"C28P01\0");
                campos.push(b'M');
                campos.extend_from_slice(texto.as_bytes());
                campos.push(0);
                campos.push(0);
                c.extend_from_slice(&((campos.len() + 4) as u32).to_be_bytes());
                c.extend_from_slice(&campos);
                Paso::RespondeYCierra(c)
            }
            _ => Paso::Cierra,
        }
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.dicho.iter().map(tam_revelacion).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MSSQL
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de Microsoft SQL Server.
///
/// El `PRELOGIN` de TDS se contesta con version y cifrado, y el `LOGIN7` que viene
/// detras trae **usuario, contrasena, base, maquina y aplicacion**. La contrasena
/// va «cifrada» con un giro de nibbles y un XOR con `0xA5` que es publico desde
/// hace veinte anos: se deshace aqui, y por eso este senuelo entrega la clave en
/// claro.
#[derive(Debug, Default)]
pub struct Mssql {
    dicho: Vec<Revelacion>,
}

// Los desplazamientos de los campos variables del `LOGIN7`, contados desde el
// principio del registro —es decir, tras los 8 bytes de cabecera TDS—.
//
// # Por que van con nombre y no como numeros dentro de la funcion
//
// Porque la primera version los puso a ojo y se equivoco en ocho bytes: leia el
// usuario en 48 y la clave en 52, que son `ibAppName` e `ibServerName`. El senuelo
// habria dado el nombre de la aplicacion como usuario y el del servidor
// des-ofuscado como contrasena — basura, justo donde esta fase afirma entregar la
// credencial en claro.
//
// Y no lo atrapo ninguna prueba, porque la prueba construia el paquete con los
// mismos desplazamientos equivocados: comprobaba que el codigo coincide consigo
// mismo, que es no comprobar nada. Con los cinco campos nombrados y colocados en su
// sitio, leer el que no es devuelve otro texto y la prueba se cae.
//
// La parte fija va de `Length` a `ClientLCID` y mide 36 bytes; de ahi en adelante
// cada campo son dos `u16`: desplazamiento y longitud EN CARACTERES.
/// `ibHostName` — la maquina desde la que se conecta.
const IB_HOST_NAME: usize = 36;
/// `ibUserName` — el usuario que prueba.
const IB_USER_NAME: usize = 40;
/// `ibPassword` — la contrasena, ofuscada.
const IB_PASSWORD: usize = 44;
/// `ibAppName` — la aplicacion cliente.
const IB_APP_NAME: usize = 48;
/// `ibServerName` — el servidor al que creia conectarse.
const IB_SERVER_NAME: usize = 52;

impl Mssql {
    /// Un senuelo de MSSQL nuevo.
    #[must_use]
    pub fn nuevo() -> Mssql {
        Mssql::default()
    }

    /// Deshace el ofuscado de una contrasena de `LOGIN7`.
    ///
    /// Cada byte lleva los nibbles intercambiados y un XOR con `0xA5`; el texto es
    /// UTF-16 en little-endian.
    #[must_use]
    pub fn clave_en_claro(ofuscada: &[u8]) -> String {
        let claros: Vec<u8> = ofuscada.iter().map(|b| (b ^ 0xA5).rotate_left(4)).collect();
        let u: Vec<u16> = claros
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        String::from_utf16_lossy(&u)
    }

    /// Saca usuario y clave de un paquete `LOGIN7`.
    ///
    /// Las posiciones de los campos son desplazamientos y longitudes de 16 bits a
    /// partir del principio del cuerpo, y **los escribe el cliente**: cada uno se
    /// comprueba contra el tamano real.
    #[must_use]
    pub fn usuario_y_clave(datos: &[u8]) -> Option<(String, String)> {
        // Cabecera TDS de 8 bytes; tipo 16 = LOGIN7.
        if datos.len() < 8 + 94 || datos[0] != 0x10 {
            return None;
        }
        let c = &datos[8..];
        let leer = |desp: usize| -> String {
            if desp + 4 > c.len() {
                return String::new();
            }
            let off = u16::from_le_bytes([c[desp], c[desp + 1]]) as usize;
            let largo = u16::from_le_bytes([c[desp + 2], c[desp + 3]]) as usize * 2;
            if largo == 0 || largo > MAX_CAMPO * 2 || off + largo > c.len() {
                return String::new();
            }
            let u: Vec<u16> = c[off..off + largo]
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect();
            String::from_utf16_lossy(&u)
        };
        let crudo = |desp: usize| -> Vec<u8> {
            if desp + 4 > c.len() {
                return Vec::new();
            }
            let off = u16::from_le_bytes([c[desp], c[desp + 1]]) as usize;
            let largo = u16::from_le_bytes([c[desp + 2], c[desp + 3]]) as usize * 2;
            if largo == 0 || largo > MAX_CAMPO * 2 || off + largo > c.len() {
                return Vec::new();
            }
            c[off..off + largo].to_vec()
        };
        let usuario = leer(IB_USER_NAME);
        let clave = Mssql::clave_en_claro(&crudo(IB_PASSWORD));
        if usuario.is_empty() && clave.is_empty() {
            return None;
        }
        Some((usuario, clave))
    }

    /// Los otros tres campos en claro del `LOGIN7`: maquina, aplicacion y el
    /// servidor al que creia conectarse.
    ///
    /// La aplicacion es la mas util de las tres: la pone la biblioteca cliente
    /// —`SQL Server Management Studio`, `sqlmap`, `.Net SqlClient Data Provider`—
    /// y dice con que estan mirando. El nombre de servidor dice a que creian
    /// llegar, que a veces es un nombre interno que no deberian conocer.
    #[must_use]
    pub fn maquina_app_y_servidor(datos: &[u8]) -> Option<(String, String, String)> {
        if datos.len() < 8 + 94 || datos[0] != 0x10 {
            return None;
        }
        let c = &datos[8..];
        let leer = |desp: usize| -> String {
            if desp + 4 > c.len() {
                return String::new();
            }
            let off = u16::from_le_bytes([c[desp], c[desp + 1]]) as usize;
            let largo = u16::from_le_bytes([c[desp + 2], c[desp + 3]]) as usize * 2;
            if largo == 0 || largo > MAX_CAMPO * 2 || off + largo > c.len() {
                return String::new();
            }
            let u: Vec<u16> = c[off..off + largo]
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect();
            String::from_utf16_lossy(&u)
        };
        Some((leer(IB_HOST_NAME), leer(IB_APP_NAME), leer(IB_SERVER_NAME)))
    }
}

impl Dialogo for Mssql {
    fn servicio(&self) -> &'static str {
        "mssql"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        match entrada.first() {
            // PRELOGIN
            Some(0x12) => {
                self.dicho.push(Revelacion::Herramienta {
                    texto: "cliente TDS: mando PRELOGIN".to_owned(),
                });
                // Respuesta con VERSION (0) y ENCRYPTION (1) y el terminador.
                let mut cuerpo = vec![
                    0x00, 0x00, 0x1a, 0x00, 0x06, // VERSION en 26, 6 bytes
                    0x01, 0x00, 0x20, 0x00, 0x01, // ENCRYPTION en 32, 1 byte
                    0xff, // terminador
                ];
                cuerpo.extend_from_slice(&[0u8; 15]); // hasta el offset 26
                cuerpo.extend_from_slice(&[15, 0, 0x07, 0xd0, 0, 0]); // 15.0.2000
                cuerpo.push(0x02); // cifrado no soportado
                let mut v = vec![0x04, 0x01];
                v.extend_from_slice(&((cuerpo.len() + 8) as u16).to_be_bytes());
                v.extend_from_slice(&[0, 0, 1, 0]);
                v.extend_from_slice(&cuerpo);
                Paso::Responde(v)
            }
            // LOGIN7
            Some(0x10) => {
                if let Some((usuario, clave)) = Mssql::usuario_y_clave(entrada) {
                    self.dicho.push(Revelacion::Credencial { usuario, clave });
                }
                if let Some((maquina, app, servidor)) = Mssql::maquina_app_y_servidor(entrada) {
                    if !app.is_empty() {
                        self.dicho.push(Revelacion::Herramienta {
                            texto: format!(
                                "aplicacion cliente «{app}» desde la maquina «{maquina}»"
                            ),
                        });
                    }
                    if !servidor.is_empty() {
                        self.dicho.push(Revelacion::Peticion {
                            que: format!("creia conectarse a «{servidor}»"),
                        });
                    }
                }
                // Un token de error de TDS con «Login failed».
                let texto = "Login failed for user.";
                let u: Vec<u8> = texto.encode_utf16().flat_map(u16::to_le_bytes).collect();
                let mut t = vec![0xAA];
                t.extend_from_slice(&((u.len() + 14) as u16).to_le_bytes());
                t.extend_from_slice(&18456u32.to_le_bytes()); // numero
                t.push(1); // estado
                t.push(14); // clase
                t.extend_from_slice(&((texto.len()) as u16).to_le_bytes());
                t.extend_from_slice(&u);
                t.extend_from_slice(&[0, 0, 0, 0]);
                t.push(0xFD); // DONE
                let mut v = vec![0x04, 0x01];
                v.extend_from_slice(&((t.len() + 8) as u16).to_be_bytes());
                v.extend_from_slice(&[0, 0, 1, 0]);
                v.extend_from_slice(&t);
                Paso::RespondeYCierra(v)
            }
            _ => Paso::Cierra,
        }
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.dicho.iter().map(tam_revelacion).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Redis
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de Redis.
///
/// # Por que este deja entrar
///
/// Porque Redis se expone sin contrasena constantemente, y eso es lo que el
/// atacante espera encontrar. Un senuelo que pidiera autenticacion seria menos
/// creible que uno que no la pide, y ademas perderia lo que de verdad interesa:
/// **que hace cuando entra**. Y lo que hace con un Redis abierto esta muy
/// estudiado — `CONFIG SET dir`, `CONFIG SET dbfilename`, `SAVE` — porque es como
/// se escribe una clave SSH en el disco del servidor. Ver esa secuencia es ver a
/// alguien intentando ejecutar codigo, no consultando datos.
#[derive(Debug, Default)]
pub struct Redis {
    dicho: Vec<Revelacion>,
    /// Lo que devuelve un `GET` o un `KEYS`, con tokens atribuibles dentro.
    cebo: String,
}

impl Redis {
    /// Un senuelo de Redis nuevo.
    #[must_use]
    pub fn nuevo() -> Redis {
        Redis::default()
    }

    /// Un senuelo que sirve `cebo` como valor de las claves.
    #[must_use]
    pub fn con_cebo(cebo: String) -> Redis {
        Redis {
            cebo,
            ..Redis::default()
        }
    }

    /// Trocea un mando en el protocolo RESP (`*N\r\n$L\r\n...`).
    ///
    /// Tambien acepta la forma en linea, que es la que usa quien prueba a mano con
    /// `telnet` y la que usan varios exploits.
    #[must_use]
    pub fn trocear(datos: &[u8]) -> Option<Vec<String>> {
        let texto = recortado(datos, 4096);
        if !texto.starts_with('*') {
            let partes: Vec<String> = texto
                .split_whitespace()
                .take(16)
                .map(|s| s.chars().take(MAX_CAMPO).collect())
                .collect();
            return if partes.is_empty() {
                None
            } else {
                Some(partes)
            };
        }
        let mut lineas = texto.split("\r\n");
        let n: usize = lineas.next()?.trim_start_matches('*').parse().ok()?;
        if n > 16 {
            return None; // un mando con mas de dieciseis partes no es de Redis
        }
        let mut partes = Vec::with_capacity(n);
        for _ in 0..n {
            let l = lineas.next()?;
            if !l.starts_with('$') {
                return None;
            }
            let v = lineas.next()?;
            partes.push(v.chars().take(MAX_CAMPO).collect());
        }
        Some(partes)
    }
}

impl Dialogo for Redis {
    fn servicio(&self) -> &'static str {
        "redis"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        let Some(partes) = Redis::trocear(entrada) else {
            return Paso::RespondeYCierra(b"-ERR Protocol error\r\n".to_vec());
        };
        let orden = partes[0].to_ascii_uppercase();
        let arg = |i: usize| partes.get(i).cloned().unwrap_or_default();

        // CONFIG SET y SAVE son el camino conocido para escribir un fichero en el
        // disco del servidor. No es una consulta: es ejecucion en dos pasos.
        if orden == "CONFIG" && arg(1).eq_ignore_ascii_case("set") {
            self.dicho.push(Revelacion::OrdenDeEscritura {
                que: format!("CONFIG SET {} {}", arg(2), arg(3)),
            });
            return Paso::Responde(b"+OK\r\n".to_vec());
        }
        match orden.as_str() {
            "AUTH" => {
                self.dicho.push(Revelacion::Credencial {
                    usuario: if partes.len() > 2 {
                        arg(1)
                    } else {
                        "default".to_owned()
                    },
                    clave: partes.last().cloned().unwrap_or_default(),
                });
                Paso::Responde(b"+OK\r\n".to_vec())
            }
            "PING" => Paso::Responde(b"+PONG\r\n".to_vec()),
            "INFO" => {
                self.dicho.push(Revelacion::Peticion {
                    que: "INFO: estaba inventariando el servidor".to_owned(),
                });
                let info = "# Server\r\nredis_version:7.0.11\r\nos:Linux 5.15.0 x86_64\r\n\
                            # Keyspace\r\ndb0:keys=3,expires=0\r\n";
                Paso::Responde(format!("${}\r\n{info}\r\n", info.len()).into_bytes())
            }
            "KEYS" | "SCAN" => {
                self.dicho.push(Revelacion::Peticion {
                    que: format!("{orden} {}", arg(1)),
                });
                let claves = ["sesiones:activas", "config:api", "clientes:export"];
                let mut v = format!("*{}\r\n", claves.len());
                for c in claves {
                    v.push_str(&format!("${}\r\n{c}\r\n", c.len()));
                }
                Paso::Responde(v.into_bytes())
            }
            "GET" | "HGETALL" | "LRANGE" => {
                self.dicho.push(Revelacion::Peticion {
                    que: format!("{orden} {}", arg(1)),
                });
                if self.cebo.is_empty() {
                    Paso::Responde(b"$-1\r\n".to_vec())
                } else {
                    Paso::Responde(
                        format!("${}\r\n{}\r\n", self.cebo.len(), self.cebo).into_bytes(),
                    )
                }
            }
            "SET" | "DEL" | "FLUSHALL" | "FLUSHDB" => {
                self.dicho.push(Revelacion::OrdenDeEscritura {
                    que: format!("{orden} {}", arg(1)),
                });
                Paso::Responde(b"+OK\r\n".to_vec())
            }
            "SAVE" | "BGSAVE" => {
                self.dicho.push(Revelacion::OrdenDeEscritura {
                    que: format!("{orden}: queria volcar a disco"),
                });
                Paso::Responde(b"+OK\r\n".to_vec())
            }
            "QUIT" => Paso::RespondeYCierra(b"+OK\r\n".to_vec()),
            otra => Paso::Responde(
                format!("-ERR unknown command '{}'\r\n", primeros(otra, 32)).into_bytes(),
            ),
        }
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.cebo.len() + self.dicho.iter().map(tam_revelacion).sum::<usize>()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MongoDB
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de MongoDB.
///
/// Contesta al `hello`/`isMaster` con una respuesta creible y recoge de las
/// consultas **que base y que coleccion** buscaban. Como Redis, se expone sin
/// autenticacion muy a menudo, asi que no se finge un rechazo.
#[derive(Debug, Default)]
pub struct Mongo {
    dicho: Vec<Revelacion>,
}

impl Mongo {
    /// Un senuelo de MongoDB nuevo.
    #[must_use]
    pub fn nuevo() -> Mongo {
        Mongo::default()
    }

    /// El nombre del mando de un mensaje, sacado del BSON sin parsearlo entero.
    ///
    /// Un documento BSON empieza con su longitud y despues los campos, cada uno
    /// con su tipo y su nombre terminado en nulo. El **primer** nombre es el
    /// mando, que es lo unico que hace falta aqui: parsear BSON entero seria traer
    /// un analizador de formato binario ajeno a la ruta de un senuelo.
    #[must_use]
    pub fn mando(datos: &[u8]) -> Option<String> {
        // 16 de cabecera de mensaje; para OP_MSG, 4 de banderas y 1 de tipo.
        let doc = datos.get(21..)?;
        if doc.len() < 5 {
            return None;
        }
        let nombre = doc.get(5..)?;
        let fin = nombre.iter().position(|&b| b == 0)?;
        if fin == 0 || fin > 64 {
            return None;
        }
        Some(String::from_utf8_lossy(&nombre[..fin]).to_string())
    }
}

impl Dialogo for Mongo {
    fn servicio(&self) -> &'static str {
        "mongodb"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        if entrada.len() < 16 {
            return Paso::Cierra;
        }
        let codigo = u32::from_le_bytes([entrada[12], entrada[13], entrada[14], entrada[15]]);
        let mando = Mongo::mando(entrada).unwrap_or_else(|| format!("codigo {codigo}"));
        // Las escrituras de Mongo se llaman asi y no hay que adivinarlas.
        if matches!(
            mando.as_str(),
            "insert" | "update" | "delete" | "drop" | "dropDatabase" | "createUser"
        ) {
            self.dicho.push(Revelacion::OrdenDeEscritura { que: mando });
        } else {
            self.dicho.push(Revelacion::Peticion { que: mando });
        }
        // Una respuesta OP_MSG con un documento minimo `{ok: 1.0}`.
        let mut doc = Vec::new();
        doc.extend_from_slice(&0u32.to_le_bytes()); // hueco para la longitud
        doc.push(0x01); // double
        doc.extend_from_slice(b"ok\0");
        doc.extend_from_slice(&1.0f64.to_le_bytes());
        doc.push(0);
        let n = doc.len() as u32;
        doc[..4].copy_from_slice(&n.to_le_bytes());

        let mut cuerpo = Vec::new();
        cuerpo.extend_from_slice(&0u32.to_le_bytes()); // banderas
        cuerpo.push(0); // seccion tipo 0
        cuerpo.extend_from_slice(&doc);

        let total = 16 + cuerpo.len();
        let mut v = Vec::with_capacity(total);
        v.extend_from_slice(&(total as u32).to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes()); // id de peticion
        v.extend_from_slice(&entrada[4..8]); // en respuesta a
        v.extend_from_slice(&2013u32.to_le_bytes()); // OP_MSG
        v.extend_from_slice(&cuerpo);
        Paso::Responde(v)
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.dicho.iter().map(tam_revelacion).sum()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_saludo_de_mysql_declara_su_tamano_de_verdad() {
        let s = Mysql::saludo_inicial();
        let n = u32::from_le_bytes([s[0], s[1], s[2], 0]) as usize;
        assert_eq!(n, s.len() - 4);
        assert_eq!(s[4], 10, "protocolo 10");
        assert!(s.windows(6).any(|v| v == b"8.0.35"));
    }

    #[test]
    fn mysql_saca_usuario_y_base_del_saludo_del_cliente() {
        let mut c = vec![0u8; 32];
        c.extend_from_slice(b"svc_facturacion\0");
        c.push(20); // largo de la respuesta de autenticacion
        c.extend_from_slice(&[0xAB; 20]);
        c.extend_from_slice(b"contabilidad\0");
        let paquete = con_cabecera_mysql(&c, 1);

        assert_eq!(
            Mysql::usuario_y_base(&paquete),
            Some(("svc_facturacion".to_owned(), "contabilidad".to_owned()))
        );
        let mut m = Mysql::nuevo();
        m.saludo();
        let p = m.turno(&paquete);
        assert!(p.cierra());
        assert!(String::from_utf8_lossy(p.bytes()).contains("Access denied"));
        assert!(m
            .revelado()
            .iter()
            .any(|r| r.frase().contains("contabilidad")));
    }

    #[test]
    fn mysql_no_se_sale_con_un_saludo_recortado() {
        let mut c = vec![0u8; 32];
        c.extend_from_slice(b"root\0");
        c.push(200); // dice 200 bytes de autenticacion que no estan
        let paquete = con_cabecera_mysql(&c, 1);
        assert!(Mysql::usuario_y_base(&paquete).is_none());
        for n in 0..paquete.len() {
            let _ = Mysql::usuario_y_base(&paquete[..n]);
        }
    }

    #[test]
    fn postgres_saca_usuario_base_y_herramienta() {
        let mut cuerpo = Vec::new();
        cuerpo.extend_from_slice(&196_608u32.to_be_bytes());
        for (k, v) in [
            ("user", "svc_informes"),
            ("database", "crm"),
            ("application_name", "sqlmap"),
        ] {
            cuerpo.extend_from_slice(k.as_bytes());
            cuerpo.push(0);
            cuerpo.extend_from_slice(v.as_bytes());
            cuerpo.push(0);
        }
        cuerpo.push(0);
        let mut m = ((cuerpo.len() + 4) as u32).to_be_bytes().to_vec();
        m.extend_from_slice(&cuerpo);

        let mut p = Postgres::nuevo();
        let paso = p.turno(&m);
        assert!(paso.cierra());
        let s = String::from_utf8_lossy(paso.bytes()).to_string();
        assert!(s.contains("svc_informes"), "{s}");
        assert!(p.revelado().iter().any(|r| r.frase().contains("sqlmap")));
        assert!(p.revelado().iter().any(|r| r.frase().contains("crm")));
    }

    #[test]
    fn postgres_contesta_que_no_al_sslrequest() {
        let mut m = 8u32.to_be_bytes().to_vec();
        m.extend_from_slice(&80_877_103u32.to_be_bytes());
        let mut p = Postgres::nuevo();
        assert_eq!(p.turno(&m).bytes(), b"N");
    }

    #[test]
    fn mssql_deshace_el_ofuscado_de_la_contrasena() {
        // Se ofusca «Verano2024» con el mismo algoritmo y se comprueba la vuelta.
        let claro = "Verano2024";
        let u: Vec<u8> = claro.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let ofuscada: Vec<u8> = u.iter().map(|b| b.rotate_left(4) ^ 0xA5).collect();
        assert_eq!(Mssql::clave_en_claro(&ofuscada), claro);
    }

    /// Construye un `LOGIN7` con los CINCO campos variables en su sitio, cada uno
    /// con un texto distinto.
    ///
    /// Que los cinco lleven texto distinto es lo que hace que la prueba sirva: la
    /// version anterior solo colocaba usuario y clave, y los colocaba en los
    /// mismos desplazamientos equivocados que leia el codigo, asi que pasaba
    /// comprobando que el codigo coincide consigo mismo. Con los cinco puestos
    /// segun la norma, leer el que no es devuelve otro texto y la prueba se cae.
    fn login7(maquina: &str, usuario: &str, clave: &str, app: &str, servidor: &str) -> Vec<u8> {
        let u16le = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let ofuscar =
            |s: &str| -> Vec<u8> { u16le(s).iter().map(|b| b.rotate_left(4) ^ 0xA5).collect() };

        // La parte fija del LOGIN7 llega hasta el byte 94; los campos variables van
        // detras, y cada par (desplazamiento, longitud en CARACTERES) apunta ahi.
        let mut cuerpo = vec![0u8; 94];
        let mut datos = Vec::new();
        let poner =
            |cuerpo: &mut Vec<u8>, datos: &mut Vec<u8>, desp: usize, bytes: &[u8], chars: usize| {
                let off = (94 + datos.len()) as u16;
                cuerpo[desp..desp + 2].copy_from_slice(&off.to_le_bytes());
                cuerpo[desp + 2..desp + 4].copy_from_slice(&(chars as u16).to_le_bytes());
                datos.extend_from_slice(bytes);
            };
        poner(
            &mut cuerpo,
            &mut datos,
            IB_HOST_NAME,
            &u16le(maquina),
            maquina.chars().count(),
        );
        poner(
            &mut cuerpo,
            &mut datos,
            IB_USER_NAME,
            &u16le(usuario),
            usuario.chars().count(),
        );
        poner(
            &mut cuerpo,
            &mut datos,
            IB_PASSWORD,
            &ofuscar(clave),
            clave.chars().count(),
        );
        poner(
            &mut cuerpo,
            &mut datos,
            IB_APP_NAME,
            &u16le(app),
            app.chars().count(),
        );
        poner(
            &mut cuerpo,
            &mut datos,
            IB_SERVER_NAME,
            &u16le(servidor),
            servidor.chars().count(),
        );
        cuerpo.extend_from_slice(&datos);

        let mut paquete = vec![0x10, 0x01];
        paquete.extend_from_slice(&((cuerpo.len() + 8) as u16).to_be_bytes());
        paquete.extend_from_slice(&[0, 0, 1, 0]);
        paquete.extend_from_slice(&cuerpo);
        paquete
    }

    #[test]
    fn mssql_saca_usuario_y_clave_del_login7() {
        // Los cinco campos, cada uno distinto. Si el parser leyera `ibAppName`
        // creyendo que es el usuario —que es lo que hacia—, aqui saldria
        // «sqlmap» en vez de «sa» y esto se caeria.
        let paquete = login7(
            "PORTATIL-07",
            "sa",
            "Admin!2024",
            "sqlmap",
            "SQL-CONTABILIDAD",
        );

        assert_eq!(
            Mssql::usuario_y_clave(&paquete),
            Some(("sa".to_owned(), "Admin!2024".to_owned())),
            "los desplazamientos del LOGIN7 no son los de la norma"
        );
        assert_eq!(
            Mssql::maquina_app_y_servidor(&paquete),
            Some((
                "PORTATIL-07".to_owned(),
                "sqlmap".to_owned(),
                "SQL-CONTABILIDAD".to_owned()
            ))
        );

        let mut m = Mssql::nuevo();
        let p = m.turno(&paquete);
        assert!(p.cierra());
        let frases: Vec<String> = m.revelado().iter().map(Revelacion::frase).collect();
        assert!(
            frases
                .iter()
                .any(|f| f.contains("sa") && f.contains("Admin!2024")),
            "{frases:?}"
        );
        assert!(frases.iter().any(|f| f.contains("sqlmap")), "{frases:?}");
        assert!(
            frases.iter().any(|f| f.contains("SQL-CONTABILIDAD")),
            "{frases:?}"
        );
    }

    #[test]
    fn los_cinco_campos_del_login7_no_se_confunden_entre_si() {
        // La comprobacion que la version anterior no podia hacer: se mueve UN campo
        // y solo cambia lo que ese campo aporta. Si dos lecturas compartieran
        // desplazamiento, cambiar uno movería el otro.
        let base = login7(
            "M",
            "usuario-real",
            "clave-real",
            "app-real",
            "servidor-real",
        );
        let (u, c) = Mssql::usuario_y_clave(&base).unwrap();
        let (_, a, sv) = Mssql::maquina_app_y_servidor(&base).unwrap();
        assert_eq!(u, "usuario-real");
        assert_eq!(c, "clave-real");
        assert_eq!(a, "app-real");
        assert_eq!(sv, "servidor-real");

        let cambiado = login7("M", "OTRO", "clave-real", "app-real", "servidor-real");
        let (u2, c2) = Mssql::usuario_y_clave(&cambiado).unwrap();
        let (_, a2, sv2) = Mssql::maquina_app_y_servidor(&cambiado).unwrap();
        assert_eq!(u2, "OTRO", "el usuario no salio del campo del usuario");
        assert_eq!(c2, "clave-real", "cambiar el usuario movio la clave");
        assert_eq!(a2, "app-real", "cambiar el usuario movio la aplicacion");
        assert_eq!(sv2, "servidor-real");
    }

    #[test]
    fn mssql_no_se_cree_los_desplazamientos_del_login7() {
        let mut cuerpo = vec![0u8; 94];
        cuerpo[48..50].copy_from_slice(&0xfffeu16.to_le_bytes());
        cuerpo[50..52].copy_from_slice(&0x7fffu16.to_le_bytes());
        let mut paquete = vec![0x10, 0x01];
        paquete.extend_from_slice(&((cuerpo.len() + 8) as u16).to_be_bytes());
        paquete.extend_from_slice(&[0, 0, 1, 0]);
        paquete.extend_from_slice(&cuerpo);
        assert!(Mssql::usuario_y_clave(&paquete).is_none());
    }

    #[test]
    fn redis_entiende_resp_y_la_forma_en_linea() {
        assert_eq!(
            Redis::trocear(b"*2\r\n$3\r\nGET\r\n$5\r\nclave\r\n"),
            Some(vec!["GET".to_owned(), "clave".to_owned()])
        );
        assert_eq!(Redis::trocear(b"INFO\r\n"), Some(vec!["INFO".to_owned()]));
    }

    #[test]
    fn redis_marca_como_escritura_el_camino_conocido_a_ejecucion() {
        let mut r = Redis::nuevo();
        r.turno(b"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$8\r\n/root/.ssh\r\n");
        r.turno(b"*1\r\n$4\r\nSAVE\r\n");
        r.turno(b"*1\r\n$4\r\nINFO\r\n");
        let graves: Vec<_> = r.revelado().iter().filter(|x| x.es_grave()).collect();
        assert_eq!(graves.len(), 2, "{:?}", r.revelado());
        assert!(graves[0].frase().contains("CONFIG SET dir"));
    }

    #[test]
    fn redis_sirve_el_cebo_solo_si_lo_tiene() {
        let mut sin = Redis::nuevo();
        assert_eq!(sin.turno(b"GET x\r\n").bytes(), b"$-1\r\n");
        let mut con = Redis::con_cebo("AKIA0000MARCA".to_owned());
        let s = String::from_utf8_lossy(con.turno(b"GET x\r\n").bytes()).to_string();
        assert!(s.contains("AKIA0000MARCA"), "{s}");
    }

    #[test]
    fn redis_no_se_atraganta_con_un_resp_mentiroso() {
        assert!(Redis::trocear(b"*99999\r\n").is_none());
        assert!(Redis::trocear(b"*2\r\n$3\r\nGET\r\n").is_none());
        assert!(Redis::trocear(b"").is_none());
    }

    fn mensaje_mongo(mando: &str) -> Vec<u8> {
        let mut doc = vec![0u8; 4];
        doc.push(0x01);
        doc.extend_from_slice(mando.as_bytes());
        doc.push(0);
        doc.extend_from_slice(&1.0f64.to_le_bytes());
        doc.push(0);
        let n = doc.len() as u32;
        doc[..4].copy_from_slice(&n.to_le_bytes());

        let mut v = Vec::new();
        let total = 16 + 4 + 1 + doc.len();
        v.extend_from_slice(&(total as u32).to_le_bytes());
        v.extend_from_slice(&7u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&2013u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.push(0);
        v.extend_from_slice(&doc);
        v
    }

    #[test]
    fn mongo_distingue_consultar_de_modificar() {
        let mut m = Mongo::nuevo();
        m.turno(&mensaje_mongo("find"));
        m.turno(&mensaje_mongo("dropDatabase"));
        let graves: Vec<_> = m.revelado().iter().filter(|r| r.es_grave()).collect();
        assert_eq!(graves.len(), 1);
        assert!(graves[0].frase().contains("dropDatabase"));
    }

    #[test]
    fn mongo_contesta_un_op_msg_bien_medido() {
        let mut m = Mongo::nuevo();
        let p = m.turno(&mensaje_mongo("hello"));
        let v = p.bytes();
        let n = u32::from_le_bytes([v[0], v[1], v[2], v[3]]) as usize;
        assert_eq!(n, v.len(), "la longitud declarada es la real");
        assert_eq!(u32::from_le_bytes([v[12], v[13], v[14], v[15]]), 2013);
    }

    #[test]
    fn ninguna_base_se_rompe_con_entradas_recortadas() {
        // La comprobacion barata que atrapa los desbordamientos por un byte.
        let muestras: Vec<Vec<u8>> = vec![
            mensaje_mongo("find"),
            b"*2\r\n$3\r\nGET\r\n$1\r\na\r\n".to_vec(),
            Mysql::saludo_inicial(),
        ];
        for m in muestras {
            for n in 0..m.len() {
                let trozo = &m[..n];
                let _ = Mysql::nuevo().turno(trozo);
                let _ = Postgres::nuevo().turno(trozo);
                let _ = Mssql::nuevo().turno(trozo);
                let _ = Redis::nuevo().turno(trozo);
                let _ = Mongo::nuevo().turno(trozo);
            }
        }
    }
}
