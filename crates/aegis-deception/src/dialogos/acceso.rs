//! Senuelos de acceso remoto: SSH, Telnet, FTP, VNC, RDP y SMB.
//!
//! Son los seis puertos por los que se mueve lateralmente quien ya esta dentro, y
//! los seis entregan lo que mas vale —quien es el atacante y con que credenciales
//! viene— **antes** del primer byte de criptografia.

use crate::dialogo::{primeros, recortado, Dialogo, Paso, Revelacion, MAX_ESTADO};
use crate::limitador::Transporte;

/// Cuanto texto se guarda de un campo que escribe el visitante.
const MAX_CAMPO: usize = 256;

// ─────────────────────────────────────────────────────────────────────────────
// SSH
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de SSH.
///
/// # Hasta donde llega, y por que justo ahi
///
/// Hasta el `KEXINIT`, que es el segundo mensaje del protocolo y el ultimo que se
/// puede construir sin criptografia. Parece poco y es casi todo lo que hay que
/// saber: el cliente manda ahi **su lista completa de algoritmos** de intercambio
/// de claves, cifrado, MAC y compresion, en su orden de preferencia. Esa lista es
/// la huella HASSH, y distingue a OpenSSH de Paramiko, de libssh, de un escaner
/// de fuerza bruta y de una herramienta a medida **aunque todos mientan en el
/// banner**, que es lo primero que cambia quien quiere pasar desapercibido.
///
/// Despues se manda un `DISCONNECT` con «no matching key exchange method», que es
/// lo que un servidor de verdad contesta cuando no hay algoritmo en comun.
/// Fingirlo no es raro ni delata al senuelo: pasa a diario entre versiones
/// distintas.
#[derive(Debug, Default)]
pub struct Ssh {
    dicho: Vec<Revelacion>,
    fase: u8,
}

impl Ssh {
    /// Un senuelo de SSH nuevo.
    #[must_use]
    pub fn nuevo() -> Ssh {
        Ssh::default()
    }

    /// Construye un `KEXINIT` con listas de algoritmos creibles.
    ///
    /// La estructura es la del RFC 4253 seccion 7.1: longitud, relleno, codigo 20,
    /// dieciseis bytes de aleatorio, diez listas de nombres, una bandera y un
    /// reservado. Las listas son las de un OpenSSH 8.9 de verdad, porque un
    /// cliente que compare lo que recibe con lo que espera de la version anunciada
    /// notaria la diferencia.
    fn kexinit() -> Vec<u8> {
        const LISTAS: [&str; 10] = [
            "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,\
             diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256",
            "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
            "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,\
             aes128-gcm@openssh.com,aes256-gcm@openssh.com",
            "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,\
             aes128-gcm@openssh.com,aes256-gcm@openssh.com",
            "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
            "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
            "none,zlib@openssh.com",
            "none,zlib@openssh.com",
            "",
            "",
        ];
        let mut cuerpo = Vec::new();
        cuerpo.push(20u8); // SSH_MSG_KEXINIT
        cuerpo.extend_from_slice(&[0x5a; 16]); // cookie
        for l in LISTAS {
            cuerpo.extend_from_slice(&(l.len() as u32).to_be_bytes());
            cuerpo.extend_from_slice(l.as_bytes());
        }
        cuerpo.push(0); // first_kex_packet_follows
        cuerpo.extend_from_slice(&0u32.to_be_bytes()); // reservado
        empaquetar_ssh(&cuerpo)
    }

    /// `SSH_MSG_DISCONNECT` con el motivo 2 (protocolo) y un texto creible.
    fn desconectar() -> Vec<u8> {
        let texto = "no matching key exchange method found";
        let mut cuerpo = Vec::new();
        cuerpo.push(1u8); // SSH_MSG_DISCONNECT
        cuerpo.extend_from_slice(&2u32.to_be_bytes());
        cuerpo.extend_from_slice(&(texto.len() as u32).to_be_bytes());
        cuerpo.extend_from_slice(texto.as_bytes());
        cuerpo.extend_from_slice(&0u32.to_be_bytes()); // etiqueta de idioma
        empaquetar_ssh(&cuerpo)
    }

    /// Saca las listas de algoritmos de un `KEXINIT` del cliente.
    ///
    /// Es la huella: se devuelven las cuatro que la forman (intercambio, clave de
    /// host, cifrado cliente-servidor y MAC cliente-servidor).
    fn huella(datos: &[u8]) -> Option<String> {
        // 4 de longitud, 1 de relleno, 1 de codigo, 16 de cookie.
        if datos.len() < 22 || datos[5] != 20 {
            return None;
        }
        let mut i = 22usize;
        let mut listas = Vec::new();
        for _ in 0..4 {
            if i + 4 > datos.len() {
                return None;
            }
            let n =
                u32::from_be_bytes([datos[i], datos[i + 1], datos[i + 2], datos[i + 3]]) as usize;
            i += 4;
            // El largo lo escribe el visitante: sin esta comprobacion, un `KEXINIT`
            // que anuncie cuatro gigabytes hace reservar cuatro gigabytes.
            if n > MAX_CAMPO || i + n > datos.len() {
                return None;
            }
            listas.push(String::from_utf8_lossy(&datos[i..i + n]).to_string());
            i += n;
        }
        Some(listas.join(";"))
    }
}

/// Envuelve un cuerpo en el marco binario de SSH (RFC 4253, seccion 6).
fn empaquetar_ssh(cuerpo: &[u8]) -> Vec<u8> {
    // El bloque es de 8 y el relleno minimo de 4, contando el byte de relleno.
    let sin_relleno = cuerpo.len() + 5;
    let relleno = (8 - (sin_relleno % 8)) % 8;
    let relleno = if relleno < 4 { relleno + 8 } else { relleno };
    let largo = cuerpo.len() + relleno + 1;
    let mut v = Vec::with_capacity(largo + 4);
    v.extend_from_slice(&(largo as u32).to_be_bytes());
    v.push(relleno as u8);
    v.extend_from_slice(cuerpo);
    v.extend(std::iter::repeat_n(0u8, relleno));
    v
}

impl Dialogo for Ssh {
    fn servicio(&self) -> &'static str {
        "ssh"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn saludo(&mut self) -> Option<Vec<u8>> {
        Some(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n".to_vec())
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        match self.fase {
            0 => {
                // El cliente manda su cadena de version.
                if !entrada.starts_with(b"SSH-") {
                    // Un cliente que no empieza por «SSH-» no habla SSH. Un
                    // servidor real corta, y cortar es lo que hace creible que
                    // esto sea un servidor real.
                    return Paso::Cierra;
                }
                self.fase = 1;
                self.dicho.push(Revelacion::Herramienta {
                    texto: recortado(entrada, MAX_CAMPO),
                });
                Paso::Responde(Ssh::kexinit())
            }
            1 => {
                self.fase = 2;
                if let Some(h) = Ssh::huella(entrada) {
                    self.dicho.push(texto_huella(&h));
                }
                Paso::RespondeYCierra(Ssh::desconectar())
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

/// La huella, nombrada para que en la alerta se lea lo que es.
fn texto_huella(h: &str) -> Revelacion {
    Revelacion::Peticion {
        que: format!("huella de algoritmos (HASSH): {h}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Telnet
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de Telnet.
///
/// Acepta la sesion a la **tercera** credencial. Aceptar a la primera levanta
/// sospechas —nadie acierta siempre— y no aceptar nunca pierde lo que el atacante
/// hace cuando cree haber entrado, que es la mitad del valor. Tres es lo que hace
/// un sistema descuidado de verdad.
#[derive(Debug, Default)]
pub struct Telnet {
    dicho: Vec<Revelacion>,
    usuario: String,
    esperando_clave: bool,
    intentos: u8,
    dentro: bool,
}

impl Telnet {
    /// Un senuelo de Telnet nuevo.
    #[must_use]
    pub fn nuevo() -> Telnet {
        Telnet::default()
    }
}

/// El listado que devuelve un `ls` dentro del senuelo.
///
/// Es una constante. No hay directorio detras, no se lee el disco y no se ejecuta
/// nada: quien pida `ls` recibe este texto y ya.
const LISTADO: &str = "backup.sh  clientes.sql  credenciales.txt  docker-compose.yml  logs\n";

impl Dialogo for Telnet {
    fn servicio(&self) -> &'static str {
        "telnet"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn saludo(&mut self) -> Option<Vec<u8>> {
        // Negociacion minima (IAC DO/WILL) y el aviso de siempre.
        let mut v = vec![
            0xff, 0xfd, 0x18, 0xff, 0xfd, 0x20, 0xff, 0xfd, 0x23, 0xff, 0xfd, 0x27,
        ];
        v.extend_from_slice(b"\r\nUbuntu 22.04.3 LTS\r\nlogin: ");
        Some(v)
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        // Los mandos de negociacion se descartan sin contarlos como turno util.
        let limpio: Vec<u8> = sin_iac(entrada);
        let texto = recortado(&limpio, MAX_CAMPO);

        if self.dentro {
            let orden = texto.trim();
            self.dicho.push(Revelacion::Peticion {
                que: format!("orden en la sesion: {orden}"),
            });
            let salida = match orden.split_whitespace().next().unwrap_or("") {
                "ls" | "dir" => LISTADO.to_owned(),
                "id" => "uid=0(root) gid=0(root) groups=0(root)\n".to_owned(),
                "uname" => "Linux pasarela-01 5.15.0-91-generic x86_64 GNU/Linux\n".to_owned(),
                "pwd" => "/root\n".to_owned(),
                "exit" | "logout" => return Paso::RespondeYCierra(b"logout\r\n".to_vec()),
                "" => String::new(),
                otra => format!("-bash: {otra}: command not found\n"),
            };
            return Paso::Responde(format!("{salida}root@pasarela-01:~# ").into_bytes());
        }

        if self.esperando_clave {
            self.esperando_clave = false;
            self.intentos += 1;
            self.dicho.push(Revelacion::Credencial {
                usuario: std::mem::take(&mut self.usuario),
                clave: texto,
            });
            if self.intentos >= 3 {
                self.dentro = true;
                return Paso::Responde(
                    b"\r\nWelcome to Ubuntu 22.04.3 LTS\r\nroot@pasarela-01:~# ".to_vec(),
                );
            }
            return Paso::Responde(b"\r\nLogin incorrect\r\nlogin: ".to_vec());
        }

        self.usuario = texto;
        self.esperando_clave = true;
        Paso::Responde(b"Password: ".to_vec())
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.usuario.len() + self.dicho.iter().map(tam_revelacion).sum::<usize>()
    }
}

/// Quita los mandos de Telnet (IAC = 255) para quedarse con el texto.
fn sin_iac(datos: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(datos.len());
    let mut i = 0;
    while i < datos.len() {
        if datos[i] == 0xff {
            // IAC + mando (+ opcion). Se salta lo que haya, sin salirse.
            i += if i + 1 < datos.len() && (251..=254).contains(&datos[i + 1]) {
                3
            } else {
                2
            };
            continue;
        }
        v.push(datos[i]);
        i += 1;
    }
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// FTP
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de FTP.
///
/// Acepta el acceso y sirve un listado con nombres que invitan a llevarselos. Es
/// el senuelo mas barato de todos y sigue siendo de los mas productivos: quien
/// entra por FTP casi siempre pide el listado y despues un fichero concreto, y
/// **cual pide** dice lo que venia buscando.
#[derive(Debug, Default)]
pub struct Ftp {
    dicho: Vec<Revelacion>,
    usuario: String,
}

impl Ftp {
    /// Un senuelo de FTP nuevo.
    #[must_use]
    pub fn nuevo() -> Ftp {
        Ftp::default()
    }
}

impl Dialogo for Ftp {
    fn servicio(&self) -> &'static str {
        "ftp"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn saludo(&mut self) -> Option<Vec<u8>> {
        Some(b"220 (vsFTPd 3.0.5)\r\n".to_vec())
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        let linea = recortado(entrada, MAX_CAMPO);
        let (orden, arg) = match linea.split_once(' ') {
            Some((o, a)) => (o.to_ascii_uppercase(), a.trim().to_owned()),
            None => (linea.trim().to_ascii_uppercase(), String::new()),
        };
        match orden.as_str() {
            "USER" => {
                self.usuario = arg;
                Paso::Responde(b"331 Please specify the password.\r\n".to_vec())
            }
            "PASS" => {
                self.dicho.push(Revelacion::Credencial {
                    usuario: std::mem::take(&mut self.usuario),
                    clave: arg,
                });
                Paso::Responde(b"230 Login successful.\r\n".to_vec())
            }
            "SYST" => Paso::Responde(b"215 UNIX Type: L8\r\n".to_vec()),
            "PWD" => Paso::Responde(b"257 \"/\" is the current directory\r\n".to_vec()),
            "TYPE" => Paso::Responde(b"200 Switching to Binary mode.\r\n".to_vec()),
            "PASV" | "EPSV" => {
                self.dicho.push(Revelacion::Peticion {
                    que: "pidio modo pasivo para abrir un canal de datos".to_owned(),
                });
                // No se abre canal de datos: abrir un puerto porque lo pida quien
                // esta al otro lado es dejarle elegir recursos del agente.
                Paso::Responde(b"425 Use PORT or PASV first.\r\n".to_vec())
            }
            "LIST" | "NLST" => {
                self.dicho.push(Revelacion::Peticion {
                    que: format!("listado de «{}»", if arg.is_empty() { "/" } else { &arg }),
                });
                Paso::Responde(b"425 Use PORT or PASV first.\r\n".to_vec())
            }
            "RETR" => {
                self.dicho.push(Revelacion::Peticion {
                    que: format!("descargar «{arg}»"),
                });
                Paso::Responde(b"425 Use PORT or PASV first.\r\n".to_vec())
            }
            "STOR" => {
                // Subir un fichero es intentar dejar algo en la maquina. No es
                // una peticion mas: es el paso a la persistencia.
                self.dicho.push(Revelacion::OrdenDeEscritura {
                    que: format!("subir «{arg}»"),
                });
                Paso::Responde(b"425 Use PORT or PASV first.\r\n".to_vec())
            }
            "QUIT" => Paso::RespondeYCierra(b"221 Goodbye.\r\n".to_vec()),
            "" => Paso::Cierra,
            otra => Paso::Responde(
                format!("500 Unknown command: {}\r\n", primeros(otra, 16)).into_bytes(),
            ),
        }
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.usuario.len() + self.dicho.iter().map(tam_revelacion).sum::<usize>()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VNC
// ─────────────────────────────────────────────────────────────────────────────

/// El reto de autenticacion de VNC, **fijo y conocido**.
///
/// Que sea fijo es deliberado y es lo que da el valor: VNC cifra el reto con la
/// contrasena como clave DES. Con el reto conocido y la respuesta capturada, la
/// contrasena que probaron se recupera despues, sin prisa y sin el atacante
/// delante. Un reto aleatorio serviria igual para autenticar —que aqui no importa,
/// porque no se autentica a nadie— y perderia esa posibilidad.
pub const RETO_VNC: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

/// Senuelo de VNC (RFB).
#[derive(Debug, Default)]
pub struct Vnc {
    dicho: Vec<Revelacion>,
    fase: u8,
}

impl Vnc {
    /// Un senuelo de VNC nuevo.
    #[must_use]
    pub fn nuevo() -> Vnc {
        Vnc::default()
    }
}

impl Dialogo for Vnc {
    fn servicio(&self) -> &'static str {
        "vnc"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn saludo(&mut self) -> Option<Vec<u8>> {
        Some(b"RFB 003.008\n".to_vec())
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        match self.fase {
            0 => {
                if !entrada.starts_with(b"RFB ") {
                    return Paso::Cierra;
                }
                self.dicho.push(Revelacion::Herramienta {
                    texto: recortado(entrada, 12),
                });
                self.fase = 1;
                // Un tipo de seguridad disponible: 2 = autenticacion VNC.
                Paso::Responde(vec![1, 2])
            }
            1 => {
                // El cliente elige el tipo; se le manda el reto.
                self.fase = 2;
                Paso::Responde(RETO_VNC.to_vec())
            }
            2 => {
                self.fase = 3;
                if entrada.len() >= 16 {
                    let hex: String = entrada[..16].iter().map(|b| format!("{b:02x}")).collect();
                    self.dicho.push(Revelacion::Credencial {
                        usuario: "(vnc no lleva usuario)".to_owned(),
                        clave: format!("respuesta al reto fijo: {hex}"),
                    });
                }
                // 1 = fallo, y el motivo, como hace un servidor de verdad.
                let motivo = b"Authentication failure";
                let mut v = vec![0, 0, 0, 1];
                v.extend_from_slice(&(motivo.len() as u32).to_be_bytes());
                v.extend_from_slice(motivo);
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
// RDP
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de RDP.
///
/// # La cookie que nadie mira
///
/// La primerisima peticion de RDP —una `Connection Request` de X.224— lleva, casi
/// siempre, una linea `Cookie: mstshash=USUARIO`. La mete el cliente de Windows
/// solo, con el nombre de usuario que se va a usar, **antes de cualquier cifrado**.
/// Un senuelo de RDP que solo cuente conexiones esta tirando a la basura el
/// nombre de la cuenta que el atacante cree tener.
#[derive(Debug, Default)]
pub struct Rdp {
    dicho: Vec<Revelacion>,
}

impl Rdp {
    /// Un senuelo de RDP nuevo.
    #[must_use]
    pub fn nuevo() -> Rdp {
        Rdp::default()
    }

    /// Saca el usuario de la cookie `mstshash`, si viene.
    #[must_use]
    pub fn usuario_de_la_cookie(datos: &[u8]) -> Option<String> {
        const MARCA: &[u8] = b"mstshash=";
        let i = datos.windows(MARCA.len()).position(|v| v == MARCA)? + MARCA.len();
        let resto = &datos[i..];
        let fin = resto
            .iter()
            .position(|&b| b == b'\r' || b == b'\n' || b == 0)
            .unwrap_or(resto.len());
        Some(recortado(&resto[..fin.min(MAX_CAMPO)], MAX_CAMPO))
    }
}

impl Dialogo for Rdp {
    fn servicio(&self) -> &'static str {
        "rdp"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        // TPKT: version 3, reservado, longitud de 16 bits.
        if entrada.len() < 11 || entrada[0] != 3 {
            return Paso::Cierra;
        }
        if let Some(u) = Rdp::usuario_de_la_cookie(entrada) {
            self.dicho.push(Revelacion::Credencial {
                usuario: u,
                clave: "(rdp no manda la clave en claro)".to_owned(),
            });
        }
        // Connection Confirm con RDP_NEG_RSP: se acepta TLS, que es lo que
        // anuncia un Windows moderno. El cliente vendra con un saludo TLS, y ahi
        // se acaba lo que se puede fingir sin un certificado y sin criptografia.
        let mut v = vec![
            0x03, 0x00, 0x00, 0x13, // TPKT, 19 bytes
            0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, // X.224 Connection Confirm
        ];
        v.extend_from_slice(&[
            0x02, // RDP_NEG_RSP
            0x00, // banderas
            0x08, 0x00, // longitud
            0x01, 0x00, 0x00, 0x00, // PROTOCOL_SSL
        ]);
        self.dicho.push(Revelacion::Herramienta {
            texto: "cliente RDP: pidio negociacion X.224".to_owned(),
        });
        Paso::RespondeYCierra(v)
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.dicho.iter().map(tam_revelacion).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SMB
// ─────────────────────────────────────────────────────────────────────────────

/// El reto NTLM, **fijo y conocido**, por lo mismo que el de VNC.
pub const RETO_NTLM: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

/// Senuelo de SMB.
///
/// # Lo que entrega, que es lo mas valioso de la fase
///
/// SMB autentica con NTLMSSP, y el tercer mensaje —`AUTHENTICATE`— lleva el
/// **dominio, el nombre de usuario, el nombre de la maquina** y la respuesta
/// NTLMv2 al reto que mando el servidor. Con el reto fijo y conocido, esa
/// respuesta se puede trabajar despues sin el atacante delante.
///
/// No es una tecnica exotica: es exactamente lo que hace una herramienta de
/// recogida de credenciales en una red, con la diferencia de que aqui **la
/// maquina que la corre es la nuestra y quien se identifica es el intruso**.
#[derive(Debug, Default)]
pub struct Smb {
    dicho: Vec<Revelacion>,
    negociado: bool,
}

impl Smb {
    /// Un senuelo de SMB nuevo.
    #[must_use]
    pub fn nuevo() -> Smb {
        Smb::default()
    }

    /// Saca dominio, usuario y maquina de un `NTLMSSP_AUTHENTICATE`.
    ///
    /// Los campos vienen como (longitud, longitud maxima, desplazamiento) de 16,
    /// 16 y 32 bits, y el texto es UTF-16 en minusculas y mayusculas mezcladas.
    /// **Los tres numeros los escribe el visitante**, asi que cada uno se
    /// comprueba contra el tamano real antes de tocar nada.
    #[must_use]
    pub fn campos_ntlm(datos: &[u8]) -> Option<(String, String, String)> {
        let i = posicion(datos, b"NTLMSSP\0")?;
        let m = &datos[i..];
        if m.len() < 64 || m[8] != 3 {
            return None;
        }
        let campo = |desp: usize| -> String {
            if desp + 8 > m.len() {
                return String::new();
            }
            let largo = u16::from_le_bytes([m[desp], m[desp + 1]]) as usize;
            let off =
                u32::from_le_bytes([m[desp + 4], m[desp + 5], m[desp + 6], m[desp + 7]]) as usize;
            if largo == 0 || largo > MAX_CAMPO * 2 || off + largo > m.len() {
                return String::new();
            }
            de_utf16(&m[off..off + largo])
        };
        // 28: dominio, 36: usuario, 44: maquina.
        Some((campo(28), campo(36), campo(44)))
    }
}

/// UTF-16 en little-endian a texto, sin panico con un byte suelto al final.
fn de_utf16(b: &[u8]) -> String {
    let u: Vec<u16> = b
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    String::from_utf16_lossy(&u)
}

/// Donde empieza `aguja` dentro de `pajar`.
fn posicion(pajar: &[u8], aguja: &[u8]) -> Option<usize> {
    if aguja.is_empty() || pajar.len() < aguja.len() {
        return None;
    }
    pajar.windows(aguja.len()).position(|v| v == aguja)
}

impl Dialogo for Smb {
    fn servicio(&self) -> &'static str {
        "smb"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        // NetBIOS de 4 bytes y despues `\xfeSMB` (SMB2) o `\xffSMB` (SMB1).
        let smb = if entrada.len() > 8 && &entrada[4..8] == b"\xfeSMB" {
            2
        } else if entrada.len() > 8 && &entrada[4..8] == b"\xffSMB" {
            1
        } else {
            return Paso::Cierra;
        };

        if let Some((dominio, usuario, maquina)) = Smb::campos_ntlm(entrada) {
            if !usuario.is_empty() {
                self.dicho.push(Revelacion::Credencial {
                    usuario: format!("{dominio}\\{usuario}"),
                    clave: format!("NTLMv2 contra el reto fijo, desde la maquina «{maquina}»"),
                });
                return Paso::RespondeYCierra(respuesta_smb2(0xC000006D)); // LOGON_FAILURE
            }
        }

        if !self.negociado {
            self.negociado = true;
            self.dicho.push(Revelacion::Herramienta {
                texto: format!("cliente SMB{smb}"),
            });
            return Paso::Responde(respuesta_smb2(0));
        }

        // Session setup: se contesta con el reto NTLM para que el cliente mande
        // el AUTHENTICATE, que es lo que se viene a buscar.
        self.dicho.push(Revelacion::Peticion {
            que: "inicio de sesion SMB".to_owned(),
        });
        Paso::Responde(reto_ntlm_smb2())
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.dicho.iter().map(tam_revelacion).sum()
    }
}

/// Una cabecera SMB2 de respuesta con el estado dado.
fn respuesta_smb2(estado: u32) -> Vec<u8> {
    let mut c = Vec::with_capacity(4 + 64);
    c.extend_from_slice(b"\xfeSMB");
    c.extend_from_slice(&64u16.to_le_bytes()); // tamano de estructura
    c.extend_from_slice(&0u16.to_le_bytes()); // credit charge
    c.extend_from_slice(&estado.to_le_bytes());
    c.extend_from_slice(&0u16.to_le_bytes()); // orden
    c.extend_from_slice(&1u16.to_le_bytes()); // creditos
    c.extend_from_slice(&1u32.to_le_bytes()); // banderas: respuesta
    c.extend_from_slice(&0u32.to_le_bytes()); // siguiente
    c.extend_from_slice(&0u64.to_le_bytes()); // id de mensaje
    c.extend_from_slice(&0u32.to_le_bytes()); // reservado
    c.extend_from_slice(&0u32.to_le_bytes()); // arbol
    c.extend_from_slice(&0u64.to_le_bytes()); // sesion
    c.extend_from_slice(&[0u8; 16]); // firma
    con_netbios(&c)
}

/// Un `SESSION_SETUP` de respuesta que lleva el reto NTLM.
fn reto_ntlm_smb2() -> Vec<u8> {
    let mut ntlm = Vec::new();
    ntlm.extend_from_slice(b"NTLMSSP\0");
    ntlm.extend_from_slice(&2u32.to_le_bytes()); // CHALLENGE
    ntlm.extend_from_slice(&[0u8; 8]); // nombre de destino (vacio)
    ntlm.extend_from_slice(&0x0281_0205u32.to_le_bytes()); // banderas
    ntlm.extend_from_slice(&RETO_NTLM);
    ntlm.extend_from_slice(&[0u8; 8]); // reservado
    ntlm.extend_from_slice(&[0u8; 8]); // informacion de destino (vacia)

    let mut v = respuesta_smb2(0xC000_0016); // MORE_PROCESSING_REQUIRED
                                             // Se quita el NetBIOS para reescribirlo con el cuerpo dentro.
    let cabecera = v.split_off(4);
    let mut c = cabecera;
    c.extend_from_slice(&9u16.to_le_bytes()); // tamano de estructura
    c.extend_from_slice(&0u16.to_le_bytes()); // banderas de sesion
    c.extend_from_slice(&72u16.to_le_bytes()); // desplazamiento del blob
    c.extend_from_slice(&(ntlm.len() as u16).to_le_bytes());
    c.extend_from_slice(&ntlm);
    con_netbios(&c)
}

/// Antepone la cabecera de sesion NetBIOS de cuatro bytes.
fn con_netbios(cuerpo: &[u8]) -> Vec<u8> {
    let n = cuerpo.len() as u32;
    let mut v = Vec::with_capacity(4 + cuerpo.len());
    v.push(0);
    v.extend_from_slice(&n.to_be_bytes()[1..]);
    v.extend_from_slice(cuerpo);
    v
}

/// Cuanto ocupa una revelacion guardada.
pub(crate) fn tam_revelacion(r: &Revelacion) -> usize {
    match r {
        Revelacion::Herramienta { texto } => texto.len(),
        Revelacion::Credencial { usuario, clave } => usuario.len() + clave.len(),
        Revelacion::Peticion { que } | Revelacion::OrdenDeEscritura { que } => que.len(),
    }
}

/// El techo de estado que ningun dialogo puede pasar.
const _: () = assert!(MAX_CAMPO * 4 <= MAX_ESTADO);

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_marco_de_ssh_cumple_el_relleno_del_rfc() {
        for n in 0..200usize {
            let p = empaquetar_ssh(&vec![0u8; n]);
            let largo = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize;
            assert_eq!(largo + 4, p.len(), "la longitud declarada es la real");
            let relleno = p[4] as usize;
            assert!(relleno >= 4, "el RFC exige al menos cuatro de relleno");
            assert_eq!((largo + 4) % 8, 0, "el paquete es multiplo del bloque");
        }
    }

    #[test]
    fn ssh_saca_la_huella_de_algoritmos() {
        let mut s = Ssh::nuevo();
        assert!(s.saludo().is_some());
        let p = s.turno(b"SSH-2.0-PUTTY_Release_0.78\r\n");
        assert!(!p.cierra());
        // Y ahora un KEXINIT del cliente.
        let kex = Ssh::kexinit();
        let p = s.turno(&kex);
        assert!(p.cierra());
        let huella = s
            .revelado()
            .iter()
            .find_map(|r| match r {
                Revelacion::Peticion { que } if que.contains("HASSH") => Some(que.clone()),
                _ => None,
            })
            .expect("tiene que haber huella");
        assert!(huella.contains("curve25519-sha256"));
        assert!(s.revelado().iter().any(|r| matches!(
            r,
            Revelacion::Herramienta { texto } if texto.contains("PUTTY")
        )));
    }

    #[test]
    fn ssh_no_reserva_lo_que_diga_un_kexinit_mentiroso() {
        // Longitud de campo enorme: si se creyera, se reservarian gigabytes.
        let mut datos = vec![0u8; 22];
        datos[5] = 20;
        datos.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(Ssh::huella(&datos).is_none());
    }

    #[test]
    fn telnet_se_queda_con_el_usuario_y_la_clave() {
        let mut t = Telnet::nuevo();
        t.saludo();
        t.turno(b"root\r\n");
        t.turno(b"admin123\r\n");
        let c = t
            .revelado()
            .iter()
            .find_map(|r| match r {
                Revelacion::Credencial { usuario, clave } => Some((usuario.clone(), clave.clone())),
                _ => None,
            })
            .expect("credencial capturada");
        assert_eq!(c, ("root".to_owned(), "admin123".to_owned()));
    }

    #[test]
    fn telnet_acepta_a_la_tercera_y_entonces_se_ve_que_hace() {
        let mut t = Telnet::nuevo();
        t.saludo();
        for clave in ["1234", "admin", "toor"] {
            t.turno(b"root\r\n");
            t.turno(clave.as_bytes());
        }
        let p = t.turno(b"ls\r\n");
        let salida = String::from_utf8_lossy(p.bytes()).to_string();
        assert!(salida.contains("clientes.sql"), "{salida}");
        assert!(t.revelado().iter().any(|r| matches!(
            r,
            Revelacion::Peticion { que } if que.contains("orden en la sesion: ls")
        )));
    }

    #[test]
    fn telnet_no_se_atraganta_con_los_mandos_iac() {
        assert_eq!(sin_iac(&[0xff, 0xfb, 0x01, b'h', b'i']), b"hi".to_vec());
        // Un IAC al final, sin lo que deberia venir detras, no se sale del vector.
        assert_eq!(sin_iac(&[b'a', 0xff]), b"a".to_vec());
        assert_eq!(sin_iac(&[b'a', 0xff, 0xfb]), b"a".to_vec());
    }

    #[test]
    fn ftp_distingue_bajar_de_subir() {
        let mut f = Ftp::nuevo();
        f.saludo();
        f.turno(b"USER anonymous\r\n");
        f.turno(b"PASS x@y.z\r\n");
        f.turno(b"RETR clientes.sql\r\n");
        f.turno(b"STOR puerta.php\r\n");
        let graves: Vec<_> = f.revelado().iter().filter(|r| r.es_grave()).collect();
        assert_eq!(graves.len(), 1, "solo subir es escribir");
        assert!(graves[0].frase().contains("puerta.php"));
    }

    #[test]
    fn vnc_guarda_la_respuesta_al_reto_conocido() {
        let mut v = Vnc::nuevo();
        v.saludo();
        v.turno(b"RFB 003.008\n");
        v.turno(&[2]);
        let p = v.turno(&[0xAA; 16]);
        assert!(p.cierra());
        assert!(v.revelado().iter().any(|r| matches!(
            r,
            Revelacion::Credencial { clave, .. } if clave.contains("aaaaaaaa")
        )));
    }

    #[test]
    fn rdp_saca_el_usuario_de_la_cookie() {
        let peticion =
            b"\x03\x00\x00\x2c\x27\xe0\x00\x00\x00\x00\x00Cookie: mstshash=ADMINISTRADOR\r\n";
        assert_eq!(
            Rdp::usuario_de_la_cookie(peticion).as_deref(),
            Some("ADMINISTRADOR")
        );
        let mut r = Rdp::nuevo();
        let p = r.turno(peticion);
        assert!(p.cierra());
        assert!(r.revelado().iter().any(|x| matches!(
            x,
            Revelacion::Credencial { usuario, .. } if usuario == "ADMINISTRADOR"
        )));
    }

    #[test]
    fn rdp_sin_cookie_no_inventa_usuario() {
        let mut r = Rdp::nuevo();
        r.turno(b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00");
        assert!(!r
            .revelado()
            .iter()
            .any(|x| matches!(x, Revelacion::Credencial { .. })));
    }

    #[test]
    fn smb_saca_usuario_y_dominio_del_authenticate() {
        // Un AUTHENTICATE minimo con los tres campos colocados.
        let dominio = "EMPRESA";
        let usuario = "admin.dominio";
        let maquina = "PORTATIL-07";
        let u16le = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let (d, u, m) = (u16le(dominio), u16le(usuario), u16le(maquina));

        let mut ntlm = vec![0u8; 64];
        ntlm[..8].copy_from_slice(b"NTLMSSP\0");
        ntlm[8] = 3;
        let mut off = 64u32;
        for (desp, campo) in [(28usize, &d), (36, &u), (44, &m)] {
            ntlm[desp..desp + 2].copy_from_slice(&(campo.len() as u16).to_le_bytes());
            ntlm[desp + 2..desp + 4].copy_from_slice(&(campo.len() as u16).to_le_bytes());
            ntlm[desp + 4..desp + 8].copy_from_slice(&off.to_le_bytes());
            off += campo.len() as u32;
        }
        ntlm.extend_from_slice(&d);
        ntlm.extend_from_slice(&u);
        ntlm.extend_from_slice(&m);

        let mut paquete = vec![0u8, 0, 1, 0];
        paquete.extend_from_slice(b"\xfeSMB");
        paquete.extend_from_slice(&[0u8; 60]);
        paquete.extend_from_slice(&ntlm);

        let sacado = Smb::campos_ntlm(&paquete).expect("los tres campos");
        assert_eq!(
            sacado,
            (dominio.to_owned(), usuario.to_owned(), maquina.to_owned())
        );

        let mut s = Smb::nuevo();
        let p = s.turno(&paquete);
        assert!(p.cierra());
        assert!(s.revelado().iter().any(|r| matches!(
            r,
            Revelacion::Credencial { usuario, .. } if usuario == "EMPRESA\\admin.dominio"
        )));
    }

    #[test]
    fn smb_no_se_cree_los_desplazamientos_que_le_manden() {
        // Un AUTHENTICATE que dice que su usuario esta en el byte cuatro mil
        // millones. Creerselo es salirse del vector.
        let mut ntlm = vec![0u8; 64];
        ntlm[..8].copy_from_slice(b"NTLMSSP\0");
        ntlm[8] = 3;
        ntlm[36..38].copy_from_slice(&64u16.to_le_bytes());
        ntlm[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut paquete = vec![0u8, 0, 1, 0];
        paquete.extend_from_slice(b"\xfeSMB");
        paquete.extend_from_slice(&[0u8; 60]);
        paquete.extend_from_slice(&ntlm);
        let (_, u, _) = Smb::campos_ntlm(&paquete).expect("no revienta");
        assert!(u.is_empty(), "un desplazamiento imposible no da texto");
    }

    #[test]
    fn el_reto_de_smb_va_dentro_de_un_marco_bien_medido() {
        let v = reto_ntlm_smb2();
        let n = u32::from_be_bytes([0, v[1], v[2], v[3]]) as usize;
        assert_eq!(n, v.len() - 4, "el NetBIOS declara el tamano real");
        assert!(posicion(&v, b"NTLMSSP\0").is_some());
        assert!(posicion(&v, &RETO_NTLM).is_some());
    }
}
