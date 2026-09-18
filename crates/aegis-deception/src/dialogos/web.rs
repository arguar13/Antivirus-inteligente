//! Senuelos de web: HTTP en claro y TLS.
//!
//! # Por que la web es el senuelo que mas rinde
//!
//! Porque es el unico puerto que esta abierto en todas partes, y porque quien
//! busca entrar prueba siempre las mismas rutas: `/.env`, `/.git/config`,
//! `/admin`, `/wp-login.php`, `/actuator/env`, `/api/v1/config`. **Que ruta pide
//! dice que exploit trae**, y la lista de rutas que prueba en orden identifica la
//! herramienta mejor que su agente de usuario, que se cambia con un parametro.

use crate::dialogo::{recortado, Dialogo, Paso, Revelacion};
use crate::dialogos::acceso::tam_revelacion;
use crate::limitador::Transporte;

/// Cuanto se guarda de un campo escrito por el visitante.
const MAX_CAMPO: usize = 256;

/// Cuanto se lee de una peticion, como mucho.
///
/// Ocho kilobytes es lo que aceptan los servidores de verdad en la linea de
/// peticion mas las cabeceras. Pasado eso, un servidor real contesta `431` y
/// corta, asi que cortar aqui no delata el senuelo: es lo que se espera.
const MAX_PETICION: usize = 8 * 1024;

/// Senuelo de HTTP.
#[derive(Debug, Default)]
pub struct Http {
    dicho: Vec<Revelacion>,
    /// Lo que se sirve en `/.env` y compania: se pone desde fuera para que lleve
    /// tokens atribuibles sembrados por [`crate::plantado`].
    cebo: String,
    peticiones: u32,
}

impl Http {
    /// Un senuelo de HTTP nuevo, sin cebo.
    #[must_use]
    pub fn nuevo() -> Http {
        Http::default()
    }

    /// Un senuelo que sirve `cebo` en las rutas de configuracion.
    ///
    /// El cebo es lo que convierte el senuelo en atribuible: quien se lleve ese
    /// texto se lleva un marcador que solo existe en ESTE senuelo, y cuando lo use
    /// se sabra por donde entro. Ver [`crate::plantado`].
    #[must_use]
    pub fn con_cebo(cebo: String) -> Http {
        Http {
            cebo,
            ..Http::default()
        }
    }

    /// Lo que se sirve, segun la ruta.
    fn cuerpo(&self, ruta: &str) -> (u16, &'static str, String) {
        match ruta {
            "/" | "/index.html" => (
                200,
                "text/html",
                "<!doctype html><html><head><title>Panel interno</title></head>\
                 <body><h1>Acceso restringido</h1><form method=post action=/login>\
                 <input name=usuario><input name=clave type=password>\
                 <button>Entrar</button></form></body></html>"
                    .to_owned(),
            ),
            "/.env" | "/api/v1/config" | "/actuator/env" | "/config.json" => {
                if self.cebo.is_empty() {
                    (404, "text/plain", "Not Found\n".to_owned())
                } else {
                    (200, "text/plain", self.cebo.clone())
                }
            }
            "/admin" | "/admin/" | "/wp-login.php" | "/phpmyadmin/" => (
                401,
                "text/html",
                "<html><body><h1>401 Unauthorized</h1></body></html>".to_owned(),
            ),
            "/server-status" => (403, "text/plain", "Forbidden\n".to_owned()),
            _ => (
                404,
                "text/html",
                "<html><body><h1>404 Not Found</h1></body></html>".to_owned(),
            ),
        }
    }
}

/// Saca el valor de una cabecera de una peticion HTTP, sin distinguir mayusculas.
#[must_use]
pub fn cabecera(peticion: &str, nombre: &str) -> Option<String> {
    for linea in peticion.lines().skip(1) {
        if linea.is_empty() {
            break;
        }
        let (n, v) = linea.split_once(':')?;
        if n.trim().eq_ignore_ascii_case(nombre) {
            return Some(v.trim().chars().take(MAX_CAMPO).collect());
        }
    }
    None
}

impl Dialogo for Http {
    fn servicio(&self) -> &'static str {
        "http"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        if entrada.len() > MAX_PETICION {
            return Paso::RespondeYCierra(
                b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            );
        }
        let texto = recortado(entrada, MAX_PETICION);
        let mut lineas = texto.lines();
        let primera = lineas.next().unwrap_or_default();
        let mut partes = primera.split_whitespace();
        let (metodo, ruta) = match (partes.next(), partes.next()) {
            (Some(m), Some(r)) => (m.to_owned(), r.chars().take(MAX_CAMPO).collect::<String>()),
            _ => return Paso::Cierra,
        };
        self.peticiones += 1;

        if let Some(ua) = cabecera(&texto, "user-agent") {
            if self.peticiones == 1 {
                self.dicho.push(Revelacion::Herramienta { texto: ua });
            }
        }
        // `Authorization` es la cabecera que trae las credenciales, tanto en
        // `Basic` (usuario y clave en base64, es decir, en claro) como en `Bearer`
        // (una ficha robada de otro sitio, que es aun mas interesante).
        if let Some(a) = cabecera(&texto, "authorization") {
            let (tipo, resto) = a.split_once(' ').unwrap_or((a.as_str(), ""));
            self.dicho.push(Revelacion::Credencial {
                usuario: format!("cabecera Authorization ({tipo})"),
                clave: resto.to_owned(),
            });
        }

        // Un metodo que modifica no es una peticion mas: es un intento de dejar
        // algo o de cambiar algo.
        let escribe = matches!(metodo.as_str(), "POST" | "PUT" | "DELETE" | "PATCH");
        let que = format!("{metodo} {ruta}");
        if escribe {
            self.dicho.push(Revelacion::OrdenDeEscritura { que });
        } else {
            self.dicho.push(Revelacion::Peticion { que });
        }

        // El cuerpo de un POST de acceso lleva las credenciales del formulario.
        if escribe {
            if let Some((_, cuerpo)) = texto.split_once("\r\n\r\n") {
                if let Some(c) = credenciales_de_formulario(cuerpo) {
                    self.dicho.push(c);
                }
            }
        }

        let (codigo, tipo, cuerpo) = self.cuerpo(&ruta);
        let razon = match codigo {
            200 => "OK",
            401 => "Unauthorized",
            403 => "Forbidden",
            _ => "Not Found",
        };
        let respuesta = format!(
            "HTTP/1.1 {codigo} {razon}\r\nServer: nginx/1.18.0 (Ubuntu)\r\n\
             Content-Type: {tipo}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{cuerpo}",
            cuerpo.len()
        );
        Paso::Responde(respuesta.into_bytes())
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.cebo.len() + self.dicho.iter().map(tam_revelacion).sum::<usize>()
    }
}

/// Saca usuario y clave de un cuerpo de formulario.
fn credenciales_de_formulario(cuerpo: &str) -> Option<Revelacion> {
    let mut usuario = None;
    let mut clave = None;
    for par in cuerpo.split('&').take(32) {
        let (k, v) = par.split_once('=')?;
        let v: String = v.chars().take(MAX_CAMPO).collect();
        match k.to_ascii_lowercase().as_str() {
            "usuario" | "user" | "username" | "login" | "email" | "log" => usuario = Some(v),
            "clave" | "pass" | "password" | "passwd" | "pwd" => clave = Some(v),
            _ => {}
        }
    }
    match (usuario, clave) {
        (Some(u), Some(c)) => Some(Revelacion::Credencial {
            usuario: u,
            clave: c,
        }),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de HTTPS.
///
/// # Hasta donde llega, y por que eso ya es mucho
///
/// Hasta el `ClientHello`, que es el primerisimo mensaje y va **en claro**.
/// Contestar al saludo exigiria un certificado y criptografia de verdad, asi que
/// no se contesta: se manda una alerta de `handshake_failure`, que es lo que hace
/// un servidor al que no le sirve ninguna propuesta del cliente.
///
/// Lo que se saca antes de parar:
///
/// - **El SNI**: el nombre de maquina que el cliente buscaba. Dice si venia a por
///   esta maquina en concreto o estaba barriendo direcciones — y a veces trae el
///   nombre interno de un sistema que no deberia conocer.
/// - **Las suites de cifrado, las extensiones y las curvas, en su orden**: la
///   huella JA3. Identifica la biblioteca y la version aunque el agente de usuario
///   mienta, porque quien escribe el exploit casi nunca toca esa parte.
#[derive(Debug, Default)]
pub struct Tls {
    dicho: Vec<Revelacion>,
}

impl Tls {
    /// Un senuelo de TLS nuevo.
    #[must_use]
    pub fn nuevo() -> Tls {
        Tls::default()
    }

    /// Saca el SNI de un `ClientHello`, si lo trae.
    ///
    /// Todos los tamanos vienen del cliente, asi que cada salto se comprueba
    /// contra lo que hay de verdad: un `ClientHello` que diga que su lista de
    /// suites mide sesenta mil bytes no puede mover el cursor mas alla del final.
    #[must_use]
    pub fn sni(datos: &[u8]) -> Option<String> {
        // Registro TLS: tipo 22 (handshake), version, longitud.
        if datos.len() < 43 || datos[0] != 22 || datos[5] != 1 {
            return None;
        }
        let mut i = 43usize; // tras id de sesion no leido todavia
        let n_sesion = *datos.get(43)? as usize;
        i = i.checked_add(1)?.checked_add(n_sesion)?;

        let n_suites = u16::from_be_bytes([*datos.get(i)?, *datos.get(i + 1)?]) as usize;
        i = i.checked_add(2)?.checked_add(n_suites)?;

        let n_comp = *datos.get(i)? as usize;
        i = i.checked_add(1)?.checked_add(n_comp)?;

        let n_ext = u16::from_be_bytes([*datos.get(i)?, *datos.get(i + 1)?]) as usize;
        i = i.checked_add(2)?;
        let fin = i.checked_add(n_ext)?.min(datos.len());

        while i + 4 <= fin {
            let tipo = u16::from_be_bytes([datos[i], datos[i + 1]]);
            let largo = u16::from_be_bytes([datos[i + 2], datos[i + 3]]) as usize;
            i += 4;
            if i + largo > fin {
                return None;
            }
            if tipo == 0 {
                // server_name: lista de 16 bits, tipo de 8, nombre de 16.
                let e = &datos[i..i + largo];
                if e.len() >= 5 && e[2] == 0 {
                    let n = u16::from_be_bytes([e[3], e[4]]) as usize;
                    if 5 + n <= e.len() && n <= MAX_CAMPO {
                        return Some(String::from_utf8_lossy(&e[5..5 + n]).to_string());
                    }
                }
                return None;
            }
            i += largo;
        }
        None
    }

    /// Las suites de cifrado que propone el cliente, en su orden.
    #[must_use]
    pub fn suites(datos: &[u8]) -> Option<Vec<u16>> {
        if datos.len() < 44 || datos[0] != 22 || datos[5] != 1 {
            return None;
        }
        let n_sesion = datos[43] as usize;
        let i = 44usize.checked_add(n_sesion)?;
        let n = u16::from_be_bytes([*datos.get(i)?, *datos.get(i + 1)?]) as usize;
        let d = datos.get(i + 2..i + 2 + n)?;
        Some(
            d.chunks_exact(2)
                .map(|p| u16::from_be_bytes([p[0], p[1]]))
                .collect(),
        )
    }
}

impl Dialogo for Tls {
    fn servicio(&self) -> &'static str {
        "https"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        if entrada.first() != Some(&22) {
            // No es un saludo TLS: puede ser HTTP en claro contra el puerto de
            // TLS, que es un error tan comun que contestarlo es lo creible.
            return Paso::RespondeYCierra(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_vec(),
            );
        }
        if let Some(n) = Tls::sni(entrada) {
            self.dicho.push(Revelacion::Peticion {
                que: format!("buscaba el nombre «{n}»"),
            });
        }
        if let Some(s) = Tls::suites(entrada) {
            let lista: Vec<String> = s.iter().take(24).map(|c| format!("{c:04x}")).collect();
            self.dicho.push(Revelacion::Herramienta {
                texto: format!("huella TLS (suites en orden): {}", lista.join("-")),
            });
        }
        // Alerta fatal 40 = handshake_failure.
        Paso::RespondeYCierra(vec![21, 3, 3, 0, 2, 2, 40])
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

    fn peticion(metodo: &str, ruta: &str, extra: &str, cuerpo: &str) -> Vec<u8> {
        format!(
            "{metodo} {ruta} HTTP/1.1\r\nHost: intranet\r\n\
             User-Agent: Mozilla/5.0 (compatible; Nuclei)\r\n{extra}\r\n{cuerpo}"
        )
        .into_bytes()
    }

    #[test]
    fn http_anota_la_ruta_y_la_herramienta() {
        let mut h = Http::nuevo();
        h.turno(&peticion("GET", "/.git/config", "", ""));
        assert!(h.revelado().iter().any(|r| matches!(
            r, Revelacion::Herramienta { texto } if texto.contains("Nuclei")
        )));
        assert!(h.revelado().iter().any(|r| matches!(
            r, Revelacion::Peticion { que } if que == "GET /.git/config"
        )));
    }

    #[test]
    fn http_distingue_leer_de_escribir() {
        let mut h = Http::nuevo();
        h.turno(&peticion("GET", "/", "", ""));
        h.turno(&peticion("PUT", "/subida.php", "", ""));
        let graves: Vec<_> = h.revelado().iter().filter(|r| r.es_grave()).collect();
        assert_eq!(graves.len(), 1);
        assert!(graves[0].frase().contains("PUT /subida.php"));
    }

    #[test]
    fn http_se_queda_con_las_credenciales_de_la_cabecera_y_del_formulario() {
        let mut h = Http::nuevo();
        h.turno(&peticion(
            "GET",
            "/admin",
            "Authorization: Basic YWRtaW46MTIzNA==\r\n",
            "",
        ));
        h.turno(&peticion(
            "POST",
            "/login",
            "Content-Type: application/x-www-form-urlencoded\r\n",
            "usuario=root&clave=Verano2024",
        ));
        let creds: Vec<_> = h
            .revelado()
            .iter()
            .filter(|r| matches!(r, Revelacion::Credencial { .. }))
            .collect();
        assert_eq!(creds.len(), 2, "{:?}", h.revelado());
        assert!(creds[0].frase().contains("YWRtaW46MTIzNA=="));
        assert!(creds[1].frase().contains("Verano2024"));
    }

    #[test]
    fn el_cebo_solo_se_sirve_si_se_puso() {
        let mut vacio = Http::nuevo();
        let p = vacio.turno(&peticion("GET", "/.env", "", ""));
        assert!(String::from_utf8_lossy(p.bytes()).contains("404"));

        let mut cebado = Http::con_cebo("API_KEY=AKIA0000MARCADOR\n".to_owned());
        let p = cebado.turno(&peticion("GET", "/.env", "", ""));
        let s = String::from_utf8_lossy(p.bytes());
        assert!(s.contains("200 OK"), "{s}");
        assert!(s.contains("AKIA0000MARCADOR"));
    }

    #[test]
    fn una_peticion_gigante_se_corta_como_la_cortaria_un_servidor_real() {
        let mut h = Http::nuevo();
        let p = h.turno(&vec![b'A'; MAX_PETICION + 1]);
        assert!(p.cierra());
        assert!(String::from_utf8_lossy(p.bytes()).contains("431"));
    }

    /// Un `ClientHello` de TLS 1.2 con SNI, construido byte a byte.
    fn cliente_hello(nombre: &str) -> Vec<u8> {
        let sni_nombre = nombre.as_bytes();
        let mut ext_sni = Vec::new();
        ext_sni.extend_from_slice(&((sni_nombre.len() + 3) as u16).to_be_bytes());
        ext_sni.push(0); // tipo host_name
        ext_sni.extend_from_slice(&(sni_nombre.len() as u16).to_be_bytes());
        ext_sni.extend_from_slice(sni_nombre);

        let mut exts = Vec::new();
        exts.extend_from_slice(&0u16.to_be_bytes()); // server_name
        exts.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_sni);

        let suites: [u16; 3] = [0x1301, 0xc02f, 0x009c];
        let mut cuerpo = Vec::new();
        cuerpo.extend_from_slice(&[3, 3]); // version
        cuerpo.extend_from_slice(&[0x42; 32]); // aleatorio
        cuerpo.push(0); // sin id de sesion
        cuerpo.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for s in suites {
            cuerpo.extend_from_slice(&s.to_be_bytes());
        }
        cuerpo.push(1); // un metodo de compresion
        cuerpo.push(0); // null
        cuerpo.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        cuerpo.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(1); // ClientHello
        hs.extend_from_slice(&(cuerpo.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&cuerpo);

        let mut v = Vec::new();
        v.extend_from_slice(&[22, 3, 1]);
        v.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        v.extend_from_slice(&hs);
        v
    }

    #[test]
    fn tls_saca_el_nombre_que_buscaban_y_la_huella() {
        let hello = cliente_hello("vpn.empresa.es");
        assert_eq!(Tls::sni(&hello).as_deref(), Some("vpn.empresa.es"));
        assert_eq!(Tls::suites(&hello), Some(vec![0x1301, 0xc02f, 0x009c]));

        let mut t = Tls::nuevo();
        let p = t.turno(&hello);
        assert!(p.cierra());
        assert_eq!(p.bytes(), &[21, 3, 3, 0, 2, 2, 40], "alerta fatal");
        assert!(t
            .revelado()
            .iter()
            .any(|r| r.frase().contains("vpn.empresa.es")));
        assert!(t
            .revelado()
            .iter()
            .any(|r| r.frase().contains("1301-c02f-009c")));
    }

    #[test]
    fn tls_no_se_sale_del_vector_con_un_hello_mentiroso() {
        // Se recorta el saludo por todos los puntos posibles: ninguno puede
        // hacer panico ni leer de mas.
        let hello = cliente_hello("a.b.c");
        for n in 0..hello.len() {
            let _ = Tls::sni(&hello[..n]);
            let _ = Tls::suites(&hello[..n]);
        }
        // Y con longitudes imposibles metidas a mano.
        let mut roto = hello.clone();
        roto[43] = 0xff; // id de sesion enorme
        assert!(Tls::sni(&roto).is_none());
        let mut roto2 = hello.clone();
        roto2[44] = 0xff;
        roto2[45] = 0xff; // lista de suites enorme
        assert!(Tls::sni(&roto2).is_none());
    }

    #[test]
    fn http_en_claro_contra_el_puerto_de_tls_se_contesta_como_haria_un_servidor() {
        let mut t = Tls::nuevo();
        let p = t.turno(b"GET / HTTP/1.1\r\n\r\n");
        assert!(String::from_utf8_lossy(p.bytes()).contains("400"));
    }
}
