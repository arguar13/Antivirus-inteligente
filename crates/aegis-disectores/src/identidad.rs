//! Identidad y directorio: NTLM, RADIUS, Diameter, SAML y OAuth.
//!
//! # Por que estos cinco van juntos
//!
//! Porque todos contestan a la misma pregunta —**quien dice ser quien**— y
//! porque un ataque de credenciales no se queda en uno. El mismo intento viaja
//! por NTLM dentro de SMB, por RADIUS desde la VPN y por OAuth desde el portal
//! web, y un sensor que emita un evento distinto por cada uno obliga a que
//! alguien escriba despues la capa que los junta.
//!
//! Aqui los cinco emiten [`Hecho::AutenticacionVista`], con el mismo hueco para
//! el usuario y el mismo para el dominio. Contar intentos fallidos por usuario
//! sin importar por donde entro es una consulta, no un proyecto.
//!
//! # NTLM: por que se busca la firma y no el protocolo que lo lleva
//!
//! NTLM no tiene puerto. Viaja dentro de SMB, dentro de HTTP en una cabecera
//! `Authorization`, dentro de DCERPC y dentro de LDAP. Buscar la firma
//! `NTLMSSP\0` en la carga es lo que hace que se vea en los cuatro sitios con
//! un disector, y es tambien lo que permite ver un relay: el mismo reto del
//! servidor apareciendo en dos flujos distintos.

use aegis_wire::error::{ErrorDiseccion, Resultado};
use aegis_wire::hecho::{Hecho, ProtocoloApp};
use aegis_wire::lector::Lector;

use crate::disector::{Contexto, Disector, Fuerza, Salida};
use crate::texto;

// ════════════════════════════════════════════════════════════════════════════
// NTLM
// ════════════════════════════════════════════════════════════════════════════

/// La firma con la que empieza todo mensaje NTLMSSP.
pub const FIRMA_NTLMSSP: &[u8; 8] = b"NTLMSSP\0";

/// Hasta donde se busca la firma dentro de la carga.
///
/// NTLM va empotrado, asi que la firma no esta al principio. Buscarla en todo
/// el buffer haria que cada paquete grande costara un barrido completo; cuatro
/// kilobytes cubren la cabecera de SMB, la de HTTP y la de DCERPC con holgura.
pub const VENTANA_NTLM: usize = 4096;

/// Se negocio texto en Unicode y no en la pagina de codigos OEM.
const UNICODE: u32 = 0x0000_0001;

/// Un campo de NTLM que apunta a un texto en otra parte del mensaje.
#[derive(Debug, Clone, Copy)]
struct Campo {
    largo: u16,
    desplazamiento: u32,
}

impl Campo {
    fn leer(l: &mut Lector<'_>, campo: &'static str) -> Resultado<Campo> {
        let largo = l.u16_le(campo)?;
        let _maximo = l.u16_le(campo)?;
        let desplazamiento = l.u32_le(campo)?;
        Ok(Campo {
            largo,
            desplazamiento,
        })
    }

    /// El texto al que apunta, leido desde el principio del mensaje NTLM.
    ///
    /// El desplazamiento lo escribe el emisor, asi que puede apuntar fuera: esa
    /// es la forma clasica de sacar memoria de un servidor mal escrito. Aqui
    /// devuelve vacio y no lee nada.
    fn texto(&self, mensaje: &[u8], unicode: bool) -> String {
        let inicio = self.desplazamiento as usize;
        let fin = inicio.saturating_add(self.largo as usize);
        if self.largo == 0 || fin > mensaje.len() {
            return String::new();
        }
        let bytes = &mensaje[inicio..fin];
        if unicode {
            texto::utf16le(bytes)
        } else {
            aegis_wire::lector::ascii_legible(bytes)
        }
    }
}

/// Disector de NTLM, alla donde viaje.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ntlm;

impl Ntlm {
    /// Donde empieza el mensaje NTLMSSP dentro de la carga, si esta.
    fn donde(datos: &[u8]) -> Option<usize> {
        let tope = datos.len().min(VENTANA_NTLM);
        if tope < FIRMA_NTLMSSP.len() {
            return None;
        }
        datos[..tope]
            .windows(FIRMA_NTLMSSP.len())
            .position(|v| v == FIRMA_NTLMSSP)
    }

    fn analizar(datos: &[u8]) -> Resultado<Vec<Hecho>> {
        let Some(inicio) = Ntlm::donde(datos) else {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("ntlm"));
        };
        let mensaje = &datos[inicio..];
        let mut l = Lector::nuevo(mensaje);
        l.saltar(FIRMA_NTLMSSP.len(), "ntlm.firma")?;
        let tipo = l.u32_le("ntlm.tipo")?;
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Ntlm)];

        match tipo {
            1 => {
                let banderas = l.u32_le("ntlm.banderas")?;
                let unicode = banderas & UNICODE != 0;
                let dominio = Campo::leer(&mut l, "ntlm.dominio")?;
                let equipo = Campo::leer(&mut l, "ntlm.equipo")?;
                hechos.push(Hecho::AutenticacionVista {
                    mecanismo: "ntlmssp-negociacion".to_owned(),
                    usuario: String::new(),
                    dominio: dominio.texto(mensaje, unicode),
                    resultado: format!("desde {}", equipo.texto(mensaje, unicode)),
                });
            }
            2 => {
                let objetivo = Campo::leer(&mut l, "ntlm.objetivo")?;
                let banderas = l.u32_le("ntlm.banderas")?;
                let unicode = banderas & UNICODE != 0;
                let reto = l.tomar(8, "ntlm.reto")?;
                // El reto en hexadecimal es lo que permite ver un relay: el
                // mismo reto de servidor apareciendo en dos flujos distintos es
                // exactamente la firma de un ataque de retransmision.
                let hex: String = reto.iter().map(|b| format!("{b:02x}")).collect();
                hechos.push(Hecho::AutenticacionVista {
                    mecanismo: "ntlmssp-reto".to_owned(),
                    usuario: String::new(),
                    dominio: objetivo.texto(mensaje, unicode),
                    resultado: format!("reto {hex}"),
                });
            }
            3 => {
                let _lm = Campo::leer(&mut l, "ntlm.respuesta-lm")?;
                let nt = Campo::leer(&mut l, "ntlm.respuesta-nt")?;
                let dominio = Campo::leer(&mut l, "ntlm.dominio")?;
                let usuario = Campo::leer(&mut l, "ntlm.usuario")?;
                let equipo = Campo::leer(&mut l, "ntlm.equipo")?;
                let _sesion = Campo::leer(&mut l, "ntlm.clave-de-sesion")?;
                let banderas = l.u32_le("ntlm.banderas")?;
                let unicode = banderas & UNICODE != 0;
                // Una respuesta NT de 24 bytes es NTLMv1, que se puede romper
                // fuera de linea. Que siga viva en una red en 2026 es un hecho
                // por si mismo, y por eso va en el resultado y no se calla.
                let version = if nt.largo == 24 { "NTLMv1" } else { "NTLMv2" };
                hechos.push(Hecho::AutenticacionVista {
                    mecanismo: format!("ntlmssp-respuesta-{version}"),
                    usuario: usuario.texto(mensaje, unicode),
                    dominio: dominio.texto(mensaje, unicode),
                    resultado: format!("desde {}", equipo.texto(mensaje, unicode)),
                });
            }
            otro => {
                return Err(ErrorDiseccion::ValorInvalido {
                    campo: "ntlm.tipo",
                    valor: u64::from(otro),
                })
            }
        }
        Ok(hechos)
    }
}

impl Disector for Ntlm {
    /// Los ocho bytes de `NTLMSSP\0`, que no salen por casualidad.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Marca
    }

    fn nombre(&self) -> &'static str {
        "ntlm"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Ntlm::donde(datos).is_some()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        Salida::de_resultado(Ntlm::analizar(datos))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "negociacion (tipo 1) con su dominio y su equipo",
            "reto (tipo 2) con el reto del servidor en claro, que delata un relay",
            "respuesta (tipo 3) con usuario, dominio y equipo",
            "la distincion entre NTLMv1 y NTLMv2 por la longitud de la respuesta",
            "el texto en Unicode y en la pagina OEM, segun lo negociado",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "la informacion de objetivo del tipo 2 (los pares atributo-valor)",
            "la clave de sesion cifrada",
            "la firma y el sellado del canal una vez establecido",
            "NTLM empotrado mas alla de los primeros cuatro kilobytes de la carga",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// RADIUS
// ════════════════════════════════════════════════════════════════════════════

/// Puertos de RADIUS: autenticacion y contabilidad.
pub const PUERTOS_RADIUS: [u16; 4] = [1812, 1813, 1645, 1646];

/// La longitud minima de un paquete RADIUS, por la RFC 2865.
const MIN_RADIUS: usize = 20;

/// El codigo de un paquete RADIUS.
fn codigo_radius(c: u8) -> Option<(&'static str, &'static str)> {
    Some(match c {
        1 => ("radius-peticion-de-acceso", "peticion"),
        2 => ("radius-acceso-aceptado", "acepta"),
        3 => ("radius-acceso-rechazado", "rechaza"),
        4 => ("radius-peticion-de-contabilidad", "peticion"),
        5 => ("radius-respuesta-de-contabilidad", "acepta"),
        11 => ("radius-reto-de-acceso", "reto"),
        40 => ("radius-peticion-de-desconexion", "peticion"),
        43 => ("radius-cambio-de-autorizacion", "peticion"),
        _ => return None,
    })
}

/// Disector de RADIUS.
#[derive(Debug, Default, Clone, Copy)]
pub struct Radius;

impl Radius {
    /// La cabecera: `(codigo, identificador, longitud)`.
    fn cabecera(datos: &[u8]) -> Resultado<(u8, u8, usize)> {
        let mut l = Lector::nuevo(datos);
        let codigo = l.u8("radius.codigo")?;
        if codigo_radius(codigo).is_none() {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("radius"));
        }
        let identificador = l.u8("radius.identificador")?;
        let largo = l.u16("radius.longitud")? as usize;
        // La RFC fija el rango: veinte como minimo y 4096 como maximo.
        if !(MIN_RADIUS..=4096).contains(&largo) {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "radius.longitud",
                valor: largo as u64,
            });
        }
        if largo > datos.len() {
            return Err(ErrorDiseccion::LongitudImposible {
                campo: "radius.longitud",
                declarada: largo,
                disponible: datos.len(),
            });
        }
        Ok((codigo, identificador, largo))
    }

    fn analizar(datos: &[u8]) -> Resultado<Vec<Hecho>> {
        let (codigo, identificador, largo) = Radius::cabecera(datos)?;
        let (mecanismo, resultado) = codigo_radius(codigo).unwrap_or(("radius", "peticion"));
        let mut l = Lector::nuevo(&datos[..largo]);
        l.saltar(4, "radius.cabecera")?;
        l.saltar(16, "radius.autenticador")?;

        let mut usuario = String::new();
        let mut nas = String::new();
        let mut llamante = String::new();
        // Los atributos son una lista con longitudes que escribe el emisor: sin
        // el tope de iteraciones, un atributo de longitud dos que se repita
        // bastaria para dar dos mil vueltas por paquete. Con el, el coste por
        // paquete esta acotado pase lo que pase.
        for _ in 0..256 {
            if l.restante() < 2 {
                break;
            }
            let tipo = l.u8("radius.atributo")?;
            let largo_attr = l.u8("radius.longitud-de-atributo")? as usize;
            // Menos de dos incluye su propia cabecera: seguir seria avanzar cero
            // y dar vueltas para siempre.
            if largo_attr < 2 {
                return Err(ErrorDiseccion::ValorInvalido {
                    campo: "radius.longitud-de-atributo",
                    valor: largo_attr as u64,
                });
            }
            let valor = l.tomar(largo_attr - 2, "radius.valor")?;
            match tipo {
                1 => usuario = aegis_wire::lector::ascii_legible(valor),
                32 => nas = aegis_wire::lector::ascii_legible(valor),
                31 => llamante = aegis_wire::lector::ascii_legible(valor),
                4 if valor.len() == 4 => {
                    nas = format!("{}.{}.{}.{}", valor[0], valor[1], valor[2], valor[3]);
                }
                _ => {}
            }
        }

        let mut detalle = format!("identificador {identificador}");
        if !llamante.is_empty() {
            detalle.push_str(&format!(", desde {llamante}"));
        }
        Ok(vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Radius),
            Hecho::AutenticacionVista {
                mecanismo: mecanismo.to_owned(),
                usuario,
                dominio: nas,
                resultado: format!("{resultado} ({detalle})"),
            },
        ])
    }
}

impl Disector for Radius {
    /// Codigo conocido y longitud dentro del rango de la RFC, comprobada contra lo que hay.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "radius"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Radius::cabecera(datos).is_ok()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        Salida::de_resultado(Radius::analizar(datos))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "peticion, aceptacion, rechazo y reto de acceso",
            "peticion y respuesta de contabilidad",
            "desconexion y cambio de autorizacion",
            "los atributos User-Name, NAS-Identifier, NAS-IP-Address y Calling-Station-Id",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "User-Password, que va cifrado con el secreto compartido",
            "los mensajes EAP encapsulados en el atributo 79",
            "los atributos especificos de fabricante (atributo 26)",
            "la comprobacion del autenticador de respuesta",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Diameter
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de Diameter.
pub const PUERTO_DIAMETER: u16 = 3868;

/// El comando de Diameter, por su codigo (RFC 6733 y sus aplicaciones).
fn comando_diameter(c: u32) -> Option<&'static str> {
    Some(match c {
        257 => "intercambio-de-capacidades",
        258 => "reautorizacion",
        271 => "contabilidad",
        272 => "control-de-credito",
        274 => "terminacion-de-sesion-por-el-servidor",
        275 => "terminacion-de-sesion",
        280 => "vigilancia-del-dispositivo",
        282 => "desconexion-del-par",
        316 => "actualizacion-de-ubicacion",
        318 => "peticion-de-autenticacion",
        _ => return None,
    })
}

/// Disector de Diameter.
#[derive(Debug, Default, Clone, Copy)]
pub struct Diameter;

impl Diameter {
    /// La cabecera: `(longitud, banderas, comando, aplicacion)`.
    fn cabecera(datos: &[u8]) -> Resultado<(usize, u8, u32, u32)> {
        let mut l = Lector::nuevo(datos);
        let version = l.u8("diameter.version")?;
        if version != 1 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("diameter"));
        }
        let largo = l.u24("diameter.longitud")? as usize;
        // La cabecera son veinte bytes y la longitud los cuenta. Ademas Diameter
        // alinea todo a cuatro: una longitud que no sea multiplo de cuatro no
        // puede venir de un emisor que cumpla la norma.
        if largo < 20 || largo % 4 != 0 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "diameter.longitud",
                valor: largo as u64,
            });
        }
        let banderas = l.u8("diameter.banderas")?;
        let comando = l.u24("diameter.comando")?;
        let aplicacion = l.u32("diameter.aplicacion")?;
        Ok((largo, banderas, comando, aplicacion))
    }

    fn analizar(datos: &[u8]) -> Resultado<Vec<Hecho>> {
        let (largo, banderas, comando, aplicacion) = Diameter::cabecera(datos)?;
        let es_peticion = banderas & 0x80 != 0;
        let nombre = comando_diameter(comando).unwrap_or("comando-no-catalogado");
        let mut l = Lector::nuevo(&datos[..largo.min(datos.len())]);
        l.saltar(20.min(datos.len()), "diameter.cabecera")?;

        let mut usuario = String::new();
        let mut reino = String::new();
        // El mismo tope que en RADIUS y por lo mismo: la lista de AVP la escribe
        // el emisor, y sin tope una longitud minima repetida da vueltas de mas.
        for _ in 0..256 {
            if l.restante() < 8 {
                break;
            }
            let codigo = l.u32("diameter.avp")?;
            let banderas_avp = l.u8("diameter.banderas-de-avp")?;
            let largo_avp = l.u24("diameter.longitud-de-avp")? as usize;
            if largo_avp < 8 {
                return Err(ErrorDiseccion::ValorInvalido {
                    campo: "diameter.longitud-de-avp",
                    valor: largo_avp as u64,
                });
            }
            let mut cabecera_avp = 8;
            if banderas_avp & 0x80 != 0 {
                let _vendedor = l.u32("diameter.vendedor")?;
                cabecera_avp += 4;
            }
            if largo_avp < cabecera_avp {
                return Err(ErrorDiseccion::ValorInvalido {
                    campo: "diameter.longitud-de-avp",
                    valor: largo_avp as u64,
                });
            }
            let valor = l.tomar(largo_avp - cabecera_avp, "diameter.valor")?;
            // Diameter rellena cada AVP hasta el siguiente multiplo de cuatro, y
            // ese relleno no cuenta en la longitud.
            let relleno = (4 - (largo_avp % 4)) % 4;
            if relleno > 0 && l.restante() >= relleno {
                l.saltar(relleno, "diameter.relleno")?;
            }
            match codigo {
                1 => usuario = aegis_wire::lector::ascii_legible(valor),
                283 => reino = aegis_wire::lector::ascii_legible(valor),
                _ => {}
            }
        }

        Ok(vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Diameter),
            Hecho::AutenticacionVista {
                mecanismo: format!("diameter-{nombre}"),
                usuario,
                dominio: reino,
                resultado: format!(
                    "{} de la aplicacion {aplicacion}",
                    if es_peticion { "peticion" } else { "respuesta" }
                ),
            },
        ])
    }
}

impl Disector for Diameter {
    /// Version uno, longitud alineada a cuatro y comando conocido.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "diameter"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Diameter::cabecera(datos).is_ok()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        Salida::de_resultado(Diameter::analizar(datos))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la cabecera con su comando, su aplicacion y si es peticion o respuesta",
            "intercambio-de-capacidades, control-de-credito y vigilancia-del-dispositivo",
            "los AVP User-Name y Destination-Realm, incluidos los de fabricante",
            "el relleno de alineacion a cuatro bytes entre AVP",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "los AVP agrupados y su contenido anidado",
            "los codigos de resultado y su significado por aplicacion",
            "las aplicaciones 3GPP (S6a, Gx, Rx) mas alla del identificador",
            "Diameter sobre TLS o sobre DTLS",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SAML y OAuth: los que viajan dentro de HTTP
// ════════════════════════════════════════════════════════════════════════════

/// Disector de SAML dentro de HTTP.
///
/// # El muro, declarado
///
/// Una asercion SAML es XML comprimido con deflate y codificado en base64, y
/// muchas veces firmada. Este disector ve el **sobre**: que hubo un intercambio
/// SAML, en que sentido y contra que punto final. El contenido de la asercion
/// —el `NameID`, los atributos, la firma— no se analiza, y decirlo es la
/// diferencia entre un informe honesto y uno que parezca completo.
#[derive(Debug, Default, Clone, Copy)]
pub struct Saml;

impl Saml {
    /// Los parametros de SAML que aparecen en una peticion o en un cuerpo.
    const MARCAS: [(&'static str, &'static str); 4] = [
        ("SAMLResponse=", "saml-respuesta"),
        ("SAMLRequest=", "saml-peticion"),
        ("SAMLart=", "saml-artefacto"),
        ("RelayState=", "saml-estado-de-retorno"),
    ];

    fn encontrar(datos: &[u8]) -> Option<(&'static str, String)> {
        let tope = datos.len().min(64 * 1024);
        let hay = &datos[..tope];
        for (marca, nombre) in Saml::MARCAS {
            if hay
                .windows(marca.len())
                .any(|v| v.eq_ignore_ascii_case(marca.as_bytes()))
            {
                let ruta = texto::peticion_http(datos)
                    .map(|(_, r, _)| r)
                    .unwrap_or_default();
                return Some((nombre, ruta));
            }
        }
        None
    }
}

impl Disector for Saml {
    /// Una peticion HTTP con un parametro de SAML.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Marca
    }

    fn nombre(&self) -> &'static str {
        "saml"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Saml::encontrar(datos).is_some()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        let Some((nombre, ruta)) = Saml::encontrar(datos) else {
            return Salida::sin_analizar(crate::cobertura::Motivo::NoReconocido);
        };
        // El sobre se entiende; la asercion no. Se declara lo segundo en vez de
        // contar el mensaje como entendido, que es lo que infla una cifra.
        Salida::no_implementado(vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Saml),
            Hecho::AutenticacionVista {
                mecanismo: nombre.to_owned(),
                usuario: String::new(),
                dominio: String::new(),
                resultado: format!("contra {ruta}"),
            },
        ])
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "que hubo un intercambio SAML y en que sentido",
            "el punto final contra el que se hizo",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "la asercion: va en XML comprimido con deflate y codificado en base64",
            "el NameID y los atributos que lleva",
            "la firma de la asercion y su validez",
            "el perfil de artefacto y su resolucion contra el emisor",
        ]
    }
}

/// Disector de OAuth 2.0 y OpenID Connect dentro de HTTP.
#[derive(Debug, Default, Clone, Copy)]
pub struct Oauth;

/// Lo que se ve de un intercambio OAuth.
struct Rastro {
    mecanismo: &'static str,
    detalle: String,
}

impl Oauth {
    fn encontrar(datos: &[u8]) -> Option<Rastro> {
        // Un portador en la cabecera: es la credencial en si, viajando.
        if let Some(a) = texto::cabecera(datos, "Authorization") {
            if a.len() > 7 && a[..7].eq_ignore_ascii_case("Bearer ") {
                let testigo = &a[7..];
                // Un JWT tiene tres partes separadas por puntos. La primera es
                // la cabecera en base64url, y de ahi sale el algoritmo — que es
                // lo unico que se mira, porque `alg: none` es un ataque entero.
                let partes: Vec<&str> = testigo.split('.').collect();
                let detalle = if partes.len() == 3 {
                    match texto::base64(partes[0].as_bytes()) {
                        Some(c) if texto::parece_texto(&c) => {
                            format!("jwt con cabecera {}", aegis_wire::lector::ascii_legible(&c))
                        }
                        _ => "jwt con cabecera ilegible".to_owned(),
                    }
                } else {
                    format!("testigo opaco de {} caracteres", testigo.len())
                };
                return Some(Rastro {
                    mecanismo: "oauth-portador",
                    detalle,
                });
            }
        }
        let tope = datos.len().min(64 * 1024);
        let hay = &datos[..tope];
        let contiene = |m: &str| {
            hay.windows(m.len())
                .any(|v| v.eq_ignore_ascii_case(m.as_bytes()))
        };
        if contiene("grant_type=") {
            let tipo = if contiene("grant_type=client_credentials") {
                "credenciales-de-cliente"
            } else if contiene("grant_type=refresh_token") {
                "refresco"
            } else if contiene("grant_type=password") {
                // El flujo de contrasena esta desaconsejado desde OAuth 2.1
                // justo porque la aplicacion ve la credencial del usuario.
                "contrasena-del-propietario"
            } else if contiene("grant_type=authorization_code") {
                "codigo-de-autorizacion"
            } else {
                "concesion-no-catalogada"
            };
            return Some(Rastro {
                mecanismo: "oauth-peticion-de-testigo",
                detalle: tipo.to_owned(),
            });
        }
        if contiene("/.well-known/openid-configuration") {
            return Some(Rastro {
                mecanismo: "oidc-descubrimiento",
                detalle: String::new(),
            });
        }
        if contiene("response_type=") && contiene("client_id=") {
            return Some(Rastro {
                mecanismo: "oauth-autorizacion",
                detalle: String::new(),
            });
        }
        None
    }
}

impl Disector for Oauth {
    /// Una cabecera de portador o un parametro de concesion de OAuth.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Marca
    }

    fn nombre(&self) -> &'static str {
        "oauth"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Oauth::encontrar(datos).is_some()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        let Some(r) = Oauth::encontrar(datos) else {
            return Salida::sin_analizar(crate::cobertura::Motivo::NoReconocido);
        };
        Salida::entendido(vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Oauth),
            Hecho::AutenticacionVista {
                mecanismo: r.mecanismo.to_owned(),
                usuario: String::new(),
                dominio: String::new(),
                resultado: r.detalle,
            },
        ])
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "el portador en la cabecera Authorization",
            "la cabecera de un JWT, de donde sale su algoritmo",
            "la peticion de testigo con su tipo de concesion",
            "la peticion de autorizacion y el descubrimiento de OpenID Connect",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el cuerpo del JWT: los alegatos, el emisor y la caducidad",
            "la firma del testigo y su validez",
            "los testigos opacos, que por definicion no llevan contenido legible",
            "el flujo de dispositivo y el intercambio con PKCE",
        ]
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn autenticacion(s: &Salida) -> Option<(&str, &str, &str, &str)> {
        s.hechos.iter().find_map(|h| match h {
            Hecho::AutenticacionVista {
                mecanismo,
                usuario,
                dominio,
                resultado,
            } => Some((
                mecanismo.as_str(),
                usuario.as_str(),
                dominio.as_str(),
                resultado.as_str(),
            )),
            _ => None,
        })
    }

    /// Un NTLMSSP de tipo 3 con dominio `CASA`, usuario `admin` y equipo `PC1`,
    /// en Unicode, tal y como lo manda Windows.
    fn ntlm_respuesta() -> Vec<u8> {
        let dominio: Vec<u8> = "CASA".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let usuario: Vec<u8> = "admin".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let equipo: Vec<u8> = "PC1".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let cabecera = 64usize;
        let off_lm = cabecera;
        let off_nt = off_lm + 24;
        let off_dom = off_nt + 32;
        let off_usr = off_dom + dominio.len();
        let off_eq = off_usr + usuario.len();

        let mut v = Vec::new();
        v.extend_from_slice(FIRMA_NTLMSSP);
        v.extend_from_slice(&3u32.to_le_bytes());
        let campo = |largo: usize, off: usize| -> Vec<u8> {
            let mut c = Vec::new();
            c.extend_from_slice(&(largo as u16).to_le_bytes());
            c.extend_from_slice(&(largo as u16).to_le_bytes());
            c.extend_from_slice(&(off as u32).to_le_bytes());
            c
        };
        v.extend_from_slice(&campo(24, off_lm));
        v.extend_from_slice(&campo(32, off_nt));
        v.extend_from_slice(&campo(dominio.len(), off_dom));
        v.extend_from_slice(&campo(usuario.len(), off_usr));
        v.extend_from_slice(&campo(equipo.len(), off_eq));
        v.extend_from_slice(&campo(0, 0));
        v.extend_from_slice(&UNICODE.to_le_bytes());
        v.resize(off_lm, 0);
        v.extend_from_slice(&[0u8; 24]);
        v.extend_from_slice(&[0u8; 32]);
        v.extend_from_slice(&dominio);
        v.extend_from_slice(&usuario);
        v.extend_from_slice(&equipo);
        v
    }

    #[test]
    fn ntlm_saca_el_usuario_y_el_dominio_de_una_respuesta() {
        let d = Ntlm;
        let b = ntlm_respuesta();
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(445)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(445));
        assert!(s.cobertura.completa());
        let (mec, usr, dom, _) = autenticacion(&s).expect("una autenticacion");
        assert_eq!(usr, "admin");
        assert_eq!(dom, "CASA");
        assert!(mec.ends_with("NTLMv2"), "{mec}");
    }

    /// NTLM no tiene puerto: viaja dentro de SMB, de HTTP, de DCERPC y de LDAP.
    /// Buscar la firma en la carga es lo que hace que se vea en los cuatro.
    #[test]
    fn ntlm_se_ve_empotrado_dentro_de_otro_protocolo() {
        let d = Ntlm;
        let mut b = b"\x00\x00\x00\x54\xffSMB\x73\x00\x00\x00\x00".to_vec();
        b.extend_from_slice(&ntlm_respuesta());
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(445)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(445));
        let (_, usr, _, _) = autenticacion(&s).expect("una autenticacion");
        assert_eq!(usr, "admin");
    }

    #[test]
    fn ntlm_marca_la_version_uno_que_se_rompe_fuera_de_linea() {
        // Que NTLMv1 siga vivo en una red es un hecho por si mismo: su respuesta
        // se rompe fuera de linea con hardware de aficionado.
        let d = Ntlm;
        let mut b = ntlm_respuesta();
        // La respuesta NT pasa a 24 bytes, que es la longitud de NTLMv1. Su
        // campo empieza en el byte 20: longitud, maximo y desplazamiento.
        b[20] = 24;
        b[22] = 24;
        let s = d.disecar(&b, &Contexto::tcp_cliente(445));
        let (mec, _, _, _) = autenticacion(&s).expect("una autenticacion");
        assert!(mec.ends_with("NTLMv1"), "{mec}");
    }

    #[test]
    fn ntlm_no_lee_fuera_del_mensaje_aunque_el_desplazamiento_mienta() {
        // Un desplazamiento que apunta fuera es la forma clasica de sacar
        // memoria de un servidor mal escrito. Aqui devuelve vacio, no panico.
        let d = Ntlm;
        let mut b = ntlm_respuesta();
        b[32..36].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
        let s = d.disecar(&b, &Contexto::tcp_cliente(445));
        let (_, _, dom, _) = autenticacion(&s).expect("una autenticacion");
        assert_eq!(dom, "", "un desplazamiento que miente no da texto");
    }

    #[test]
    fn ntlm_deja_ver_el_reto_del_servidor_que_delata_un_relay() {
        let d = Ntlm;
        let mut v = Vec::new();
        v.extend_from_slice(FIRMA_NTLMSSP);
        v.extend_from_slice(&2u32.to_le_bytes());
        v.extend_from_slice(&[0u8; 8]); // campo de objetivo vacio
        v.extend_from_slice(&UNICODE.to_le_bytes());
        v.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        let s = d.disecar(&v, &Contexto::tcp_servidor(445));
        let (_, _, _, res) = autenticacion(&s).expect("una autenticacion");
        assert!(res.contains("0123456789abcdef"), "{res}");
    }

    /// Una peticion de acceso de RADIUS con el usuario `vpn1`.
    fn radius_peticion() -> Vec<u8> {
        let mut v = vec![1u8, 42];
        let usuario = b"vpn1";
        let largo = 20 + 2 + usuario.len();
        v.extend_from_slice(&(largo as u16).to_be_bytes());
        v.extend_from_slice(&[0u8; 16]);
        v.push(1);
        v.push((2 + usuario.len()) as u8);
        v.extend_from_slice(usuario);
        v
    }

    #[test]
    fn radius_saca_el_usuario_de_una_peticion_de_acceso() {
        let d = Radius;
        let b = radius_peticion();
        assert!(d.reconoce(&b, &Contexto::udp(1812)));
        let s = d.disecar(&b, &Contexto::udp(1812));
        assert!(s.cobertura.completa());
        let (mec, usr, _, _) = autenticacion(&s).expect("una autenticacion");
        assert_eq!(mec, "radius-peticion-de-acceso");
        assert_eq!(usr, "vpn1");
    }

    #[test]
    fn radius_no_da_vueltas_con_un_atributo_de_longitud_cero() {
        // Un atributo de longitud menor que su propia cabecera haria avanzar
        // cero: sin la comprobacion, el disector da vueltas para siempre.
        let d = Radius;
        let mut v = vec![1u8, 42, 0, 23];
        v.extend_from_slice(&[0u8; 16]);
        v.push(1);
        v.push(0);
        v.push(0);
        let s = d.disecar(&v, &Contexto::udp(1812));
        assert_eq!(
            s.cobertura
                .sin_analizar
                .get(&crate::cobertura::Motivo::Malformado),
            Some(&1)
        );
    }

    /// Un intercambio de capacidades de Diameter con User-Name.
    fn diameter_cer() -> Vec<u8> {
        let usuario = b"nodo1@casa";
        let largo_avp = 8 + usuario.len();
        let relleno = (4 - (largo_avp % 4)) % 4;
        let total = 20 + largo_avp + relleno;
        let mut v = vec![1u8];
        v.extend_from_slice(&(total as u32).to_be_bytes()[1..]);
        v.push(0x80); // peticion
        v.extend_from_slice(&257u32.to_be_bytes()[1..]);
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes()); // AVP User-Name
        v.push(0x40);
        v.extend_from_slice(&(largo_avp as u32).to_be_bytes()[1..]);
        v.extend_from_slice(usuario);
        v.extend(std::iter::repeat_n(0u8, relleno));
        v
    }

    #[test]
    fn diameter_lee_el_comando_y_el_usuario() {
        let d = Diameter;
        let b = diameter_cer();
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_DIAMETER)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_DIAMETER));
        assert!(s.cobertura.completa(), "{:?}", s.cobertura);
        let (mec, usr, _, res) = autenticacion(&s).expect("una autenticacion");
        assert_eq!(mec, "diameter-intercambio-de-capacidades");
        assert_eq!(usr, "nodo1@casa");
        assert!(res.starts_with("peticion"), "{res}");
    }

    #[test]
    fn diameter_rechaza_una_longitud_no_alineada() {
        // Diameter alinea todo a cuatro: una longitud que no sea multiplo de
        // cuatro no viene de un emisor que cumpla la norma.
        let d = Diameter;
        let mut b = diameter_cer();
        b[3] = b[3].wrapping_add(1);
        assert!(!d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_DIAMETER)));
    }

    #[test]
    fn saml_declara_que_ve_el_sobre_y_no_la_asercion() {
        // La diferencia entre un informe honesto y uno que parezca completo.
        let d = Saml;
        let b = b"POST /acs HTTP/1.1\r\nHost: idp\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nSAMLResponse=PHNhbWxw&RelayState=x";
        assert!(d.reconoce(b, &Contexto::tcp_cliente(443)));
        let s = d.disecar(b, &Contexto::tcp_cliente(443));
        assert!(
            !s.cobertura.completa(),
            "la asercion no se analiza y la cifra tiene que decirlo"
        );
        let (mec, _, _, res) = autenticacion(&s).expect("una autenticacion");
        assert_eq!(mec, "saml-respuesta");
        assert_eq!(res, "contra /acs");
    }

    #[test]
    fn oauth_lee_la_cabecera_de_un_jwt_sin_creerse_su_firma() {
        // `alg: none` es un ataque entero, y la cabecera es lo unico que hace
        // falta ver para que aparezca en el informe.
        let d = Oauth;
        let b = b"GET /api HTTP/1.1\r\nHost: api\r\nAuthorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.\r\n\r\n";
        let s = d.disecar(b, &Contexto::tcp_cliente(443));
        let (mec, _, _, det) = autenticacion(&s).expect("una autenticacion");
        assert_eq!(mec, "oauth-portador");
        assert!(det.contains("none"), "{det}");
    }

    #[test]
    fn oauth_distingue_el_flujo_de_contrasena_de_los_demas() {
        let d = Oauth;
        let b =
            b"POST /token HTTP/1.1\r\nHost: idp\r\n\r\ngrant_type=password&username=a&password=b";
        let s = d.disecar(b, &Contexto::tcp_cliente(443));
        let (mec, _, _, det) = autenticacion(&s).expect("una autenticacion");
        assert_eq!(mec, "oauth-peticion-de-testigo");
        assert_eq!(det, "contrasena-del-propietario");
    }

    #[test]
    fn los_cinco_de_identidad_emiten_el_mismo_hecho() {
        // La propiedad del modulo: contar intentos por usuario sin importar por
        // donde entro tiene que ser una consulta, no un proyecto.
        let casos: Vec<(Box<dyn Disector>, Vec<u8>)> = vec![
            (Box::new(Ntlm), ntlm_respuesta()),
            (Box::new(Radius), radius_peticion()),
            (Box::new(Diameter), diameter_cer()),
            (
                Box::new(Saml),
                b"POST /acs HTTP/1.1\r\n\r\nSAMLResponse=x".to_vec(),
            ),
            (
                Box::new(Oauth),
                b"POST /token HTTP/1.1\r\n\r\ngrant_type=client_credentials".to_vec(),
            ),
        ];
        for (d, b) in casos {
            let s = d.disecar(&b, &Contexto::tcp_cliente(443));
            assert!(
                autenticacion(&s).is_some(),
                "{} no emitio AutenticacionVista",
                d.nombre()
            );
            assert!(!d.mensajes_que_no_analiza().is_empty(), "{}", d.nombre());
        }
    }
}
