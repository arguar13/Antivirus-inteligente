//! Disector de DNS, con el bucle de compresion cerrado y deteccion de tunel.
//!
//! # El ataque que define este modulo: el puntero que apunta a si mismo
//!
//! DNS comprime los nombres repetidos con punteros: dos bits a uno y catorce de
//! desplazamiento dentro del mensaje. Nada en el formato impide que un puntero
//! apunte **hacia atras a si mismo**, o que dos punteros se apunten
//! mutuamente. Un descompresor escrito de la forma obvia —seguir el puntero y
//! repetir— entra en un **bucle infinito** con un paquete de cuarenta bytes.
//!
//! Es un fallo con historia: ha aparecido una y otra vez en pilas DNS, en
//! analizadores de captura y en IDS. Aqui se cierra con tres cotas a la vez, y
//! las tres hacen falta:
//!
//! 1. **Tope de saltos.** Cada puntero seguido cuenta; pasado el tope, se para.
//! 2. **Progreso estricto hacia atras.** Un puntero solo puede apuntar a una
//!    posicion ESTRICTAMENTE ANTERIOR a la del propio puntero. Con eso, dos
//!    punteros no pueden apuntarse mutuamente ni uno a si mismo.
//! 3. **Tope de longitud del nombre.** 255 bytes, que es lo que la norma
//!    permite. Sin el, una cadena larga de punteros validos construye un nombre
//!    de megabytes.
//!
//! # La tunelizacion se OBSERVA, no se juzga
//!
//! Sacar datos por DNS es una tecnica de exfiltracion clasica: el atacante
//! codifica la informacion en el nombre consultado. Este modulo emite
//! [`crate::hecho::Hecho::IndicioTunelDns`] con **la entropia y la longitud
//! medidas**, y no un veredicto. Quien decide es el arbitro, porque un dominio
//! de una red de distribucion de contenido tiene nombres largos y de alta
//! entropia sin ser un tunel, y ese contexto el disector no lo tiene.

use crate::error::{ErrorDiseccion, Resultado};
use crate::hecho::{Hecho, ProtocoloApp, RespuestaDns};
use crate::lector::Lector;

/// Tope de punteros de compresion seguidos al resolver un nombre.
pub const MAX_SALTOS: usize = 16;

/// Longitud maxima de un nombre, en bytes. Es la de la norma.
pub const MAX_NOMBRE: usize = 255;

/// Longitud maxima de una etiqueta. Tambien de la norma.
pub const MAX_ETIQUETA: usize = 63;

/// Tope de registros que se procesan de un mensaje.
///
/// Las cuentas de la cabecera las escribe el emisor: un mensaje que dice tener
/// sesenta mil respuestas en cien bytes es un intento de hacer iterar al
/// disector. Se procesa lo que de verdad haya, con este tope encima.
pub const MAX_REGISTROS: usize = 256;

/// Longitud de etiqueta a partir de la cual se mira la entropia.
pub const ETIQUETA_SOSPECHOSA: usize = 30;

/// Entropia por caracter a partir de la cual el nombre parece codificado.
///
/// Un dominio en lenguaje natural ronda 3,0-3,5 bits por caracter. Base32 o
/// hexadecimal, que es como se codifica un tunel, pasa de 4,0.
pub const ENTROPIA_SOSPECHOSA: f64 = 4.0;

/// Cabecera de un mensaje DNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cabecera {
    /// Identificador de transaccion.
    pub id: u16,
    /// Si es respuesta.
    pub es_respuesta: bool,
    /// Codigo de operacion.
    pub opcode: u8,
    /// Codigo de respuesta.
    pub rcode: u8,
    /// Preguntas declaradas.
    pub preguntas: u16,
    /// Respuestas declaradas.
    pub respuestas: u16,
    /// Registros de autoridad declarados.
    pub autoridad: u16,
    /// Registros adicionales declarados.
    pub adicionales: u16,
}

impl Cabecera {
    /// Analiza los doce bytes de cabecera.
    ///
    /// # Errores
    /// [`ErrorDiseccion::Truncado`] si el mensaje no llega a doce bytes.
    pub fn analizar(l: &mut Lector<'_>) -> Resultado<Cabecera> {
        let id = l.u16("dns.id")?;
        let banderas = l.u16("dns.banderas")?;
        Ok(Cabecera {
            id,
            es_respuesta: banderas & 0x8000 != 0,
            opcode: ((banderas >> 11) & 0x0F) as u8,
            rcode: (banderas & 0x0F) as u8,
            preguntas: l.u16("dns.qdcount")?,
            respuestas: l.u16("dns.ancount")?,
            autoridad: l.u16("dns.nscount")?,
            adicionales: l.u16("dns.arcount")?,
        })
    }
}

/// Nombre estable de un codigo de respuesta.
#[must_use]
pub fn nombre_rcode(c: u8) -> &'static str {
    match c {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTRO",
    }
}

/// Nombre estable de un tipo de registro.
#[must_use]
pub fn nombre_tipo(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        41 => "OPT",
        43 => "DS",
        48 => "DNSKEY",
        65 => "HTTPS",
        252 => "AXFR",
        255 => "ANY",
        _ => "OTRO",
    }
}

/// Resuelve un nombre desde la posicion actual, siguiendo la compresion.
///
/// Devuelve el nombre y deja el cursor **despues del nombre en su posicion
/// original**, que es lo correcto cuando hubo un puntero: el resto del registro
/// continua tras el puntero, no tras el nombre al que apuntaba.
///
/// # Errores
/// [`ErrorDiseccion::AnidamientoExcesivo`] si se pasan los saltos,
/// [`ErrorDiseccion::LimiteExcedido`] si el nombre resulta mas largo de lo que
/// permite la norma, o los de lectura si el mensaje esta truncado.
pub fn leer_nombre(l: &mut Lector<'_>) -> Resultado<String> {
    let mensaje = l.todo();
    let mut nombre = String::new();
    let mut pos = l.posicion();
    let mut saltos = 0usize;
    let mut fin_original: Option<usize> = None;
    // El limite de progreso: un puntero solo puede ir ESTRICTAMENTE hacia atras
    // respecto del puntero anterior. Empieza en el final del mensaje para que el
    // primer salto pueda ir a cualquier sitio anterior a el.
    let mut tope_puntero = mensaje.len();

    loop {
        let Some(&largo) = mensaje.get(pos) else {
            return Err(ErrorDiseccion::Truncado {
                campo: "dns.etiqueta",
                esperados: 1,
                habia: 0,
            });
        };

        // Puntero de compresion: los dos bits altos a uno.
        if largo & 0xC0 == 0xC0 {
            let Some(&bajo) = mensaje.get(pos + 1) else {
                return Err(ErrorDiseccion::Truncado {
                    campo: "dns.puntero",
                    esperados: 2,
                    habia: 1,
                });
            };
            let destino = (usize::from(largo & 0x3F) << 8) | usize::from(bajo);

            saltos += 1;
            if saltos > MAX_SALTOS {
                return Err(ErrorDiseccion::AnidamientoExcesivo {
                    campo: "dns.puntero",
                    niveles: saltos,
                });
            }
            // PROGRESO ESTRICTO HACIA ATRAS. Esto es lo que impide el bucle: un
            // puntero que apunte a si mismo, hacia delante, o a un sitio ya
            // visitado, no cumple `destino < tope_puntero`.
            if destino >= tope_puntero {
                return Err(ErrorDiseccion::AnidamientoExcesivo {
                    campo: "dns.puntero-sin-progreso",
                    niveles: saltos,
                });
            }
            tope_puntero = destino;

            // La primera vez que se salta, se recuerda donde continuaba el
            // registro: tras los dos bytes del puntero.
            if fin_original.is_none() {
                fin_original = Some(pos + 2);
            }
            pos = destino;
            continue;
        }

        // Los otros dos patrones de bits altos estan reservados y no son
        // longitudes validas. Aceptarlos leeria basura como si fuera un nombre.
        if largo & 0xC0 != 0 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "dns.etiqueta-reservada",
                valor: u64::from(largo),
            });
        }

        let largo = usize::from(largo);
        if largo == 0 {
            // Fin del nombre.
            if fin_original.is_none() {
                fin_original = Some(pos + 1);
            }
            break;
        }
        if largo > MAX_ETIQUETA {
            return Err(ErrorDiseccion::LimiteExcedido {
                campo: "dns.etiqueta",
                valor: largo,
                tope: MAX_ETIQUETA,
            });
        }
        let inicio = pos + 1;
        let fin = inicio + largo;
        let Some(etiqueta) = mensaje.get(inicio..fin) else {
            return Err(ErrorDiseccion::Truncado {
                campo: "dns.etiqueta",
                esperados: largo,
                habia: mensaje.len().saturating_sub(inicio),
            });
        };

        if !nombre.is_empty() {
            nombre.push('.');
        }
        nombre.push_str(&crate::lector::ascii_legible(etiqueta));

        // Tope de longitud total: sin el, una cadena de punteros validos
        // construye un nombre de megabytes.
        if nombre.len() > MAX_NOMBRE {
            return Err(ErrorDiseccion::LimiteExcedido {
                campo: "dns.nombre",
                valor: nombre.len(),
                tope: MAX_NOMBRE,
            });
        }
        pos = fin;
    }

    let fin = fin_original.unwrap_or(pos);
    l.ir_a(fin.min(mensaje.len()), "dns.fin-nombre")?;
    Ok(nombre)
}

/// Entropia de Shannon del texto, en bits por caracter.
///
/// Se calcula sobre las etiquetas sin los puntos: los separadores son
/// estructura, no contenido, e incluirlos rebaja artificialmente la entropia de
/// los nombres con muchos niveles.
#[must_use]
pub fn entropia(texto: &str) -> f64 {
    let bytes: Vec<u8> = texto.bytes().filter(|&b| b != b'.').collect();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut cuenta = [0usize; 256];
    for b in &bytes {
        cuenta[*b as usize] += 1;
    }
    let total = bytes.len() as f64;
    -cuenta
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

/// La etiqueta mas larga de un nombre.
#[must_use]
pub fn etiqueta_mas_larga(nombre: &str) -> usize {
    nombre.split('.').map(str::len).max().unwrap_or(0)
}

/// Analiza un mensaje DNS completo y emite sus hechos.
///
/// Nunca falla hacia fuera: un mensaje que no se puede analizar produce un
/// [`Hecho::NoAnalizable`] con su motivo. Devolver un error y que quien llame lo
/// ignore seria perder la observacion; devolver nada seria confundirla con
/// «estaba limpio».
#[must_use]
pub fn analizar(datos: &[u8]) -> Vec<Hecho> {
    let mut l = Lector::nuevo(datos);
    let cab = match Cabecera::analizar(&mut l) {
        Ok(c) => c,
        Err(e) => return vec![Hecho::no_analizable(ProtocoloApp::Dns, &e)],
    };

    let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Dns)];

    // Las preguntas. La cuenta la escribe el emisor, asi que se acota y se para
    // en cuanto el mensaje real se acabe.
    let n_preguntas = usize::from(cab.preguntas).min(MAX_REGISTROS);
    let mut primera_pregunta = String::new();
    for i in 0..n_preguntas {
        let nombre = match leer_nombre(&mut l) {
            Ok(n) => n,
            Err(e) => {
                hechos.push(Hecho::no_analizable(ProtocoloApp::Dns, &e));
                return hechos;
            }
        };
        let tipo = match l.u16("dns.qtype") {
            Ok(t) => t,
            Err(e) => {
                hechos.push(Hecho::no_analizable(ProtocoloApp::Dns, &e));
                return hechos;
            }
        };
        if l.u16("dns.qclass").is_err() {
            return hechos;
        }
        if i == 0 {
            primera_pregunta = nombre.clone();
        }
        if !cab.es_respuesta {
            hechos.push(Hecho::ConsultaDns {
                id: cab.id,
                nombre: nombre.clone(),
                tipo: nombre_tipo(tipo).to_string(),
            });
        }
        // El indicio de tunel se mide sobre el nombre consultado, que es donde
        // el atacante codifica los datos.
        if let Some(h) = indicio_de_tunel(&nombre) {
            hechos.push(h);
        }
    }

    if !cab.es_respuesta {
        return hechos;
    }

    // Las respuestas.
    let n = usize::from(cab.respuestas).min(MAX_REGISTROS);
    let mut registros = Vec::new();
    for _ in 0..n {
        match leer_registro(&mut l) {
            Ok(r) => registros.push(r),
            // Se para en el primer registro ilegible y se entrega lo que si se
            // leyo: media respuesta es mas util que ninguna, y la parada se
            // anota como no analizable.
            Err(e) => {
                hechos.push(Hecho::no_analizable(ProtocoloApp::Dns, &e));
                break;
            }
        }
    }

    hechos.push(Hecho::RespuestaDns {
        id: cab.id,
        codigo: nombre_rcode(cab.rcode).to_string(),
        registros,
    });
    let _ = primera_pregunta;
    hechos
}

/// Lee un registro de recurso.
fn leer_registro(l: &mut Lector<'_>) -> Resultado<RespuestaDns> {
    let nombre = leer_nombre(l)?;
    let tipo = l.u16("dns.rr.tipo")?;
    let _clase = l.u16("dns.rr.clase")?;
    let ttl = l.u32("dns.rr.ttl")?;
    let datos = l.bloque_u16("dns.rr.rdata")?;

    let valor = match tipo {
        // A
        1 if datos.len() == 4 => format!("{}.{}.{}.{}", datos[0], datos[1], datos[2], datos[3]),
        // AAAA
        28 if datos.len() == 16 => {
            let mut partes = Vec::with_capacity(8);
            for c in datos.chunks_exact(2) {
                partes.push(format!("{:x}", u16::from_be_bytes([c[0], c[1]])));
            }
            partes.join(":")
        }
        // Nombres: se resuelven con compresion, que puede apuntar a cualquier
        // sitio del mensaje. Por eso se lee sobre el mensaje entero.
        2 | 5 | 12 => {
            let inicio = l.posicion().saturating_sub(datos.len());
            let mut sub = Lector::nuevo(l.todo());
            sub.ir_a(inicio, "dns.rr.nombre")?;
            leer_nombre(&mut sub).unwrap_or_else(|_| crate::lector::ascii_legible(datos))
        }
        // TXT: cadenas con longitud por delante.
        16 => {
            let mut sub = Lector::nuevo(datos);
            let mut partes = Vec::new();
            while !sub.vacio() {
                match sub.bloque_u8("dns.txt") {
                    Ok(t) => partes.push(crate::lector::ascii_legible(t)),
                    Err(_) => break,
                }
            }
            partes.join("")
        }
        _ => crate::lector::ascii_legible(datos),
    };

    Ok(RespuestaDns {
        nombre,
        tipo: nombre_tipo(tipo).to_string(),
        valor,
        ttl,
    })
}

/// Mide el nombre y, si parece codificado, emite el indicio con sus numeros.
///
/// No decide: mide. Un dominio de una red de distribucion de contenido tiene
/// nombres largos y de alta entropia sin ser un tunel, y ese contexto lo tiene
/// el arbitro, no el disector.
#[must_use]
pub fn indicio_de_tunel(nombre: &str) -> Option<Hecho> {
    let mayor = etiqueta_mas_larga(nombre);
    if mayor < ETIQUETA_SOSPECHOSA {
        return None;
    }
    let e = entropia(nombre);
    if e < ENTROPIA_SOSPECHOSA {
        return None;
    }
    Some(Hecho::IndicioTunelDns {
        nombre: nombre.to_string(),
        entropia: e,
        etiqueta_mas_larga: mayor,
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Construye un mensaje DNS de verdad, byte a byte.
    fn mensaje(id: u16, banderas: u16, cuerpo: &[u8], cuentas: [u16; 4]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&banderas.to_be_bytes());
        for c in cuentas {
            v.extend_from_slice(&c.to_be_bytes());
        }
        v.extend_from_slice(cuerpo);
        v
    }

    /// Codifica un nombre en el formato de etiquetas de DNS.
    fn nombre_codificado(n: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for etiqueta in n.split('.') {
            v.push(etiqueta.len() as u8);
            v.extend_from_slice(etiqueta.as_bytes());
        }
        v.push(0);
        v
    }

    #[test]
    fn una_consulta_normal_se_lee_entera() {
        let mut cuerpo = nombre_codificado("www.ejemplo.com");
        cuerpo.extend_from_slice(&1u16.to_be_bytes()); // A
        cuerpo.extend_from_slice(&1u16.to_be_bytes()); // IN
        let msg = mensaje(0x1234, 0x0100, &cuerpo, [1, 0, 0, 0]);

        let hechos = analizar(&msg);
        assert!(hechos.contains(&Hecho::ProtocoloIdentificado(ProtocoloApp::Dns)));
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::ConsultaDns { nombre, tipo, id }
                if nombre == "www.ejemplo.com" && tipo == "A" && *id == 0x1234
        )));
    }

    /// EL ATAQUE CLASICO: un puntero de compresion que apunta a si mismo. Un
    /// descompresor escrito de la forma obvia se cuelga con cuarenta bytes.
    #[test]
    fn un_puntero_que_apunta_a_si_mismo_no_cuelga_el_disector() {
        // El puntero esta en el desplazamiento 12 y apunta al 12.
        let cuerpo = vec![0xC0, 0x0C];
        let msg = mensaje(1, 0x0100, &cuerpo, [1, 0, 0, 0]);

        let hechos = analizar(&msg);
        assert!(
            hechos
                .iter()
                .any(|h| matches!(h, Hecho::NoAnalizable { .. })),
            "tiene que rechazarse DICIENDO por que: {hechos:?}"
        );
    }

    /// Y dos punteros que se apuntan mutuamente, que es la version que salta el
    /// tope de saltos ingenuo.
    #[test]
    fn dos_punteros_que_se_apuntan_mutuamente_no_cuelgan() {
        // En 12: puntero a 14. En 14: puntero a 12.
        let cuerpo = vec![0xC0, 0x0E, 0xC0, 0x0C];
        let msg = mensaje(1, 0x0100, &cuerpo, [1, 0, 0, 0]);
        let hechos = analizar(&msg);
        assert!(hechos
            .iter()
            .any(|h| matches!(h, Hecho::NoAnalizable { .. })));
    }

    /// Un puntero hacia DELANTE tampoco vale: permitirlo abre el bucle por el
    /// otro lado.
    #[test]
    fn un_puntero_hacia_delante_se_rechaza() {
        let cuerpo = vec![
            0xC0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let msg = mensaje(1, 0x0100, &cuerpo, [1, 0, 0, 0]);
        let hechos = analizar(&msg);
        assert!(hechos
            .iter()
            .any(|h| matches!(h, Hecho::NoAnalizable { .. })));
    }

    /// La compresion LEGITIMA si tiene que funcionar: si se rompiera, la mitad
    /// del DNS del mundo quedaria sin analizar.
    #[test]
    fn la_compresion_legitima_hacia_atras_funciona() {
        let mut cuerpo = nombre_codificado("ejemplo.com");
        cuerpo.extend_from_slice(&1u16.to_be_bytes());
        cuerpo.extend_from_slice(&1u16.to_be_bytes());
        // Segunda pregunta: "www" + puntero a "ejemplo.com" (desplazamiento 12).
        cuerpo.push(3);
        cuerpo.extend_from_slice(b"www");
        cuerpo.extend_from_slice(&[0xC0, 0x0C]);
        cuerpo.extend_from_slice(&1u16.to_be_bytes());
        cuerpo.extend_from_slice(&1u16.to_be_bytes());

        let msg = mensaje(1, 0x0100, &cuerpo, [2, 0, 0, 0]);
        let hechos = analizar(&msg);
        let nombres: Vec<String> = hechos
            .iter()
            .filter_map(|h| match h {
                Hecho::ConsultaDns { nombre, .. } => Some(nombre.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(nombres, vec!["ejemplo.com", "www.ejemplo.com"]);
    }

    /// Una cuenta de preguntas que MIENTE no hace iterar al disector sesenta mil
    /// veces sobre un mensaje de cien bytes.
    #[test]
    fn una_cuenta_mentirosa_en_la_cabecera_no_hace_iterar_sin_fin() {
        let cuerpo = nombre_codificado("a.com");
        let msg = mensaje(1, 0x0100, &cuerpo, [60_000, 60_000, 60_000, 60_000]);
        let hechos = analizar(&msg);
        assert!(hechos.len() < 100, "hechos = {}", hechos.len());
    }

    #[test]
    fn una_respuesta_con_registros_a_y_aaaa_se_interpreta() {
        let mut cuerpo = nombre_codificado("ejemplo.com");
        cuerpo.extend_from_slice(&1u16.to_be_bytes());
        cuerpo.extend_from_slice(&1u16.to_be_bytes());
        // Registro A.
        cuerpo.extend_from_slice(&[0xC0, 0x0C]);
        cuerpo.extend_from_slice(&1u16.to_be_bytes());
        cuerpo.extend_from_slice(&1u16.to_be_bytes());
        cuerpo.extend_from_slice(&300u32.to_be_bytes());
        cuerpo.extend_from_slice(&4u16.to_be_bytes());
        cuerpo.extend_from_slice(&[93, 184, 216, 34]);

        let msg = mensaje(7, 0x8180, &cuerpo, [1, 1, 0, 0]);
        let hechos = analizar(&msg);
        match hechos
            .iter()
            .find(|h| matches!(h, Hecho::RespuestaDns { .. }))
        {
            Some(Hecho::RespuestaDns {
                codigo,
                registros,
                id,
            }) => {
                assert_eq!(*id, 7);
                assert_eq!(codigo, "NOERROR");
                assert_eq!(registros.len(), 1);
                assert_eq!(registros[0].tipo, "A");
                assert_eq!(registros[0].valor, "93.184.216.34");
                assert_eq!(registros[0].ttl, 300);
            }
            otro => panic!("se esperaba una respuesta: {otro:?}"),
        }
    }

    /// LA MEDIDA DEL TUNEL, contra valores calculados: un nombre en lenguaje
    /// natural NO dispara; uno codificado SI.
    #[test]
    fn un_nombre_normal_no_dispara_el_indicio_y_uno_codificado_si() {
        assert!(indicio_de_tunel("www.google.com").is_none());
        assert!(indicio_de_tunel("correo.empresa.ejemplo.com").is_none());

        // Base32 de datos: etiqueta larga y alta entropia.
        let tunel = "mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho2lqmf2gs33o.tunel.ejemplo.com";
        match indicio_de_tunel(tunel) {
            Some(Hecho::IndicioTunelDns {
                entropia: e,
                etiqueta_mas_larga: m,
                ..
            }) => {
                assert!(e >= ENTROPIA_SOSPECHOSA, "entropia medida = {e}");
                assert!(m >= ETIQUETA_SOSPECHOSA);
            }
            otro => panic!("un nombre codificado tiene que medirse: {otro:?}"),
        }
    }

    /// La entropia contra un valor hecho a mano: cuatro simbolos equiprobables
    /// dan exactamente 2 bits por caracter.
    #[test]
    fn la_entropia_coincide_con_el_valor_calculado_a_mano() {
        assert!((entropia("abcd") - 2.0).abs() < 1e-9);
        assert!((entropia("aabb") - 1.0).abs() < 1e-9);
        assert_eq!(entropia("aaaa"), 0.0);
        assert_eq!(entropia(""), 0.0);
        // Los puntos son estructura y no cuentan.
        assert!((entropia("ab.ab") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn una_etiqueta_mas_larga_de_lo_que_permite_la_norma_se_rechaza() {
        let mut cuerpo = vec![64u8];
        cuerpo.extend_from_slice(&[b'a'; 64]);
        cuerpo.push(0);
        let msg = mensaje(1, 0x0100, &cuerpo, [1, 0, 0, 0]);
        let hechos = analizar(&msg);
        assert!(hechos
            .iter()
            .any(|h| matches!(h, Hecho::NoAnalizable { .. })));
    }

    /// Barrido determinista: ningun mensaje arbitrario puede provocar panico ni
    /// bucle. Se acota el tiempo implicitamente porque la prueba termina.
    #[test]
    fn ningun_mensaje_arbitrario_provoca_panico_ni_bucle() {
        let mut semilla = 0xDEAD_BEEF_CAFE_1234u64;
        for _ in 0..8000 {
            semilla = semilla
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let largo = (semilla >> 32) as usize % 300;
            let datos: Vec<u8> = (0..largo)
                .map(|i| {
                    let s = semilla.wrapping_add(i as u64);
                    (s >> (i % 8)) as u8
                })
                .collect();
            let _ = analizar(&datos);
        }
    }

    #[test]
    fn los_nombres_de_tipo_y_codigo_son_estables() {
        assert_eq!(nombre_tipo(1), "A");
        assert_eq!(nombre_tipo(28), "AAAA");
        assert_eq!(nombre_tipo(252), "AXFR");
        assert_eq!(nombre_tipo(9999), "OTRO");
        assert_eq!(nombre_rcode(0), "NOERROR");
        assert_eq!(nombre_rcode(3), "NXDOMAIN");
    }
}
