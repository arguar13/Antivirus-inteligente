//! Lector DER acotado: certificados X.509, Kerberos y LDAP comparten ASN.1.
//!
//! # Por que este modulo es especialmente peligroso y por que existe
//!
//! Los analizadores de ASN.1 tienen uno de los peores historiales de
//! vulnerabilidades de la informatica: recursion sin fondo, longitudes de
//! tamano arbitrario, etiquetas de varios bytes y estructuras que se anidan
//! entre si. Los fallos famosos de OpenSSL, de las pilas SNMP y de los
//! analizadores de certificados vienen casi todos de aqui.
//!
//! Y no se puede evitar: un certificado X.509 es ASN.1, un ticket Kerberos es
//! ASN.1 y una peticion LDAP es ASN.1. Si el producto quiere ver esas tres
//! cosas, tiene que analizar DER.
//!
//! Asi que se analiza, pero con las cuatro cotas que cierran las cuatro
//! familias de fallo, y **sin recursion**: el recorrido es iterativo con una
//! pila explicita y acotada, de modo que ni el ASN.1 mas anidado del mundo
//! puede agotar la pila del proceso.
//!
//! 1. **Profundidad maxima.** Un `SEQUENCE` dentro de otro dentro de otro, mil
//!    veces, es un desbordamiento de pila en cualquier analizador recursivo.
//! 2. **Longitud acotada.** DER permite codificar la longitud en hasta 126
//!    bytes. Una longitud de 2^64 hace que un analizador ingenuo reserve.
//! 3. **Progreso estricto.** Un elemento de longitud cero dentro de un bucle de
//!    recorrido es un bucle infinito si no se exige avanzar.
//! 4. **Tope de elementos.** Un millon de enteros de un byte es valido y hace
//!    iterar un millon de veces.

use crate::error::{ErrorDiseccion, Resultado};

/// Profundidad maxima de anidamiento.
pub const MAX_PROFUNDIDAD: usize = 32;

/// Bytes maximos que puede ocupar el campo de longitud.
///
/// Ocho bytes ya son 2^64: cualquier cosa por encima es, por construccion, una
/// longitud que no puede caber en la memoria de nadie.
pub const MAX_BYTES_LONGITUD: usize = 8;

/// Tope de elementos que se recorren en un mismo nivel.
pub const MAX_ELEMENTOS: usize = 4096;

/// Clase de una etiqueta ASN.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clase {
    /// Universal: los tipos basicos.
    Universal,
    /// De aplicacion.
    Aplicacion,
    /// Especifica de contexto: los `[0]`, `[1]`... de Kerberos y X.509.
    Contexto,
    /// Privada.
    Privada,
}

/// Un elemento DER: etiqueta, longitud y contenido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elemento<'a> {
    /// Clase de la etiqueta.
    pub clase: Clase,
    /// Si es un tipo construido (contiene otros elementos).
    pub construido: bool,
    /// Numero de etiqueta.
    pub etiqueta: u32,
    /// Contenido, ya acotado.
    pub contenido: &'a [u8],
    /// Bytes totales que ocupo el elemento, cabecera incluida.
    pub total: usize,
}

/// Etiquetas universales que importan.
pub mod etiqueta {
    /// Entero.
    pub const ENTERO: u32 = 0x02;
    /// Cadena de bits.
    pub const CADENA_BITS: u32 = 0x03;
    /// Cadena de octetos.
    pub const CADENA_OCTETOS: u32 = 0x04;
    /// Identificador de objeto.
    pub const OID: u32 = 0x06;
    /// UTF8String.
    pub const UTF8: u32 = 0x0C;
    /// SEQUENCE.
    pub const SECUENCIA: u32 = 0x10;
    /// SET.
    pub const CONJUNTO: u32 = 0x11;
    /// PrintableString.
    pub const IMPRIMIBLE: u32 = 0x13;
    /// IA5String.
    pub const IA5: u32 = 0x16;
    /// UTCTime.
    pub const HORA_UTC: u32 = 0x17;
    /// GeneralizedTime.
    pub const HORA_GENERALIZADA: u32 = 0x18;
    /// GeneralString (Kerberos lo usa mucho).
    pub const GENERAL: u32 = 0x1B;
}

/// Lee UN elemento desde el principio de `datos`.
///
/// # Errores
/// Truncamiento, longitud imposible, o una etiqueta de mas de cuatro bytes.
pub fn leer(datos: &[u8]) -> Resultado<Elemento<'_>> {
    let Some(&primero) = datos.first() else {
        return Err(ErrorDiseccion::Truncado {
            campo: "der.etiqueta",
            esperados: 1,
            habia: 0,
        });
    };

    let clase = match primero >> 6 {
        0 => Clase::Universal,
        1 => Clase::Aplicacion,
        2 => Clase::Contexto,
        _ => Clase::Privada,
    };
    let construido = primero & 0x20 != 0;
    let mut pos = 1usize;
    let mut etiqueta = u32::from(primero & 0x1F);

    // Etiqueta larga: los cinco bits bajos a uno y el numero continua en los
    // bytes siguientes, siete bits por byte. Se acota a cuatro bytes: una
    // etiqueta mas larga que eso no existe en ningun protocolo real y es la via
    // para hacer iterar al lector.
    if etiqueta == 0x1F {
        etiqueta = 0;
        let mut bytes = 0;
        loop {
            let Some(&b) = datos.get(pos) else {
                return Err(ErrorDiseccion::Truncado {
                    campo: "der.etiqueta-larga",
                    esperados: 1,
                    habia: 0,
                });
            };
            pos += 1;
            bytes += 1;
            if bytes > 4 {
                return Err(ErrorDiseccion::LimiteExcedido {
                    campo: "der.etiqueta-larga",
                    valor: bytes,
                    tope: 4,
                });
            }
            etiqueta = (etiqueta << 7) | u32::from(b & 0x7F);
            if b & 0x80 == 0 {
                break;
            }
        }
    }

    // Longitud.
    let Some(&l0) = datos.get(pos) else {
        return Err(ErrorDiseccion::Truncado {
            campo: "der.longitud",
            esperados: 1,
            habia: 0,
        });
    };
    pos += 1;

    let longitud = if l0 & 0x80 == 0 {
        usize::from(l0)
    } else {
        let n = usize::from(l0 & 0x7F);
        if n == 0 {
            // Forma indefinida: valida en BER, PROHIBIDA en DER. Aceptarla
            // obligaria a buscar un terminador, que es otra via de bucle.
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "der.longitud-indefinida",
                valor: 0,
            });
        }
        if n > MAX_BYTES_LONGITUD {
            return Err(ErrorDiseccion::LimiteExcedido {
                campo: "der.bytes-longitud",
                valor: n,
                tope: MAX_BYTES_LONGITUD,
            });
        }
        let mut v: u64 = 0;
        for _ in 0..n {
            let Some(&b) = datos.get(pos) else {
                return Err(ErrorDiseccion::Truncado {
                    campo: "der.longitud",
                    esperados: 1,
                    habia: 0,
                });
            };
            pos += 1;
            v = (v << 8) | u64::from(b);
        }
        usize::try_from(v).map_err(|_| ErrorDiseccion::LimiteExcedido {
            campo: "der.longitud",
            valor: usize::MAX,
            tope: datos.len(),
        })?
    };

    let fin = pos
        .checked_add(longitud)
        .ok_or(ErrorDiseccion::LongitudImposible {
            campo: "der.contenido",
            declarada: longitud,
            disponible: datos.len().saturating_sub(pos),
        })?;
    if fin > datos.len() {
        return Err(ErrorDiseccion::LongitudImposible {
            campo: "der.contenido",
            declarada: longitud,
            disponible: datos.len().saturating_sub(pos),
        });
    }

    Ok(Elemento {
        clase,
        construido,
        etiqueta,
        contenido: &datos[pos..fin],
        total: fin,
    })
}

/// Recorre los elementos de un mismo nivel.
///
/// # Errores
/// Los de [`leer`]; ademas para si un elemento no hace progresar el cursor.
pub fn hijos(datos: &[u8]) -> Resultado<Vec<Elemento<'_>>> {
    let mut salida = Vec::new();
    let mut pos = 0usize;
    while pos < datos.len() {
        if salida.len() >= MAX_ELEMENTOS {
            return Err(ErrorDiseccion::LimiteExcedido {
                campo: "der.elementos",
                valor: salida.len(),
                tope: MAX_ELEMENTOS,
            });
        }
        let e = leer(&datos[pos..])?;
        // PROGRESO ESTRICTO. Un elemento cuya cabecera ocupa cero bytes no
        // existe, pero si alguna vez lo hiciera este bucle no avanzaria.
        if e.total == 0 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "der.sin-progreso",
                valor: 0,
            });
        }
        pos += e.total;
        salida.push(e);
    }
    Ok(salida)
}

/// Busca, **sin recursion**, el primer elemento que cumpla `predicado`.
///
/// El recorrido usa una pila explicita acotada por [`MAX_PROFUNDIDAD`], de modo
/// que un ASN.1 anidado a proposito no puede agotar la pila del proceso — que es
/// como se rompen los analizadores recursivos.
pub fn buscar<'a, F>(datos: &'a [u8], predicado: F) -> Option<Elemento<'a>>
where
    F: Fn(&Elemento<'a>) -> bool,
{
    let mut pila: Vec<(&[u8], usize)> = vec![(datos, 0)];
    while let Some((nivel, profundidad)) = pila.pop() {
        if profundidad > MAX_PROFUNDIDAD {
            continue;
        }
        let Ok(elementos) = hijos(nivel) else {
            continue;
        };
        for e in elementos {
            if predicado(&e) {
                return Some(e);
            }
            if e.construido {
                pila.push((e.contenido, profundidad + 1));
            }
        }
    }
    None
}

/// Todos los textos legibles de un elemento, en orden, sin recursion.
///
/// Sirve para sacar el sujeto y el emisor de un certificado sin implementar el
/// modelo completo de nombres X.500, que es enorme y que no aporta nada al
/// veredicto: lo que interesa es el texto que un analista va a leer.
#[must_use]
pub fn textos(datos: &[u8], tope: usize) -> Vec<String> {
    let mut salida = Vec::new();
    // Pila de (nivel, profundidad). El orden de exploracion se mantiene estable
    // procesando los hijos en orden inverso al apilarlos.
    let mut pila: Vec<(&[u8], usize)> = vec![(datos, 0)];
    while let Some((nivel, profundidad)) = pila.pop() {
        if profundidad > MAX_PROFUNDIDAD || salida.len() >= tope {
            continue;
        }
        let Ok(elementos) = hijos(nivel) else {
            continue;
        };
        let mut anidados = Vec::new();
        for e in elementos {
            if salida.len() >= tope {
                break;
            }
            match e.etiqueta {
                etiqueta::UTF8 | etiqueta::IMPRIMIBLE | etiqueta::IA5 | etiqueta::GENERAL
                    if e.clase == Clase::Universal && !e.construido =>
                {
                    let t = crate::lector::ascii_legible(e.contenido);
                    if !t.is_empty() {
                        salida.push(t);
                    }
                }
                _ if e.construido => anidados.push((e.contenido, profundidad + 1)),
                _ => {}
            }
        }
        // Se apilan al reves para que salgan en el orden en que aparecen.
        for a in anidados.into_iter().rev() {
            pila.push(a);
        }
    }
    salida
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Construye un elemento DER de verdad.
    fn der(etiqueta: u8, contenido: &[u8]) -> Vec<u8> {
        let mut v = vec![etiqueta];
        if contenido.len() < 0x80 {
            v.push(contenido.len() as u8);
        } else {
            let bytes = contenido.len().to_be_bytes();
            let primero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
            let usados = &bytes[primero..];
            v.push(0x80 | usados.len() as u8);
            v.extend_from_slice(usados);
        }
        v.extend_from_slice(contenido);
        v
    }

    #[test]
    fn un_entero_corto_se_lee_entero() {
        let d = der(0x02, &[0x2A]);
        let e = leer(&d).unwrap();
        assert_eq!(e.clase, Clase::Universal);
        assert_eq!(e.etiqueta, etiqueta::ENTERO);
        assert!(!e.construido);
        assert_eq!(e.contenido, &[0x2A]);
        assert_eq!(e.total, 3);
    }

    #[test]
    fn una_secuencia_se_recorre_y_sus_hijos_salen_en_orden() {
        let dentro = [der(0x02, &[1]), der(0x02, &[2]), der(0x02, &[3])].concat();
        let d = der(0x30, &dentro);
        let seq = leer(&d).unwrap();
        assert!(seq.construido);
        let h = hijos(seq.contenido).unwrap();
        assert_eq!(h.len(), 3);
        assert_eq!(h[0].contenido, &[1]);
        assert_eq!(h[2].contenido, &[3]);
    }

    #[test]
    fn una_longitud_larga_se_lee_bien() {
        let contenido = vec![0xAAu8; 300];
        let d = der(0x04, &contenido);
        let e = leer(&d).unwrap();
        assert_eq!(e.contenido.len(), 300);
    }

    /// EL ATAQUE DE RESERVA: una longitud de 2^64 no puede hacer que el lector
    /// reserve nada.
    #[test]
    fn una_longitud_absurda_se_rechaza_sin_reservar() {
        // 0x88 = forma larga con 8 bytes de longitud, todos 0xFF.
        let d = vec![0x04, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(leer(&d).is_err());

        // Y una forma larga con mas bytes de longitud de los que pueden existir.
        let d = vec![0x04, 0xFF];
        assert!(matches!(
            leer(&d),
            Err(ErrorDiseccion::LimiteExcedido { .. })
        ));
    }

    /// La forma indefinida es valida en BER y PROHIBIDA en DER. Aceptarla
    /// obligaria a buscar un terminador, que es otra via de bucle.
    #[test]
    fn la_forma_indefinida_de_ber_se_rechaza() {
        let d = vec![0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00];
        assert!(matches!(
            leer(&d),
            Err(ErrorDiseccion::ValorInvalido {
                campo: "der.longitud-indefinida",
                ..
            })
        ));
    }

    /// EL ATAQUE DE PILA: mil secuencias anidadas. Un analizador recursivo se
    /// desborda; este recorre con pila explicita acotada.
    #[test]
    fn mil_secuencias_anidadas_no_desbordan_la_pila() {
        let mut d = der(0x02, &[1]);
        for _ in 0..1000 {
            d = der(0x30, &d);
        }
        // No puede entrar en panico ni desbordarse: o encuentra algo, o no.
        let _ = buscar(&d, |e| e.etiqueta == etiqueta::ENTERO);
        let _ = textos(&d, 10);
    }

    /// Y el anidamiento por debajo del tope SI se explora: una cota que corta
    /// demasiado pronto seria ceguera disfrazada de robustez.
    #[test]
    fn el_anidamiento_razonable_si_se_explora() {
        let mut d = der(0x0C, b"encontrado");
        for _ in 0..10 {
            d = der(0x30, &d);
        }
        let ts = textos(&d, 10);
        assert_eq!(ts, vec!["encontrado"]);
    }

    #[test]
    fn los_textos_salen_en_el_orden_en_que_aparecen() {
        let dentro = [
            der(0x13, b"primero"),
            der(0x0C, b"segundo"),
            der(0x30, &der(0x16, b"tercero")),
        ]
        .concat();
        let d = der(0x30, &dentro);
        let e = leer(&d).unwrap();
        assert_eq!(
            textos(e.contenido, 10),
            vec!["primero", "segundo", "tercero"]
        );
    }

    #[test]
    fn una_etiqueta_larga_desmesurada_se_rechaza() {
        // 0x1F abre etiqueta larga; luego bytes con el bit alto puesto sin fin.
        let d = vec![0x3F, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00];
        assert!(leer(&d).is_err());
    }

    #[test]
    fn el_tope_de_elementos_corta_una_avalancha() {
        let mut dentro = Vec::new();
        for _ in 0..(MAX_ELEMENTOS + 100) {
            dentro.extend_from_slice(&der(0x02, &[1]));
        }
        assert!(matches!(
            hijos(&dentro),
            Err(ErrorDiseccion::LimiteExcedido { .. })
        ));
    }

    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico() {
        let mut semilla = 0xF0E1_D2C3_B4A5_9687u64;
        for _ in 0..10_000 {
            semilla = semilla
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let largo = (semilla >> 32) as usize % 200;
            let datos: Vec<u8> = (0..largo).map(|i| (semilla >> (i % 8)) as u8).collect();
            let _ = leer(&datos);
            let _ = hijos(&datos);
            let _ = buscar(&datos, |e| e.etiqueta == 0x10);
            let _ = textos(&datos, 20);
        }
    }
}
