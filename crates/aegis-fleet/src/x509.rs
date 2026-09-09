//! Lectura minima de DER para extraer el `subject CN` de un certificado.
//!
//! `rustls` autentica que el certificado del par esta firmado por la CA de la
//! flota, pero no expone su `subject`. El plano de control necesita la identidad
//! (el CN) para ligar la sesion autenticada a un agente concreto y evitar que un
//! agente con certificado valido se haga pasar por otro. Aqui se camina la
//! estructura ASN.1 justa —sin dependencias de parsers— hasta el `subject`, y se
//! extrae su `CommonName`.
//!
//! ```text
//! Certificate  ::= SEQUENCE { tbsCertificate SEQUENCE { ... }, ... }
//! TBSCertificate ::= SEQUENCE {
//!     version        [0] EXPLICIT  (opcional)
//!     serialNumber   INTEGER
//!     signature      SEQUENCE
//!     issuer         Name (SEQUENCE)
//!     validity       SEQUENCE
//!     subject        Name (SEQUENCE)   <-- el que se busca
//!     ... }
//! ```

/// OID de `commonName` (2.5.4.3), codificado sin la cabecera de tipo/longitud.
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

/// Un elemento DER: su etiqueta, y el rango de su contenido dentro del buffer.
struct Elemento {
    etiqueta: u8,
    inicio: usize,
    fin: usize,
    /// Posicion del primer byte DESPUES de este elemento (para iterar hermanos).
    siguiente: usize,
}

/// Lee un elemento DER en `datos[pos..]`: etiqueta, longitud y contenido.
fn leer_elemento(datos: &[u8], pos: usize) -> Option<Elemento> {
    let etiqueta = *datos.get(pos)?;
    let primer_len = *datos.get(pos + 1)?;
    let (long, inicio_contenido) = if primer_len & 0x80 == 0 {
        // Forma corta: la longitud cabe en un byte.
        (primer_len as usize, pos + 2)
    } else {
        // Forma larga: los 7 bits bajos dicen cuantos bytes siguen con la
        // longitud real.
        let n = (primer_len & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut long = 0usize;
        for i in 0..n {
            long = (long << 8) | (*datos.get(pos + 2 + i)? as usize);
        }
        (long, pos + 2 + n)
    };
    let fin = inicio_contenido.checked_add(long)?;
    if fin > datos.len() {
        return None;
    }
    Some(Elemento {
        etiqueta,
        inicio: inicio_contenido,
        fin,
        siguiente: fin,
    })
}

/// Extrae el `CommonName` del `subject` de un certificado en DER.
///
/// Devuelve `None` si el certificado no se puede recorrer o no tiene CN.
pub fn subject_cn(cert_der: &[u8]) -> Option<String> {
    // Certificate ::= SEQUENCE
    let cert = leer_elemento(cert_der, 0)?;
    if cert.etiqueta != 0x30 {
        return None;
    }
    // tbsCertificate ::= SEQUENCE (primer hijo)
    let tbs = leer_elemento(cert_der, cert.inicio)?;
    if tbs.etiqueta != 0x30 {
        return None;
    }

    // Recorrer los hijos de tbsCertificate en orden para llegar al `subject`.
    let mut pos = tbs.inicio;
    let mut idx_secuencias = 0; // cuenta las SEQUENCE de nivel superior del tbs

    while pos < tbs.fin {
        let el = leer_elemento(cert_der, pos)?;
        // Saltar la version opcional [0] (etiqueta de contexto 0xA0).
        if el.etiqueta == 0xa0 {
            pos = el.siguiente;
            continue;
        }
        if el.etiqueta == 0x30 {
            idx_secuencias += 1;
            // Orden de las SEQUENCE tras (opcional) version y el INTEGER de
            // serie: 1=signature, 2=issuer, 3=validity, 4=subject.
            if idx_secuencias == 4 {
                return cn_en_nombre(cert_der, el.inicio, el.fin);
            }
        }
        pos = el.siguiente;
    }
    None
}

/// Busca el CN dentro de un `Name` (RDNSequence), delimitado por `[inicio,fin)`.
fn cn_en_nombre(datos: &[u8], inicio: usize, fin: usize) -> Option<String> {
    let mut pos = inicio;
    while pos + 5 <= fin {
        // Un AttributeTypeAndValue empieza por el OID: 06 03 55 04 03.
        if datos[pos] == 0x06
            && datos.get(pos + 1) == Some(&0x03)
            && &datos[pos + 2..pos + 5] == OID_CN
        {
            // Tras el OID viene el valor: una cadena (UTF8String 0x0c o
            // PrintableString 0x13).
            let val = leer_elemento(datos, pos + 5)?;
            if matches!(val.etiqueta, 0x0c | 0x13 | 0x14 | 0x16) {
                return std::str::from_utf8(&datos[val.inicio..val.fin])
                    .ok()
                    .map(|s| s.to_string());
            }
        }
        pos += 1;
    }
    None
}
