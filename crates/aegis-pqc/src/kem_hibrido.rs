//! Combinador de KEM hibrido `X25519MLKEM768`.
//!
//! # Por que combinar y no elegir
//!
//! ML-KEM es joven; podria tener un fallo aun no descubierto. X25519 es viejo y
//! muy escrutado, pero caera ante una computadora cuantica. Combinarlos da un
//! canal seguro si aguanta **cualquiera de los dos**: un atacante clasico tiene
//! que romper X25519 (imposible hoy) y uno cuantico tiene que romper ML-KEM
//! (cuya seguridad es la apuesta del NIST). Es el consenso de la industria.
//!
//! # El combinador esta ATADO AL TRANSCRIPT
//!
//! No basta con concatenar los dos secretos y hashear: eso permitiria a un
//! atacante reutilizar piezas de otra sesion (reflexion, mezcla). El secreto de
//! sesion sale de
//!
//! ```text
//!   HKDF-SHA256( x25519_ss || mlkem768_ss || transcript )
//! ```
//!
//! donde el `transcript` incluye la suite y TODO el material publico de la
//! sesion: las claves publicas del receptor y el encapsulado del iniciador. Asi
//! el secreto queda atado a ESTA sesion y a ESTE orden. La prueba de binding
//! verifica que cambiar cualquiera de los dos secretos, su orden, o el
//! transcript, cambia el secreto derivado.
//!
//! # Forma de uso (estilo HPKE, RFC 9180)
//!
//! El **receptor** publica su clave publica hibrida. El **iniciador** encapsula
//! contra ella (generando una X25519 efimera y encapsulando ML-KEM), obtiene un
//! secreto de sesion y envia el [`EncapsuladoHibrido`]. El receptor desencapsula
//! y obtiene el mismo secreto. En AegisCore esta capa va POR ENCIMA del mTLS
//! existente (defensa en profundidad), no en su lugar.

use crate::kem::{self, ClavePublica, ClaveSecreta, TextoCifrado};
use crate::suite::SuiteKem;
use crate::PqcError;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Longitud de una clave/valor publico X25519.
pub const X25519_LEN: usize = 32;
/// Longitud del secreto de sesion que produce el combinador.
pub const SECRETO_SESION_LEN: usize = 32;
/// Longitud serializada de la clave publica hibrida (X25519 || ML-KEM ek).
pub const CLAVE_PUBLICA_LEN: usize = X25519_LEN + kem::PK_LEN;
/// Longitud serializada del encapsulado hibrido (X25519 efimera || ML-KEM ct).
pub const ENCAPSULADO_LEN: usize = X25519_LEN + kem::CT_LEN;

// Dominios de separacion del HKDF. Cambiarlos es un cambio de suite (agilidad).
const ETIQUETA_SALT: &[u8] = b"AegisCore/PQC/X25519MLKEM768/v1";
const ETIQUETA_INFO: &[u8] = b"clave-de-sesion";

/// Secreto de sesion de 32 bytes, salida del combinador. Material secreto: se
/// limpia al soltarse.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretoSesion([u8; SECRETO_SESION_LEN]);

impl SecretoSesion {
    /// Vista de los 32 bytes del secreto de sesion.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRETO_SESION_LEN] {
        &self.0
    }
}

/// Clave publica hibrida del receptor: una X25519 y una ML-KEM-768.
#[derive(Clone)]
pub struct ClavePublicaHibrida {
    x25519: [u8; X25519_LEN],
    mlkem: ClavePublica,
}

impl ClavePublicaHibrida {
    /// Serializa como `x25519_pk (32) || mlkem_ek (1184)`.
    #[must_use]
    pub fn a_bytes(&self) -> [u8; CLAVE_PUBLICA_LEN] {
        let mut out = [0u8; CLAVE_PUBLICA_LEN];
        out[..X25519_LEN].copy_from_slice(&self.x25519);
        out[X25519_LEN..].copy_from_slice(self.mlkem.as_bytes());
        out
    }

    /// Reconstruye desde el formato de wire.
    ///
    /// # Errores
    /// [`PqcError::TamanoInvalido`] si `bytes` no mide [`CLAVE_PUBLICA_LEN`].
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != CLAVE_PUBLICA_LEN {
            return Err(PqcError::TamanoInvalido {
                campo: "clave publica hibrida",
                esperado: CLAVE_PUBLICA_LEN,
                recibido: bytes.len(),
            });
        }
        let mut x25519 = [0u8; X25519_LEN];
        x25519.copy_from_slice(&bytes[..X25519_LEN]);
        let mlkem = ClavePublica::desde_bytes(&bytes[X25519_LEN..])?;
        Ok(Self { x25519, mlkem })
    }

    /// Encapsula contra esta clave publica, tomando la aleatoriedad del sistema.
    ///
    /// Devuelve el encapsulado que hay que enviar al receptor y el secreto de
    /// sesion compartido.
    ///
    /// # Errores
    /// [`PqcError::Entropia`] si no hay entropia; [`PqcError::MaterialInvalido`]
    /// si la clave publica ML-KEM no es valida.
    pub fn encapsular_aleatorio(&self) -> Result<(EncapsuladoHibrido, SecretoSesion), PqcError> {
        // X25519 efimera: escalar aleatorio del sistema.
        let mut escalar = [0u8; X25519_LEN];
        getrandom::getrandom(&mut escalar).map_err(|_| PqcError::Entropia)?;
        let efimera = X25519Secret::from(escalar);
        escalar.zeroize();
        let efimera_pub = X25519Public::from(&efimera).to_bytes();
        let x25519_ss = efimera.diffie_hellman(&X25519Public::from(self.x25519));

        // ML-KEM contra la clave publica del receptor.
        let (ct, mlkem_ss) = kem::encapsular_aleatorio(&self.mlkem)?;

        let enc = EncapsuladoHibrido {
            x25519_eph: efimera_pub,
            mlkem_ct: ct,
        };
        let transcript = self.transcript(&enc.x25519_eph, &enc.mlkem_ct);
        let ss = combinar(x25519_ss.as_bytes(), mlkem_ss.as_bytes(), &transcript);
        Ok((enc, ss))
    }

    /// Transcript atado a la sesion: suite, claves publicas del receptor, y el
    /// encapsulado del iniciador. Es lo que hace el binding del secreto.
    fn transcript(&self, x25519_eph: &[u8; X25519_LEN], ct: &TextoCifrado) -> Vec<u8> {
        let mut t = Vec::with_capacity(1 + CLAVE_PUBLICA_LEN + ENCAPSULADO_LEN);
        t.push(SuiteKem::X25519MlKem768.as_u8());
        t.extend_from_slice(&self.x25519);
        t.extend_from_slice(self.mlkem.as_bytes());
        t.extend_from_slice(x25519_eph);
        t.extend_from_slice(ct.as_bytes());
        t
    }
}

/// Par de claves hibrido del receptor (X25519 estatica + ML-KEM-768).
pub struct ParHibrido {
    /// Clave publica, que se entrega al iniciador.
    pub publica: ClavePublicaHibrida,
    x25519_sk: X25519Secret,
    mlkem_sk: ClaveSecreta,
}

impl ParHibrido {
    /// Genera un par hibrido tomando la entropia del sistema.
    ///
    /// # Errores
    /// [`PqcError::Entropia`] si el sistema no puede entregar aleatoriedad.
    pub fn generar_aleatorio() -> Result<Self, PqcError> {
        let mut escalar = [0u8; X25519_LEN];
        getrandom::getrandom(&mut escalar).map_err(|_| PqcError::Entropia)?;
        let x25519_sk = X25519Secret::from(escalar);
        escalar.zeroize();
        let x25519 = X25519Public::from(&x25519_sk).to_bytes();

        let (mlkem_pub, mlkem_sk) = kem::ParClaves::generar_aleatorio()?.into_partes();

        Ok(Self {
            publica: ClavePublicaHibrida {
                x25519,
                mlkem: mlkem_pub,
            },
            x25519_sk,
            mlkem_sk,
        })
    }

    /// Desencapsula un [`EncapsuladoHibrido`] y obtiene el secreto de sesion.
    ///
    /// No falla: si el encapsulado viene manipulado, ML-KEM aplica rechazo
    /// implicito y el secreto derivado simplemente no coincidira con el del
    /// iniciador, cosa que la capa superior detecta al no poder descifrar.
    #[must_use]
    pub fn desencapsular(&self, enc: &EncapsuladoHibrido) -> SecretoSesion {
        let x25519_ss = self
            .x25519_sk
            .diffie_hellman(&X25519Public::from(enc.x25519_eph));
        let mlkem_ss = kem::desencapsular(&self.mlkem_sk, &enc.mlkem_ct);
        let transcript = self.publica.transcript(&enc.x25519_eph, &enc.mlkem_ct);
        combinar(x25519_ss.as_bytes(), mlkem_ss.as_bytes(), &transcript)
    }
}

/// Encapsulado hibrido que viaja del iniciador al receptor.
#[derive(Clone)]
pub struct EncapsuladoHibrido {
    x25519_eph: [u8; X25519_LEN],
    mlkem_ct: TextoCifrado,
}

impl EncapsuladoHibrido {
    /// Serializa como `x25519_eph (32) || mlkem_ct (1088)`.
    #[must_use]
    pub fn a_bytes(&self) -> [u8; ENCAPSULADO_LEN] {
        let mut out = [0u8; ENCAPSULADO_LEN];
        out[..X25519_LEN].copy_from_slice(&self.x25519_eph);
        out[X25519_LEN..].copy_from_slice(self.mlkem_ct.as_bytes());
        out
    }

    /// Reconstruye desde el formato de wire.
    ///
    /// # Errores
    /// [`PqcError::TamanoInvalido`] si `bytes` no mide [`ENCAPSULADO_LEN`].
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ENCAPSULADO_LEN {
            return Err(PqcError::TamanoInvalido {
                campo: "encapsulado hibrido",
                esperado: ENCAPSULADO_LEN,
                recibido: bytes.len(),
            });
        }
        let mut x25519_eph = [0u8; X25519_LEN];
        x25519_eph.copy_from_slice(&bytes[..X25519_LEN]);
        let mlkem_ct = TextoCifrado::desde_bytes(&bytes[X25519_LEN..])?;
        Ok(Self {
            x25519_eph,
            mlkem_ct,
        })
    }
}

/// El combinador: deriva un secreto de 32 bytes a partir de los dos secretos
/// (clasico y PQC) atados al transcript.
///
/// `HKDF-SHA256(salt, x25519_ss || mlkem768_ss || transcript)`. El orden es
/// parte del binding: intercambiar los dos secretos produce un resultado
/// distinto.
#[must_use]
pub fn combinar(x25519_ss: &[u8; 32], mlkem_ss: &[u8; 32], transcript: &[u8]) -> SecretoSesion {
    let mut ikm = Vec::with_capacity(64 + transcript.len());
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(mlkem_ss);
    ikm.extend_from_slice(transcript);

    let hk = Hkdf::<Sha256>::new(Some(ETIQUETA_SALT), &ikm);
    let mut okm = [0u8; SECRETO_SESION_LEN];
    hk.expand(ETIQUETA_INFO, &mut okm)
        .expect("32 bytes estan dentro del limite de HKDF-SHA256");
    ikm.zeroize();
    SecretoSesion(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn acuerdo_de_secreto_iniciador_receptor() {
        let receptor = ParHibrido::generar_aleatorio().expect("entropia");
        let (enc, ss_iniciador) = receptor.publica.encapsular_aleatorio().expect("encapsular");
        let ss_receptor = receptor.desencapsular(&enc);
        assert_eq!(
            ss_iniciador.as_bytes(),
            ss_receptor.as_bytes(),
            "ambos lados deben derivar el mismo secreto de sesion"
        );
    }

    #[test]
    fn serializacion_de_clave_y_encapsulado() {
        let receptor = ParHibrido::generar_aleatorio().expect("entropia");
        let pk_bytes = receptor.publica.a_bytes();
        assert_eq!(pk_bytes.len(), CLAVE_PUBLICA_LEN);
        let pk = ClavePublicaHibrida::desde_bytes(&pk_bytes).expect("pk");
        let (enc, _) = pk.encapsular_aleatorio().expect("encaps");
        let enc_bytes = enc.a_bytes();
        assert_eq!(enc_bytes.len(), ENCAPSULADO_LEN);
        // Roundtrip de wire: serializar y reconstruir da los mismos bytes.
        let enc2 = EncapsuladoHibrido::desde_bytes(&enc_bytes).expect("enc");
        assert_eq!(enc_bytes, enc2.a_bytes());
    }

    #[test]
    fn binding_cambiar_cualquier_entrada_cambia_el_secreto() {
        let x = [1u8; 32];
        let m = [2u8; 32];
        let t = b"transcript".to_vec();

        let base = *combinar(&x, &m, &t).as_bytes();

        // Cambiar el secreto clasico.
        let mut x2 = x;
        x2[0] ^= 0x01;
        assert_ne!(base, *combinar(&x2, &m, &t).as_bytes());

        // Cambiar el secreto PQC.
        let mut m2 = m;
        m2[0] ^= 0x01;
        assert_ne!(base, *combinar(&x, &m2, &t).as_bytes());

        // Cambiar el transcript.
        let mut t2 = t.clone();
        t2.push(0xFF);
        assert_ne!(base, *combinar(&x, &m, &t2).as_bytes());

        // Intercambiar el ORDEN de los dos secretos (x != m) cambia el resultado.
        assert_ne!(base, *combinar(&m, &x, &t).as_bytes());
    }

    #[test]
    fn encapsulado_manipulado_rompe_el_acuerdo() {
        let receptor = ParHibrido::generar_aleatorio().expect("entropia");
        let (enc, ss_iniciador) = receptor.publica.encapsular_aleatorio().expect("encaps");

        // Voltear un bit del componente X25519 del encapsulado.
        let mut bytes = enc.a_bytes();
        bytes[0] ^= 0x01;
        let enc_malo = EncapsuladoHibrido::desde_bytes(&bytes).expect("tamano");
        let ss_malo = receptor.desencapsular(&enc_malo);
        assert_ne!(
            ss_iniciador.as_bytes(),
            ss_malo.as_bytes(),
            "un encapsulado manipulado no debe producir el mismo secreto"
        );
    }

    #[test]
    fn kat_x25519_rfc7748() {
        // RFC 7748, seccion 5.2, primer vector de prueba de X25519. Ancla de
        // honestidad del primitivo CLASICO del hibrido.
        let escalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let esperado = hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        let mut e = [0u8; 32];
        e.copy_from_slice(&escalar);
        let mut uu = [0u8; 32];
        uu.copy_from_slice(&u);

        let sk = X25519Secret::from(e);
        let ss = sk.diffie_hellman(&X25519Public::from(uu));
        assert_eq!(ss.as_bytes()[..], esperado[..], "X25519 RFC 7748");
    }
}
