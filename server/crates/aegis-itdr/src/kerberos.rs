//! Modelo de Kerberos y parser DER de tickets (RFC 4120).
//!
//! Dos fuentes de verdad alimentan los detectores:
//!
//! - Los **eventos de la KDC** ([`EventoKdc`]): lo que un Controlador de Dominio
//!   registra al emitir tickets (en Windows, los eventos 4768/4769/4770 del
//!   Registro de Seguridad). Es la fuente de mas senal para Kerberoasting y
//!   Golden Ticket, y la que usa cualquier SIEM serio.
//! - El **uso de tickets en el servicio** ([`UsoServicio`]): un ticket de
//!   servicio presentado a un recurso. Es lo que delata un Silver Ticket, porque
//!   un Silver Ticket **nunca pasa por la KDC** y por tanto no deja un 4769.
//!
//! Y para leer un ticket tal cual viaja por el cable, [`ticket_desde_der`]
//! decodifica la estructura `Ticket` de RFC 4120 **byte a byte**, sin librerias
//! externas de ASN.1: extrae el realm, el SPN y —lo que importa para detectar el
//! degradado— el **tipo de cifrado**. Se parsea solo el sobre en claro del
//! ticket (version, realm, sname, y el `etype` de `enc-part`); la parte cifrada
//! con la clave del servicio no se toca porque no se puede.

use crate::ItdrError;

/// Tipo de cifrado de un ticket Kerberos (los `etype` de RFC 3961, tal como
/// aparecen en el campo "Ticket Encryption Type" del evento 4769 de Windows).
///
/// La distincion que importa para la deteccion: **RC4 es crackeable offline**
/// mucho mas rapido que AES, asi que un atacante que va a robar un ticket para
/// romperlo pide RC4 a proposito (un "degradado"). DES esta roto de fabrica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TipoCifrado {
    /// `des-cbc-crc` (etype 1). Legado, roto.
    DesCbcCrc,
    /// `des-cbc-md5` (etype 3). Legado, roto.
    DesCbcMd5,
    /// `aes128-cts-hmac-sha1-96` (etype 17). Fuerte.
    Aes128,
    /// `aes256-cts-hmac-sha1-96` (etype 18). Fuerte.
    Aes256,
    /// `rc4-hmac` (etype 23). El favorito del Kerberoasting: se craquea offline.
    Rc4Hmac,
    /// `rc4-hmac-exp` (etype 24). RC4 "exportable", igual de degradado.
    Rc4HmacExp,
    /// Cualquier otro identificador, conservado tal cual para no perder telemetria.
    Otro(i32),
}

impl TipoCifrado {
    /// Construye el tipo a partir del identificador numerico `etype`.
    #[must_use]
    pub fn desde_id(id: i32) -> Self {
        match id {
            1 => Self::DesCbcCrc,
            3 => Self::DesCbcMd5,
            17 => Self::Aes128,
            18 => Self::Aes256,
            23 => Self::Rc4Hmac,
            24 => Self::Rc4HmacExp,
            otro => Self::Otro(otro),
        }
    }

    /// El identificador numerico `etype` de este cifrado.
    #[must_use]
    pub fn id(&self) -> i32 {
        match self {
            Self::DesCbcCrc => 1,
            Self::DesCbcMd5 => 3,
            Self::Aes128 => 17,
            Self::Aes256 => 18,
            Self::Rc4Hmac => 23,
            Self::Rc4HmacExp => 24,
            Self::Otro(x) => *x,
        }
    }

    /// `true` si es alguna variante de RC4 (crackeable offline con rapidez).
    #[must_use]
    pub fn es_rc4(&self) -> bool {
        matches!(self, Self::Rc4Hmac | Self::Rc4HmacExp)
    }

    /// `true` si es AES (el cifrado fuerte que un dominio moderno espera).
    #[must_use]
    pub fn es_aes(&self) -> bool {
        matches!(self, Self::Aes128 | Self::Aes256)
    }

    /// `true` si el cifrado es debil (RC4 o DES): un ticket asi es material
    /// apto para crackear.
    #[must_use]
    pub fn es_debil(&self) -> bool {
        matches!(
            self,
            Self::DesCbcCrc | Self::DesCbcMd5 | Self::Rc4Hmac | Self::Rc4HmacExp
        )
    }
}

/// Clase de evento que registra la KDC. Se corresponde con los eventos del
/// Registro de Seguridad de Windows en un Controlador de Dominio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TipoEventoKdc {
    /// Se pidio un TGT: el usuario se autentico (evento 4768, `AS-REQ`).
    SolicitudTgt,
    /// Se pidio un ticket de servicio (evento 4769, `TGS-REQ`).
    SolicitudServicio,
    /// Se renovo un TGT (evento 4770).
    RenovacionTgt,
    /// Fallo la preautenticacion (evento 4771): util para detectar rociado de
    /// contrasenas, aunque los detectores de esta fase no lo consumen aun.
    PreautenticacionFallida,
}

/// Un evento de la KDC, normalizado desde el Registro de Seguridad / ETW.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EventoKdc {
    /// Que clase de operacion de Kerberos.
    pub tipo: TipoEventoKdc,
    /// Cuenta que hace la peticion (`cname`).
    pub cuenta: String,
    /// SPN del servicio pedido; solo presente en [`TipoEventoKdc::SolicitudServicio`].
    pub spn: Option<String>,
    /// Cifrado del ticket emitido.
    pub cifrado: TipoCifrado,
    /// Momento del evento, en segundos Unix.
    pub momento_unix: u64,
    /// Vida solicitada del ticket, en segundos, si el evento la trae. Sirve para
    /// detectar un Golden Ticket con vida absurda (Mimikatz pone 10 anos).
    pub vida_solicitada_seg: Option<u32>,
}

impl EventoKdc {
    /// Atajo para un evento 4769 (solicitud de servicio), el mas frecuente en la
    /// deteccion. `vida_solicitada_seg` queda a `None`.
    #[must_use]
    pub fn solicitud_servicio(
        cuenta: impl Into<String>,
        spn: impl Into<String>,
        cifrado: TipoCifrado,
        momento_unix: u64,
    ) -> Self {
        Self {
            tipo: TipoEventoKdc::SolicitudServicio,
            cuenta: cuenta.into(),
            spn: Some(spn.into()),
            cifrado,
            momento_unix,
            vida_solicitada_seg: None,
        }
    }

    /// Atajo para un evento 4768 (solicitud de TGT).
    #[must_use]
    pub fn solicitud_tgt(
        cuenta: impl Into<String>,
        cifrado: TipoCifrado,
        momento_unix: u64,
    ) -> Self {
        Self {
            tipo: TipoEventoKdc::SolicitudTgt,
            cuenta: cuenta.into(),
            spn: None,
            cifrado,
            momento_unix,
            vida_solicitada_seg: None,
        }
    }
}

/// El uso de un ticket de servicio contra un recurso, observado en el propio
/// servicio (no en la KDC). Es la contraparte que permite ver un Silver Ticket:
/// un ticket que se USA sin que la KDC lo haya EMITIDO.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UsoServicio {
    /// Cuenta que presenta el ticket.
    pub cuenta: String,
    /// SPN del servicio al que se accede.
    pub spn: String,
    /// Cifrado del ticket presentado.
    pub cifrado: TipoCifrado,
    /// Momento del acceso, en segundos Unix.
    pub momento_unix: u64,
    /// Host del servicio donde se observo el uso.
    pub host_servicio: String,
}

/// Politica del dominio, contra la que se juzga lo anomalo. Sus valores por
/// defecto ([`PoliticaDominio::tipica`]) son los de un Active Directory moderno.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoliticaDominio {
    /// Vida maxima de un TGT, en segundos. Por defecto 10 horas (36000 s): es el
    /// valor por defecto de Windows y define la ventana en la que un 4769 debe
    /// tener un 4768 que lo respalde.
    pub vida_max_tgt_seg: u32,
    /// Vida maxima con renovaciones, en segundos. Por defecto 7 dias (604800 s):
    /// ni con renovaciones un TGT legitimo dura mas. Una vida solicitada por
    /// encima de esto es imposible en un dominio real y delata un ticket forjado
    /// (Mimikatz pone 10 anos por defecto).
    pub vida_max_renovacion_seg: u32,
    /// El dominio espera AES. Si es `true`, un ticket RC4 es un degradado
    /// sospechoso; si el dominio aun admite RC4 legitimamente, se pone `false`.
    pub exige_aes: bool,
}

impl PoliticaDominio {
    /// La politica de un dominio moderno: TGT de 10 horas, renovacion de 7 dias
    /// y AES exigido.
    #[must_use]
    pub fn tipica() -> Self {
        Self {
            vida_max_tgt_seg: 36_000,
            vida_max_renovacion_seg: 604_800,
            exige_aes: true,
        }
    }
}

/// Un ticket Kerberos decodificado de su forma DER en el cable (la parte en
/// claro; la cifrada no se toca). Ver [`ticket_desde_der`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketKerberos {
    /// Version del ticket (`tkt-vno`, siempre 5 en Kerberos v5).
    pub version: i32,
    /// Realm del ticket (p. ej. `EXAMPLE.COM`).
    pub realm: String,
    /// Tipo del nombre del servicio (`name-type` de `PrincipalName`).
    pub tipo_nombre: i32,
    /// SPN reconstruido, con las partes unidas por `/` (p. ej. `cifs/fs1`).
    pub spn: String,
    /// Cifrado de la parte cifrada del ticket (`enc-part.etype`).
    pub cifrado: TipoCifrado,
    /// Numero de version de la clave (`kvno`), si el ticket lo trae.
    pub kvno: Option<u32>,
}

/// Decodifica la estructura `Ticket` de RFC 4120 desde sus bytes DER.
///
/// Parsea solo el sobre en claro: `Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno
/// [0] INTEGER, realm [1] GeneralString, sname [2] PrincipalName, enc-part [3]
/// EncryptedData }`, y de `EncryptedData` toma el `etype` (y el `kvno` si
/// esta). La parte cifrada (`cipher`) se comprueba que existe pero no se
/// interpreta: va cifrada con la clave del servicio.
///
/// # Errores
/// [`ItdrError::KerberosMalFormado`] si los bytes no respetan exactamente esa
/// estructura DER. El parser es **estricto**: cualquier tag inesperado, longitud
/// no minima, byte sobrante o cadena no UTF-8 se rechaza en vez de adivinar.
pub fn ticket_desde_der(bytes: &[u8]) -> Result<TicketKerberos, ItdrError> {
    let mut top = Lector::new(bytes);
    let cuerpo = top.contenido(0x61, "Ticket [APPLICATION 1]")?;
    if !top.agotado() {
        return Err(ItdrError::KerberosMalFormado(
            "bytes sobrantes tras el Ticket",
        ));
    }

    let mut t = Lector::new(cuerpo);
    let sec = t.contenido(0x30, "Ticket SEQUENCE")?;
    if !t.agotado() {
        return Err(ItdrError::KerberosMalFormado(
            "bytes sobrantes en el Ticket",
        ));
    }

    let mut s = Lector::new(sec);
    let version = entero_i32(s.contenido(0xA0, "tkt-vno [0]")?, "tkt-vno")?;
    let realm = cadena(s.contenido(0xA1, "realm [1]")?, "realm")?;
    let (tipo_nombre, spn) = principal(s.contenido(0xA2, "sname [2]")?)?;
    let (etype, kvno) = datos_cifrados(s.contenido(0xA3, "enc-part [3]")?)?;
    if !s.agotado() {
        return Err(ItdrError::KerberosMalFormado("campos de mas en el Ticket"));
    }

    Ok(TicketKerberos {
        version,
        realm,
        tipo_nombre,
        spn,
        cifrado: TipoCifrado::desde_id(etype),
        kvno,
    })
}

/// Decodifica un `PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string
/// [1] SEQUENCE OF KerberosString }` y devuelve `(name-type, spn)`.
fn principal(slice: &[u8]) -> Result<(i32, String), ItdrError> {
    let mut r = Lector::new(slice);
    let sec = r.contenido(0x30, "PrincipalName SEQUENCE")?;
    if !r.agotado() {
        return Err(ItdrError::KerberosMalFormado("bytes sobrantes en sname"));
    }
    let mut p = Lector::new(sec);
    let tipo = entero_i32(p.contenido(0xA0, "name-type [0]")?, "name-type")?;
    let lista = p.contenido(0xA1, "name-string [1]")?;
    if !p.agotado() {
        return Err(ItdrError::KerberosMalFormado(
            "campos de mas en PrincipalName",
        ));
    }

    let mut q = Lector::new(lista);
    let sec_partes = q.contenido(0x30, "name-string SEQUENCE")?;
    let mut it = Lector::new(sec_partes);
    let mut partes = Vec::new();
    while !it.agotado() {
        // `it.contenido(0x1B, ...)` ya devuelve el contenido de la GeneralString
        // (la parte de texto), asi que se decodifica aqui directamente en vez de
        // volver a desenvolver otro TLV.
        let texto = it.contenido(0x1B, "KerberosString")?;
        partes.push(
            String::from_utf8(texto.to_vec())
                .map_err(|_| ItdrError::KerberosMalFormado("GeneralString no es UTF-8"))?,
        );
    }
    if partes.is_empty() {
        return Err(ItdrError::KerberosMalFormado(
            "PrincipalName sin componentes",
        ));
    }
    Ok((tipo, partes.join("/")))
}

/// Decodifica un `EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] UInt32
/// OPTIONAL, cipher [2] OCTET STRING }` y devuelve `(etype, kvno)`.
fn datos_cifrados(slice: &[u8]) -> Result<(i32, Option<u32>), ItdrError> {
    let mut r = Lector::new(slice);
    let sec = r.contenido(0x30, "EncryptedData SEQUENCE")?;
    if !r.agotado() {
        return Err(ItdrError::KerberosMalFormado("bytes sobrantes en enc-part"));
    }
    let mut e = Lector::new(sec);
    let etype = entero_i32(e.contenido(0xA0, "etype [0]")?, "etype")?;

    let kvno = if e.mira_tag() == Some(0xA1) {
        Some(entero_u32(e.contenido(0xA1, "kvno [1]")?, "kvno")?)
    } else {
        None
    };

    // La parte cifrada existe (es un OCTET STRING) pero no se interpreta.
    let envoltura = e.contenido(0xA2, "cipher [2]")?;
    let mut c = Lector::new(envoltura);
    let _ = c.contenido(0x04, "cipher OCTET STRING")?;
    if !e.agotado() {
        return Err(ItdrError::KerberosMalFormado(
            "campos de mas en EncryptedData",
        ));
    }
    Ok((etype, kvno))
}

/// Decodifica el contenido de un elemento que es exactamente un `INTEGER` DER y
/// lo devuelve como `i64` (complemento a dos, big-endian, minimo 1 byte).
fn entero_i64(slice: &[u8], ctx: &'static str) -> Result<i64, ItdrError> {
    let mut r = Lector::new(slice);
    let v = r.contenido(0x02, ctx)?;
    if !r.agotado() {
        return Err(ItdrError::KerberosMalFormado(
            "bytes sobrantes tras INTEGER",
        ));
    }
    if v.is_empty() || v.len() > 8 {
        return Err(ItdrError::KerberosMalFormado(
            "INTEGER de longitud invalida",
        ));
    }
    let negativo = v[0] & 0x80 != 0;
    let mut acc: i64 = if negativo { -1 } else { 0 };
    for &b in v {
        acc = (acc << 8) | i64::from(b);
    }
    Ok(acc)
}

/// Como [`entero_i64`] pero exige que quepa en `i32` (etype, name-type, version).
fn entero_i32(slice: &[u8], ctx: &'static str) -> Result<i32, ItdrError> {
    let v = entero_i64(slice, ctx)?;
    i32::try_from(v).map_err(|_| ItdrError::KerberosMalFormado("INTEGER fuera de rango i32"))
}

/// Como [`entero_i64`] pero exige un `u32` no negativo (kvno).
fn entero_u32(slice: &[u8], ctx: &'static str) -> Result<u32, ItdrError> {
    let v = entero_i64(slice, ctx)?;
    u32::try_from(v).map_err(|_| ItdrError::KerberosMalFormado("INTEGER fuera de rango u32"))
}

/// Decodifica el contenido de un elemento que es exactamente un `GeneralString`
/// DER (tag 0x1B) y lo devuelve como `String` UTF-8.
fn cadena(slice: &[u8], ctx: &'static str) -> Result<String, ItdrError> {
    let mut r = Lector::new(slice);
    let bytes = r.contenido(0x1B, ctx)?;
    if !r.agotado() {
        return Err(ItdrError::KerberosMalFormado(
            "bytes sobrantes tras GeneralString",
        ));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| ItdrError::KerberosMalFormado("GeneralString no es UTF-8"))
}

/// Lector DER minimo y estricto sobre un slice. No asigna: cada elemento se
/// devuelve como un subslice prestado. Rechaza la forma indefinida de longitud,
/// las longitudes no minimas y los desbordes.
struct Lector<'a> {
    datos: &'a [u8],
    pos: usize,
}

impl<'a> Lector<'a> {
    fn new(datos: &'a [u8]) -> Self {
        Self { datos, pos: 0 }
    }

    fn agotado(&self) -> bool {
        self.pos >= self.datos.len()
    }

    /// El tag del siguiente elemento sin consumirlo, o `None` si no queda nada.
    fn mira_tag(&self) -> Option<u8> {
        self.datos.get(self.pos).copied()
    }

    fn byte(&mut self, ctx: &'static str) -> Result<u8, ItdrError> {
        let b = *self
            .datos
            .get(self.pos)
            .ok_or(ItdrError::KerberosMalFormado(ctx))?;
        self.pos += 1;
        Ok(b)
    }

    /// Lee una longitud DER: forma corta (`< 0x80`) o forma larga (`0x81`/`0x82`,
    /// hasta dos bytes big-endian). Rechaza la forma indefinida (`0x80`), las
    /// longitudes de mas de dos bytes (un ticket no las necesita y aceptarlas
    /// abriria a longitudes absurdas) y la codificacion no minima.
    fn longitud(&mut self, ctx: &'static str) -> Result<usize, ItdrError> {
        let primero = self.byte(ctx)?;
        if primero & 0x80 == 0 {
            return Ok(primero as usize);
        }
        let n = (primero & 0x7F) as usize;
        if n == 0 || n > 2 {
            return Err(ItdrError::KerberosMalFormado("longitud DER no soportada"));
        }
        let mut valor = 0usize;
        for _ in 0..n {
            valor = (valor << 8) | self.byte(ctx)? as usize;
        }
        if valor < 0x80 {
            return Err(ItdrError::KerberosMalFormado("longitud DER no minima"));
        }
        Ok(valor)
    }

    fn bytes(&mut self, n: usize, ctx: &'static str) -> Result<&'a [u8], ItdrError> {
        let fin = self
            .pos
            .checked_add(n)
            .ok_or(ItdrError::KerberosMalFormado(ctx))?;
        if fin > self.datos.len() {
            return Err(ItdrError::KerberosMalFormado(ctx));
        }
        let s = &self.datos[self.pos..fin];
        self.pos = fin;
        Ok(s)
    }

    /// Lee un elemento TLV cuyo tag debe ser `tag` y devuelve su contenido.
    fn contenido(&mut self, tag: u8, ctx: &'static str) -> Result<&'a [u8], ItdrError> {
        let t = self.byte(ctx)?;
        if t != tag {
            return Err(ItdrError::KerberosMalFormado(ctx));
        }
        let len = self.longitud(ctx)?;
        self.bytes(len, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clasifica_cifrados_por_su_etype() {
        assert!(TipoCifrado::desde_id(23).es_rc4());
        assert!(TipoCifrado::desde_id(24).es_rc4());
        assert!(TipoCifrado::desde_id(23).es_debil());
        assert!(TipoCifrado::desde_id(18).es_aes());
        assert!(!TipoCifrado::desde_id(18).es_debil());
        assert!(TipoCifrado::desde_id(1).es_debil());
        assert_eq!(TipoCifrado::desde_id(99), TipoCifrado::Otro(99));
        // Ida y vuelta del identificador.
        for id in [1, 3, 17, 18, 23, 24, 99] {
            assert_eq!(TipoCifrado::desde_id(id).id(), id);
        }
    }

    /// Un `Ticket` de RFC 4120 codificado a mano, byte a byte, con cada TLV
    /// anotado. Es el ancla de honestidad del parser: se puede verificar contra
    /// el RFC leyendo los comentarios. Realm `EXAMPLE.COM`, SPN `cifs/fs1`,
    /// cifrado RC4 (etype 23).
    const TICKET_RC4: &[u8] = &[
        0x61, 0x3E, // Ticket [APPLICATION 1], len 62
        0x30, 0x3C, //   SEQUENCE, len 60
        0xA0, 0x03, 0x02, 0x01, 0x05, //     tkt-vno [0] INTEGER 5
        0xA1, 0x0D, 0x1B, 0x0B, // realm [1] GeneralString, len 11:
        0x45, 0x58, 0x41, 0x4D, 0x50, 0x4C, 0x45, 0x2E, 0x43, 0x4F, 0x4D, // "EXAMPLE.COM"
        0xA2, 0x16, //     sname [2], len 22
        0x30, 0x14, //       PrincipalName SEQUENCE, len 20
        0xA0, 0x03, 0x02, 0x01, 0x02, //         name-type [0] INTEGER 2 (NT-SRV-INST)
        0xA1, 0x0D, //         name-string [1], len 13
        0x30, 0x0B, //           SEQUENCE OF, len 11
        0x1B, 0x04, 0x63, 0x69, 0x66, 0x73, //             "cifs"
        0x1B, 0x03, 0x66, 0x73, 0x31, //             "fs1"
        0xA3, 0x0E, //     enc-part [3], len 14
        0x30, 0x0C, //       EncryptedData SEQUENCE, len 12
        0xA0, 0x03, 0x02, 0x01, 0x17, //         etype [0] INTEGER 23 (rc4-hmac)
        0xA2, 0x05, 0x04, 0x03, 0xAA, 0xBB, 0xCC, //         cipher [2] OCTET STRING (3 bytes)
    ];

    #[test]
    fn parsea_un_ticket_der_real() {
        let t = ticket_desde_der(TICKET_RC4).expect("el ticket es DER valido");
        assert_eq!(t.version, 5);
        assert_eq!(t.realm, "EXAMPLE.COM");
        assert_eq!(t.tipo_nombre, 2);
        assert_eq!(t.spn, "cifs/fs1");
        assert_eq!(t.cifrado, TipoCifrado::Rc4Hmac);
        assert!(t.cifrado.es_rc4());
        assert_eq!(t.kvno, None);
    }

    #[test]
    fn rechaza_un_ticket_truncado() {
        // La mitad del ticket: la longitud declarada excede los bytes presentes.
        let corto = &TICKET_RC4[..30];
        // La longitud declarada del [APPLICATION 1] (62) excede los bytes
        // presentes, asi que se rechaza ya en la capa externa.
        assert_eq!(
            ticket_desde_der(corto),
            Err(ItdrError::KerberosMalFormado("Ticket [APPLICATION 1]"))
        );
    }

    #[test]
    fn rechaza_el_tag_externo_incorrecto() {
        // Un AS-REP ([APPLICATION 11] = 0x6B) no es un Ticket: se rechaza en la
        // primera comprobacion en vez de intentar interpretarlo.
        let mut malo = TICKET_RC4.to_vec();
        malo[0] = 0x6B;
        assert_eq!(
            ticket_desde_der(&malo),
            Err(ItdrError::KerberosMalFormado("Ticket [APPLICATION 1]"))
        );
    }

    #[test]
    fn rechaza_bytes_sobrantes_al_final() {
        let mut con_cola = TICKET_RC4.to_vec();
        con_cola.push(0x00);
        assert_eq!(
            ticket_desde_der(&con_cola),
            Err(ItdrError::KerberosMalFormado(
                "bytes sobrantes tras el Ticket"
            ))
        );
    }

    #[test]
    fn rechaza_un_spn_no_utf8() {
        // Se corrompe el primer byte de "cifs" (offset del contenido) con 0xFF,
        // que solo no es UTF-8 valido: el parser lo rechaza en vez de aceptar
        // basura como nombre de servicio.
        let mut malo = TICKET_RC4.to_vec();
        // Byte de la 'c' de "cifs": localizarlo por su posicion conocida.
        let idx = malo
            .iter()
            .position(|&b| b == 0x63)
            .expect("la 'c' de cifs");
        malo[idx] = 0xFF;
        assert_eq!(
            ticket_desde_der(&malo),
            Err(ItdrError::KerberosMalFormado("GeneralString no es UTF-8"))
        );
    }
}
