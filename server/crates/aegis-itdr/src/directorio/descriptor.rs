//! El descriptor de seguridad NT, parseado byte a byte del formato binario real.
//!
//! # Por que esto es el nucleo, y por que se prueba byte a byte
//!
//! Las escaladas silenciosas del directorio no estan en los grupos: estan en las
//! **listas de control de acceso**. Un usuario raso al que alguien, hace anos, le
//! dio `WriteDacl` sobre el grupo «Domain Admins» puede hacerse administrador del
//! dominio sin pertenecer a ningun grupo privilegiado y sin que ningun evento lo
//! delate. Encontrar eso —para que se remedie— exige leer el `ntSecurityDescriptor`
//! de cada objeto, que es una estructura binaria del formato **MS-DTYP** de
//! Microsoft: un `SECURITY_DESCRIPTOR` auto-relativo, con su `ACL` y sus `ACE`.
//!
//! Este parser recibe **bytes que vienen del directorio** —entrada que un
//! atacante con acceso al directorio podria manipular— y por eso se comporta como
//! el resto de los que comen entrada hostil en este producto: comprueba cada
//! longitud antes de leerla, no entra en panico ante nada, y ante una estructura
//! que no cuadra devuelve su motivo en vez de adivinar. Se prueba contra
//! descriptores construidos byte a byte segun la especificacion, igual que el
//! nucleo Kerberos se prueba contra tickets DER reales.

use super::objeto::Sid;
use super::relacion::RelacionDirectorio;

/// Motivo por el que un descriptor no se pudo interpretar.
///
/// Se nombra la parte que falla: un descriptor que no cuadra es, o corrupcion, o
/// un intento de confundir al parser, y en ambos casos se rechaza en vez de
/// devolver una lista de permisos vacia que se leeria como «este objeto no tiene
/// ACL peligrosas».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorMalFormado(pub &'static str);

// ── Mascara de acceso (MS-DTYP 2.4.3, ADTS) ─────────────────────────────────────
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
/// `ADS_RIGHT_DS_WRITE_PROP`.
const WRITE_PROPERTY: u32 = 0x0000_0020;
/// `ADS_RIGHT_DS_CONTROL_ACCESS` (derecho extendido / acceso de control).
const CONTROL_ACCESS: u32 = 0x0000_0100;

// ── Tipos de ACE (MS-DTYP 2.4.4) ────────────────────────────────────────────────
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;

// ── Banderas del ACE de objeto (que GUID esta presente) ──────────────────────────
const ACE_OBJECT_TYPE_PRESENT: u32 = 0x0000_0001;
const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x0000_0002;

// ── Bit de control del descriptor: DACL presente ────────────────────────────────
const SE_DACL_PRESENT: u16 = 0x0004;

// ── GUID bien conocidos (derechos extendidos y atributos) ────────────────────────
/// `User-Force-Change-Password`: forzar el cambio de contrasena sin saber la vieja.
const GUID_FORZAR_CLAVE: &str = "00299570-246d-11d0-a768-00aa006e0529";
/// `DS-Replication-Get-Changes-All`: la mitad de DCSync que entrega los hashes.
const GUID_REPLICA_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
/// El atributo `member` de un grupo: escribirlo es anadir miembros.
const GUID_MEMBER: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";

/// Extrae las relaciones de control que la DACL de un objeto concede, mas la del
/// propietario.
///
/// Devuelve pares `(principal que tiene el derecho, relacion sobre el objetivo)`.
/// El llamante los convierte en aristas `principal -> objetivo`.
///
/// # Errores
/// [`DescriptorMalFormado`] si la estructura binaria no respeta MS-DTYP.
pub fn relaciones_de_descriptor(
    sd: &[u8],
    _objetivo: &Sid,
) -> Result<Vec<(Sid, RelacionDirectorio)>, DescriptorMalFormado> {
    // SECURITY_DESCRIPTOR auto-relativo (MS-DTYP 2.4.6): 20 bytes de cabecera fija.
    //   Revision(1) Sbz1(1) Control(2 LE) OffsetOwner(4 LE) OffsetGroup(4 LE)
    //   OffsetSacl(4 LE) OffsetDacl(4 LE)
    if sd.len() < 20 {
        return Err(DescriptorMalFormado("descriptor mas corto que su cabecera"));
    }
    let control = leer_u16(sd, 2)?;
    let offset_owner = leer_u32(sd, 4)? as usize;
    let offset_dacl = leer_u32(sd, 16)? as usize;

    let mut salida = Vec::new();

    // El propietario puede reescribir la DACL de su objeto: es un camino de control
    // aunque no aparezca en ninguna ACE.
    if offset_owner != 0 {
        let owner = leer_sid(sd, offset_owner)?;
        if !owner.texto().is_empty() {
            salida.push((owner, RelacionDirectorio::Posee));
        }
    }

    // Sin DACL presente, no hay ACE que leer. NO es «sin permisos peligrosos»: un
    // objeto sin DACL presente hereda una por defecto, pero eso no se decide aqui.
    if control & SE_DACL_PRESENT == 0 || offset_dacl == 0 {
        return Ok(salida);
    }

    // ACL (MS-DTYP 2.4.5): AclRevision(1) Sbz1(1) AclSize(2 LE) AceCount(2 LE)
    //   Sbz2(2 LE), y luego AceCount ACE consecutivas.
    if offset_dacl + 8 > sd.len() {
        return Err(DescriptorMalFormado("la DACL no cabe en el descriptor"));
    }
    let ace_count = leer_u16(sd, offset_dacl + 4)?;
    let mut cursor = offset_dacl + 8;

    for _ in 0..ace_count {
        // Cabecera del ACE: AceType(1) AceFlags(1) AceSize(2 LE).
        if cursor + 4 > sd.len() {
            return Err(DescriptorMalFormado("un ACE se sale del descriptor"));
        }
        let ace_type = sd[cursor];
        let ace_size = leer_u16(sd, cursor + 2)? as usize;
        if ace_size < 4 || cursor + ace_size > sd.len() {
            return Err(DescriptorMalFormado("un ACE declara un tamano imposible"));
        }
        let cuerpo = &sd[cursor + 4..cursor + ace_size];
        if let Some((trustee, relacion)) = interpretar_ace(ace_type, cuerpo)? {
            salida.push((trustee, relacion));
        }
        cursor += ace_size;
    }

    Ok(salida)
}

/// Extrae los SID de los principales presentes en la DACL de un descriptor,
/// **sin exigir mascara de control**.
///
/// Es lo que hace falta para la delegacion basada en recursos (RBCD): el atributo
/// `msDS-AllowedToActOnBehalfOfOtherIdentity` es un descriptor de seguridad cuya
/// sola presencia de un principal en la DACL significa «este puede actuar en mi
/// nombre». Ahi no importa la mascara: importa quien esta en la lista.
///
/// # Errores
/// [`DescriptorMalFormado`] si la estructura binaria no respeta MS-DTYP.
pub fn sids_permitidos(sd: &[u8]) -> Result<Vec<Sid>, DescriptorMalFormado> {
    if sd.len() < 20 {
        return Err(DescriptorMalFormado("descriptor mas corto que su cabecera"));
    }
    let control = leer_u16(sd, 2)?;
    let offset_dacl = leer_u32(sd, 16)? as usize;
    if control & SE_DACL_PRESENT == 0 || offset_dacl == 0 {
        return Ok(Vec::new());
    }
    if offset_dacl + 8 > sd.len() {
        return Err(DescriptorMalFormado("la DACL no cabe en el descriptor"));
    }
    let ace_count = leer_u16(sd, offset_dacl + 4)?;
    let mut cursor = offset_dacl + 8;
    let mut salida = Vec::new();
    for _ in 0..ace_count {
        if cursor + 4 > sd.len() {
            return Err(DescriptorMalFormado("un ACE se sale del descriptor"));
        }
        let ace_type = sd[cursor];
        let ace_size = leer_u16(sd, cursor + 2)? as usize;
        if ace_size < 4 || cursor + ace_size > sd.len() {
            return Err(DescriptorMalFormado("un ACE declara un tamano imposible"));
        }
        let cuerpo = &sd[cursor + 4..cursor + ace_size];
        if ace_type == ACCESS_ALLOWED_ACE_TYPE && cuerpo.len() >= 4 {
            salida.push(leer_sid(cuerpo, 4)?);
        }
        cursor += ace_size;
    }
    Ok(salida)
}

/// Interpreta un ACE de permiso concedido. Los ACE de denegacion y de auditoria
/// no abren caminos de control, asi que no producen arista.
fn interpretar_ace(
    ace_type: u8,
    cuerpo: &[u8],
) -> Result<Option<(Sid, RelacionDirectorio)>, DescriptorMalFormado> {
    match ace_type {
        ACCESS_ALLOWED_ACE_TYPE => {
            // Mask(4 LE) Sid(variable).
            if cuerpo.len() < 4 {
                return Err(DescriptorMalFormado("ACE de acceso sin mascara"));
            }
            let mask = u32::from_le_bytes([cuerpo[0], cuerpo[1], cuerpo[2], cuerpo[3]]);
            let sid = leer_sid(cuerpo, 4)?;
            Ok(relacion_de_mascara(mask, None).map(|r| (sid, r)))
        }
        ACCESS_ALLOWED_OBJECT_ACE_TYPE => {
            // Mask(4 LE) Flags(4 LE) [ObjectType 16] [InheritedObjectType 16] Sid.
            if cuerpo.len() < 8 {
                return Err(DescriptorMalFormado(
                    "ACE de objeto sin mascara ni banderas",
                ));
            }
            let mask = u32::from_le_bytes([cuerpo[0], cuerpo[1], cuerpo[2], cuerpo[3]]);
            let flags = u32::from_le_bytes([cuerpo[4], cuerpo[5], cuerpo[6], cuerpo[7]]);
            let mut off = 8;
            let mut object_type = None;
            if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
                if off + 16 > cuerpo.len() {
                    return Err(DescriptorMalFormado("falta el GUID de tipo de objeto"));
                }
                object_type = Some(guid_a_texto(&cuerpo[off..off + 16]));
                off += 16;
            }
            if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                if off + 16 > cuerpo.len() {
                    return Err(DescriptorMalFormado("falta el GUID heredado"));
                }
                off += 16;
            }
            let sid = leer_sid(cuerpo, off)?;
            Ok(relacion_de_mascara(mask, object_type.as_deref()).map(|r| (sid, r)))
        }
        // Denegaciones, auditorias y variantes que no conceden acceso: no abren
        // camino de control.
        _ => Ok(None),
    }
}

/// Traduce una mascara de acceso (y el GUID de objeto, si lo hay) a la relacion de
/// control mas fuerte que representa. `None` si no otorga control.
fn relacion_de_mascara(mask: u32, object_type: Option<&str>) -> Option<RelacionDirectorio> {
    // Los derechos genericos y de reescritura de seguridad no dependen del GUID:
    // valen sobre el objeto entero.
    if mask & GENERIC_ALL != 0 {
        return Some(RelacionDirectorio::ControlTotal);
    }
    if mask & WRITE_DAC != 0 {
        return Some(RelacionDirectorio::EscrituraDacl);
    }
    if mask & WRITE_OWNER != 0 {
        return Some(RelacionDirectorio::EscrituraPropietario);
    }
    // Un acceso de control (derecho extendido). Con GUID, es un derecho concreto;
    // sin GUID, son TODOS los derechos extendidos.
    if mask & CONTROL_ACCESS != 0 {
        return Some(match object_type {
            Some(g) if g.eq_ignore_ascii_case(GUID_FORZAR_CLAVE) => {
                RelacionDirectorio::ForzarCambioClave
            }
            Some(g) if g.eq_ignore_ascii_case(GUID_REPLICA_ALL) => {
                RelacionDirectorio::ReplicaDirectorio
            }
            Some(_) => return None, // otro derecho extendido concreto: no es control
            None => RelacionDirectorio::TodosDerechosExtendidos,
        });
    }
    // Escritura de una propiedad: sobre el atributo `member` es anadir miembros;
    // sin GUID es escritura generica de atributos.
    if mask & WRITE_PROPERTY != 0 {
        return Some(match object_type {
            Some(g) if g.eq_ignore_ascii_case(GUID_MEMBER) => RelacionDirectorio::AnadirMiembro,
            Some(_) => return None,
            None => RelacionDirectorio::EscrituraGenerica,
        });
    }
    if mask & GENERIC_WRITE != 0 {
        return Some(RelacionDirectorio::EscrituraGenerica);
    }
    None
}

/// Lee un SID en formato binario (MS-DTYP 2.4.2) desde un desplazamiento.
///
///   Revision(1) SubAuthorityCount(1) IdentifierAuthority(6 BE) SubAuthority[N](4 LE)
fn leer_sid(buf: &[u8], off: usize) -> Result<Sid, DescriptorMalFormado> {
    if off + 8 > buf.len() {
        return Err(DescriptorMalFormado("un SID no cabe en su cabecera"));
    }
    let revision = buf[off];
    let sub_count = buf[off + 1] as usize;
    // La autoridad es un entero de 48 bits big-endian.
    let mut autoridad: u64 = 0;
    for &b in &buf[off + 2..off + 8] {
        autoridad = (autoridad << 8) | u64::from(b);
    }
    let fin = off + 8 + sub_count * 4;
    if sub_count > 15 || fin > buf.len() {
        return Err(DescriptorMalFormado(
            "un SID declara mas subautoridades de las que caben",
        ));
    }
    let mut s = format!("S-{revision}-{autoridad}");
    let mut p = off + 8;
    for _ in 0..sub_count {
        let sub = u32::from_le_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
        s.push('-');
        s.push_str(&sub.to_string());
        p += 4;
    }
    Ok(Sid::nuevo(s))
}

/// Convierte un GUID binario (Data1/2/3 en little-endian, Data4 tal cual) a su
/// forma canonica de texto.
fn guid_a_texto(b: &[u8]) -> String {
    debug_assert!(b.len() >= 16);
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    let mut s = format!("{d1:08x}-{d2:04x}-{d3:04x}-");
    for &x in &b[8..10] {
        s.push_str(&format!("{x:02x}"));
    }
    s.push('-');
    for &x in &b[10..16] {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn leer_u16(buf: &[u8], off: usize) -> Result<u16, DescriptorMalFormado> {
    if off + 2 > buf.len() {
        return Err(DescriptorMalFormado("lectura de 16 bits fuera de rango"));
    }
    Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
}

fn leer_u32(buf: &[u8], off: usize) -> Result<u32, DescriptorMalFormado> {
    if off + 4 > buf.len() {
        return Err(DescriptorMalFormado("lectura de 32 bits fuera de rango"));
    }
    Ok(u32::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Construye un SID binario canonico `S-1-5-21-a-b-c-rid`.
    fn sid_bin(rid: u32) -> Vec<u8> {
        let mut v = vec![1u8, 5]; // revision, subauth count
        v.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // autoridad 5 (NT), 48 bits BE
        for sub in [21u32, 1, 2, 3, rid] {
            v.extend_from_slice(&sub.to_le_bytes());
        }
        v
    }

    /// Un GUID canonico a sus 16 bytes binarios.
    fn guid_bin(canonico: &str) -> [u8; 16] {
        let hex: String = canonico.chars().filter(|c| *c != '-').collect();
        let bytes: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let mut b = [0u8; 16];
        // Data1 (4) LE, Data2 (2) LE, Data3 (2) LE, Data4 (8) as-is.
        b[0..4].copy_from_slice(&u32::from_str_radix(&hex[0..8], 16).unwrap().to_le_bytes());
        b[4..6].copy_from_slice(&u16::from_str_radix(&hex[8..12], 16).unwrap().to_le_bytes());
        b[6..8].copy_from_slice(&u16::from_str_radix(&hex[12..16], 16).unwrap().to_le_bytes());
        b[8..16].copy_from_slice(&bytes[8..16]);
        b
    }

    /// Un ACCESS_ALLOWED_ACE con una mascara y un trustee.
    fn ace_simple(mask: u32, rid: u32) -> Vec<u8> {
        let sid = sid_bin(rid);
        let size = 8 + sid.len();
        let mut v = vec![ACCESS_ALLOWED_ACE_TYPE, 0];
        v.extend_from_slice(&(size as u16).to_le_bytes());
        v.extend_from_slice(&mask.to_le_bytes());
        v.extend_from_slice(&sid);
        v
    }

    /// Un ACCESS_ALLOWED_OBJECT_ACE con mascara, GUID de tipo de objeto y trustee.
    fn ace_objeto(mask: u32, guid: &str, rid: u32) -> Vec<u8> {
        let sid = sid_bin(rid);
        let size = 8 + 4 + 16 + sid.len();
        let mut v = vec![ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0];
        v.extend_from_slice(&(size as u16).to_le_bytes());
        v.extend_from_slice(&mask.to_le_bytes());
        v.extend_from_slice(&ACE_OBJECT_TYPE_PRESENT.to_le_bytes());
        v.extend_from_slice(&guid_bin(guid));
        v.extend_from_slice(&sid);
        v
    }

    /// Envuelve unos ACE en un SECURITY_DESCRIPTOR auto-relativo con propietario.
    fn descriptor(owner_rid: Option<u32>, aces: &[Vec<u8>]) -> Vec<u8> {
        let owner = owner_rid.map(sid_bin);
        // La DACL va detras de la cabecera de 20 bytes; el owner detras de la DACL.
        let mut acl = vec![2u8, 0]; // AclRevision, Sbz1
        let ace_bytes: Vec<u8> = aces.iter().flatten().copied().collect();
        let acl_size = 8 + ace_bytes.len();
        acl.extend_from_slice(&(acl_size as u16).to_le_bytes());
        acl.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        acl.extend_from_slice(&[0, 0]); // Sbz2
        acl.extend_from_slice(&ace_bytes);

        let offset_dacl = 20u32;
        let offset_owner = if owner.is_some() {
            20 + acl.len() as u32
        } else {
            0
        };
        let mut sd = vec![1u8, 0]; // Revision, Sbz1
        sd.extend_from_slice(&SE_DACL_PRESENT.to_le_bytes()); // Control
        sd.extend_from_slice(&offset_owner.to_le_bytes());
        sd.extend_from_slice(&0u32.to_le_bytes()); // OffsetGroup
        sd.extend_from_slice(&0u32.to_le_bytes()); // OffsetSacl
        sd.extend_from_slice(&offset_dacl.to_le_bytes());
        sd.extend_from_slice(&acl);
        if let Some(o) = owner {
            sd.extend_from_slice(&o);
        }
        sd
    }

    fn objetivo() -> Sid {
        Sid::nuevo("S-1-5-21-1-2-3-512")
    }

    #[test]
    fn un_sid_binario_se_lee_a_su_forma_canonica() {
        let bin = sid_bin(1104);
        let s = leer_sid(&bin, 0).expect("SID valido");
        assert_eq!(s.texto(), "S-1-5-21-1-2-3-1104");
    }

    #[test]
    fn un_guid_binario_se_lee_a_su_forma_canonica() {
        assert_eq!(
            guid_a_texto(&guid_bin(GUID_FORZAR_CLAVE)),
            GUID_FORZAR_CLAVE
        );
        assert_eq!(guid_a_texto(&guid_bin(GUID_MEMBER)), GUID_MEMBER);
    }

    #[test]
    fn write_dac_sobre_el_objetivo_es_una_arista_de_control() {
        let sd = descriptor(None, &[ace_simple(WRITE_DAC, 1104)]);
        let r = relaciones_de_descriptor(&sd, &objetivo()).expect("descriptor valido");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].0.texto(), "S-1-5-21-1-2-3-1104");
        assert_eq!(r[0].1, RelacionDirectorio::EscrituraDacl);
    }

    #[test]
    fn generic_all_es_control_total() {
        let sd = descriptor(None, &[ace_simple(GENERIC_ALL, 1104)]);
        let r = relaciones_de_descriptor(&sd, &objetivo()).unwrap();
        assert_eq!(r[0].1, RelacionDirectorio::ControlTotal);
    }

    #[test]
    fn el_derecho_extendido_de_forzar_clave_se_distingue_por_su_guid() {
        let sd = descriptor(None, &[ace_objeto(CONTROL_ACCESS, GUID_FORZAR_CLAVE, 1104)]);
        let r = relaciones_de_descriptor(&sd, &objetivo()).unwrap();
        assert_eq!(r[0].1, RelacionDirectorio::ForzarCambioClave);
    }

    #[test]
    fn los_derechos_de_replicacion_son_la_arista_de_dcsync() {
        let sd = descriptor(None, &[ace_objeto(CONTROL_ACCESS, GUID_REPLICA_ALL, 1104)]);
        let r = relaciones_de_descriptor(&sd, &objetivo()).unwrap();
        assert_eq!(r[0].1, RelacionDirectorio::ReplicaDirectorio);
    }

    #[test]
    fn escribir_el_atributo_member_es_anadir_miembros() {
        let sd = descriptor(None, &[ace_objeto(WRITE_PROPERTY, GUID_MEMBER, 1104)]);
        let r = relaciones_de_descriptor(&sd, &objetivo()).unwrap();
        assert_eq!(r[0].1, RelacionDirectorio::AnadirMiembro);
    }

    #[test]
    fn el_acceso_de_control_sin_guid_son_todos_los_derechos_extendidos() {
        let sd = descriptor(None, &[ace_simple(CONTROL_ACCESS, 1104)]);
        let r = relaciones_de_descriptor(&sd, &objetivo()).unwrap();
        assert_eq!(r[0].1, RelacionDirectorio::TodosDerechosExtendidos);
    }

    #[test]
    fn el_propietario_produce_una_arista_de_posesion() {
        let sd = descriptor(Some(1104), &[ace_simple(0, 2001)]);
        let r = relaciones_de_descriptor(&sd, &objetivo()).unwrap();
        // El ACE con mascara 0 no otorga control; solo aparece el propietario.
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].0.texto(), "S-1-5-21-1-2-3-1104");
        assert_eq!(r[0].1, RelacionDirectorio::Posee);
    }

    #[test]
    fn una_denegacion_no_abre_camino() {
        // ACE_DENIED (tipo 1) con GENERIC_ALL: no produce arista de control.
        let sid = sid_bin(1104);
        let size = 8 + sid.len();
        let mut ace = vec![1u8, 0]; // ACCESS_DENIED_ACE_TYPE
        ace.extend_from_slice(&(size as u16).to_le_bytes());
        ace.extend_from_slice(&GENERIC_ALL.to_le_bytes());
        ace.extend_from_slice(&sid);
        let sd = descriptor(None, &[ace]);
        let r = relaciones_de_descriptor(&sd, &objetivo()).unwrap();
        assert!(r.is_empty(), "una denegacion no es un camino de ataque");
    }

    /// AUTOATAQUE del parser: bytes hostiles no provocan panico ni lectura fuera de
    /// rango. Un descriptor es entrada que un atacante con acceso al directorio
    /// puede fabricar.
    #[test]
    fn ninguna_entrada_hostil_provoca_panico() {
        // Descriptores truncados, tamanos mentirosos, contadores gigantes.
        let base = descriptor(
            Some(512),
            &[
                ace_simple(WRITE_DAC, 1104),
                ace_objeto(CONTROL_ACCESS, GUID_FORZAR_CLAVE, 2001),
            ],
        );
        for corte in 0..base.len() {
            let _ = relaciones_de_descriptor(&base[..corte], &objetivo());
        }
        // Un AceCount enorme con un buffer pequeno: se rechaza, no se cuelga.
        let mut mentiroso = descriptor(None, &[ace_simple(WRITE_DAC, 1104)]);
        mentiroso[24] = 0xff; // AceCount low byte tras la cabecera de 20 + 4
        mentiroso[25] = 0xff;
        let _ = relaciones_de_descriptor(&mentiroso, &objetivo());
        // Un tamano de ACE de 0 no debe hacer avanzar el cursor en cero (bucle).
        let mut cero = descriptor(None, &[ace_simple(WRITE_DAC, 1104)]);
        // El AceSize esta en offset 20(dacl)+8(cabecera acl)+2 = 30.
        cero[30] = 0;
        cero[31] = 0;
        assert!(relaciones_de_descriptor(&cero, &objetivo()).is_err());
    }
}
