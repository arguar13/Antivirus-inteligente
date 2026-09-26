//! Las variables UEFI, todas, con sus atributos: las que deciden que arranca y
//! con que claves se comprueba.
//!
//! # Lo que la FASE 26 miraba y lo que faltaba
//!
//! `aegis-firmware` leia `SecureBoot`, `SetupMode` y `dbx`. Con eso se sabe si
//! Secure Boot esta encendido, pero no se sabe **que** va a arrancar ni si las
//! bases de claves se pueden reescribir sin firma:
//!
//! - **Los atributos.** PK, KEK, db y dbx tienen que llevar
//!   `TIME_BASED_AUTHENTICATED_WRITE_ACCESS`: sin el, cualquier codigo con
//!   privilegio puede anadir su propio certificado a `db` y firmar su bootkit
//!   con el. Y `SecureBoot`/`SetupMode` son volatiles por especificacion: una
//!   `SecureBoot` no volatil es un estado que alguien puede dejar guardado.
//! - **`AuditMode`.** Con `AuditMode = 1` el firmware registra los fallos de
//!   firma y **arranca igual**. `SecureBoot = 1` y `SetupMode = 0` no bastan.
//! - **`BootOrder`, `BootNext` y `Boot####`.** Que cargador se ejecuta, desde
//!   donde, y si alguien dejo un arranque de una sola vez preparado.
//!
//! # Todo se lee, nada se escribe
//!
//! `efivarfs` permite escribir variables a root. Una variable mal escrita ha
//! dejado placas reales sin arrancar. Aqui se lee cada fichero por
//! [`LecturaSolo`], que no tiene operacion de escritura.

use std::path::Path;

use aegis_firmware::guid::Guid;
use aegis_firmware::report::CheckState;
use aegis_firmware::uefi::{attr, parse_signature_lists, EFI_GLOBAL, EFI_IMAGE_SECURITY_DATABASE};

use crate::comprobacion::{Comprobacion, Naturaleza, Superficie};
use crate::linea_base::guid_de_texto;
use crate::ruta_dispositivo::{decodificar, utf16, Origen, Ruta};
use crate::solo_lectura::LecturaSolo;

/// Directorio de `efivarfs`, relativo a la raiz de sysfs.
pub const DIR_EFIVARS: &str = "firmware/efi/efivars";
/// Tope de lo que se lee de una variable.
pub const TOPE_VARIABLE: usize = 1024 * 1024;
/// Tope de variables que se enumeran.
pub const MAX_VARIABLES: usize = 4096;

/// `NV | BS | RT | TIME_BASED_AUTHENTICATED_WRITE_ACCESS`: lo que deben llevar
/// PK, KEK, db y dbx.
pub const ATRIB_AUTENTICADA: u32 = attr::NON_VOLATILE
    | attr::BOOTSERVICE_ACCESS
    | attr::RUNTIME_ACCESS
    | attr::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
/// `BS | RT`: volatil, solo lectura para el SO.
pub const ATRIB_VOLATIL: u32 = attr::BOOTSERVICE_ACCESS | attr::RUNTIME_ACCESS;
/// `NV | BS | RT`: la de las opciones de arranque.
pub const ATRIB_ARRANQUE: u32 =
    attr::NON_VOLATILE | attr::BOOTSERVICE_ACCESS | attr::RUNTIME_ACCESS;

/// Una variable UEFI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableUefi {
    /// Nombre (`BootOrder`).
    pub nombre: String,
    /// GUID del fabricante.
    pub guid: Guid,
    /// Atributos.
    pub atributos: u32,
    /// Datos, sin el prefijo de atributos.
    pub datos: Vec<u8>,
}

/// Todas las variables leidas.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Almacen {
    /// Las variables, ordenadas por GUID y nombre.
    pub variables: Vec<VariableUefi>,
    /// Ficheros que no se pudieron leer, con el motivo.
    pub ilegibles: Vec<(String, String)>,
}

impl Almacen {
    /// Una variable por nombre y GUID.
    #[must_use]
    pub fn get(&self, nombre: &str, guid: &Guid) -> Option<&VariableUefi> {
        self.variables
            .iter()
            .find(|v| v.nombre == nombre && v.guid == *guid)
    }

    /// Una variable global.
    #[must_use]
    pub fn global(&self, nombre: &str) -> Option<&VariableUefi> {
        self.get(nombre, &EFI_GLOBAL)
    }

    /// El primer byte de una variable global, como booleano.
    #[must_use]
    pub fn bandera(&self, nombre: &str) -> Option<bool> {
        self.global(nombre)
            .map(|v| v.datos.first().copied().unwrap_or(0) == 1)
    }
}

/// Separa `Nombre-8be4df61-93ca-11d2-aa0d-00e098032b8c`.
#[must_use]
pub fn separar_nombre(fichero: &str) -> Option<(String, Guid)> {
    if fichero.len() < 38 {
        return None;
    }
    let (nombre, resto) = fichero.split_at(fichero.len() - 37);
    let guid = guid_de_texto(resto.strip_prefix('-')?)?;
    (!nombre.is_empty()).then(|| (nombre.to_string(), guid))
}

/// Lee todas las variables de un directorio `efivarfs`.
///
/// # Errores
/// El motivo si el directorio no existe: una maquina que no arranco por UEFI.
pub fn leer(dir: &Path) -> Result<Almacen, String> {
    let e = std::fs::read_dir(dir).map_err(|e| {
        format!(
            "{} no se puede leer ({e}): la maquina no arranco por UEFI o efivarfs no esta montado",
            dir.display()
        )
    })?;
    let mut a = Almacen::default();
    for x in e.flatten().take(MAX_VARIABLES) {
        let fichero = x.file_name().to_string_lossy().to_string();
        let Some((nombre, guid)) = separar_nombre(&fichero) else {
            continue;
        };
        match LecturaSolo::abrir(&x.path()).and_then(|l| l.leer_todo(TOPE_VARIABLE)) {
            Ok(b) if b.len() >= 4 => a.variables.push(VariableUefi {
                nombre,
                guid,
                atributos: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
                datos: b[4..].to_vec(),
            }),
            Ok(b) => a.ilegibles.push((
                fichero,
                format!("mide {} B, menos que el prefijo de atributos", b.len()),
            )),
            Err(err) => a.ilegibles.push((fichero, err.to_string())),
        }
    }
    a.variables
        .sort_by(|x, y| x.guid.cmp(&y.guid).then(x.nombre.cmp(&y.nombre)));
    a.ilegibles.sort();
    Ok(a)
}

/// Una opcion de carga (`EFI_LOAD_OPTION`) decodificada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcionCarga {
    /// El numero (`Boot0003` → 3).
    pub numero: u16,
    /// `LOAD_OPTION_ACTIVE`.
    pub activa: bool,
    /// La descripcion que ve el usuario en el menu.
    pub descripcion: String,
    /// La ruta de lo que carga.
    pub ruta: Ruta,
}

/// Decodifica una `EFI_LOAD_OPTION`: atributos (4), longitud de la lista de
/// rutas (2), descripcion UTF-16 terminada en cero, y la lista de rutas.
#[must_use]
pub fn analizar_opcion(numero: u16, datos: &[u8]) -> Option<OpcionCarga> {
    let atributos = u32::from_le_bytes(datos.get(0..4)?.try_into().ok()?);
    let largo_rutas = u16::from_le_bytes(datos.get(4..6)?.try_into().ok()?) as usize;
    // La descripcion acaba en el primer cero de 16 bits.
    let mut fin_desc = 6;
    while let Some(par) = datos.get(fin_desc..fin_desc + 2) {
        fin_desc += 2;
        if par == [0, 0] {
            break;
        }
    }
    let descripcion = utf16(datos.get(6..fin_desc)?);
    let rutas = datos.get(fin_desc..fin_desc.checked_add(largo_rutas)?)?;
    Some(OpcionCarga {
        numero,
        activa: atributos & 1 != 0,
        descripcion,
        ruta: decodificar(rutas),
    })
}

/// Las opciones de carga del almacen, y el orden de arranque.
#[must_use]
pub fn opciones(a: &Almacen) -> (Vec<u16>, Vec<OpcionCarga>) {
    let orden: Vec<u16> = a
        .global("BootOrder")
        .map(|v| {
            v.datos
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect()
        })
        .unwrap_or_default();
    let mut ops: Vec<OpcionCarga> = a
        .variables
        .iter()
        .filter(|v| v.guid == EFI_GLOBAL)
        .filter_map(|v| {
            let n = v.nombre.strip_prefix("Boot")?;
            if n.len() != 4 {
                return None;
            }
            let numero = u16::from_str_radix(n, 16).ok()?;
            analizar_opcion(numero, &v.datos)
        })
        .collect();
    ops.sort_by_key(|o| o.numero);
    (orden, ops)
}

/// Atributos que la especificacion UEFI fija para las variables de seguridad.
const ATRIBUTOS_SEGURIDAD: &[(&str, bool, u32)] = &[
    // (nombre, es de la base de imagenes, atributos exigidos)
    ("SecureBoot", false, ATRIB_VOLATIL),
    ("SetupMode", false, ATRIB_VOLATIL),
    ("AuditMode", false, ATRIB_VOLATIL),
    ("DeployedMode", false, ATRIB_VOLATIL),
    ("PK", false, ATRIB_AUTENTICADA),
    ("KEK", false, ATRIB_AUTENTICADA),
    ("db", true, ATRIB_AUTENTICADA),
    ("dbx", true, ATRIB_AUTENTICADA),
];

fn exposicion(id: &'static str, e: CheckState, chipsec: &'static [&'static str]) -> Comprobacion {
    Comprobacion::nueva(id, Superficie::VariablesUefi, Naturaleza::Exposicion, e)
        .como_chipsec(chipsec)
}

/// Las comprobaciones de variables.
#[must_use]
pub fn evaluar(a: &Result<Almacen, String>) -> Vec<Comprobacion> {
    let a = match a {
        Err(m) => {
            let e = CheckState::NoAplicable(m.clone());
            return vec![
                exposicion(
                    "uefi-secure-boot-imponiendo",
                    e.clone(),
                    &["common.secureboot.variables"],
                ),
                exposicion(
                    "uefi-atributos-seguridad",
                    e.clone(),
                    &["common.secureboot.variables", "common.uefi.access_uefispec"],
                ),
                exposicion("uefi-dbx", e.clone(), &[]),
                Comprobacion::nueva(
                    "uefi-entradas-arranque",
                    Superficie::VariablesUefi,
                    Naturaleza::Compromiso,
                    e,
                ),
            ];
        }
        Ok(a) => a,
    };
    vec![
        evaluar_modo(a),
        evaluar_atributos(a),
        evaluar_dbx(a),
        evaluar_arranque(a),
    ]
}

/// Secure Boot imponiendo de verdad: activo, fuera de configuracion y fuera de
/// auditoria.
fn evaluar_modo(a: &Almacen) -> Comprobacion {
    let estado = match a.bandera("SecureBoot") {
        None => CheckState::Fallo(
            "no existe la variable SecureBoot: el firmware no implementa Secure Boot, y \
             cualquier cargador arranca sin comprobar su firma"
                .into(),
        ),
        Some(false) => CheckState::Fallo(
            "SecureBoot=0: el firmware arranca cualquier cargador sin comprobar su firma".into(),
        ),
        Some(true) if a.bandera("SetupMode") == Some(true) => CheckState::Fallo(
            "SecureBoot=1 pero SetupMode=1: no hay PK, y cualquiera puede matricular sus \
             propias claves sin autenticarse"
                .into(),
        ),
        Some(true) if a.bandera("AuditMode") == Some(true) => CheckState::Fallo(
            "SecureBoot=1 pero AuditMode=1: los fallos de firma se REGISTRAN y el sistema \
             arranca igual. Parece encendido y no impone nada"
                .into(),
        ),
        Some(true) => CheckState::Ok,
    };
    exposicion(
        "uefi-secure-boot-imponiendo",
        estado,
        &["common.secureboot.variables"],
    )
}

/// Los atributos de las variables de seguridad, contra la especificacion.
fn evaluar_atributos(a: &Almacen) -> Comprobacion {
    let mut mal = Vec::new();
    for (nombre, de_imagenes, exigidos) in ATRIBUTOS_SEGURIDAD {
        let guid = if *de_imagenes {
            EFI_IMAGE_SECURITY_DATABASE
        } else {
            EFI_GLOBAL
        };
        let Some(v) = a.get(nombre, &guid) else {
            continue;
        };
        if v.atributos & 0x7F != *exigidos {
            let falta_auth = *exigidos & attr::TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0
                && v.atributos & attr::TIME_BASED_AUTHENTICATED_WRITE_ACCESS == 0;
            mal.push(format!(
                "{nombre} lleva {:#x} y la especificacion exige {exigidos:#x}{}",
                v.atributos,
                if falta_auth {
                    " (SIN escritura autenticada: se puede reescribir sin firma)"
                } else if *exigidos & attr::NON_VOLATILE == 0 && v.atributos & attr::NON_VOLATILE != 0 {
                    " (NO VOLATIL: un estado que deberia recalcularse en cada arranque se puede dejar guardado)"
                } else {
                    ""
                }
            ));
        }
    }
    let estado = if mal.is_empty() {
        CheckState::Ok
    } else {
        CheckState::Fallo(mal.join("; "))
    };
    exposicion(
        "uefi-atributos-seguridad",
        estado,
        &["common.secureboot.variables", "common.uefi.access_uefispec"],
    )
}

/// La DBX: que exista, que se pueda analizar y que no este vacia.
fn evaluar_dbx(a: &Almacen) -> Comprobacion {
    let sb = a.bandera("SecureBoot") == Some(true);
    let estado = match a.get("dbx", &EFI_IMAGE_SECURITY_DATABASE) {
        None if sb => CheckState::Fallo(
            "Secure Boot activo SIN lista de revocacion: cualquier cargador firmado que se \
             sepa comprometido (los que usa BlackLotus, por ejemplo) sigue arrancando"
                .into(),
        ),
        None => CheckState::NoAplicable("no hay dbx y Secure Boot no esta activo".into()),
        Some(v) => match parse_signature_lists(&v.datos) {
            Err(e) => CheckState::Indeterminado(format!("la dbx no se puede analizar: {e}")),
            Ok(f) if f.is_empty() && sb => CheckState::Fallo(
                "la dbx existe pero esta VACIA: no revoca ningun cargador comprometido".into(),
            ),
            Ok(_) => CheckState::Ok,
        },
    };
    exposicion("uefi-dbx", estado, &[])
}

/// Las entradas de arranque: que va a arrancar, y si hay algo preparado.
///
/// Es la unica comprobacion de este modulo que es de COMPROMISO: un arranque de
/// una sola vez (`BootNext`) o la primera entrada activa apuntando a la red, a un
/// extraible o a un fichero fuera de `\EFI\` no es una configuracion de fabrica:
/// es alguien que dejo preparado lo que se ejecutara en el proximo arranque.
fn evaluar_arranque(a: &Almacen) -> Comprobacion {
    let (orden, ops) = opciones(a);
    let mut hallazgos = Vec::new();
    let raro = |o: &OpcionCarga| -> Option<String> {
        match o.ruta.origen() {
            Origen::Red => Some("se carga por RED".into()),
            Origen::Extraible => Some("se carga de un EXTRAIBLE".into()),
            Origen::Disco => match o.ruta.fichero() {
                Some(f) if !f.to_ascii_uppercase().starts_with("\\EFI\\") => {
                    Some(format!("carga '{f}', fuera de \\EFI\\"))
                }
                _ => None,
            },
            _ => None,
        }
    };
    if let Some(v) = a.global("BootNext") {
        if let Some(n) = v.datos.get(0..2).map(|b| u16::from_le_bytes([b[0], b[1]])) {
            let destino = ops.iter().find(|o| o.numero == n);
            hallazgos.push(format!(
                "BootNext={n:04X} esta puesto: el proximo arranque, y solo ese, ejecutara {}",
                destino.map_or_else(
                    || "una entrada que NO EXISTE".to_string(),
                    |o| format!("'{}' ({})", o.descripcion, o.ruta.texto())
                )
            ));
        }
    }
    if let Some(primera) = orden
        .iter()
        .filter_map(|n| ops.iter().find(|o| o.numero == *n && o.activa))
        .next()
    {
        if let Some(motivo) = raro(primera) {
            hallazgos.push(format!(
                "la primera entrada activa de BootOrder, Boot{:04X} '{}', {motivo}",
                primera.numero, primera.descripcion
            ));
        }
    }
    let estado = if orden.is_empty() && ops.is_empty() {
        CheckState::Indeterminado("no hay BootOrder ni entradas Boot####".into())
    } else if hallazgos.is_empty() {
        CheckState::Ok
    } else {
        CheckState::Fallo(hallazgos.join("; "))
    };
    Comprobacion::nueva(
        "uefi-entradas-arranque",
        Superficie::VariablesUefi,
        Naturaleza::Compromiso,
        estado,
    )
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;
    use crate::ruta_dispositivo::pruebas::{fichero, fin, nodo, ruta_disco};

    pub(crate) fn var(nombre: &str, guid: Guid, atributos: u32, datos: &[u8]) -> VariableUefi {
        VariableUefi {
            nombre: nombre.into(),
            guid,
            atributos,
            datos: datos.to_vec(),
        }
    }

    pub(crate) fn opcion(desc: &str, ruta: &[u8], activa: bool) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&u32::from(activa).to_le_bytes());
        v.extend_from_slice(&(ruta.len() as u16).to_le_bytes());
        v.extend(desc.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
        v.extend_from_slice(ruta);
        v
    }

    /// Una dbx minima con una lista de un hash SHA-256.
    fn dbx() -> Vec<u8> {
        let mut l = Vec::new();
        l.extend_from_slice(&aegis_firmware::uefi::EFI_CERT_SHA256.0);
        l.extend_from_slice(&(28u32 + 48).to_le_bytes());
        l.extend_from_slice(&0u32.to_le_bytes());
        l.extend_from_slice(&48u32.to_le_bytes());
        l.extend_from_slice(&[0x77; 16]);
        l.extend_from_slice(&[0xEE; 32]);
        l
    }

    pub(crate) fn almacen_sano() -> Almacen {
        Almacen {
            variables: vec![
                var("SecureBoot", EFI_GLOBAL, ATRIB_VOLATIL, &[1]),
                var("SetupMode", EFI_GLOBAL, ATRIB_VOLATIL, &[0]),
                var("AuditMode", EFI_GLOBAL, ATRIB_VOLATIL, &[0]),
                var("PK", EFI_GLOBAL, ATRIB_AUTENTICADA, &[1, 2, 3]),
                var("KEK", EFI_GLOBAL, ATRIB_AUTENTICADA, &[1]),
                var("db", EFI_IMAGE_SECURITY_DATABASE, ATRIB_AUTENTICADA, &[1]),
                var(
                    "dbx",
                    EFI_IMAGE_SECURITY_DATABASE,
                    ATRIB_AUTENTICADA,
                    &dbx(),
                ),
                var("BootOrder", EFI_GLOBAL, ATRIB_ARRANQUE, &[1, 0, 2, 0]),
                var(
                    "Boot0001",
                    EFI_GLOBAL,
                    ATRIB_ARRANQUE,
                    &opcion("ubuntu", &ruta_disco("\\EFI\\ubuntu\\shimx64.efi"), true),
                ),
                var(
                    "Boot0002",
                    EFI_GLOBAL,
                    ATRIB_ARRANQUE,
                    &opcion(
                        "Windows Boot Manager",
                        &ruta_disco("\\EFI\\Microsoft\\Boot\\bootmgfw.efi"),
                        true,
                    ),
                ),
            ],
            ilegibles: Vec::new(),
        }
    }

    fn por_id<'a>(v: &'a [Comprobacion], id: &str) -> &'a Comprobacion {
        v.iter().find(|c| c.id == id).expect(id)
    }

    #[test]
    fn un_almacen_sano_pasa_las_cuatro() {
        for c in evaluar(&Ok(almacen_sano())) {
            assert_eq!(c.estado, CheckState::Ok, "{}", c.linea());
        }
    }

    #[test]
    fn el_nombre_de_fichero_de_efivarfs_se_separa_en_nombre_y_guid() {
        let (n, g) =
            separar_nombre("Boot0001-8be4df61-93ca-11d2-aa0d-00e098032b8c").expect("valido");
        assert_eq!(n, "Boot0001");
        assert_eq!(g, EFI_GLOBAL);
        assert!(separar_nombre("corto").is_none());
        assert!(separar_nombre("-8be4df61-93ca-11d2-aa0d-00e098032b8c").is_none());
        assert!(separar_nombre("X-no-es-un-guid-de-ninguna-maneraxxxxxx").is_none());
    }

    /// AuditMode: Secure Boot «encendido» que no impone nada.
    #[test]
    fn audit_mode_hace_que_secure_boot_no_imponga_nada() {
        let mut a = almacen_sano();
        a.variables.retain(|v| v.nombre != "AuditMode");
        a.variables
            .push(var("AuditMode", EFI_GLOBAL, ATRIB_VOLATIL, &[1]));
        let c = evaluar(&Ok(a));
        assert!(
            format!("{:?}", por_id(&c, "uefi-secure-boot-imponiendo").estado)
                .contains("AuditMode=1")
        );
    }

    #[test]
    fn db_sin_escritura_autenticada_es_una_puerta() {
        let mut a = almacen_sano();
        for v in &mut a.variables {
            if v.nombre == "db" {
                v.atributos = ATRIB_ARRANQUE;
            }
            if v.nombre == "SecureBoot" {
                v.atributos = ATRIB_ARRANQUE;
            }
        }
        let c = evaluar(&Ok(a));
        let m = format!("{:?}", por_id(&c, "uefi-atributos-seguridad").estado);
        assert!(
            m.contains("db lleva") && m.contains("SIN escritura autenticada"),
            "{m}"
        );
        assert!(
            m.contains("SecureBoot lleva") && m.contains("NO VOLATIL"),
            "{m}"
        );
    }

    #[test]
    fn secure_boot_sin_dbx_o_con_dbx_vacia_es_exposicion() {
        let mut a = almacen_sano();
        a.variables.retain(|v| v.nombre != "dbx");
        assert!(por_id(&evaluar(&Ok(a.clone())), "uefi-dbx")
            .estado
            .es_fallo());
        a.variables.push(var(
            "dbx",
            EFI_IMAGE_SECURITY_DATABASE,
            ATRIB_AUTENTICADA,
            &[],
        ));
        assert!(format!("{:?}", por_id(&evaluar(&Ok(a)), "uefi-dbx").estado).contains("VACIA"));
    }

    #[test]
    fn las_opciones_de_carga_se_decodifican_en_orden() {
        let (orden, ops) = opciones(&almacen_sano());
        assert_eq!(orden, vec![1, 2]);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].descripcion, "ubuntu");
        assert_eq!(
            ops[0].ruta.fichero().as_deref(),
            Some("\\EFI\\ubuntu\\shimx64.efi")
        );
        assert!(ops[0].activa);
        assert!(analizar_opcion(0, &[1, 0]).is_none(), "truncada");
        assert!(
            analizar_opcion(0, &[1, 0, 0, 0, 0xFF, 0xFF, b'a', 0, 0, 0]).is_none(),
            "rutas mas largas que la variable"
        );
    }

    /// LO QUE SI ES DE COMPROMISO: dejar preparado lo que ejecutara el proximo
    /// arranque.
    #[test]
    fn boot_next_y_una_primera_entrada_rara_son_compromiso() {
        let mut a = almacen_sano();
        let mut usb = nodo(0x03, 0x05, &[1, 0]);
        usb.extend(fichero("\\EFI\\BOOT\\BOOTX64.EFI"));
        usb.extend(fin());
        a.variables.push(var(
            "Boot0009",
            EFI_GLOBAL,
            ATRIB_ARRANQUE,
            &opcion("x", &usb, true),
        ));
        a.variables
            .push(var("BootNext", EFI_GLOBAL, ATRIB_ARRANQUE, &[9, 0]));
        let c = evaluar(&Ok(a.clone()));
        let e = por_id(&c, "uefi-entradas-arranque");
        assert_eq!(e.naturaleza, Naturaleza::Compromiso);
        assert!(format!("{:?}", e.estado).contains("BootNext=0009"));

        let mut b = almacen_sano();
        for v in &mut b.variables {
            if v.nombre == "Boot0001" {
                v.datos = opcion("ubuntu", &ruta_disco("\\Windows\\Temp\\x.efi"), true);
            }
        }
        // Se compara el mensaje, no su forma `Debug`: esa duplica las barras
        // invertidas y la ruta no casaria nunca.
        let c = evaluar(&Ok(b));
        let CheckState::Fallo(m) = &por_id(&c, "uefi-entradas-arranque").estado else {
            panic!("una primera entrada fuera de \\EFI\\ tiene que fallar");
        };
        assert!(m.contains("fuera de \\EFI\\"), "{m}");
    }

    #[test]
    fn sin_uefi_todo_es_no_aplicable_con_su_motivo() {
        let c = evaluar(&Err("no arranco por UEFI".into()));
        assert_eq!(c.len(), 4);
        assert!(c
            .iter()
            .all(|x| matches!(x.estado, CheckState::NoAplicable(_))));
    }

    /// Un efivarfs de verdad en disco (un directorio con el formato real de los
    /// ficheros: 4 bytes de atributos y los datos), leido por el mismo lector.
    #[test]
    fn un_directorio_efivarfs_se_lee_con_sus_atributos() {
        let dir = std::env::temp_dir().join(format!("aegis-efivars-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        for v in almacen_sano().variables {
            let mut b = v.atributos.to_le_bytes().to_vec();
            b.extend_from_slice(&v.datos);
            std::fs::write(dir.join(format!("{}-{}", v.nombre, v.guid.hyphenated())), b)
                .expect("escribir");
        }
        std::fs::write(
            dir.join("corta-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            [1, 2],
        )
        .expect("x");
        let a = leer(&dir).expect("leer");
        assert_eq!(a.variables.len(), almacen_sano().variables.len());
        assert_eq!(
            a.ilegibles.len(),
            1,
            "la variable corta se declara, no se omite"
        );
        for c in evaluar(&Ok(a)) {
            assert_eq!(c.estado, CheckState::Ok, "{}", c.linea());
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(leer(&dir).is_err());
    }
}
