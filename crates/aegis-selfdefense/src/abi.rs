//! Contratos de ABI para la autodefensa empresarial en Windows: el callback de
//! ELAM (Early Launch Anti-Malware) y la proteccion de proceso PPL.
//!
//! # Por que una capa de ABI, y por que aqui se verifica en COMPILACION
//!
//! La [`crate::elam`] decide (bueno/malo/critico) y la [`crate::ppl`] comprueba
//! requisitos; esta capa es el **contrato binario** con el que esas decisiones
//! cruzan la frontera hacia el kernel de Windows. Un driver ELAM del WDK recibe
//! del kernel una estructura `BDCB_IMAGE_INFORMATION` y devuelve un codigo
//! `BDCB_CLASSIFICATION`; un proceso protegido lleva un byte `PS_PROTECTION` con
//! un formato de bits exacto. Si el tamano, el orden de los campos o el valor de
//! un enum no coinciden **al byte** con los del `ntddk.h` del WDK, el driver lee
//! basura o el kernel rechaza la peticion. Por eso cada estructura de esta capa
//! lleva su tamano, su alineacion y sus offsets **verificados en compilacion**
//! (`assert!` en contexto `const`): la ABI no puede desincronizarse en silencio;
//! si alguien la rompe, no compila.
//!
//! # El muro fisico, declarado
//!
//! Registrar el callback ELAM de verdad (`IoRegisterBootDriverCallback`), o que
//! el kernel conceda PPL-Antimalware, exige el WDK, un driver `.sys` firmado y un
//! certificado AM co-firmado por Microsoft (ver [`crate::ppl`]). Nada de eso
//! existe en el runner del CI, y **no se finge**: esta capa aporta y verifica los
//! CONTRATOS (las estructuras y los codigos que el driver usaria), y
//! `tools/verificar-resiliencia.sh` declara que la carga en vivo del driver no se
//! ejercio aqui. Lo que se entrega, se comprueba; lo que no, se dice.
//!
//! Las estructuras se modelan para el ABI de **Windows x64** (punteros de 8
//! bytes, `ULONG`=4, `USHORT`=2). Se representan con anchos fijos (`u64` para un
//! puntero, nunca `usize`) para que el contrato sea el mismo lo compile quien lo
//! compile —incluido el Linux x64 del CI—, no el del anfitrion.

use core::mem::{align_of, offset_of, size_of};

// ------------------------------------------------------------------------------
// ELAM: el callback de clasificacion de drivers de arranque (BDCB_*).
// ------------------------------------------------------------------------------

/// Tipo de invocacion del callback de driver de arranque (`BDCB_CALLBACK_TYPE`).
///
/// El kernel llama al callback registrado con uno de estos motivos: para una
/// actualizacion de estado del proceso de arranque, o para pedir la
/// clasificacion de una imagen concreta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum BdcbCallbackType {
    /// Actualizacion de estado del arranque (`BdCbStatusUpdate`).
    StatusUpdate = 0,
    /// Se pide clasificar una imagen que se va a cargar (`BdCbInitializeImage`).
    InitializeImage = 1,
}

impl BdcbCallbackType {
    /// El valor `int` que Windows usa en el `enum`.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Codigo de clasificacion que el callback ELAM devuelve al kernel
/// (`BDCB_CLASSIFICATION`).
///
/// **Estos son los valores REALES del WDK**, y son el motivo de que esta capa
/// exista: no coinciden con el orden interno de [`crate::elam::ClasificacionElam`]
/// (que es una decision nuestra, no un codigo de wire). En Windows, `0` es
/// "desconocida", no "buena". El puente correcto entre nuestra decision y este
/// codigo es [`From<crate::elam::ClasificacionElam>`], probado en
/// [`crate::elam`]; devolver el numero equivocado haria que el kernel bloqueara
/// un driver bueno o cargara uno malo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum BdcbClassification {
    /// Imagen desconocida: ni buena ni mala conocida (`...UnknownImage`).
    UnknownImage = 0,
    /// Imagen buena conocida: se carga (`...KnownGoodImage`).
    KnownGoodImage = 1,
    /// Imagen mala conocida y NO critica de arranque: se bloquea
    /// (`...KnownBadImage`).
    KnownBadImage = 2,
    /// Imagen mala conocida PERO critica de arranque: el kernel la carga igual
    /// para no dejar la maquina sin arrancar (`...KnownBadImageBootCritical`).
    KnownBadImageBootCritical = 3,
    /// Centinela de fin del enum del WDK (`...End`).
    End = 4,
}

impl BdcbClassification {
    /// El valor `int` que Windows espera del callback.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Interpreta con seguridad un `int` recibido del kernel. Un valor fuera de
    /// rango se colapsa en [`BdcbClassification::UnknownImage`] (la clasificacion
    /// mas conservadora: no bloquea, observa) en vez de ser comportamiento
    /// indefinido, como seria un `transmute`.
    #[must_use]
    pub const fn desde_i32(v: i32) -> Self {
        match v {
            1 => BdcbClassification::KnownGoodImage,
            2 => BdcbClassification::KnownBadImage,
            3 => BdcbClassification::KnownBadImageBootCritical,
            4 => BdcbClassification::End,
            _ => BdcbClassification::UnknownImage,
        }
    }
}

/// `UNICODE_STRING` de Windows x64: un contador de longitud y un puntero al
/// buffer UTF-16. **No** posee el buffer; es una vista sobre memoria del kernel.
///
/// Disposicion x64: `USHORT`(2) + `USHORT`(2) + 4 de relleno + `PWSTR`(8) = 16.
/// El relleno lo obliga la alineacion a 8 del puntero; se verifica abajo.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UnicodeString {
    /// Longitud en BYTES del contenido (no en caracteres).
    pub length: u16,
    /// Capacidad en bytes del buffer.
    pub maximum_length: u16,
    /// Puntero al buffer UTF-16 (modelado como u64: es un puntero de 64 bits).
    pub buffer: u64,
}

/// Informacion de una imagen que el kernel entrega al callback ELAM para que la
/// clasifique (`BDCB_IMAGE_INFORMATION`).
///
/// El campo `classification` se modela como `i32` crudo (no como el enum) a
/// proposito: es un valor que viene del otro lado de la frontera, y darle un tipo
/// enum a bytes arbitrarios seria comportamiento indefinido. Se interpreta con
/// [`BdcbClassification::desde_i32`] y se responde con
/// [`BdcbClassification::as_i32`].
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BdcbImageInformation {
    /// Clasificacion (in/out), como `int` crudo. Ver arriba.
    pub classification: i32,
    /// Banderas de la imagen (`BDCB_IMAGE_FLAGS`).
    pub image_flags: u32,
    /// Nombre de la imagen.
    pub image_name: UnicodeString,
    /// Ruta del registro del servicio del driver.
    pub registry_path: UnicodeString,
    /// Publicador del certificado de firma.
    pub certificate_publisher: UnicodeString,
    /// Emisor del certificado de firma.
    pub certificate_issuer: UnicodeString,
    /// Puntero al hash de la imagen (modelado como u64).
    pub image_hash: u64,
    /// Puntero a la huella del certificado (modelado como u64).
    pub certificate_thumbprint: u64,
    /// Algoritmo del hash de la imagen (identificador de algoritmo CNG).
    pub image_hash_algorithm: u32,
    /// Algoritmo del hash de la huella.
    pub thumbprint_hash_algorithm: u32,
    /// Longitud en bytes del hash de la imagen.
    pub image_hash_length: u32,
    /// Longitud en bytes de la huella del certificado.
    pub certificate_thumbprint_length: u32,
}

// --- Verificacion del contrato ELAM en COMPILACION -----------------------------
// Si el WDK y esto se desincronizan, el proyecto no compila. Es la unica forma
// honesta de "probar" una ABI que aqui no se puede ejecutar contra el kernel.
const _: () = assert!(
    size_of::<UnicodeString>() == 16,
    "UNICODE_STRING x64 = 16 B"
);
const _: () = assert!(
    align_of::<UnicodeString>() == 8,
    "UNICODE_STRING alinea a 8"
);
const _: () = assert!(
    size_of::<BdcbImageInformation>() == 104,
    "BDCB_IMAGE_INFORMATION x64 = 104 B"
);
const _: () = assert!(align_of::<BdcbImageInformation>() == 8);
// Offsets clave: si un campo se mueve, el driver leeria el equivocado.
const _: () = assert!(offset_of!(BdcbImageInformation, classification) == 0);
const _: () = assert!(offset_of!(BdcbImageInformation, image_flags) == 4);
const _: () = assert!(offset_of!(BdcbImageInformation, image_name) == 8);
const _: () = assert!(offset_of!(BdcbImageInformation, registry_path) == 24);
const _: () = assert!(offset_of!(BdcbImageInformation, image_hash) == 72);
const _: () = assert!(offset_of!(BdcbImageInformation, image_hash_algorithm) == 88);
const _: () = assert!(offset_of!(BdcbImageInformation, certificate_thumbprint_length) == 100);

// ------------------------------------------------------------------------------
// ELAM: registro del servicio del driver (constantes bien conocidas).
// ------------------------------------------------------------------------------

/// Grupo de orden de carga en el que arranca un driver ELAM. El kernel carga
/// este grupo antes que los drivers de terceros.
pub const GRUPO_CARGA_EARLY_LAUNCH: &str = "Early-Launch";

/// Valor `Start` del servicio para arrancar en el arranque (`SERVICE_BOOT_START`).
/// Un driver ELAM tiene que ser boot-start para estar antes que el malware.
pub const SERVICE_BOOT_START: u32 = 0;

// ------------------------------------------------------------------------------
// PPL: el byte PS_PROTECTION y como se arranca un servicio protegido.
// ------------------------------------------------------------------------------

/// Tipo de proteccion de proceso (`PS_PROTECTED_TYPE`), en los bits 0..2 de
/// `PS_PROTECTION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PsProtectedType {
    /// Sin proteccion.
    None = 0,
    /// Proceso protegido ligero (PPL): la variante que usa un AV/EDR.
    ProtectedLight = 1,
    /// Proceso protegido pleno (reservado a componentes del sistema).
    Protected = 2,
}

/// Firmante que respalda la proteccion (`PS_PROTECTED_SIGNER`), en los bits 4..7
/// de `PS_PROTECTION`. Para un AV/EDR, el relevante es
/// [`PsProtectedSigner::Antimalware`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PsProtectedSigner {
    /// Ninguno.
    None = 0,
    /// Authenticode.
    Authenticode = 1,
    /// Generacion de codigo (CodeGen).
    CodeGen = 2,
    /// Antimalware: el firmante de un AV/EDR con certificado AM de Microsoft.
    Antimalware = 3,
    /// LSA.
    Lsa = 4,
    /// Windows.
    Windows = 5,
    /// WinTcb (base de computo de confianza).
    WinTcb = 6,
    /// WinSystem.
    WinSystem = 7,
    /// Aplicacion (AppLocker / proteccion de apps de la Store).
    App = 8,
}

/// El byte `PS_PROTECTION`: `Signer(4 bits) | Audit(1 bit) | Type(3 bits)`.
///
/// Es lo que el kernel guarda en el `EPROCESS` para decidir a quien deja abrir el
/// proceso con derechos peligrosos. Para AegisCore-Antimalware-Light el byte es
/// `0x31`, lo mismo que [`crate::ppl::NIVEL_PPL_ANTIMALWARE_CODIGO`]; ambos se
/// atan abajo en compilacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PsProtection(pub u8);

impl PsProtection {
    /// Compone el byte a partir del tipo, el firmante y el bit de auditoria.
    #[must_use]
    pub const fn nueva(
        tipo: PsProtectedType,
        firmante: PsProtectedSigner,
        auditoria: bool,
    ) -> Self {
        let t = tipo as u8 & 0b0000_0111;
        let a = (auditoria as u8) << 3;
        let s = (firmante as u8) << 4;
        PsProtection(s | a | t)
    }

    /// El byte `PS_PROTECTION` (== campo `Level`).
    #[must_use]
    pub const fn level(self) -> u8 {
        self.0
    }

    /// Los bits de tipo (0..2).
    #[must_use]
    pub const fn tipo_crudo(self) -> u8 {
        self.0 & 0b0000_0111
    }

    /// El bit de auditoria (3).
    #[must_use]
    pub const fn auditoria(self) -> bool {
        (self.0 >> 3) & 1 == 1
    }

    /// Los bits de firmante (4..7).
    #[must_use]
    pub const fn firmante_crudo(self) -> u8 {
        self.0 >> 4
    }
}

/// Nivel de proteccion de lanzamiento de un SERVICIO (`SERVICE_LAUNCH_PROTECTED_*`).
///
/// Es la via real por la que AegisCore, como servicio, pide al SCM arrancar
/// protegido: `ChangeServiceConfig2` con `SERVICE_CONFIG_LAUNCH_PROTECTED`. Para
/// un antimalware es [`NivelLanzamientoProtegido::AntimalwareLight`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NivelLanzamientoProtegido {
    /// Sin proteccion de lanzamiento.
    None = 0,
    /// Windows.
    Windows = 1,
    /// Windows ligero.
    WindowsLight = 2,
    /// Antimalware ligero: el nivel de un AV/EDR.
    AntimalwareLight = 3,
}

impl NivelLanzamientoProtegido {
    /// El valor que espera el SCM.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Atributo de `UpdateProcThreadAttribute` para arrancar un hijo protegido
/// (`PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL`). Se documenta como la via
/// alternativa (crear un proceso protegido directamente, no via servicio).
pub const PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL: u32 = 0x0002_000B;

// ------------------------------------------------------------------------------
// Codigos de control del SCM (Service Control Manager) que llegan al servicio.
// Los consume el guardian de detencion en [`crate::resiliencia`].
// ------------------------------------------------------------------------------

/// Parar el servicio (`SERVICE_CONTROL_STOP`).
pub const SERVICE_CONTROL_STOP: u32 = 0x0000_0001;
/// Pausar el servicio (`SERVICE_CONTROL_PAUSE`).
pub const SERVICE_CONTROL_PAUSE: u32 = 0x0000_0002;
/// Reanudar el servicio (`SERVICE_CONTROL_CONTINUE`).
pub const SERVICE_CONTROL_CONTINUE: u32 = 0x0000_0003;
/// Consultar el estado (`SERVICE_CONTROL_INTERROGATE`).
pub const SERVICE_CONTROL_INTERROGATE: u32 = 0x0000_0004;
/// Apagado del sistema (`SERVICE_CONTROL_SHUTDOWN`).
pub const SERVICE_CONTROL_SHUTDOWN: u32 = 0x0000_0005;
/// Pre-apagado del sistema (`SERVICE_CONTROL_PRESHUTDOWN`).
pub const SERVICE_CONTROL_PRESHUTDOWN: u32 = 0x0000_000F;

// --- Verificacion del contrato PPL en COMPILACION ------------------------------
const _: () = assert!(size_of::<PsProtection>() == 1, "PS_PROTECTION es un UCHAR");
// El byte de AegisCore (Antimalware + ProtectedLight, sin auditoria) es 0x31, y
// tiene que ser IGUAL al que ya publica el modulo ppl. Aqui se atan.
const _: () = assert!(
    PsProtection::nueva(
        PsProtectedType::ProtectedLight,
        PsProtectedSigner::Antimalware,
        false
    )
    .level()
        == crate::ppl::NIVEL_PPL_ANTIMALWARE_CODIGO
);
const _: () = assert!(
    PsProtection::nueva(
        PsProtectedType::ProtectedLight,
        PsProtectedSigner::Antimalware,
        false
    )
    .level()
        == 0x31
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn los_codigos_bdcb_son_los_reales_de_windows() {
        // En Windows, 0 es DESCONOCIDA, no buena. Esta es justo la trampa que la
        // capa de ABI existe para evitar.
        assert_eq!(BdcbClassification::UnknownImage.as_i32(), 0);
        assert_eq!(BdcbClassification::KnownGoodImage.as_i32(), 1);
        assert_eq!(BdcbClassification::KnownBadImage.as_i32(), 2);
        assert_eq!(BdcbClassification::KnownBadImageBootCritical.as_i32(), 3);
        assert_eq!(BdcbClassification::End.as_i32(), 4);
    }

    #[test]
    fn bdcb_desde_i32_es_total_y_conservador() {
        assert_eq!(
            BdcbClassification::desde_i32(1),
            BdcbClassification::KnownGoodImage
        );
        assert_eq!(
            BdcbClassification::desde_i32(3),
            BdcbClassification::KnownBadImageBootCritical
        );
        // Cualquier valor fuera de rango -> UnknownImage (no bloquea, observa),
        // nunca comportamiento indefinido.
        assert_eq!(
            BdcbClassification::desde_i32(-1),
            BdcbClassification::UnknownImage
        );
        assert_eq!(
            BdcbClassification::desde_i32(99),
            BdcbClassification::UnknownImage
        );
    }

    #[test]
    fn el_callback_type_coincide_con_windows() {
        assert_eq!(BdcbCallbackType::StatusUpdate.as_i32(), 0);
        assert_eq!(BdcbCallbackType::InitializeImage.as_i32(), 1);
    }

    #[test]
    fn ps_protection_descompone_el_byte_como_windows() {
        // Antimalware(3) << 4 | Audit(0) << 3 | ProtectedLight(1) = 0x31.
        let p = PsProtection::nueva(
            PsProtectedType::ProtectedLight,
            PsProtectedSigner::Antimalware,
            false,
        );
        assert_eq!(p.level(), 0x31);
        assert_eq!(p.firmante_crudo(), PsProtectedSigner::Antimalware as u8);
        assert_eq!(p.tipo_crudo(), PsProtectedType::ProtectedLight as u8);
        assert!(!p.auditoria());

        // Con el bit de auditoria puesto: 0x31 | 0x08 = 0x39.
        let pa = PsProtection::nueva(
            PsProtectedType::ProtectedLight,
            PsProtectedSigner::Antimalware,
            true,
        );
        assert_eq!(pa.level(), 0x39);
        assert!(pa.auditoria());
    }

    #[test]
    fn el_nivel_de_lanzamiento_de_servicio_es_el_del_scm() {
        assert_eq!(NivelLanzamientoProtegido::None.as_u32(), 0);
        assert_eq!(NivelLanzamientoProtegido::Windows.as_u32(), 1);
        assert_eq!(NivelLanzamientoProtegido::WindowsLight.as_u32(), 2);
        assert_eq!(NivelLanzamientoProtegido::AntimalwareLight.as_u32(), 3);
    }

    #[test]
    fn el_atributo_de_proceso_protegido_es_el_de_windows() {
        assert_eq!(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, 0x0002_000B);
    }
}
