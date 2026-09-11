//! Extended Page Tables (EPT): las estructuras de traduccion de memoria del
//! hardware de virtualizacion de Intel, y la clasificacion de sus violaciones.
//!
//! # Para que, en defensa
//!
//! Un rootkit de Ring 0 controla las tablas de paginas del SO, asi que puede
//! mentirle a cualquier herramienta que corra DENTRO del SO sobre que hay en la
//! memoria. Las EPT son una segunda capa de traduccion que controla el
//! HIPERVISOR (Ring -1), por debajo del SO: el rootkit no las ve ni las toca. Si
//! AegisCore marca las paginas de codigo del kernel como **solo ejecucion** (o
//! solo lectura) en las EPT, entonces:
//!
//! - Ejecutar codigo desde una pagina que NO marcamos ejecutable dispara una
//!   **EPT violation** de ejecucion: es un modulo oculto corriendo.
//! - Escribir sobre una pagina de codigo protegida dispara una violacion de
//!   escritura: es alguien parcheando el kernel (un hook en linea).
//!
//! Esa deteccion es puramente DEFENSIVA: se observa el SO desde debajo para
//! delatar la manipulacion. No se persiste, no se oculta nada, no se pelea con el
//! dueno de la maquina.
//!
//! # Honestidad
//!
//! El **diseno de las estructuras** (tamano y disposicion de bits, verificados en
//! compilacion) y la **logica de traduccion y clasificacion** son Rust puro y se
//! prueban aqui. Programar estas tablas en un procesador de verdad y atrapar sus
//! violaciones necesita VT-x/AMD-V y privilegios: es el muro, gated tras la
//! caracteristica `kvm`.

/// Una entrada de una tabla EPT (8 bytes). Los bits siguen el formato de Intel
/// SDM vol. 3C: bit 0 lectura, bit 1 escritura, bit 2 ejecucion, bit 7 "pagina
/// grande" (hoja en PDPTE/PDE), y la direccion fisica del siguiente nivel o del
/// marco de pagina en los bits 51:12.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct EntradaEpt(pub u64);

/// Mascara de la direccion fisica de 4 KiB alineada (bits 51:12).
const MASCARA_DIR: u64 = 0x000F_FFFF_FFFF_F000;

impl EntradaEpt {
    /// Una entrada vacia (no presente).
    #[must_use]
    pub const fn vacia() -> Self {
        EntradaEpt(0)
    }

    /// Construye una entrada que apunta a `dir_fisica` con los permisos dados.
    #[must_use]
    pub const fn nueva(dir_fisica: u64, lectura: bool, escritura: bool, ejecucion: bool) -> Self {
        let mut v = dir_fisica & MASCARA_DIR;
        if lectura {
            v |= 1;
        }
        if escritura {
            v |= 1 << 1;
        }
        if ejecucion {
            v |= 1 << 2;
        }
        EntradaEpt(v)
    }

    /// Marca esta entrada como hoja de pagina grande (bit 7): en un PDPTE es una
    /// pagina de 1 GiB, en un PDE de 2 MiB.
    #[must_use]
    pub const fn como_pagina_grande(self) -> Self {
        EntradaEpt(self.0 | (1 << 7))
    }

    /// Permiso de lectura (bit 0).
    #[must_use]
    pub const fn lectura(self) -> bool {
        self.0 & 1 != 0
    }

    /// Permiso de escritura (bit 1).
    #[must_use]
    pub const fn escritura(self) -> bool {
        self.0 & (1 << 1) != 0
    }

    /// Permiso de ejecucion (bit 2).
    #[must_use]
    pub const fn ejecucion(self) -> bool {
        self.0 & (1 << 2) != 0
    }

    /// Una entrada esta presente si tiene ALGUN permiso (R, W o X): en EPT, los
    /// tres bits a cero significan "no presente".
    #[must_use]
    pub const fn presente(self) -> bool {
        self.0 & 0b111 != 0
    }

    /// Es una hoja de pagina grande (bit 7).
    #[must_use]
    pub const fn es_pagina_grande(self) -> bool {
        self.0 & (1 << 7) != 0
    }

    /// La direccion fisica a la que apunta (bits 51:12).
    #[must_use]
    pub const fn direccion_fisica(self) -> u64 {
        self.0 & MASCARA_DIR
    }
}

/// Una tabla EPT: 512 entradas de 8 bytes = exactamente una pagina de 4 KiB.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
pub struct TablaEpt {
    /// Las 512 entradas de la tabla.
    pub entradas: [EntradaEpt; 512],
}

impl Default for TablaEpt {
    fn default() -> Self {
        Self::vacia()
    }
}

impl TablaEpt {
    /// Una tabla toda a cero (nada mapeado).
    #[must_use]
    pub const fn vacia() -> Self {
        TablaEpt {
            entradas: [EntradaEpt::vacia(); 512],
        }
    }
}

// Verificacion de ABI/tamano EN COMPILACION: si el tamano no cuadra, no compila.
// Es la "honestidad de CI" que pide la fase para las estructuras de hardware.
const _: () = assert!(core::mem::size_of::<EntradaEpt>() == 8);
const _: () = assert!(core::mem::size_of::<TablaEpt>() == 4096);
const _: () = assert!(core::mem::align_of::<TablaEpt>() == 4096);

/// El resultado de traducir una direccion fisica de invitado (GPA) a fisica de
/// anfitrion (HPA) por las EPT, con los permisos efectivos (el Y logico de los
/// permisos de cada nivel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Traduccion {
    /// Direccion fisica de anfitrion resultante.
    pub hpa: u64,
    /// Permiso efectivo de lectura.
    pub lectura: bool,
    /// Permiso efectivo de escritura.
    pub escritura: bool,
    /// Permiso efectivo de ejecucion.
    pub ejecucion: bool,
}

/// Por que fallo una traduccion EPT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EptFallo {
    /// Una tabla intermedia no estaba en la memoria dada.
    #[error("tabla EPT ausente en {0:#x}")]
    TablaAusente(u64),
    /// La entrada del nivel `nivel` no esta presente: la GPA no esta mapeada.
    #[error("GPA no mapeada: entrada no presente en el nivel {0}")]
    NoPresente(u8),
}

/// Extrae el indice de 9 bits de la GPA para un nivel (por su desplazamiento).
const fn indice(gpa: u64, desplazamiento: u32) -> usize {
    ((gpa >> desplazamiento) & 0x1FF) as usize
}

/// Traduce una GPA a HPA recorriendo las cuatro tablas EPT (PML4 -> PDPT -> PD ->
/// PT), empezando en la tabla raiz `pml4`. `leer` entrega la tabla que hay en una
/// direccion fisica (en produccion, leyendo la memoria del anfitrion; en las
/// pruebas, de un mapa).
///
/// Soporta paginas de 4 KiB (los cuatro niveles) y paginas grandes de 1 GiB
/// (hoja en PDPTE) y 2 MiB (hoja en PDE). Los permisos efectivos son el Y logico
/// de los de cada nivel, como en el hardware.
///
/// # Errores
/// [`EptFallo`] si una tabla falta o una entrada no esta presente.
pub fn traducir(
    pml4: u64,
    gpa: u64,
    leer: &impl Fn(u64) -> Option<TablaEpt>,
) -> Result<Traduccion, EptFallo> {
    // (desplazamiento del indice, mascara del offset dentro de una hoja en ese nivel)
    let niveles: [(u32, u64); 4] = [
        (39, 0),           // PML4: nunca es hoja
        (30, 0x3FFF_FFFF), // PDPT: hoja = 1 GiB
        (21, 0x001F_FFFF), // PD: hoja = 2 MiB
        (12, 0x0000_0FFF), // PT: hoja = 4 KiB (siempre)
    ];

    let mut dir_tabla = pml4;
    let mut lectura = true;
    let mut escritura = true;
    let mut ejecucion = true;

    for (nivel_idx, (desplazamiento, offset_hoja)) in niveles.iter().enumerate() {
        let tabla = leer(dir_tabla).ok_or(EptFallo::TablaAusente(dir_tabla))?;
        let entrada = tabla.entradas[indice(gpa, *desplazamiento)];
        let nivel = 4 - nivel_idx as u8;
        if !entrada.presente() {
            return Err(EptFallo::NoPresente(nivel));
        }
        // Los permisos se acumulan por Y logico.
        lectura &= entrada.lectura();
        escritura &= entrada.escritura();
        ejecucion &= entrada.ejecucion();

        // Es hoja si estamos en el PT (ultimo nivel) o si la entrada marca pagina
        // grande en un nivel que lo permite (PDPT/PD).
        let es_ultimo = nivel_idx == niveles.len() - 1;
        if es_ultimo || (entrada.es_pagina_grande() && *offset_hoja != 0) {
            let hpa = entrada.direccion_fisica() | (gpa & *offset_hoja);
            return Ok(Traduccion {
                hpa,
                lectura,
                escritura,
                ejecucion,
            });
        }
        dir_tabla = entrada.direccion_fisica();
    }
    // Inalcanzable: el ultimo nivel siempre es hoja.
    Err(EptFallo::NoPresente(0))
}

/// El tipo de acceso que provoco una EPT violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceso {
    /// Lectura de datos.
    Lectura,
    /// Escritura de datos.
    Escritura,
    /// Obtencion de instruccion (ejecucion).
    Ejecucion,
}

/// Una EPT violation notificada por el hardware: que GPA se toco y como.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViolacionEpt {
    /// Direccion fisica de invitado que se intento acceder.
    pub gpa: u64,
    /// Tipo de acceso.
    pub acceso: Acceso,
}

/// El veredicto defensivo de una EPT violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VeredictoEpt {
    /// El acceso estaba permitido por las EPT (no deberia haber violado; ruido).
    Permitido,
    /// Se ejecuto codigo desde una pagina que NO estaba marcada ejecutable: un
    /// modulo oculto corriendo por debajo del SO.
    EjecucionOculta,
    /// Se ejecuto desde una GPA no mapeada: shellcode fuera de toda pagina
    /// conocida.
    EjecucionNoMapeada,
    /// Se escribio sobre una pagina de solo lectura/ejecucion: parcheo de codigo
    /// del kernel (un hook en linea).
    EscrituraDeCodigo,
    /// Lectura de una pagina que protegimos contra lectura (p. ej. una region de
    /// secretos del kernel).
    LecturaProhibida,
}

/// Clasifica una EPT violation a partir de la traduccion de su GPA. Es la
/// decision defensiva: distingue el codigo oculto y el parcheo de kernel del
/// ruido.
#[must_use]
pub fn clasificar(
    violacion: ViolacionEpt,
    traduccion: &Result<Traduccion, EptFallo>,
) -> VeredictoEpt {
    let Ok(t) = traduccion else {
        // La GPA no se traduce: solo es una amenaza si se intento EJECUTAR ahi.
        return match violacion.acceso {
            Acceso::Ejecucion => VeredictoEpt::EjecucionNoMapeada,
            _ => VeredictoEpt::Permitido,
        };
    };
    match violacion.acceso {
        Acceso::Ejecucion if !t.ejecucion => VeredictoEpt::EjecucionOculta,
        Acceso::Escritura if !t.escritura => VeredictoEpt::EscrituraDeCodigo,
        Acceso::Lectura if !t.lectura => VeredictoEpt::LecturaProhibida,
        _ => VeredictoEpt::Permitido,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Construye un mapa fisico y un lector para las pruebas.
    fn lector(mapa: HashMap<u64, TablaEpt>) -> impl Fn(u64) -> Option<TablaEpt> {
        move |dir| mapa.get(&dir).copied()
    }

    /// Mapea una GPA a una HPA de 4 KiB con permisos, construyendo las 4 tablas.
    fn mapa_de_una_pagina(
        gpa: u64,
        hpa: u64,
        r: bool,
        w: bool,
        x: bool,
    ) -> (u64, HashMap<u64, TablaEpt>) {
        // Direcciones fisicas arbitrarias pero distintas para cada tabla.
        let (pml4a, pdpta, pda, pta) = (0x1000, 0x2000, 0x3000, 0x4000);
        let mut pml4 = TablaEpt::vacia();
        let mut pdpt = TablaEpt::vacia();
        let mut pd = TablaEpt::vacia();
        let mut pt = TablaEpt::vacia();
        pml4.entradas[indice(gpa, 39)] = EntradaEpt::nueva(pdpta, true, true, true);
        pdpt.entradas[indice(gpa, 30)] = EntradaEpt::nueva(pda, true, true, true);
        pd.entradas[indice(gpa, 21)] = EntradaEpt::nueva(pta, true, true, true);
        pt.entradas[indice(gpa, 12)] = EntradaEpt::nueva(hpa, r, w, x);
        let mut mapa = HashMap::new();
        mapa.insert(pml4a, pml4);
        mapa.insert(pdpta, pdpt);
        mapa.insert(pda, pd);
        mapa.insert(pta, pt);
        (pml4a, mapa)
    }

    #[test]
    fn traduce_una_pagina_de_4k_con_sus_permisos() {
        let gpa = 0x1234_5678;
        let (pml4, mapa) = mapa_de_una_pagina(gpa, 0xAAAA_0000, true, false, true);
        let leer = lector(mapa);
        let t = traducir(pml4, gpa, &leer).expect("mapeada");
        // La HPA es el marco + el offset dentro de la pagina.
        assert_eq!(t.hpa, 0xAAAA_0000 | (gpa & 0xFFF));
        assert!(t.lectura && t.ejecucion && !t.escritura);
    }

    #[test]
    fn una_gpa_no_mapeada_falla() {
        let (pml4, mapa) = mapa_de_una_pagina(0x1000, 0x5000, true, true, true);
        let leer = lector(mapa);
        // Otra GPA muy lejana no tiene entradas.
        assert!(matches!(
            traducir(pml4, 0xDEAD_0000_0000, &leer),
            Err(EptFallo::NoPresente(_))
        ));
    }

    #[test]
    fn ejecutar_una_pagina_no_ejecutable_es_ejecucion_oculta() {
        // Pagina de datos del kernel: R+W, NO ejecutable. Un rootkit ejecuta ahi.
        let gpa = 0x9000;
        let (pml4, mapa) = mapa_de_una_pagina(gpa, 0xB000, true, true, false);
        let leer = lector(mapa);
        let t = traducir(pml4, gpa, &leer);
        let v = ViolacionEpt {
            gpa,
            acceso: Acceso::Ejecucion,
        };
        assert_eq!(clasificar(v, &t), VeredictoEpt::EjecucionOculta);
    }

    #[test]
    fn escribir_codigo_del_kernel_es_parcheo() {
        // Pagina de codigo del kernel: R+X, NO escribible. Alguien la parchea.
        let gpa = 0xC000;
        let (pml4, mapa) = mapa_de_una_pagina(gpa, 0xD000, true, false, true);
        let leer = lector(mapa);
        let t = traducir(pml4, gpa, &leer);
        let v = ViolacionEpt {
            gpa,
            acceso: Acceso::Escritura,
        };
        assert_eq!(clasificar(v, &t), VeredictoEpt::EscrituraDeCodigo);
        // Pero EJECUTAR esa misma pagina de codigo es legitimo.
        let v_exec = ViolacionEpt {
            gpa,
            acceso: Acceso::Ejecucion,
        };
        assert_eq!(clasificar(v_exec, &t), VeredictoEpt::Permitido);
    }

    #[test]
    fn ejecutar_una_gpa_no_mapeada_es_shellcode() {
        let (pml4, mapa) = mapa_de_una_pagina(0x1000, 0x2000, true, true, true);
        let leer = lector(mapa);
        let t = traducir(pml4, 0xFFFF_0000, &leer);
        let v = ViolacionEpt {
            gpa: 0xFFFF_0000,
            acceso: Acceso::Ejecucion,
        };
        assert_eq!(clasificar(v, &t), VeredictoEpt::EjecucionNoMapeada);
    }
}
