//! El decisor: de tablas y ficheros parseados, a anomalías con severidad.
//!
//! # Lo que puede estar mal de forma peligrosa
//!
//! Todo lo anterior es parseo: leer bytes y colocarlos en estructuras. Esto es
//! lo otro — **decidir qué es un implante y qué es un fabricante haciendo su
//! trabajo**—, y es donde un error no se ve hasta que el producto esta desplegado.
//!
//! Los dos errores posibles tienen coste asimetrico y opuesto:
//!
//! - **Marcar de mas**: la mera presencia de WPBT es legitima en una fraccion
//!   enorme de los portatiles corporativos. Marcarla como critica produce una
//!   alerta por maquina el primer dia, y a la semana nadie mira la categoria.
//! - **Marcar de menos**: un checksum roto significa que alguien reescribio una
//!   tabla **despues** de que el firmware la generara. Eso no tiene explicacion
//!   benigna, y dejarlo pasar es no tener deteccion.
//!
//! Por eso la escala tiene tres niveles y el nivel `Informativa` se usa de
//! verdad: hay hechos que hay que **registrar** sin **avisar**.

use crate::acpi::{ConjuntoTablas, TablaAcpi};
use crate::wpbt::Wpbt;

/// Gravedad de una anomalia.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severidad {
    /// Se registra, no se avisa. Un hecho que el analista querra ver en contexto.
    Informativa,
    /// Merece revision: no tiene explicacion benigna obvia, pero tampoco prueba
    /// un compromiso.
    Sospechosa,
    /// No tiene explicacion benigna.
    Critica,
}

/// Una anomalia concreta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomalia {
    /// Codigo estable, para la telemetria y el Control Plane.
    pub codigo: &'static str,
    /// Gravedad.
    pub severidad: Severidad,
    /// Sobre que se detecto (nombre de tabla, GUID de fichero).
    pub sujeto: String,
    /// Evidencia legible.
    pub detalle: String,
}

impl Anomalia {
    /// Construye una anomalia.
    #[must_use]
    pub fn nueva(
        codigo: &'static str,
        severidad: Severidad,
        sujeto: impl Into<String>,
        detalle: impl Into<String>,
    ) -> Anomalia {
        Anomalia {
            codigo,
            severidad,
            sujeto: sujeto.into(),
            detalle: detalle.into(),
        }
    }
}

/// Firmas de tabla ACPI que define el estandar y que aparecen en maquinas
/// normales. Solo se usa para NO marcar lo conocido; una firma ausente de esta
/// lista se anota como informativa, nunca como compromiso: el estandar crece y
/// los fabricantes anaden tablas propias legitimamente.
const FIRMAS_HABITUALES: &[&[u8; 4]] = &[
    b"APIC", b"BERT", b"BGRT", b"BOOT", b"CPEP", b"DBG2", b"DBGP", b"DMAR", b"DSDT", b"ECDT",
    b"EINJ", b"ERST", b"ETDT", b"FACP", b"FACS", b"FPDT", b"GTDT", b"HEST", b"HPET", b"IORT",
    b"IVRS", b"LPIT", b"MCFG", b"MCHI", b"MPST", b"MSCT", b"MSDM", b"NFIT", b"OEM0", b"PCCT",
    b"PMTT", b"PPTT", b"RSDT", b"SBST", b"SDEI", b"SLIC", b"SLIT", b"SPCR", b"SPMI", b"SRAT",
    b"SSDT", b"STAO", b"TCPA", b"TPM2", b"UEFI", b"VFCT", b"WAET", b"WDAT", b"WDDT", b"WDRT",
    b"WPBT", b"WSMT", b"XENV", b"XSDT",
];

/// Audita una sola tabla ACPI.
#[must_use]
pub fn auditar_tabla(t: &TablaAcpi) -> Vec<Anomalia> {
    let mut salida = Vec::new();
    let nombre = t.nombre();

    // 1. CHECKSUM ROTO. No tiene explicacion benigna: el firmware calcula el
    //    checksum al generar la tabla, asi que uno roto significa que alguien la
    //    reescribio DESPUES. Es la senal mas fuerte de todo el modulo.
    //
    //    Solo cuenta `Invalido`. Una tabla que NO lleva checksum —la FACS— no es
    //    un hallazgo: antes se la acusaba de reescrita en cualquier maquina que la
    //    expusiera, que es la peor clase de falso positivo porque es Critico y
    //    habla del firmware.
    if t.checksum.es_sospechoso() {
        salida.push(Anomalia::nueva(
            "acpi-checksum-invalido",
            Severidad::Critica,
            &nombre,
            format!(
                "la suma de los {} bytes de la tabla no da cero: fue reescrita despues \
                 de que el firmware la generara",
                t.bytes.len()
            ),
        ));
    }

    // 2. UN EJECUTABLE DENTRO DE UNA TABLA DE DESCRIPCION DE HARDWARE.
    if let Some(off) = buscar_pe_embebido(&t.bytes) {
        salida.push(Anomalia::nueva(
            "acpi-pe-embebido",
            Severidad::Critica,
            &nombre,
            format!(
                "hay una imagen PE/COFF en el desplazamiento {off}: una tabla ACPI \
                 describe hardware, no transporta ejecutables"
            ),
        ));
    }

    // 3. Una firma que no esta en el estandar ni entre las de fabricante
    //    conocidas. INFORMATIVA a proposito: el estandar crece y los fabricantes
    //    anaden tablas propias legitimamente. Marcarlo como sospechoso produciria
    //    ruido en maquinas perfectamente sanas.
    if !FIRMAS_HABITUALES.contains(&&t.cabecera.firma) {
        salida.push(Anomalia::nueva(
            "acpi-firma-desconocida",
            Severidad::Informativa,
            &nombre,
            format!(
                "firma '{}' no reconocida (OEM '{}'): puede ser una tabla propia del \
                 fabricante",
                t.cabecera.firma_texto(),
                t.cabecera.oem_texto()
            ),
        ));
    }

    // 4. Una tabla cargada DINAMICAMENTE, despues del arranque. Es un vector de
    //    inyeccion real, y por eso se mira el directorio `dynamic`; pero tambien
    //    lo usan controladores legitimos, asi que es sospechosa, no critica.
    if t.dinamica {
        salida.push(Anomalia::nueva(
            "acpi-tabla-dinamica",
            Severidad::Sospechosa,
            &nombre,
            "tabla cargada despues del arranque: puede ser un controlador legitimo \
             o una inyeccion"
                .to_string(),
        ));
    }

    salida
}

/// Audita el conjunto completo, incluida la WPBT.
#[must_use]
pub fn auditar_conjunto(c: &ConjuntoTablas) -> Vec<Anomalia> {
    let mut salida = Vec::new();
    for t in &c.tablas {
        salida.extend(auditar_tabla(t));
    }
    for (ruta, motivo) in &c.ilegibles {
        // Que una tabla no se pueda leer NO es un compromiso, pero tampoco puede
        // callarse: la diferencia entre «no hay WPBT» y «habia una tabla que no
        // se pudo leer» es exactamente lo que el analista necesita.
        salida.push(Anomalia::nueva(
            "acpi-tabla-ilegible",
            Severidad::Informativa,
            ruta.display().to_string(),
            motivo.clone(),
        ));
    }
    if let Some(t) = c.por_firma(b"WPBT") {
        salida.extend(auditar_wpbt_bytes(&t.bytes));
    }
    // Orden estable: dos auditorias de la misma maquina tienen que producir el
    // mismo informe, o compararlas deja de ser trivial.
    salida.sort_by(|a, b| {
        b.severidad
            .cmp(&a.severidad)
            .then(a.codigo.cmp(b.codigo))
            .then(a.sujeto.cmp(&b.sujeto))
    });
    salida
}

/// Audita una tabla WPBT a partir de sus bytes.
#[must_use]
pub fn auditar_wpbt_bytes(bytes: &[u8]) -> Vec<Anomalia> {
    match Wpbt::analizar(bytes) {
        Ok(w) => auditar_wpbt(&w),
        Err(e) => vec![Anomalia::nueva(
            "wpbt-malformada",
            Severidad::Sospechosa,
            "WPBT",
            format!("la tabla no se puede analizar: {e}"),
        )],
    }
}

/// Audita una WPBT ya analizada.
///
/// # La decision central de la fase
///
/// La presencia de WPBT se reporta como **hecho informativo**, no como
/// compromiso. Es deliberado y es lo que hace utilizable la deteccion: muchos
/// fabricantes envian WPBT legitimamente (es el mecanismo del software antirrobo
/// preinstalado), y marcarla como critica produciria una alerta critica en una
/// fraccion enorme de los portatiles corporativos del mundo.
///
/// Lo que SI eleva son los indicios concretos.
#[must_use]
pub fn auditar_wpbt(w: &Wpbt) -> Vec<Anomalia> {
    let mut salida = vec![Anomalia::nueva(
        "wpbt-presente",
        Severidad::Informativa,
        "WPBT",
        format!(
            "el firmware entrega un binario de {} B para ejecutar en cada arranque \
             (OEM '{}'). Es un mecanismo legitimo de fabricante, y tambien la via \
             de persistencia mas limpia que existe: formatear no lo quita",
            w.handoff_size,
            w.cabecera.oem_texto()
        ),
    )];

    let indicios = w.indicios_en_argumentos();
    if !indicios.is_empty() {
        salida.push(Anomalia::nueva(
            "wpbt-argumentos-de-ataque",
            Severidad::Critica,
            "WPBT",
            format!(
                "los argumentos que el firmware le pasa al binario contienen {}: \
                 un lanzador de fabricante pasa rutas y modificadores propios, no \
                 una linea de descarga y ejecucion. Argumentos: '{}'",
                indicios.join(", "),
                w.argumentos.chars().take(200).collect::<String>()
            ),
        ));
    }

    if !w.campos_conocidos() {
        salida.push(Anomalia::nueva(
            "wpbt-campos-desconocidos",
            Severidad::Sospechosa,
            "WPBT",
            format!(
                "layout={} y content_type={} no son los valores definidos (1 y 1)",
                w.layout, w.content_type
            ),
        ));
    }

    if !w.handoff_plausible() {
        salida.push(Anomalia::nueva(
            "wpbt-handoff-implausible",
            Severidad::Sospechosa,
            "WPBT",
            format!(
                "el binario entregado declara {} B, fuera de lo razonable para un \
                 lanzador de fabricante",
                w.handoff_size
            ),
        ));
    }

    if w.argumentos_recortados {
        salida.push(Anomalia::nueva(
            "wpbt-argumentos-mentirosos",
            Severidad::Sospechosa,
            "WPBT",
            format!(
                "arguments_length declara {} B pero la tabla no los tiene: la \
                 cabecera miente sobre su propio contenido",
                w.arguments_length
            ),
        ));
    }

    salida
}

/// Busca una imagen PE/COFF embebida.
///
/// No basta con encontrar `MZ`: esos dos bytes aparecen por azar en cualquier
/// volcado de tamano decente. Se exige la estructura completa — el `e_lfanew` del
/// desplazamiento `0x3C` tiene que apuntar, **dentro** del mismo buffer, a la
/// firma `PE\0\0`—, que es lo que distingue un ejecutable real de una coincidencia.
#[must_use]
pub fn buscar_pe_embebido(bytes: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i + 0x40 <= bytes.len() {
        if bytes[i] == b'M' && bytes[i + 1] == b'Z' {
            let e_lfanew = u32::from_le_bytes(
                bytes[i + 0x3C..i + 0x40]
                    .try_into()
                    .expect("acotado por el bucle"),
            ) as usize;
            if let Some(pe) = i.checked_add(e_lfanew) {
                if pe + 4 <= bytes.len() && &bytes[pe..pe + 4] == b"PE\0\0" {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::acpi::analizar_tabla;
    use std::path::Path;

    fn tabla_de(bytes: Vec<u8>, dinamica: bool) -> TablaAcpi {
        analizar_tabla(Path::new("/tmp/t"), bytes, dinamica).expect("tabla valida")
    }

    fn tabla_valida(firma: &[u8; 4], cuerpo: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; crate::acpi::TAM_CABECERA];
        t[0..4].copy_from_slice(firma);
        t[10..16].copy_from_slice(b"OEMCO ");
        t.extend_from_slice(cuerpo);
        let largo = t.len() as u32;
        t[4..8].copy_from_slice(&largo.to_le_bytes());
        let suma = t.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        t[9] = suma.wrapping_neg();
        t
    }

    #[test]
    fn un_checksum_roto_es_critico_sin_matices() {
        let mut bytes = tabla_valida(b"FACP", b"cuerpo normal");
        let ultimo = bytes.len() - 1;
        bytes[ultimo] ^= 0xFF;
        // `analizar_tabla` acepta la tabla (la longitud cuadra) y marca el
        // checksum; es el decisor el que decide la gravedad.
        let t = tabla_de(bytes, false);
        assert_eq!(t.checksum, crate::acpi::Checksum::Invalido);
        let a = auditar_tabla(&t);
        let c = a
            .iter()
            .find(|x| x.codigo == "acpi-checksum-invalido")
            .expect("tiene que detectarse");
        assert_eq!(c.severidad, Severidad::Critica);
    }

    #[test]
    fn una_tabla_normal_no_produce_nada_grave() {
        let t = tabla_de(tabla_valida(b"APIC", &[0u8; 40]), false);
        let a = auditar_tabla(&t);
        assert!(
            a.iter().all(|x| x.severidad == Severidad::Informativa),
            "una tabla sana no puede producir avisos: {a:#?}"
        );
    }

    /// EL EQUILIBRIO QUE DEFINE LA FASE. La presencia de WPBT es legitima en una
    /// fraccion enorme de los portatiles corporativos. Marcarla como critica
    /// produciria una alerta por maquina el primer dia.
    #[test]
    fn una_wpbt_de_fabricante_se_registra_pero_no_avisa() {
        let w = Wpbt::analizar(&crate::wpbt::pruebas::wpbt(
            102_400,
            0x7FF0_0000,
            1,
            1,
            "/silent /oem",
        ))
        .expect("valida");
        let a = auditar_wpbt(&w);
        assert_eq!(a.len(), 1, "{a:#?}");
        assert_eq!(a[0].codigo, "wpbt-presente");
        assert_eq!(
            a[0].severidad,
            Severidad::Informativa,
            "la mera presencia de WPBT NO puede ser critica"
        );
    }

    /// Y el otro lado: una WPBT que le dice al SO que ejecute PowerShell con un
    /// comando codificado, desde la placa base, en cada arranque.
    #[test]
    fn una_wpbt_con_linea_de_ataque_si_es_critica() {
        let w = Wpbt::analizar(&crate::wpbt::pruebas::wpbt(
            4096,
            0,
            1,
            1,
            "powershell -nop -w hidden -enc SQBFAFgA",
        ))
        .expect("valida");
        let a = auditar_wpbt(&w);
        let c = a
            .iter()
            .find(|x| x.codigo == "wpbt-argumentos-de-ataque")
            .expect("tiene que detectarse");
        assert_eq!(c.severidad, Severidad::Critica);
        assert!(c.detalle.contains("powershell"), "{}", c.detalle);
    }

    #[test]
    fn un_pe_embebido_en_una_tabla_es_critico() {
        // Un PE minimo pero ESTRUCTURALMENTE valido: MZ, e_lfanew y PE\0\0.
        let mut pe = vec![0u8; 0x80];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(buscar_pe_embebido(&pe), Some(0));

        let t = tabla_de(tabla_valida(b"SSDT", &pe), false);
        let a = auditar_tabla(&t);
        assert!(a.iter().any(|x| x.codigo == "acpi-pe-embebido"));
    }

    /// `MZ` suelto aparece por azar en cualquier volcado. Exigir la estructura
    /// completa es lo que separa una deteccion de un generador de ruido.
    #[test]
    fn dos_bytes_mz_sueltos_no_son_un_ejecutable() {
        let mut datos = vec![0u8; 4096];
        datos[100] = b'M';
        datos[101] = b'Z';
        assert_eq!(buscar_pe_embebido(&datos), None);

        // Y un e_lfanew que apunta fuera del buffer tampoco cuenta.
        let mut casi = vec![0u8; 0x80];
        casi[0] = b'M';
        casi[1] = b'Z';
        casi[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert_eq!(buscar_pe_embebido(&casi), None);
        assert_eq!(buscar_pe_embebido(&[]), None);
    }

    #[test]
    fn una_tabla_dinamica_es_sospechosa_pero_no_critica() {
        let t = tabla_de(tabla_valida(b"SSDT", &[0u8; 16]), true);
        let a = auditar_tabla(&t);
        let d = a
            .iter()
            .find(|x| x.codigo == "acpi-tabla-dinamica")
            .expect("tiene que detectarse");
        assert_eq!(d.severidad, Severidad::Sospechosa);
    }

    /// Una firma que no esta en el estandar es INFORMATIVA. El estandar crece y
    /// los fabricantes anaden tablas propias; marcarlo como sospechoso produciria
    /// ruido en maquinas perfectamente sanas.
    #[test]
    fn una_firma_desconocida_solo_se_anota() {
        let t = tabla_de(tabla_valida(b"ZZZZ", &[0u8; 8]), false);
        let a = auditar_tabla(&t);
        let f = a
            .iter()
            .find(|x| x.codigo == "acpi-firma-desconocida")
            .expect("tiene que anotarse");
        assert_eq!(f.severidad, Severidad::Informativa);
    }

    /// LAS TABLAS REALES DE ESTA MAQUINA no pueden producir ni una anomalia
    /// grave. Si lo hicieran, o esta maquina esta comprometida o el decisor esta
    /// mal calibrado — y lo segundo significa una alerta critica en cada endpoint
    /// del cliente el primer dia.
    #[test]
    fn el_firmware_real_de_esta_maquina_no_produce_alertas_graves() {
        let c = crate::acpi::leer_tablas_del_sistema();
        if c.is_empty() {
            eprintln!("OMITIDA: esta maquina no expone tablas ACPI");
            return;
        }
        let a = auditar_conjunto(&c);
        for x in &a {
            eprintln!("  [{:?}] {} — {}", x.severidad, x.codigo, x.sujeto);
        }
        let graves: Vec<_> = a
            .iter()
            .filter(|x| x.severidad >= Severidad::Sospechosa)
            .collect();
        assert!(
            graves.is_empty(),
            "el firmware real de esta maquina no deberia producir avisos: {graves:#?}"
        );
    }

    #[test]
    fn el_informe_es_estable_entre_ejecuciones() {
        let c = crate::acpi::leer_tablas_del_sistema();
        if c.is_empty() {
            return;
        }
        assert_eq!(auditar_conjunto(&c), auditar_conjunto(&c));
    }
}
