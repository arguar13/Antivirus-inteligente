//! IPv6 y su cadena de cabeceras de extension.
//!
//! # El ataque: la cadena de cabeceras que no termina
//!
//! IPv6 sustituyo las opciones de IPv4 por una **cadena enlazada** de cabeceras
//! de extension: cada una dice cual es la siguiente. Nada en el formato limita su
//! numero, y nada impide que una cabecera declare longitud cero.
//!
//! Eso da dos ataques clasicos, los dos usados para evadir cortafuegos e IDS:
//!
//! 1. **Cadena interminable.** Cientos de cabeceras de relleno antes de la de
//!    transporte. Un analizador que las recorra sin tope se queda ahi; uno que se
//!    rinda en silencio deja pasar el paquete **sin analizar su contenido**, que
//!    es lo que busca el atacante.
//! 2. **Longitud cero.** Una cabecera cuya longitud declarada hace que el
//!    recorrido no avance: bucle infinito.
//!
//! Aqui se cierran los dos con tope de cabeceras y progreso estricto. Y lo
//! importante: cuando se llega al tope, el paquete se marca como **no
//! analizable con su motivo**, no se da por limpio. Rendirse en silencio es la
//! evasion.
//!
//! # Los fragmentos
//!
//! La cabecera de fragmento se reconoce y se DECLARA, pero el reensamblado de
//! fragmentos IP no se hace aqui: es otra superficie de ataque entera —la de los
//! solapes de fragmentos, con dos decadas de CVE— y mezclarla con el resto haria
//! imposible razonar sobre ninguna de las dos. Un paquete fragmentado se marca
//! como tal para que el motor sepa que su contenido esta incompleto.

use crate::error::{ErrorDiseccion, Resultado};
use crate::lector::Lector;

/// Longitud de la cabecera fija de IPv6.
pub const CABECERA_FIJA: usize = 40;

/// Tope de cabeceras de extension que se recorren.
///
/// Ocho es mas de lo que usa cualquier trafico legitimo. Pasado el tope, el
/// paquete se marca no analizable en vez de darse por limpio.
pub const MAX_EXTENSIONES: usize = 8;

/// Siguiente cabecera: salto a salto.
pub const NH_SALTO_A_SALTO: u8 = 0;
/// Siguiente cabecera: enrutado.
pub const NH_ENRUTADO: u8 = 43;
/// Siguiente cabecera: fragmento.
pub const NH_FRAGMENTO: u8 = 44;
/// Siguiente cabecera: destino.
pub const NH_DESTINO: u8 = 60;
/// Siguiente cabecera: sin carga util.
pub const NH_NINGUNA: u8 = 59;
/// Siguiente cabecera: autenticacion.
pub const NH_AUTENTICACION: u8 = 51;

/// TCP.
pub const NH_TCP: u8 = 6;
/// UDP.
pub const NH_UDP: u8 = 17;
/// ICMPv6.
pub const NH_ICMPV6: u8 = 58;

/// Una cabecera IPv6 ya recorrida hasta el transporte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CabeceraIpv6 {
    /// Direccion de origen.
    pub origen: [u8; 16],
    /// Direccion de destino.
    pub destino: [u8; 16],
    /// Limite de saltos.
    pub limite_saltos: u8,
    /// Protocolo de transporte al final de la cadena.
    pub transporte: u8,
    /// Desplazamiento donde empieza la carga de transporte.
    pub inicio_carga: usize,
    /// Cuantas cabeceras de extension se recorrieron.
    pub extensiones: usize,
    /// Si el paquete venia fragmentado.
    ///
    /// Se declara en vez de reensamblar: el reensamblado de fragmentos IP es otra
    /// superficie de ataque entera y mezclarla aqui haria imposible razonar
    /// sobre ninguna de las dos.
    pub fragmentado: bool,
    /// Desplazamiento del fragmento EN BYTES, cero si es el primero.
    ///
    /// Se expone en bytes y no en unidades de ocho como viene en el cable
    /// porque olvidar el factor ocho es un fallo clasico, y un desplazamiento
    /// mal leido convierte un fragmento posterior en "primer fragmento".
    ///
    /// Importa porque solo el PRIMER fragmento lleva cabecera de transporte.
    /// Leer un fragmento posterior como TCP interpreta carga util como puertos
    /// y numero de secuencia: es una via directa para inyectar bytes en el
    /// reensamblador en el offset que el atacante elija.
    ///
    /// Si el paquete encadena varias cabeceras de fragmento —cosa que ya es
    /// anomala— se queda el desplazamiento mayor, que es el lado seguro: ante
    /// la duda, no se analiza transporte.
    pub desplazamiento_fragmento: usize,
}

/// Si una cabecera es de extension.
#[must_use]
pub fn es_extension(nh: u8) -> bool {
    matches!(
        nh,
        NH_SALTO_A_SALTO | NH_ENRUTADO | NH_FRAGMENTO | NH_DESTINO | NH_AUTENTICACION
    )
}

/// Analiza una cabecera IPv6 y recorre su cadena de extensiones.
///
/// # Errores
/// [`ErrorDiseccion::NoEsEsteProtocolo`] si la version no es 6,
/// [`ErrorDiseccion::AnidamientoExcesivo`] si la cadena pasa del tope —y ahi el
/// paquete queda marcado como NO analizable, que es lo correcto—, o
/// truncamiento.
pub fn analizar(datos: &[u8]) -> Resultado<CabeceraIpv6> {
    let mut l = Lector::nuevo(datos);
    let primero = l.u8("ipv6.version")?;
    if primero >> 4 != 6 {
        return Err(ErrorDiseccion::NoEsEsteProtocolo("ipv6"));
    }
    l.saltar(3, "ipv6.flujo")?;
    let _longitud_carga = l.u16("ipv6.longitud")?;
    let mut siguiente = l.u8("ipv6.siguiente")?;
    let limite_saltos = l.u8("ipv6.limite")?;

    let mut origen = [0u8; 16];
    origen.copy_from_slice(l.tomar(16, "ipv6.origen")?);
    let mut destino = [0u8; 16];
    destino.copy_from_slice(l.tomar(16, "ipv6.destino")?);

    let mut extensiones = 0usize;
    let mut fragmentado = false;
    let mut desplazamiento_fragmento = 0usize;

    while es_extension(siguiente) {
        extensiones += 1;
        if extensiones > MAX_EXTENSIONES {
            // NO se da por limpio: se dice que no se pudo llegar al transporte.
            // Rendirse en silencio ES la evasion.
            return Err(ErrorDiseccion::AnidamientoExcesivo {
                campo: "ipv6.extensiones",
                niveles: extensiones,
            });
        }

        let antes = l.posicion();
        let nh = l.u8("ipv6.ext.siguiente")?;
        let longitud_declarada = l.u8("ipv6.ext.longitud")?;

        let largo = if siguiente == NH_FRAGMENTO {
            fragmentado = true;
            // El lector viene de consumir los dos primeros bytes de la cabecera
            // de fragmento (siguiente y reservado), asi que aqui estan los bits
            // de desplazamiento: 13 arriba, 2 reservados y la bandera M abajo.
            let campo = l.u16("ipv6.fragmento.desplazamiento")?;
            let bytes = usize::from(campo >> 3) * 8;
            desplazamiento_fragmento = desplazamiento_fragmento.max(bytes);
            // La cabecera de fragmento mide SIEMPRE 8 bytes; su segundo byte es
            // reservado, no una longitud. Interpretarlo como longitud es un
            // fallo clasico que descoloca todo el resto del recorrido.
            8
        } else if siguiente == NH_AUTENTICACION {
            // La de autenticacion se mide en palabras de 4 bytes, +2. Las demas
            // en palabras de 8, +1. Confundirlas descoloca el recorrido.
            (usize::from(longitud_declarada) + 2) * 4
        } else {
            (usize::from(longitud_declarada) + 1) * 8
        };

        // PROGRESO ESTRICTO: si el salto no avanza, se para. Sin esto, una
        // cabecera de longitud cero es un bucle infinito.
        if largo < 2 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "ipv6.ext.sin-progreso",
                valor: u64::from(longitud_declarada),
            });
        }
        l.ir_a(antes, "ipv6.ext")?;
        l.saltar(largo, "ipv6.ext.cuerpo")?;
        siguiente = nh;

        if siguiente == NH_NINGUNA {
            break;
        }
    }

    Ok(CabeceraIpv6 {
        origen,
        destino,
        limite_saltos,
        transporte: siguiente,
        inicio_carga: l.posicion(),
        extensiones,
        fragmentado,
        desplazamiento_fragmento,
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Construye una cabecera IPv6 de verdad.
    fn cabecera(siguiente: u8, extensiones: &[u8]) -> Vec<u8> {
        let mut v = vec![0x60, 0, 0, 0];
        v.extend_from_slice(&(extensiones.len() as u16).to_be_bytes());
        v.push(siguiente);
        v.push(64); // limite de saltos
        v.extend_from_slice(&[0x20; 16]); // origen
        v.extend_from_slice(&[0x30; 16]); // destino
        v.extend_from_slice(extensiones);
        v
    }

    /// Una cabecera de extension bien formada: siguiente, longitud en palabras
    /// de 8 menos 1, y relleno.
    fn ext(siguiente: u8, palabras_extra: u8) -> Vec<u8> {
        let largo = (usize::from(palabras_extra) + 1) * 8;
        let mut v = vec![siguiente, palabras_extra];
        v.resize(largo, 0);
        v
    }

    #[test]
    fn una_cabecera_sin_extensiones_llega_directa_al_transporte() {
        let p = cabecera(NH_TCP, &[]);
        let c = analizar(&p).expect("valida");
        assert_eq!(c.transporte, NH_TCP);
        assert_eq!(c.inicio_carga, CABECERA_FIJA);
        assert_eq!(c.extensiones, 0);
        assert_eq!(c.limite_saltos, 64);
        assert!(!c.fragmentado);
    }

    #[test]
    fn una_cadena_razonable_de_extensiones_se_recorre_hasta_el_transporte() {
        let mut e = ext(NH_DESTINO, 0);
        e.extend_from_slice(&ext(NH_UDP, 1));
        let p = cabecera(NH_SALTO_A_SALTO, &e);

        let c = analizar(&p).expect("valida");
        assert_eq!(c.transporte, NH_UDP);
        assert_eq!(c.extensiones, 2);
        assert_eq!(c.inicio_carga, CABECERA_FIJA + 8 + 16);
    }

    /// EL ATAQUE 1: cientos de cabeceras antes del transporte. Lo importante NO
    /// es solo no colgarse: es que el paquete quede marcado como NO ANALIZABLE
    /// en vez de darse por limpio. Rendirse en silencio ES la evasion.
    #[test]
    fn una_cadena_interminable_se_rechaza_diciendo_que_no_se_pudo_llegar() {
        let mut e = Vec::new();
        for _ in 0..200 {
            e.extend_from_slice(&ext(NH_DESTINO, 0));
        }
        e.extend_from_slice(&ext(NH_TCP, 0));
        let p = cabecera(NH_DESTINO, &e);

        match analizar(&p) {
            Err(ErrorDiseccion::AnidamientoExcesivo { campo, .. }) => {
                assert_eq!(campo, "ipv6.extensiones");
            }
            otro => panic!("una cadena interminable NO puede darse por buena: {otro:?}"),
        }
    }

    /// EL ATAQUE 2: una cabecera cuya longitud hace que el recorrido no avance.
    /// Sin progreso estricto, esto es un bucle infinito.
    #[test]
    fn una_cabecera_que_no_hace_avanzar_no_produce_un_bucle() {
        // Se fabrica a mano una cabecera de autenticacion con longitud tal que
        // el calculo daria menos de dos bytes si estuviera mal hecho.
        let p = cabecera(NH_ENRUTADO, &[NH_TCP, 0, 0, 0, 0, 0, 0, 0]);
        // Con longitud 0 el largo es (0+1)*8 = 8, que si avanza: valido.
        let c = analizar(&p).expect("ocho bytes si avanzan");
        assert_eq!(c.transporte, NH_TCP);
        assert_eq!(c.extensiones, 1);
    }

    /// La cabecera de fragmento mide SIEMPRE 8 bytes; su segundo byte es
    /// reservado, no una longitud. Interpretarlo como longitud descoloca todo el
    /// recorrido posterior.
    #[test]
    fn la_cabecera_de_fragmento_mide_ocho_bytes_y_se_declara() {
        // Segundo byte a 0xFF: si se interpretara como longitud, el recorrido
        // saltaria 2048 bytes y se perderia.
        let mut e = vec![NH_TCP, 0xFF, 0x00, 0x01, 0, 0, 0, 0];
        e.extend_from_slice(&[0u8; 20]);
        let p = cabecera(NH_FRAGMENTO, &e);

        let c = analizar(&p).expect("valida");
        assert_eq!(c.transporte, NH_TCP);
        assert!(c.fragmentado, "el fragmento tiene que DECLARARSE");
        assert_eq!(
            c.inicio_carga,
            CABECERA_FIJA + 8,
            "la de fragmento mide ocho, no lo que diga su segundo byte"
        );
    }

    #[test]
    fn lo_que_no_es_ipv6_se_rechaza_como_tal() {
        let mut p = cabecera(NH_TCP, &[]);
        p[0] = 0x45; // IPv4
        assert!(matches!(
            analizar(&p),
            Err(ErrorDiseccion::NoEsEsteProtocolo("ipv6"))
        ));
    }

    #[test]
    fn una_cabecera_truncada_se_rechaza_sin_leer_basura() {
        for corte in 0..CABECERA_FIJA {
            let p = cabecera(NH_TCP, &[]);
            assert!(analizar(&p[..corte]).is_err(), "corte {corte}");
        }
    }

    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico_ni_bucle() {
        let mut semilla = 0x6C62_7275_6E6E_6572u64;
        for _ in 0..10_000 {
            semilla = semilla
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let largo = (semilla >> 32) as usize % 300;
            let mut datos: Vec<u8> = (0..largo).map(|i| (semilla >> (i % 8)) as u8).collect();
            // La mitad con version 6, para llegar al recorrido de extensiones.
            if !datos.is_empty() && largo % 2 == 0 {
                datos[0] = 0x60;
            }
            let _ = analizar(&datos);
        }
    }
}
