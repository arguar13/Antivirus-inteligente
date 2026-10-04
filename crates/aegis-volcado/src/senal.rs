//! El puente al arbitro.
//!
//! # Por que la confianza de esto es distinta a la del desensamblador
//!
//! `aegis-disasm` mira el codigo de un fichero: lo que dice es cierto del
//! fichero, y lo que ese fichero haga al ejecutarse es otra pregunta. Aqui se
//! mira lo que un proceso **tenia en memoria cuando se volco**, que es un hecho
//! sobre lo que de verdad paso en esa maquina.
//!
//! Aun asi el tope sigue siendo el del motor estatico, y por una razon que
//! conviene dejar escrita: una region ejecutable sin respaldo la produce un
//! compilador al vuelo igual que un cargador reflexivo. Lo que sube no es la
//! confianza, es la severidad.

use aegis_entidad::{Confianza, Eid, Juicio, Motor, Senal, Severidad};

use crate::hallazgos::{Clase, Informe};

/// El tope de confianza del motor estatico, repetido aqui para poder probarlo.
pub const TOPE: u8 = 80;

/// Convierte lo encontrado en una senal para el arbitro.
///
/// `cuando_ns` lo pone quien llama: este crate no lee el reloj, para que el
/// mismo volcado analizado dos veces produzca el mismo resultado.
pub fn senal_de(informe: &Informe, entidad: Eid, cuando_ns: u64) -> Senal {
    let (juicio, confianza, severidad) = decidir(informe);
    Senal::nueva(
        Motor::Estatico,
        entidad,
        juicio,
        severidad,
        confianza,
        informe.frase(),
        cuando_ns,
    )
}

/// Que se puede decir de esta memoria.
fn decidir(informe: &Informe) -> (Juicio, Confianza, Severidad) {
    if informe.hallazgos().is_empty() {
        return if informe.la_ausencia_significa_algo() {
            // Se miro el mapa entero y el codigo de todo lo que lo tenia. Es un
            // hecho, y de mas alcance que el equivalente en un fichero: aqui se
            // esta mirando lo que el proceso TENIA, no lo que un fichero podria
            // llegar a hacer.
            (Juicio::Limpio, Confianza::MEDIA, Severidad::Info)
        } else {
            (Juicio::NoConcluyente, Confianza::NULA, Severidad::Info)
        };
    }
    // El codigo con capacidades reconocidas es lo mas fuerte que hay aqui: no es
    // solo que haya codigo donde no deberia, es que ese codigo hace algo
    // concreto y se puede ensenar cual.
    let con_capacidad = informe
        .hallazgos()
        .iter()
        .any(|h| h.clase == Clase::CapacidadEnMemoria);
    let ejecutable_a_mano = informe
        .hallazgos()
        .iter()
        .any(|h| h.clase == Clase::EjecutableSinCargar);
    let severidad = if con_capacidad || ejecutable_a_mano {
        Severidad::Alta
    } else {
        Severidad::Media
    };
    let confianza = if con_capacidad {
        Confianza::nueva(TOPE)
    } else {
        Confianza::MEDIA
    };
    (Juicio::Sospechoso, confianza, severidad)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::adquirir::EnMemoria;
    use crate::hallazgos::analizar_memoria;
    use crate::regiones::{Permisos, Region, Respaldo};
    use aegis_disasm::instruccion::Arquitectura;
    use aegis_disasm::plazo::Plazo;

    fn entidad() -> Eid {
        aegis_entidad::entidad::contenido(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
    }

    fn region(inicio: u64, fin: u64, p: &str, respaldo: Respaldo) -> Region {
        Region {
            inicio,
            fin,
            permisos: Permisos::de_texto(p),
            respaldo,
            desplazamiento_en_volcado: 0,
        }
    }

    fn analizar(bytes: Vec<u8>, r: Region) -> Informe {
        let m = EnMemoria::nueva(bytes, vec![r]);
        analizar_memoria(&m, Arquitectura::X86_64, &mut Plazo::determinista())
    }

    #[test]
    fn el_tope_de_este_modulo_es_el_del_motor_estatico() {
        assert_eq!(TOPE, Motor::Estatico.tope_confianza().centesimas());
    }

    #[test]
    fn una_memoria_limpia_y_mirada_entera_sale_limpia() {
        let i = analizar(
            vec![0x90; 64],
            region(
                0x1000,
                0x1040,
                "r--p",
                Respaldo::Fichero {
                    ruta: "/usr/lib/x".to_owned(),
                },
            ),
        );
        let s = senal_de(&i, entidad(), 0);
        assert_eq!(s.juicio, Juicio::Limpio);
    }

    #[test]
    fn una_memoria_que_no_se_pudo_mirar_entera_no_sale_limpia() {
        // La averia que este producto persigue desde la primera fase, aplicada a
        // forense: «no se comprobo» no es «se comprobo y esta bien».
        let mut bytes = vec![0x90u8; 200_000];
        bytes[0] = 0x90;
        let m = EnMemoria::nueva(
            bytes,
            vec![region(0x1000, 0x1000 + 200_000, "r-xp", Respaldo::Anonima)],
        );
        let mut plazo = Plazo::nuevo(std::time::Duration::from_secs(3600), 50);
        let i = analizar_memoria(&m, Arquitectura::X86_64, &mut plazo);
        let s = senal_de(&i, entidad(), 0);
        assert_ne!(s.juicio, Juicio::Limpio);
    }

    #[test]
    fn la_confianza_nunca_pasa_del_tope() {
        let mut bytes = vec![0x66, 0x0F, 0x38, 0xDC, 0xC1, 0xC3];
        bytes.resize(64, 0x90);
        let i = analizar(bytes, region(0x1000, 0x1040, "rwxp", Respaldo::Anonima));
        let s = senal_de(&i, entidad(), 0);
        assert!(s.confianza.centesimas() <= TOPE);
    }

    #[test]
    fn el_analisis_de_memoria_no_emite_nunca_un_juicio_de_malicioso() {
        // Una region ejecutable sin respaldo la produce un compilador al vuelo
        // igual que un cargador reflexivo. Quien decide es el arbitro.
        let mut bytes = vec![0x66, 0x0F, 0x38, 0xDC, 0xC1, 0xC3];
        bytes.resize(64, 0x90);
        for p in ["rwxp", "r-xp"] {
            let i = analizar(bytes.clone(), region(0x1000, 0x1040, p, Respaldo::Anonima));
            assert_ne!(senal_de(&i, entidad(), 0).juicio, Juicio::Malicioso);
        }
    }

    #[test]
    fn el_codigo_con_capacidades_pesa_mas_que_una_region_rara_a_secas() {
        // Que haya codigo donde no deberia es un hecho; que ese codigo haga algo
        // concreto y se pueda ensenar cual es otro.
        let sola = analizar(
            vec![0x90; 64],
            region(0x1000, 0x1040, "r-xp", Respaldo::Anonima),
        );
        let mut con = vec![0x66, 0x0F, 0x38, 0xDC, 0xC1, 0xC3];
        con.resize(64, 0x90);
        let con = analizar(con, region(0x1000, 0x1040, "r-xp", Respaldo::Anonima));
        assert!(senal_de(&con, entidad(), 0).confianza > senal_de(&sola, entidad(), 0).confianza);
    }

    #[test]
    fn la_frase_de_la_senal_lleva_lo_que_se_miro() {
        let i = analizar(
            vec![0x90; 64],
            region(0x1000, 0x1040, "r-xp", Respaldo::Anonima),
        );
        let s = senal_de(&i, entidad(), 0);
        assert!(s.porque.contains("region"), "{}", s.porque);
    }
}
