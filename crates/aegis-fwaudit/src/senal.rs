//! El veredicto de plataforma, al arbitro.
//!
//! # Que llega y que no
//!
//! Al arbitro llega una sola [`Senal`] del motor `fwaudit` sobre la entidad
//! **maquina**, y la deciden solo las comprobaciones de **compromiso**. Las
//! exposiciones —un BLE a cero, un microcodigo atrasado, un SMRR sin activar— no
//! mueven el juicio, ni un poco: una flota con la mitad de las placas mal
//! configuradas de fabrica no tiene la mitad de las maquinas comprometidas, y un
//! arbitro que lo creyera aprenderia al analista a ignorar la plataforma entera.
//! Las exposiciones viajan en el informe, que es lo que consume la postura.
//!
//! # Tres juicios, y el cuarto
//!
//! - **Malicioso**: un fallo sin explicacion benigna (un FFS o un AML reescrito
//!   frente a su linea base, un checksum ACPI roto, un evento del registro cuyo
//!   texto no es lo que se midio, Secure Boot medido distinto del actual).
//! - **Sospechoso**: un fallo de compromiso que admite explicacion (un arranque de
//!   una sola vez preparado, una primera entrada de arranque rara).
//! - **Limpio**: se miro lo bastante y no hay nada; la confianza depende de
//!   cuanto se miro.
//! - **NoConcluyente**: no se pudo mirar ninguna comprobacion de compromiso.
//!   Nunca «limpio por defecto».

use aegis_entidad::{Confianza, Eid, Juicio, Motor, Senal, Severidad};

use crate::comprobacion::Naturaleza;
use crate::plataforma::InformePlataforma;

/// Las comprobaciones de compromiso cuyo fallo no tiene explicacion benigna.
pub const SIN_EXPLICACION_BENIGNA: &[&str] = &[
    "acpi-tablas",
    "acpi-wpbt",
    "spi-ficheros",
    "aml-metodos-automaticos",
    "option-rom-integridad",
    "cadena-pcr-reproducidos",
    "cadena-resumenes",
    "cadena-secure-boot-coherente",
    "cadena-controladores-pci",
];

/// El tope de confianza del motor, repetido para poder probarlo.
pub const TOPE: u8 = 85;

/// Convierte el informe en la senal del motor de plataforma.
///
/// `cuando_ns` lo pone quien llama: el mismo informe tiene que dar la misma
/// senal.
#[must_use]
pub fn senal_de(inf: &InformePlataforma, maquina: Eid, cuando_ns: u64) -> Senal {
    let compromisos = inf.compromisos();
    let (miradas, total) = inf.cobertura(Naturaleza::Compromiso);
    let (juicio, severidad, confianza, porque) = if compromisos.is_empty() {
        if miradas == 0 {
            (
                Juicio::NoConcluyente,
                Severidad::Info,
                Confianza::NULA,
                format!(
                    "no se pudo mirar ninguna de las {total} comprobaciones de compromiso de la \
                     plataforma: no hay veredicto, que no es lo mismo que limpio"
                ),
            )
        } else {
            // La confianza crece con la fraccion de lo mirado: haber mirado 3 de
            // 20 superficies no permite la misma seguridad que 18 de 20.
            let confianza = if miradas * 2 >= total {
                Confianza::MEDIA
            } else {
                Confianza::BAJA
            };
            (
                Juicio::Limpio,
                Severidad::Info,
                confianza,
                format!(
                    "plataforma sin indicios de compromiso en {miradas} de {total} comprobaciones \
                     que se pudieron mirar; {} exposicion(es) van al informe de postura",
                    inf.exposiciones().len()
                ),
            )
        }
    } else {
        let graves: Vec<_> = compromisos
            .iter()
            .filter(|c| SIN_EXPLICACION_BENIGNA.contains(&c.id))
            .collect();
        let lista = compromisos
            .iter()
            .map(|c| c.id)
            .collect::<Vec<_>>()
            .join(", ");
        if graves.is_empty() {
            (
                Juicio::Sospechoso,
                Severidad::Alta,
                Confianza::MEDIA,
                format!(
                    "indicios de manipulacion de la plataforma que admiten explicacion: {lista}"
                ),
            )
        } else {
            (
                Juicio::Malicioso,
                Severidad::Critica,
                Confianza::nueva(TOPE),
                format!("la plataforma esta manipulada por debajo del sistema operativo: {lista}"),
            )
        }
    };
    Senal::nueva(
        Motor::FirmwareAudit,
        maquina,
        juicio,
        severidad,
        confianza,
        porque,
        cuando_ns,
    )
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::comprobacion::{Comprobacion, Superficie};
    use aegis_firmware::report::CheckState;

    fn maquina() -> Eid {
        aegis_entidad::entidad::maquina("matricula-de-prueba")
    }

    fn inf(c: Vec<Comprobacion>) -> InformePlataforma {
        InformePlataforma {
            comprobaciones: c,
            ..Default::default()
        }
    }

    fn comp(id: &'static str, n: Naturaleza, e: CheckState) -> Comprobacion {
        Comprobacion::nueva(id, Superficie::Acpi, n, e)
    }

    #[test]
    fn el_tope_de_este_modulo_es_el_del_motor() {
        assert_eq!(TOPE, Motor::FirmwareAudit.tope_confianza().centesimas());
    }

    /// LA REGLA QUE HACE UTIL AL MOTOR: una placa llena de exposiciones y sin un
    /// solo compromiso sale LIMPIA, no sospechosa.
    #[test]
    fn las_exposiciones_no_mueven_el_juicio_ni_un_poco() {
        let mut v: Vec<Comprobacion> = (0..20)
            .map(|_| {
                comp(
                    "spi-proteccion-escritura",
                    Naturaleza::Exposicion,
                    CheckState::Fallo("BLE=0".into()),
                )
            })
            .collect();
        v.push(comp("acpi-tablas", Naturaleza::Compromiso, CheckState::Ok));
        let s = senal_de(&inf(v), maquina(), 0);
        assert_eq!(s.juicio, Juicio::Limpio);
        assert_eq!(s.severidad, Severidad::Info);
        assert!(s.porque.contains("20 exposicion"), "{}", s.porque);
    }

    #[test]
    fn sin_nada_mirado_no_hay_veredicto() {
        let v = vec![comp(
            "acpi-tablas",
            Naturaleza::Compromiso,
            CheckState::NoAplicable("x".into()),
        )];
        let s = senal_de(&inf(v), maquina(), 0);
        assert_eq!(s.juicio, Juicio::NoConcluyente);
        assert!(!s.aporta());
    }

    #[test]
    fn un_compromiso_sin_explicacion_benigna_es_malicioso_y_uno_con_ella_sospechoso() {
        let s = senal_de(
            &inf(vec![comp(
                "cadena-resumenes",
                Naturaleza::Compromiso,
                CheckState::Fallo("x".into()),
            )]),
            maquina(),
            0,
        );
        assert_eq!(s.juicio, Juicio::Malicioso);
        assert!(s.confianza.centesimas() <= TOPE);
        let s = senal_de(
            &inf(vec![comp(
                "uefi-entradas-arranque",
                Naturaleza::Compromiso,
                CheckState::Fallo("x".into()),
            )]),
            maquina(),
            0,
        );
        assert_eq!(s.juicio, Juicio::Sospechoso);
    }

    #[test]
    fn la_confianza_de_limpio_depende_de_cuanto_se_miro() {
        let poco = vec![
            comp("a", Naturaleza::Compromiso, CheckState::Ok),
            comp(
                "b",
                Naturaleza::Compromiso,
                CheckState::NoAplicable("x".into()),
            ),
            comp(
                "c",
                Naturaleza::Compromiso,
                CheckState::NoAplicable("x".into()),
            ),
        ];
        let mucho = vec![
            comp("a", Naturaleza::Compromiso, CheckState::Ok),
            comp("b", Naturaleza::Compromiso, CheckState::Ok),
            comp(
                "c",
                Naturaleza::Compromiso,
                CheckState::NoAplicable("x".into()),
            ),
        ];
        assert!(
            senal_de(&inf(poco), maquina(), 0).confianza
                < senal_de(&inf(mucho), maquina(), 0).confianza
        );
    }

    #[test]
    fn los_ids_graves_existen_de_verdad_en_el_informe() {
        let ids = crate::plataforma::pruebas::ids_posibles();
        for g in SIN_EXPLICACION_BENIGNA {
            assert!(
                ids.contains(g) || *g == "spi-ficheros" || *g == "acpi-wpbt",
                "{g} no lo emite nadie"
            );
        }
    }
}
