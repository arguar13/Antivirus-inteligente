//! La postura de aplicacion del agente, medida y publicada (H-28).
//!
//! `aegis-enforce` separa lo que el kernel OFRECE (`DISPONIBLE`) de lo que el
//! producto IMPONE (`APLICA`), y lo segundo solo sale de una evidencia medida
//! sobre un proceso concreto del producto: un testigo. En el agente, el proceso
//! que de verdad esta confinado es su trabajador de analisis, que se pone un
//! dominio Landlock y un filtro seccomp antes de leer un solo byte. Por eso el
//! testigo es el, y por eso nadie mas que el puede hacer que una capa salga
//! con la etiqueta `APLICA`.
//!
//! # Quien construye el testigo
//!
//! Este modulo no: recibe un [`Testigo`] ya hecho. Lo construye el motor
//! estatico, que es el dueño del trabajador, con su pid y con la ABI de
//! Landlock que el trabajador declaro en su saludo. Tiene que ser el dueño: el
//! pid de un hijo solo es de ese hijo mientras nadie lo recoja, y quien lo
//! recoge es el propio cliente del trabajador. Midiendo desde el hilo que lo
//! posee, entre dos peticiones, el pid no puede pasar a otro proceso a mitad de
//! la medida; como mucho el trabajador puede haber muerto sin que nadie lo
//! sepa todavia, y un proceso muerto no cuenta como testigo (`aegis-enforce`
//! lo comprueba en su `State:`).
//!
//! # Solo-auditoria por construccion
//!
//! Medir es leer `/proc` y `/sys/kernel/security/lsm`. Lo medido no entra en el
//! arbitro, no aporta señales, no rechaza politicas ni cambia ninguna decision
//! del agente: solo se publica en el informe periodico y, con el, en
//! `aegisctl status`. Si alguna vez una decision depende de esta medida (por
//! ejemplo, rechazar una politica de bloqueo con `Postura::puede_cumplir`), esa
//! decision nacera en solo-auditoria como cualquier otro gancho del agente.
//!
//! Sin testigo —no hay trabajador, murio y aun no se ha relanzado, o esta
//! enfriando— ninguna capa puede salir `APLICA`: lo mas que puede salir es
//! `DISPONIBLE`, que es lo honrado.

use std::time::Instant;

use aegis_enforce::{Estado, Postura, Testigo};

/// Una medida de la postura de aplicacion, con sobre que y cuando se hizo.
#[derive(Debug, Clone)]
pub struct Medida {
    /// Lo medido: el estado de cada capa, con su evidencia o su motivo.
    pub postura: Postura,
    /// El proceso sobre el que se busco evidencia, si habia alguno.
    pub testigo: Option<Testigo>,
    /// Cuando se midio: el informe dice hace cuanto, para que una medida vieja
    /// no pase por actual.
    pub cuando: Instant,
}

/// Mide la postura de esta maquina con el testigo dado, o sin ninguno.
///
/// Sin testigo, `aegis-enforce` no puede encontrar evidencia y ninguna capa
/// sale aplicada: lo que el kernel ofrece sale como disponible.
pub fn medir(testigo: Option<Testigo>) -> Medida {
    Medida {
        postura: Postura::medida_con(testigo.as_slice()),
        testigo,
        cuando: Instant::now(),
    }
}

/// Las lineas con las que la medida entra en el informe periodico (y, con el,
/// en `aegisctl status`).
///
/// La primera dice como debe describirse el agente, sobre que testigo se midio y
/// hace cuanto. Despues va una linea por capa de esta plataforma, con su
/// etiqueta estable (`APLICA`, `DISPONIBLE`, `SOLO-OBSERVA`, `AUSENTE`) y su
/// evidencia o su motivo, tal como los da `aegis-enforce`: aqui no se escribe a
/// mano el estado de ninguna capa. Las capas de otras plataformas no se listan:
/// en Linux no son una carencia, y meterlas llenaria el informe de ruido.
pub fn lineas(m: &Medida) -> Vec<String> {
    let testigo = match m.testigo {
        Some(t) => {
            let pid = t.pid;
            match t.landlock_declarado {
                Some(abi) => format!(
                    "trabajador confinado, pid {pid}, declara un dominio Landlock de ABI {abi}"
                ),
                None => format!("trabajador confinado, pid {pid}, no declara dominio Landlock"),
            }
        }
        None => "ninguno (sin trabajador confinado vivo no hay proceso del producto sobre el \
                 que medir)"
            .to_string(),
    };
    let mut v = vec![format!(
        "aplicacion: {} | testigo: {testigo} | medida hace {} s",
        m.postura.como_describirse(),
        m.cuando.elapsed().as_secs()
    )];
    for (c, e) in &m.postura.capacidades {
        if matches!(e, Estado::OtraPlataforma) {
            continue;
        }
        v.push(format!(
            "aplicacion {}: {} ({})",
            c.nombre(),
            e.etiqueta(),
            e.detalle()
        ));
    }
    v
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn sin_testigo_ninguna_capa_sale_aplicada() {
        let m = medir(None);
        assert!(m.testigo.is_none());
        assert!(
            m.postura.aplicando().is_empty(),
            "sin testigo no hay evidencia: {:?}",
            m.postura.capacidades
        );
        let l = lineas(&m);
        assert!(l[0].starts_with("aplicacion: SOLO OBSERVANDO"), "{l:?}");
        assert!(l[0].contains("testigo: ninguno"), "{l:?}");
        // Cada linea de capa lleva su etiqueta estable, y ninguna la de aplicado.
        for linea in &l[1..] {
            let etiqueta = linea
                .split_once(": ")
                .and_then(|(_, r)| r.split_once(' '))
                .map(|(e, _)| e);
            assert!(etiqueta.is_some(), "linea sin etiqueta: {linea}");
            assert_ne!(etiqueta, Some("APLICA"), "{linea}");
        }
    }

    #[test]
    fn las_capas_de_otras_plataformas_no_salen_en_el_informe() {
        let l = lineas(&medir(None));
        for ajena in ["minifiltro", "ObCallbacks", "Endpoint Security"] {
            assert!(
                !l.iter().any(|x| x.contains(ajena)),
                "{ajena} no es una carencia de una maquina Linux: {l:?}"
            );
        }
        // Y las de Linux, todas, cada una con su etiqueta.
        for capa in ["seccomp", "Landlock", "BPF LSM", "XDP"] {
            assert!(
                l.iter()
                    .any(|x| x.starts_with(&format!("aplicacion {capa}: "))),
                "falta {capa}: {l:?}"
            );
        }
    }

    #[test]
    fn el_testigo_se_nombra_con_su_pid_y_lo_que_declara() {
        // Nombrar un testigo no es evidencia: aqui solo se comprueba que el
        // informe dice sobre que proceso se midio y que declaraba. Que salga o
        // no aplicado lo decide aegis-enforce con lo que lee de /proc, y lo
        // prueba tests/postura_aplicacion.rs con un trabajador de verdad.
        let pid = std::process::id();
        let l = lineas(&medir(Some(Testigo::proceso(pid).con_landlock(1))));
        assert!(l[0].contains(&format!("pid {pid}")), "{l:?}");
        assert!(l[0].contains("dominio Landlock de ABI 1"), "{l:?}");
        let l = lineas(&medir(Some(Testigo::proceso(pid))));
        assert!(l[0].contains("no declara dominio Landlock"), "{l:?}");
    }
}
