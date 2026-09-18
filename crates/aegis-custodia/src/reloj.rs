//! Los dos relojes, y por que hacen falta los dos.
//!
//! # El reloj de pared miente cuando mas importa
//!
//! Una cronologia forense se sostiene sobre marcas de tiempo, y la marca obvia
//! —el reloj de pared— es la unica que un atacante con root puede mover:
//! `clock_settime` esta a una llamada de distancia. Retrasarlo dos horas coloca
//! la actividad del atacante ANTES de la ventana que el analista esta mirando;
//! adelantarlo la coloca despues. En los dos casos la evidencia sigue siendo
//! autentica, sigue estando firmada, y cuenta una historia falsa.
//!
//! Firmar la marca no arregla nada: lo que se firma es el numero que el kernel
//! devolvio, y ese numero ya venia movido.
//!
//! # El segundo reloj
//!
//! El reloj de arranque cuenta desde que la maquina arranco, incluye el tiempo
//! suspendido y **no se puede mover**: no hay llamada para fijarlo. No sirve
//! para decir «esto paso el martes» —no sabe que dia es—, pero si para lo que
//! aqui hace falta:
//!
//! - **Ordenar** dos hechos del mismo arranque, con independencia de lo que diga
//!   el reloj de pared.
//! - **Delatar** que el reloj de pared se movio: si dos marcas del mismo arranque
//!   estan en un orden por el reloj monotono y en el contrario por el de pared,
//!   alguien toco el reloj entre las dos. Eso no es una sospecha, es aritmetica.
//!
//! Por eso cada marca lleva los dos relojes y el identificador de arranque. Y
//! por eso [`Marca::incoherente_con`] existe: la contradiccion se REPORTA, no se
//! resuelve por decreto eligiendo uno de los dos.
//!
//! Las dos lecturas vienen de `aegis_scal::linux::reloj`, que es donde el
//! producto concentra las llamadas al sistema. Este crate no necesita `unsafe` y
//! por eso lo prohibe.

use aegis_scal::linux::reloj;

use crate::canon::Codificador;

/// Instante en que ocurrio algo, medido por los dos relojes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Marca {
    /// Segundos desde la epoca Unix segun el reloj de pared.
    ///
    /// Es el unico que sabe que dia es, y el unico que se puede mover. Se
    /// registra porque un informe forense sin fecha no sirve, no porque se
    /// confie en el.
    pub pared: u64,
    /// Nanosegundos desde el arranque, contando la suspension.
    ///
    /// No se puede fijar y no retrocede. Ordena hechos del mismo arranque.
    pub arranque_ns: u64,
    /// Identificador del arranque en curso.
    ///
    /// Sin el, comparar dos `arranque_ns` de arranques distintos no significa
    /// nada: los dos cuentan desde cero. Ver [`id_de_arranque`].
    pub arranque: u64,
}

impl Marca {
    /// Toma la marca de ahora mismo.
    ///
    /// Un reloj que no responde se anota como cero y no como una hora
    /// inventada. Cero es reconocible —ningun hecho de este producto ocurrio en
    /// 1970— y [`Marca::fechable`] lo dice sin que haya que adivinarlo.
    pub fn ahora() -> Marca {
        Marca {
            pared: reloj::pared_segundos().unwrap_or(0),
            arranque_ns: reloj::arranque_nanos().unwrap_or(0),
            arranque: id_de_arranque(),
        }
    }

    /// Indica si esta marca puede fechar un hecho.
    ///
    /// Falso cuando el reloj de pared no se pudo leer. Un informe que presente
    /// una marca no fechable como una fecha estaria inventando, asi que el dato
    /// viaja con su propia advertencia en vez de confiar en que quien lo lea se
    /// fije en que vale cero.
    pub fn fechable(&self) -> bool {
        self.pared > 0
    }

    /// Anade la marca a una codificacion canonica.
    pub fn codificar(&self, c: &mut Codificador) {
        c.u64(self.pared).u64(self.arranque_ns).u64(self.arranque);
    }

    /// Indica si esta marca y `otra` se contradicen.
    ///
    /// Solo es comparable dentro del **mismo arranque**: entre arranques
    /// distintos los contadores parten de cero otra vez y cualquier comparacion
    /// seria ruido. Dentro del mismo arranque, que el orden por el reloj
    /// monotono y el orden por el de pared no coincidan solo tiene una
    /// explicacion: el reloj de pared se movio entre los dos hechos.
    ///
    /// Devuelve `false` cuando no son comparables. No saber no es una
    /// contradiccion, y tratarlo como tal convertiria cada reinicio de la
    /// maquina en una acusacion de manipulacion.
    pub fn incoherente_con(&self, otra: &Marca) -> bool {
        // Arranques distintos, o un arranque que no se pudo identificar: no hay
        // nada que comparar.
        if self.arranque != otra.arranque || self.arranque == 0 {
            return false;
        }
        // Sin reloj de pared en alguno de los dos lados tampoco hay dos ordenes
        // que contrastar.
        if !self.fechable() || !otra.fechable() {
            return false;
        }
        let orden_monotono = self.arranque_ns.cmp(&otra.arranque_ns);
        let orden_pared = self.pared.cmp(&otra.pared);
        // La igualdad en el reloj de pared no contradice nada: su resolucion
        // aqui es de un segundo y dos hechos del mismo segundo son normales.
        if orden_pared == std::cmp::Ordering::Equal {
            return false;
        }
        orden_monotono != orden_pared
    }
}

/// Identificador del arranque en curso.
///
/// Linux lo publica en `/proc/sys/kernel/random/boot_id`: un UUID que cambia en
/// cada arranque. Se condensa a 64 bits porque lo unico que hace falta es
/// distinguir arranques, no identificarlos.
///
/// Si no se puede leer devuelve 0, y entonces [`Marca::incoherente_con`] no
/// comparara nada: sin saber si dos marcas son del mismo arranque, la unica
/// respuesta honesta sobre su coherencia es que no consta.
pub fn id_de_arranque() -> u64 {
    let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") else {
        return 0;
    };
    let r = crate::canon::resumir(s.trim().as_bytes());
    u64::from_be_bytes([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]])
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_marca_de_esta_maquina_trae_los_dos_relojes() {
        let m = Marca::ahora();
        assert!(m.fechable(), "reloj de pared legible: {}", m.pared);
        assert!(m.arranque_ns > 0, "el reloj de arranque avanza");
        assert!(m.arranque != 0, "esta maquina publica su boot_id");
    }

    #[test]
    fn el_reloj_monotono_no_retrocede_entre_dos_lecturas() {
        let a = Marca::ahora();
        let b = Marca::ahora();
        assert!(b.arranque_ns >= a.arranque_ns);
        assert_eq!(a.arranque, b.arranque, "el mismo arranque");
    }

    #[test]
    fn un_reloj_de_pared_movido_hacia_atras_se_delata() {
        // Dos hechos del mismo arranque: el segundo ocurre despues por el reloj
        // monotono y ANTES por el de pared. Solo pasa si alguien movio el reloj.
        let primero = Marca {
            pared: 1_700_000_100,
            arranque_ns: 1_000,
            arranque: 7,
        };
        let segundo = Marca {
            pared: 1_700_000_000, // cien segundos hacia atras
            arranque_ns: 2_000,   // pero despues de verdad
            arranque: 7,
        };
        assert!(
            segundo.incoherente_con(&primero),
            "los dos ordenes se contradicen: el reloj se movio entre los dos \
             hechos"
        );
    }

    #[test]
    fn dos_marcas_coherentes_no_se_acusan() {
        let primero = Marca {
            pared: 1_700_000_000,
            arranque_ns: 1_000,
            arranque: 7,
        };
        let segundo = Marca {
            pared: 1_700_000_100,
            arranque_ns: 2_000,
            arranque: 7,
        };
        assert!(!segundo.incoherente_con(&primero));
    }

    #[test]
    fn marcas_de_arranques_distintos_no_son_comparables() {
        // Los dos contadores parten de cero en cada arranque, asi que
        // compararlos seria ruido. No saber NO es una contradiccion: si lo
        // fuera, cada reinicio acusaria de manipulacion.
        let a = Marca {
            pared: 1_700_000_100,
            arranque_ns: 5_000,
            arranque: 1,
        };
        let b = Marca {
            pared: 1_700_000_000,
            arranque_ns: 9_000,
            arranque: 2,
        };
        assert!(!b.incoherente_con(&a));
    }

    #[test]
    fn sin_identificador_de_arranque_no_se_compara() {
        // Arranque 0 significa que no se pudo leer el boot_id. Dos marcas con
        // cero no son "del mismo arranque": son dos desconocidos.
        let a = Marca {
            pared: 1_700_000_100,
            arranque_ns: 1_000,
            arranque: 0,
        };
        let b = Marca {
            pared: 1_700_000_000,
            arranque_ns: 2_000,
            arranque: 0,
        };
        assert!(!b.incoherente_con(&a));
    }

    #[test]
    fn sin_reloj_de_pared_no_se_compara_ni_se_fecha() {
        let a = Marca {
            pared: 0,
            arranque_ns: 1_000,
            arranque: 7,
        };
        let b = Marca {
            pared: 1_700_000_000,
            arranque_ns: 2_000,
            arranque: 7,
        };
        assert!(!a.fechable(), "sin reloj de pared no hay fecha");
        assert!(!b.incoherente_con(&a), "y sin fecha no hay contradiccion");
    }

    #[test]
    fn dos_hechos_del_mismo_segundo_no_son_una_contradiccion() {
        // El reloj de pared se guarda con resolucion de un segundo. Dos hechos
        // dentro del mismo segundo son lo normal, no una manipulacion.
        let a = Marca {
            pared: 1_700_000_000,
            arranque_ns: 1_000,
            arranque: 7,
        };
        let b = Marca {
            pared: 1_700_000_000,
            arranque_ns: 2_000,
            arranque: 7,
        };
        assert!(!b.incoherente_con(&a));
    }

    #[test]
    fn el_identificador_de_arranque_es_estable_dentro_del_arranque() {
        assert_eq!(id_de_arranque(), id_de_arranque());
    }
}
