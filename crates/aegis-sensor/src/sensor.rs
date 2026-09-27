//! El sensor: cuenta lo que ve, cuenta lo que pierde POR FAMILIA, degrada por
//! presupuesto diciendolo, y traduce la ceguera en `SinDatos`.
//!
//! # Un sensor que pierde, lo dice y lo cuenta
//!
//! La perdida no es un supuesto del operador: es una CIFRA por familia que el
//! propio sensor publica. Un anillo lleno produce un `NoConcluyente` de esa familia
//! —un `SinDatos` con su cuenta—, jamas un hueco silencioso que se lea como «no
//! paso nada».
//!
//! # La degradacion es visible
//!
//! Si el coste sube por encima del presupuesto, se apagan familias por orden de
//! VALOR ascendente —la de menor valor primero— y se DICE cual se apago. Una
//! familia apagada tambien produce `SinDatos`: el cliente sabe que ahi no se esta
//! mirando. Una degradacion silenciosa es una ceguera que el cliente no sabe que
//! tiene.

use std::collections::{BTreeMap, BTreeSet};

use aegis_entidad::{Confianza, Eid, Juicio, Senal, Severidad};

use crate::evento::Evento;
use crate::familia::Familia;

/// El estado por familia: cuantos eventos se vieron y cuantos se perdieron.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EstadoFamilia {
    /// Eventos entregados.
    pub vistos: u64,
    /// Eventos perdidos por anillo lleno.
    pub perdidos: u64,
    /// Si la familia esta encendida.
    pub activa: bool,
}

/// El sensor de telemetria.
#[derive(Debug, Clone)]
pub struct Sensor {
    activas: BTreeSet<Familia>,
    vistos: BTreeMap<Familia, u64>,
    perdidos: BTreeMap<Familia, u64>,
}

impl Default for Sensor {
    fn default() -> Sensor {
        Sensor::nuevo()
    }
}

impl Sensor {
    /// Un sensor con todas las familias encendidas.
    #[must_use]
    pub fn nuevo() -> Sensor {
        Sensor {
            activas: Familia::todas().iter().copied().collect(),
            vistos: BTreeMap::new(),
            perdidos: BTreeMap::new(),
        }
    }

    /// Si una familia esta encendida.
    #[must_use]
    pub fn activa(&self, f: Familia) -> bool {
        self.activas.contains(&f)
    }

    /// Registra un evento entregado.
    pub fn registrar(&mut self, e: &Evento) {
        *self.vistos.entry(e.familia).or_insert(0) += 1;
    }

    /// Registra `n` eventos perdidos de una familia (anillo lleno).
    pub fn registrar_perdida(&mut self, f: Familia, n: u64) {
        *self.perdidos.entry(f).or_insert(0) += n;
    }

    /// El estado de una familia.
    #[must_use]
    pub fn estado(&self, f: Familia) -> EstadoFamilia {
        EstadoFamilia {
            vistos: self.vistos.get(&f).copied().unwrap_or(0),
            perdidos: self.perdidos.get(&f).copied().unwrap_or(0),
            activa: self.activa(f),
        }
    }

    /// El total de eventos perdidos, en todas las familias.
    #[must_use]
    pub fn perdida_total(&self) -> u64 {
        self.perdidos.values().sum()
    }

    /// Las familias que hoy son un punto ciego: apagadas, o con perdida. Sobre
    /// ellas no se puede afirmar «no paso nada».
    #[must_use]
    pub fn familias_ciegas(&self) -> Vec<Familia> {
        Familia::todas()
            .iter()
            .copied()
            .filter(|f| !self.activa(*f) || self.perdidos.get(f).copied().unwrap_or(0) > 0)
            .collect()
    }

    /// Degrada por presupuesto: apaga familias por VALOR ascendente hasta que el
    /// coste de las activas quepa en `presupuesto`. Devuelve las apagadas en esta
    /// llamada, para DECIRLO.
    pub fn degradar(&mut self, presupuesto: u32) -> Vec<Familia> {
        let mut apagadas = Vec::new();
        // Candidatas a apagar: las activas, de menor a mayor valor (y por nombre
        // como desempate estable).
        let mut orden: Vec<Familia> = self.activas.iter().copied().collect();
        orden.sort_by(|a, b| a.valor().cmp(&b.valor()).then(a.nombre().cmp(b.nombre())));
        let mut i = 0;
        while self.costo_activo() > presupuesto && i < orden.len() {
            let f = orden[i];
            self.activas.remove(&f);
            apagadas.push(f);
            i += 1;
        }
        apagadas
    }

    /// El coste total de las familias activas.
    #[must_use]
    pub fn costo_activo(&self) -> u32 {
        self.activas.iter().map(|f| f.costo()).sum()
    }

    /// Las señales de SinDatos para una entidad: por cada familia ciega, un
    /// `NoConcluyente` del motor de esa familia. El arbitro asi VE que ese plano no
    /// tuvo datos —no que estuviera limpio—.
    ///
    /// La confianza es nula a proposito: un `NoConcluyente` no mueve el veredicto
    /// hacia malicioso; solo declara la ausencia de datos en ese plano.
    #[must_use]
    pub fn senales_sin_datos(&self, entidad: &Eid, ahora_ns: u64) -> Vec<Senal> {
        let mut salida = Vec::new();
        for f in self.familias_ciegas() {
            let perdidos = self.perdidos.get(&f).copied().unwrap_or(0);
            let motivo = if !self.activa(f) {
                format!(
                    "la familia «{}» esta APAGADA por presupuesto: en el plano {} no se esta \
                     mirando, asi que no es «limpio», es «no se»",
                    f.nombre(),
                    f.plano().nombre()
                )
            } else {
                format!(
                    "la familia «{}» perdio {perdidos} evento(s) por anillo lleno: en el plano {} \
                     hay un hueco de cobertura, no una ausencia de actividad",
                    f.nombre(),
                    f.plano().nombre()
                )
            };
            salida.push(Senal::nueva(
                f.motor(),
                entidad.clone(),
                Juicio::NoConcluyente,
                Severidad::Info,
                Confianza::NULA,
                motivo,
                ahora_ns,
            ));
        }
        salida
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::{arbitrar, entidad, Resultado};

    fn ent() -> Eid {
        entidad::contenido("7f1e")
    }

    #[test]
    fn cuenta_lo_visto_y_lo_perdido_por_familia() {
        let mut s = Sensor::nuevo();
        let e = Evento::nuevo(Familia::Proceso, ent(), None, vec![], 1);
        s.registrar(&e);
        s.registrar(&e);
        s.registrar_perdida(Familia::Proceso, 5);
        let est = s.estado(Familia::Proceso);
        assert_eq!(est.vistos, 2);
        assert_eq!(est.perdidos, 5);
    }

    #[test]
    fn una_familia_con_perdida_produce_no_concluyente_y_no_limpio() {
        // El corazon de la fase: perder eventos NO es «limpio». El arbitro, con
        // solo una señal NoConcluyente, da SinDatos.
        let mut s = Sensor::nuevo();
        s.registrar_perdida(Familia::Red, 3);
        let senales = s.senales_sin_datos(&ent(), 1000);
        assert!(senales
            .iter()
            .any(|sig| sig.motor == aegis_entidad::Motor::Wire));
        let solo_red: Vec<Senal> = senales
            .into_iter()
            .filter(|sig| sig.motor == aegis_entidad::Motor::Wire)
            .collect();
        let v = arbitrar(&ent(), &solo_red, 1000);
        assert_eq!(
            v.resultado,
            Resultado::SinDatos,
            "perder eventos no es limpio"
        );
    }

    #[test]
    fn la_degradacion_apaga_lo_de_menor_valor_y_lo_dice() {
        let mut s = Sensor::nuevo();
        let total = s.costo_activo();
        // Presupuesto justo por debajo del total: se apagan las de menor valor.
        let apagadas = s.degradar(total - 1);
        assert!(!apagadas.is_empty(), "algo se tuvo que apagar");
        // La primera apagada es la de menor valor (perf, valor 50).
        assert_eq!(
            apagadas[0],
            Familia::Perf,
            "se apaga primero la de menor valor"
        );
        // Y proceso (la de mas valor) NUNCA se apaga por un recorte pequeno.
        assert!(
            s.activa(Familia::Proceso),
            "la ejecucion de procesos se conserva"
        );
        assert!(s.costo_activo() < total);
    }

    #[test]
    fn una_familia_apagada_es_sin_datos_no_limpio() {
        let mut s = Sensor::nuevo();
        s.degradar(0); // apaga todo lo posible
                       // Las apagadas producen SinDatos.
        let senales = s.senales_sin_datos(&ent(), 1);
        assert!(!senales.is_empty());
        assert!(senales
            .iter()
            .all(|sig| sig.juicio == Juicio::NoConcluyente));
    }

    #[test]
    fn sin_perdida_ni_apagados_no_hay_familias_ciegas() {
        let s = Sensor::nuevo();
        assert!(
            s.familias_ciegas().is_empty(),
            "todo encendido y sin perdida: nada ciego"
        );
        assert!(s.senales_sin_datos(&ent(), 1).is_empty());
    }
}
