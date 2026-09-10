//! Reconexion exponencial con dispersion.
//!
//! # Por que la dispersion no es un adorno
//!
//! El SIEM del cliente se reinicia por mantenimiento. Diez mil agentes —o, en
//! el caso del plano de control, sus canales de salida— detectan la caida en el
//! mismo segundo, y con un retroceso exponencial puro reintentan todos en el
//! mismo instante: 1 s, 2 s, 4 s, 8 s... siempre a la vez.
//!
//! El SIEM vuelve, recibe diez mil conexiones simultaneas, se cae otra vez, y
//! el sistema entra en un ciclo que se alimenta solo. Es la **estampida**: el
//! mecanismo puesto para tolerar la caida es lo que impide que se recupere.
//!
//! La dispersion rompe la sincronia: cada reintento espera un tiempo aleatorio
//! DENTRO de la ventana, no la ventana entera. Se usa la variante «completa»
//! —uniforme en `[0, ventana]`— y no la «igualada» porque reparte mejor cuando
//! hay muchos clientes, que es el caso que hay que sobrevivir.
//!
//! # Por que hay un techo
//!
//! Sin techo, tras una caida larga la espera crece hasta horas: el SIEM lleva
//! diez minutos disponible y nadie le ha enviado nada porque todos esperan a
//! que venzan sus cuatro horas. El techo acota cuanto puede tardar el sistema
//! en darse cuenta de que el destino volvio.
//!
//! # De donde sale el azar
//!
//! De `SystemTime` mezclado con la direccion de una asignacion propia, sin
//! traer un generador aleatorio como dependencia. Esto NO es criptografia:
//! nadie gana nada prediciendo cuando reintentara un productor. Lo unico que se
//! necesita es que diez mil procesos no elijan el mismo numero, y para eso
//! basta con que las semillas difieran.

use std::time::Duration;

/// Politica de reintento.
#[derive(Debug, Clone)]
pub struct Politica {
    /// Espera base del primer reintento.
    pub base: Duration,
    /// Techo de la ventana de espera.
    pub techo: Duration,
    /// Factor de crecimiento por intento.
    pub factor: u32,
}

impl Default for Politica {
    fn default() -> Politica {
        Politica {
            base: Duration::from_millis(250),
            techo: Duration::from_secs(60),
            factor: 2,
        }
    }
}

/// Estado del reintento de UN destino.
#[derive(Debug)]
pub struct Reintento {
    politica: Politica,
    intentos: u32,
    semilla: u64,
}

impl Reintento {
    /// Crea el estado con la politica dada.
    pub fn nuevo(politica: Politica) -> Reintento {
        // La semilla mezcla el reloj con la direccion de una asignacion propia:
        // dos procesos que arranquen en el mismo milisegundo —lo normal en un
        // despliegue— no pueden acabar con la misma secuencia.
        let ahora = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        let propio = Box::new(0u8);
        let direccion = std::ptr::from_ref(&*propio) as u64;
        Reintento {
            politica,
            intentos: 0,
            semilla: (ahora ^ direccion.rotate_left(17) ^ 0x9E37_79B9_7F4A_7C15) | 1,
        }
    }

    /// Intentos fallidos acumulados.
    pub fn intentos(&self) -> u32 {
        self.intentos
    }

    /// Ventana de espera SIN dispersar, para el intento actual.
    ///
    /// Es la que se documenta y la que se prueba: la dispersada es aleatoria
    /// por definicion y de ella solo se puede afirmar que cae dentro.
    pub fn ventana(&self) -> Duration {
        let mut d = self.politica.base;
        for _ in 0..self.intentos {
            // Saturar en el techo en vez de desbordar: un desbordamiento
            // volveria a una espera diminuta y produciria la estampida que
            // todo esto existe para evitar.
            d = match d.checked_mul(self.politica.factor) {
                Some(v) => v,
                None => self.politica.techo,
            };
            if d >= self.politica.techo {
                return self.politica.techo;
            }
        }
        d.min(self.politica.techo)
    }

    /// Registra un fallo y devuelve cuanto esperar, ya dispersado.
    pub fn fallo(&mut self) -> Duration {
        let ventana = self.ventana();
        self.intentos = self.intentos.saturating_add(1);
        self.dispersar(ventana)
    }

    /// Registra un exito: la proxima caida vuelve a empezar por la base.
    ///
    /// Sin esto, un destino que se cae y se recupera cada pocos minutos
    /// acabaria con la espera en el techo permanentemente, y una caida corta
    /// costaria un minuto de retraso que no hacia falta.
    pub fn exito(&mut self) {
        self.intentos = 0;
    }

    /// Uniforme en `[0, ventana]`: la dispersion «completa».
    fn dispersar(&mut self, ventana: Duration) -> Duration {
        let micros = ventana.as_micros() as u64;
        if micros == 0 {
            return Duration::ZERO;
        }
        // xorshift64*: suficiente para repartir, trivial de auditar, sin
        // dependencias. No es criptografia y no pretende serlo.
        let mut x = self.semilla;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.semilla = x;
        Duration::from_micros(x.wrapping_mul(0x2545_F491_4F6C_DD1D) % (micros + 1))
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_ventana_crece_y_se_detiene_en_el_techo() {
        let mut r = Reintento::nuevo(Politica {
            base: Duration::from_millis(100),
            techo: Duration::from_secs(1),
            factor: 2,
        });
        assert_eq!(r.ventana(), Duration::from_millis(100));
        r.fallo();
        assert_eq!(r.ventana(), Duration::from_millis(200));
        r.fallo();
        assert_eq!(r.ventana(), Duration::from_millis(400));
        for _ in 0..20 {
            r.fallo();
        }
        assert_eq!(
            r.ventana(),
            Duration::from_secs(1),
            "sin techo, tras una caida larga la espera crece hasta horas y el \
             SIEM lleva diez minutos vivo sin recibir nada"
        );
    }

    #[test]
    fn muchos_intentos_no_desbordan_hasta_volver_a_una_espera_diminuta() {
        // Un desbordamiento devolveria una espera casi nula y produciria la
        // estampida que todo este modulo existe para evitar.
        let mut r = Reintento::nuevo(Politica {
            base: Duration::from_secs(1),
            techo: Duration::from_secs(300),
            factor: 10,
        });
        for _ in 0..100 {
            let e = r.fallo();
            assert!(e <= Duration::from_secs(300));
        }
        assert_eq!(r.ventana(), Duration::from_secs(300));
    }

    #[test]
    fn un_exito_devuelve_la_espera_a_la_base() {
        // Un destino que se cae y se recupera cada pocos minutos no puede
        // quedarse con la espera en el techo para siempre.
        let mut r = Reintento::nuevo(Politica::default());
        for _ in 0..10 {
            r.fallo();
        }
        assert_eq!(r.ventana(), Duration::from_secs(60));
        r.exito();
        assert_eq!(r.ventana(), Duration::from_millis(250));
    }

    #[test]
    fn la_dispersion_reparte_de_verdad_dentro_de_la_ventana() {
        // La propiedad que evita la estampida: mil productores no pueden elegir
        // el mismo instante. Se comprueba que los valores se reparten por la
        // ventana y no se agolpan en un extremo.
        let mut r = Reintento::nuevo(Politica {
            base: Duration::from_secs(10),
            techo: Duration::from_secs(10),
            factor: 1,
        });
        let mut cubos = [0usize; 10];
        for _ in 0..2000 {
            let e = r.fallo();
            assert!(
                e <= Duration::from_secs(10),
                "nunca por encima de la ventana"
            );
            let cubo = ((e.as_millis() * 10) / 10_000).min(9) as usize;
            cubos[cubo] += 1;
        }
        // Con reparto uniforme cada cubo tendria ~200. Se exige que ninguno
        // quede vacio y que ninguno acapare: un generador roto que devolviera
        // siempre lo mismo, o casi, fallaria aqui.
        for (i, c) in cubos.iter().enumerate() {
            assert!(*c > 50, "el cubo {i} solo recibio {c} de 2000: no reparte");
            assert!(*c < 600, "el cubo {i} acaparo {c} de 2000: no reparte");
        }
    }

    #[test]
    fn dos_reintentos_creados_a_la_vez_no_siguen_la_misma_secuencia() {
        // El caso real: diez mil procesos arrancan en el mismo despliegue. Si
        // compartieran secuencia, la dispersion no dispersaria nada.
        let p = Politica {
            base: Duration::from_secs(10),
            techo: Duration::from_secs(10),
            factor: 1,
        };
        let (mut a, mut b) = (Reintento::nuevo(p.clone()), Reintento::nuevo(p));
        let sa: Vec<_> = (0..8).map(|_| a.fallo()).collect();
        let sb: Vec<_> = (0..8).map(|_| b.fallo()).collect();
        assert_ne!(sa, sb, "dos productores no pueden reintentar al unisono");
    }
}
