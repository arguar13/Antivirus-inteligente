//! El tope de bloqueos, y la degradacion automatica.
//!
//! # La frase que resume la fase entera
//!
//! > Si el motor esta bloqueando media red, el motor esta mal, **no la red**.
//!
//! Un IPS que empieza a cortar muchisimo no esta conteniendo una intrusion
//! masiva: casi siempre es una regla mal escrita, un indicador envenenado, o un
//! cambio en el trafico legitimo del cliente que la regla no contemplaba. En los
//! tres casos, seguir cortando empeora las cosas a cada segundo.
//!
//! Y en el caso que NO es un error —una intrusion de verdad, a escala— cortar
//! media red por decision automatica tampoco es la respuesta correcta: eso es
//! una decision de negocio que toma una persona, no un umbral.
//!
//! Por eso, al pasar el tope, el motor **se degrada solo** a
//! [`Modo::SoloDeteccion`](crate::Modo::SoloDeteccion) y lo **declara**.
//!
//! # Por que la degradacion es pegajosa
//!
//! Una vez degradado, no se re-arma solo al bajar el ritmo. Si lo hiciera,
//! entraria en un ciclo de cortar, pasarse, parar, volver a cortar — que desde
//! fuera se ve como una red que va y viene, que es peor de diagnosticar que una
//! que esta cortada del todo. Volver a bloquear exige que una persona lo
//! reactive, que es exactamente la intervencion que la degradacion pide.
//!
//! # Ventana deslizante de verdad
//!
//! El recuento no se reinicia de golpe cada minuto. Con un contador que se pone
//! a cero, mandar el tope entero justo antes del corte y otro tanto justo
//! despues pasa desapercibido: el doble del tope en un instante, sin disparar
//! nada. Aqui se guardan los instantes y se cuenta cuantos caben en el ultimo
//! minuto, mirando desde donde se este.

/// Ventana sobre la que se cuenta el ritmo de bloqueos, en microsegundos.
pub const VENTANA_US: u64 = 60 * 1_000_000;

/// Bloqueos por ventana a partir de los cuales el motor se degrada.
///
/// Treinta cortes por minuto ya es muchisimo para un solo endpoint: un endpoint
/// sano no habla con treinta destinos maliciosos distintos en un minuto. Si se
/// llega ahi, lo mas probable con diferencia es que la regla este mal.
pub const TOPE_POR_VENTANA: usize = 30;

/// Cuantos instantes se guardan como mucho.
///
/// Acota la memoria del limitador pase lo que pase: sin esto, un motor que
/// enloquezca bloqueando reservaria memoria proporcional a su propio fallo.
const MAX_INSTANTES: usize = 4 * TOPE_POR_VENTANA;

/// Lo que el limitador decide sobre un bloqueo que se quiere aplicar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permiso {
    /// Se puede bloquear.
    Adelante,
    /// Este bloqueo dispara la degradacion: NO se aplica, y el modo baja.
    ///
    /// Se distingue de [`Permiso::YaDegradado`] porque es el instante que hay
    /// que contar y avisar: es cuando el operador tiene que enterarse.
    Degradar,
    /// Ya estaba degradado de antes: no se bloquea y no se vuelve a avisar.
    YaDegradado,
}

/// Cuenta bloqueos en una ventana deslizante y degrada al pasarse.
#[derive(Debug, Clone)]
pub struct Limitador {
    tope: usize,
    ventana_us: u64,
    instantes: Vec<u64>,
    degradado_en_us: Option<u64>,
}

impl Default for Limitador {
    fn default() -> Limitador {
        Limitador::nuevo(TOPE_POR_VENTANA, VENTANA_US)
    }
}

impl Limitador {
    /// Un limitador con tope y ventana explicitos.
    ///
    /// Un tope de cero no tiene sentido —seria degradar con el primer bloqueo—
    /// y se sube a uno en vez de aceptarlo en silencio.
    #[must_use]
    pub fn nuevo(tope: usize, ventana_us: u64) -> Limitador {
        Limitador {
            tope: tope.max(1),
            ventana_us: ventana_us.max(1),
            instantes: Vec::new(),
            degradado_en_us: None,
        }
    }

    /// Si el motor esta degradado.
    #[must_use]
    pub fn degradado(&self) -> bool {
        self.degradado_en_us.is_some()
    }

    /// Cuando se degrado, si lo esta.
    #[must_use]
    pub fn degradado_en_us(&self) -> Option<u64> {
        self.degradado_en_us
    }

    /// Bloqueos contados en la ventana que termina en `ahora_us`.
    #[must_use]
    pub fn ritmo(&self, ahora_us: u64) -> usize {
        self.instantes
            .iter()
            .filter(|t| ahora_us.saturating_sub(**t) < self.ventana_us)
            .count()
    }

    /// Pide permiso para aplicar un bloqueo.
    ///
    /// Llamar a esto CUENTA el bloqueo: no es una consulta, es el registro del
    /// intento. Separarlo en «consultar» y «anotar» permitiria consultar y
    /// olvidarse de anotar, que es como un limitador deja de limitar.
    pub fn pedir(&mut self, ahora_us: u64) -> Permiso {
        if self.degradado_en_us.is_some() {
            return Permiso::YaDegradado;
        }

        // Se olvidan los instantes que ya han salido de la ventana.
        let ventana = self.ventana_us;
        self.instantes
            .retain(|t| ahora_us.saturating_sub(*t) < ventana);

        if self.instantes.len() >= self.tope {
            self.degradado_en_us = Some(ahora_us);
            return Permiso::Degradar;
        }

        self.instantes.push(ahora_us);
        // COTA: pase lo que pase, el limitador no crece sin limite.
        if self.instantes.len() > MAX_INSTANTES {
            let sobra = self.instantes.len() - MAX_INSTANTES;
            self.instantes.drain(..sobra);
        }
        Permiso::Adelante
    }

    /// Reactiva el bloqueo tras una degradacion.
    ///
    /// Es una accion DELIBERADA de un operador, no algo que ocurra solo al pasar
    /// el tiempo: ver la doctrina del modulo sobre por que la degradacion es
    /// pegajosa.
    pub fn rearmar(&mut self) {
        self.degradado_en_us = None;
        self.instantes.clear();
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn por_debajo_del_tope_se_bloquea_sin_mas() {
        let mut l = Limitador::nuevo(3, 1_000_000);
        assert_eq!(l.pedir(0), Permiso::Adelante);
        assert_eq!(l.pedir(1), Permiso::Adelante);
        assert_eq!(l.pedir(2), Permiso::Adelante);
        assert!(!l.degradado());
    }

    /// LA SALVAGUARDA: al pasar el tope NO se bloquea, se degrada. El bloqueo
    /// que dispara la degradacion tampoco se aplica.
    #[test]
    fn al_pasar_el_tope_se_degrada_y_ese_bloqueo_no_se_aplica() {
        let mut l = Limitador::nuevo(3, 1_000_000);
        for i in 0..3 {
            assert_eq!(l.pedir(i), Permiso::Adelante);
        }
        assert_eq!(l.pedir(4), Permiso::Degradar);
        assert!(l.degradado());
        assert_eq!(l.degradado_en_us(), Some(4));
    }

    /// La degradacion es PEGAJOSA: no se re-arma sola por mucho que baje el
    /// ritmo. Si lo hiciera, la red iria y vendria, que es peor de diagnosticar
    /// que una red cortada del todo.
    #[test]
    fn la_degradacion_no_se_rearma_sola_con_el_tiempo() {
        let mut l = Limitador::nuevo(2, 1_000);
        l.pedir(0);
        l.pedir(1);
        assert_eq!(l.pedir(2), Permiso::Degradar);

        // Pasan mil ventanas enteras sin bloquear nada.
        assert_eq!(l.pedir(10_000_000), Permiso::YaDegradado);
        assert!(l.degradado(), "sigue degradado, y tiene que seguirlo");

        // Solo una intervencion deliberada lo reactiva.
        l.rearmar();
        assert!(!l.degradado());
        assert_eq!(l.pedir(10_000_001), Permiso::Adelante);
    }

    /// Solo se avisa UNA vez. Avisar por cada bloqueo posterior ahogaria el
    /// aviso que importa en un torrente de avisos identicos.
    #[test]
    fn solo_se_avisa_una_vez_de_la_degradacion() {
        let mut l = Limitador::nuevo(1, 1_000_000);
        l.pedir(0);
        assert_eq!(l.pedir(1), Permiso::Degradar);
        for i in 2..100 {
            assert_eq!(l.pedir(i), Permiso::YaDegradado);
        }
    }

    /// LA EVASION QUE MATA A UN CONTADOR QUE SE REINICIA: con una ventana que se
    /// pone a cero cada minuto, el tope entero justo antes del corte y otro
    /// tanto justo despues pasan desapercibidos. Con ventana deslizante, no.
    #[test]
    fn una_ventana_deslizante_ve_la_rafaga_a_caballo_del_corte() {
        let mut l = Limitador::nuevo(10, 1_000_000);
        // Nueve bloqueos al final de la primera ventana.
        for i in 0..9u64 {
            assert_eq!(l.pedir(900_000 + i), Permiso::Adelante);
        }
        // Y dos mas justo despues del minuto: con reinicio esto seria «2 de 10»
        // y pasaria; en ventana deslizante son 10 en el ultimo minuto.
        assert_eq!(l.pedir(1_000_001), Permiso::Adelante);
        assert_eq!(
            l.pedir(1_000_002),
            Permiso::Degradar,
            "la rafaga a caballo del corte TIENE que verse"
        );
    }

    /// Y el reverso: bloqueos repartidos de verdad a lo largo del tiempo NO
    /// degradan. Si degradaran, el IPS se apagaria solo en una red normal.
    #[test]
    fn un_ritmo_bajo_sostenido_no_degrada_nunca() {
        let mut l = Limitador::nuevo(5, 1_000_000);
        // Un bloqueo cada medio segundo durante mucho rato: 2 por ventana.
        for i in 0..500u64 {
            assert_eq!(l.pedir(i * 500_000), Permiso::Adelante, "en i={i}");
        }
        assert!(!l.degradado());
    }

    /// El ritmo se mide sobre la ventana, no desde el principio de los tiempos.
    #[test]
    fn el_ritmo_solo_cuenta_lo_que_cae_en_la_ventana() {
        let mut l = Limitador::nuevo(100, 1_000_000);
        for i in 0..10u64 {
            l.pedir(i);
        }
        assert_eq!(l.ritmo(100), 10);
        assert_eq!(l.ritmo(2_000_000), 0, "ya salio todo de la ventana");
    }

    /// La memoria del limitador esta acotada aunque el motor enloquezca.
    #[test]
    fn la_memoria_del_limitador_esta_acotada() {
        let mut l = Limitador::nuevo(usize::MAX, u64::MAX);
        for i in 0..100_000u64 {
            l.pedir(i);
        }
        assert!(
            l.instantes.len() <= MAX_INSTANTES,
            "instantes = {}",
            l.instantes.len()
        );
    }

    /// Un tope de cero es un error de configuracion, y aceptarlo degradaria con
    /// el primer bloqueo: se sube a uno en vez de callarlo.
    #[test]
    fn un_tope_de_cero_no_se_acepta_en_silencio() {
        let mut l = Limitador::nuevo(0, 1_000_000);
        assert_eq!(
            l.pedir(0),
            Permiso::Adelante,
            "al menos uno tiene que caber"
        );
    }
}
