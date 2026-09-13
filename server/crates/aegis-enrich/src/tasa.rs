//! La cuota del proveedor, respetada bajo concurrencia.
//!
//! # Por que un contador no basta
//!
//! Lo evidente es «llevo la cuenta y si paso del limite, espero». Y funciona en
//! una prueba de un solo hilo. Con veinte tareas a la vez, veinte comprueban «voy
//! por 99 de 100», veinte pasan, y salen ciento diecinueve consultas. Es la
//! carrera clasica de comprobar-y-actuar, y aqui la paga el cliente: pasarse de la
//! cuota **corta el servicio**, y lo corta justo durante un incidente, que es
//! cuando se consulta mas.
//!
//! Por eso aqui no se comprueba y despues se actua: se **reserva**. Una tarea que
//! obtiene un [`Permiso`] ya ha consumido su ficha antes de salir a la red.
//!
//! # Y por que la reserva se devuelve
//!
//! Si la consulta ni siquiera llega a hacerse —el orquestador la corta por tiempo
//! antes de empezar, o el modo sin salida la impide—, la ficha vuelve. Un
//! consumidor que reserva y no devuelve va agotando la cuota con consultas que no
//! ocurrieron, y el sintoma es un limite que parece mas bajo de lo contratado.
//!
//! La devolucion es explicita ([`Permiso::devolver`]) y **no** ocurre en `Drop`:
//! en `Drop` no se puede distinguir «se solto porque la consulta se hizo» de «se
//! solto porque no se hizo», que es justo la distincion que importa.
//!
//! # El deposito se rellena por tiempo, no por ventana
//!
//! Una ventana fija —«cien por minuto, contador a cero cada minuto»— deja pasar
//! doscientas consultas en dos segundos si caen a caballo del cambio de minuto. El
//! proveedor lo ve como un pico del doble del limite y corta igual. Con relleno
//! continuo eso no puede pasar.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Un segundo, en nanosegundos.
const SEG: u64 = 1_000_000_000;

/// La cuota contratada con un proveedor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cuota {
    /// Consultas por minuto sostenidas.
    pub por_minuto: u32,
    /// Cuantas se pueden gastar de golpe.
    ///
    /// Separado de la tasa sostenida porque son dos cosas distintas: casi todos
    /// los proveedores toleran una rafaga corta y ninguno tolera una tasa media
    /// por encima de lo contratado. Sin rafaga, enriquecer un caso con veinte
    /// observables tarda veinte veces el intervalo y el analista se va.
    pub rafaga: u32,
}

impl Cuota {
    /// Una cuota con rafaga igual a un cuarto de la tasa por minuto, minimo uno.
    #[must_use]
    pub fn por_minuto(n: u32) -> Cuota {
        Cuota {
            por_minuto: n,
            rafaga: (n / 4).max(1),
        }
    }

    /// Cada cuanto entra una ficha nueva, en nanosegundos.
    #[must_use]
    pub fn intervalo_ns(&self) -> u64 {
        if self.por_minuto == 0 {
            return u64::MAX;
        }
        (60 * SEG) / u64::from(self.por_minuto)
    }
}

/// Una ficha ya reservada.
///
/// Existir **es** haber consumido. No hay forma de tener un permiso sin haber
/// pagado por el, y esa es la razon de que el tipo no tenga constructor publico.
#[derive(Debug)]
pub struct Permiso {
    fuente: String,
    limitador: Arc<Limitador>,
    devuelto: bool,
}

impl Permiso {
    /// A que fuente pertenece.
    #[must_use]
    pub fn fuente(&self) -> &str {
        &self.fuente
    }

    /// Devuelve la ficha porque la consulta **no llego a hacerse**.
    ///
    /// Explicito y no en `Drop`: en `Drop` no se puede distinguir «se solto porque
    /// la consulta se hizo» de «se solto porque no se hizo».
    pub fn devolver(mut self) {
        self.limitador.devolver(&self.fuente);
        self.devuelto = true;
    }

    /// Confirma que la consulta se hizo y la ficha se queda gastada.
    pub fn gastado(mut self) {
        self.devuelto = true;
    }
}

impl Drop for Permiso {
    fn drop(&mut self) {
        // Si nadie dijo nada, se asume gastado: es lo conservador. Asumir devuelto
        // haria que un camino de error olvidado regalara cuota que el proveedor si
        // contabilizo.
        self.devuelto = true;
    }
}

/// Por que no se pudo reservar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinCuota {
    /// No hay fichas ahora; vuelve en tanto.
    Espera {
        /// Cuanto falta, en nanosegundos.
        falta_ns: u64,
    },
    /// Esa fuente no tiene cuota configurada.
    FuenteDesconocida,
}

impl SinCuota {
    /// Texto para el informe.
    #[must_use]
    pub fn texto(&self) -> String {
        match self {
            SinCuota::Espera { falta_ns } => format!(
                "cuota del proveedor agotada; la siguiente ficha entra en {} ms. No se consulto, \
                 que NO es lo mismo que que no hubiera nada",
                falta_ns / 1_000_000
            ),
            SinCuota::FuenteDesconocida => {
                "esa fuente no tiene cuota configurada, asi que no se consulta: una fuente sin \
                 cuota declarada es una fuente que puede agotar el contrato sin que nadie lo vea"
                    .to_string()
            }
        }
    }
}

#[derive(Debug)]
struct Deposito {
    cuota: Cuota,
    /// Fichas disponibles en milesimas, para que el relleno continuo no pierda
    /// resolucion con tasas bajas.
    fichas_mili: u64,
    ultimo_ns: u64,
    concedidos: u64,
    rechazados: u64,
}

/// El limitador de todas las fuentes.
#[derive(Debug, Default)]
pub struct Limitador {
    depositos: Mutex<HashMap<String, Deposito>>,
}

impl Limitador {
    /// Un limitador sin fuentes.
    #[must_use]
    pub fn nuevo() -> Arc<Limitador> {
        Arc::new(Limitador::default())
    }

    /// Declara la cuota de una fuente.
    ///
    /// El deposito empieza **lleno hasta la rafaga**: al arrancar no se debe nada
    /// al proveedor, y empezar vacio haria que el primer enriquecimiento tras un
    /// reinicio fuera artificialmente lento.
    pub fn declarar(&self, fuente: impl Into<String>, cuota: Cuota, ahora_ns: u64) {
        let mut d = self
            .depositos
            .lock()
            .expect("el limitador no entra en panico");
        d.insert(
            fuente.into(),
            Deposito {
                cuota,
                fichas_mili: u64::from(cuota.rafaga) * 1000,
                ultimo_ns: ahora_ns,
                concedidos: 0,
                rechazados: 0,
            },
        );
    }

    /// Reserva una ficha.
    ///
    /// # Errors
    ///
    /// Devuelve [`SinCuota`] si no hay fichas o la fuente no esta declarada.
    pub fn reservar(self: &Arc<Self>, fuente: &str, ahora_ns: u64) -> Result<Permiso, SinCuota> {
        let mut mapa = self
            .depositos
            .lock()
            .expect("el limitador no entra en panico");
        let Some(d) = mapa.get_mut(fuente) else {
            return Err(SinCuota::FuenteDesconocida);
        };
        rellenar(d, ahora_ns);
        if d.fichas_mili >= 1000 {
            d.fichas_mili -= 1000;
            d.concedidos += 1;
            return Ok(Permiso {
                fuente: fuente.to_string(),
                limitador: Arc::clone(self),
                devuelto: false,
            });
        }
        d.rechazados += 1;
        let faltan_mili = 1000 - d.fichas_mili;
        let falta_ns = faltan_mili.saturating_mul(d.cuota.intervalo_ns()) / 1000;
        Err(SinCuota::Espera { falta_ns })
    }

    /// Devuelve una ficha que no se llego a gastar.
    fn devolver(&self, fuente: &str) {
        let mut mapa = self
            .depositos
            .lock()
            .expect("el limitador no entra en panico");
        if let Some(d) = mapa.get_mut(fuente) {
            let tope = u64::from(d.cuota.rafaga) * 1000;
            d.fichas_mili = (d.fichas_mili + 1000).min(tope);
            d.concedidos = d.concedidos.saturating_sub(1);
        }
    }

    /// Concedidos y rechazados de una fuente.
    #[must_use]
    pub fn cuentas(&self, fuente: &str) -> Option<(u64, u64)> {
        let mapa = self
            .depositos
            .lock()
            .expect("el limitador no entra en panico");
        mapa.get(fuente).map(|d| (d.concedidos, d.rechazados))
    }

    /// Fichas disponibles ahora mismo, redondeando hacia abajo.
    #[must_use]
    pub fn disponibles(&self, fuente: &str, ahora_ns: u64) -> Option<u32> {
        let mut mapa = self
            .depositos
            .lock()
            .expect("el limitador no entra en panico");
        let d = mapa.get_mut(fuente)?;
        rellenar(d, ahora_ns);
        Some(u32::try_from(d.fichas_mili / 1000).unwrap_or(u32::MAX))
    }
}

/// Rellena el deposito por el tiempo transcurrido.
///
/// Continuo y no por ventana: una ventana fija deja pasar el doble del limite si
/// las consultas caen a caballo del cambio de ventana.
fn rellenar(d: &mut Deposito, ahora_ns: u64) {
    if ahora_ns <= d.ultimo_ns {
        // El tiempo no va hacia atras, pero el argumento podria: no se regala nada
        // y tampoco se rompe.
        return;
    }
    let intervalo = d.cuota.intervalo_ns();
    if intervalo == u64::MAX {
        d.ultimo_ns = ahora_ns;
        return;
    }
    let pasado = ahora_ns - d.ultimo_ns;
    let ganadas_mili = pasado.saturating_mul(1000) / intervalo;
    if ganadas_mili == 0 {
        // No se toca `ultimo_ns`: si se tocara, los avances pequeños se perderian
        // por redondeo y el deposito no se rellenaria nunca con consultas
        // frecuentes.
        return;
    }
    let tope = u64::from(d.cuota.rafaga) * 1000;
    d.fichas_mili = (d.fichas_mili + ganadas_mili).min(tope);
    // Se avanza solo lo consumido por las fichas ganadas, para no perder el resto.
    d.ultimo_ns += ganadas_mili.saturating_mul(intervalo) / 1000;
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    const AHORA: u64 = 1_700_000_000 * SEG;

    #[test]
    fn el_deposito_empieza_lleno_hasta_la_rafaga() {
        // Al arrancar no se le debe nada al proveedor, y empezar vacio haria que el
        // primer enriquecimiento tras un reinicio fuera artificialmente lento.
        let l = Limitador::nuevo();
        l.declarar(
            "rep",
            Cuota {
                por_minuto: 60,
                rafaga: 10,
            },
            AHORA,
        );
        assert_eq!(l.disponibles("rep", AHORA), Some(10));
    }

    #[test]
    fn la_rafaga_se_agota_y_despues_se_va_al_ritmo_sostenido() {
        let l = Limitador::nuevo();
        l.declarar(
            "rep",
            Cuota {
                por_minuto: 60,
                rafaga: 5,
            },
            AHORA,
        );
        for _ in 0..5 {
            l.reservar("rep", AHORA).expect("hay rafaga").gastado();
        }
        // La sexta no cabe.
        let e = l.reservar("rep", AHORA).expect_err("rafaga agotada");
        assert!(matches!(e, SinCuota::Espera { .. }));
        // A 60/min entra una ficha por segundo.
        assert!(l.reservar("rep", AHORA + SEG).is_ok());
    }

    #[test]
    fn el_relleno_es_continuo_y_no_por_ventana() {
        // Con ventana fija de un minuto, gastar 60 al final de una ventana y 60 al
        // principio de la siguiente da 120 en dos segundos. El proveedor lo ve como
        // un pico del doble y corta igual.
        let l = Limitador::nuevo();
        l.declarar(
            "rep",
            Cuota {
                por_minuto: 60,
                rafaga: 60,
            },
            AHORA,
        );
        for _ in 0..60 {
            l.reservar("rep", AHORA).expect("rafaga inicial").gastado();
        }
        // Un segundo despues solo hay UNA ficha, no sesenta.
        assert_eq!(l.disponibles("rep", AHORA + SEG), Some(1));
        l.reservar("rep", AHORA + SEG).expect("una").gastado();
        assert!(l.reservar("rep", AHORA + SEG).is_err());
    }

    #[test]
    fn la_cuota_se_respeta_con_veinte_hilos_a_la_vez() {
        // La carrera clasica de comprobar-y-actuar: veinte tareas leen «voy por 99
        // de 100», veinte pasan, y salen 119 consultas. Pasarse de cuota corta el
        // servicio justo durante un incidente.
        let l = Limitador::nuevo();
        const RAFAGA: u32 = 100;
        l.declarar(
            "rep",
            Cuota {
                por_minuto: 60,
                rafaga: RAFAGA,
            },
            AHORA,
        );

        let concedidos = Arc::new(AtomicU64::new(0));
        thread::scope(|s| {
            for _ in 0..20 {
                let l = Arc::clone(&l);
                let concedidos = Arc::clone(&concedidos);
                s.spawn(move || {
                    for _ in 0..50 {
                        // Mismo instante en todos: el unico limite es la rafaga.
                        if let Ok(p) = l.reservar("rep", AHORA) {
                            concedidos.fetch_add(1, Ordering::SeqCst);
                            p.gastado();
                        }
                    }
                });
            }
        });
        assert_eq!(
            concedidos.load(Ordering::SeqCst),
            u64::from(RAFAGA),
            "se concedieron mas fichas de las que habia"
        );
    }

    #[test]
    fn una_ficha_no_gastada_vuelve_al_deposito() {
        // Un consumidor que reserva y no devuelve va agotando la cuota con
        // consultas que no ocurrieron, y el sintoma es un limite que parece mas
        // bajo de lo contratado.
        let l = Limitador::nuevo();
        l.declarar(
            "rep",
            Cuota {
                por_minuto: 60,
                rafaga: 3,
            },
            AHORA,
        );
        let p = l.reservar("rep", AHORA).expect("hay");
        assert_eq!(l.disponibles("rep", AHORA), Some(2));
        p.devolver();
        assert_eq!(l.disponibles("rep", AHORA), Some(3));
    }

    #[test]
    fn devolver_no_pasa_del_tope_de_rafaga() {
        let l = Limitador::nuevo();
        l.declarar(
            "rep",
            Cuota {
                por_minuto: 60,
                rafaga: 2,
            },
            AHORA,
        );
        let a = l.reservar("rep", AHORA).expect("hay");
        let b = l.reservar("rep", AHORA).expect("hay");
        a.devolver();
        b.devolver();
        assert_eq!(l.disponibles("rep", AHORA), Some(2));
    }

    #[test]
    fn una_fuente_sin_cuota_declarada_no_se_consulta() {
        // Una fuente sin cuota es una fuente que puede agotar el contrato sin que
        // nadie lo vea.
        let l = Limitador::nuevo();
        assert_eq!(
            l.reservar("nadie", AHORA).expect_err("no declarada"),
            SinCuota::FuenteDesconocida
        );
    }

    #[test]
    fn el_rechazo_dice_cuanto_falta() {
        // «No se consulto» sin plazo se lee igual que «no habia nada».
        let l = Limitador::nuevo();
        l.declarar(
            "rep",
            Cuota {
                por_minuto: 60,
                rafaga: 1,
            },
            AHORA,
        );
        l.reservar("rep", AHORA).expect("hay").gastado();
        let SinCuota::Espera { falta_ns } = l.reservar("rep", AHORA).expect_err("agotada") else {
            panic!("deberia ser espera");
        };
        assert_eq!(falta_ns, SEG, "a 60/min falta un segundo");
        assert!(SinCuota::Espera { falta_ns }.texto().contains("1000 ms"));
    }

    #[test]
    fn los_avances_pequenos_no_se_pierden_por_redondeo() {
        // Si cada consulta avanzara el reloj del deposito sin ganar ficha, con
        // trafico frecuente el deposito no se rellenaria NUNCA.
        let l = Limitador::nuevo();
        l.declarar(
            "rep",
            Cuota {
                por_minuto: 60,
                rafaga: 1,
            },
            AHORA,
        );
        l.reservar("rep", AHORA).expect("hay").gastado();
        // Diez consultas fallidas cada 100 ms: al cabo de un segundo hay ficha.
        for i in 1..=9 {
            assert!(l.reservar("rep", AHORA + i * 100_000_000).is_err());
        }
        assert!(
            l.reservar("rep", AHORA + SEG).is_ok(),
            "el deposito no se rellenó pese a haber pasado un segundo"
        );
    }

    #[test]
    fn un_tiempo_que_va_hacia_atras_no_regala_fichas() {
        let l = Limitador::nuevo();
        l.declarar(
            "rep",
            Cuota {
                por_minuto: 60,
                rafaga: 2,
            },
            AHORA,
        );
        l.reservar("rep", AHORA).expect("hay").gastado();
        l.reservar("rep", AHORA).expect("hay").gastado();
        assert!(l.reservar("rep", AHORA - 3600 * SEG).is_err());
    }

    #[test]
    fn una_cuota_de_cero_no_concede_nunca() {
        let l = Limitador::nuevo();
        l.declarar(
            "rep",
            Cuota {
                por_minuto: 0,
                rafaga: 0,
            },
            AHORA,
        );
        assert!(l.reservar("rep", AHORA).is_err());
        assert!(l.reservar("rep", AHORA + 3600 * SEG).is_err());
    }

    #[test]
    fn se_cuentan_concedidos_y_rechazados() {
        let l = Limitador::nuevo();
        l.declarar(
            "rep",
            Cuota {
                por_minuto: 60,
                rafaga: 2,
            },
            AHORA,
        );
        l.reservar("rep", AHORA).expect("hay").gastado();
        l.reservar("rep", AHORA).expect("hay").gastado();
        let _ = l.reservar("rep", AHORA);
        assert_eq!(l.cuentas("rep"), Some((2, 1)));
    }

    #[test]
    fn la_rafaga_por_defecto_es_un_cuarto_y_nunca_cero() {
        // Sin rafaga, enriquecer un caso con veinte observables tarda veinte veces
        // el intervalo y el analista se va.
        assert_eq!(Cuota::por_minuto(60).rafaga, 15);
        assert_eq!(Cuota::por_minuto(1).rafaga, 1);
        assert_eq!(Cuota::por_minuto(4).intervalo_ns(), 15 * SEG);
    }
}
