//! La pizarra: estado difundido a todos los canales de suscripcion.
//!
//! # Por que existe esto y no un canal de tokio
//!
//! El transporte de flota es UN HILO DEL SISTEMA POR CONEXION: el listener
//! acepta y entrega la conexion a un hilo que bloquea. Los diez mil canales de
//! una flota grande son, literalmente, diez mil hilos parados.
//!
//! Esperar ahi con `tokio::sync::watch` obliga a cada hilo a entrar en el
//! runtime en CADA vuelta de su bucle para inscribirse en dos esperas y armar un
//! temporizador de keepalive. Con diez mil hilos eso son, por cada orden
//! difundida, veinte mil inscripciones, diez mil altas y diez mil bajas en la
//! rueda de temporizadores —que los hilos ajenos al runtime comparten— y diez
//! mil despertares individuales. Todo ese trabajo lo hace el que publica, en
//! serie, mientras los endpoints esperan.
//!
//! Medido con diez mil canales sobre esta maquina de cuatro nucleos: la orden
//! tardaba 365 ms en estar en el cable para el ultimo endpoint, con la maquina a
//! la mitad de su capacidad. No faltaba CPU: sobraba serializacion.
//!
//! Un cerrojo y una variable de condicion son la primitiva que corresponde a
//! diez mil hilos bloqueados. `notify_all` es UNA llamada al sistema que despacha
//! a todos los que esperan, no diez mil llamadas; no hay temporizadores que dar
//! de alta, porque la espera con plazo es la propia `wait_timeout_while`; y no
//! hay inscripciones que rehacer, porque no hay nada en que inscribirse.
//!
//! # Por que la condicion es de CONTENIDO y no de "me han avisado"
//!
//! Un canal esta escribiendo el empuje anterior justo cuando llega la orden. Si
//! la condicion fuera "ha habido un aviso desde que empece a esperar", ese canal
//! se quedaria sin la orden hasta el siguiente cambio, que puede no llegar nunca.
//! La condicion es "hay algo que este canal todavia no ha atendido", que no
//! depende de si estaba mirando; y se evalua bajo el cerrojo, asi que ni se
//! pierde un cambio ni se despierta de mas.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::notificador::Aviso;

/// La lista de cuarentena vigente, con la generacion que la produjo.
///
/// La generacion no es contabilidad decorativa: es lo que permite atribuir cada
/// escritura en un socket a la orden concreta que la provoco. Sin ella, dos
/// ordenes seguidas mezclarian sus tiempos y la medicion diria algo que no es.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ListaCuarentena {
    /// Direcciones vigentes, separadas por comas, tal cual viajan al agente.
    pub lista: String,
    /// Numero de orden de esta lista. Empieza en cero (estado inicial).
    pub gen: u64,
}

/// Lo que la pizarra publica a todos los canales.
#[derive(Debug, Clone, Default)]
pub struct EstadoDifundido {
    /// Ultimo aviso de politica o caceria.
    pub aviso: Aviso,
    /// Lista de cuarentena vigente.
    pub cuarentena: Arc<ListaCuarentena>,
}

/// Lo que un canal concreto YA ha atendido.
///
/// Se construye desde el estado del canal en cada vuelta; no vive en la pizarra,
/// porque es distinto para cada uno de los diez mil.
#[derive(Debug, Clone, Copy)]
pub struct Atendido<'a> {
    /// Generacion de aviso de politica ya atendida.
    pub gen_politica: u64,
    /// Generacion de aviso de caceria ya atendida.
    pub gen_caza: u64,
    /// Cuarentena ya entregada, o `None` si no se le ha dicho nada todavia.
    ///
    /// `None` NO es lo mismo que `Some("")`: lo primero es "no sabe nada de
    /// cuarentena" y lo segundo "sabe que no hay ninguna". Confundirlos deja a un
    /// endpoint que reconecta sin la contencion en vigor, o reenvia la lista
    /// entera a diez mil endpoints en cada latido.
    pub cuarentena: Option<&'a str>,
}

impl Atendido<'_> {
    /// Si no queda nada por atender en `e`.
    fn al_dia_con(&self, e: &EstadoDifundido) -> bool {
        e.aviso.gen_politica <= self.gen_politica
            && e.aviso.gen_caza <= self.gen_caza
            && self.cuarentena == Some(e.cuarentena.lista.as_str())
    }
}

/// Estado difundido a todos los canales de suscripcion.
#[derive(Debug, Default)]
pub struct Pizarra {
    estado: Mutex<EstadoDifundido>,
    cambio: Condvar,
}

impl Pizarra {
    /// Lee el estado vigente sin esperar.
    pub fn leer(&self) -> EstadoDifundido {
        self.estado
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Publica un aviso de politica o caceria.
    pub fn publicar_aviso(&self, aviso: Aviso) {
        let mut g = self.estado.lock().unwrap_or_else(|e| e.into_inner());
        g.aviso = aviso;
        drop(g);
        self.cambio.notify_all();
    }

    /// Publica una lista de cuarentena nueva.
    pub fn publicar_cuarentena(&self, lista: Arc<ListaCuarentena>) {
        let mut g = self.estado.lock().unwrap_or_else(|e| e.into_inner());
        g.cuarentena = lista;
        drop(g);
        self.cambio.notify_all();
    }

    /// Espera hasta que haya algo que `atendido` no haya atendido.
    ///
    /// Devuelve `None` si vencio el plazo sin novedad, que es lo que provoca el
    /// latido del canal: sin el, un canal sano y uno muerto serian
    /// indistinguibles para los dos extremos.
    pub fn esperar(&self, atendido: Atendido<'_>, plazo: Duration) -> Option<EstadoDifundido> {
        let g = self.estado.lock().unwrap_or_else(|e| e.into_inner());
        // La comprobacion va ANTES de dormir y bajo el mismo cerrojo que usa
        // quien publica: un cambio ocurrido mientras este canal escribia el
        // empuje anterior se ve aqui, no se pierde.
        if !atendido.al_dia_con(&g) {
            return Some(g.clone());
        }
        let (g, resultado) = self
            .cambio
            .wait_timeout_while(g, plazo, |e| atendido.al_dia_con(e))
            .unwrap_or_else(|e| e.into_inner());
        if resultado.timed_out() {
            None
        } else {
            Some(g.clone())
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn atendido<'a>(gp: u64, gc: u64, cua: Option<&'a str>) -> Atendido<'a> {
        Atendido {
            gen_politica: gp,
            gen_caza: gc,
            cuarentena: cua,
        }
    }

    #[test]
    fn un_canal_que_no_sabe_nada_de_cuarentena_no_esta_al_dia() {
        // `None` es "no se le ha dicho nada", no "no hay ninguna". Tratarlos
        // igual deja a un endpoint que reconecta sin la contencion en vigor.
        let p = Pizarra::default();
        assert!(p.esperar(atendido(0, 0, None), Duration::ZERO).is_some());
        assert!(p
            .esperar(atendido(0, 0, Some("")), Duration::ZERO)
            .is_none());
    }

    #[test]
    fn una_cuarentena_publicada_mientras_el_canal_escribia_no_se_pierde() {
        // El caso que la version con canales de notificacion perdia: el cambio
        // ocurre cuando este canal NO esta esperando. Al volver, tiene que verlo
        // igualmente, porque la condicion es de contenido y no "me han avisado".
        let p = Pizarra::default();
        p.publicar_cuarentena(Arc::new(ListaCuarentena {
            lista: "10.0.0.5".to_string(),
            gen: 1,
        }));
        let e = p
            .esperar(atendido(0, 0, Some("")), Duration::ZERO)
            .expect("el canal tiene que ver la cuarentena que se publico sin el delante");
        assert_eq!(e.cuarentena.lista, "10.0.0.5");
    }

    #[test]
    fn un_canal_al_dia_espera_y_devuelve_el_latido() {
        let p = Pizarra::default();
        let inicio = std::time::Instant::now();
        assert!(p
            .esperar(atendido(0, 0, Some("")), Duration::from_millis(80))
            .is_none());
        assert!(
            inicio.elapsed() >= Duration::from_millis(70),
            "un canal al dia tiene que DORMIR hasta el latido, no girar en vacio"
        );
    }

    #[test]
    fn una_publicacion_despierta_a_todos_los_que_esperan() {
        // Es la propiedad de la que depende la difusion: una sola publicacion
        // despierta a los diez mil, no uno a uno.
        let p = Arc::new(Pizarra::default());
        let mut hilos = Vec::new();
        for _ in 0..64 {
            let p = p.clone();
            hilos.push(std::thread::spawn(move || {
                p.esperar(atendido(0, 0, Some("")), Duration::from_secs(10))
                    .is_some()
            }));
        }
        // Se da tiempo a que todos esten dentro de la espera.
        std::thread::sleep(Duration::from_millis(200));
        p.publicar_cuarentena(Arc::new(ListaCuarentena {
            lista: "203.0.113.7".to_string(),
            gen: 1,
        }));
        for h in hilos {
            assert!(h.join().unwrap(), "un canal se quedo sin la orden");
        }
    }

    #[test]
    fn una_caceria_atendida_no_vuelve_a_despertar_al_canal() {
        // Sin esta comparacion, el canal veia la caceria pendiente, la empujaba,
        // volvia a mirar, la seguia viendo, y la empujaba otra vez: un bucle
        // cerrado entre el canal y un agente que aun no ha contestado.
        let p = Pizarra::default();
        p.publicar_aviso(Aviso {
            gen_caza: 3,
            ..Default::default()
        });
        assert!(p
            .esperar(atendido(0, 3, Some("")), Duration::ZERO)
            .is_none());
        assert!(p
            .esperar(atendido(0, 2, Some("")), Duration::ZERO)
            .is_some());
    }
}
