//! Ejecucion en baja prioridad de la sincronizacion.
//!
//! La sincronizacion de threat intel no es urgente: puede tardar segundos o
//! minutos sin que pase nada. Lo que NO puede es robarle CPU a la deteccion. Se
//! ejecuta en un hilo con la prioridad rebajada (`nice`), de modo que el
//! planificador se la quite en cuanto la deteccion o cualquier otra cosa la
//! necesite.

/// Rebaja la prioridad del HILO actual al valor `nice` indicado.
///
/// En Linux, `setpriority(PRIO_PROCESS, 0, nice)` sobre un hilo afecta solo a
/// ese hilo (no a todo el proceso), que es lo que se quiere: el hilo de
/// sincronizacion cede, el resto del agente no. Un proceso sin privilegios solo
/// puede SUBIR el nice (rebajar su prioridad), que es justo la direccion segura.
///
/// Devuelve `true` si se aplico. Un fallo no es critico: la sincronizacion
/// seguira funcionando, solo que sin la deferencia de prioridad.
pub fn rebajar_prioridad(nice: i32) -> bool {
    // El nice valido va de -20 (mas prioridad) a 19 (menos). Se acota a la
    // mitad baja: subir la prioridad requeriria privilegios y no es lo que se
    // busca.
    let nice = nice.clamp(1, 19);
    // SAFETY: setpriority con PRIO_PROCESS y who=0 actua sobre el hilo llamante
    // en Linux; no toca memoria de este proceso.
    let r = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) };
    r == 0
}

/// Ejecuta `f` en un hilo nuevo de baja prioridad y devuelve su manejador.
///
/// Es la forma recomendada de lanzar una sincronizacion: no bloquea al que
/// llama, y el hilo cede la CPU a la deteccion por su `nice`.
pub fn en_hilo_baja_prioridad<F, T>(nice: i32, f: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        rebajar_prioridad(nice);
        f()
    })
}
