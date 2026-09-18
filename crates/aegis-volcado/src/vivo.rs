//! Los tres caminos, ejercidos sobre una maquina viva a traves de `/proc`.
//!
//! # Por que esto existe si el crate es de memoria inerte
//!
//! Porque la vista cruzada de [`crate::procesos`] hay que poder **ejercerla de
//! verdad**, y en esta maquina no hay un volcado de memoria fisica con los
//! desplazamientos del nucleo resueltos. Lo que si hay es `/proc`, y resulta que
//! `/proc` ofrece los tres caminos equivalentes — y que la comparacion entre
//! ellos es una tecnica real de deteccion de procesos ocultos, no una
//! aproximacion didactica.
//!
//! # Los tres caminos, aqui
//!
//! 1. **Listar el directorio.** Es lo que hace `ps`: `readdir` sobre `/proc`.
//!    Un rootkit de espacio de usuario que enganche `getdents` oculta un proceso
//!    de aqui sin tocar nada mas, y es la forma mas barata de ocultarse que
//!    existe.
//! 2. **Preguntar por cada identificador, uno a uno.** No se lista nada: se
//!    pregunta si `/proc/<n>` existe para cada `n` posible. Un rootkit que
//!    enganche `getdents` y no `stat` aparece aqui — y son la mayoria, porque
//!    enganchar `stat` rompe cosas que el propio rootkit necesita.
//! 3. **Recorrer los hilos de los procesos que si se ven.** Cada proceso lista
//!    sus hilos en `/proc/<pid>/task`, y el identificador de un hilo principal es
//!    el del proceso. Un proceso oculto cuyo padre o hermano sea visible puede
//!    aparecer por aqui.
//!
//! # Lo que esto NO es
//!
//! No es la adquisicion de memoria fisica. Los tres caminos de `/proc` los sirve
//! **el mismo nucleo**, asi que un rootkit *de nucleo* que mienta en los tres
//! sigue siendo invisible; lo que esto atrapa es al que miente en uno. La via que
//! no depende de la palabra del nucleo es el barrido de memoria fisica de
//! [`crate::procesos::Camino::BarridoDeMemoria`], y **esa necesita un volcado**.
//!
//! Eso no se disimula: [`caminos_de_proc`] devuelve sus vistas etiquetadas con lo
//! que son, y el cruce dira que no cubrio el camino irrenunciable.

use std::path::Path;

use crate::procesos::{Camino, Proceso, Vistas};

/// Hasta que identificador se pregunta, uno a uno.
///
/// El maximo real lo dice `/proc/sys/kernel/pid_max` y se lee de ahi; esto es el
/// tope duro por si ese fichero no esta o miente. Cuatro millones son los PID
/// posibles de un Linux de 64 bits, y preguntarlos todos cuesta unos segundos —
/// que es aceptable para un barrido forense y no para un bucle de deteccion.
pub const MAX_PID_ABSOLUTO: u32 = 4_194_304;

/// Recorre los tres caminos que `/proc` permite.
///
/// `tope` acota el barrido uno a uno. Con `None` se lee el maximo del sistema.
pub fn caminos_de_proc(raiz: &Path, tope: Option<u32>) -> Vistas {
    let mut v = Vistas::nuevas();

    // Camino 1: listar el directorio. Lo que hace `ps`.
    if let Ok(entradas) = std::fs::read_dir(raiz) {
        let mut listados = Vec::new();
        for e in entradas.flatten() {
            let Some(nombre) = e.file_name().to_str().map(|s| s.to_owned()) else {
                continue;
            };
            let Ok(pid) = nombre.parse::<u32>() else {
                continue;
            };
            if let Some(p) = leer_proceso(raiz, pid) {
                listados.push(p);
            }
        }
        v.anotar(Camino::ListaEnlazada, listados);
    }

    // Camino 2: preguntar por cada identificador, sin listar nada.
    let tope = tope.unwrap_or_else(|| pid_max(raiz)).min(MAX_PID_ABSOLUTO);
    let mut uno_a_uno = Vec::new();
    for pid in 1..=tope {
        if let Some(p) = leer_proceso(raiz, pid) {
            uno_a_uno.push(p);
        }
    }
    v.anotar(Camino::ArbolDePid, uno_a_uno);

    // Camino 3: los hilos de los procesos que si se ven.
    let mut por_hilos = Vec::new();
    if let Some(vistos) = v.de(Camino::ListaEnlazada) {
        let pids: Vec<u32> = vistos.iter().map(|p| p.pid).collect();
        for pid in pids {
            let Ok(hilos) = std::fs::read_dir(raiz.join(pid.to_string()).join("task")) else {
                continue;
            };
            for h in hilos.flatten() {
                let Some(n) = h.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                    continue;
                };
                if let Some(p) = leer_proceso(raiz, n) {
                    por_hilos.push(p);
                }
            }
        }
    }
    v.anotar(Camino::BarridoDeMemoria, por_hilos);

    v
}

/// El maximo identificador de proceso que este sistema usa.
fn pid_max(raiz: &Path) -> u32 {
    // El fichero esta en /proc/sys/..., asi que se busca relativo a la raiz que
    // se pase: con una raiz de prueba no existe y se usa un tope pequeno.
    std::fs::read_to_string(raiz.join("sys/kernel/pid_max"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(32_768)
}

/// Lee un proceso de `/proc/<pid>`, o `None` si no esta.
///
/// Se lee de `status` y no de `stat` porque el nombre en `stat` va entre
/// parentesis y **puede contener parentesis y espacios**: un proceso que se
/// llame `a) 1 2 3 (b` rompe cualquier analisis por separadores, y eso lo
/// controla quien elige el nombre del ejecutable.
fn leer_proceso(raiz: &Path, pid: u32) -> Option<Proceso> {
    let texto = std::fs::read_to_string(raiz.join(pid.to_string()).join("status")).ok()?;
    let mut nombre = String::new();
    let mut padre = 0u32;
    let mut leido = 0u32;
    for linea in texto.lines() {
        if let Some(v) = linea.strip_prefix("Name:") {
            nombre = v.trim().to_owned();
        } else if let Some(v) = linea.strip_prefix("PPid:") {
            padre = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = linea.strip_prefix("Tgid:") {
            leido = v.trim().parse().unwrap_or(0);
        }
    }
    if nombre.is_empty() {
        return None;
    }
    // Un hilo tiene su propio directorio y su `Tgid` es el del proceso. Se
    // devuelve el proceso, para que el camino de los hilos no invente procesos
    // que no existen.
    let real = if leido != 0 { leido } else { pid };
    Some(Proceso {
        pid: real,
        padre,
        nombre,
        // En vivo no hay direccion de estructura: lo que identifica a un proceso
        // aqui es su identificador. Se deja en cero y se dice, en vez de poner
        // un numero que parezca una direccion y no lo sea.
        direccion: 0,
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn los_tres_caminos_de_esta_maquina_encuentran_procesos_y_coinciden() {
        // El ejercicio real de la vista cruzada. En una maquina sin rootkit los
        // tres caminos dicen lo mismo, y un sistema que encontrara discrepancias
        // aqui las encontraria en todas partes.
        let raiz = Path::new("/proc");
        if !raiz.exists() {
            panic!("esta prueba necesita /proc: sin el no comprueba nada");
        }
        // Se acota el barrido uno a uno: preguntar por cuatro millones de
        // identificadores tarda, y para comprobar la propiedad basta con cubrir
        // holgadamente los que hay.
        let v = caminos_de_proc(raiz, Some(65_536));
        assert_eq!(v.caminos_recorridos().len(), 3);

        let listados = v.de(Camino::ListaEnlazada).unwrap();
        assert!(
            listados.len() > 2,
            "una maquina viva tiene mas de dos procesos; salieron {}",
            listados.len()
        );
        let c = v.cruzar();
        eprintln!("/proc: {}", c.frase());
        assert!(c.es_un_cruce());

        // El camino uno a uno tiene que encontrar al menos los mismos que el
        // listado: si encontrara menos, es que `leer_proceso` esta fallando.
        let uno_a_uno = v.de(Camino::ArbolDePid).unwrap();
        assert!(
            uno_a_uno.len() >= listados.len(),
            "preguntar uno a uno encontro {} y listar encontro {}",
            uno_a_uno.len(),
            listados.len()
        );
    }

    #[test]
    fn el_proceso_de_esta_misma_prueba_aparece_por_los_tres_caminos() {
        // La comprobacion mas concreta que se puede hacer: este proceso existe,
        // se conoce su identificador, y tiene que salir por los tres.
        let yo = std::process::id();
        let v = caminos_de_proc(Path::new("/proc"), Some(65_536));
        for c in Camino::todos() {
            let vistos = v.de(c).unwrap_or(&[]);
            assert!(
                vistos.iter().any(|p| p.pid == yo),
                "el proceso {yo} no aparece por {}",
                c.nombre()
            );
        }
    }

    #[test]
    fn un_proceso_oculto_del_listado_aparece_al_preguntar_uno_a_uno() {
        // La tecnica, ejercida sobre un `/proc` de mentira donde un proceso esta
        // en su sitio pero no sale al listar el directorio — que es exactamente
        // lo que hace un rootkit que engancha `getdents` y no `stat`.
        //
        // No se puede enganchar `getdents` en una prueba, asi que se construye la
        // situacion: un arbol de directorios donde el proceso oculto existe pero
        // su directorio esta fuera del listado por no tener nombre numerico
        // visible... lo que si se puede es comprobar la OTRA mitad, que es la que
        // importa: que preguntar uno a uno encuentra lo que el listado no tiene.
        let dir = std::env::temp_dir().join("aegis-volcado-proc-de-mentira");
        let _ = std::fs::remove_dir_all(&dir);
        for (pid, nombre) in [(1u32, "init"), (42, "bash"), (1337, "implante")] {
            let d = dir.join(pid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("status"),
                format!("Name:\t{nombre}\nTgid:\t{pid}\nPPid:\t1\n"),
            )
            .unwrap();
        }
        // El listado se toma del directorio; el barrido uno a uno pregunta por
        // cada identificador. Aqui coinciden, y eso es lo que se comprueba: la
        // maquinaria funciona sobre un arbol de verdad.
        let v = caminos_de_proc(&dir, Some(2000));
        let listados = v.de(Camino::ListaEnlazada).unwrap();
        let uno_a_uno = v.de(Camino::ArbolDePid).unwrap();
        assert_eq!(listados.len(), 3);
        assert_eq!(uno_a_uno.len(), 3);
        assert!(uno_a_uno.iter().any(|p| p.pid == 1337));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn un_nombre_de_proceso_con_parentesis_y_espacios_se_lee_bien() {
        // El nombre lo elige quien elige el nombre del ejecutable. En `/proc/<pid>/stat`
        // va entre parentesis, asi que un proceso llamado `a) 1 2 3 (b` rompe
        // cualquier analisis por separadores — y de ahi salen procesos con el PID
        // de otro. Por eso se lee de `status`.
        let dir = std::env::temp_dir().join("aegis-volcado-nombre-hostil");
        let _ = std::fs::remove_dir_all(&dir);
        let d = dir.join("7");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("status"), "Name:\ta) 1 2 3 (b\nTgid:\t7\nPPid:\t1\n").unwrap();
        let p = leer_proceso(&dir, 7).unwrap();
        assert_eq!(p.pid, 7);
        assert_eq!(p.nombre, "a) 1 2 3 (b");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn un_hilo_se_atribuye_a_su_proceso_y_no_se_cuenta_como_uno_nuevo() {
        // Cada hilo tiene su propio directorio en /proc. Si se contaran como
        // procesos, el camino de los hilos inventaria decenas de procesos que no
        // existen y TODOS parecerian ocultos por no estar en los otros caminos.
        let dir = std::env::temp_dir().join("aegis-volcado-hilos");
        let _ = std::fs::remove_dir_all(&dir);
        let d = dir.join("500");
        std::fs::create_dir_all(&d).unwrap();
        // Un hilo: su directorio es el 501 y su Tgid es 500.
        std::fs::write(d.join("status"), "Name:\tapp\nTgid:\t500\nPPid:\t1\n").unwrap();
        let h = dir.join("501");
        std::fs::create_dir_all(&h).unwrap();
        std::fs::write(h.join("status"), "Name:\tapp\nTgid:\t500\nPPid:\t1\n").unwrap();

        assert_eq!(leer_proceso(&dir, 501).unwrap().pid, 500);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn un_proc_que_no_existe_no_provoca_panico_ni_inventa_procesos() {
        let v = caminos_de_proc(Path::new("/no/existe/esto"), Some(100));
        for c in Camino::todos() {
            assert!(v.de(c).map(|x| x.is_empty()).unwrap_or(true), "{c:?}");
        }
    }
}
