//! El cambio de integridad CON AUTOR: quien lo hizo, capturado en el kernel.
//!
//! # La diferencia de categoria con inotify
//!
//! `inotify` —lo que usan Wazuh FIM, y lo que usaba `aegis-fim`— dice «este
//! fichero cambio». No dice quien. Para saberlo hay que ir a `/proc` DESPUES del
//! evento, y para entonces el atacante ya reciclo el PID o cerro el proceso: eso
//! es la carrera TOCTOU que la invariante 9 prohibe.
//!
//! Aqui el cambio nace de un [`aegis_sensor::Evento`] del gancho LSM (FASE 103),
//! donde el kernel YA resolvio el objeto y tiene delante la tarea que lo toca. El
//! autor —el proceso, sus credenciales y su LINAJE— se captura EN ESE INSTANTE y
//! viaja dentro del tipo. No hay ninguna operacion que vuelva a leer el sistema:
//! lo que el analisis necesita esta en el cambio, o no esta y se dice.

use aegis_entidad::Eid;
use aegis_sensor::Evento;

/// Las credenciales del autor de un cambio, capturadas en el instante del evento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credenciales {
    /// UID real.
    pub uid: u32,
    /// GID real.
    pub gid: u32,
    /// UID efectivo. Difiere del real tras un `setuid`; la diferencia es en si
    /// misma una senal (un proceso que escalo privilegios antes de tocar el
    /// fichero).
    pub euid: u32,
}

impl Credenciales {
    /// Credenciales de root real (uid 0).
    #[must_use]
    pub fn root() -> Credenciales {
        Credenciales {
            uid: 0,
            gid: 0,
            euid: 0,
        }
    }

    /// Si el proceso escalo privilegios (euid distinto del uid real).
    #[must_use]
    pub fn escalo(&self) -> bool {
        self.uid != self.euid
    }
}

/// El autor de un cambio: el proceso, sus credenciales y su LINAJE.
///
/// El linaje —la cadena de ancestros hacia la raiz— es lo que convierte «se
/// cambio `authorized_keys`» en «lo cambio un shell descendiente del proceso del
/// servidor web», que es la diferencia entre una alerta accionable y un aviso que
/// no dice nada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Autor {
    /// El proceso que hizo el cambio.
    pub proceso: Eid,
    /// Sus credenciales en el instante del cambio, si se capturaron. `None` se
    /// dice como tal: un uid inventado se leeria como un uid.
    pub credenciales: Option<Credenciales>,
    /// Los ancestros, del padre hacia la raiz. Vacio si no se pudo reconstruir la
    /// cadena (y entonces se dice, no se inventa).
    pub linaje: Vec<Eid>,
}

impl Autor {
    /// Construye un autor.
    #[must_use]
    pub fn nuevo(proceso: Eid, credenciales: Credenciales, linaje: Vec<Eid>) -> Autor {
        Autor {
            proceso,
            credenciales: Some(credenciales),
            linaje,
        }
    }

    /// Un autor del que no se pudieron capturar las credenciales.
    #[must_use]
    pub fn sin_credenciales(proceso: Eid, linaje: Vec<Eid>) -> Autor {
        Autor {
            proceso,
            credenciales: None,
            linaje,
        }
    }

    /// Si algun eslabon del linaje es el proceso dado (p. ej. el servidor web).
    /// Es la consulta que responde «¿esto desciende de un servicio expuesto?».
    #[must_use]
    pub fn desciende_de(&self, ancestro: &Eid) -> bool {
        self.linaje.iter().any(|e| e == ancestro)
    }
}

/// Un cambio de integridad con su autor, nacido de un evento del kernel.
///
/// Todos sus campos se fijaron en el gancho LSM en el instante del cambio. No hay
/// forma de re-leer el sistema desde aqui: lo que hay es lo que se capturo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CambioConAutor {
    /// El objeto cambiado, del modelo unico (derivado en el kernel).
    pub objetivo: Eid,
    /// La ruta completa RESUELTA en el kernel, si la hay. Es la del instante del
    /// cambio, no la de ahora: si el fichero se renombro despues, esto sigue
    /// siendo la ruta que se toco.
    ruta_capturada: Option<String>,
    /// Quien lo hizo.
    pub autor: Autor,
    /// Cuando, en nanosegundos monotonos del kernel.
    pub cuando_ns: u64,
}

impl CambioConAutor {
    /// Nace de un evento del sensor (gancho LSM de la FASE 103) mas el autor
    /// capturado en ese mismo instante. El objetivo y la ruta salen del evento,
    /// que ya los resolvio el kernel; **no se relee nada**.
    #[must_use]
    pub fn desde_evento(evento: &Evento, autor: Autor) -> CambioConAutor {
        CambioConAutor {
            objetivo: evento.entidad.clone(),
            ruta_capturada: evento.ruta().map(str::to_string),
            autor,
            cuando_ns: evento.cuando_ns,
        }
    }

    /// Nace de una captura que no es un evento del sensor —la telemetria de
    /// ficheros de las sondas del agente—, con los mismos campos: el objeto
    /// cambiado, su ruta tal y como se capturo, el autor y el instante.
    #[must_use]
    pub fn nuevo(
        objetivo: Eid,
        ruta: Option<String>,
        autor: Autor,
        cuando_ns: u64,
    ) -> CambioConAutor {
        CambioConAutor {
            objetivo,
            ruta_capturada: ruta,
            autor,
            cuando_ns,
        }
    }

    /// La ruta capturada en el kernel. **No relee el disco**.
    #[must_use]
    pub fn ruta(&self) -> Option<&str> {
        self.ruta_capturada.as_deref()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::entidad;
    use aegis_sensor::Familia;

    fn maquina_test() -> Eid {
        entidad::maquina("m-1")
    }

    fn proc(pid: u32) -> Eid {
        entidad::proceso(&maquina_test(), 0, pid, 0)
    }

    #[test]
    fn el_cambio_lleva_a_su_autor_no_solo_el_hecho() {
        // inotify daria solo la ruta; aqui el cambio dice QUIEN, con que
        // credenciales y de quien desciende.
        let evento = Evento::nuevo(
            Familia::Fichero,
            entidad::ubicacion(&maquina_test(), "/root/.ssh/authorized_keys"),
            Some("/root/.ssh/authorized_keys".to_string()),
            vec!["O_WRONLY".to_string()],
            5_000,
        );
        let autor = Autor::nuevo(
            proc(4099),
            Credenciales::root(),
            vec![proc(4090), proc(1200)],
        );
        let cambio = CambioConAutor::desde_evento(&evento, autor);
        assert_eq!(cambio.ruta(), Some("/root/.ssh/authorized_keys"));
        // La pregunta que importa: ¿esto desciende del servidor web expuesto (1200)?
        assert!(cambio.autor.desciende_de(&proc(1200)));
        assert!(!cambio.autor.desciende_de(&proc(900)));
    }

    #[test]
    fn conserva_la_ruta_del_instante_aunque_el_mundo_cambie() {
        // TOCTOU: el objetivo y la ruta son los del instante del cambio. Que
        // "el sistema" cambie despues no altera lo que el evento capturo.
        let evento = Evento::nuevo(
            Familia::Fichero,
            entidad::ubicacion(&maquina_test(), "/etc/sudoers"),
            Some("/etc/sudoers".to_string()),
            vec![],
            10,
        );
        let autor = Autor::nuevo(proc(77), Credenciales::root(), vec![]);
        let cambio = CambioConAutor::desde_evento(&evento, autor);
        assert_eq!(cambio.ruta(), Some("/etc/sudoers"));
        assert_eq!(cambio.cuando_ns, 10);
    }

    #[test]
    fn la_escalada_de_privilegios_se_ve_en_las_credenciales() {
        let c = Credenciales {
            uid: 1000,
            gid: 1000,
            euid: 0,
        };
        assert!(c.escalo(), "uid 1000 con euid 0 escalo");
        assert!(!Credenciales::root().escalo());
    }
}
