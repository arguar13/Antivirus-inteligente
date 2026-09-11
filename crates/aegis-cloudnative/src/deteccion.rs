//! El decisor: de un evento de syscall a un patron de escape de contenedor.
//!
//! Es la parte que puede estar MAL de forma peligrosa —de menos, un escape pasa;
//! de mas, se marca una operacion legitima de orquestacion—, asi que es Rust puro
//! y se prueba entera con secuencias reales de escape, cero mocks. Enganchar las
//! syscalls con eBPF es el muro (necesita kernel); ESTO no lo necesita.
//!
//! # Que se detecta (patrones de Deepce / Traitor y companyia)
//!
//! El hilo comun de casi todo escape de contenedor es: desde DENTRO del
//! contenedor, conseguir que se ejecute algo EN EL HOST, o alcanzar los recursos
//! del host. Los caminos conocidos:
//!
//! - Escribir el `release_agent` de un cgroup v1, `core_pattern` o `modprobe`:
//!   el kernel ejecuta ese programa en el host. Ejecucion directa: **critico**.
//! - Montar el disco del host (`mount` de un dispositivo de bloque del anfitrion)
//!   dentro del contenedor. Acceso total al host: **critico**.
//! - `setns` a un namespace del host (p. ej. el del PID 1): salir del contenedor
//!   por la puerta de los namespaces.
//! - Cargar eBPF (`bpf`) desde un contenedor: casi nunca es legitimo y da lectura
//!   /escritura del kernel.
//! - La secuencia clasica `unshare(CLONE_NEWUSER)` y luego `mount`: crear un
//!   namespace de usuario para ganar capacidades y montar. Es multi-paso, y por
//!   eso el decisor guarda un poco de estado por proceso.
//!
//! Todo esto solo cuenta como escape si pasa DENTRO de un contenedor: las mismas
//! syscalls en el host son la orquestacion normal (Docker, systemd, runc) y no se
//! tocan.

use std::collections::HashMap;

use crate::eventos::{EventoNucleo, Operacion, RutaSensible, CLONE_NEWUSER};

/// La gravedad de una deteccion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severidad {
    /// Sospechoso: vigilar.
    Media,
    /// Un precursor claro de escape.
    Alta,
    /// Ejecucion en el host o acceso total: escape en curso.
    Critica,
}

/// El patron de escape reconocido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatronEscape {
    /// Escritura del `release_agent` de un cgroup v1.
    ReleaseAgentCgroup,
    /// Escritura de `/proc/sys/kernel/core_pattern`.
    CorePattern,
    /// Reescritura de `/proc/sys/kernel/modprobe`.
    ModprobeReescrito,
    /// Montaje de un dispositivo de bloque del host dentro del contenedor.
    MontajeDiscoHost,
    /// `setns` a un namespace del host desde el contenedor.
    SetnsAlHost,
    /// Carga de eBPF desde un contenedor.
    BpfEnContenedor,
    /// Secuencia `unshare(CLONE_NEWUSER)` seguida de `mount`.
    UserNsYMontaje,
}

/// Una deteccion de escape: el patron, su gravedad, el proceso y por que.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeteccionEscape {
    /// El patron reconocido.
    pub patron: PatronEscape,
    /// La gravedad.
    pub severidad: Severidad,
    /// El proceso implicado.
    pub pid: u32,
    /// Una explicacion legible para el analista.
    pub explicacion: &'static str,
}

/// Lo que se recuerda de un proceso entre eventos, para los patrones multi-paso.
#[derive(Debug, Clone, Copy, Default)]
struct EstadoProceso {
    /// El proceso creo un namespace de usuario (`unshare(CLONE_NEWUSER)`).
    creo_userns: bool,
}

/// El monitor de escape: examina cada evento y guarda el poco estado por proceso
/// que hace falta para los escapes que ocurren en varios pasos.
#[derive(Debug, Default)]
pub struct MonitorEscape {
    estado: HashMap<u32, EstadoProceso>,
}

impl MonitorEscape {
    /// Un monitor nuevo, sin estado.
    #[must_use]
    pub fn nuevo() -> Self {
        Self {
            estado: HashMap::new(),
        }
    }

    /// Examina un evento y decide si delata un escape de contenedor.
    ///
    /// Solo se consideran las operaciones que ocurren DENTRO de un contenedor: las
    /// mismas syscalls en el host son orquestacion legitima.
    pub fn analizar(&mut self, ev: &EventoNucleo) -> Option<DeteccionEscape> {
        // Fuera de un contenedor no hay "escape de contenedor" que detectar.
        if !ev.ctx.en_contenedor {
            return None;
        }
        let pid = ev.ctx.pid;

        match ev.operacion {
            Operacion::Escritura => self.por_escritura(ev),
            Operacion::Montar => self.por_montaje(ev),
            Operacion::Setns if ev.destino_ns_host() => Some(DeteccionEscape {
                patron: PatronEscape::SetnsAlHost,
                severidad: Severidad::Alta,
                pid,
                explicacion:
                    "setns a un namespace del host desde el contenedor: salida por namespaces",
            }),
            Operacion::Bpf => Some(DeteccionEscape {
                patron: PatronEscape::BpfEnContenedor,
                severidad: Severidad::Alta,
                pid,
                explicacion:
                    "carga de eBPF desde un contenedor: acceso al kernel, casi nunca legitimo",
            }),
            Operacion::Unshare => {
                // Crear un namespace de usuario arma el patron multi-paso, pero no
                // es concluyente por si solo (a veces es legitimo).
                if ev.flags & CLONE_NEWUSER != 0 {
                    self.estado.entry(pid).or_default().creo_userns = true;
                }
                None
            }
            // Setns que no apunta al host, o capset: se observan, no se marcan
            // solos (evitar falsos positivos). El contrato los soporta para el
            // futuro.
            Operacion::Setns | Operacion::Capset => None,
        }
    }

    /// Olvida el estado de un proceso que termino.
    pub fn olvidar(&mut self, pid: u32) {
        self.estado.remove(&pid);
    }

    fn por_escritura(&self, ev: &EventoNucleo) -> Option<DeteccionEscape> {
        let (patron, explicacion) = match ev.ruta {
            RutaSensible::ReleaseAgentCgroup => (
                PatronEscape::ReleaseAgentCgroup,
                "escritura del release_agent de un cgroup: el kernel ejecutara ese programa en el host",
            ),
            RutaSensible::CorePattern => (
                PatronEscape::CorePattern,
                "escritura de core_pattern: un core dump ejecutara el programa en el host",
            ),
            RutaSensible::Modprobe => (
                PatronEscape::ModprobeReescrito,
                "reescritura de modprobe: el kernel ejecutara ese binario en el host al cargar un modulo",
            ),
            RutaSensible::Ninguna => return None,
        };
        Some(DeteccionEscape {
            patron,
            severidad: Severidad::Critica,
            pid: ev.ctx.pid,
            explicacion,
        })
    }

    fn por_montaje(&mut self, ev: &EventoNucleo) -> Option<DeteccionEscape> {
        let pid = ev.ctx.pid;
        // Montar el disco del host es acceso total: critico, sin mas.
        if ev.montaje_dispositivo_host() {
            return Some(DeteccionEscape {
                patron: PatronEscape::MontajeDiscoHost,
                severidad: Severidad::Critica,
                pid,
                explicacion: "montaje de un dispositivo de bloque del host dentro del contenedor",
            });
        }
        // Montar tras haber creado un namespace de usuario es la secuencia clasica
        // de Deepce/Traitor: ganar capacidades y montar.
        if self.estado.get(&pid).is_some_and(|e| e.creo_userns) {
            return Some(DeteccionEscape {
                patron: PatronEscape::UserNsYMontaje,
                severidad: Severidad::Alta,
                pid,
                explicacion:
                    "mount tras unshare(CLONE_NEWUSER): patron de escape por namespace de usuario",
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventos::{
        ContextoProceso, BANDERA_DESTINO_NS_HOST, BANDERA_MONTAJE_DISPOSITIVO_HOST, CAP_SYS_ADMIN,
    };

    fn en_contenedor(pid: u32) -> ContextoProceso {
        ContextoProceso {
            pid,
            en_contenedor: true,
            capacidades: 1 << CAP_SYS_ADMIN,
        }
    }

    fn ev(op: Operacion, ctx: ContextoProceso) -> EventoNucleo {
        EventoNucleo {
            operacion: op,
            ctx,
            flags: 0,
            banderas: 0,
            ruta: RutaSensible::Ninguna,
        }
    }

    #[test]
    fn escribir_release_agent_es_escape_critico() {
        let mut m = MonitorEscape::nuevo();
        let mut e = ev(Operacion::Escritura, en_contenedor(10));
        e.ruta = RutaSensible::ReleaseAgentCgroup;
        let d = m.analizar(&e).expect("release_agent es escape");
        assert_eq!(d.patron, PatronEscape::ReleaseAgentCgroup);
        assert_eq!(d.severidad, Severidad::Critica);
    }

    #[test]
    fn escribir_core_pattern_es_escape_critico() {
        let mut m = MonitorEscape::nuevo();
        let mut e = ev(Operacion::Escritura, en_contenedor(10));
        e.ruta = RutaSensible::CorePattern;
        assert_eq!(
            m.analizar(&e).map(|d| (d.patron, d.severidad)),
            Some((PatronEscape::CorePattern, Severidad::Critica))
        );
    }

    #[test]
    fn montar_el_disco_del_host_es_escape_critico() {
        let mut m = MonitorEscape::nuevo();
        let mut e = ev(Operacion::Montar, en_contenedor(10));
        e.banderas = BANDERA_MONTAJE_DISPOSITIVO_HOST;
        let d = m.analizar(&e).expect("montar disco host es escape");
        assert_eq!(d.patron, PatronEscape::MontajeDiscoHost);
        assert_eq!(d.severidad, Severidad::Critica);
    }

    #[test]
    fn setns_al_host_es_escape() {
        let mut m = MonitorEscape::nuevo();
        let mut e = ev(Operacion::Setns, en_contenedor(10));
        e.banderas = BANDERA_DESTINO_NS_HOST;
        assert_eq!(
            m.analizar(&e).map(|d| d.patron),
            Some(PatronEscape::SetnsAlHost)
        );
    }

    #[test]
    fn cargar_bpf_desde_contenedor_es_escape() {
        let mut m = MonitorEscape::nuevo();
        let e = ev(Operacion::Bpf, en_contenedor(10));
        assert_eq!(
            m.analizar(&e).map(|d| d.patron),
            Some(PatronEscape::BpfEnContenedor)
        );
    }

    #[test]
    fn la_secuencia_userns_y_montaje_es_escape() {
        let mut m = MonitorEscape::nuevo();
        // Paso 1: unshare(CLONE_NEWUSER) -> solo arma el estado, no marca aun.
        let mut u = ev(Operacion::Unshare, en_contenedor(20));
        u.flags = CLONE_NEWUSER;
        assert!(m.analizar(&u).is_none());
        // Paso 2: mount -> ahora si, por la secuencia.
        let mnt = ev(Operacion::Montar, en_contenedor(20));
        let d = m.analizar(&mnt).expect("mount tras userns es escape");
        assert_eq!(d.patron, PatronEscape::UserNsYMontaje);
        assert_eq!(d.severidad, Severidad::Alta);
    }

    #[test]
    fn un_montaje_normal_sin_userns_no_se_marca() {
        // Sin el precursor userns y sin dispositivo del host, un mount no es escape.
        let mut m = MonitorEscape::nuevo();
        let mnt = ev(Operacion::Montar, en_contenedor(30));
        assert!(m.analizar(&mnt).is_none());
    }

    #[test]
    fn las_mismas_syscalls_en_el_host_no_son_escape() {
        // En el host (no en un contenedor) todo esto es orquestacion legitima.
        let mut m = MonitorEscape::nuevo();
        let host = ContextoProceso {
            pid: 1,
            en_contenedor: false,
            capacidades: 1 << CAP_SYS_ADMIN,
        };
        let mut escr = ev(Operacion::Escritura, host);
        escr.ruta = RutaSensible::ReleaseAgentCgroup;
        assert!(m.analizar(&escr).is_none());
        let e_bpf = ev(Operacion::Bpf, host);
        assert!(m.analizar(&e_bpf).is_none());
        let mut setns = ev(Operacion::Setns, host);
        setns.banderas = BANDERA_DESTINO_NS_HOST;
        assert!(m.analizar(&setns).is_none());
    }

    #[test]
    fn olvidar_un_proceso_limpia_su_estado() {
        let mut m = MonitorEscape::nuevo();
        let mut u = ev(Operacion::Unshare, en_contenedor(40));
        u.flags = CLONE_NEWUSER;
        m.analizar(&u);
        m.olvidar(40);
        // Tras olvidar, un mount ya no arrastra el precursor userns.
        let mnt = ev(Operacion::Montar, en_contenedor(40));
        assert!(m.analizar(&mnt).is_none());
    }
}
