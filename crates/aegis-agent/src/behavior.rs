//! Traduccion de la telemetria del kernel a tecnicas de MITRE ATT&CK.
//!
//! El motor conductual de [`aegis_behavior`] no sabe nada de `execve`, de
//! `ptrace` ni de sockets: habla de tecnicas y de causalidad. Este modulo es lo
//! que convierte lo uno en lo otro, y por tanto donde se decide **que cuenta
//! como que**.
//!
//! # El criterio de las traducciones
//!
//! Una traduccion demasiado generosa arruina el motor. La tentacion obvia es
//! marcar cada escritura de alta entropia como T1486 (cifrado con impacto,
//! peso 60): con eso, guardar un `.tar.gz` alertaria. Por eso aqui **no** se
//! traduce ninguna senal ambigua directamente; el cifrado solo se anota cuando
//! el motor de ransomware, que cruza velocidad, entropia normalizada y senuelos,
//! lo ha CONFIRMADO ([`BehaviorBridge::on_ransom_confirmed`]).
//!
//! Las traducciones que si estan son las que no admiten lectura alternativa a
//! nivel de evento, o cuyo peso es lo bastante bajo como para que solo importen
//! dentro de una cadena.

use std::collections::HashMap;

use aegis_behavior::dag::EdgeKind;
use aegis_behavior::engine::{Assessment, BehavioralGraphEngine, EngineConfig};
use aegis_behavior::technique::Technique;
use aegis_scal::process::{ProcessKey, ProcessLifecycleProvider};

use crate::graph::ProcKey;
use crate::scal::EbpfProcessProvider;
use crate::triage::TelemetryEvent;

/// Interpretes de comandos, por nombre de imagen.
const INTERPRETES: &[&str] = aegis_behavior::chain::INTERPRETES;
/// Herramientas de transferencia.
const DESCARGADORES: &[&str] = aegis_behavior::chain::DESCARGADORES;
/// Utilidades que cambian permisos de ficheros.
const PERMISOS: &[&str] = &["chmod", "chown", "chgrp", "setfacl"];
/// Utilidades de tarea programada.
const PROGRAMADORES: &[&str] = &["crontab", "at", "batch", "systemd-run", "systemctl"];
/// Utilidades de borrado seguro, la firma del borrado de rastros.
const BORRADORES: &[&str] = &["shred", "wipe", "srm"];
/// Puertos de servicios remotos: SSH, SMB, RDP, WinRM, VNC.
const PUERTOS_REMOTOS: &[u16] = &[22, 445, 3389, 5985, 5986, 5900];
/// Prefijos de los directorios de registro del sistema.
const RUTAS_DE_REGISTRO: &[&str] = &["/var/log/", "/var/adm/"];

/// Nombre del ejecutable a partir de una ruta.
fn basename(ruta: &str) -> &str {
    ruta.rsplit('/').next().unwrap_or(ruta)
}

/// Tecnicas que implica un `exec` por la imagen que ejecuta.
///
/// Devuelve una lista porque un mismo binario puede implicar varias: `busybox`
/// es interprete y descargador a la vez.
pub fn tecnicas_de_imagen(image: &str) -> Vec<Technique> {
    let n = basename(image);
    let mut v = Vec::new();
    if INTERPRETES.contains(&n) {
        v.push(Technique::CommandInterpreter);
    }
    if DESCARGADORES.contains(&n) {
        v.push(Technique::IngressToolTransfer);
    }
    if PERMISOS.contains(&n) {
        v.push(Technique::PermissionsModification);
    }
    if PROGRAMADORES.contains(&n) {
        v.push(Technique::ScheduledTask);
    }
    if BORRADORES.contains(&n) {
        v.push(Technique::IndicatorRemoval);
    }
    v
}

/// Puente entre la telemetria del agente y el motor conductual.
///
/// Mantiene una sola identidad para cada proceso —la de la capa de
/// abstraccion— compartida con [`EbpfProcessProvider`]: dos vocabularios de
/// identidad sobre los mismos procesos acaban atribuyendo acciones al proceso
/// equivocado.
#[derive(Debug)]
pub struct BehaviorBridge {
    procesos: EbpfProcessProvider,
    motor: BehavioralGraphEngine,
    /// Actores que el puente vio nacer y siguen dados de alta en el motor.
    conocidos: HashMap<ProcKey, ProcessKey>,
}

impl BehaviorBridge {
    /// Crea el puente.
    pub fn new(config: EngineConfig) -> BehaviorBridge {
        BehaviorBridge {
            procesos: EbpfProcessProvider::new(),
            motor: BehavioralGraphEngine::new(config),
            conocidos: HashMap::new(),
        }
    }

    /// Motor, para consultarlo y para las pruebas.
    pub fn engine(&self) -> &BehavioralGraphEngine {
        &self.motor
    }

    /// Proveedor de ciclo de vida subyacente.
    pub fn processes(&self) -> &EbpfProcessProvider {
        &self.procesos
    }

    /// Identidad de la capa para un actor del ABI.
    pub fn identidad(&self, actor: ProcKey) -> Option<ProcessKey> {
        self.conocidos.get(&actor).copied()
    }

    /// Ingiere un evento de telemetria.
    ///
    /// Devuelve las valoraciones que merecen accion. Puede ser mas de una: un
    /// `ptrace` que inyecta escala al que inyecta y al inyectado.
    pub fn ingest(&mut self, ev: &TelemetryEvent, now_ns: u64) -> Vec<Assessment> {
        let mut salida = Vec::new();

        // 1. Ciclo de vida. Se hace primero: el motor no puede anotar tecnicas
        //    sobre un proceso que todavia no ha dado de alta.
        if self.procesos.ingest(ev) {
            if let Ok(eventos) = self.procesos.poll(std::time::Duration::ZERO) {
                for e in eventos {
                    if let Some(a) = self.motor.on_process(&e, now_ns) {
                        salida.push(a);
                    }
                }
            }
        }
        if let TelemetryEvent::Exec { actor, .. } = ev {
            if let Some(k) = self.procesos.identidad(*actor) {
                self.conocidos.insert(*actor, k);
            }
        }

        // 2. Tecnicas.
        let Some(actor_key) = self.identidad(ev.actor()) else {
            // Proceso que ya existia antes de arrancar el agente, o que murio
            // antes de poder resolverlo: no hay a quien atribuirle la tecnica.
            return salida;
        };

        for t in self.tecnicas_de(ev, actor_key) {
            if let Ok(Some(a)) = self.motor.observe(actor_key, t) {
                salida.push(a);
            }
        }

        // 3. Linaje segun la sonda, no segun `procfs`.
        //
        // El evento de `exec` trae el padre capturado EN EL MOMENTO de la
        // ejecucion. `procfs` trae el padre actual, que puede ser otro: cuando
        // un proceso muere, sus hijos se reasignan a `init`, y con ellos se
        // pierde el linaje del incidente. Desligarse asi es ademas una tecnica
        // deliberada. Por eso, cuando la sonda dice quien era el padre, esa es
        // la arista que vale.
        if let TelemetryEvent::Exec { parent, .. } = ev {
            if let Some(padre) = self.identidad(*parent) {
                if let Ok(Some(a)) = self.motor.link(padre, actor_key, EdgeKind::Spawned, now_ns) {
                    salida.push(a);
                }
            }
        }

        // 4. Causalidad distinta del linaje.
        if let TelemetryEvent::Ptrace {
            target_pid,
            writes_memory: true,
            ..
        } = ev
        {
            // El objetivo se resuelve por PID contra el grafo: un `ptrace` no
            // trae la identidad del objetivo, solo su numero.
            if let Some(destino) = self.motor.graph().key_of_pid(*target_pid) {
                if let Ok(Some(a)) = self
                    .motor
                    .link(actor_key, destino, EdgeKind::Injected, now_ns)
                {
                    salida.push(a);
                }
            }
        }

        salida
    }

    /// Tecnicas que implica un evento concreto.
    ///
    /// Para un `exec`, la imagen que decide es la que resolvio la capa de
    /// abstraccion (`/proc/<pid>/exe` en Linux), no la que traia el evento. Son
    /// dos cosas distintas: el evento trae la ruta que el proceso PASO a
    /// `execve`, que el atacante elige y puede ser un enlace a cualquier sitio;
    /// la capa trae el binario que el kernel acabo ejecutando. Ademas, es la
    /// misma imagen con la que [`aegis_behavior::chain`] evalua los patrones:
    /// dos autoridades distintas para "que binario es este" acabarian
    /// clasificando el mismo proceso de dos maneras.
    fn tecnicas_de(&self, ev: &TelemetryEvent, actor_key: ProcessKey) -> Vec<Technique> {
        match ev {
            TelemetryEvent::Exec { image, .. } => {
                let resuelta = self
                    .motor
                    .graph()
                    .node(actor_key)
                    .and_then(|n| n.image.as_ref())
                    .and_then(|p| p.to_str())
                    .map(str::to_owned);
                tecnicas_de_imagen(resuelta.as_deref().unwrap_or(image))
            }
            // Escribir en `ptrace` la memoria de otro proceso es inyeccion sin
            // ambiguedad. LEERLA no lo es: los depuradores y los perfiladores
            // lo hacen, y traducirlo daria un falso positivo por cada uso de
            // `gdb` en una maquina de desarrollo.
            TelemetryEvent::Ptrace {
                writes_memory: true,
                source_pid,
                target_pid,
                ..
            } if source_pid != target_pid => vec![Technique::ProcessInjection],
            TelemetryEvent::NetConnect {
                dport,
                loopback: false,
                private_dst,
                ..
            } => {
                if *private_dst && PUERTOS_REMOTOS.contains(dport) {
                    vec![Technique::RemoteServices]
                } else if !*private_dst {
                    vec![Technique::ApplicationLayerProtocol]
                } else {
                    Vec::new()
                }
            }
            // Renombrar o reescribir dentro de los directorios de registro es
            // borrado de rastros. Se mira el DESTINO del renombrado: mover el
            // registro a otro sitio lo hace desaparecer igual que borrarlo.
            TelemetryEvent::FileRename { from, to, .. } => {
                if es_registro(from) || es_registro(to) {
                    vec![Technique::IndicatorRemoval]
                } else {
                    Vec::new()
                }
            }
            // Una escritura de alta entropia NO se traduce a T1486 aqui: ver la
            // nota del modulo. El cifrado lo confirma el motor de ransomware.
            _ => Vec::new(),
        }
    }

    /// Anota cifrado con impacto (T1486) sobre un proceso que el motor de
    /// ransomware ya ha confirmado.
    ///
    /// Es la unica via por la que entra T1486, y es deliberado: es la tecnica de
    /// mas peso del catalogo, y anotarla desde una senal ambigua convertiria
    /// cada copia de seguridad comprimida en un aislamiento automatico.
    pub fn on_ransom_confirmed(&mut self, actor: ProcKey) -> Option<Assessment> {
        let key = self.identidad(actor)?;
        self.motor
            .observe(key, Technique::DataEncryptedForImpact)
            .ok()
            .flatten()
    }

    /// Mantenimiento periodico. Devuelve cuantos nodos se expiraron.
    pub fn maintain(&mut self, now_ns: u64) -> usize {
        let fuera = self.motor.maintain(now_ns);
        if fuera > 0 {
            let m = &self.motor;
            self.conocidos.retain(|_, k| m.graph().node(*k).is_some());
        }
        fuera
    }
}

/// Indica si una ruta esta dentro de los directorios de registro del sistema.
fn es_registro(ruta: &str) -> bool {
    RUTAS_DE_REGISTRO.iter().any(|p| ruta.starts_with(p))
}
