//! El almacen del agente: que contenido esta activo, cual habia antes y hasta
//! que epoca se ha visto.
//!
//! # Ficheros (todos en el mismo directorio, para que `rename` sea atomico)
//!
//! | Fichero | Que es |
//! |---|---|
//! | `activo.aegc` | el paquete sellado activo |
//! | `anterior.aegc` | el que estaba antes (un nivel de rollback local) |
//! | `descartado.aegc` | el que se aparto al revertir, para el forense |
//! | `ajustes.aegs` | los ajustes sellados vigentes |
//! | `estado` | epoca vista, huella del activo, epoca de ajustes e historial |
//!
//! # El disco no es de fiar
//!
//! Cada carga vuelve a verificar la firma, y el fichero activo tiene que ser
//! exactamente el que el estado registra (su SHA-256). Reponer en disco un
//! paquete viejo autentico no basta: habria que tocar tambien el estado, que es
//! comprometer al agente, otro nivel entero. Si se corta la corriente a mitad de
//! una instalacion, el estado sigue apuntando al paquete anterior y la carga lo
//! toma de `anterior.aegc` (lo dice: `recuperado_de_anterior`).
//!
//! # El orden de las comprobaciones al instalar
//!
//! Firma, canal, epoca, anillo, estructura, escalera contra el historial local y
//! validacion de las reglas. La firma va primero: comprobar la epoca antes le
//! dejaria a cualquiera mover el estado del agente mandando basura con una
//! epoca enorme. La epoca vista solo sube cuando TODO ha pasado.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use aegis_update::ClaveActualizacion;

use crate::ajustes::{Ajustes, Rebaja, CTX_AJUSTES};
use crate::codificacion::{de_hex32, hex};
use crate::paquete::{sha256, Manifiesto, Modo, Sellado, Tipo, CTX_CONTENIDO};
use crate::validar::{Medir, Validadores};
use crate::{ClaveVerificacionHibrida, ErrorCanal};

const ACTIVO: &str = "activo.aegc";
const ANTERIOR: &str = "anterior.aegc";
const DESCARTADO: &str = "descartado.aegc";
const AJUSTES: &str = "ajustes.aegs";
const ESTADO: &str = "estado";
const CABECERA_ESTADO: &str = "aegis-contenido-estado 1";

/// Entradas del historial local que se recuerdan.
pub const MAX_HISTORIAL: usize = 32;

/// Con que se verifica en este equipo.
///
/// Solo se construye con una clave HIBRIDA: la clasica no lleva contexto, y sin
/// contexto una firma de ajustes podria pasar por la de un paquete.
#[derive(Debug)]
pub struct Verificacion {
    clave: ClaveActualizacion,
    canal: String,
    id_equipo: String,
    validadores: Validadores,
}

impl Verificacion {
    /// Verificacion con la clave publica hibrida del canal.
    #[must_use]
    pub fn nueva(
        clave: ClaveVerificacionHibrida,
        canal: impl Into<String>,
        id_equipo: impl Into<String>,
        validadores: Validadores,
    ) -> Verificacion {
        Verificacion {
            clave: ClaveActualizacion::from(clave),
            canal: canal.into(),
            id_equipo: id_equipo.into(),
            validadores,
        }
    }

    /// Firma, canal, estructura y reglas: todo lo que no depende del estado.
    fn paquete_sin_estado(&self, bytes: &[u8]) -> Result<Manifiesto, ErrorCanal> {
        let s = Sellado::de_bytes(bytes)?;
        self.clave.verificar(&s.cuerpo, CTX_CONTENIDO, &s.firma)?;
        let m = Manifiesto::de_bytes(&s.cuerpo)?;
        if m.canal != self.canal {
            return Err(ErrorCanal::OtroCanal {
                ofrecido: m.canal,
                esperado: self.canal.clone(),
            });
        }
        m.comprobar_estructura().map_err(ErrorCanal::Estructura)?;
        self.validadores
            .validar(&m, Medir::SoloDeterminista)
            .map_err(ErrorCanal::Roto)?;
        Ok(m)
    }

    fn ajustes(&self, bytes: &[u8]) -> Result<Ajustes, ErrorCanal> {
        let s = Sellado::de_bytes(bytes)?;
        self.clave.verificar(&s.cuerpo, CTX_AJUSTES, &s.firma)?;
        let a = Ajustes::de_bytes(&s.cuerpo)?;
        if a.canal != self.canal {
            return Err(ErrorCanal::OtroCanal {
                ofrecido: a.canal,
                esperado: self.canal.clone(),
            });
        }
        Ok(a)
    }
}

/// Lo que el almacen recuerda.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Estado {
    /// Epoca mas alta aceptada. Nunca baja, ni al revertir.
    pub epoca_vista: u64,
    /// SHA-256 del paquete sellado activo.
    pub sha_activo: Option<[u8; 32]>,
    /// Epoca mas alta de ajustes aceptada.
    pub epoca_ajustes: u64,
    /// (epoca, huella de contenido) aceptadas aqui, las mas recientes.
    pub historial: Vec<(u64, [u8; 32])>,
}

impl Estado {
    fn a_texto(&self) -> String {
        let mut s = format!("{CABECERA_ESTADO}\n");
        s.push_str(&format!("epoca_vista {}\n", self.epoca_vista));
        match &self.sha_activo {
            Some(h) => s.push_str(&format!("sha_activo {}\n", hex(h))),
            None => s.push_str("sha_activo -\n"),
        }
        s.push_str(&format!("epoca_ajustes {}\n", self.epoca_ajustes));
        for (e, h) in &self.historial {
            s.push_str(&format!("historial {e} {}\n", hex(h)));
        }
        s
    }

    fn de_texto(t: &str) -> Result<Estado, String> {
        let mut lineas = t.lines();
        if lineas.next() != Some(CABECERA_ESTADO) {
            return Err("cabecera desconocida".into());
        }
        let mut e = Estado::default();
        for l in lineas {
            let partes: Vec<&str> = l.split(' ').collect();
            let numero = |x: &str| {
                x.parse::<u64>()
                    .map_err(|_| format!("«{l}»: numero invalido"))
            };
            match partes.as_slice() {
                ["epoca_vista", n] => e.epoca_vista = numero(n)?,
                ["epoca_ajustes", n] => e.epoca_ajustes = numero(n)?,
                ["sha_activo", "-"] => e.sha_activo = None,
                ["sha_activo", h] => e.sha_activo = Some(de_hex32(h).map_err(|x| x.0)?),
                ["historial", n, h] => e
                    .historial
                    .push((numero(n)?, de_hex32(h).map_err(|x| x.0)?)),
                _ => return Err(format!("linea desconocida: «{l}»")),
            }
        }
        Ok(e)
    }

    fn registrar(&mut self, epoca: u64, sha_contenido: [u8; 32]) {
        self.historial.push((epoca, sha_contenido));
        if self.historial.len() > MAX_HISTORIAL {
            let sobra = self.historial.len() - MAX_HISTORIAL;
            self.historial.drain(..sobra);
        }
    }

    fn contenido_en(&self, epoca: u64) -> Option<[u8; 32]> {
        self.historial
            .iter()
            .find(|(e, _)| *e == epoca)
            .map(|(_, h)| *h)
    }
}

/// Una regla lista para su motor, con su modo EFECTIVO (tras los ajustes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReglaActiva {
    /// Identificador.
    pub id: String,
    /// Tipo.
    pub tipo: Tipo,
    /// Modo efectivo.
    pub modo: Modo,
    /// Fuente.
    pub fuente: Vec<u8>,
}

/// El contenido cargado y verificado, listo para los motores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContenidoActivo {
    /// Canal.
    pub canal: String,
    /// Epoca del paquete activo.
    pub epoca: u64,
    /// Epoca mas alta vista (puede ser mayor tras un rollback local).
    pub epoca_vista: u64,
    /// Anillo con el que llego.
    pub anillo: &'static str,
    /// Reglas encendidas, con su modo efectivo.
    pub reglas: Vec<ReglaActiva>,
    /// Reglas apagadas (por el paquete o por los ajustes).
    pub apagadas: Vec<String>,
    /// Epoca de los ajustes aplicados (0 si ninguno).
    pub epoca_ajustes: u64,
    /// Si el activo estaba a medio instalar y se tomo el anterior.
    pub recuperado_de_anterior: bool,
}

impl ContenidoActivo {
    fn componer(m: Manifiesto, ajustes: Option<&Ajustes>, epoca_vista: u64) -> ContenidoActivo {
        let mut reglas = Vec::new();
        let mut apagadas = Vec::new();
        let anillo = m.anillo.nombre();
        for e in m.entradas {
            let rebaja = ajustes.and_then(|a| a.rebaja(&e.id));
            if !e.activa || rebaja == Some(Rebaja::Apagar) {
                apagadas.push(e.id);
                continue;
            }
            let modo = if rebaja == Some(Rebaja::Auditoria) {
                Modo::Auditoria
            } else {
                e.modo
            };
            reglas.push(ReglaActiva {
                id: e.id,
                tipo: e.tipo,
                modo,
                fuente: e.fuente,
            });
        }
        ContenidoActivo {
            canal: m.canal,
            epoca: m.epoca,
            epoca_vista,
            anillo,
            reglas,
            apagadas,
            epoca_ajustes: ajustes.map_or(0, |a| a.epoca),
            recuperado_de_anterior: false,
        }
    }

    /// Cuantas reglas encendidas hay en un modo.
    #[must_use]
    pub fn cuantas(&self, modo: Modo) -> usize {
        self.reglas.iter().filter(|r| r.modo == modo).count()
    }

    /// Las fuentes de un tipo y modo, para entregarlas a su motor.
    #[must_use]
    pub fn fuentes(&self, tipo: Tipo, modo: Modo) -> Vec<&[u8]> {
        self.reglas
            .iter()
            .filter(|r| r.tipo == tipo && r.modo == modo)
            .map(|r| r.fuente.as_slice())
            .collect()
    }
}

/// Lo que dejo una instalacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instalado {
    /// Epoca instalada.
    pub epoca: u64,
    /// Anillo con el que llego.
    pub anillo: &'static str,
    /// Reglas del paquete.
    pub reglas: usize,
}

/// Lo que dejo un rollback local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revertido {
    /// Epoca del paquete restaurado.
    pub epoca_restaurada: u64,
    /// Epoca vista, que NO baja.
    pub epoca_vista: u64,
}

/// El almacen de contenido de un equipo.
#[derive(Debug)]
pub struct Almacen {
    dir: PathBuf,
    estado: Estado,
}

fn io(ruta: &Path, error: std::io::Error) -> ErrorCanal {
    ErrorCanal::Io {
        ruta: ruta.display().to_string(),
        error,
    }
}

impl Almacen {
    /// Abre el almacen de `dir`. No crea nada: un directorio que no existe es un
    /// almacen vacio.
    ///
    /// # Errores
    /// [`ErrorCanal::Estado`] si el fichero de estado existe y no se entiende;
    /// [`ErrorCanal::Io`] si no se puede leer.
    pub fn abrir(dir: impl AsRef<Path>) -> Result<Almacen, ErrorCanal> {
        let dir = dir.as_ref().to_path_buf();
        let ruta = dir.join(ESTADO);
        let estado = match std::fs::read_to_string(&ruta) {
            Ok(t) => Estado::de_texto(&t).map_err(ErrorCanal::Estado)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Estado::default(),
            Err(e) => return Err(io(&ruta, e)),
        };
        Ok(Almacen { dir, estado })
    }

    /// Lo que recuerda.
    #[must_use]
    pub fn estado(&self) -> &Estado {
        &self.estado
    }

    fn ruta(&self, nombre: &str) -> PathBuf {
        self.dir.join(nombre)
    }

    fn leer(&self, nombre: &str) -> Result<Vec<u8>, ErrorCanal> {
        let r = self.ruta(nombre);
        std::fs::read(&r).map_err(|e| io(&r, e))
    }

    /// Escribe en un fichero de ensayo del mismo directorio, lo fuerza a disco y
    /// lo renombra encima del destino: en ningun instante hay un fichero a medias.
    fn escribir_atomico(&self, nombre: &str, datos: &[u8]) -> Result<(), ErrorCanal> {
        std::fs::create_dir_all(&self.dir).map_err(|e| io(&self.dir, e))?;
        let ensayo = self.ruta(&format!("{nombre}.ensayo"));
        {
            let mut f = File::create(&ensayo).map_err(|e| io(&ensayo, e))?;
            f.write_all(datos).map_err(|e| io(&ensayo, e))?;
            f.sync_all().map_err(|e| io(&ensayo, e))?;
        }
        let destino = self.ruta(nombre);
        std::fs::rename(&ensayo, &destino).map_err(|e| io(&destino, e))?;
        // Que el renombrado tambien llegue a disco (en Linux; donde no se pueda
        // abrir un directorio, se queda en lo anterior).
        if let Ok(d) = File::open(&self.dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    fn guardar(&mut self, nuevo: Estado) -> Result<(), ErrorCanal> {
        self.escribir_atomico(ESTADO, nuevo.a_texto().as_bytes())?;
        self.estado = nuevo;
        Ok(())
    }

    /// Instala un paquete sellado recibido.
    ///
    /// # Errores
    /// Cualquier [`ErrorCanal`]; en todos los casos el estado y el contenido
    /// activo quedan como estaban.
    pub fn instalar(&mut self, bytes: &[u8], v: &Verificacion) -> Result<Instalado, ErrorCanal> {
        // Firma primero; de ella depende que se mire lo demas.
        let s = Sellado::de_bytes(bytes)?;
        v.clave.verificar(&s.cuerpo, CTX_CONTENIDO, &s.firma)?;
        let m = Manifiesto::de_bytes(&s.cuerpo)?;
        if m.canal != v.canal {
            return Err(ErrorCanal::OtroCanal {
                ofrecido: m.canal,
                esperado: v.canal.clone(),
            });
        }
        if m.epoca <= self.estado.epoca_vista {
            return Err(ErrorCanal::Retroceso {
                ofrecida: m.epoca,
                vista: self.estado.epoca_vista,
            });
        }
        if !m.anillo.incluye(&v.id_equipo) {
            return Err(ErrorCanal::FueraDeAnillo {
                anillo: m.anillo.nombre(),
                epoca: m.epoca,
            });
        }
        m.comprobar_estructura().map_err(ErrorCanal::Estructura)?;

        // Lo que este equipo vio con sus propios ojos manda sobre lo que dice
        // la escalera.
        let sha = m.sha_contenido();
        for p in &m.escalera {
            if self.estado.contenido_en(p.epoca).is_some_and(|h| h != sha) {
                return Err(ErrorCanal::Escalera(format!(
                    "el peldaño de la epoca {} afirma un contenido distinto del que este equipo \
                     acepto en esa epoca",
                    p.epoca
                )));
            }
        }
        if m.revierte_a != 0
            && self
                .estado
                .contenido_en(m.revierte_a)
                .is_some_and(|h| h != sha)
        {
            return Err(ErrorCanal::Escalera(format!(
                "revierte a la epoca {} con un contenido distinto del que este equipo tuvo",
                m.revierte_a
            )));
        }
        v.validadores
            .validar(&m, Medir::SoloDeterminista)
            .map_err(ErrorCanal::Roto)?;

        // Persistir: paquete, luego estado. Un corte entre medias deja el estado
        // apuntando al anterior, que la carga sabe recuperar.
        self.escribir_atomico(&format!("{ACTIVO}.nuevo"), bytes)?;
        let activo = self.ruta(ACTIVO);
        if activo.exists() {
            let anterior = self.ruta(ANTERIOR);
            std::fs::rename(&activo, &anterior).map_err(|e| io(&anterior, e))?;
        }
        let nuevo_f = self.ruta(&format!("{ACTIVO}.nuevo"));
        std::fs::rename(nuevo_f, &activo).map_err(|e| io(&activo, e))?;

        let mut nuevo = self.estado.clone();
        nuevo.epoca_vista = m.epoca;
        nuevo.sha_activo = Some(sha256(bytes));
        nuevo.registrar(m.epoca, sha);
        self.guardar(nuevo)?;
        Ok(Instalado {
            epoca: m.epoca,
            anillo: m.anillo.nombre(),
            reglas: m.entradas.len(),
        })
    }

    /// Carga y verifica el contenido activo, con los ajustes aplicados.
    ///
    /// # Errores
    /// [`ErrorCanal::SinContenido`] si no hay nada instalado; cualquier otro si
    /// lo que hay en disco no verifica. Unos ajustes presentes que no verifican
    /// tambien impiden la carga: cargar sin ellos volveria a encender reglas que
    /// alguien apago por algo.
    pub fn cargar(&self, v: &Verificacion) -> Result<ContenidoActivo, ErrorCanal> {
        let esperado = self.estado.sha_activo.ok_or(ErrorCanal::SinContenido)?;
        let (bytes, recuperado) = match self.leer(ACTIVO) {
            Ok(b) if sha256(&b) == esperado => (b, false),
            _ => match self.leer(ANTERIOR) {
                Ok(b) if sha256(&b) == esperado => (b, true),
                _ => {
                    return Err(ErrorCanal::Estado(
                        "ni el paquete activo ni el anterior son el que registra el estado".into(),
                    ))
                }
            },
        };
        let m = v.paquete_sin_estado(&bytes)?;
        let ajustes = match self.leer(AJUSTES) {
            Ok(b) => {
                let a = v.ajustes(&b)?;
                if a.epoca != self.estado.epoca_ajustes {
                    return Err(ErrorCanal::Estado(format!(
                        "los ajustes en disco son de la epoca {} y el estado registra la {}",
                        a.epoca, self.estado.epoca_ajustes
                    )));
                }
                Some(a)
            }
            Err(_) if self.estado.epoca_ajustes == 0 => None,
            Err(e) => return Err(e),
        };
        let mut c = ContenidoActivo::componer(m, ajustes.as_ref(), self.estado.epoca_vista);
        c.recuperado_de_anterior = recuperado;
        Ok(c)
    }

    /// Rollback local en un comando: vuelve al paquete anterior.
    ///
    /// El anterior se vuelve a verificar y tiene que figurar en el historial de
    /// este equipo (no se restaura nada que nunca se acepto aqui). La epoca vista
    /// NO baja: un paquete viejo que llegue despues se sigue rechazando. El que
    /// se aparta queda como `descartado.aegc`.
    ///
    /// # Errores
    /// [`ErrorCanal::SinAnterior`] si no hay anterior; los de la verificacion.
    pub fn revertir(&mut self, v: &Verificacion) -> Result<Revertido, ErrorCanal> {
        let bytes = match self.leer(ANTERIOR) {
            Ok(b) => b,
            Err(_) => return Err(ErrorCanal::SinAnterior),
        };
        let m = v.paquete_sin_estado(&bytes)?;
        if self.estado.contenido_en(m.epoca) != Some(m.sha_contenido()) {
            return Err(ErrorCanal::Estado(format!(
                "el paquete anterior (epoca {}) no figura en el historial de este equipo",
                m.epoca
            )));
        }
        // El estado PRIMERO. Un corte entre los dos renombrados de abajo deja el
        // anterior en su sitio y el estado apuntandolo, y la carga lo toma de
        // `anterior.aegc`; en el orden inverso, el estado apuntaria a un paquete
        // que ya se aparto y el equipo se quedaria sin contenido.
        let mut nuevo = self.estado.clone();
        nuevo.sha_activo = Some(sha256(&bytes));
        self.guardar(nuevo)?;
        let activo = self.ruta(ACTIVO);
        if activo.exists() {
            let descartado = self.ruta(DESCARTADO);
            let _ = std::fs::remove_file(&descartado);
            std::fs::rename(&activo, &descartado).map_err(|e| io(&descartado, e))?;
        }
        std::fs::rename(self.ruta(ANTERIOR), &activo).map_err(|e| io(&activo, e))?;
        Ok(Revertido {
            epoca_restaurada: m.epoca,
            epoca_vista: self.estado.epoca_vista,
        })
    }

    /// Aplica unos ajustes sellados (apagar reglas o bajarlas a auditoria).
    ///
    /// # Errores
    /// [`ErrorCanal::Retroceso`] si su epoca no supera la de los vigentes; los de
    /// la verificacion.
    pub fn aplicar_ajustes(&mut self, bytes: &[u8], v: &Verificacion) -> Result<u64, ErrorCanal> {
        let a = v.ajustes(bytes)?;
        if a.epoca <= self.estado.epoca_ajustes {
            return Err(ErrorCanal::Retroceso {
                ofrecida: a.epoca,
                vista: self.estado.epoca_ajustes,
            });
        }
        self.escribir_atomico(AJUSTES, bytes)?;
        let mut nuevo = self.estado.clone();
        nuevo.epoca_ajustes = a.epoca;
        self.guardar(nuevo)?;
        Ok(a.epoca)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_estado_va_y_vuelve() {
        let mut e = Estado {
            epoca_vista: 9,
            sha_activo: Some([3; 32]),
            epoca_ajustes: 2,
            historial: Vec::new(),
        };
        e.registrar(8, [1; 32]);
        e.registrar(9, [2; 32]);
        assert_eq!(Estado::de_texto(&e.a_texto()).unwrap(), e);
        assert!(Estado::de_texto("otra cosa\n").is_err());
    }

    #[test]
    fn el_historial_no_crece_sin_limite() {
        let mut e = Estado::default();
        for i in 0..(MAX_HISTORIAL as u64 + 10) {
            e.registrar(i, [0; 32]);
        }
        assert_eq!(e.historial.len(), MAX_HISTORIAL);
        assert_eq!(e.historial[0].0, 10);
    }
}
