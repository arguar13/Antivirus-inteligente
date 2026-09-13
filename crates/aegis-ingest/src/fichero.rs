//! Seguimiento de ficheros de log planos, con rotacion.
//!
//! # El caso que casi todo el mundo hace mal
//!
//! Seguir un fichero que crece es trivial. Seguir un fichero que **rota** es
//! donde fallan la mayoria de los recolectores, y falla de las dos formas
//! posibles a la vez: perdiendo lineas y duplicandolas.
//!
//! Lo que hace `logrotate` cuando llega la medianoche, en este orden:
//!
//! ```text
//!   mv  auth.log  auth.log.1      <- el inodo NO cambia; el nombre si
//!   create auth.log               <- un inodo NUEVO en el nombre de siempre
//!   kill -HUP rsyslog             <- el demonio reabre por nombre
//! ```
//!
//! Y aqui estan los cuatro errores clasicos:
//!
//! 1. **Seguir por nombre.** El recolector reabre `auth.log`, ve un fichero de
//!    cero bytes, y se lleva por delante todo lo que quedaba sin leer del
//!    fichero renombrado. Se pierden lineas, y son justo las de la franja de
//!    tiempo en que nadie mira.
//! 2. **Detectar la rotacion y saltar de inmediato.** Se ve que el nombre apunta
//!    a otro inodo y se cambia ya. Pero el descriptor viejo **todavia tenia
//!    bytes sin leer**: entre la ultima lectura y el `mv` se escribieron lineas.
//!    Se pierden igual. Hay que **agotar el viejo primero**.
//! 3. **No detectar el truncado.** Con `copytruncate` el inodo no cambia: el
//!    fichero se copia y se pone a cero. El recolector sigue en el
//!    desplazamiento de ayer, que ahora esta mas alla del final, y no vuelve a
//!    leer nada **hasta que el fichero crezca por encima de donde estaba**. Un
//!    dia entero de silencio sin un solo error en ningun sitio.
//! 4. **Emitir lineas a medias.** El escritor no es atomico: una lectura puede
//!    caer entre el mensaje y su salto de linea. Emitir lo que hay produce dos
//!    registros rotos donde habia uno bueno, y ninguno de los dos clasifica.
//!
//! Los cuatro estan resueltos aqui y los cuatro tienen su prueba.
//!
//! # El ancla lleva el inodo, no la ruta
//!
//! Es lo que hace que la deduplicacion sobreviva a la rotacion: la linea 500 de
//! `auth.log` de hoy y la linea 500 de `auth.log` de ayer estan en la misma ruta
//! y en el mismo desplazamiento, pero en inodos distintos. Con la ruta como
//! ancla se fundirian en una sola y desapareceria un dia de evidencia.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{ErrorIngesta, Resultado};

/// Bytes maximos de una linea antes de cortarla.
///
/// Un fichero sin un solo salto de linea en cien megas es entrada hostil o un
/// volcado por error, y en los dos casos el bufer no puede crecer con el. Lo que
/// se lee se entrega marcado como cortado; lo que sobra se descarta hasta el
/// siguiente salto, que es lo unico que permite resincronizar.
pub const MAX_LINEA: usize = 1024 * 1024;

/// Bytes que se leen del disco de una vez.
pub const BLOQUE: usize = 64 * 1024;

/// Una linea leida, con su sitio exacto en el fichero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Linea {
    /// El contenido, sin el salto de linea.
    pub datos: Vec<u8>,
    /// Dispositivo e inodo del fichero del que salio.
    pub identidad: Identidad,
    /// Desplazamiento del primer byte de la linea.
    pub desplazamiento: u64,
    /// Si se corto por [`MAX_LINEA`].
    pub cortada: bool,
}

impl Linea {
    /// Ancla estable de esta linea, para la deduplicacion.
    ///
    /// Lleva el inodo y no la ruta: ver el encabezado del modulo.
    #[must_use]
    pub fn ancla(&self) -> String {
        format!(
            "fichero:{}:{}@{}",
            self.identidad.dispositivo, self.identidad.inodo, self.desplazamiento
        )
    }
}

/// Identidad de un fichero en el sistema de ficheros.
///
/// El par dispositivo+inodo y no solo el inodo: los inodos se repiten entre
/// sistemas de ficheros, y un recolector que siga `/var/log` y `/srv/log`
/// montados por separado confundiria dos ficheros distintos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identidad {
    /// Dispositivo del sistema de ficheros.
    pub dispositivo: u64,
    /// Numero de inodo.
    pub inodo: u64,
}

impl Identidad {
    fn de(meta: &std::fs::Metadata) -> Identidad {
        Identidad {
            dispositivo: meta.dev(),
            inodo: meta.ino(),
        }
    }
}

/// Lo que hay que recordar entre reinicios para reanudar exactamente donde se
/// estaba.
///
/// Se guarda **despues** de que los eventos esten a salvo, nunca antes: ver
/// [`crate::punto`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marca {
    /// De que fichero.
    pub identidad: Identidad,
    /// Hasta donde se leyo.
    pub desplazamiento: u64,
}

/// Por que se cambio de fichero. Se publica porque distingue una operacion
/// normal de una perdida.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cambio {
    /// El nombre pasa a apuntar a otro inodo: rotacion clasica.
    Rotado,
    /// El mismo inodo se quedo mas corto: `copytruncate`.
    Truncado,
    /// El fichero no existia y ahora si.
    Aparecido,
}

/// Contadores del seguidor.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Contadores {
    /// Lineas entregadas.
    pub lineas: u64,
    /// Bytes leidos.
    pub bytes: u64,
    /// Rotaciones atendidas.
    pub rotaciones: u64,
    /// Truncados atendidos.
    pub truncados: u64,
    /// Lineas cortadas por [`MAX_LINEA`].
    pub cortadas: u64,
    /// Bytes saltados al resincronizar tras una linea cortada.
    pub saltados: u64,
}

/// Un fichero abierto, con su identidad y por donde va.
#[derive(Debug)]
struct Abierto {
    fichero: File,
    identidad: Identidad,
    desplazamiento: u64,
    /// El nombre ya no apunta a este inodo: hay que agotarlo y cerrarlo.
    condenado: bool,
}

/// Sigue un fichero de log a traves de sus rotaciones.
#[derive(Debug)]
pub struct Seguidor {
    ruta: PathBuf,
    abierto: Option<Abierto>,
    /// Linea a medias: lo leido desde el ultimo salto de linea.
    resto: Vec<u8>,
    /// Bytes ya leidos del disco que todavia no se han repartido en lineas.
    ///
    /// # Sin esto se pierden lineas y no lo nota nadie
    ///
    /// Una lectura trae 64 KiB de golpe, pero quien llama pide como mucho `n`
    /// lineas. Las que sobran del bloque **ya han salido del fichero**: el
    /// descriptor esta mas adelante y nadie las va a volver a leer. Tirarlas
    /// pierde de golpe casi todo un bloque cada vez que se alcanza el tope, que
    /// con un tope pequeno es casi siempre.
    pendiente: Vec<u8>,
    /// Desplazamiento en el que empieza `resto`.
    inicio_resto: u64,
    /// Se esta descartando hasta el siguiente salto tras cortar una linea.
    resincronizando: bool,
    contadores: Contadores,
    ultimo_cambio: Option<Cambio>,
}

impl Seguidor {
    /// Empieza a seguir una ruta desde el principio del fichero.
    #[must_use]
    pub fn nuevo(ruta: impl Into<PathBuf>) -> Seguidor {
        Seguidor {
            ruta: ruta.into(),
            abierto: None,
            resto: Vec::new(),
            pendiente: Vec::new(),
            inicio_resto: 0,
            resincronizando: false,
            contadores: Contadores::default(),
            ultimo_cambio: None,
        }
    }

    /// Reanuda desde una marca guardada.
    ///
    /// Si el fichero que hay en la ruta ya no es el de la marca —roto mientras
    /// el agente estaba parado— se empieza el nuevo desde cero, que es lo
    /// correcto: sus lineas no se han leido nunca. Lo que quedara sin leer del
    /// viejo se pierde, y eso **se declara** en vez de disimularse: el fichero
    /// viejo ya no tiene nombre por el que abrirlo.
    pub fn reanudar(ruta: impl Into<PathBuf>, marca: Marca) -> Resultado<Seguidor> {
        let mut s = Seguidor::nuevo(ruta);
        let ruta = s.ruta.clone();
        match std::fs::metadata(&ruta) {
            Ok(meta) if Identidad::de(&meta) == marca.identidad => {
                let mut f = File::open(&ruta)
                    .map_err(|e| ErrorIngesta::es(format!("abriendo {}", ruta.display()), e))?;
                // SI EL FICHERO ENCOGIO MIENTRAS SE ESTABA PARADO, la marca
                // apunta mas alla del final. Eso solo puede significar que el
                // contenido se sustituyo —`copytruncate` conserva el inodo— y lo
                // correcto es empezar de cero: lo que hay ahora no se ha leido
                // nunca. Recortar la marca al tamano actual dejaria al seguidor
                // parado en el final de un fichero nuevo, mudo hasta que
                // creciera por encima de donde estaba.
                let desplazamiento = if marca.desplazamiento > meta.len() {
                    0
                } else {
                    marca.desplazamiento
                };
                f.seek(SeekFrom::Start(desplazamiento))
                    .map_err(|e| ErrorIngesta::es("posicionando", e))?;
                s.inicio_resto = desplazamiento;
                s.abierto = Some(Abierto {
                    fichero: f,
                    identidad: marca.identidad,
                    desplazamiento,
                    condenado: false,
                });
            }
            _ => {
                // Otro inodo o no existe: el seguidor abrira lo que haya desde
                // el principio en la primera lectura.
            }
        }
        Ok(s)
    }

    /// Marca actual, para guardar.
    ///
    /// Apunta al principio de la linea incompleta, **no al final de lo leido**.
    /// Si apuntara al final, un reinicio en medio de una linea la perderia: los
    /// bytes ya estarian «leidos» segun la marca pero no se habria emitido nada.
    #[must_use]
    pub fn marca(&self) -> Option<Marca> {
        let a = self.abierto.as_ref()?;
        Some(Marca {
            identidad: a.identidad,
            desplazamiento: self.inicio_resto,
        })
    }

    /// Contadores acumulados.
    #[must_use]
    pub fn contadores(&self) -> Contadores {
        self.contadores
    }

    /// Por que se cambio de fichero en la ultima lectura, si se cambio.
    #[must_use]
    pub fn ultimo_cambio(&self) -> Option<Cambio> {
        self.ultimo_cambio
    }

    /// Lee hasta `maximo` lineas completas.
    ///
    /// Devuelve vacio cuando no hay nada nuevo; no bloquea ni espera.
    pub fn leer(&mut self, maximo: usize) -> Resultado<Vec<Linea>> {
        self.ultimo_cambio = None;
        let mut salida = Vec::new();
        // CUATRO VUELTAS COMO MAXIMO, y el numero no es arbitrario: atender una
        // rotacion cuesta tres pasos —agotar el descriptor viejo, cambiar al
        // nuevo, leer del nuevo— y la cuarta deja margen para el caso en que la
        // rotacion se detecta en la primera vuelta. Con dos, la llamada se
        // quedaba justo despues de cambiar de fichero y devolvia menos lineas de
        // las que habia; con un bucle sin tope, una cascada de rotaciones dejaria
        // al resto del agente sin turno.
        for _ in 0..4 {
            if self.abierto.is_none() && !self.abrir()? {
                break;
            }
            let agotado = self.leer_del_abierto(maximo, &mut salida)?;
            if salida.len() >= maximo {
                break;
            }
            if !agotado {
                break;
            }
            // Se llego al final del fichero abierto. Solo AQUI se mira si hay
            // que cambiar: mirarlo antes seria abandonar bytes sin leer.
            if !self.atender_cambio()? {
                break;
            }
        }
        Ok(salida)
    }

    /// Abre lo que haya en la ruta. Devuelve si habia algo.
    fn abrir(&mut self) -> Resultado<bool> {
        let meta = match std::fs::metadata(&self.ruta) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(ErrorIngesta::es(
                    format!("consultando {}", self.ruta.display()),
                    e,
                ))
            }
        };
        if !meta.is_file() {
            return Ok(false);
        }
        let f = File::open(&self.ruta)
            .map_err(|e| ErrorIngesta::es(format!("abriendo {}", self.ruta.display()), e))?;
        if self.ultimo_cambio.is_none() {
            self.ultimo_cambio = Some(Cambio::Aparecido);
        }
        self.abierto = Some(Abierto {
            fichero: f,
            identidad: Identidad::de(&meta),
            desplazamiento: 0,
            condenado: false,
        });
        self.resto.clear();
        self.pendiente.clear();
        self.inicio_resto = 0;
        self.resincronizando = false;
        Ok(true)
    }

    /// Lee del descriptor abierto. Devuelve si llego al final.
    fn leer_del_abierto(&mut self, maximo: usize, salida: &mut Vec<Linea>) -> Resultado<bool> {
        let mut bloque = [0u8; BLOQUE];
        loop {
            // Primero lo que quedo sin repartir de la llamada anterior: son
            // bytes que YA salieron del fichero y no se pueden volver a leer.
            if !self.pendiente.is_empty() {
                let Some(identidad) = self.abierto.as_ref().map(|a| a.identidad) else {
                    return Ok(false);
                };
                let pend = std::mem::take(&mut self.pendiente);
                let consumidos = self.partir(&pend, identidad, maximo, salida);
                if consumidos < pend.len() {
                    self.pendiente = pend[consumidos..].to_vec();
                    return Ok(false);
                }
            }
            if salida.len() >= maximo {
                return Ok(false);
            }
            let Some(a) = self.abierto.as_mut() else {
                return Ok(false);
            };
            let leidos = a
                .fichero
                .read(&mut bloque)
                .map_err(|e| ErrorIngesta::es("leyendo", e))?;
            if leidos == 0 {
                return Ok(true);
            }
            a.desplazamiento += leidos as u64;
            self.contadores.bytes += leidos as u64;
            let identidad = a.identidad;
            let consumidos = self.partir(&bloque[..leidos], identidad, maximo, salida);
            if consumidos < leidos {
                self.pendiente = bloque[consumidos..leidos].to_vec();
                return Ok(false);
            }
        }
    }

    /// Reparte un bloque recien leido en lineas, guardando la ultima a medias.
    ///
    /// Devuelve cuantos bytes del bloque consumio: cuando se alcanza el tope de
    /// lineas, el resto vuelve a `pendiente` en vez de perderse.
    fn partir(
        &mut self,
        bloque: &[u8],
        identidad: Identidad,
        maximo: usize,
        salida: &mut Vec<Linea>,
    ) -> usize {
        for (indice, &b) in bloque.iter().enumerate() {
            if self.resincronizando {
                self.inicio_resto += 1;
                self.contadores.saltados += 1;
                if b == b'\n' {
                    self.resincronizando = false;
                }
                continue;
            }
            if b == b'\n' {
                let mut datos = std::mem::take(&mut self.resto);
                // El `\r\n` de los ficheros que vienen de Windows.
                if datos.last() == Some(&b'\r') {
                    datos.pop();
                }
                let largo = datos.len() as u64;
                salida.push(Linea {
                    datos,
                    identidad,
                    desplazamiento: self.inicio_resto,
                    cortada: false,
                });
                self.contadores.lineas += 1;
                self.inicio_resto += largo + 1;
                if salida.len() >= maximo {
                    return indice + 1;
                }
                continue;
            }
            if self.resto.len() >= MAX_LINEA {
                // Un fichero sin un solo salto de linea en cien megas es entrada
                // hostil o un volcado por error. Se entrega lo leido MARCADO y
                // se descarta hasta el siguiente salto.
                let datos = std::mem::take(&mut self.resto);
                let largo = datos.len() as u64;
                salida.push(Linea {
                    datos,
                    identidad,
                    desplazamiento: self.inicio_resto,
                    cortada: true,
                });
                self.contadores.lineas += 1;
                self.contadores.cortadas += 1;
                self.inicio_resto += largo;
                self.resincronizando = true;
                self.inicio_resto += 1;
                self.contadores.saltados += 1;
                if b == b'\n' {
                    self.resincronizando = false;
                }
                if salida.len() >= maximo {
                    return indice + 1;
                }
                continue;
            }
            self.resto.push(b);
        }
        bloque.len()
    }

    /// En el final del fichero: decide si hay que cambiar de descriptor.
    ///
    /// Devuelve `true` si se cambio y merece la pena otra vuelta de lectura.
    fn atender_cambio(&mut self) -> Resultado<bool> {
        let Some(a) = self.abierto.as_ref() else {
            return Ok(false);
        };
        if a.condenado {
            // Ya se sabia que estaba rotado y ahora se ha agotado: adios.
            self.abierto = None;
            self.resto.clear();
            self.pendiente.clear();
            self.inicio_resto = 0;
            self.contadores.rotaciones += 1;
            self.ultimo_cambio = Some(Cambio::Rotado);
            return self.abrir();
        }

        let actual = std::fs::metadata(&self.ruta);
        match actual {
            Ok(meta) if Identidad::de(&meta) != a.identidad => {
                // EL NOMBRE APUNTA A OTRO INODO. No se cambia todavia: se marca
                // condenado y se vuelve a leer el viejo hasta agotarlo. Entre la
                // ultima lectura y el `mv` puede haberse escrito, y esas lineas
                // son justo las de la franja en que nadie mira.
                if let Some(a) = self.abierto.as_mut() {
                    a.condenado = true;
                }
                Ok(true)
            }
            Ok(meta) if meta.len() < a.desplazamiento => {
                // MISMO INODO, MAS CORTO: `copytruncate`. Sin esto el recolector
                // se queda mudo hasta que el fichero crezca por encima de donde
                // estaba, y eso puede ser un dia entero sin un solo error.
                let Some(a) = self.abierto.as_mut() else {
                    return Ok(false);
                };
                a.fichero
                    .seek(SeekFrom::Start(0))
                    .map_err(|e| ErrorIngesta::es("rebobinando tras truncado", e))?;
                a.desplazamiento = 0;
                self.resto.clear();
                self.pendiente.clear();
                self.inicio_resto = 0;
                self.resincronizando = false;
                self.contadores.truncados += 1;
                self.ultimo_cambio = Some(Cambio::Truncado);
                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Borrado sin crear otro. El descriptor sigue siendo valido y el
                // escritor puede seguir escribiendo en el; se sigue leyendo de
                // ahi hasta que aparezca un fichero nuevo con ese nombre.
                Ok(false)
            }
            Err(e) => Err(ErrorIngesta::es(
                format!("consultando {}", self.ruta.display()),
                e,
            )),
        }
    }
}

/// Comprueba si una ruta se puede seguir, con un mensaje util si no.
///
/// Existe porque el fallo mas comun al desplegar esto no es un error de
/// programa: es que el agente no tiene permiso sobre `/var/log/auth.log`, y sin
/// una comprobacion explicita el sintoma es «no llegan eventos» sin nada mas.
pub fn comprobar(ruta: &Path) -> Resultado<()> {
    let meta = std::fs::metadata(ruta)
        .map_err(|e| ErrorIngesta::es(format!("no se puede seguir {}", ruta.display()), e))?;
    if !meta.is_file() {
        return Err(ErrorIngesta::Config(format!(
            "{} no es un fichero regular",
            ruta.display()
        )));
    }
    File::open(ruta).map_err(|e| {
        ErrorIngesta::es(format!("sin permiso de lectura en {}", ruta.display()), e)
    })?;
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::io::Write;

    fn escribir(ruta: &Path, texto: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(ruta)
            .unwrap();
        f.write_all(texto.as_bytes()).unwrap();
        f.flush().unwrap();
    }

    fn textos(lineas: &[Linea]) -> Vec<String> {
        lineas
            .iter()
            .map(|l| String::from_utf8_lossy(&l.datos).into_owned())
            .collect()
    }

    #[test]
    fn lee_lo_que_se_va_escribiendo() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("app.log");
        escribir(&ruta, "una\ndos\n");
        let mut s = Seguidor::nuevo(&ruta);
        assert_eq!(textos(&s.leer(100).unwrap()), ["una", "dos"]);
        assert!(s.leer(100).unwrap().is_empty(), "no hay mas");
        escribir(&ruta, "tres\n");
        assert_eq!(textos(&s.leer(100).unwrap()), ["tres"]);
    }

    #[test]
    fn una_linea_a_medias_no_se_entrega_partida() {
        // ERROR CLASICO 4. El escritor no es atomico: una lectura puede caer
        // entre el mensaje y su salto de linea. Emitir lo que hay produce dos
        // registros rotos donde habia uno bueno, y ninguno de los dos clasifica.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("app.log");
        escribir(&ruta, "completa\nincom");
        let mut s = Seguidor::nuevo(&ruta);
        assert_eq!(textos(&s.leer(100).unwrap()), ["completa"]);
        escribir(&ruta, "pleta\n");
        assert_eq!(textos(&s.leer(100).unwrap()), ["incompleta"]);
    }

    #[test]
    fn una_rotacion_a_mitad_de_lectura_no_pierde_ni_duplica_una_linea() {
        // LA PRUEBA DE LA FASE. Se escribe en el fichero DESPUES de la ultima
        // lectura y ANTES del `mv`: esas lineas solo existen en el descriptor
        // viejo, y un recolector que salte de inmediato al inodo nuevo las
        // pierde para siempre.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("auth.log");
        escribir(&ruta, "antes-1\nantes-2\n");

        let mut s = Seguidor::nuevo(&ruta);
        assert_eq!(textos(&s.leer(100).unwrap()), ["antes-1", "antes-2"]);

        // La franja en la que nadie mira.
        escribir(&ruta, "en-la-franja-1\nen-la-franja-2\n");

        // logrotate: mueve y crea.
        let rotado = dir.path().join("auth.log.1");
        std::fs::rename(&ruta, &rotado).unwrap();
        escribir(&ruta, "despues-1\n");

        // Una sola llamada agota el viejo Y abre el nuevo.
        let leidas = s.leer(100).unwrap();
        assert_eq!(
            textos(&leidas),
            ["en-la-franja-1", "en-la-franja-2", "despues-1"],
            "se perdio la franja o se salto el fichero nuevo"
        );
        assert_eq!(s.contadores().rotaciones, 1);

        // Y no se duplica nada al volver a preguntar.
        assert!(s.leer(100).unwrap().is_empty());
        escribir(&ruta, "despues-2\n");
        assert_eq!(textos(&s.leer(100).unwrap()), ["despues-2"]);
    }

    #[test]
    fn el_ancla_distingue_la_misma_linea_de_dos_ficheros_rotados() {
        // La linea 1 de auth.log de hoy y la de ayer estan en la misma ruta y en
        // el mismo desplazamiento. Con la ruta como ancla se fundirian en una y
        // desapareceria un dia de evidencia.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("auth.log");
        escribir(&ruta, "identica\n");
        let mut s = Seguidor::nuevo(&ruta);
        let ayer = s.leer(1).unwrap().remove(0);

        std::fs::rename(&ruta, dir.path().join("auth.log.1")).unwrap();
        escribir(&ruta, "identica\n");
        let hoy = s.leer(10).unwrap().remove(0);

        assert_eq!(ayer.datos, hoy.datos, "el texto es el mismo");
        assert_eq!(
            ayer.desplazamiento, hoy.desplazamiento,
            "y el sitio tambien"
        );
        assert_ne!(ayer.ancla(), hoy.ancla(), "pero el ancla no");
    }

    #[test]
    fn el_truncado_se_detecta_aunque_el_inodo_no_cambie() {
        // ERROR CLASICO 3. Con `copytruncate` el inodo no cambia. Un recolector
        // que solo mire el inodo se queda en el desplazamiento de ayer y no lee
        // nada hasta que el fichero crezca por encima: un dia entero de silencio
        // sin un solo error en ningun sitio.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("app.log");
        escribir(&ruta, "linea larga de ayer que ocupa bastante\n");
        let mut s = Seguidor::nuevo(&ruta);
        assert_eq!(s.leer(100).unwrap().len(), 1);

        // copytruncate: se copia y se pone a cero, mismo inodo.
        let antes = std::fs::metadata(&ruta).unwrap().ino();
        std::fs::File::create(&ruta).unwrap();
        assert_eq!(
            std::fs::metadata(&ruta).unwrap().ino(),
            antes,
            "la prueba necesita que el inodo NO cambie"
        );
        escribir(&ruta, "corta\n");

        assert_eq!(textos(&s.leer(100).unwrap()), ["corta"]);
        assert_eq!(s.contadores().truncados, 1);
        assert_eq!(s.ultimo_cambio(), Some(Cambio::Truncado));
    }

    #[test]
    fn un_reinicio_reanuda_exactamente_donde_estaba() {
        // LA OTRA PRUEBA DE LA FASE: ni se pierde ni se manda dos veces sin
        // saberlo.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("app.log");
        escribir(&ruta, "uno\ndos\ntres\n");

        let mut s = Seguidor::nuevo(&ruta);
        assert_eq!(textos(&s.leer(2).unwrap()), ["uno", "dos"]);
        let marca = s.marca().unwrap();
        drop(s);

        // El agente se reinicia. Mientras tanto, mas lineas.
        escribir(&ruta, "cuatro\n");

        let mut s2 = Seguidor::reanudar(&ruta, marca).unwrap();
        assert_eq!(
            textos(&s2.leer(100).unwrap()),
            ["tres", "cuatro"],
            "ni repite las dos primeras ni se salta la tercera"
        );
    }

    #[test]
    fn la_marca_apunta_al_principio_de_la_linea_incompleta() {
        // Si apuntara al final de lo leido, un reinicio en medio de una linea la
        // perderia: los bytes estarian «leidos» segun la marca pero no se habria
        // emitido nada.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("app.log");
        escribir(&ruta, "entera\na-med");
        let mut s = Seguidor::nuevo(&ruta);
        assert_eq!(textos(&s.leer(100).unwrap()), ["entera"]);
        let marca = s.marca().unwrap();
        assert_eq!(marca.desplazamiento, 7, "justo tras «entera\\n»");
        drop(s);

        escribir(&ruta, "ias\n");
        let mut s2 = Seguidor::reanudar(&ruta, marca).unwrap();
        assert_eq!(textos(&s2.leer(100).unwrap()), ["a-medias"]);
    }

    #[test]
    fn reanudar_sobre_un_fichero_encogido_no_deja_al_seguidor_mudo() {
        // La marca apunta mas alla del final. Empezar ahi seria no leer nada
        // nunca mas.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("app.log");
        escribir(&ruta, "una linea bastante larga de ayer\n");
        let meta = std::fs::metadata(&ruta).unwrap();
        let marca = Marca {
            identidad: Identidad::de(&meta),
            desplazamiento: 10_000,
        };
        std::fs::write(&ruta, b"nueva\n").unwrap();
        let mut s = Seguidor::reanudar(&ruta, marca).unwrap();
        assert_eq!(textos(&s.leer(100).unwrap()), ["nueva"]);
    }

    #[test]
    fn reanudar_cuando_el_fichero_roto_estando_parado_lee_el_nuevo_desde_cero() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("app.log");
        escribir(&ruta, "viejo\n");
        let marca = Marca {
            identidad: Identidad::de(&std::fs::metadata(&ruta).unwrap()),
            desplazamiento: 6,
        };
        std::fs::rename(&ruta, dir.path().join("app.log.1")).unwrap();
        escribir(&ruta, "nuevo-1\nnuevo-2\n");

        let mut s = Seguidor::reanudar(&ruta, marca).unwrap();
        assert_eq!(
            textos(&s.leer(100).unwrap()),
            ["nuevo-1", "nuevo-2"],
            "sus lineas no se han leido nunca"
        );
    }

    #[test]
    fn un_fichero_que_todavia_no_existe_no_es_un_error() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("aun-no.log");
        let mut s = Seguidor::nuevo(&ruta);
        assert!(s.leer(100).unwrap().is_empty());
        escribir(&ruta, "ya esta\n");
        assert_eq!(textos(&s.leer(100).unwrap()), ["ya esta"]);
        assert_eq!(s.ultimo_cambio(), Some(Cambio::Aparecido));
    }

    #[test]
    fn un_fichero_borrado_sin_sustituto_se_sigue_leyendo_del_descriptor() {
        // El escritor puede seguir escribiendo en el inodo borrado.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("app.log");
        escribir(&ruta, "antes\n");
        let mut s = Seguidor::nuevo(&ruta);
        assert_eq!(textos(&s.leer(100).unwrap()), ["antes"]);

        let mut abierto = std::fs::OpenOptions::new()
            .append(true)
            .open(&ruta)
            .unwrap();
        std::fs::remove_file(&ruta).unwrap();
        abierto.write_all(b"despues-del-borrado\n").unwrap();
        abierto.flush().unwrap();

        assert_eq!(textos(&s.leer(100).unwrap()), ["despues-del-borrado"]);
    }

    // --- Entrada hostil ------------------------------------------------------

    #[test]
    fn un_fichero_sin_saltos_de_linea_no_hace_crecer_el_bufer() {
        // Entrada hostil o un volcado por error; en los dos casos el bufer no
        // puede crecer con el.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("bomba.log");
        {
            let mut f = File::create(&ruta).unwrap();
            let bloque = vec![b'x'; 1024 * 1024];
            for _ in 0..4 {
                f.write_all(&bloque).unwrap();
            }
            f.write_all(b"\nnormal\n").unwrap();
        }
        let mut s = Seguidor::nuevo(&ruta);
        let lineas = s.leer(1000).unwrap();
        assert!(lineas.iter().any(|l| l.cortada), "se entrego marcada");
        for l in &lineas {
            assert!(l.datos.len() <= MAX_LINEA, "{} bytes", l.datos.len());
        }
        // Y se resincroniza: la linea buena de despues sale entera.
        assert!(
            textos(&lineas).contains(&"normal".to_string()),
            "no resincronizo: {:?}",
            textos(&lineas)
        );
        assert!(s.contadores().cortadas >= 1);
        assert!(s.contadores().saltados > 0);
    }

    #[test]
    fn el_retorno_de_carro_de_windows_no_se_queda_pegado() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("windows.log");
        escribir(&ruta, "una\r\ndos\r\n");
        let mut s = Seguidor::nuevo(&ruta);
        assert_eq!(textos(&s.leer(100).unwrap()), ["una", "dos"]);
    }

    #[test]
    fn los_bytes_binarios_no_rompen_la_lectura() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("bin.log");
        std::fs::write(&ruta, [0xff, 0x00, 0x80, b'\n', b'o', b'k', b'\n']).unwrap();
        let mut s = Seguidor::nuevo(&ruta);
        let lineas = s.leer(100).unwrap();
        assert_eq!(lineas.len(), 2);
        assert_eq!(lineas[0].datos, vec![0xff, 0x00, 0x80]);
        assert_eq!(lineas[1].datos, b"ok");
    }

    #[test]
    fn el_tope_de_lineas_por_llamada_se_respeta_y_no_pierde_el_resto() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("muchas.log");
        {
            let mut f = File::create(&ruta).unwrap();
            for i in 0..1000 {
                writeln!(f, "linea-{i}").unwrap();
            }
        }
        let mut s = Seguidor::nuevo(&ruta);
        let mut todas = Vec::new();
        loop {
            let lote = s.leer(7).unwrap();
            if lote.is_empty() {
                break;
            }
            assert!(lote.len() <= 7);
            todas.extend(textos(&lote));
        }
        assert_eq!(todas.len(), 1000);
        assert_eq!(todas[0], "linea-0");
        assert_eq!(todas[999], "linea-999");
    }

    #[test]
    fn un_reinicio_en_medio_de_un_lote_no_pierde_las_lineas_que_faltaban() {
        // La marca apunta a `inicio_resto` y no al desplazamiento del
        // descriptor, asi que reanudar vuelve a leer desde la linea siguiente a
        // la ultima ENTREGADA, no a la ultima leida del disco.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("lote.log");
        {
            let mut f = File::create(&ruta).unwrap();
            for i in 0..100 {
                writeln!(f, "linea-{i}").unwrap();
            }
        }
        let mut s = Seguidor::nuevo(&ruta);
        let primeras = textos(&s.leer(3).unwrap());
        assert_eq!(primeras, ["linea-0", "linea-1", "linea-2"]);
        let marca = s.marca().unwrap();
        drop(s);

        let mut s2 = Seguidor::reanudar(&ruta, marca).unwrap();
        let resto = textos(&s2.leer(1000).unwrap());
        assert_eq!(resto.len(), 97);
        assert_eq!(resto[0], "linea-3");
    }

    #[test]
    fn comprobar_dice_que_pasa_en_vez_de_dejar_la_ingesta_muda() {
        // El fallo mas comun al desplegar esto no es un error de programa: es que
        // el agente no tiene permiso, y el sintoma sin esto es «no llegan
        // eventos».
        let dir = tempfile::tempdir().unwrap();
        assert!(comprobar(&dir.path().join("no-existe.log")).is_err());
        assert!(comprobar(dir.path()).is_err(), "un directorio no se sigue");
        let ruta = dir.path().join("si.log");
        escribir(&ruta, "x\n");
        assert!(comprobar(&ruta).is_ok());
    }
}
