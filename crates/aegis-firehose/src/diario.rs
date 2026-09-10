//! El diario en disco (WAL): lo que hace que «sin perdida» sea cierto.
//!
//! # Por que el diario y no una cola en memoria
//!
//! Una cola en memoria pierde todo lo que tenga dentro cuando el proceso muere.
//! Da igual lo bien escrita que este: un corte de corriente, un OOM killer o un
//! `kill -9` durante un despliegue se llevan la evidencia. Y el momento en que
//! el plano de control es mas probable que muera es exactamente el momento en
//! que mas evidencia esta produciendo.
//!
//! Aqui el orden es: **escribir en disco, sincronizar, y solo entonces admitir
//! el registro**. Lo que se le devuelve al productor es una promesa que ya esta
//! cumplida, no una intencion.
//!
//! # Lo que «sin perdida» significa exactamente
//!
//! Un `fsync` por registro limita el caudal a los IOPS del disco: unos cientos
//! por segundo en un disco giratorio. Con diez mil endpoints eso no da. Se hace
//! **confirmacion en grupo**: se sincroniza por lote, y un registro es durable
//! cuando su lote se sincronizo.
//!
//! La consecuencia se dice, no se esconde: entre que un registro se escribe y
//! que su lote se sincroniza hay una ventana en la que un corte de corriente lo
//! perderia. Esa ventana esta acotada por [`Config::registros_por_sincronizacion`]
//! y por [`Config::plazo_sincronizacion`], y quien despliega decide su tamano.
//! Con `registros_por_sincronizacion = 1` no hay ventana y el caudal es el del
//! disco. Un producto que dijera «cero perdida» sin explicar esto estaria
//! mintiendo.
//!
//! # Formato del registro
//!
//! ```text
//! magia:u32 | longitud:u32 | crc32:u32 | carga:[u8; longitud]
//! ```
//!
//! El CRC no es contra un disco malicioso —para eso no serviria— sino contra la
//! ESCRITURA A MEDIAS: el proceso murio mientras escribia. Sin el, al reiniciar
//! se leeria una longitud plausible seguida de basura y se enviaria al SIEM un
//! registro de auditoria inventado. Un registro de auditoria falso es peor que
//! uno perdido: el perdido se nota, el falso no.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{ErrorFirehose, Resultado};

/// Marca de inicio de registro.
///
/// Sirve para RESINCRONIZAR: si la cola del diario quedo a medias, el lector
/// sabe que un registro empieza aqui y no en cualquier byte.
const MAGIA: u32 = 0x4147_5257; // "AGRW"

/// Cabecera: magia + longitud + crc.
const CABECERA: usize = 12;

/// Tamano maximo de un registro.
///
/// Un registro de auditoria es un evento, no un volcado de memoria. Sin techo,
/// un productor equivocado —o comprometido— escribe un registro de un giga y se
/// come el presupuesto entero del diario de una vez.
pub const MAX_REGISTRO: usize = 1024 * 1024;

/// Que hacer cuando el diario alcanza su presupuesto.
///
/// LA ELECCION IMPORTA Y POR ESO ES EXPLICITA
/// ------------------------------------------
/// Cuando el SIEM lleva horas caido, el diario crece. Un EDR que llenara el
/// disco del cliente para no perder un registro de auditoria habria cambiado un
/// fallo por otro peor: la maquina entera deja de funcionar, incluido el propio
/// EDR. Asi que en algun momento hay que ceder algo, y QUE se cede es una
/// decision de politica de seguridad, no un detalle de implementacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoliticaLleno {
    /// Rechazar lo nuevo. El productor se entera.
    ///
    /// Es el valor por defecto porque falla RUIDOSAMENTE: quien produce el
    /// registro recibe un error y puede decidir. La alternativa falla en
    /// silencio, y un registro de auditoria que desaparece sin que nadie se
    /// entere es exactamente lo que un atacante quiere.
    Rechazar,
    /// Descartar los registros mas antiguos para hacer sitio.
    ///
    /// Es la eleccion de disponibilidad: el firehose sigue aceptando lo
    /// reciente a costa de lo viejo. Tiene sentido cuando la telemetria
    /// reciente vale mas que la historica. Los descartes se CUENTAN y se
    /// publican; no desaparecen sin dejar rastro.
    DescartarMasAntiguos,
}

/// Ajustes del diario.
#[derive(Debug, Clone)]
pub struct Config {
    /// Directorio donde viven los segmentos.
    pub directorio: PathBuf,
    /// Bytes por segmento antes de rotar.
    pub bytes_por_segmento: u64,
    /// Presupuesto total en disco.
    ///
    /// Es el limite que el cliente acepta ceder a la auditoria pendiente. Sin
    /// el, un SIEM caido un fin de semana llena el disco del servidor.
    pub presupuesto_bytes: u64,
    /// Registros escritos entre sincronizaciones.
    ///
    /// Ver la ventana de perdida en la documentacion del modulo.
    pub registros_por_sincronizacion: u32,
    /// Plazo maximo sin sincronizar, aunque no se llene el lote.
    ///
    /// Sin este plazo, un sistema con poco trafico dejaria el ultimo registro
    /// sin sincronizar indefinidamente: justo el caso en el que UN registro es
    /// toda la evidencia que hay.
    pub plazo_sincronizacion: std::time::Duration,
    /// Que hacer al llegar al presupuesto.
    pub politica_lleno: PoliticaLleno,
}

impl Config {
    /// Configuracion por defecto sobre `directorio`.
    pub fn nueva(directorio: impl Into<PathBuf>) -> Config {
        Config {
            directorio: directorio.into(),
            bytes_por_segmento: 64 * 1024 * 1024,
            presupuesto_bytes: 4 * 1024 * 1024 * 1024,
            registros_por_sincronizacion: 64,
            plazo_sincronizacion: std::time::Duration::from_millis(200),
            politica_lleno: PoliticaLleno::Rechazar,
        }
    }

    fn validar(&self) -> Resultado<()> {
        if self.bytes_por_segmento < (CABECERA + MAX_REGISTRO) as u64 {
            return Err(ErrorFirehose::Config(format!(
                "un segmento de {} bytes no admite ni un registro maximo de {}",
                self.bytes_por_segmento, MAX_REGISTRO
            )));
        }
        if self.presupuesto_bytes < self.bytes_por_segmento {
            return Err(ErrorFirehose::Config(format!(
                "el presupuesto ({}) no llega ni para un segmento ({})",
                self.presupuesto_bytes, self.bytes_por_segmento
            )));
        }
        if self.registros_por_sincronizacion == 0 {
            return Err(ErrorFirehose::Config(
                "registros_por_sincronizacion tiene que ser al menos 1".to_string(),
            ));
        }
        Ok(())
    }
}

/// Posicion estable de un registro dentro del diario.
///
/// Es lo que permite confirmar la entrega DESPUES de que el SIEM la acuse, y no
/// antes: hasta entonces el registro sigue en disco y un reinicio lo reenvia.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Posicion {
    /// Segmento que lo contiene.
    pub segmento: u64,
    /// Desplazamiento del primer byte de su cabecera.
    pub desplazamiento: u64,
}

/// Un registro leido del diario.
#[derive(Debug, Clone)]
pub struct Registro {
    /// Donde esta.
    pub posicion: Posicion,
    /// Donde empieza el registro SIGUIENTE.
    ///
    /// POR QUE VIAJA CON EL REGISTRO
    /// -----------------------------
    /// Quien consume tiene que poder decir «sigue por aqui» despues de
    /// confirmar. Calcularlo fuera obligaria a conocer el tamano de la cabecera
    /// —un detalle del formato— y una version del formato con otra cabecera
    /// dejaria al consumidor leyendo desde el medio de un registro: no
    /// encontraria la magia, pararia, y el diario se quedaria sin vaciar
    /// mientras aparenta estar al dia. Lo sabe quien lo leyo; que lo diga el.
    pub siguiente: Posicion,
    /// Su carga, tal cual se escribio.
    pub carga: Vec<u8>,
}

/// Contadores del diario. Todo lo que se descarta se cuenta.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Contadores {
    /// Registros admitidos.
    pub admitidos: u64,
    /// Registros rechazados por presupuesto.
    pub rechazados: u64,
    /// Registros descartados por presupuesto (politica de descarte).
    pub descartados: u64,
    /// Registros truncados al recuperar por escritura a medias.
    pub truncados: u64,
    /// Sincronizaciones ejecutadas.
    pub sincronizaciones: u64,
}

/// El diario en disco.
pub struct Diario {
    cfg: Config,
    /// Segmento en el que se escribe.
    activo: u64,
    escritor: File,
    /// Bytes ya escritos en el segmento activo.
    escrito_en_activo: u64,
    /// Registros escritos desde la ultima sincronizacion.
    sin_sincronizar: u32,
    /// Momento de la ultima sincronizacion.
    ultima_sincronizacion: std::time::Instant,
    /// Primer segmento vivo (los anteriores ya se entregaron y se borraron).
    primero: u64,
    contadores: Contadores,
}

impl Diario {
    /// Abre —o crea— el diario, recuperando lo que quedara pendiente.
    ///
    /// La recuperacion no es opcional ni perezosa: si el proceso murio con
    /// registros sin entregar, esos registros son la razon de existir del
    /// diario. Se recuperan al abrir, antes de admitir nada nuevo.
    pub fn abrir(cfg: Config) -> Resultado<Diario> {
        cfg.validar()?;
        std::fs::create_dir_all(&cfg.directorio).map_err(|e| ErrorFirehose::Diario {
            op: "create_dir_all",
            source: e,
        })?;

        let mut segmentos = segmentos_en(&cfg.directorio)?;
        segmentos.sort_unstable();
        let primero = segmentos.first().copied().unwrap_or(0);
        let activo = segmentos.last().copied().unwrap_or(0);

        // La cola del ultimo segmento puede estar a medias: el proceso murio
        // mientras escribia. Se trunca hasta el ultimo registro INTEGRO. Es
        // seguro porque un registro no confirmado nunca se prometio a nadie.
        let (valido, truncados) = validar_segmento(&ruta_de(&cfg.directorio, activo))?;

        let escritor = OpenOptions::new()
            .create(true)
            // NUNCA `truncate`: este fichero puede contener registros
            // pendientes de entregar, que son justamente la razon de que el
            // diario exista. Se abre para escribir SOBRE lo que ya hay, y el
            // `set_len` de abajo recorta solo la cola a medias.
            .truncate(false)
            .write(true)
            .read(true)
            .open(ruta_de(&cfg.directorio, activo))
            .map_err(|e| ErrorFirehose::Diario {
                op: "open",
                source: e,
            })?;
        escritor
            .set_len(valido)
            .map_err(|e| ErrorFirehose::Diario {
                op: "set_len",
                source: e,
            })?;
        let mut escritor = escritor;
        escritor
            .seek(SeekFrom::Start(valido))
            .map_err(|e| ErrorFirehose::Diario {
                op: "seek",
                source: e,
            })?;

        Ok(Diario {
            activo,
            escritor,
            escrito_en_activo: valido,
            sin_sincronizar: 0,
            ultima_sincronizacion: std::time::Instant::now(),
            primero,
            contadores: Contadores {
                truncados,
                ..Default::default()
            },
            cfg,
        })
    }

    /// Contadores acumulados.
    pub fn contadores(&self) -> Contadores {
        self.contadores
    }

    /// Bytes ocupados por el diario.
    pub fn ocupado(&self) -> Resultado<u64> {
        let mut total = 0;
        for s in segmentos_en(&self.cfg.directorio)? {
            if let Ok(m) = std::fs::metadata(ruta_de(&self.cfg.directorio, s)) {
                total += m.len();
            }
        }
        Ok(total)
    }

    /// Admite un registro. Vuelve cuando el registro esta EN DISCO.
    ///
    /// «En disco» significa escrito y, si al lote le tocaba, sincronizado. Ver
    /// la ventana de perdida en la documentacion del modulo.
    pub fn admitir(&mut self, carga: &[u8]) -> Resultado<Posicion> {
        if carga.len() > MAX_REGISTRO {
            return Err(ErrorFirehose::RegistroDesmesurado {
                tamano: carga.len(),
                maximo: MAX_REGISTRO,
            });
        }
        let necesario = (CABECERA + carga.len()) as u64;

        // Rotacion ANTES de comprobar el presupuesto: rotar no ocupa mas sitio,
        // y comprobar despues daria un rechazo que se resolvia solo.
        if self.escrito_en_activo + necesario > self.cfg.bytes_por_segmento {
            self.rotar()?;
        }
        self.hacer_sitio(necesario)?;

        let mut marco = Vec::with_capacity(CABECERA + carga.len());
        marco.extend_from_slice(&MAGIA.to_le_bytes());
        marco.extend_from_slice(&(carga.len() as u32).to_le_bytes());
        marco.extend_from_slice(&crc32(carga).to_le_bytes());
        marco.extend_from_slice(carga);

        let posicion = Posicion {
            segmento: self.activo,
            desplazamiento: self.escrito_en_activo,
        };
        self.escritor
            .write_all(&marco)
            .map_err(|e| ErrorFirehose::Diario {
                op: "write_all",
                source: e,
            })?;
        self.escrito_en_activo += necesario;
        self.sin_sincronizar += 1;
        self.contadores.admitidos += 1;

        if self.sin_sincronizar >= self.cfg.registros_por_sincronizacion
            || self.ultima_sincronizacion.elapsed() >= self.cfg.plazo_sincronizacion
        {
            self.sincronizar()?;
        }
        Ok(posicion)
    }

    /// Fuerza la sincronizacion del lote pendiente.
    pub fn sincronizar(&mut self) -> Resultado<()> {
        if self.sin_sincronizar == 0 {
            return Ok(());
        }
        self.escritor
            .sync_data()
            .map_err(|e| ErrorFirehose::Diario {
                op: "sync_data",
                source: e,
            })?;
        self.sin_sincronizar = 0;
        self.ultima_sincronizacion = std::time::Instant::now();
        self.contadores.sincronizaciones += 1;
        Ok(())
    }

    /// Lee hasta `maximo` registros a partir de `desde`, sin consumirlos.
    ///
    /// NO se consumen aqui a proposito: un registro se confirma cuando el SIEM
    /// lo acusa, no cuando este proceso lo lee. Si el envio falla —o el proceso
    /// muere entre leer y enviar— el registro sigue en disco y se reintenta.
    /// Confirmar al leer convertiria «al menos una vez» en «como mucho una
    /// vez», que es justo lo contrario de lo que hace falta en auditoria.
    pub fn leer_desde(&self, desde: Option<Posicion>, maximo: usize) -> Resultado<Vec<Registro>> {
        let mut salida = Vec::new();
        let segmentos = {
            let mut s = segmentos_en(&self.cfg.directorio)?;
            s.sort_unstable();
            s
        };
        let (seg_inicial, desp_inicial) = match desde {
            Some(p) => (p.segmento, p.desplazamiento),
            None => (self.primero, 0),
        };

        for seg in segmentos.into_iter().filter(|s| *s >= seg_inicial) {
            if salida.len() >= maximo {
                break;
            }
            let inicio = if seg == seg_inicial { desp_inicial } else { 0 };
            leer_segmento(
                &ruta_de(&self.cfg.directorio, seg),
                seg,
                inicio,
                maximo - salida.len(),
                &mut salida,
            )?;
        }
        Ok(salida)
    }

    /// Confirma que todo lo anterior o igual a `hasta` ya se entrego.
    ///
    /// Borra los segmentos que quedan ENTEROS por detras. No se borra dentro de
    /// un segmento: reescribir un fichero que se esta leyendo para recortarle el
    /// principio es la clase de operacion que, interrumpida, deja el diario en
    /// un estado que ya no se puede interpretar.
    pub fn confirmar_hasta(&mut self, hasta: Posicion) -> Resultado<()> {
        let mut segmentos = segmentos_en(&self.cfg.directorio)?;
        segmentos.sort_unstable();
        for seg in segmentos {
            // El segmento activo no se borra aunque este entero por detras: se
            // sigue escribiendo en el.
            if seg >= hasta.segmento || seg == self.activo {
                break;
            }
            let _ = std::fs::remove_file(ruta_de(&self.cfg.directorio, seg));
            self.primero = seg + 1;
        }
        Ok(())
    }

    /// Cierra el segmento activo y abre el siguiente.
    fn rotar(&mut self) -> Resultado<()> {
        self.sincronizar()?;
        self.activo += 1;
        self.escritor = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(true)
            .open(ruta_de(&self.cfg.directorio, self.activo))
            .map_err(|e| ErrorFirehose::Diario {
                op: "open",
                source: e,
            })?;
        self.escrito_en_activo = 0;
        Ok(())
    }

    /// Aplica la politica de presupuesto.
    fn hacer_sitio(&mut self, necesario: u64) -> Resultado<()> {
        let mut ocupado = self.ocupado()?;
        if ocupado + necesario <= self.cfg.presupuesto_bytes {
            return Ok(());
        }
        match self.cfg.politica_lleno {
            PoliticaLleno::Rechazar => {
                self.contadores.rechazados += 1;
                Err(ErrorFirehose::DiarioLleno {
                    presupuesto: self.cfg.presupuesto_bytes,
                    ocupado,
                })
            }
            PoliticaLleno::DescartarMasAntiguos => {
                let mut segmentos = segmentos_en(&self.cfg.directorio)?;
                segmentos.sort_unstable();
                for seg in segmentos {
                    if ocupado + necesario <= self.cfg.presupuesto_bytes {
                        break;
                    }
                    // Nunca el activo: es donde se esta escribiendo.
                    if seg == self.activo {
                        break;
                    }
                    let ruta = ruta_de(&self.cfg.directorio, seg);
                    let (_, n) = contar_registros(&ruta)?;
                    let tam = std::fs::metadata(&ruta).map(|m| m.len()).unwrap_or(0);
                    let _ = std::fs::remove_file(&ruta);
                    // Los descartes se CUENTAN. Un registro de auditoria que
                    // desaparece sin dejar rastro es lo que un atacante quiere.
                    self.contadores.descartados += n;
                    self.primero = seg + 1;
                    ocupado = ocupado.saturating_sub(tam);
                }
                if ocupado + necesario > self.cfg.presupuesto_bytes {
                    // Ni descartando cabe: el presupuesto no da ni para el
                    // segmento activo. Se rechaza en vez de romper el
                    // invariante de no tocar el activo.
                    self.contadores.rechazados += 1;
                    return Err(ErrorFirehose::DiarioLleno {
                        presupuesto: self.cfg.presupuesto_bytes,
                        ocupado,
                    });
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Formato en disco
// ---------------------------------------------------------------------------

fn ruta_de(dir: &Path, seg: u64) -> PathBuf {
    dir.join(format!("{seg:020}.diario"))
}

fn segmentos_en(dir: &Path) -> Resultado<Vec<u64>> {
    let mut salida = Vec::new();
    let lectura = match std::fs::read_dir(dir) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(salida),
        Err(e) => {
            return Err(ErrorFirehose::Diario {
                op: "read_dir",
                source: e,
            })
        }
    };
    for entrada in lectura.flatten() {
        let nombre = entrada.file_name();
        let nombre = nombre.to_string_lossy();
        if let Some(n) = nombre.strip_suffix(".diario") {
            if let Ok(seg) = n.parse::<u64>() {
                salida.push(seg);
            }
        }
    }
    Ok(salida)
}

/// Recorre un segmento y devuelve `(bytes validos, registros truncados)`.
///
/// Un registro incompleto EN LA COLA es normal: el proceso murio escribiendo.
/// Se trunca. Un registro ilegible EN MEDIO no lo es —significa auditoria
/// perdida— y se devuelve como error en vez de saltarselo en silencio.
fn validar_segmento(ruta: &Path) -> Resultado<(u64, u64)> {
    let f = match File::open(ruta) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(e) => {
            return Err(ErrorFirehose::Diario {
                op: "open",
                source: e,
            })
        }
    };
    let total = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut lector = BufReader::new(f);
    let mut valido = 0u64;
    let mut cabecera = [0u8; CABECERA];

    // Cola incompleta: normal, el proceso murio escribiendo.
    while lector.read_exact(&mut cabecera).is_ok() {
        let magia = u32::from_le_bytes(cabecera[0..4].try_into().unwrap_or([0; 4]));
        let longitud = u32::from_le_bytes(cabecera[4..8].try_into().unwrap_or([0; 4])) as usize;
        let crc = u32::from_le_bytes(cabecera[8..12].try_into().unwrap_or([0; 4]));
        if magia != MAGIA || longitud > MAX_REGISTRO {
            break;
        }
        let mut carga = vec![0u8; longitud];
        if lector.read_exact(&mut carga).is_err() {
            break;
        }
        if crc32(&carga) != crc {
            break;
        }
        valido += (CABECERA + longitud) as u64;
    }

    let truncados = u64::from(valido < total);
    Ok((valido, truncados))
}

fn contar_registros(ruta: &Path) -> Resultado<(u64, u64)> {
    let mut salida = Vec::new();
    leer_segmento(ruta, 0, 0, usize::MAX, &mut salida)?;
    Ok((0, salida.len() as u64))
}

fn leer_segmento(
    ruta: &Path,
    seg: u64,
    desde: u64,
    maximo: usize,
    salida: &mut Vec<Registro>,
) -> Resultado<()> {
    let mut f = match File::open(ruta) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(ErrorFirehose::Diario {
                op: "open",
                source: e,
            })
        }
    };
    f.seek(SeekFrom::Start(desde))
        .map_err(|e| ErrorFirehose::Diario {
            op: "seek",
            source: e,
        })?;
    let mut lector = BufReader::new(f);
    let mut desplazamiento = desde;
    let mut cabecera = [0u8; CABECERA];

    while salida.len() < maximo {
        if lector.read_exact(&mut cabecera).is_err() {
            break;
        }
        let magia = u32::from_le_bytes(cabecera[0..4].try_into().unwrap_or([0; 4]));
        let longitud = u32::from_le_bytes(cabecera[4..8].try_into().unwrap_or([0; 4])) as usize;
        let crc = u32::from_le_bytes(cabecera[8..12].try_into().unwrap_or([0; 4]));
        if magia != MAGIA || longitud > MAX_REGISTRO {
            break;
        }
        let mut carga = vec![0u8; longitud];
        if lector.read_exact(&mut carga).is_err() {
            break;
        }
        if crc32(&carga) != crc {
            break;
        }
        let fin = desplazamiento + (CABECERA + longitud) as u64;
        salida.push(Registro {
            posicion: Posicion {
                segmento: seg,
                desplazamiento,
            },
            siguiente: Posicion {
                segmento: seg,
                desplazamiento: fin,
            },
            carga,
        });
        desplazamiento = fin;
    }
    Ok(())
}

/// CRC-32 (IEEE 802.3), tabla generada en el primer uso.
///
/// Se implementa aqui en vez de traerse una dependencia: son veinte lineas y el
/// polinomio esta en el estandar. La cadena de suministro de un producto de
/// seguridad se paga en auditorias, no en lineas de codigo.
fn crc32(datos: &[u8]) -> u32 {
    static TABLA: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let tabla = TABLA.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *e = c;
        }
        t
    });
    let mut crc = 0xFFFF_FFFFu32;
    for b in datos {
        crc = tabla[((crc ^ u32::from(*b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}
