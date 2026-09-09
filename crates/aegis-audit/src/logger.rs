//! El registro de auditoria: SQLite embebida, cuerpos cifrados, rotacion.
//!
//! # Modelo de amenaza, explicito
//!
//! Los METADATOS (instante, gravedad, tipo, actor) se guardan en claro para
//! poder consultar e indexar sin descifrar nada. El CUERPO —donde van rutas,
//! lineas de comando y demas detalle sensible— se cifra con AES-256-GCM por
//! fila. Es un compromiso deliberado, no un descuido: un atacante con el fichero
//! ve la FORMA de la actividad (cuantos incidentes, cuando, de que tipo) pero no
//! su CONTENIDO. Cifrar tambien los metadatos (como haria SQLCipher a nivel de
//! pagina) impediria consultar sin la clave, que es justo lo que el agente
//! necesita hacer en caliente. Se elige poder consultar y proteger el detalle.
//!
//! # Rotacion
//!
//! El registro no puede crecer sin limite en el disco del usuario. Cuando el
//! fichero supera el tamano maximo, se **sella** (se renombra con su secuencia)
//! y se abre uno nuevo. Se conserva un numero acotado de segmentos sellados; los
//! mas antiguos se borran. Asi el coste en disco esta acotado por diseno.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension};
use zeroize::Zeroize;

use crate::crypto::{self, RowId};
use crate::event::{AuditEvent, Severity, StoredEvent};

/// Error del registro de auditoria.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// Error de la base de datos.
    #[error("error de la base de datos de auditoria: {0}")]
    Db(#[from] rusqlite::Error),
    /// Error de entrada/salida al rotar o abrir ficheros.
    #[error("error de E/S en el registro de auditoria: {0}")]
    Io(#[from] std::io::Error),
    /// Un cuerpo cifrado no se pudo descifrar.
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    /// Los metadatos de una fila son incoherentes (gravedad fuera de rango).
    #[error("fila {0} con metadatos corruptos")]
    CorruptRow(i64),
}

/// Configuracion del registro.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Tamano maximo del fichero activo antes de rotar, en bytes.
    pub max_bytes: u64,
    /// Numero maximo de segmentos sellados que se conservan.
    pub max_segments: usize,
    /// Cada cuantas escrituras se comprueba el tamano para decidir si rotar.
    ///
    /// Comprobar el tamano del fichero en cada evento seria una llamada al
    /// sistema por evento; hacerlo cada N amortiza el coste sin dejar que el
    /// fichero se pase mas de un lote del limite.
    pub check_every: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            // 100 MB, el limite que fija el presupuesto de disco del producto.
            max_bytes: 100 * 1024 * 1024,
            max_segments: 8,
            check_every: 256,
        }
    }
}

/// Registro de auditoria local.
pub struct AuditLogger {
    dir: PathBuf,
    base: String,
    key: [u8; 32],
    config: AuditConfig,
    conn: Connection,
    /// Secuencia del segmento activo. Forma parte del nonce, asi que tiene que
    /// ser monotona y no repetirse jamas.
    segment: u32,
    /// Filas escritas en el segmento activo.
    filas: i64,
    /// Escrituras desde la ultima comprobacion de tamano.
    desde_chequeo: u64,
    /// Escrituras totales, para diagnostico.
    total: u64,
}

impl AuditLogger {
    /// Abre (o crea) el registro en `dir`, con ficheros `base-<segmento>.db`.
    ///
    /// La clave se copia y la copia del llamante se puede poner a cero: el
    /// registro es su unico dueno mientras vive.
    pub fn open(
        dir: impl AsRef<Path>,
        base: impl Into<String>,
        key: [u8; 32],
        config: AuditConfig,
    ) -> Result<AuditLogger, AuditError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let base = base.into();

        // El segmento activo es el de secuencia mas alta ya presente, o 0.
        let segment = Self::max_segment(&dir, &base).unwrap_or(0);
        let ruta = Self::segment_path(&dir, &base, segment);
        let conn = Self::abrir_conexion(&ruta)?;
        let filas: i64 = conn
            .query_row("SELECT COUNT(*) FROM eventos", [], |r| r.get(0))
            .optional()?
            .unwrap_or(0);

        Ok(AuditLogger {
            dir,
            base,
            key,
            config,
            conn,
            segment,
            filas,
            desde_chequeo: 0,
            total: 0,
        })
    }

    fn abrir_conexion(ruta: &Path) -> Result<Connection, AuditError> {
        let conn = Connection::open(ruta)?;
        // WAL para que las escrituras no bloqueen las lecturas de la consola, y
        // NORMAL para no pagar un fsync por evento: un registro de auditoria
        // prioriza no frenar la deteccion sobre no perder el ultimo evento ante
        // un corte de corriente.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS eventos (
                id       INTEGER PRIMARY KEY,
                ts_ns    INTEGER NOT NULL,
                severity INTEGER NOT NULL,
                kind     TEXT    NOT NULL,
                actor    INTEGER NOT NULL,
                nonce    BLOB    NOT NULL,
                cuerpo   BLOB    NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_eventos_ts ON eventos(ts_ns)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_eventos_sev ON eventos(severity)",
            [],
        )?;
        Ok(conn)
    }

    fn segment_path(dir: &Path, base: &str, seq: u32) -> PathBuf {
        dir.join(format!("{base}-{seq:06}.db"))
    }

    fn max_segment(dir: &Path, base: &str) -> Option<u32> {
        let prefijo = format!("{base}-");
        let mut max = None;
        for e in std::fs::read_dir(dir).ok()?.flatten() {
            let nombre = e.file_name();
            let n = nombre.to_string_lossy();
            if let Some(resto) = n.strip_prefix(&prefijo) {
                if let Some(num) = resto.strip_suffix(".db") {
                    if let Ok(seq) = num.parse::<u32>() {
                        max = Some(max.map_or(seq, |m: u32| m.max(seq)));
                    }
                }
            }
        }
        max
    }

    /// Registra un evento, cifrando su cuerpo. Devuelve el id asignado.
    pub fn log(&mut self, ev: &AuditEvent) -> Result<i64, AuditError> {
        let id = self.filas + 1;
        let row = RowId {
            id,
            segment: self.segment,
            ts_ns: ev.ts_ns,
            actor: ev.actor,
            kind: &ev.kind,
        };
        let cuerpo = crypto::encrypt_body(&self.key, row, &ev.detail);
        let nonce = row.nonce();

        self.conn.execute(
            "INSERT INTO eventos (id, ts_ns, severity, kind, actor, nonce, cuerpo)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                id,
                ev.ts_ns as i64,
                ev.severity.as_i64(),
                ev.kind,
                ev.actor as i64,
                nonce.to_vec(),
                cuerpo,
            ],
        )?;
        self.filas = id;
        self.total += 1;
        self.desde_chequeo += 1;

        if self.desde_chequeo >= self.config.check_every {
            self.desde_chequeo = 0;
            self.rotar_si_procede()?;
        }
        Ok(id)
    }

    /// Comprueba el tamano del fichero activo y rota si supera el limite.
    fn rotar_si_procede(&mut self) -> Result<(), AuditError> {
        let ruta = Self::segment_path(&self.dir, &self.base, self.segment);
        let tam = std::fs::metadata(&ruta).map(|m| m.len()).unwrap_or(0);
        if tam < self.config.max_bytes {
            return Ok(());
        }
        self.rotar()
    }

    /// Fuerza una rotacion: sella el segmento activo y abre el siguiente.
    pub fn rotar(&mut self) -> Result<(), AuditError> {
        // Al cerrar el WAL hay que hacer checkpoint para que el .db quede
        // autonomo antes de dejarlo como segmento sellado.
        self.conn
            .pragma_update(None, "wal_checkpoint", "TRUNCATE")?;

        self.segment = self.segment.checked_add(1).expect(
            "desbordamiento de la secuencia de segmentos: 4.000 millones de \
             rotaciones es un imposible operativo, y reutilizar una secuencia \
             reutilizaria nonces",
        );
        let nueva = Self::segment_path(&self.dir, &self.base, self.segment);
        self.conn = Self::abrir_conexion(&nueva)?;
        self.filas = 0;

        self.podar_segmentos()?;
        Ok(())
    }

    /// Borra los segmentos sellados mas antiguos que exceden `max_segments`.
    fn podar_segmentos(&self) -> Result<(), AuditError> {
        let mut seqs: Vec<u32> = Vec::new();
        let prefijo = format!("{}-", self.base);
        for e in std::fs::read_dir(&self.dir)?.flatten() {
            let nombre = e.file_name();
            let n = nombre.to_string_lossy();
            if let Some(resto) = n.strip_prefix(&prefijo) {
                if let Some(num) = resto.strip_suffix(".db") {
                    if let Ok(seq) = num.parse::<u32>() {
                        seqs.push(seq);
                    }
                }
            }
        }
        seqs.sort_unstable();
        // Se conservan los `max_segments` mas recientes (incluido el activo).
        if seqs.len() > self.config.max_segments {
            let a_borrar = seqs.len() - self.config.max_segments;
            for seq in &seqs[..a_borrar] {
                let ruta = Self::segment_path(&self.dir, &self.base, *seq);
                // Se borran tambien los ficheros auxiliares del WAL.
                let _ = std::fs::remove_file(&ruta);
                let _ = std::fs::remove_file(ruta.with_extension("db-wal"));
                let _ = std::fs::remove_file(ruta.with_extension("db-shm"));
            }
        }
        Ok(())
    }

    /// Lee los eventos del segmento activo con gravedad al menos `minima`,
    /// descifrando cada cuerpo.
    pub fn query_active(&self, minima: Severity) -> Result<Vec<StoredEvent>, AuditError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts_ns, severity, kind, actor, cuerpo
             FROM eventos WHERE severity >= ?1 ORDER BY id",
        )?;
        let filas = stmt.query_map([minima.as_i64()], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        })?;

        let mut salida = Vec::new();
        for fila in filas {
            let (id, ts, sev, kind, actor, cuerpo) = fila?;
            let severity = Severity::from_i64(sev).ok_or(AuditError::CorruptRow(id))?;
            let row = RowId {
                id,
                segment: self.segment,
                ts_ns: ts as u64,
                actor: actor as u64,
                kind: &kind,
            };
            let detail = crypto::decrypt_body(&self.key, row, &cuerpo)?;
            salida.push(StoredEvent {
                id,
                event: AuditEvent {
                    ts_ns: ts as u64,
                    severity,
                    kind,
                    actor: actor as u64,
                    detail,
                },
            });
        }
        Ok(salida)
    }

    /// Secuencia del segmento activo.
    pub fn segment(&self) -> u32 {
        self.segment
    }

    /// Filas en el segmento activo.
    pub fn active_rows(&self) -> i64 {
        self.filas
    }

    /// Eventos escritos desde que se abrio el registro.
    pub fn total_written(&self) -> u64 {
        self.total
    }

    /// Ficheros de segmento presentes en el directorio, ordenados.
    pub fn segments_on_disk(&self) -> Vec<u32> {
        let mut seqs = Vec::new();
        let prefijo = format!("{}-", self.base);
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let nombre = e.file_name();
                let n = nombre.to_string_lossy();
                if let Some(resto) = n.strip_prefix(&prefijo) {
                    if let Some(num) = resto.strip_suffix(".db") {
                        if let Ok(seq) = num.parse::<u32>() {
                            seqs.push(seq);
                        }
                    }
                }
            }
        }
        seqs.sort_unstable();
        seqs
    }
}

impl Drop for AuditLogger {
    fn drop(&mut self) {
        // La clave se borra de la memoria al cerrar el registro.
        self.key.zeroize();
        // Checkpoint de cortesia para que el ultimo lote llegue al .db.
        let _ = self.conn.pragma_update(None, "wal_checkpoint", "TRUNCATE");
    }
}

impl std::fmt::Debug for AuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogger")
            .field("dir", &self.dir)
            .field("base", &self.base)
            .field("segment", &self.segment)
            .field("filas_activas", &self.filas)
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}
