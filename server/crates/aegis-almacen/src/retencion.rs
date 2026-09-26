//! Retencion por niveles, con su coste declarado.
//!
//! | Nivel | Que cambia | Que cuesta |
//! |---|---|---|
//! | caliente | deflate rapido, indices secundarios | la ingesta mas barata y la lectura mas rapida |
//! | tibio | cada columna se recomprime al nivel maximo; los indices secundarios se sueltan | menos disco; una busqueda por indice declarado barre ese dia (el coste lo declara) |
//! | frio | las columnas salen de PostgreSQL a un fichero por dia; se quedan los metadatos y el indice de entidad | lo minimo en la base; leer el dia es recorrer su fichero |
//! | mas alla | `DROP` de las particiones y borrado del fichero | nada |
//!
//! El indice de entidad no baja nunca de PostgreSQL: es lo que hace que «todo
//! lo de esta entidad» siga respondiendo en un dia frio sin recorrer los que no
//! la tienen.
//!
//! # Lo que llega tarde
//!
//! Una fila de un dia que ya es FRIO no se acepta: sus columnas ya estan en un
//! fichero y el dia tendria datos en dos sitios. Se rechaza con ese motivo. Un
//! dia tibio si la acepta: su particion de columnas sigue en la base.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::codec;
use crate::sql::{self, dia_de, nombre_particion, NS_DIA};
use crate::{Almacen, ErrorAlmacen};

/// Nivel de deflate al pasar a tibio.
pub const NIVEL_TIBIO: u8 = 9;

/// Cabecera de un fichero frio.
const MAGIA: &[u8; 12] = b"AEGISFRIO01\n";

/// Tope de un registro de un fichero frio.
const MAX_REGISTRO: u32 = 256 * 1024 * 1024;

/// Nivel de retencion de un dia.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Nivel {
    /// Recien ingerido.
    Caliente,
    /// Recomprimido, sin indices secundarios.
    Tibio,
    /// Fuera de PostgreSQL.
    Frio,
}

/// Cuantos dias pasa cada dato en cada nivel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retencion {
    /// Dias en caliente.
    pub caliente_dias: u32,
    /// Hasta cuantos dias de antiguedad en tibio.
    pub tibio_dias: u32,
    /// Hasta cuantos dias de antiguedad en frio; despues, se purga.
    pub frio_dias: u32,
}

impl Default for Retencion {
    fn default() -> Retencion {
        Retencion {
            caliente_dias: 7,
            tibio_dias: 30,
            frio_dias: 395,
        }
    }
}

impl Retencion {
    /// Comprueba que los niveles estan en orden.
    ///
    /// # Errors
    ///
    /// Si no lo estan.
    pub fn validar(&self) -> Result<(), ErrorAlmacen> {
        if self.caliente_dias >= 1
            && self.caliente_dias <= self.tibio_dias
            && self.tibio_dias <= self.frio_dias
            && self.frio_dias <= 3_660
        {
            Ok(())
        } else {
            Err(ErrorAlmacen::Configuracion(format!(
                "retencion no valida: hace falta 1 <= caliente ({}) <= tibio ({}) <= frio ({}) <= 3660",
                self.caliente_dias, self.tibio_dias, self.frio_dias
            )))
        }
    }

    /// El nivel que corresponde a un dia con esta antiguedad, o `None` si ya
    /// hay que purgarlo.
    #[must_use]
    pub fn nivel(&self, edad_dias: u32) -> Option<Nivel> {
        if edad_dias < self.caliente_dias {
            Some(Nivel::Caliente)
        } else if edad_dias < self.tibio_dias {
            Some(Nivel::Tibio)
        } else if edad_dias < self.frio_dias {
            Some(Nivel::Frio)
        } else {
            None
        }
    }
}

/// Lo que hizo una pasada de retencion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InformeRetencion {
    /// Dias que pasaron a tibio.
    pub a_tibio: Vec<i32>,
    /// Dias que pasaron a frio.
    pub a_frio: Vec<i32>,
    /// Dias purgados.
    pub purgados: Vec<i32>,
}

/// Lo que cuesta cada nivel ahora mismo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosteNivel {
    /// Nivel.
    pub nivel: Nivel,
    /// Dias en el.
    pub dias: usize,
    /// Bytes en PostgreSQL (tablas e indices de sus particiones).
    pub bytes_base: i64,
    /// Bytes en ficheros (solo el frio).
    pub bytes_fichero: u64,
}

fn crc32(b: &[u8]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for x in b {
        c ^= u32::from(*x);
        for _ in 0..8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// Escribe un registro: segmento, columna y bytes, con su CRC.
fn escribir_registro(w: &mut impl Write, seg: i64, col: &str, datos: &[u8]) -> std::io::Result<()> {
    let mut r = Vec::with_capacity(datos.len() + col.len() + 16);
    r.extend_from_slice(&seg.to_le_bytes());
    r.extend_from_slice(&u16::try_from(col.len()).unwrap_or(u16::MAX).to_le_bytes());
    r.extend_from_slice(col.as_bytes());
    r.extend_from_slice(datos);
    w.write_all(&u32::try_from(r.len()).unwrap_or(u32::MAX).to_le_bytes())?;
    w.write_all(&crc32(&r).to_le_bytes())?;
    w.write_all(&r)
}

/// Lee de un fichero frio los registros de unos segmentos y columnas.
///
/// Recorre el fichero entero: es el coste del nivel frio, y el plan lo declara.
///
/// # Errors
///
/// Si el fichero no existe, no empieza por la cabecera, o un registro no
/// cuadra con su CRC: un fichero frio alterado es un error, no un resultado a
/// medias.
pub fn leer_frio(
    ruta: &Path,
    segmentos: &[i64],
    columnas: &[String],
) -> Result<Vec<(i64, String, Vec<u8>)>, ErrorAlmacen> {
    let mut f = std::io::BufReader::new(std::fs::File::open(ruta)?);
    let mut magia = [0u8; 12];
    f.read_exact(&mut magia)?;
    if &magia != MAGIA {
        return Err(ErrorAlmacen::Configuracion(format!(
            "{} no es un fichero frio",
            ruta.display()
        )));
    }
    let quiero: std::collections::HashSet<i64> = segmentos.iter().copied().collect();
    let mut out = Vec::new();
    loop {
        let mut cab = [0u8; 8];
        match f.read_exact(&mut cab) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let largo = u32::from_le_bytes([cab[0], cab[1], cab[2], cab[3]]);
        let crc = u32::from_le_bytes([cab[4], cab[5], cab[6], cab[7]]);
        if !(10..=MAX_REGISTRO).contains(&largo) {
            return Err(ErrorAlmacen::Configuracion(format!(
                "{}: registro de {largo} bytes, fuera de rango",
                ruta.display()
            )));
        }
        let mut r = vec![0u8; largo as usize];
        f.read_exact(&mut r)?;
        if crc32(&r) != crc {
            return Err(ErrorAlmacen::Configuracion(format!(
                "{}: registro con CRC incorrecto",
                ruta.display()
            )));
        }
        let seg = i64::from_le_bytes(r[0..8].try_into().unwrap_or([0; 8]));
        let lc = usize::from(u16::from_le_bytes([r[8], r[9]]));
        let col = r
            .get(10..10 + lc)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .ok_or_else(|| {
                ErrorAlmacen::Configuracion(format!("{}: registro truncado", ruta.display()))
            })?;
        if quiero.contains(&seg) && columnas.contains(&col) {
            out.push((seg, col, r[10 + lc..].to_vec()));
        }
    }
    Ok(out)
}

impl Almacen {
    fn fichero_frio(&self, dia: i32) -> PathBuf {
        self.dir_frio
            .join(&self.esquema)
            .join(format!("d{dia}.frio"))
    }

    /// Aplica la retencion respecto a `ahora_ns`.
    ///
    /// # Errors
    ///
    /// Si PostgreSQL o el disco fallan. Cada dia se procesa en su propia
    /// transaccion: un fallo a medias deja los dias ya tratados tratados y el
    /// resto como estaba.
    pub async fn aplicar_retencion(&self, ahora_ns: u64) -> Result<InformeRetencion, ErrorAlmacen> {
        let hoy = dia_de(ahora_ns);
        let mut inf = InformeRetencion::default();
        for (dia, nivel, archivo) in sql::dias(&self.pool, &self.esquema).await? {
            let edad = u32::try_from(hoy.saturating_sub(dia).max(0)).unwrap_or(0);
            match self.retencion.nivel(edad) {
                None => {
                    sql::soltar_dia(&self.pool, &self.esquema, dia).await?;
                    if let Some(a) = archivo {
                        let _ = std::fs::remove_file(a);
                    }
                    inf.purgados.push(dia);
                }
                Some(Nivel::Frio) if nivel < 2 => {
                    if nivel < 1 {
                        self.a_tibio(dia).await?;
                    }
                    self.a_frio(dia).await?;
                    inf.a_frio.push(dia);
                }
                Some(Nivel::Tibio) if nivel < 1 => {
                    self.a_tibio(dia).await?;
                    inf.a_tibio.push(dia);
                }
                _ => {}
            }
        }
        Ok(inf)
    }

    /// Caliente a tibio: recomprime al nivel maximo y suelta los secundarios.
    async fn a_tibio(&self, dia: i32) -> Result<(), ErrorAlmacen> {
        let s = &self.esquema;
        let mut tx = self.pool.begin().await?;
        let filas: Vec<(i64, String, Vec<u8>)> = sqlx::query_as(&format!(
            "SELECT segmento, columna, datos FROM {s}.columnas WHERE dia = DATE '1970-01-01' + $1"
        ))
        .bind(dia)
        .fetch_all(&mut *tx)
        .await?;
        for (seg, col, datos) in filas {
            let valores = codec::decodificar(&datos)?;
            let tipo = tipo_de_columna(&valores);
            let b = codec::codificar(tipo, &valores, NIVEL_TIBIO);
            sqlx::query(&format!(
                "UPDATE {s}.columnas SET datos = $1 WHERE dia = DATE '1970-01-01' + $2 AND segmento = $3 AND columna = $4"
            ))
            .bind(&b.datos)
            .bind(dia)
            .bind(seg)
            .bind(&col)
            .execute(&mut *tx)
            .await?;
        }
        let p = nombre_particion("secundarios", dia);
        sqlx::raw_sql(&format!("DROP TABLE IF EXISTS {s}.{p}"))
            .execute(&mut *tx)
            .await?;
        // La particion de secundarios se recrea vacia: una fila tardia de un dia
        // tibio se acepta, y su insercion necesita donde caer.
        sqlx::raw_sql(&format!(
            "CREATE TABLE {s}.{p} PARTITION OF {s}.secundarios \
             FOR VALUES FROM (DATE '1970-01-01' + {dia}) TO (DATE '1970-01-01' + {})",
            dia + 1
        ))
        .execute(&mut *tx)
        .await?;
        sqlx::query(&format!(
            "UPDATE {s}.particiones SET nivel = 1 WHERE dia = DATE '1970-01-01' + $1"
        ))
        .bind(dia)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        // El espacio que libera la recompresion lo recupera el vacio.
        sqlx::raw_sql(&format!("VACUUM {s}.{}", nombre_particion("columnas", dia)))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Tibio a frio: las columnas del dia a un fichero, y su particion fuera.
    async fn a_frio(&self, dia: i32) -> Result<(), ErrorAlmacen> {
        let s = &self.esquema;
        let ruta = self.fichero_frio(dia);
        if let Some(d) = ruta.parent() {
            std::fs::create_dir_all(d)?;
        }
        let filas: Vec<(i64, String, Vec<u8>)> = sqlx::query_as(&format!(
            "SELECT segmento, columna, datos FROM {s}.columnas WHERE dia = DATE '1970-01-01' + $1 ORDER BY segmento, columna"
        ))
        .bind(dia)
        .fetch_all(&self.pool)
        .await?;
        // Se escribe a un temporal, se sincroniza y se renombra: un corte a
        // medias no deja un fichero frio incompleto con el nombre bueno.
        let tmp = ruta.with_extension("frio.tmp");
        {
            let mut w = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
            w.write_all(MAGIA)?;
            for (seg, col, datos) in &filas {
                escribir_registro(&mut w, *seg, col, datos)?;
            }
            w.flush()?;
            w.get_ref().sync_all()?;
        }
        std::fs::rename(&tmp, &ruta)?;
        let mut tx = self.pool.begin().await?;
        let p = nombre_particion("columnas", dia);
        sqlx::raw_sql(&format!("DROP TABLE IF EXISTS {s}.{p}"))
            .execute(&mut *tx)
            .await?;
        sqlx::query(&format!(
            "UPDATE {s}.particiones SET nivel = 2, archivo = $2 WHERE dia = DATE '1970-01-01' + $1"
        ))
        .bind(dia)
        .bind(ruta.to_string_lossy().into_owned())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Lo que ocupa cada nivel ahora mismo.
    ///
    /// # Errors
    ///
    /// Si PostgreSQL falla.
    pub async fn coste_por_nivel(&self) -> Result<Vec<CosteNivel>, ErrorAlmacen> {
        let mut v = vec![
            CosteNivel {
                nivel: Nivel::Caliente,
                dias: 0,
                bytes_base: 0,
                bytes_fichero: 0,
            },
            CosteNivel {
                nivel: Nivel::Tibio,
                dias: 0,
                bytes_base: 0,
                bytes_fichero: 0,
            },
            CosteNivel {
                nivel: Nivel::Frio,
                dias: 0,
                bytes_base: 0,
                bytes_fichero: 0,
            },
        ];
        for (dia, nivel, archivo) in sql::dias(&self.pool, &self.esquema).await? {
            let k = usize::try_from(nivel).unwrap_or(0).min(2);
            v[k].dias += 1;
            v[k].bytes_base += sql::bytes_dia(&self.pool, &self.esquema, dia).await?;
            if let Some(a) = archivo {
                v[k].bytes_fichero += std::fs::metadata(a).map(|m| m.len()).unwrap_or(0);
            }
        }
        Ok(v)
    }
}

/// El tipo de una columna a partir de sus valores (para recodificarla).
fn tipo_de_columna(v: &[aegis_parser::valor::Valor]) -> aegis_parser::esquema::Tipo {
    use aegis_parser::esquema::Tipo;
    use aegis_parser::valor::Valor;
    for x in v {
        match x {
            Valor::Entero(_) => return Tipo::Entero,
            Valor::Real(_) => return Tipo::Real,
            Valor::Texto(_) => return Tipo::Texto,
            Valor::Booleano(_) => return Tipo::Booleano,
            Valor::Ausente => {}
        }
    }
    Tipo::Texto
}

/// Dias de un intervalo, para las pruebas y el informe.
#[must_use]
pub fn dias_de(desde_ns: u64, hasta_ns: u64) -> u64 {
    hasta_ns.saturating_sub(desde_ns).div_ceil(NS_DIA)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn los_niveles_por_edad() {
        let r = Retencion::default();
        assert_eq!(r.nivel(0), Some(Nivel::Caliente));
        assert_eq!(r.nivel(7), Some(Nivel::Tibio));
        assert_eq!(r.nivel(30), Some(Nivel::Frio));
        assert_eq!(r.nivel(395), None);
        assert!(Retencion {
            caliente_dias: 10,
            tibio_dias: 5,
            frio_dias: 20
        }
        .validar()
        .is_err());
        assert!(Retencion {
            caliente_dias: 0,
            tibio_dias: 5,
            frio_dias: 20
        }
        .validar()
        .is_err());
    }

    #[test]
    fn un_fichero_frio_alterado_es_un_error() {
        let d = std::env::temp_dir().join(format!("aegis-frio-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("x.frio");
        let mut b = MAGIA.to_vec();
        escribir_registro(&mut b, 7, "name", b"datos").unwrap();
        escribir_registro(&mut b, 8, "pid", b"otros").unwrap();
        std::fs::write(&f, &b).unwrap();
        let r = leer_frio(&f, &[7], &["name".into()]).unwrap();
        assert_eq!(r, vec![(7, "name".to_string(), b"datos".to_vec())]);
        let n = b.len();
        b[n - 2] ^= 0xff;
        std::fs::write(&f, &b).unwrap();
        assert!(leer_frio(&f, &[7, 8], &["name".into(), "pid".into()]).is_err());
        std::fs::write(&f, &b[..n - 3]).unwrap();
        assert!(leer_frio(&f, &[7], &["name".into()]).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
