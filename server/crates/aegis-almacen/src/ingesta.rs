//! La entrada al almacen: filas validadas, segmentos columnares e indices.
//!
//! # Una fila que no cuadra con su esquema es un error, no una conversion
//!
//! El almacen promete que una consulta significa lo mismo contra el vivo y
//! contra el historico. Si aceptara un texto donde el esquema dice entero —y lo
//! convirtiera, o lo guardara como ausente—, la misma consulta daria respuestas
//! distintas en los dos sitios. Por eso se valida CADA valor contra el tipo de su
//! columna antes de escribir nada, y un lote con una sola fila mala se rechaza
//! entero, con la fila y la columna.
//!
//! # Un dia, una transaccion
//!
//! Cada dia del lote se escribe en una transaccion: el segmento, sus columnas, su
//! indice de entidades y sus secundarios declarados entran juntos o no entra
//! ninguno. Un segmento a medias —columnas sin indice, o indice sin columnas— es
//! una fila que existe y no se encuentra, o que se encuentra y no se puede leer.

use std::collections::{BTreeMap, BTreeSet};

use aegis_ingest::esquema::Evento;
use aegis_parser::esquema::{historico as cat, Tipo};
use aegis_parser::valor::Valor;

use crate::codec::{self, Bloque};
use crate::sql::{self, dia_de};
use crate::{
    columnas_de_segmento, columnas_guardadas, Almacen, ErrorAlmacen, FilaEntrada, SEGMENTO_FILAS,
};

/// Nivel de deflate de la ingesta (retencion caliente): rapido.
pub const NIVEL_CALIENTE: u8 = 1;

/// Lo que hizo una ingesta.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InformeIngesta {
    /// Filas escritas.
    pub filas: u64,
    /// Segmentos creados.
    pub segmentos: u64,
    /// Dias tocados.
    pub dias: u64,
    /// Bytes de las columnas antes de comprimir.
    pub bytes_crudos: u64,
    /// Bytes de las columnas comprimidas.
    pub bytes_comprimidos: u64,
}

fn tipo_de(v: &Valor) -> Option<Tipo> {
    match v {
        Valor::Entero(_) => Some(Tipo::Entero),
        Valor::Real(_) => Some(Tipo::Real),
        Valor::Texto(_) => Some(Tipo::Texto),
        Valor::Booleano(_) => Some(Tipo::Booleano),
        Valor::Ausente => None,
    }
}

impl Almacen {
    /// Ingiere filas de una tabla.
    ///
    /// # Errors
    ///
    /// [`ErrorAlmacen::Filas`] si alguna fila no cuadra con el esquema; y los
    /// de PostgreSQL.
    pub async fn ingerir(
        &self,
        tabla: &str,
        filas: Vec<FilaEntrada>,
    ) -> Result<InformeIngesta, ErrorAlmacen> {
        let t = cat::tabla(tabla).ok_or_else(|| ErrorAlmacen::Filas {
            tabla: tabla.into(),
            motivo: "la tabla no existe en el historico".into(),
        })?;
        let cols = columnas_guardadas(t);
        for (i, f) in filas.iter().enumerate() {
            if f.valores.len() != cols.len() {
                return Err(ErrorAlmacen::Filas {
                    tabla: tabla.into(),
                    motivo: format!(
                        "la fila {i} trae {} valores y la tabla guarda {} columnas",
                        f.valores.len(),
                        cols.len()
                    ),
                });
            }
            for (c, v) in cols.iter().zip(&f.valores) {
                if let Some(tv) = tipo_de(v) {
                    if tv != c.tipo {
                        return Err(ErrorAlmacen::Filas {
                            tabla: tabla.into(),
                            motivo: format!(
                                "la fila {i} trae {} en '{}', que es {}",
                                tv.nombre(),
                                c.nombre,
                                c.tipo.nombre()
                            ),
                        });
                    }
                }
            }
        }
        let declarados: BTreeSet<String> = self.indices_de(tabla).await?.into_iter().collect();

        let mut por_dia: BTreeMap<i32, Vec<FilaEntrada>> = BTreeMap::new();
        for f in filas {
            por_dia.entry(dia_de(f.ts_ns)).or_default().push(f);
        }
        let mut informe = InformeIngesta::default();
        let esquema_seg = columnas_de_segmento(t);
        for (dia, mut filas) in por_dia {
            // DENTRO DEL DIA, POR ENTIDAD Y LUEGO POR TIEMPO. La primera version
            // ordenaba solo por tiempo, y cada segmento de ocho mil filas acababa
            // con filas de casi todas las entidades: medido con 500 anfitriones,
            // «todo de una entidad en siete dias» usaba el indice y leia 272 de
            // 273 segmentos. Agrupadas por entidad, las filas de una entidad caen
            // en pocos segmentos y el indice primario —la razon de ser de este
            // almacen— elige de verdad. Lo que se cede es el mapa de zona temporal
            // DENTRO del dia; la particion diaria sigue acotando el tiempo.
            filas.sort_by_cached_key(|f| {
                (f.entidad.as_ref().map(aegis_entidad::Eid::texto), f.ts_ns)
            });
            self.escribir_dia(tabla, dia, &filas, &esquema_seg, &declarados, &mut informe)
                .await?;
            informe.dias += 1;
        }
        Ok(informe)
    }

    async fn escribir_dia(
        &self,
        tabla: &str,
        dia: i32,
        filas: &[FilaEntrada],
        esquema_seg: &[(&'static str, Tipo)],
        declarados: &BTreeSet<String>,
        informe: &mut InformeIngesta,
    ) -> Result<(), ErrorAlmacen> {
        let s = &self.esquema;
        let mut tx = self.pool.begin().await?;
        sql::asegurar_dia(&mut tx, s, dia).await?;
        let trozos: Vec<&[FilaEntrada]> = filas.chunks(SEGMENTO_FILAS).collect();
        let ids: Vec<i64> = sqlx::query_scalar(&format!(
            "SELECT nextval('{s}.segmento_id') FROM generate_series(1, $1)"
        ))
        .bind(i32::try_from(trozos.len()).unwrap_or(i32::MAX))
        .fetch_all(&mut *tx)
        .await?;

        // Columnas de las inserciones masivas.
        let (mut sg_id, mut sg_min, mut sg_max, mut sg_filas) = (vec![], vec![], vec![], vec![]);
        let (mut c_seg, mut c_col, mut c_datos, mut c_min, mut c_max, mut c_crudos) =
            (vec![], vec![], vec![], vec![], vec![], vec![]);
        let (mut e_ent, mut e_seg, mut e_min, mut e_max) = (vec![], vec![], vec![], vec![]);
        let (mut s_col, mut s_val, mut s_seg) = (vec![], vec![], vec![]);

        for (trozo, id) in trozos.iter().zip(&ids) {
            // Con el orden por entidad, la primera y la ultima fila ya no son el
            // minimo y el maximo del tiempo: se calculan.
            let ts_min = trozo.iter().map(|f| f.ts_ns).min().unwrap_or(0);
            let ts_max = trozo.iter().map(|f| f.ts_ns).max().unwrap_or(0);
            sg_id.push(*id);
            sg_min.push(ts_a_i64(ts_min));
            sg_max.push(ts_a_i64(ts_max));
            sg_filas.push(i32::try_from(trozo.len()).unwrap_or(i32::MAX));

            // Indice primario: cada entidad del segmento con su tramo de tiempo.
            let mut entidades: BTreeMap<String, (u64, u64)> = BTreeMap::new();
            for f in trozo.iter() {
                if let Some(e) = &f.entidad {
                    let r = entidades.entry(e.texto()).or_insert((f.ts_ns, f.ts_ns));
                    r.0 = r.0.min(f.ts_ns);
                    r.1 = r.1.max(f.ts_ns);
                }
            }
            for (e, (a, b)) in entidades {
                e_ent.push(e);
                e_seg.push(*id);
                e_min.push(ts_a_i64(a));
                e_max.push(ts_a_i64(b));
            }

            for (k, (nombre, tipo)) in esquema_seg.iter().enumerate() {
                let valores: Vec<Valor> = trozo
                    .iter()
                    .map(|f| match k {
                        0 => Valor::Entero(ts_a_i64(f.ts_ns)),
                        1 => f
                            .entidad
                            .as_ref()
                            .map_or(Valor::Ausente, |e| Valor::Texto(e.texto())),
                        _ => f.valores[k - 2].clone(),
                    })
                    .collect();
                if declarados.contains(*nombre) {
                    let distintos: BTreeSet<String> = valores
                        .iter()
                        .filter(|v| !v.es_ausente())
                        .map(Valor::a_texto)
                        .collect();
                    for v in distintos {
                        s_col.push((*nombre).to_string());
                        s_val.push(v);
                        s_seg.push(*id);
                    }
                }
                let Bloque {
                    datos,
                    minimo,
                    maximo,
                    crudos,
                } = codec::codificar(*tipo, &valores, NIVEL_CALIENTE);
                informe.bytes_crudos += crudos as u64;
                informe.bytes_comprimidos += datos.len() as u64;
                c_seg.push(*id);
                c_col.push((*nombre).to_string());
                c_datos.push(datos);
                c_min.push(minimo);
                c_max.push(maximo);
                c_crudos.push(i32::try_from(crudos).unwrap_or(i32::MAX));
            }
            informe.filas += trozo.len() as u64;
            informe.segmentos += 1;
        }

        sqlx::query(&format!(
            "INSERT INTO {s}.segmentos (dia, id, tabla, ts_min, ts_max, filas) \
             SELECT DATE '1970-01-01' + $1, i, $2, a, b, n \
             FROM UNNEST($3::bigint[], $4::bigint[], $5::bigint[], $6::int[]) AS t(i, a, b, n)"
        ))
        .bind(dia)
        .bind(tabla)
        .bind(&sg_id)
        .bind(&sg_min)
        .bind(&sg_max)
        .bind(&sg_filas)
        .execute(&mut *tx)
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {s}.columnas (dia, segmento, columna, datos, minimo, maximo, crudos) \
             SELECT DATE '1970-01-01' + $1, g, c, d, a, b, n \
             FROM UNNEST($2::bigint[], $3::text[], $4::bytea[], $5::bigint[], $6::bigint[], $7::int[]) \
             AS t(g, c, d, a, b, n)"
        ))
        .bind(dia)
        .bind(&c_seg)
        .bind(&c_col)
        .bind(&c_datos)
        .bind(&c_min)
        .bind(&c_max)
        .bind(&c_crudos)
        .execute(&mut *tx)
        .await?;
        if !e_ent.is_empty() {
            sqlx::query(&format!(
                "INSERT INTO {s}.entidades (dia, entidad, tabla, segmento, ts_min, ts_max) \
                 SELECT DATE '1970-01-01' + $1, e, $2, g, a, b \
                 FROM UNNEST($3::text[], $4::bigint[], $5::bigint[], $6::bigint[]) AS t(e, g, a, b)"
            ))
            .bind(dia)
            .bind(tabla)
            .bind(&e_ent)
            .bind(&e_seg)
            .bind(&e_min)
            .bind(&e_max)
            .execute(&mut *tx)
            .await?;
        }
        if !s_col.is_empty() {
            sqlx::query(&format!(
                "INSERT INTO {s}.secundarios (dia, tabla, columna, valor, segmento) \
                 SELECT DATE '1970-01-01' + $1, $2, c, v, g \
                 FROM UNNEST($3::text[], $4::text[], $5::bigint[]) AS t(c, v, g)"
            ))
            .bind(dia)
            .bind(tabla)
            .bind(&s_col)
            .bind(&s_val)
            .bind(&s_seg)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Ingiere eventos normalizados de la ingesta en la tabla `events`.
    ///
    /// Un evento no es de ninguna entidad del modelo por si mismo; si la ingesta
    /// lo atribuye, se le pasa en `entidad`.
    ///
    /// # Errors
    ///
    /// Los de [`Almacen::ingerir`].
    pub async fn ingerir_eventos(
        &self,
        eventos: &[Evento],
    ) -> Result<InformeIngesta, ErrorAlmacen> {
        let filas = eventos
            .iter()
            .map(|e| FilaEntrada {
                ts_ns: e.ocurrio_ns,
                entidad: None,
                valores: vec![
                    Valor::Texto(e.clase.nombre().to_string()),
                    Valor::Texto(e.clase.categoria().nombre().to_string()),
                    Valor::Texto(e.resultado.nombre().to_string()),
                    Valor::Texto(e.severidad.nombre().to_string()),
                    Valor::Texto(e.origen.nombre().to_string()),
                    Valor::Texto(e.anfitrion.clone()),
                    Valor::Texto(e.inquilino.clone()),
                    Valor::Texto(e.productor.clone()),
                    Valor::Texto(e.mensaje.clone()),
                    Valor::Entero(ts_a_i64(e.observado_ns)),
                ],
            })
            .collect();
        self.ingerir("events", filas).await
    }
}

/// Un instante u64 como i64 de PostgreSQL. Los instantes Unix en nanosegundos
/// caben en i64 hasta el ano 2262.
pub(crate) fn ts_a_i64(ts: u64) -> i64 {
    i64::try_from(ts).unwrap_or(i64::MAX)
}
