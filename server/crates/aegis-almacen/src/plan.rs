//! El coste de una consulta, declarado ANTES de leer nada, y el rechazo.
//!
//! # Una consulta no tumba el almacen
//!
//! Un SIEM que se cuelga con una consulta mal escrita deja al SOC ciego en el
//! peor momento: justo cuando alguien, con prisa, escribe la consulta sin
//! acotar. Por eso el planificador mira el catalogo —particiones, segmentos,
//! filas y bytes de las columnas que la consulta necesita— SIN descomprimir
//! nada, y decide antes de leer:
//!
//! 1. Sin filtro de tiempo (`DURING` o una comparacion sobre `ts`) y sin filtro
//!    de entidad ni de indice declarado, la consulta barre la tabla entera. Mas
//!    de [`crate::MAX_PARTICIONES_SIN_FILTRO`] dias asi, y se rechaza.
//! 2. Con o sin filtro, mas de [`crate::MAX_SEGMENTOS_CONSULTA`] segmentos se
//!    rechaza.
//!
//! Y el rechazo no es «consulta demasiado cara»: dice cuanto habria leido y
//! COMO arreglarla, con la ventana concreta que la haria caber.

use std::collections::BTreeMap;

use aegis_parser::ast::Proyeccion;
use aegis_parser::ast::{Comparador, Expr, Literal};
use aegis_parser::esquema::{historico as cat, Tabla};
use aegis_parser::historico::{ConsultaHistorica, ExprH, Salida, Seleccion};
use aegis_parser::valor::Valor;

use crate::sql::{self, dia_de};
use crate::{Almacen, ErrorAlmacen, MAX_PARTICIONES_SIN_FILTRO, MAX_SEGMENTOS_CONSULTA};

/// Como se eligen los segmentos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    /// El indice primario, por entidad.
    Entidad(usize),
    /// Un indice secundario declarado.
    Secundario {
        /// La columna.
        columna: String,
    },
    /// Todos los segmentos de la tabla en la ventana.
    Barrido,
}

/// El coste de una consulta, declarado antes de ejecutarla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coste {
    /// Particiones (dias) que toca.
    pub particiones: usize,
    /// De ellas, cuantas en cada nivel: caliente, tibio, frio.
    pub por_nivel: [usize; 3],
    /// Segmentos que leera.
    pub segmentos: u64,
    /// Filas que examinara.
    pub filas: u64,
    /// Bytes comprimidos de las columnas que leera (de lo que esta en
    /// PostgreSQL; lo frio se lee de fichero).
    pub bytes: u64,
    /// Como se eligieron los segmentos.
    pub via: Via,
    /// Si la consulta esta acotada en el tiempo.
    pub acotada_en_tiempo: bool,
    /// Columnas que leera.
    pub columnas: Vec<&'static str>,
}

impl Coste {
    /// Frase para el operador.
    #[must_use]
    pub fn frase(&self) -> String {
        format!(
            "{} particion(es) ({} caliente, {} tibia, {} fria), {} segmento(s), {} fila(s), {:.1} MiB de {} columna(s), por {}",
            self.particiones,
            self.por_nivel[0],
            self.por_nivel[1],
            self.por_nivel[2],
            self.segmentos,
            self.filas,
            self.bytes as f64 / (1024.0 * 1024.0),
            self.columnas.len(),
            match &self.via {
                Via::Entidad(n) => format!("el indice de entidad ({n} entidad(es))"),
                Via::Secundario { columna } => format!("el indice declarado sobre '{columna}'"),
                Via::Barrido => "barrido de la tabla".into(),
            }
        )
    }
}

/// Una consulta que no se ejecuta por su coste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rechazo {
    /// Por que.
    pub motivo: String,
    /// Como arreglarla.
    pub sugerencia: String,
    /// Lo que habria costado.
    pub coste: Coste,
}

impl std::fmt::Display for Rechazo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "consulta rechazada por su coste: {}. {}. Habria leido {}",
            self.motivo,
            self.sugerencia,
            self.coste.frase()
        )
    }
}

/// Un segmento que se leera.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Candidato {
    pub(crate) dia: i32,
    pub(crate) id: i64,
    pub(crate) filas: i32,
}

/// Lo que el planificador decide.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub(crate) tabla: &'static Tabla,
    pub(crate) desde_ns: u64,
    pub(crate) hasta_ns: u64,
    pub(crate) candidatos: Vec<Candidato>,
    pub(crate) niveles: BTreeMap<i32, (i16, Option<String>)>,
    pub(crate) coste: Coste,
}

/// El intervalo `[desde, hasta)` que imponen la ventana y las comparaciones
/// sobre `ts` que van en conjuncion en la raiz del filtro.
fn intervalo(q: &ConsultaHistorica, ahora_ns: u64) -> (u64, u64, bool) {
    let (mut desde, mut hasta, mut acotada) = (0u64, u64::MAX, false);
    if let Some(v) = &q.ventana {
        let (d, h) = v.intervalo(ahora_ns);
        desde = d;
        hasta = h;
        acotada = true;
    }
    let mut conj = Vec::new();
    if let Some(f) = &q.filtro {
        conjunciones(f, &mut conj);
    }
    for e in conj {
        if let ExprH::Hoja(Expr::Comparacion {
            columna,
            op,
            valor: Literal::Entero(x),
        }) = e
        {
            if *columna != cat::TS.nombre {
                continue;
            }
            let x = u64::try_from(*x).unwrap_or(0);
            match op {
                Comparador::Mayor => desde = desde.max(x.saturating_add(1)),
                Comparador::MayorIgual => desde = desde.max(x),
                Comparador::Menor => hasta = hasta.min(x),
                Comparador::MenorIgual => hasta = hasta.min(x.saturating_add(1)),
                Comparador::Igual => {
                    desde = desde.max(x);
                    hasta = hasta.min(x.saturating_add(1));
                }
                Comparador::Distinto => continue,
            }
            acotada = true;
        }
    }
    (desde, hasta, acotada)
}

/// Los terminos de la conjuncion de la raiz.
pub(crate) fn conjunciones<'a>(e: &'a ExprH, v: &mut Vec<&'a ExprH>) {
    match e {
        ExprH::Y(a, b) => {
            conjunciones(a, v);
            conjunciones(b, v);
        }
        otro => v.push(otro),
    }
}

/// Las columnas que la consulta necesita leer.
pub(crate) fn columnas_necesarias(q: &ConsultaHistorica, t: &'static Tabla) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = vec![cat::TS.nombre, cat::ENTITY.nombre];
    let anadir = |c: &'static str, v: &mut Vec<&'static str>| {
        if !v.contains(&c) {
            v.push(c);
        }
    };
    match &q.seleccion {
        Seleccion::Filas(Proyeccion::Todo) => {
            for c in asterisco(t) {
                anadir(c, &mut v);
            }
        }
        Seleccion::Filas(Proyeccion::Columnas(cs)) => {
            for c in cs {
                anadir(c.nombre, &mut v);
            }
        }
        Seleccion::Filas(Proyeccion::Cuenta) => {}
        Seleccion::Agregada(salidas) => {
            for s in salidas {
                match s {
                    Salida::Grupo(c) => anadir(c.nombre, &mut v),
                    Salida::Agregado(a) => {
                        use aegis_parser::historico::Agregado as A;
                        if let A::Suma(c) | A::Minimo(c) | A::Maximo(c) | A::Media(c) = a {
                            anadir(c.nombre, &mut v);
                        }
                    }
                    Salida::Cubo => {}
                }
            }
        }
    }
    for g in &q.agrupar {
        anadir(g.nombre, &mut v);
    }
    if let Some(o) = &q.orden {
        anadir(o.columna, &mut v);
    }
    if let Some(f) = &q.filtro {
        filtro_columnas(f, &mut |c| anadir(c, &mut v));
    }
    v
}

fn filtro_columnas(e: &ExprH, f: &mut impl FnMut(&'static str)) {
    match e {
        ExprH::Hoja(x) => x.para_cada_columna(f),
        ExprH::EnSubconsulta { columna, .. } => f(columna.nombre),
        ExprH::Y(a, b) | ExprH::O(a, b) => {
            filtro_columnas(a, f);
            filtro_columnas(b, f);
        }
        ExprH::No(a) => filtro_columnas(a, f),
    }
}

/// Las columnas de `SELECT *`: las mismas que en el endpoint, las de coste
/// trivial o barato.
pub(crate) fn asterisco(t: &'static Tabla) -> Vec<&'static str> {
    crate::columnas_guardadas(t)
        .into_iter()
        .filter(|c| c.coste <= aegis_parser::esquema::Coste::Barato)
        .map(|c| c.nombre)
        .collect()
}

/// Las entidades que fija la raiz del filtro: `entity = '...'`, `entity IN
/// (...)` o `entity IN (subconsulta)` ya resuelta.
fn entidades_fijadas(
    q: &ConsultaHistorica,
    subresultados: &BTreeMap<usize, Vec<Valor>>,
) -> Option<Vec<String>> {
    let mut conj = Vec::new();
    conjunciones(q.filtro.as_ref()?, &mut conj);
    for e in conj {
        match e {
            ExprH::Hoja(Expr::Comparacion {
                columna,
                op: Comparador::Igual,
                valor: Literal::Texto(t),
            }) if *columna == cat::ENTITY.nombre => return Some(vec![t.clone()]),
            ExprH::Hoja(Expr::En {
                columna,
                valores,
                negado: false,
            }) if *columna == cat::ENTITY.nombre => {
                return Some(
                    valores
                        .iter()
                        .filter_map(|l| match l {
                            Literal::Texto(t) => Some(t.clone()),
                            _ => None,
                        })
                        .collect(),
                )
            }
            ExprH::EnSubconsulta {
                columna,
                sub,
                negado: false,
            } if columna.nombre == cat::ENTITY.nombre => {
                let v = subresultados.get(&(&**sub as *const ConsultaHistorica as usize))?;
                return Some(v.iter().map(Valor::a_texto).collect());
            }
            _ => {}
        }
    }
    None
}

/// `columna = 'texto'` en la raiz, sobre una columna con indice declarado.
fn igualdad_declarada(
    q: &ConsultaHistorica,
    declarados: &[String],
) -> Option<(&'static str, String)> {
    let mut conj = Vec::new();
    conjunciones(q.filtro.as_ref()?, &mut conj);
    for e in conj {
        if let ExprH::Hoja(Expr::Comparacion {
            columna,
            op: Comparador::Igual,
            valor,
        }) = e
        {
            if declarados.iter().any(|d| d == columna) {
                let v = match valor {
                    Literal::Texto(t) => t.clone(),
                    Literal::Entero(n) => n.to_string(),
                    Literal::Real(x) => format!("{x:.4}"),
                    Literal::Booleano(b) => b.to_string(),
                };
                return Some((columna, v));
            }
        }
    }
    None
}

impl Almacen {
    /// Planifica una consulta: elige segmentos y declara su coste, o la rechaza.
    pub(crate) async fn planificar(
        &self,
        q: &ConsultaHistorica,
        ahora_ns: u64,
        subresultados: &BTreeMap<usize, Vec<Valor>>,
    ) -> Result<Plan, ErrorAlmacen> {
        let t = cat::tabla(q.tabla)
            .ok_or_else(|| ErrorAlmacen::Consulta(format!("no existe la tabla '{}'", q.tabla)))?;
        let columnas = columnas_necesarias(q, t);
        if let Some(c) = columnas.iter().find(|c| c.contains('.')) {
            return Err(ErrorAlmacen::Consulta(format!(
                "'{c}' solo existe contra el endpoint vivo: es un cuantificador sobre una coleccion que el \
                 ejecutor calcula en la maquina, y el historico no la guarda"
            )));
        }
        let (desde, hasta, acotada) = intervalo(q, ahora_ns);
        let s = &self.esquema;

        let todos = sql::dias(&self.pool, s).await?;
        let (dd, dh) = (dia_de(desde), dia_de(hasta.saturating_sub(1)));
        let dias: Vec<&(i32, i16, Option<String>)> = todos
            .iter()
            .filter(|(d, ..)| *d >= dd && *d <= dh)
            .collect();
        let mut por_nivel = [0usize; 3];
        for (_, n, _) in &dias {
            por_nivel[usize::try_from(*n).unwrap_or(0).min(2)] += 1;
        }
        let niveles: BTreeMap<i32, (i16, Option<String>)> =
            dias.iter().map(|(d, n, a)| (*d, (*n, a.clone()))).collect();

        let declarados = self.indices_de(q.tabla).await?;
        let entidades = entidades_fijadas(q, subresultados);
        let secundario = if entidades.is_none() {
            igualdad_declarada(q, &declarados)
        } else {
            None
        };
        let via = match (&entidades, &secundario) {
            (Some(e), _) => Via::Entidad(e.len()),
            (None, Some((c, _))) => Via::Secundario {
                columna: (*c).to_string(),
            },
            _ => Via::Barrido,
        };

        let mut coste = Coste {
            particiones: dias.len(),
            por_nivel,
            segmentos: 0,
            filas: 0,
            bytes: 0,
            via: via.clone(),
            acotada_en_tiempo: acotada,
            columnas: columnas.clone(),
        };

        // Regla 1: barrer muchos dias sin acotar, ANTES de preguntar por un solo
        // segmento.
        if via == Via::Barrido && !acotada && dias.len() > MAX_PARTICIONES_SIN_FILTRO {
            let (lo, hi) = (
                dias.first().map_or(0, |d| d.0),
                dias.last().map_or(0, |d| d.0),
            );
            return Err(ErrorAlmacen::Rechazada(Box::new(Rechazo {
                motivo: format!(
                    "leeria {} dias de '{}' ({} a {}) sin filtro de tiempo ni de entidad, y el tope es {}",
                    dias.len(),
                    q.tabla,
                    fecha(lo),
                    fecha(hi),
                    MAX_PARTICIONES_SIN_FILTRO
                ),
                sugerencia: format!(
                    "anade DURING LAST {MAX_PARTICIONES_SIN_FILTRO} DAYS (o DURING 'desde' TO 'hasta'), o filtra por \
                     entity = '...' para usar el indice primario{}",
                    if declarados.is_empty() {
                        String::new()
                    } else {
                        format!(", o por igualdad sobre una columna con indice ({})", declarados.join(", "))
                    }
                ),
                coste,
            })));
        }

        let (d_lo, d_hi) = (
            i64::try_from(desde).unwrap_or(i64::MAX),
            i64::try_from(hasta).unwrap_or(i64::MAX),
        );
        let candidatos: Vec<(i32, i64, i32)> = match (&entidades, &secundario) {
            (Some(e), _) => {
                sqlx::query_as(&format!(
                    "SELECT DISTINCT (s.dia - DATE '1970-01-01')::int, s.id, s.filas \
                     FROM {s}.entidades e JOIN {s}.segmentos s ON s.dia = e.dia AND s.id = e.segmento \
                     WHERE e.entidad = ANY($1) AND e.tabla = $2 \
                       AND e.dia BETWEEN DATE '1970-01-01' + $3 AND DATE '1970-01-01' + $4 \
                       AND e.ts_max >= $5 AND e.ts_min < $6 \
                     ORDER BY 1, 2"
                ))
                .bind(e)
                .bind(q.tabla)
                .bind(dd)
                .bind(dh)
                .bind(d_lo)
                .bind(d_hi)
                .fetch_all(&self.pool)
                .await?
            }
            (None, Some((c, v))) => {
                sqlx::query_as(&format!(
                    "SELECT DISTINCT (s.dia - DATE '1970-01-01')::int, s.id, s.filas \
                     FROM {s}.secundarios x JOIN {s}.segmentos s ON s.dia = x.dia AND s.id = x.segmento \
                     WHERE x.tabla = $1 AND x.columna = $2 AND x.valor = $3 \
                       AND x.dia BETWEEN DATE '1970-01-01' + $4 AND DATE '1970-01-01' + $5 \
                       AND s.ts_max >= $6 AND s.ts_min < $7 \
                     ORDER BY 1, 2"
                ))
                .bind(q.tabla)
                .bind(*c)
                .bind(v)
                .bind(dd)
                .bind(dh)
                .bind(d_lo)
                .bind(d_hi)
                .fetch_all(&self.pool)
                .await?
            }
            _ => {
                sqlx::query_as(&format!(
                    "SELECT (dia - DATE '1970-01-01')::int, id, filas FROM {s}.segmentos \
                     WHERE tabla = $1 AND dia BETWEEN DATE '1970-01-01' + $2 AND DATE '1970-01-01' + $3 \
                       AND ts_max >= $4 AND ts_min < $5 \
                     ORDER BY 1, 2"
                ))
                .bind(q.tabla)
                .bind(dd)
                .bind(dh)
                .bind(d_lo)
                .bind(d_hi)
                .fetch_all(&self.pool)
                .await?
            }
        };
        // Un indice secundario de un dia tibio o frio ya no existe (se suelta al
        // bajar de nivel): esos dias se barren, y el coste lo dice.
        let mut candidatos = candidatos;
        if secundario.is_some() {
            let sin_indice: Vec<i32> = niveles
                .iter()
                .filter(|(_, (n, _))| *n > 0)
                .map(|(d, _)| *d)
                .collect();
            if !sin_indice.is_empty() {
                let extra: Vec<(i32, i64, i32)> = sqlx::query_as(&format!(
                    "SELECT (dia - DATE '1970-01-01')::int, id, filas FROM {s}.segmentos \
                     WHERE tabla = $1 AND (dia - DATE '1970-01-01')::int = ANY($2) \
                       AND ts_max >= $3 AND ts_min < $4"
                ))
                .bind(q.tabla)
                .bind(&sin_indice)
                .bind(d_lo)
                .bind(d_hi)
                .fetch_all(&self.pool)
                .await?;
                candidatos.extend(extra);
                candidatos.sort_unstable();
                candidatos.dedup();
            }
        }

        coste.segmentos = candidatos.len() as u64;
        coste.filas = candidatos
            .iter()
            .map(|c| u64::try_from(c.2).unwrap_or(0))
            .sum();

        // Regla 2: demasiados segmentos, con la ventana que haria caber.
        if coste.segmentos > MAX_SEGMENTOS_CONSULTA {
            let por_dia = (coste.segmentos / (dias.len().max(1) as u64)).max(1);
            let dias_que_caben = (MAX_SEGMENTOS_CONSULTA / por_dia).max(1);
            return Err(ErrorAlmacen::Rechazada(Box::new(Rechazo {
                motivo: format!(
                    "leeria {} segmentos y el tope es {MAX_SEGMENTOS_CONSULTA}",
                    coste.segmentos
                ),
                sugerencia: format!(
                    "a unos {por_dia} segmentos por dia, DURING LAST {dias_que_caben} DAYS cabe; o filtra por entity \
                     o por una columna con indice declarado"
                ),
                coste,
            })));
        }

        let ids: Vec<i64> = candidatos.iter().map(|c| c.1).collect();
        if !ids.is_empty() {
            let cols: Vec<String> = columnas.iter().map(|c| (*c).to_string()).collect();
            let b: Option<i64> = sqlx::query_scalar(&format!(
                "SELECT sum(pg_column_size(datos))::bigint FROM {s}.columnas \
                 WHERE dia BETWEEN DATE '1970-01-01' + $1 AND DATE '1970-01-01' + $2 \
                   AND segmento = ANY($3) AND columna = ANY($4)"
            ))
            .bind(dd)
            .bind(dh)
            .bind(&ids)
            .bind(&cols)
            .fetch_one(&self.pool)
            .await?;
            coste.bytes = u64::try_from(b.unwrap_or(0)).unwrap_or(0);
        }

        Ok(Plan {
            tabla: t,
            desde_ns: desde,
            hasta_ns: hasta,
            candidatos: candidatos
                .into_iter()
                .map(|(dia, id, filas)| Candidato { dia, id, filas })
                .collect(),
            niveles,
            coste,
        })
    }
}

/// Fecha civil de un dia desde 1970, para los mensajes.
#[must_use]
pub fn fecha(dia: i32) -> String {
    // Algoritmo de Howard Hinnant, inverso de dias_desde_civil.
    let z = i64::from(dia) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_parser::historico::analizar;

    #[test]
    fn la_ventana_y_las_comparaciones_sobre_ts_acotan() {
        let q =
            analizar("SELECT pid FROM processes WHERE ts >= 100 AND ts < 200 AND pid > 3").unwrap();
        assert_eq!(intervalo(&q, 0), (100, 200, true));
        let q = analizar("SELECT pid FROM processes WHERE ts > 100 OR pid = 3").unwrap();
        assert!(!intervalo(&q, 0).2, "un OR no acota");
        let q = analizar("SELECT pid FROM processes DURING LAST 1 HOURS").unwrap();
        assert_eq!(
            intervalo(&q, 3_600_000_000_000 * 5),
            (3_600_000_000_000 * 4, 3_600_000_000_000 * 5 + 1, true)
        );
    }

    #[test]
    fn las_columnas_necesarias_son_solo_las_que_se_usan() {
        let q = analizar("SELECT name FROM processes WHERE uid = 0").unwrap();
        let t = cat::tabla("processes").unwrap();
        assert_eq!(columnas_necesarias(&q, t), ["ts", "entity", "name", "uid"]);
    }

    #[test]
    fn fechas() {
        assert_eq!(fecha(0), "1970-01-01");
        assert_eq!(fecha(20_697), "2026-09-01");
        assert_eq!(fecha(11_016), "2000-02-29");
    }
}
