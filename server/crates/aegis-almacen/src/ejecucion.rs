//! La ejecucion: subconsultas, segmentos, filtro, agregacion y orden.
//!
//! # La misma semantica que el endpoint
//!
//! El filtro se evalua con las reglas del ejecutor del endpoint
//! (`aegis_hunt::estado::evaluar_sobre`), copiadas regla a regla y cubiertas por
//! la prueba de paridad, que corre la misma consulta contra el ejecutor REAL y
//! contra este:
//!
//! - lo ausente no casa: `x = 1`, `x LIKE '...'`, `x IN (...)` son falsos;
//! - por eso sus negaciones son CIERTAS: `x NOT LIKE`, `x NOT IN` y `NOT (...)`
//!   sobre un ausente dan verdadero (logica de dos valores, ver
//!   `aegis_parser::valor`);
//! - una columna booleana suelta solo es cierta si es `true`.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;

use aegis_parser::ast::{Comparador, Expr, Literal, Proyeccion};
use aegis_parser::esquema::historico as cat;
use aegis_parser::historico::{
    self, Agregado, ConsultaHistorica, ExprH, Salida, Seleccion, Ventana,
};
use aegis_parser::valor::Valor;

use crate::codec;
use crate::plan::{asterisco, Coste, Plan};
use crate::retencion;
use crate::{Almacen, ErrorAlmacen};

/// La respuesta a una consulta.
#[derive(Debug, Clone, PartialEq)]
pub struct Respuesta {
    /// Nombres de las columnas.
    pub columnas: Vec<String>,
    /// Filas.
    pub filas: Vec<Vec<Valor>>,
    /// El coste que se declaro antes de ejecutar.
    pub coste: Coste,
    /// Filas examinadas.
    pub examinadas: u64,
    /// Si habia mas filas que el techo.
    pub truncada: bool,
}

type Subresultados = BTreeMap<usize, Vec<Valor>>;

/// Los valores de un segmento, por columna.
struct Lote {
    columnas: HashMap<&'static str, Vec<Valor>>,
    filas: usize,
}

impl Lote {
    fn valor(&self, c: &str, i: usize) -> &Valor {
        static AUSENTE: Valor = Valor::Ausente;
        self.columnas
            .get(c)
            .and_then(|v| v.get(i))
            .unwrap_or(&AUSENTE)
    }
}

fn evaluar_expr(e: &Expr, l: &Lote, i: usize) -> bool {
    match e {
        Expr::Comparacion { columna, op, valor } => l.valor(columna, i).compara(*op, valor),
        Expr::Like {
            columna,
            patron,
            negado,
        } => {
            let v = l.valor(columna, i);
            let casa = !v.es_ausente() && v.casa_patron(patron);
            casa != *negado
        }
        Expr::En {
            columna,
            valores,
            negado,
        } => {
            let v = l.valor(columna, i);
            let dentro = !v.es_ausente() && valores.iter().any(|x| v.compara(Comparador::Igual, x));
            dentro != *negado
        }
        Expr::Bandera { columna } => matches!(l.valor(columna, i), Valor::Booleano(true)),
        Expr::Y(a, b) => evaluar_expr(a, l, i) && evaluar_expr(b, l, i),
        Expr::O(a, b) => evaluar_expr(a, l, i) || evaluar_expr(b, l, i),
        Expr::No(a) => !evaluar_expr(a, l, i),
    }
}

fn a_literal(v: &Valor) -> Option<Literal> {
    Some(match v {
        Valor::Entero(n) => Literal::Entero(*n),
        Valor::Real(x) => Literal::Real(*x),
        Valor::Texto(t) => Literal::Texto(t.clone()),
        Valor::Booleano(b) => Literal::Booleano(*b),
        Valor::Ausente => return None,
    })
}

fn evaluar(e: &ExprH, l: &Lote, i: usize, subs: &HashMap<usize, Vec<Literal>>) -> bool {
    match e {
        ExprH::Hoja(x) => evaluar_expr(x, l, i),
        ExprH::EnSubconsulta {
            columna,
            sub,
            negado,
        } => {
            let v = l.valor(columna.nombre, i);
            let lista = subs.get(&(&**sub as *const ConsultaHistorica as usize));
            let dentro = !v.es_ausente()
                && lista.is_some_and(|ls| ls.iter().any(|x| v.compara(Comparador::Igual, x)));
            dentro != *negado
        }
        ExprH::Y(a, b) => evaluar(a, l, i, subs) && evaluar(b, l, i, subs),
        ExprH::O(a, b) => evaluar(a, l, i, subs) || evaluar(b, l, i, subs),
        ExprH::No(a) => !evaluar(a, l, i, subs),
    }
}

/// Orden total para `ORDER BY`: numeros por valor, texto por bytes, falso antes
/// que cierto, y lo ausente al final en los dos sentidos —una fila que no se
/// pudo leer no encabeza un informe—.
fn comparar(a: &Valor, b: &Valor) -> std::cmp::Ordering {
    use std::cmp::Ordering::{Greater, Less};
    match (a, b) {
        (Valor::Ausente, Valor::Ausente) => std::cmp::Ordering::Equal,
        (Valor::Ausente, _) => Greater,
        (_, Valor::Ausente) => Less,
        (Valor::Entero(x), Valor::Entero(y)) => x.cmp(y),
        (Valor::Texto(x), Valor::Texto(y)) => x.cmp(y),
        (Valor::Booleano(x), Valor::Booleano(y)) => x.cmp(y),
        (x, y) => num(x).total_cmp(&num(y)),
    }
}

fn num(v: &Valor) -> f64 {
    match v {
        Valor::Entero(n) => *n as f64,
        Valor::Real(x) => *x,
        Valor::Booleano(b) => f64::from(u8::from(*b)),
        _ => 0.0,
    }
}

/// Estado de un agregado.
#[derive(Debug, Clone)]
enum Acumulador {
    Cuenta(i64),
    Suma(f64, bool),
    Min(Option<Valor>),
    Max(Option<Valor>),
    Media(f64, u64),
}

impl Acumulador {
    fn nuevo(a: &Agregado) -> Acumulador {
        match a {
            Agregado::Cuenta => Acumulador::Cuenta(0),
            Agregado::Suma(c) => {
                Acumulador::Suma(0.0, c.tipo == aegis_parser::esquema::Tipo::Entero)
            }
            Agregado::Minimo(_) => Acumulador::Min(None),
            Agregado::Maximo(_) => Acumulador::Max(None),
            Agregado::Media(_) => Acumulador::Media(0.0, 0),
        }
    }

    fn sumar(&mut self, v: Option<&Valor>) {
        match (self, v) {
            (Acumulador::Cuenta(n), _) => *n += 1,
            (_, None | Some(Valor::Ausente)) => {}
            (Acumulador::Suma(s, _), Some(v)) => *s += num(v),
            (Acumulador::Media(s, n), Some(v)) => {
                *s += num(v);
                *n += 1;
            }
            (Acumulador::Min(m), Some(v)) => {
                if m.as_ref().is_none_or(|x| comparar(v, x).is_lt()) {
                    *m = Some(v.clone());
                }
            }
            (Acumulador::Max(m), Some(v)) => {
                if m.as_ref().is_none_or(|x| comparar(v, x).is_gt()) {
                    *m = Some(v.clone());
                }
            }
        }
    }

    fn valor(&self) -> Valor {
        match self {
            Acumulador::Cuenta(n) => Valor::Entero(*n),
            Acumulador::Suma(s, true) => Valor::Entero(*s as i64),
            Acumulador::Suma(s, false) => Valor::Real(*s),
            Acumulador::Min(m) | Acumulador::Max(m) => m.clone().unwrap_or(Valor::Ausente),
            Acumulador::Media(_, 0) => Valor::Ausente,
            Acumulador::Media(s, n) => Valor::Real(*s / *n as f64),
        }
    }
}

impl Almacen {
    /// Analiza y ejecuta una consulta de AegisQL sobre el historico.
    ///
    /// # Errors
    ///
    /// [`ErrorAlmacen::Consulta`] si no se entiende (con el error dibujado bajo
    /// la consulta); [`ErrorAlmacen::Rechazada`] si su coste no cabe.
    pub async fn consultar(&self, texto: &str, ahora_ns: u64) -> Result<Respuesta, ErrorAlmacen> {
        let q = historico::analizar(texto).map_err(|e| ErrorAlmacen::Consulta(e.dibujar(texto)))?;
        self.ejecutar(&q, ahora_ns).await
    }

    /// Solo el plan: el coste que tendria, sin ejecutarla. Una subconsulta SI
    /// se ejecuta, porque sin su resultado no se sabe que entidades mira la de
    /// fuera.
    ///
    /// # Errors
    ///
    /// Los de [`Almacen::consultar`].
    pub async fn explicar(&self, texto: &str, ahora_ns: u64) -> Result<Coste, ErrorAlmacen> {
        let q = historico::analizar(texto).map_err(|e| ErrorAlmacen::Consulta(e.dibujar(texto)))?;
        let subs = self.resolver_subconsultas(&q, ahora_ns).await?;
        Ok(self.planificar(&q, ahora_ns, &subs).await?.coste)
    }

    fn resolver_subconsultas<'a>(
        &'a self,
        q: &'a ConsultaHistorica,
        ahora_ns: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Subresultados, ErrorAlmacen>> + Send + 'a>> {
        Box::pin(async move {
            let mut subs = Subresultados::new();
            if let Some(f) = &q.filtro {
                for s in f.subconsultas() {
                    let r = self.ejecutar(s, ahora_ns).await?;
                    let vals = r
                        .filas
                        .into_iter()
                        .filter_map(|f| f.into_iter().next())
                        .collect();
                    subs.insert(s as *const ConsultaHistorica as usize, vals);
                }
            }
            Ok(subs)
        })
    }

    /// Ejecuta una consulta ya analizada.
    ///
    /// # Errors
    ///
    /// Los de [`Almacen::consultar`].
    pub fn ejecutar<'a>(
        &'a self,
        q: &'a ConsultaHistorica,
        ahora_ns: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Respuesta, ErrorAlmacen>> + Send + 'a>> {
        Box::pin(async move {
            let subs = self.resolver_subconsultas(q, ahora_ns).await?;
            let plan = self.planificar(q, ahora_ns, &subs).await?;
            let listas: HashMap<usize, Vec<Literal>> = subs
                .iter()
                .map(|(k, v)| (*k, v.iter().filter_map(a_literal).collect()))
                .collect();
            self.leer_y_resolver(q, &plan, &listas).await
        })
    }

    async fn cargar(
        &self,
        plan: &Plan,
        dia: i32,
        ids: &[i64],
    ) -> Result<HashMap<i64, Lote>, ErrorAlmacen> {
        let cols: Vec<String> = plan
            .coste
            .columnas
            .iter()
            .map(|c| (*c).to_string())
            .collect();
        let crudas: Vec<(i64, String, Vec<u8>)> = match plan.niveles.get(&dia) {
            Some((2, archivo)) => {
                let ruta = archivo.as_deref().ok_or_else(|| {
                    ErrorAlmacen::Configuracion(format!("el dia {dia} es frio y no tiene fichero"))
                })?;
                retencion::leer_frio(std::path::Path::new(ruta), ids, &cols)?
            }
            _ => {
                let s = &self.esquema;
                sqlx::query_as(&format!(
                    "SELECT segmento, columna, datos FROM {s}.columnas \
                     WHERE dia = DATE '1970-01-01' + $1 AND segmento = ANY($2) AND columna = ANY($3)"
                ))
                .bind(dia)
                .bind(ids)
                .bind(&cols)
                .fetch_all(&self.pool)
                .await?
            }
        };
        let mut lotes: HashMap<i64, Lote> = HashMap::new();
        for (seg, col, datos) in crudas {
            let Some(nombre) = plan.coste.columnas.iter().find(|c| **c == col) else {
                continue;
            };
            let v = codec::decodificar(&datos)?;
            let l = lotes.entry(seg).or_insert_with(|| Lote {
                columnas: HashMap::new(),
                filas: 0,
            });
            l.filas = l.filas.max(v.len());
            l.columnas.insert(nombre, v);
        }
        Ok(lotes)
    }

    async fn leer_y_resolver(
        &self,
        q: &ConsultaHistorica,
        plan: &Plan,
        subs: &HashMap<usize, Vec<Literal>>,
    ) -> Result<Respuesta, ErrorAlmacen> {
        let mut por_dia: BTreeMap<i32, Vec<i64>> = BTreeMap::new();
        for c in &plan.candidatos {
            por_dia.entry(c.dia).or_default().push(c.id);
        }
        let mut examinadas = 0u64;
        let mut filas: Vec<Vec<Valor>> = Vec::new();
        let mut grupos: BTreeMap<Vec<String>, (Vec<Valor>, Vec<Acumulador>)> = BTreeMap::new();
        let mut cuenta = 0i64;
        let columnas_filas: Vec<&'static str> = match &q.seleccion {
            Seleccion::Filas(Proyeccion::Todo) => asterisco(plan.tabla),
            Seleccion::Filas(Proyeccion::Columnas(cs)) => cs.iter().map(|c| c.nombre).collect(),
            _ => Vec::new(),
        };
        let salidas: &[Salida] = match &q.seleccion {
            Seleccion::Agregada(s) => s,
            Seleccion::Filas(_) => &[],
        };

        for (dia, ids) in por_dia {
            let lotes = self.cargar(plan, dia, &ids).await?;
            for id in ids {
                let Some(l) = lotes.get(&id) else {
                    continue;
                };
                for i in 0..l.filas {
                    examinadas += 1;
                    let ts = match l.valor(cat::TS.nombre, i) {
                        Valor::Entero(t) => u64::try_from(*t).unwrap_or(0),
                        _ => 0,
                    };
                    if ts < plan.desde_ns || ts >= plan.hasta_ns {
                        continue;
                    }
                    if let Some(f) = &q.filtro {
                        if !evaluar(f, l, i, subs) {
                            continue;
                        }
                    }
                    match &q.seleccion {
                        Seleccion::Filas(Proyeccion::Cuenta) => cuenta += 1,
                        Seleccion::Filas(_) => {
                            filas.push(
                                columnas_filas
                                    .iter()
                                    .map(|c| l.valor(c, i).clone())
                                    .collect(),
                            );
                        }
                        Seleccion::Agregada(_) => {
                            let cubo = q.cada_ns.map(|w| ts - ts % w);
                            let mut clave: Vec<String> = Vec::with_capacity(q.agrupar.len() + 1);
                            let mut claves_v: Vec<Valor> = Vec::new();
                            if let Some(c) = cubo {
                                clave.push(c.to_string());
                                claves_v.push(Valor::Entero(i64::try_from(c).unwrap_or(i64::MAX)));
                            }
                            for g in &q.agrupar {
                                let v = l.valor(g.nombre, i);
                                clave.push(format!("{v:?}"));
                                claves_v.push(v.clone());
                            }
                            let entrada = grupos.entry(clave).or_insert_with(|| {
                                (
                                    claves_v,
                                    salidas
                                        .iter()
                                        .filter_map(|s| match s {
                                            Salida::Agregado(a) => Some(Acumulador::nuevo(a)),
                                            _ => None,
                                        })
                                        .collect(),
                                )
                            });
                            let mut k = 0;
                            for s in salidas {
                                if let Salida::Agregado(a) = s {
                                    let v = match a {
                                        Agregado::Cuenta => None,
                                        Agregado::Suma(c)
                                        | Agregado::Minimo(c)
                                        | Agregado::Maximo(c)
                                        | Agregado::Media(c) => Some(l.valor(c.nombre, i)),
                                    };
                                    entrada.1[k].sumar(v);
                                    k += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        let limite = q.limite as usize;
        let (columnas, mut salida_filas): (Vec<String>, Vec<Vec<Valor>>) = match &q.seleccion {
            Seleccion::Filas(Proyeccion::Cuenta) => {
                (vec!["count".into()], vec![vec![Valor::Entero(cuenta)]])
            }
            Seleccion::Filas(_) => {
                if let Some(o) = &q.orden {
                    if let Some(k) = columnas_filas.iter().position(|c| *c == o.columna) {
                        filas.sort_by(|a, b| {
                            let c = comparar(&a[k], &b[k]);
                            if o.descendente && !a[k].es_ausente() && !b[k].es_ausente() {
                                c.reverse()
                            } else {
                                c
                            }
                        });
                    }
                }
                (
                    columnas_filas.iter().map(|c| (*c).to_string()).collect(),
                    filas,
                )
            }
            Seleccion::Agregada(salidas) => {
                let hay_cubo = q.cada_ns.is_some();
                let mut v: Vec<(Vec<Valor>, Vec<Valor>)> = grupos
                    .into_values()
                    .map(|(claves, acs)| (claves, acs.iter().map(Acumulador::valor).collect()))
                    .collect();
                // Sin ORDER BY: de mayor a menor por el primer agregado, que es la
                // pregunta de un SOC («los anfitriones con mas fallos»).
                match &q.orden {
                    Some(o) => {
                        let k = q
                            .agrupar
                            .iter()
                            .position(|g| g.nombre == o.columna)
                            .unwrap_or(0)
                            + usize::from(hay_cubo);
                        v.sort_by(|a, b| {
                            let c = comparar(&a.0[k], &b.0[k]);
                            if o.descendente {
                                c.reverse()
                            } else {
                                c
                            }
                        });
                    }
                    None if hay_cubo => v.sort_by(|a, b| comparar(&a.0[0], &b.0[0])),
                    None => v.sort_by(|a, b| comparar(&b.1[0], &a.1[0])),
                }
                let mut nombres = Vec::new();
                for s in salidas {
                    nombres.push(match s {
                        Salida::Grupo(c) => c.nombre.to_string(),
                        Salida::Cubo => "bucket".into(),
                        Salida::Agregado(a) => a.nombre(),
                    });
                }
                let filas = v
                    .into_iter()
                    .map(|(claves, aggs)| {
                        let mut ai = aggs.into_iter();
                        salidas
                            .iter()
                            .map(|s| match s {
                                Salida::Cubo => claves.first().cloned().unwrap_or(Valor::Ausente),
                                Salida::Grupo(c) => {
                                    let k = q
                                        .agrupar
                                        .iter()
                                        .position(|g| g.nombre == c.nombre)
                                        .unwrap_or(0)
                                        + usize::from(hay_cubo);
                                    claves.get(k).cloned().unwrap_or(Valor::Ausente)
                                }
                                Salida::Agregado(_) => ai.next().unwrap_or(Valor::Ausente),
                            })
                            .collect()
                    })
                    .collect();
                (nombres, filas)
            }
        };
        let truncada = salida_filas.len() > limite;
        salida_filas.truncate(limite);
        Ok(Respuesta {
            columnas,
            filas: salida_filas,
            coste: plan.coste.clone(),
            examinadas,
            truncada,
        })
    }

    /// Todo lo que se sabe de una entidad en una ventana, de todas las tablas.
    ///
    /// Es la consulta por la que existe el almacen: una entidad del modelo unico
    /// y sus filas en cada subsistema —proceso, conexiones, ficheros,
    /// veredictos, casos— sin unir por texto. Cada tabla se consulta por el
    /// indice primario, asi que el coste lo pone la entidad y no el volumen.
    ///
    /// # Errors
    ///
    /// Los de [`Almacen::consultar`].
    pub async fn todo_de(
        &self,
        entidad: &aegis_entidad::Eid,
        ventana: Ventana,
        ahora_ns: u64,
    ) -> Result<Vec<(String, Respuesta)>, ErrorAlmacen> {
        let s = &self.esquema;
        let (desde, hasta) = ventana.intervalo(ahora_ns);
        let tablas: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT DISTINCT tabla FROM {s}.entidades WHERE entidad = $1 \
               AND dia BETWEEN DATE '1970-01-01' + $2 AND DATE '1970-01-01' + $3 ORDER BY tabla"
        ))
        .bind(entidad.texto())
        .bind(crate::sql::dia_de(desde))
        .bind(crate::sql::dia_de(hasta.saturating_sub(1)))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::new();
        for t in tablas {
            let Some(tabla) = cat::tabla(&t) else {
                continue;
            };
            let cols: Vec<&str> = std::iter::once("ts")
                .chain(crate::columnas_guardadas(tabla).iter().map(|c| c.nombre))
                .collect();
            let q = format!(
                "SELECT {} FROM {t} WHERE entity = '{}' DURING '{}' TO '{}' LIMIT {}",
                cols.join(", "),
                entidad.texto(),
                rfc3339(desde),
                rfc3339(hasta),
                aegis_parser::sintaxis::LIMITE_MAXIMO
            );
            out.push((t, self.consultar(&q, ahora_ns).await?));
        }
        Ok(out)
    }
}

fn rfc3339(ns: u64) -> String {
    let dia = i32::try_from(ns / crate::sql::NS_DIA).unwrap_or(i32::MAX);
    let r = ns % crate::sql::NS_DIA;
    let s = r / 1_000_000_000;
    format!(
        "{}T{:02}:{:02}:{:02}.{:09}Z",
        crate::plan::fecha(dia),
        s / 3600,
        (s / 60) % 60,
        s % 60,
        r % 1_000_000_000
    )
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn lote(vals: Vec<(&'static str, Vec<Valor>)>) -> Lote {
        let filas = vals.first().map_or(0, |v| v.1.len());
        Lote {
            columnas: vals.into_iter().collect(),
            filas,
        }
    }

    #[test]
    fn las_negaciones_sobre_un_ausente_son_ciertas_como_en_el_endpoint() {
        let l = lote(vec![("name", vec![Valor::Ausente])]);
        let q =
            aegis_parser::sintaxis::analizar("SELECT pid FROM processes WHERE name NOT LIKE 'a%'")
                .unwrap();
        assert!(evaluar_expr(q.filtro.as_ref().unwrap(), &l, 0));
        let q =
            aegis_parser::sintaxis::analizar("SELECT pid FROM processes WHERE name NOT IN ('a')")
                .unwrap();
        assert!(evaluar_expr(q.filtro.as_ref().unwrap(), &l, 0));
        let q =
            aegis_parser::sintaxis::analizar("SELECT pid FROM processes WHERE name = 'a'").unwrap();
        assert!(!evaluar_expr(q.filtro.as_ref().unwrap(), &l, 0));
    }

    #[test]
    fn el_orden_deja_lo_ausente_al_final_en_los_dos_sentidos() {
        assert!(comparar(&Valor::Ausente, &Valor::Entero(1)).is_gt());
        assert!(comparar(&Valor::Entero(1), &Valor::Ausente).is_lt());
        assert!(comparar(&Valor::Entero(2), &Valor::Real(1.5)).is_gt());
    }

    #[test]
    fn rfc3339_de_vuelta() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000000000Z");
        assert_eq!(
            rfc3339(1_788_220_800_000_000_123),
            "2026-09-01T00:00:00.000000123Z"
        );
    }
}
