//! El informe de postura: comprobaciones, resultados por entidad y cobertura.
//!
//! # Como se agrega, y por que en ese orden
//!
//! Cada comprobacion se contesta **por proveedor** a partir de sus resultados
//! por entidad, con una precedencia fija:
//!
//! 1. **Sin eventos del proveedor** → `SinDatos`. Un informe sin un solo evento
//!    de Azure no dice nada de Azure, y lo dice.
//! 2. **Algun resultado incumple** → `Incumple`, con la evidencia de todos.
//! 3. **Algun resultado sin datos** → `SinDatos`: un grupo de seguridad que no
//!    se pudo leer entero no permite decir que la cuenta no tiene puertos
//!    abiertos.
//! 4. **Ningun resultado** → `SinDatos`: no hubo ningun evento que tocara la
//!    comprobacion, y lo configurado antes de la ventana no se ve (EL MURO). La
//!    unica excepcion es `LOG-002`, que no pregunta por una configuracion sino
//!    por la ventana misma («¿se apago el registro y se gestionaron cuentas?»):
//!    con eventos del proveedor y ningun apagado, la respuesta es `Cumple`
//!    sobre esa ventana.
//! 5. **Todo cumple** → `Cumple`, salvo que el estado este degradado (eventos
//!    descartados por tope, piezas desbordadas, o el proveedor ciego tras un
//!    apagado del registro sin actividad posterior): entonces `SinDatos` con
//!    ese motivo.
//!
//! Y `Cumple` dice siempre su alcance: «los N observados cumplen». Nunca «la
//! cuenta cumple».

use std::fmt::Write as _;

use aegis_entidad::entidad;
use aegis_ingest::esquema::Evento;
use aegis_ingest::tiempo::civil_desde_dias;

use crate::credenciales::InformeCredenciales;
use crate::estado::{Contadores, EstadoNube, DIAS_ROTACION, DIA_NS};
use crate::modelo::{
    Definicion, Estado, Evidencia, Naturaleza, Proveedor, Referencia, Resultado, CATALOGO, CLV_001,
    LOG_002, PROVEEDORES,
};

/// Una comprobacion del catalogo, contestada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comprobacion {
    /// Su definicion estable.
    pub definicion: &'static Definicion,
    /// El estado agregado por proveedor, para cada proveedor de la definicion.
    pub por_proveedor: Vec<(Proveedor, Estado)>,
    /// Los veredictos por entidad que lo sostienen.
    pub resultados: Vec<Resultado>,
}

impl Comprobacion {
    /// El estado agregado de un proveedor, si la comprobacion aplica a el.
    #[must_use]
    pub fn estado(&self, p: Proveedor) -> Option<&Estado> {
        self.por_proveedor
            .iter()
            .find(|(q, _)| *q == p)
            .map(|(_, e)| e)
    }
}

/// Lo que se vio de un proveedor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoberturaProveedor {
    /// El proveedor.
    pub proveedor: Proveedor,
    /// Lo contado al plegar.
    pub contadores: Contadores,
    /// Comprobaciones que tuvieron datos para contestar.
    pub con_datos: Vec<&'static str>,
    /// Comprobaciones que no.
    pub sin_datos: Vec<&'static str>,
    /// Si el registro de este proveedor se apago sin que despues llegara nada:
    /// desde cuando esta ciego.
    pub ciego_desde_ns: Option<u64>,
}

impl CoberturaProveedor {
    /// Si llego algun evento.
    #[must_use]
    pub fn tuvo_eventos(&self) -> bool {
        self.contadores.eventos > 0
    }
}

/// Cuanto se pudo mirar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cobertura {
    /// Los tres proveedores, siempre, tengan o no eventos.
    pub proveedores: Vec<CoberturaProveedor>,
    /// Eventos que no se plegaron por exceder el tope.
    pub eventos_descartados: usize,
    /// Si el estado llego a su tope de piezas.
    pub desbordado: bool,
    /// Claves leidas del informe de credenciales, si se aporto uno.
    pub claves_de_credenciales: Option<usize>,
}

impl Cobertura {
    /// La de un proveedor.
    #[must_use]
    pub fn de(&self, p: Proveedor) -> Option<&CoberturaProveedor> {
        self.proveedores.iter().find(|c| c.proveedor == p)
    }
}

/// El informe de postura.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Informe {
    /// Las comprobaciones del catalogo, en su orden.
    pub comprobaciones: Vec<Comprobacion>,
    /// Cuanto se pudo mirar.
    pub cobertura: Cobertura,
    /// El instante respecto al que se mide la antiguedad de las claves.
    pub ahora_ns: u64,
}

impl Informe {
    /// Evalua una ventana de eventos.
    ///
    /// `ahora_ns` lo pone quien llama, no el reloj del sistema: el mismo lote
    /// tiene que dar el mismo informe, y una prueba tiene que poder fijar el
    /// dia.
    #[must_use]
    pub fn evaluar(eventos: &[Evento], ahora_ns: u64) -> Informe {
        Informe::evaluar_con_credenciales(eventos, None, ahora_ns)
    }

    /// Evalua una ventana de eventos mas, si lo hay, un informe de
    /// credenciales de IAM.
    #[must_use]
    pub fn evaluar_con_credenciales(
        eventos: &[Evento],
        credenciales: Option<&InformeCredenciales>,
        ahora_ns: u64,
    ) -> Informe {
        let estado = EstadoNube::reconstruir(eventos);
        let mut resultados = estado.resultados(ahora_ns);
        if let Some(c) = credenciales {
            resultados.extend(de_credenciales(c, ahora_ns));
        }

        let mut comprobaciones = Vec::new();
        for def in CATALOGO {
            let propios: Vec<Resultado> = resultados
                .iter()
                .filter(|r| r.comprobacion == def.id)
                .cloned()
                .collect();
            let mut por_proveedor = Vec::new();
            for p in def.proveedores {
                let rs: Vec<&Resultado> = propios.iter().filter(|r| r.proveedor == *p).collect();
                let contadores = estado.contadores.get(p).cloned().unwrap_or_default();
                // El informe de credenciales es una fuente de AWS aunque no
                // haya eventos de AWS.
                let hubo_fuente = contadores.eventos > 0
                    || (def.id == CLV_001 && *p == Proveedor::Aws && credenciales.is_some());
                let degradado = degradacion(&estado, *p);
                por_proveedor.push((
                    *p,
                    agregar(def, *p, &rs, hubo_fuente, &contadores, degradado),
                ));
            }
            comprobaciones.push(Comprobacion {
                definicion: def,
                por_proveedor,
                resultados: propios,
            });
        }

        let proveedores = PROVEEDORES
            .iter()
            .map(|p| {
                let mut con = Vec::new();
                let mut sin = Vec::new();
                for c in &comprobaciones {
                    if let Some(e) = c.estado(*p) {
                        if e.tiene_datos() {
                            con.push(c.definicion.id);
                        } else {
                            sin.push(c.definicion.id);
                        }
                    }
                }
                CoberturaProveedor {
                    proveedor: *p,
                    contadores: estado.contadores.get(p).cloned().unwrap_or_default(),
                    con_datos: con,
                    sin_datos: sin,
                    ciego_desde_ns: estado.ciego_desde(*p),
                }
            })
            .collect();

        Informe {
            comprobaciones,
            cobertura: Cobertura {
                proveedores,
                eventos_descartados: estado.descartados,
                desbordado: estado.desbordado,
                claves_de_credenciales: credenciales.map(|c| c.claves.len()),
            },
            ahora_ns,
        }
    }

    /// Una comprobacion por su identificador.
    #[must_use]
    pub fn comprobacion(&self, id: &str) -> Option<&Comprobacion> {
        self.comprobaciones.iter().find(|c| c.definicion.id == id)
    }

    /// El estado agregado de una comprobacion en un proveedor.
    #[must_use]
    pub fn estado(&self, id: &str, p: Proveedor) -> Option<&Estado> {
        self.comprobacion(id)?.estado(p)
    }

    /// Los resultados por entidad de una comprobacion.
    #[must_use]
    pub fn resultados(&self, id: &str) -> Vec<&Resultado> {
        self.comprobacion(id)
            .map(|c| c.resultados.iter().collect())
            .unwrap_or_default()
    }

    /// Los incumplimientos que son exposicion: van a la postura.
    #[must_use]
    pub fn exposiciones(&self) -> Vec<&Resultado> {
        self.incumplimientos(Naturaleza::Exposicion)
    }

    /// Los incumplimientos que son compromiso: van a respuesta a incidentes.
    #[must_use]
    pub fn compromisos(&self) -> Vec<&Resultado> {
        self.incumplimientos(Naturaleza::Compromiso)
    }

    fn incumplimientos(&self, n: Naturaleza) -> Vec<&Resultado> {
        self.comprobaciones
            .iter()
            .filter(|c| c.definicion.naturaleza == n)
            .flat_map(|c| c.resultados.iter())
            .filter(|r| r.estado.incumple())
            .collect()
    }

    /// El informe legible.
    #[must_use]
    pub fn texto(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "POSTURA DE NUBE (reconstruida de eventos; referencia temporal {})",
            fecha(self.ahora_ns)
        );
        let _ = writeln!(s, "\nCOBERTURA");
        for c in &self.cobertura.proveedores {
            let n = c.proveedor.nombre();
            if !c.tuvo_eventos() {
                let _ = writeln!(
                    s,
                    "  {n:<6} SIN EVENTOS: nada de este informe afirma nada sobre {n}"
                );
                continue;
            }
            let k = &c.contadores;
            let _ = writeln!(
                s,
                "  {n:<6} {} eventos ({} duplicados, {} sin efecto por fallo, {} pendientes, {} \
                 sin detalle), ventana {} .. {}",
                k.eventos,
                k.duplicados,
                k.no_aplicados,
                k.pendientes,
                k.sin_detalle,
                k.desde_ns.map_or_else(|| "?".into(), fecha),
                k.hasta_ns.map_or_else(|| "?".into(), fecha),
            );
            let _ = writeln!(
                s,
                "         con datos: {} | sin datos: {}",
                lista_ids(&c.con_datos),
                lista_ids(&c.sin_datos)
            );
            if let Some(t) = c.ciego_desde_ns {
                let _ = writeln!(
                    s,
                    "         CIEGO desde {}: el registro se apago y no llego nada despues",
                    fecha(t)
                );
            }
        }
        if self.cobertura.eventos_descartados > 0 {
            let _ = writeln!(
                s,
                "  {} eventos no se plegaron por exceder el tope",
                self.cobertura.eventos_descartados
            );
        }
        if let Some(n) = self.cobertura.claves_de_credenciales {
            let _ = writeln!(s, "  informe de credenciales de IAM: {n} ranuras de clave");
        }
        for c in &self.comprobaciones {
            let d = c.definicion;
            let _ = writeln!(
                s,
                "\n[{}] {} ({}, {})",
                d.id,
                d.titulo,
                d.naturaleza.nombre(),
                d.severidad.nombre()
            );
            for (p, e) in &c.por_proveedor {
                let _ = writeln!(s, "  {:<6} {}", p.nombre(), e.linea());
            }
            for r in &c.resultados {
                let refs = r
                    .estado
                    .evidencia()
                    .map(|e| {
                        e.referencias
                            .iter()
                            .map(Referencia::texto)
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let _ = writeln!(
                    s,
                    "    - {} {} [{}] -> {}{}",
                    r.proveedor.nombre(),
                    r.recurso,
                    r.entidad.texto(),
                    r.estado.linea(),
                    if refs.is_empty() {
                        String::new()
                    } else {
                        format!(" | evidencia: {refs}")
                    }
                );
            }
            if c.por_proveedor.iter().any(|(_, e)| e.incumple()) {
                let _ = writeln!(s, "  remediacion: {}", d.remediacion);
            }
        }
        s
    }
}

fn degradacion(estado: &EstadoNube, p: Proveedor) -> Option<String> {
    if estado.descartados > 0 {
        return Some(format!(
            "{} eventos de la ventana no se plegaron por exceder el tope: el estado puede no \
             incluir la ultima correccion",
            estado.descartados
        ));
    }
    if estado.desbordado {
        return Some("el estado llego a su tope de piezas y dejo de anadir".into());
    }
    estado.ciego_desde(p).map(|t| {
        format!(
            "el registro de {} se apago en {} y no llego nada despues: lo observado puede haber \
             cambiado sin que se vea",
            p.nombre(),
            fecha(t)
        )
    })
}

fn agregar(
    def: &Definicion,
    p: Proveedor,
    rs: &[&Resultado],
    hubo_fuente: bool,
    contadores: &Contadores,
    degradado: Option<String>,
) -> Estado {
    if !hubo_fuente {
        return Estado::SinDatos(format!(
            "no llego ningun evento de {} en la ventana: sin eventos no se afirma nada",
            p.nombre()
        ));
    }
    let total = rs.len();
    let malos: Vec<&&Resultado> = rs.iter().filter(|r| r.estado.incumple()).collect();
    if let Some(primero) = malos.first() {
        let mut ev = Evidencia::default();
        for r in &malos {
            if let Some(e) = r.estado.evidencia() {
                ev.unir(e);
            }
        }
        let extracto = primero
            .estado
            .evidencia()
            .map(|e| e.extracto.clone())
            .unwrap_or_default();
        ev.con_extracto(&format!(
            "{} de {total} observados incumplen; p.ej. {}: {extracto}",
            malos.len(),
            primero.recurso
        ));
        return Estado::Incumple(ev);
    }
    if let Some(r) = rs.iter().find(|r| !r.estado.tiene_datos()) {
        let n = rs.iter().filter(|r| !r.estado.tiene_datos()).count();
        let motivo = match &r.estado {
            Estado::SinDatos(m) => m.clone(),
            _ => String::new(),
        };
        return Estado::SinDatos(format!(
            "{n} de {total} observados sin datos; p.ej. {}: {motivo}",
            r.recurso
        ));
    }
    if rs.is_empty() {
        if def.id == LOG_002 {
            if let Some(m) = degradado {
                return Estado::SinDatos(m);
            }
            return Estado::Cumple(Evidencia::solo_extracto(&format!(
                "en la ventana observada ({} eventos de {}) no se apago el registro de auditoria",
                contadores.eventos,
                p.nombre()
            )));
        }
        return Estado::SinDatos(format!(
            "ninguno de los {} eventos de {} en la ventana toca esta comprobacion; lo configurado \
             antes de la ventana no se ve",
            contadores.eventos,
            p.nombre()
        ));
    }
    if let Some(m) = degradado {
        return Estado::SinDatos(m);
    }
    let mut ev = Evidencia::default();
    for r in rs {
        if let Some(e) = r.estado.evidencia() {
            ev.unir(e);
        }
    }
    let cuantos = if total == 1 {
        "el unico observado cumple".to_string()
    } else {
        format!("los {total} observados cumplen")
    };
    ev.con_extracto(&format!(
        "{cuantos}; lo configurado antes de la ventana no se ve"
    ));
    Estado::Cumple(ev)
}

/// Las claves del informe de credenciales, como resultados de `CLV-001`.
fn de_credenciales(c: &InformeCredenciales, ahora_ns: u64) -> Vec<Resultado> {
    let mut v = Vec::new();
    for k in &c.claves {
        // Una ranura inactiva sin fecha es una ranura vacia: no hay clave.
        if !k.activa && k.rotada_ns.is_none() {
            continue;
        }
        let r = Referencia::InformeCredenciales {
            fila: k.fila,
            generado_ns: c.generado_ns,
        };
        let recurso = aegis_ingest::esquema::recortar(
            &format!("clave {} de {} (informe de credenciales)", k.ranura, k.arn),
            crate::modelo::MAX_RECURSO,
        );
        let estado = match (k.activa, k.rotada_ns) {
            (false, _) => Estado::Cumple(Evidencia::nueva(
                r,
                &format!("la clave {} de {} esta inactiva", k.ranura, k.usuario),
            )),
            (true, None) => Estado::SinDatos(format!(
                "la clave {} de {} esta activa y su ultima rotacion no es legible ({:?}) \
                 [informe de credenciales, fila {}]",
                k.ranura,
                k.usuario,
                aegis_ingest::esquema::recortar(&k.rotada_texto, 64),
                k.fila
            )),
            (true, Some(t)) => {
                let dias = ahora_ns.saturating_sub(t) / DIA_NS;
                if dias > DIAS_ROTACION {
                    Estado::Incumple(Evidencia::nueva(
                        r,
                        &format!(
                            "la clave {} de {} se roto por ultima vez hace {dias} dias (mas de \
                             {DIAS_ROTACION}) y sigue activa",
                            k.ranura, k.usuario
                        ),
                    ))
                } else {
                    Estado::Cumple(Evidencia::nueva(
                        r,
                        &format!(
                            "la clave {} de {} se roto hace {dias} dias",
                            k.ranura, k.usuario
                        ),
                    ))
                }
            }
        };
        v.push(Resultado {
            comprobacion: CLV_001,
            proveedor: Proveedor::Aws,
            recurso,
            entidad: entidad::cuenta(&k.arn),
            estado,
        });
    }
    if c.filas_descartadas > 0 {
        v.push(Resultado {
            comprobacion: CLV_001,
            proveedor: Proveedor::Aws,
            recurso: "informe de credenciales".into(),
            entidad: entidad::cuenta("informe-de-credenciales"),
            estado: Estado::SinDatos(format!(
                "{} filas del informe de credenciales no se leyeron (tope o mal formadas)",
                c.filas_descartadas
            )),
        });
    }
    v
}

fn lista_ids(v: &[&str]) -> String {
    if v.is_empty() {
        return "-".into();
    }
    v.iter()
        .map(|id| id.trim_start_matches("AEGIS-NUBE-"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Un instante como fecha UTC legible.
#[must_use]
pub fn fecha(ns: u64) -> String {
    let s = ns / 1_000_000_000;
    let dias = i64::try_from(s / 86_400).unwrap_or(i64::MAX);
    let (a, m, d) = civil_desde_dias(dias);
    let r = s % 86_400;
    format!(
        "{a:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        r / 3600,
        (r / 60) % 60,
        r % 60
    )
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn sin_eventos_ningun_proveedor_cumple_nada() {
        // EL MURO en su forma minima: sin eventos, ni siquiera LOG-002.
        let inf = Informe::evaluar(&[], 1_790_000_000_000_000_000);
        for c in &inf.comprobaciones {
            for (p, e) in &c.por_proveedor {
                assert!(
                    matches!(e, Estado::SinDatos(_)),
                    "{} {} dijo {}",
                    c.definicion.id,
                    p.nombre(),
                    e.nombre()
                );
            }
        }
        for c in &inf.cobertura.proveedores {
            assert!(c.con_datos.is_empty());
            assert!(!c.sin_datos.is_empty());
        }
        assert!(inf.texto().contains("SIN EVENTOS"));
    }

    #[test]
    fn la_fecha_se_escribe_en_utc() {
        assert_eq!(fecha(0), "1970-01-01T00:00:00Z");
        assert_eq!(fecha(1_700_000_000_000_000_000), "2023-11-14T22:13:20Z");
    }
}
