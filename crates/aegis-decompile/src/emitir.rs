//! Emision de pseudo-C: legible, con evidencia, y con nombres estables.
//!
//! # Que sale de aqui
//!
//! Una funcion en pseudo-C donde cada variable se llama por el HASH de su
//! definicion —no por el orden— y cada sentencia lleva, en un comentario, las
//! direcciones de las instrucciones que la originan. Esa es la propiedad que
//! convierte la decompilacion en evidencia: una capacidad detectada cita el
//! codigo.
//!
//! # SSA fuera para poder leerlo
//!
//! El pseudo-C no es SSA: se sale de SSA declarando cada valor como una variable y
//! convirtiendo cada fi en asignaciones en los predecesores. Las aristas se
//! disponen en post-orden inverso ([`crate::estructura`]) y las que no caen al
//! bloque siguiente se emiten como `goto`, contadas en la calidad.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::calidad::Calidad;
use crate::estructura::disponer;
use crate::ir::{
    Ancho, BloqueId, FuncionIr, OpBin, OpCmp, OpUn, Operacion, Operando, Sentencia, Terminador,
    ValId,
};
use crate::nombres;
use crate::tipos::Tipo;

/// El pseudo-C de una funcion, con su calidad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudoC {
    /// El texto del pseudo-C.
    pub texto: String,
    /// La calidad de este resultado.
    pub calidad: Calidad,
}

/// Emite el pseudo-C de una funcion.
///
/// `tipos` da, para los valores cuyo tipo se reconstruyo, su [`Tipo`]; los que no
/// estan salen como `desconocido`.
#[must_use]
pub fn emitir(f: &FuncionIr, tipos: &BTreeMap<ValId, Tipo>, base_calidad: Calidad) -> PseudoC {
    let disp = disponer(f);
    let mut s = String::new();
    let mut calidad = base_calidad;
    calidad.gotos_emitidos += disp.gotos;
    calidad.funciones_totales += 1;

    // Cabecera: nombre estable derivado de la direccion de entrada.
    let nombre_fn = format!("f_{:08x}", f.entrada & 0xffff_ffff);
    let _ = writeln!(s, "// funcion en {:#x}", f.entrada);
    let _ = writeln!(s, "desconocido {nombre_fn}(void) {{");

    // Declaracion de variables: una por cada valor definido, con su tipo.
    let mut declaradas: BTreeMap<ValId, (String, Tipo)> = BTreeMap::new();
    recopilar_variables(f, tipos, &mut declaradas, &mut calidad);
    for (nombre, tipo) in declaradas.values() {
        let _ = writeln!(s, "    {} {nombre};", tipo.c());
    }
    if !declaradas.is_empty() {
        let _ = writeln!(s);
    }

    // Cuerpo: bloques en el orden de la disposicion.
    for (i, id) in disp.orden.iter().enumerate() {
        let Some(bl) = f.bloques.get(id) else {
            continue;
        };
        let _ = writeln!(s, "  L_{:x}:", id.0);
        for sent in &bl.sentencias {
            emitir_sentencia(&mut s, sent, &declaradas);
        }
        let siguiente = disp.orden.get(i + 1).copied();
        emitir_terminador(&mut s, f, *id, &bl.terminador, siguiente, &declaradas);
    }

    let _ = writeln!(s, "}}");
    let _ = writeln!(s, "// {}", calidad.frase());
    PseudoC { texto: s, calidad }
}

/// Recopila las variables que hay que declarar y cuenta las que quedan sin tipo.
fn recopilar_variables(
    f: &FuncionIr,
    tipos: &BTreeMap<ValId, Tipo>,
    fuera: &mut BTreeMap<ValId, (String, Tipo)>,
    calidad: &mut Calidad,
) {
    for bl in f.bloques_ordenados() {
        for sent in &bl.sentencias {
            if let Sentencia::Definir {
                destino, ancho, op, ..
            } = sent
            {
                let tipo = tipos
                    .get(destino)
                    .cloned()
                    .unwrap_or_else(|| tipo_por_ancho(*ancho));
                let nombre = nombre_de_valor(*destino, op, *ancho);
                calidad.variables_totales += 1;
                if tipo.es_desconocido_para_el_usuario() {
                    calidad.variables_sin_tipo += 1;
                }
                fuera.insert(*destino, (nombre, tipo));
            }
            if let Sentencia::Llamada {
                retorno: Some(r), ..
            } = sent
            {
                let nombre = nombres::nombre('r', u64::from(r.0));
                fuera.entry(*r).or_insert((nombre, Tipo::Desconocido));
            }
        }
    }
}

/// Un tipo por defecto derivado solo del ancho, cuando la reconstruccion no dio
/// mas. No es «inventar»: el ancho es un hecho de la instruccion; lo que no se
/// afirma es el signo ni si es puntero.
fn tipo_por_ancho(a: Ancho) -> Tipo {
    Tipo::entero(a.bits())
}

/// El nombre estable de un valor, derivado de una descripcion canonica de su
/// definicion.
fn nombre_de_valor(v: ValId, op: &Operacion, ancho: Ancho) -> String {
    let desc = format!("{v:?}:{op:?}:{}", ancho.bits());
    nombres::nombre_de('v', desc.as_bytes())
}

/// El texto de un operando.
fn texto_operando(o: &Operando, decl: &BTreeMap<ValId, (String, Tipo)>) -> String {
    match o {
        Operando::Val(v) => decl
            .get(v)
            .map(|(n, _)| n.clone())
            .unwrap_or_else(|| format!("v_{}", v.0)),
        Operando::Const(k, _) => format!("{k:#x}"),
        Operando::Indefinido => "desconocido /* no se pudo determinar */".to_string(),
    }
}

/// Emite una sentencia con su comentario de evidencia.
fn emitir_sentencia(s: &mut String, sent: &Sentencia, decl: &BTreeMap<ValId, (String, Tipo)>) {
    let evid = evidencia(sent.origen());
    match sent {
        Sentencia::Definir { destino, op, .. } => {
            let nombre = decl
                .get(destino)
                .map(|(n, _)| n.clone())
                .unwrap_or_else(|| format!("v_{}", destino.0));
            let expr = texto_operacion(op, decl);
            let _ = writeln!(s, "    {nombre} = {expr};{evid}");
        }
        Sentencia::Almacenar {
            dir, valor, ancho, ..
        } => {
            let _ = writeln!(
                s,
                "    *({}*)({}) = {};{evid}",
                Tipo::entero(ancho.bits()).c(),
                texto_operando(dir, decl),
                texto_operando(valor, decl)
            );
        }
        Sentencia::Llamada {
            destino,
            nombre,
            argumentos,
            retorno,
            ..
        } => {
            let objetivo = match nombre {
                Some(n) => n.clone(),
                None => match destino {
                    Operando::Const(k, _) => format!("f_{:08x}", k & 0xffff_ffff),
                    _ => "(*desconocido)".to_string(),
                },
            };
            let args = argumentos
                .iter()
                .map(|a| texto_operando(a, decl))
                .collect::<Vec<_>>()
                .join(", ");
            let asig = match retorno {
                Some(r) => decl
                    .get(r)
                    .map(|(n, _)| format!("{n} = "))
                    .unwrap_or_default(),
                None => String::new(),
            };
            let _ = writeln!(s, "    {asig}{objetivo}({args});{evid}");
        }
    }
}

/// La representacion en C de una operacion.
fn texto_operacion(op: &Operacion, decl: &BTreeMap<ValId, (String, Tipo)>) -> String {
    let t = |o: &Operando| texto_operando(o, decl);
    match op {
        Operacion::Copiar(o) => t(o),
        Operacion::Bin { op, a, b } => format!("{} {} {}", t(a), simbolo_bin(*op), t(b)),
        Operacion::Un { op, a } => texto_unario(*op, &t(a)),
        Operacion::Comparar { op, a, b } => format!("{} {} {}", t(a), simbolo_cmp(*op), t(b)),
        Operacion::Cargar { dir, ancho } => {
            format!("*({}*)({})", Tipo::entero(ancho.bits()).c(), t(dir))
        }
        Operacion::Fi(fi) => {
            let ramas = fi
                .fuentes
                .iter()
                .map(|(b, o)| format!("desde L_{:x}: {}", b.0, t(o)))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "phi(/* {ramas} */ {})",
                fi.fuentes
                    .values()
                    .next()
                    .map_or_else(|| "desconocido".to_string(), &t)
            )
        }
        Operacion::ResultadoLlamada => "/* retorno de la llamada anterior */".to_string(),
        Operacion::Argumento(n) => format!("arg{n}"),
        Operacion::Indefinido => "desconocido".to_string(),
    }
}

/// El simbolo C de una operacion binaria.
fn simbolo_bin(op: OpBin) -> &'static str {
    match op {
        OpBin::Sumar => "+",
        OpBin::Restar => "-",
        OpBin::Multiplicar => "*",
        OpBin::DividirU | OpBin::DividirS => "/",
        OpBin::RestoU | OpBin::RestoS => "%",
        OpBin::Y => "&",
        OpBin::O => "|",
        OpBin::Xor => "^",
        OpBin::DesplazarIzq => "<<",
        OpBin::DesplazarDerL | OpBin::DesplazarDerA => ">>",
        OpBin::RotarIzq => "<<//rot",
        OpBin::RotarDer => ">>//rot",
    }
}

/// El simbolo C de una comparacion.
fn simbolo_cmp(op: OpCmp) -> &'static str {
    match op {
        OpCmp::Igual => "==",
        OpCmp::Distinto => "!=",
        OpCmp::MenorU | OpCmp::MenorS => "<",
        OpCmp::MenorIgualU | OpCmp::MenorIgualS => "<=",
    }
}

/// La representacion en C de una operacion unaria.
fn texto_unario(op: OpUn, a: &str) -> String {
    match op {
        OpUn::Negar => format!("-{a}"),
        OpUn::No => format!("~{a}"),
        OpUn::ExtenderS(_) | OpUn::ExtenderU(_) => a.to_string(),
        OpUn::Truncar(an) => format!("({}){a}", Tipo::entero(an.bits()).c()),
    }
}

/// Emite el terminador de un bloque, con `goto` cuando el destino no cae al
/// siguiente. Las asignaciones de fi de los sucesores se resuelven al leer sus
/// sentencias `Fi`, asi que aqui solo se dirige el control.
fn emitir_terminador(
    s: &mut String,
    _f: &FuncionIr,
    _id: BloqueId,
    term: &Terminador,
    siguiente: Option<BloqueId>,
    decl: &BTreeMap<ValId, (String, Tipo)>,
) {
    match term {
        Terminador::Ir(d) => {
            if Some(*d) != siguiente {
                let _ = writeln!(s, "    goto L_{:x};", d.0);
            }
        }
        Terminador::Rama { cond, si, no } => {
            let _ = writeln!(
                s,
                "    if ({}) goto L_{:x};",
                texto_operando(cond, decl),
                si.0
            );
            if Some(*no) != siguiente {
                let _ = writeln!(s, "    goto L_{:x};", no.0);
            }
        }
        Terminador::Conmutar {
            valor,
            casos,
            defecto,
        } => {
            let _ = writeln!(s, "    switch ({}) {{", texto_operando(valor, decl));
            for (k, d) in casos {
                let _ = writeln!(s, "      case {k:#x}: goto L_{:x};", d.0);
            }
            let _ = writeln!(s, "      default: goto L_{:x};", defecto.0);
            let _ = writeln!(s, "    }}");
        }
        Terminador::Retornar(Some(o)) => {
            let _ = writeln!(s, "    return {};", texto_operando(o, decl));
        }
        Terminador::Retornar(None) => {
            let _ = writeln!(s, "    return;");
        }
        Terminador::Indirecto => {
            let _ = writeln!(
                s,
                "    goto desconocido; // transferencia indirecta no resuelta"
            );
        }
        Terminador::Inalcanzable => {
            let _ = writeln!(s, "    /* inalcanzable */");
        }
    }
}

/// El comentario de evidencia de una sentencia: las direcciones que la originan.
fn evidencia(origen: &[u64]) -> String {
    if origen.is_empty() {
        String::new()
    } else {
        let dirs = origen
            .iter()
            .map(|d| format!("{d:#x}"))
            .collect::<Vec<_>>()
            .join(",");
        format!("  // {dirs}")
    }
}

/// Emite una funcion como C **recompilable** con una firma dada, o `None` si la
/// funcion no es «limpia».
///
/// Es lo que usa el redondeo semantico: para comprobar equivalencia hay que
/// recompilar, y solo se recompila lo que es C valido. Una funcion con un `phi`
/// sin destruir, un operando indefinido o una transferencia indirecta no se
/// intenta —se cuenta honestamente como no verificada—, en vez de emitir algo que
/// no compila y fingir que se probo.
///
/// `nombre` es el nombre C de la funcion; `num_args` cuantos argumentos enteros
/// toma; `tipo_c` el tipo de retorno y de los argumentos (p. ej. `"long"`).
#[must_use]
pub fn emitir_compilable(
    f: &FuncionIr,
    nombre: &str,
    num_args: u32,
    tipo_c: &str,
) -> Option<String> {
    if !es_limpia(f) {
        return None;
    }
    let disp = disponer(f);
    let mut declaradas: BTreeMap<ValId, (String, Tipo)> = BTreeMap::new();
    let mut basura = Calidad::default();
    recopilar_variables(f, &BTreeMap::new(), &mut declaradas, &mut basura);

    let mut s = String::new();
    let params = (0..num_args)
        .map(|n| format!("{tipo_c} arg{n}"))
        .collect::<Vec<_>>()
        .join(", ");
    let params = if params.is_empty() {
        "void".to_string()
    } else {
        params
    };
    let _ = writeln!(s, "{tipo_c} {nombre}({params}) {{");
    for (n, t) in declaradas.values() {
        // Los argumentos ya son parametros; el resto se declara con un tipo C
        // valido (el reconstruido, o el ancho como entero con signo).
        let ct = if t.es_desconocido_para_el_usuario() {
            tipo_c.to_string()
        } else {
            t.c()
        };
        let _ = writeln!(s, "    {ct} {n};");
    }
    for (i, id) in disp.orden.iter().enumerate() {
        let Some(bl) = f.bloques.get(id) else {
            continue;
        };
        let _ = writeln!(s, "  L_{:x}:;", id.0);
        for sent in &bl.sentencias {
            emitir_sentencia(&mut s, sent, &declaradas);
        }
        let siguiente = disp.orden.get(i + 1).copied();
        emitir_terminador(&mut s, f, *id, &bl.terminador, siguiente, &declaradas);
    }
    let _ = writeln!(s, "}}");
    Some(s)
}

/// Si una funcion se puede emitir como C recompilable: sin `phi`, sin operandos
/// indefinidos, sin transferencia indirecta.
#[must_use]
pub fn es_limpia(f: &FuncionIr) -> bool {
    for bl in f.bloques_ordenados() {
        if matches!(bl.terminador, Terminador::Indirecto) {
            return false;
        }
        if let Terminador::Rama {
            cond: Operando::Indefinido,
            ..
        } = bl.terminador
        {
            return false;
        }
        for sent in &bl.sentencias {
            match sent {
                Sentencia::Definir { op, .. } => {
                    if matches!(op, Operacion::Fi(_) | Operacion::Indefinido) {
                        return false;
                    }
                    if operacion_tiene_indefinido(op) {
                        return false;
                    }
                }
                Sentencia::Almacenar { dir, valor, .. } => {
                    if *dir == Operando::Indefinido || *valor == Operando::Indefinido {
                        return false;
                    }
                }
                Sentencia::Llamada { .. } => return false, // sin modelo de efectos aun
            }
        }
    }
    true
}

/// Si una operacion referencia algun operando indefinido.
fn operacion_tiene_indefinido(op: &Operacion) -> bool {
    let ind = |o: &Operando| *o == Operando::Indefinido;
    match op {
        Operacion::Copiar(o) | Operacion::Un { a: o, .. } => ind(o),
        Operacion::Bin { a, b, .. } | Operacion::Comparar { a, b, .. } => ind(a) || ind(b),
        Operacion::Cargar { dir, .. } => ind(dir),
        Operacion::Fi(_) | Operacion::Indefinido => true,
        Operacion::ResultadoLlamada | Operacion::Argumento(_) => false,
    }
}

/// Emite el pseudo-C de todas las funciones de una lista, en orden de entrada.
#[must_use]
pub fn emitir_todas(funciones: &[FuncionIr], tipos: &BTreeMap<ValId, Tipo>) -> PseudoC {
    let mut texto = String::new();
    let mut calidad = Calidad::default();
    let mut orden: Vec<&FuncionIr> = funciones.iter().collect();
    orden.sort_by_key(|f| f.entrada);
    for f in orden {
        let p = emitir(f, tipos, Calidad::default());
        texto.push_str(&p.texto);
        texto.push('\n');
        calidad = calidad.mas(p.calidad);
    }
    PseudoC { texto, calidad }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::ir::{BloqueId, BloqueIr};

    fn funcion_recta() -> FuncionIr {
        // v0 = 2 + 3; return v0;
        let mut f = FuncionIr::nueva(0x1000);
        f.bloques.insert(
            BloqueId(0x1000),
            BloqueIr {
                id: BloqueId(0x1000),
                sentencias: vec![Sentencia::Definir {
                    destino: ValId(0),
                    ancho: Ancho::B32,
                    tipo: Tipo::Desconocido,
                    op: Operacion::Bin {
                        op: OpBin::Sumar,
                        a: Operando::Const(2, Ancho::B32),
                        b: Operando::Const(3, Ancho::B32),
                    },
                    origen: vec![0x1000],
                }],
                terminador: Terminador::Retornar(Some(Operando::Val(ValId(0)))),
            },
        );
        f.valores = 1;
        f
    }

    #[test]
    fn el_pseudo_c_lleva_evidencia_y_declara_variables() {
        let p = emitir(&funcion_recta(), &BTreeMap::new(), Calidad::default());
        assert!(
            p.texto.contains("0x1000"),
            "falta la evidencia: {}",
            p.texto
        );
        assert!(p.texto.contains("return"), "{}", p.texto);
        assert!(p.texto.contains("+ 0x3"), "la suma se emite: {}", p.texto);
        assert!(
            p.texto.contains("calidad:"),
            "la calidad viaja con el texto"
        );
    }

    #[test]
    fn la_emision_es_determinista() {
        let a = emitir(&funcion_recta(), &BTreeMap::new(), Calidad::default());
        let b = emitir(&funcion_recta(), &BTreeMap::new(), Calidad::default());
        assert_eq!(a.texto, b.texto);
    }

    #[test]
    fn una_variable_sin_tipo_reconstruido_cuenta_en_la_calidad() {
        let p = emitir(&funcion_recta(), &BTreeMap::new(), Calidad::default());
        // Sin mapa de tipos, la variable sale con tipo por ancho (int32_t), que NO
        // es desconocido: el ancho es un hecho. Asi que no cuenta como sin tipo.
        assert_eq!(p.calidad.variables_sin_tipo, 0);
        assert_eq!(p.calidad.variables_totales, 1);
    }
}
