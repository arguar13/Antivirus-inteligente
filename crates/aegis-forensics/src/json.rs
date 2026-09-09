//! Escritura de JSON, minima y correcta.
//!
//! # Por que a mano y no con una caja
//!
//! Lo unico dificil de emitir JSON es el escapado, y aqui el material de entrada
//! es hostil por definicion: nombres de fichero y lineas de comandos que el
//! ATACANTE elige. Un `"` sin escapar en el nombre de un binario rompe el
//! documento; peor, permite inyectar campos y falsificar el propio informe
//! forense. Concentrar el escapado en una funcion de veinte lineas, con pruebas
//! que le meten comillas, contrabarras, saltos de linea y bytes invalidos, es
//! mas auditable que confiar en que una dependencia lo haga bien.
//!
//! El formato es el de RFC 8259: se escapan las comillas, la contrabarra y todo
//! lo que este por debajo de `0x20`, estos ultimos en la forma `\u00XX`.

use std::fmt::Write;

/// Escribe una cadena JSON, con comillas y escapada.
pub fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Devuelve una cadena JSON ya escapada.
pub fn quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    write_str(&mut o, s);
    o
}

/// Convierte bytes arbitrarios en una cadena valida.
///
/// La linea de comandos de un proceso no tiene por que ser UTF-8: el kernel
/// guarda los bytes que le dieron. Sustituir lo invalido es lo correcto para un
/// informe —el dato aproximado es util— siempre que el documento siga siendo
/// valido, que es lo que garantiza esto.
pub fn from_bytes(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Constructor de objetos JSON que se encarga de las comas.
///
/// Las comas de mas o de menos son el otro error clasico de emitir JSON a mano,
/// y aparecen justo cuando un campo es opcional.
#[derive(Debug)]
pub struct Obj {
    buf: String,
    vacio: bool,
}

impl Obj {
    /// Empieza un objeto.
    pub fn new() -> Obj {
        Obj {
            buf: String::from("{"),
            vacio: true,
        }
    }

    fn coma(&mut self) {
        if self.vacio {
            self.vacio = false;
        } else {
            self.buf.push(',');
        }
    }

    /// Campo de texto.
    pub fn str(&mut self, k: &str, v: &str) -> &mut Obj {
        self.coma();
        write_str(&mut self.buf, k);
        self.buf.push(':');
        write_str(&mut self.buf, v);
        self
    }

    /// Campo de texto que se omite si es `None`.
    ///
    /// Se omite en vez de emitir `null`: en STIX, una propiedad ausente y una
    /// presente con valor nulo no significan lo mismo, y la segunda es invalida
    /// para casi todas.
    pub fn opt_str(&mut self, k: &str, v: Option<&str>) -> &mut Obj {
        if let Some(v) = v {
            self.str(k, v);
        }
        self
    }

    /// Campo numerico.
    pub fn num(&mut self, k: &str, v: u64) -> &mut Obj {
        self.coma();
        write_str(&mut self.buf, k);
        let _ = write!(self.buf, ":{v}");
        self
    }

    /// Campo numerico que se omite si es `None`.
    pub fn opt_num(&mut self, k: &str, v: Option<u64>) -> &mut Obj {
        if let Some(v) = v {
            self.num(k, v);
        }
        self
    }

    /// Campo booleano.
    pub fn bool(&mut self, k: &str, v: bool) -> &mut Obj {
        self.coma();
        write_str(&mut self.buf, k);
        let _ = write!(self.buf, ":{v}");
        self
    }

    /// Campo cuyo valor ya es JSON valido.
    pub fn raw(&mut self, k: &str, v: &str) -> &mut Obj {
        self.coma();
        write_str(&mut self.buf, k);
        self.buf.push(':');
        self.buf.push_str(v);
        self
    }

    /// Campo con un vector de cadenas.
    pub fn str_array(&mut self, k: &str, v: &[String]) -> &mut Obj {
        let mut a = String::from("[");
        for (i, s) in v.iter().enumerate() {
            if i > 0 {
                a.push(',');
            }
            write_str(&mut a, s);
        }
        a.push(']');
        self.raw(k, &a)
    }

    /// Cierra el objeto y devuelve el JSON.
    pub fn finish(&self) -> String {
        let mut s = self.buf.clone();
        s.push('}');
        s
    }
}

impl Default for Obj {
    fn default() -> Self {
        Obj::new()
    }
}

/// Une objetos ya serializados en un array JSON.
pub fn array(items: &[String]) -> String {
    let mut s = String::from("[");
    for (i, o) in items.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(o);
    }
    s.push(']');
    s
}
