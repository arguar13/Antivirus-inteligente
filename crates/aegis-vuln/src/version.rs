//! Comparacion de versiones de paquete segun la politica de Debian.
//!
//! Es la pieza mas delicada del escaneo de CVE y la que mas silenciosamente se
//! hace mal. Comparar versiones como cadenas dice que `1.10` es menor que `1.9`;
//! compararlas troceando por puntos y convirtiendo a entero se rompe con
//! `1.0-1ubuntu2` o con `1.0~rc1`. Cualquiera de los dos errores produce lo
//! peor que puede hacer un escaner de vulnerabilidades: decir que un sistema
//! esta parcheado cuando no lo esta.
//!
//! Se implementa el algoritmo de `deb-version(7)`:
//!
//! ```text
//! [epoch:]upstream[-revision]
//! ```
//!
//! - El epoch se compara numericamente y por defecto es 0.
//! - `upstream` y `revision` se comparan alternando tramos no numericos y
//!   numericos. Los tramos numericos se comparan como enteros (los ceros a la
//!   izquierda no cuentan) y los no numericos con un orden modificado en el que
//!   `~` va antes que TODO, incluido el fin de cadena, y las letras van antes
//!   que el resto de caracteres.
//!
//! La regla de `~` es la que hace que `1.0~rc1` sea anterior a `1.0`, que es
//! justo el caso que un comparador ingenuo invierte.

use std::cmp::Ordering;

/// Version de un paquete en formato Debian.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    epoch: u32,
    upstream: String,
    revision: String,
}

impl Version {
    /// Analiza una version en formato `[epoch:]upstream[-revision]`.
    ///
    /// No falla: una version con formato raro se trata como `upstream` puro.
    /// Un escaner que descarta paquetes cuya version no sabe analizar deja
    /// agujeros silenciosos en la cobertura, que es peor que compararla de
    /// forma aproximada y decirlo.
    pub fn parse(s: &str) -> Version {
        let s = s.trim();

        let (epoch, resto) = match s.find(':') {
            Some(i) => match s[..i].parse::<u32>() {
                Ok(e) => (e, &s[i + 1..]),
                Err(_) => (0, s),
            },
            None => (0, s),
        };

        // La revision es lo que sigue al ULTIMO guion: el upstream puede
        // contener guiones y la revision no.
        let (upstream, revision) = match resto.rfind('-') {
            Some(i) => (&resto[..i], &resto[i + 1..]),
            None => (resto, ""),
        };

        Version {
            epoch,
            upstream: upstream.to_string(),
            revision: revision.to_string(),
        }
    }

    /// Epoch de la version.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Parte upstream, tal y como la declara el paquete.
    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    /// Version del CONTENIDO real, resolviendo la convencion `+really`.
    ///
    /// Debian y Ubuntu usan `X+reallyY` cuando revierten el contenido de un
    /// paquete a la version `Y` pero necesitan que el numero siga ordenando por
    /// encima de `X` para que las actualizaciones lleguen a todo el mundo. El
    /// caso canonico es `xz-utils 5.6.1+really5.4.5`, publicado para revertir
    /// la puerta trasera de CVE-2024-3094.
    ///
    /// Comparar rangos de CVE contra el numero declarado dice que ese paquete
    /// esta dentro de `[5.6.0, 5.6.2)` y lo reporta como vulnerable, cuando el
    /// codigo que contiene es 5.4.5 y no lo es. Es un falso positivo sobre un
    /// CVE de CVSS 10.0, es decir, exactamente el hallazgo que un operador va a
    /// mirar primero y que le ensenara a desconfiar del escaner entero.
    ///
    /// Solo `+really` cambia el contenido. Otros sufijos de empaquetado
    /// (`+dfsg`, `+ds`, `+deb12u1`) no lo hacen y no se tocan.
    pub fn effective(&self) -> Version {
        match self.upstream.find("+really") {
            Some(i) => Version {
                epoch: self.epoch,
                upstream: self.upstream[i + "+really".len()..].to_string(),
                // La revision es de empaquetado y no describe el contenido
                // upstream, asi que no participa en la comparacion efectiva.
                revision: String::new(),
            },
            None => self.clone(),
        }
    }

    /// Indica si la version declara un contenido revertido con `+really`.
    pub fn is_reverted(&self) -> bool {
        self.upstream.contains("+really")
    }

    /// Revision de la distribucion.
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

/// Peso de un caracter en el orden modificado de Debian.
///
/// `~` tiene que ordenar por debajo de todo, incluido el fin de cadena, para
/// que las preliberaciones (`1.0~rc1`) queden por debajo de la version final.
/// Las letras ordenan por debajo del resto de caracteres no alfanumericos.
fn peso(c: Option<char>) -> i32 {
    match c {
        Some('~') => -1,
        None => 0, // fin de cadena
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(c) => c as i32 + 256,
    }
}

/// Compara un tramo de version (upstream o revision) segun el algoritmo Debian.
fn comparar_tramo(a: &str, b: &str) -> Ordering {
    let mut ai = a.chars().peekable();
    let mut bi = b.chars().peekable();

    loop {
        // --- Tramo no numerico ---
        loop {
            let ca = ai.peek().copied().filter(|c| !c.is_ascii_digit());
            let cb = bi.peek().copied().filter(|c| !c.is_ascii_digit());
            if ca.is_none() && cb.is_none() {
                break;
            }
            let orden = peso(ca).cmp(&peso(cb));
            if orden != Ordering::Equal {
                return orden;
            }
            if ca.is_some() {
                ai.next();
            }
            if cb.is_some() {
                bi.next();
            }
        }

        // --- Tramo numerico ---
        // Los ceros a la izquierda no cuentan: 007 y 7 son la misma version.
        let mut na = String::new();
        while let Some(c) = ai.peek().copied() {
            if !c.is_ascii_digit() {
                break;
            }
            na.push(c);
            ai.next();
        }
        let mut nb = String::new();
        while let Some(c) = bi.peek().copied() {
            if !c.is_ascii_digit() {
                break;
            }
            nb.push(c);
            bi.next();
        }

        let va = na.trim_start_matches('0');
        let vb = nb.trim_start_matches('0');
        // Numeros mas largos son mayores; a igual longitud, orden lexicografico
        // equivale al numerico. Se hace asi para no desbordar con versiones que
        // llevan numeros absurdamente largos, que existen.
        let orden = va.len().cmp(&vb.len()).then_with(|| va.cmp(vb));
        if orden != Ordering::Equal {
            return orden;
        }

        if ai.peek().is_none() && bi.peek().is_none() {
            return Ordering::Equal;
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| comparar_tramo(&self.upstream, &other.upstream))
            .then_with(|| comparar_tramo(&self.revision, &other.revision))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.epoch != 0 {
            write!(f, "{}:", self.epoch)?;
        }
        write!(f, "{}", self.upstream)?;
        if !self.revision.is_empty() {
            write!(f, "-{}", self.revision)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        Version::parse(a).cmp(&Version::parse(b))
    }

    #[test]
    fn comparacion_numerica_no_lexicografica() {
        // El error clasico: como cadenas, "1.10" < "1.9".
        assert_eq!(cmp("1.10", "1.9"), Greater);
        assert_eq!(cmp("1.9", "1.10"), Less);
        assert_eq!(cmp("2.0", "10.0"), Less);
    }

    #[test]
    fn los_ceros_a_la_izquierda_no_cuentan() {
        assert_eq!(cmp("1.007", "1.7"), Equal);
        assert_eq!(cmp("0.0.1", "0.0.01"), Equal);
    }

    #[test]
    fn la_tilde_ordena_por_debajo_de_todo() {
        // La regla que un comparador ingenuo invierte: una preliberacion es
        // ANTERIOR a la version final, no posterior.
        assert_eq!(cmp("1.0~rc1", "1.0"), Less);
        assert_eq!(cmp("1.0~beta", "1.0~rc1"), Less);
        assert_eq!(cmp("1.0~~", "1.0~"), Less);
        assert_eq!(cmp("1.0~", "1.0"), Less);
    }

    #[test]
    fn el_epoch_domina_sobre_el_upstream() {
        // Un epoch existe justamente para que un numero de version mas bajo
        // pueda declararse posterior tras un renumerado del upstream.
        assert_eq!(cmp("1:1.0", "2.0"), Greater);
        assert_eq!(cmp("1.0", "1:0.1"), Less);
    }

    #[test]
    fn la_revision_desempata() {
        assert_eq!(cmp("1.0-1", "1.0-2"), Less);
        assert_eq!(cmp("1.0-1ubuntu2", "1.0-1ubuntu10"), Less);
        assert_eq!(cmp("1.0-1", "1.0"), Greater);
    }

    #[test]
    fn las_letras_ordenan_antes_que_los_simbolos() {
        assert_eq!(cmp("1.0a", "1.0+"), Less);
    }

    #[test]
    fn casos_reales_de_distribucion() {
        // openssl parcheado frente a vulnerable.
        assert_eq!(cmp("3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.10"), Greater);
        // glibc con epoch.
        assert_eq!(cmp("2.39-0ubuntu8.7", "2.39-0ubuntu8"), Greater);
        // sudo con sufijo alfabetico en upstream.
        assert_eq!(cmp("1.9.15p5-3ubuntu5", "1.9.15p5-3ubuntu5"), Equal);
        assert_eq!(cmp("1.9.15p5-3ubuntu5", "1.9.15p4-3ubuntu5"), Greater);
    }

    #[test]
    fn el_analisis_reparte_bien_las_partes() {
        let v = Version::parse("2:1.2.3~rc1-4ubuntu5");
        assert_eq!(v.epoch(), 2);
        assert_eq!(v.upstream(), "1.2.3~rc1");
        // La revision es lo que sigue al ULTIMO guion.
        assert_eq!(v.revision(), "4ubuntu5");
        assert_eq!(v.to_string(), "2:1.2.3~rc1-4ubuntu5");
    }

    #[test]
    fn el_upstream_puede_contener_guiones() {
        let v = Version::parse("1.0-beta-3");
        assert_eq!(v.upstream(), "1.0-beta");
        assert_eq!(v.revision(), "3");
    }

    #[test]
    fn una_version_ilegible_no_se_descarta() {
        // Descartar lo que no se sabe analizar deja agujeros silenciosos en la
        // cobertura del escaner.
        let v = Version::parse("no-es::una:version");
        assert_eq!(v.epoch(), 0);
        assert!(!v.upstream().is_empty());
    }

    #[test]
    fn really_resuelve_la_version_real_del_contenido() {
        // El caso que motivo esto: Ubuntu publico 5.6.1+really5.4.5 para
        // revertir la puerta trasera de xz. El numero declarado cae dentro del
        // rango vulnerable [5.6.0, 5.6.2) pero el contenido es 5.4.5.
        let v = Version::parse("5.6.1+really5.4.5-1ubuntu0.2");
        assert!(v.is_reverted());
        assert_eq!(v.effective().to_string(), "5.4.5");

        // Ordenado por el numero declarado, esta dentro del rango vulnerable.
        assert!(v > Version::parse("5.6.0"));
        // Por contenido real, esta por debajo y no lo esta.
        assert!(v.effective() < Version::parse("5.6.0"));

        // El epoch se conserva.
        let e = Version::parse("2:1.0+really0.9-1");
        assert_eq!(e.effective().epoch(), 2);
        assert_eq!(e.effective().upstream(), "0.9");
    }

    #[test]
    fn los_sufijos_de_empaquetado_normales_no_se_tocan() {
        // Solo +really cambia el contenido; el resto son convenciones de
        // empaquetado y alterarlas romperia la comparacion.
        for v in [
            "1.2.3+dfsg-1",
            "1.2.3+ds1-2",
            "1.2.3+deb12u1",
            "1.2.3~bpo11+1",
        ] {
            let p = Version::parse(v);
            assert!(!p.is_reverted(), "{v} no deberia considerarse revertida");
            assert_eq!(p.effective().upstream(), p.upstream());
        }
    }

    #[test]
    fn el_orden_es_total_y_consistente() {
        let mut vs: Vec<Version> = [
            "1.0", "1.0~rc1", "0.9", "1:0.1", "1.0-1", "1.10", "1.9", "2.0",
        ]
        .iter()
        .map(|s| Version::parse(s))
        .collect();
        vs.sort();
        let orden: Vec<String> = vs.iter().map(|v| v.to_string()).collect();
        assert_eq!(
            orden,
            vec!["0.9", "1.0~rc1", "1.0", "1.0-1", "1.9", "1.10", "2.0", "1:0.1"]
        );
    }
}
