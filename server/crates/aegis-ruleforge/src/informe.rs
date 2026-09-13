//! El informe de compilacion: cuantas de cuantas, y por que las demas no.
//!
//! # La cifra que define si esta fase sirve
//!
//! Un compilador de reglas que devuelve «he compilado 34.812 reglas» no dice
//! nada. La pregunta que importa es **34.812 de cuantas**, y de las que faltan,
//! **cuales y por que**.
//!
//! Sin esa segunda parte, el operador cree que su producto cubre lo que dice el
//! feed, cuando en realidad cubre la parte que el compilador supo entender. Y lo
//! que no supo entender no es aleatorio: son las reglas que usan las opciones
//! mas nuevas, que son las que cubren las amenazas mas recientes. Es decir, el
//! silencio se concentra justo donde mas duele.
//!
//! # Por que se cuenta por MOTIVO y no por total
//!
//! «Han fallado 1.200 reglas» y «han fallado 1.200 reglas, todas por usar
//! `byte_extract`» son informes distintos. El primero invita a encogerse de
//! hombros; el segundo es una lista de trabajo concreta. Por eso cada rechazo
//! lleva su motivo con nombre estable, y el informe los agrupa.

use std::collections::BTreeMap;

/// Por que una regla no se compilo.
///
/// El nombre es estable a proposito: se cuenta, se agrupa y se compara entre
/// versiones del corpus. Un motivo que cambia de nombre rompe las comparaciones
/// historicas justo cuando sirven, que es al ver si una version nueva perdio
/// cobertura.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rechazo {
    /// Identificador de la regla, tal y como venia en el feed.
    pub regla: String,
    /// Codigo estable del motivo.
    pub motivo: &'static str,
    /// Detalle legible, con el nombre concreto de lo que no se soporta.
    pub detalle: String,
}

impl Rechazo {
    /// Un rechazo con su motivo y su detalle.
    #[must_use]
    pub fn nuevo(
        regla: impl Into<String>,
        motivo: &'static str,
        detalle: impl Into<String>,
    ) -> Rechazo {
        Rechazo {
            regla: regla.into(),
            motivo,
            detalle: detalle.into(),
        }
    }
}

/// El resultado de compilar un feed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Informe {
    /// Reglas que venian en la entrada.
    pub vistas: usize,
    /// Reglas que se compilaron.
    pub compiladas: usize,
    /// Reglas rechazadas, cada una con su motivo.
    ///
    /// Se guardan TODAS, no una muestra: una muestra impide responder «¿esta la
    /// regla X entre las que se perdieron?», que es la pregunta que se hace
    /// cuando una deteccion no salta.
    pub rechazos: Vec<Rechazo>,
    /// Reglas duplicadas que se descartaron por venir ya en el corpus.
    pub duplicadas: usize,
}

impl Informe {
    /// Anota una regla compilada.
    pub fn compilada(&mut self) {
        self.vistas += 1;
        self.compiladas += 1;
    }

    /// Anota una regla rechazada.
    pub fn rechazada(&mut self, r: Rechazo) {
        self.vistas += 1;
        self.rechazos.push(r);
    }

    /// Anota una regla duplicada.
    pub fn duplicada(&mut self) {
        self.vistas += 1;
        self.duplicadas += 1;
    }

    /// Funde otro informe en este.
    pub fn fundir(&mut self, otro: Informe) {
        self.vistas += otro.vistas;
        self.compiladas += otro.compiladas;
        self.duplicadas += otro.duplicadas;
        self.rechazos.extend(otro.rechazos);
    }

    /// Cuantas se rechazaron.
    #[must_use]
    pub fn rechazadas(&self) -> usize {
        self.rechazos.len()
    }

    /// Fraccion compilada, entre 0 y 1.
    ///
    /// Un feed vacio da 0 y no 1: «no habia nada que compilar» no es «lo he
    /// compilado todo», y devolver 1 haria que un feed que llego vacio por un
    /// fallo de red pareciera un exito.
    #[must_use]
    pub fn cobertura(&self) -> f64 {
        if self.vistas == 0 {
            return 0.0;
        }
        self.compiladas as f64 / self.vistas as f64
    }

    /// Rechazos agrupados por motivo, de mas a menos frecuente.
    ///
    /// Es la vista que convierte «han fallado 1.200 reglas» en una lista de
    /// trabajo: casi siempre son unos pocos motivos repetidos muchas veces.
    #[must_use]
    pub fn por_motivo(&self) -> Vec<(&'static str, usize)> {
        let mut cuenta: BTreeMap<&'static str, usize> = BTreeMap::new();
        for r in &self.rechazos {
            *cuenta.entry(r.motivo).or_insert(0) += 1;
        }
        let mut v: Vec<(&'static str, usize)> = cuenta.into_iter().collect();
        // De mas a menos; con empate, por nombre, para que el informe sea
        // reproducible y se pueda comparar entre ejecuciones.
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        v
    }

    /// Una linea que resume el informe, para un registro o un correo.
    #[must_use]
    pub fn resumen(&self) -> String {
        let mut s = format!(
            "{} de {} reglas compiladas ({:.1} %)",
            self.compiladas,
            self.vistas,
            self.cobertura() * 100.0
        );
        if self.duplicadas > 0 {
            s.push_str(&format!(", {} duplicadas", self.duplicadas));
        }
        let motivos = self.por_motivo();
        if !motivos.is_empty() {
            s.push_str("; rechazos: ");
            let partes: Vec<String> = motivos.iter().map(|(m, n)| format!("{m}={n}")).collect();
            s.push_str(&partes.join(", "));
        }
        s
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_informe_cuenta_las_tres_categorias() {
        let mut i = Informe::default();
        i.compilada();
        i.compilada();
        i.rechazada(Rechazo::nuevo(
            "sid:1",
            "opcion-no-soportada",
            "byte_extract",
        ));
        i.duplicada();

        assert_eq!(i.vistas, 4);
        assert_eq!(i.compiladas, 2);
        assert_eq!(i.rechazadas(), 1);
        assert_eq!(i.duplicadas, 1);
        assert!((i.cobertura() - 0.5).abs() < 1e-9);
    }

    /// UN FEED VACIO NO ES UN EXITO. Si la cobertura de cero reglas fuera 1,
    /// un feed que llego vacio por un fallo de red pareceria perfecto.
    #[test]
    fn un_feed_vacio_no_tiene_cobertura_completa() {
        let i = Informe::default();
        assert_eq!(i.cobertura(), 0.0);
    }

    /// LOS RECHAZOS SE GUARDAN TODOS, no una muestra: una muestra impide
    /// responder «¿se perdio la regla X?», que es la pregunta que se hace cuando
    /// una deteccion no salta.
    #[test]
    fn se_guardan_todos_los_rechazos_y_se_pueden_buscar() {
        let mut i = Informe::default();
        for n in 0..500 {
            i.rechazada(Rechazo::nuevo(
                format!("sid:{n}"),
                "opcion-no-soportada",
                "byte_extract",
            ));
        }
        assert_eq!(i.rechazadas(), 500);
        assert!(i.rechazos.iter().any(|r| r.regla == "sid:499"));
    }

    /// Agrupar por motivo es lo que convierte un numero en una lista de trabajo.
    #[test]
    fn los_motivos_se_agrupan_de_mas_a_menos() {
        let mut i = Informe::default();
        for _ in 0..10 {
            i.rechazada(Rechazo::nuevo("x", "opcion-no-soportada", "byte_extract"));
        }
        for _ in 0..3 {
            i.rechazada(Rechazo::nuevo("y", "regex-patologica", "(a+)+"));
        }
        let motivos = i.por_motivo();
        assert_eq!(motivos[0], ("opcion-no-soportada", 10));
        assert_eq!(motivos[1], ("regex-patologica", 3));
    }

    /// El orden con empate es por nombre, para que el informe sea reproducible:
    /// dos ejecuciones del mismo feed tienen que dar el mismo texto, o no se
    /// pueden comparar versiones.
    #[test]
    fn el_orden_es_reproducible_con_empates() {
        let mut i = Informe::default();
        i.rechazada(Rechazo::nuevo("x", "zeta", "a"));
        i.rechazada(Rechazo::nuevo("y", "alfa", "b"));
        let motivos = i.por_motivo();
        assert_eq!(motivos[0].0, "alfa");
        assert_eq!(motivos[1].0, "zeta");
    }

    #[test]
    fn el_resumen_dice_cuantas_de_cuantas_y_por_que() {
        let mut i = Informe::default();
        i.compilada();
        i.rechazada(Rechazo::nuevo("sid:1", "regex-patologica", "(a+)+$"));
        let s = i.resumen();
        assert!(s.contains("1 de 2"), "{s}");
        assert!(s.contains("regex-patologica=1"), "{s}");
    }

    #[test]
    fn fundir_suma_las_cuentas_y_conserva_los_rechazos() {
        let mut a = Informe::default();
        a.compilada();
        let mut b = Informe::default();
        b.rechazada(Rechazo::nuevo("sid:7", "motivo", "detalle"));
        a.fundir(b);
        assert_eq!(a.vistas, 2);
        assert_eq!(a.compiladas, 1);
        assert_eq!(a.rechazadas(), 1);
        assert_eq!(a.rechazos[0].regla, "sid:7");
    }
}
