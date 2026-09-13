//! Metricas del SOC, y las tres que de verdad cambian algo.
//!
//! # Las metricas existen para APAGAR reglas
//!
//! Un panel lleno de tiempos medios es decorativo. La unica metrica que cambia el
//! comportamiento de un centro de operaciones es **cuanto ruido hace cada regla**,
//! porque es la que permite apagar las que solo hacen ruido.
//!
//! Y eso importa mucho mas de lo que parece: un analista que recibe cincuenta
//! alertas al dia de las que cuarenta y ocho son ruido **deja de mirarlas**. No
//! por dejadez, sino porque es la respuesta racional a una senal con esa relacion
//! de ruido. El dia que llega la que importa, va al mismo sitio que las demas.
//!
//! Asi que la regla ruidosa no es un problema de comodidad: es una **perdida de
//! deteccion**, y de las peores, porque el panel sigue diciendo que la regla esta
//! activa.
//!
//! # Los tres tiempos, y por que el del medio no es el que parece
//!
//! * **Hasta deteccion**: de cuando OCURRIO lo primero a cuando se abrio el caso.
//!   Se mide desde la ocurrencia y no desde la alerta, porque si no, un sensor
//!   que tarda una hora en reportar sale con deteccion instantanea.
//! * **Hasta respuesta**: de la apertura a la CONTENCION, no al primer vistazo.
//!   Un caso que alguien abrio y dejo no ha tenido respuesta, por mucho que se
//!   haya mirado. Medir el vistazo premia justo lo que no sirve.
//! * **Hasta cierre**: de la apertura al veredicto. Es el que menos dice de los
//!   tres, y se publica el ultimo a proposito: un equipo que optimiza el cierre
//!   cierra casos, que no es lo mismo que resolverlos.
//!
//! # El tiempo en espera se descuenta
//!
//! Si un caso pasa seis horas esperando a que el cliente conteste, esas seis
//! horas no son tiempo de respuesta del equipo. Contarlas hace que la metrica
//! empeore por algo que no depende del equipo, y una metrica que no depende de
//! quien la puede mover deja de usarse en una semana.

use std::collections::BTreeMap;

use crate::modelo::{Caso, Estado, Veredicto};

/// Un resumen de percentiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Percentiles {
    /// Cuantas muestras.
    pub muestras: usize,
    /// Mediana, en nanosegundos.
    pub p50_ns: u64,
    /// Percentil 95.
    pub p95_ns: u64,
    /// Percentil 99.
    pub p99_ns: u64,
    /// El peor caso.
    ///
    /// Se publica junto a los percentiles porque es lo unico que enseña el caso
    /// que se quedo olvidado: con cien casos de diez minutos y uno de tres
    /// semanas, hasta el percentil 99 dice diez minutos.
    pub maximo_ns: u64,
}

impl Percentiles {
    /// Calcula los percentiles de una muestra.
    #[must_use]
    pub fn de(mut v: Vec<u64>) -> Percentiles {
        if v.is_empty() {
            return Percentiles::default();
        }
        v.sort_unstable();
        let en = |q: usize| v[(v.len() * q / 100).min(v.len() - 1)];
        Percentiles {
            muestras: v.len(),
            p50_ns: en(50),
            p95_ns: en(95),
            p99_ns: en(99),
            maximo_ns: *v.last().expect("no vacio"),
        }
    }
}

/// Lo que se sabe de una regla.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Regla {
    /// Nombre de la regla.
    pub nombre: String,
    /// Alertas que produjo.
    pub alertas: u64,
    /// Casos cerrados que la incluian.
    pub casos_cerrados: u64,
    /// Casos cerrados como falso positivo.
    pub falsos_positivos: u64,
    /// Casos cerrados como ataque real.
    pub verdaderos: u64,
    /// Casos cerrados como actividad autorizada.
    pub autorizados: u64,
    /// Casos que no se pudieron determinar.
    ///
    /// **No cuentan como ruido.** Ver [`Regla::ruido_centesimas`].
    pub no_concluyentes: u64,
}

impl Regla {
    /// Ruido de la regla, en centesimas, o `None` si no hay base suficiente.
    ///
    /// # Las dos decisiones que hacen que este numero sirva
    ///
    /// 1. **El denominador excluye lo no concluyente.** Un caso que nadie pudo
    ///    resolver no dice nada sobre la regla. Meterlo abajo hace que una regla
    ///    buena con casos dificiles parezca ruidosa, y apagarla es exactamente el
    ///    error que deja un hueco de deteccion.
    /// 2. **Lo autorizado tampoco es ruido.** La regla acerto: el hecho ocurrio y
    ///    estaba permitido. Lo que hay que ajustar es la lista de excepciones, no
    ///    la regla.
    ///
    /// Devuelve `None` con menos de [`MINIMO_PARA_JUZGAR`] casos concluyentes:
    /// apagar una regla porque sus dos primeros casos fueron falsos positivos es
    /// la forma mas rapida de quedarse sin deteccion.
    #[must_use]
    pub fn ruido_centesimas(&self) -> Option<u64> {
        let base = self.falsos_positivos + self.verdaderos + self.autorizados;
        if base < MINIMO_PARA_JUZGAR {
            return None;
        }
        Some(self.falsos_positivos * 100 / base)
    }

    /// Si la regla merece revisarse.
    #[must_use]
    pub fn sospechosa(&self) -> bool {
        self.ruido_centesimas().is_some_and(|r| r >= UMBRAL_RUIDO)
    }
}

/// Casos concluyentes minimos para juzgar una regla.
///
/// Veinte. Apagar una regla porque sus dos primeros casos fueron falsos positivos
/// es la forma mas rapida de quedarse sin deteccion, y pasa: las reglas nuevas
/// empiezan con pocos casos y alguien mira el panel.
pub const MINIMO_PARA_JUZGAR: u64 = 20;

/// Ruido, en centesimas, a partir del cual una regla se marca para revision.
///
/// Setenta por ciento. No es «apagar»: es «alguien tiene que mirar esta regla».
/// La decision de apagar es de una persona, porque una regla ruidosa que cubre
/// una tecnica que nada mas cubre se ajusta, no se apaga.
pub const UMBRAL_RUIDO: u64 = 70;

/// Metricas de un periodo.
#[derive(Debug, Clone, Default)]
pub struct Resumen {
    /// Casos abiertos en el periodo.
    pub abiertos: usize,
    /// Casos cerrados en el periodo.
    pub cerrados: usize,
    /// Casos que siguen vivos.
    pub vivos: usize,
    /// Casos vivos sin asignar.
    ///
    /// Es la cifra que mas dice del estado real de una cola: un caso sin dueño
    /// no lo esta mirando nadie, aunque el panel lo pinte del mismo color.
    pub sin_asignar: usize,
    /// De ocurrencia a apertura.
    pub hasta_deteccion: Percentiles,
    /// De apertura a contencion, descontando la espera.
    pub hasta_respuesta: Percentiles,
    /// De apertura a veredicto.
    pub hasta_cierre: Percentiles,
    /// Casos cerrados por veredicto.
    pub por_veredicto: BTreeMap<&'static str, usize>,
    /// Lo que se sabe de cada regla.
    pub reglas: BTreeMap<String, Regla>,
}

impl Resumen {
    /// Reglas que merecen revisarse, de mas ruidosa a menos.
    #[must_use]
    pub fn reglas_sospechosas(&self) -> Vec<&Regla> {
        let mut v: Vec<&Regla> = self.reglas.values().filter(|r| r.sospechosa()).collect();
        v.sort_by_key(|r| std::cmp::Reverse(r.ruido_centesimas().unwrap_or(0)));
        v
    }

    /// Casos vivos que llevan mas de `plazo_ns` sin cerrarse.
    ///
    /// Se cuenta aparte de los percentiles porque un caso abierto **no esta en la
    /// muestra**: los percentiles solo miden lo que ya se cerro, asi que un caso
    /// que lleva tres semanas abierto no aparece en ningun tiempo hasta que se
    /// cierra. Es el sesgo clasico de estas metricas, y por eso esta cifra va al
    /// lado.
    #[must_use]
    pub fn atascados(casos: &[Caso], ahora_ns: u64, plazo_ns: u64) -> Vec<String> {
        casos
            .iter()
            .filter(|c| c.estado.abierto() && ahora_ns.saturating_sub(c.abierto_ns) > plazo_ns)
            .map(|c| c.id.clone())
            .collect()
    }
}

/// Calcula las metricas de un conjunto de casos.
///
/// `espera_por_caso` lleva, por identificador de caso, cuanto tiempo estuvo en
/// espera de algo externo. Se descuenta del tiempo de respuesta: ver el
/// encabezado del modulo.
#[must_use]
pub fn calcular(casos: &[Caso], espera_por_caso: &BTreeMap<String, u64>) -> Resumen {
    let mut r = Resumen::default();
    let mut deteccion = Vec::new();
    let mut respuesta = Vec::new();
    let mut cierre = Vec::new();

    for c in casos {
        if c.estado.abierto() {
            r.vivos += 1;
            if c.asignado_a.is_none() {
                r.sin_asignar += 1;
            }
        } else {
            r.cerrados += 1;
        }
        r.abiertos += 1;

        // Hasta deteccion: de la OCURRENCIA mas antigua a la apertura del caso.
        if let Some(primera) = c.alertas.iter().map(|a| a.ocurrio_ns).min() {
            let apertura = c
                .primer_vistazo_ns
                .unwrap_or(c.cerrado_ns.unwrap_or(primera));
            deteccion.push(apertura.saturating_sub(primera));
        }

        let espera = espera_por_caso.get(&c.id).copied().unwrap_or(0);
        if let Some(contenido) = c.contenido_ns {
            respuesta.push(
                contenido
                    .saturating_sub(c.abierto_ns)
                    .saturating_sub(espera),
            );
        }
        if let Some(cerrado) = c.cerrado_ns {
            cierre.push(cerrado.saturating_sub(c.abierto_ns).saturating_sub(espera));
        }

        // Por regla. Solo los casos CERRADOS cuentan para el veredicto: un caso
        // abierto todavia no dice nada sobre la regla que lo abrio.
        let Some(v) = c.veredicto else {
            for (regla, n) in c.por_regla() {
                let e = r.reglas.entry(regla.clone()).or_default();
                e.nombre = regla;
                e.alertas += n as u64;
            }
            continue;
        };
        *r.por_veredicto.entry(v.nombre()).or_insert(0) += 1;
        for (regla, n) in c.por_regla() {
            let e = r.reglas.entry(regla.clone()).or_default();
            e.nombre = regla;
            e.alertas += n as u64;
            e.casos_cerrados += 1;
            match v {
                Veredicto::FalsoPositivo => e.falsos_positivos += 1,
                Veredicto::Verdadero => e.verdaderos += 1,
                Veredicto::Autorizado => e.autorizados += 1,
                Veredicto::NoConcluyente => e.no_concluyentes += 1,
            }
        }
    }

    r.hasta_deteccion = Percentiles::de(deteccion);
    r.hasta_respuesta = Percentiles::de(respuesta);
    r.hasta_cierre = Percentiles::de(cierre);
    r
}

/// Cuanto tiempo lleva un caso en espera, a partir de su historia de estados.
///
/// Se calcula de la historia y no de un contador que se va sumando porque un
/// contador se olvida de restar en algun camino, y el sintoma es una metrica que
/// mejora sola.
#[must_use]
pub fn espera_de(historia: &[(Estado, u64)], ahora_ns: u64) -> u64 {
    let mut total = 0u64;
    let mut desde: Option<u64> = None;
    for (estado, cuando) in historia {
        match (*estado, desde) {
            (Estado::EnEspera, None) => desde = Some(*cuando),
            (e, Some(inicio)) if e != Estado::EnEspera => {
                total += cuando.saturating_sub(inicio);
                desde = None;
            }
            _ => {}
        }
    }
    if let Some(inicio) = desde {
        total += ahora_ns.saturating_sub(inicio);
    }
    total
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::modelo::{Alerta, Observable, Severidad};

    const SEG: u64 = 1_000_000_000;
    const MIN: u64 = 60 * SEG;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn alerta(regla: &str, ns: u64) -> Alerta {
        Alerta {
            id: "A-1".into(),
            inquilino: "c".into(),
            anfitrion: "m".into(),
            sujeto: "pid:1".into(),
            tecnica: Some("T1059".into()),
            regla: regla.into(),
            severidad: Severidad::Alta,
            ocurrio_ns: ns,
            observables: vec![Observable::Anfitrion("m".into())],
            resumen: "x".into(),
        }
    }

    fn caso(id: &str, regla: &str, v: Option<Veredicto>) -> Caso {
        let mut c = Caso::abrir(id, alerta(regla, AHORA));
        if let Some(v) = v {
            c.pasar_a(Estado::EnCurso, AHORA + 5 * MIN).unwrap();
            c.pasar_a(Estado::Contenido, AHORA + 20 * MIN).unwrap();
            c.cerrar(v, None, AHORA + 60 * MIN).unwrap();
        }
        c
    }

    #[test]
    fn una_regla_ruidosa_se_marca_para_revision() {
        // LA METRICA QUE CAMBIA ALGO: un analista que recibe cincuenta alertas
        // al dia de las que cuarenta y ocho son ruido deja de mirarlas, y el dia
        // que llega la que importa va al mismo sitio que las demas.
        let mut casos = Vec::new();
        for i in 0..25 {
            casos.push(caso(
                &format!("C-{i}"),
                "regla-ruidosa",
                Some(Veredicto::FalsoPositivo),
            ));
        }
        for i in 0..5 {
            casos.push(caso(
                &format!("D-{i}"),
                "regla-ruidosa",
                Some(Veredicto::Verdadero),
            ));
        }
        let r = calcular(&casos, &BTreeMap::new());
        let regla = &r.reglas["regla-ruidosa"];
        assert_eq!(regla.ruido_centesimas(), Some(83));
        assert!(regla.sospechosa());
        assert_eq!(r.reglas_sospechosas().len(), 1);
    }

    #[test]
    fn lo_no_concluyente_no_cuenta_como_ruido() {
        // Un caso que nadie pudo resolver no dice nada sobre la regla. Meterlo
        // abajo hace que una regla buena con casos dificiles parezca ruidosa, y
        // apagarla es el error que deja un hueco de deteccion.
        let mut casos = Vec::new();
        for i in 0..20 {
            casos.push(caso(
                &format!("C-{i}"),
                "regla-x",
                Some(Veredicto::Verdadero),
            ));
        }
        for i in 0..100 {
            casos.push(caso(
                &format!("D-{i}"),
                "regla-x",
                Some(Veredicto::NoConcluyente),
            ));
        }
        let r = calcular(&casos, &BTreeMap::new());
        assert_eq!(r.reglas["regla-x"].ruido_centesimas(), Some(0));
        assert!(!r.reglas["regla-x"].sospechosa());
    }

    #[test]
    fn lo_autorizado_tampoco_es_ruido() {
        // La regla ACERTO: el hecho ocurrio y estaba permitido. Lo que hay que
        // ajustar es la lista de excepciones, no la regla.
        let mut casos = Vec::new();
        for i in 0..30 {
            casos.push(caso(
                &format!("C-{i}"),
                "regla-x",
                Some(Veredicto::Autorizado),
            ));
        }
        let r = calcular(&casos, &BTreeMap::new());
        assert_eq!(r.reglas["regla-x"].ruido_centesimas(), Some(0));
    }

    #[test]
    fn una_regla_nueva_con_pocos_casos_no_se_juzga() {
        // Apagar una regla porque sus dos primeros casos fueron falsos positivos
        // es la forma mas rapida de quedarse sin deteccion, y pasa.
        let casos = vec![
            caso("C-1", "regla-nueva", Some(Veredicto::FalsoPositivo)),
            caso("C-2", "regla-nueva", Some(Veredicto::FalsoPositivo)),
        ];
        let r = calcular(&casos, &BTreeMap::new());
        assert_eq!(r.reglas["regla-nueva"].ruido_centesimas(), None);
        assert!(!r.reglas["regla-nueva"].sospechosa());
    }

    #[test]
    fn el_tiempo_de_respuesta_se_mide_hasta_la_contencion_y_no_hasta_el_vistazo() {
        // Un caso que alguien abrio y dejo no ha tenido respuesta, por mucho que
        // se haya mirado. Medir el vistazo premia justo lo que no sirve.
        let casos = vec![caso("C-1", "r", Some(Veredicto::Verdadero))];
        let r = calcular(&casos, &BTreeMap::new());
        assert_eq!(r.hasta_respuesta.p50_ns, 20 * MIN);
        assert_eq!(r.hasta_cierre.p50_ns, 60 * MIN);
    }

    #[test]
    fn la_espera_se_descuenta_del_tiempo_de_respuesta() {
        // Seis horas esperando al cliente no son tiempo de respuesta del equipo,
        // y una metrica que no depende de quien la puede mover deja de usarse.
        let casos = vec![caso("C-1", "r", Some(Veredicto::Verdadero))];
        let mut espera = BTreeMap::new();
        espera.insert("C-1".to_string(), 15 * MIN);
        let r = calcular(&casos, &espera);
        assert_eq!(r.hasta_respuesta.p50_ns, 5 * MIN, "20 menos 15");
    }

    #[test]
    fn la_deteccion_se_mide_desde_la_ocurrencia_y_no_desde_la_alerta() {
        // Si no, un sensor que tarda una hora en reportar sale con deteccion
        // instantanea.
        let mut c = Caso::abrir("C-1", alerta("r", AHORA - 3600 * SEG));
        c.pasar_a(Estado::EnCurso, AHORA).unwrap();
        let r = calcular(&[c], &BTreeMap::new());
        assert_eq!(r.hasta_deteccion.p50_ns, 3600 * SEG);
    }

    #[test]
    fn el_maximo_va_al_lado_de_los_percentiles() {
        // Con cien casos de diez minutos y uno de tres semanas, hasta el
        // percentil 99 dice diez minutos.
        let mut v: Vec<u64> = (0..100).map(|_| 10 * MIN).collect();
        v.push(21 * 24 * 3600 * SEG);
        let p = Percentiles::de(v);
        assert_eq!(p.p99_ns, 10 * MIN);
        assert_eq!(p.maximo_ns, 21 * 24 * 3600 * SEG, "y aqui si se ve");
    }

    #[test]
    fn los_casos_atascados_se_cuentan_aparte_de_los_percentiles() {
        // Un caso ABIERTO no esta en la muestra: los percentiles solo miden lo
        // que ya se cerro. Es el sesgo clasico de estas metricas.
        let viejo = caso("C-1", "r", None);
        let nuevo = Caso::abrir("C-2", alerta("r", AHORA + 20 * 24 * 3600 * SEG));
        let atascados = Resumen::atascados(
            &[viejo, nuevo],
            AHORA + 21 * 24 * 3600 * SEG,
            7 * 24 * 3600 * SEG,
        );
        assert_eq!(atascados, vec!["C-1".to_string()]);
    }

    #[test]
    fn los_casos_sin_asignar_se_cuentan() {
        // Un caso sin dueño no lo esta mirando nadie, aunque el panel lo pinte
        // del mismo color.
        let mut a = caso("C-1", "r", None);
        a.asignado_a = Some("ana".into());
        let b = caso("C-2", "r", None);
        let r = calcular(&[a, b], &BTreeMap::new());
        assert_eq!(r.vivos, 2);
        assert_eq!(r.sin_asignar, 1);
    }

    #[test]
    fn la_espera_se_calcula_de_la_historia_y_no_de_un_contador() {
        // Un contador se olvida de restar en algun camino, y el sintoma es una
        // metrica que mejora sola.
        let historia = vec![
            (Estado::EnCurso, AHORA),
            (Estado::EnEspera, AHORA + 10 * MIN),
            (Estado::EnCurso, AHORA + 40 * MIN),
            (Estado::EnEspera, AHORA + 50 * MIN),
            (Estado::Contenido, AHORA + 55 * MIN),
        ];
        assert_eq!(espera_de(&historia, AHORA + 60 * MIN), 35 * MIN);
    }

    #[test]
    fn una_espera_todavia_abierta_cuenta_hasta_ahora() {
        let historia = vec![
            (Estado::EnCurso, AHORA),
            (Estado::EnEspera, AHORA + 10 * MIN),
        ];
        assert_eq!(espera_de(&historia, AHORA + 70 * MIN), 60 * MIN);
    }

    #[test]
    fn sin_casos_las_metricas_estan_vacias_y_no_dicen_cero() {
        // Cero de cero no es el cero por ciento.
        let r = calcular(&[], &BTreeMap::new());
        assert_eq!(r.hasta_cierre.muestras, 0);
        assert!(r.reglas.is_empty());
    }

    #[test]
    fn un_caso_abierto_no_juzga_a_su_regla() {
        // Todavia no dice nada sobre ella.
        let casos = vec![caso("C-1", "regla-x", None)];
        let r = calcular(&casos, &BTreeMap::new());
        assert_eq!(r.reglas["regla-x"].alertas, 1);
        assert_eq!(r.reglas["regla-x"].casos_cerrados, 0);
        assert_eq!(r.reglas["regla-x"].ruido_centesimas(), None);
    }
}
