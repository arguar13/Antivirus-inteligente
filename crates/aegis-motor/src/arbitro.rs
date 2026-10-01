//! El arbitro del agente: el unico que invoca motores y el unico que combina.
//!
//! Recibe cada evento, lo reparte a los motores registrados, mide lo que gasta
//! cada uno, guarda sus señales por entidad y, cuando alguna acusa, decide con la
//! regla unica de [`aegis_entidad::arbitrar`]. Emite un veredicto solo cuando
//! cambia a algo que hay que atender (malicioso, sospechoso o en disputa): el
//! mismo sospechoso repetido en cada evento del proceso no es informacion nueva.
//!
//! # Memoria acotada
//!
//! El expediente de señales de cada entidad guarda como mucho una señal por
//! motor y juicio —la mas reciente—, y el numero de expedientes tiene techo
//! ([`ConfigArbitro::max_entidades`]). Al pasarlo se expulsan los mas viejos y se
//! cuenta: un agente que olvida sin decirlo se parece demasiado a uno que no vio.

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use aegis_entidad::{arbitrar, Confianza, Eid, Juicio, Resultado, Senal, Severidad, Veredicto};

use crate::contrato::{Camino, Causa, Dictamen, Evento, Ficha, Host, Motor, Plazo, Requisito};
use crate::histograma::Histograma;

/// Limites del arbitro.
#[derive(Debug, Clone, Copy)]
pub struct ConfigArbitro {
    /// Entidades con expediente abierto como maximo.
    pub max_entidades: usize,
    /// Cuanto vive una señal sin que su entidad vuelva a aparecer.
    pub vida_ns: u64,
}

impl Default for ConfigArbitro {
    fn default() -> Self {
        ConfigArbitro {
            max_entidades: 8192,
            vida_ns: 3_600_000_000_000,
        }
    }
}

/// Un motor que no se registro porque el host no le da lo que necesita.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Omitido {
    /// El motor.
    pub motor: &'static str,
    /// Lo que le falta.
    pub requisito: Requisito,
    /// Por que el host no lo ofrece.
    pub motivo: String,
}

/// Longitud maxima del ultimo motivo de «sin datos» que se guarda por motor.
pub const MAX_MOTIVO: usize = 240;

/// Lo que se publica de cada motor.
#[derive(Debug, Clone)]
pub struct EstadoMotor {
    /// Su nombre.
    pub nombre: &'static str,
    /// Quien firma sus señales.
    pub firma: &'static str,
    /// Camino caliente o frio.
    pub camino: Camino,
    /// Eventos evaluados.
    pub evaluaciones: u64,
    /// Señales aportadas.
    pub senales: u64,
    /// Veces que no pudo mirar, por causa.
    pub sin_datos: BTreeMap<&'static str, u64>,
    /// El motivo de la ultima vez que no pudo mirar, dicho por el motor. Un
    /// contador sin motivo no deja actuar a nadie: «sin datos: 1» en un kernel
    /// que tiene los kfuncs no dice si fallo la carga, el barrido o la
    /// numeracion (FASE 2 del MP-16). Acotado a [`MAX_MOTIVO`] bytes.
    pub ultimo_sin_datos: Option<String>,
    /// Evaluaciones que se pasaron de su tiempo.
    pub excesos: u64,
    /// Veces que se le suspendio.
    pub suspensiones: u64,
    /// Si ahora mismo esta suspendido.
    pub suspendido: bool,
    /// Señales descartadas por venir firmadas en nombre de otro motor.
    pub firmas_ajenas: u64,
    /// Memoria que retiene su estado, segun la ultima consulta.
    pub memoria: usize,
    /// Latencia por evaluacion.
    pub latencia: Histograma,
}

struct Registrado<E> {
    motor: Box<dyn Motor<E>>,
    ficha: Ficha,
    excesos_seguidos: u32,
    suspendido_hasta: Option<Instant>,
    estado: EstadoMotor,
}

impl<E> Registrado<E> {
    fn suspender(&mut self) {
        self.suspendido_hasta = Some(Instant::now() + self.ficha.presupuesto.suspension);
        self.estado.suspensiones += 1;
        self.estado.suspendido = true;
        self.excesos_seguidos = 0;
    }

    fn contar_sin_datos(&mut self, causa: &Causa) {
        *self.estado.sin_datos.entry(causa.clave()).or_insert(0) += 1;
        let mut m = causa.to_string();
        if m.len() > MAX_MOTIVO {
            let mut corte = MAX_MOTIVO;
            while !m.is_char_boundary(corte) {
                corte -= 1;
            }
            m.truncate(corte);
        }
        self.estado.ultimo_sin_datos = Some(m);
    }

    fn mudo(&self, entidad: &Eid, causa: &Causa, cuando_ns: u64) -> Senal {
        Senal::nueva(
            self.ficha.firma,
            entidad.clone(),
            Juicio::NoConcluyente,
            Severidad::Info,
            Confianza::NULA,
            format!("{}: no pudo mirar ({causa})", self.ficha.nombre),
            cuando_ns,
        )
    }
}

struct Expediente {
    senales: Vec<Senal>,
    ultimo: Option<Resultado>,
    visto_ns: u64,
}

/// El arbitro del agente.
pub struct Arbitro<E> {
    motores: Vec<Registrado<E>>,
    omitidos: Vec<Omitido>,
    expedientes: HashMap<Eid, Expediente>,
    config: ConfigArbitro,
    por_evento: Histograma,
    expulsados: u64,
    veredictos: u64,
}

impl<E: Evento> Arbitro<E> {
    /// Un arbitro sin motores.
    #[must_use]
    pub fn nuevo(config: ConfigArbitro) -> Arbitro<E> {
        Arbitro {
            motores: Vec::new(),
            omitidos: Vec::new(),
            expedientes: HashMap::new(),
            config,
            por_evento: Histograma::default(),
            expulsados: 0,
            veredictos: 0,
        }
    }

    /// Registra un motor si el host le da lo que necesita.
    ///
    /// Si le falta algo, no se registra y queda declarado en
    /// [`Arbitro::omitidos`], con el motivo que dio el host.
    ///
    /// # Errores
    ///
    /// El primer requisito que el host no ofrece.
    pub fn registrar(&mut self, motor: Box<dyn Motor<E>>, host: &dyn Host) -> Result<(), Omitido> {
        let ficha = motor.ficha();
        assert!(
            self.motores.iter().all(|r| r.ficha.nombre != ficha.nombre),
            "dos motores con el mismo nombre: {}",
            ficha.nombre
        );
        for &requisito in ficha.requisitos {
            if let Err(motivo) = host.ofrece(requisito) {
                let omitido = Omitido {
                    motor: ficha.nombre,
                    requisito,
                    motivo,
                };
                self.omitidos.push(omitido.clone());
                return Err(omitido);
            }
        }
        let estado = EstadoMotor {
            nombre: ficha.nombre,
            firma: ficha.firma.nombre(),
            camino: ficha.camino,
            evaluaciones: 0,
            senales: 0,
            sin_datos: BTreeMap::new(),
            ultimo_sin_datos: None,
            excesos: 0,
            suspensiones: 0,
            suspendido: false,
            firmas_ajenas: 0,
            memoria: 0,
            latencia: Histograma::default(),
        };
        self.motores.push(Registrado {
            motor,
            ficha,
            excesos_seguidos: 0,
            suspendido_hasta: None,
            estado,
        });
        Ok(())
    }

    /// Reparte un evento a todos los motores y decide si hay que decir algo.
    ///
    /// Devuelve un veredicto solo cuando el de la entidad CAMBIA a malicioso,
    /// sospechoso o en disputa.
    pub fn procesar(&mut self, evento: &E) -> Option<Veredicto> {
        let inicio = Instant::now();
        let entidad = evento.entidad();
        let cuando = evento.cuando_ns();
        let mut nuevas: Vec<Senal> = Vec::new();

        for r in &mut self.motores {
            if let Some(hasta) = r.suspendido_hasta {
                if Instant::now() < hasta {
                    let causa = Causa::Suspendido;
                    r.contar_sin_datos(&causa);
                    nuevas.push(r.mudo(&entidad, &causa, cuando));
                    continue;
                }
                r.suspendido_hasta = None;
                r.estado.suspendido = false;
            }

            let presupuesto = r.ficha.presupuesto;
            let plazo = Plazo::desde_ahora(presupuesto.tiempo);
            let t0 = Instant::now();
            let dictamen = r.motor.evaluar(evento, &plazo);
            let gastado = t0.elapsed();
            r.estado.evaluaciones += 1;
            r.estado
                .latencia
                .anotar(u64::try_from(gastado.as_nanos()).unwrap_or(u64::MAX));

            if gastado > presupuesto.tiempo {
                r.estado.excesos += 1;
                r.excesos_seguidos += 1;
                if r.excesos_seguidos >= presupuesto.tolerancia {
                    r.suspender();
                }
            } else {
                r.excesos_seguidos = 0;
            }

            let memoria = r.motor.memoria();
            if memoria > presupuesto.memoria {
                r.motor.aligerar();
                let tras = r.motor.memoria();
                if tras > presupuesto.memoria {
                    let causa = Causa::MemoriaAgotada {
                        usada: tras,
                        tope: presupuesto.memoria,
                    };
                    r.contar_sin_datos(&causa);
                    nuevas.push(r.mudo(&entidad, &causa, cuando));
                    r.suspender();
                }
                r.estado.memoria = tras;
            } else {
                r.estado.memoria = memoria;
            }

            match dictamen {
                Dictamen::NoAplica => {}
                Dictamen::Senales(senales) => {
                    for s in senales {
                        if s.motor == r.ficha.firma {
                            r.estado.senales += 1;
                            nuevas.push(s);
                        } else {
                            r.estado.firmas_ajenas += 1;
                        }
                    }
                }
                Dictamen::SinDatos(causa) => {
                    r.contar_sin_datos(&causa);
                    nuevas.push(r.mudo(&entidad, &causa, cuando));
                }
            }
        }

        let decision = if nuevas.is_empty() {
            None
        } else {
            self.guardar(&entidad, nuevas, cuando);
            self.decidir(&entidad, cuando)
        };
        self.por_evento
            .anotar(u64::try_from(inicio.elapsed().as_nanos()).unwrap_or(u64::MAX));
        decision
    }

    /// Entrega lo que un motor de camino frio dictamino despues.
    ///
    /// Pasa por las mismas comprobaciones que [`Arbitro::procesar`]: el motor
    /// tiene que estar registrado y sus señales tienen que ir firmadas en su
    /// nombre.
    pub fn aportar(
        &mut self,
        motor: &str,
        entidad: &Eid,
        dictamen: Dictamen,
        cuando_ns: u64,
    ) -> Option<Veredicto> {
        let r = self.motores.iter_mut().find(|r| r.ficha.nombre == motor)?;
        let mut nuevas = Vec::new();
        match dictamen {
            Dictamen::NoAplica => {}
            Dictamen::Senales(senales) => {
                for s in senales {
                    if s.motor == r.ficha.firma && &s.entidad == entidad {
                        r.estado.senales += 1;
                        nuevas.push(s);
                    } else {
                        r.estado.firmas_ajenas += 1;
                    }
                }
            }
            Dictamen::SinDatos(causa) => {
                r.contar_sin_datos(&causa);
                nuevas.push(r.mudo(entidad, &causa, cuando_ns));
            }
        }
        if nuevas.is_empty() {
            return None;
        }
        self.guardar(entidad, nuevas, cuando_ns);
        self.decidir(entidad, cuando_ns)
    }

    fn guardar(&mut self, entidad: &Eid, nuevas: Vec<Senal>, cuando_ns: u64) {
        if !self.expedientes.contains_key(entidad)
            && self.expedientes.len() >= self.config.max_entidades
        {
            self.expulsar();
        }
        let exp = self
            .expedientes
            .entry(entidad.clone())
            .or_insert_with(|| Expediente {
                senales: Vec::new(),
                ultimo: None,
                visto_ns: cuando_ns,
            });
        exp.visto_ns = exp.visto_ns.max(cuando_ns);
        for s in nuevas {
            // Una señal por motor y juicio: la mas reciente sustituye a la vieja.
            if let Some(vieja) = exp
                .senales
                .iter_mut()
                .find(|v| v.motor == s.motor && v.juicio == s.juicio)
            {
                *vieja = s;
            } else {
                exp.senales.push(s);
            }
        }
    }

    fn decidir(&mut self, entidad: &Eid, ahora_ns: u64) -> Option<Veredicto> {
        let exp = self.expedientes.get_mut(entidad)?;
        let v = arbitrar(entidad, &exp.senales, ahora_ns);
        let antes = exp.ultimo.replace(v.resultado);
        let atender = matches!(
            v.resultado,
            Resultado::Malicioso | Resultado::Sospechoso | Resultado::EnDisputa
        );
        if atender && antes != Some(v.resultado) {
            self.veredictos += 1;
            Some(v)
        } else {
            None
        }
    }

    /// Expulsa la octava parte mas vieja de los expedientes.
    fn expulsar(&mut self) {
        let mut edades: Vec<(u64, Eid)> = self
            .expedientes
            .iter()
            .map(|(e, x)| (x.visto_ns, e.clone()))
            .collect();
        edades.sort_unstable_by_key(|(t, _)| *t);
        let cuantos = (edades.len() / 8).max(1);
        for (_, e) in edades.into_iter().take(cuantos) {
            self.expedientes.remove(&e);
            self.expulsados += 1;
        }
    }

    /// Mantenimiento periodico: el de cada motor, lo que entregan del camino
    /// frio y olvidar lo caducado. Devuelve los veredictos que cambiaron.
    pub fn mantener(&mut self, ahora_ns: u64) -> Vec<Veredicto> {
        let mut entregas: Vec<(&'static str, Eid, Dictamen)> = Vec::new();
        for r in &mut self.motores {
            for (e, d) in r.motor.mantener(ahora_ns) {
                entregas.push((r.ficha.nombre, e, d));
            }
            r.estado.memoria = r.motor.memoria();
        }
        let mut veredictos = Vec::new();
        for (motor, e, d) in entregas {
            if let Some(v) = self.aportar(motor, &e, d, ahora_ns) {
                veredictos.push(v);
            }
        }
        let vida = self.config.vida_ns;
        self.expedientes
            .retain(|_, x| ahora_ns.saturating_sub(x.visto_ns) <= vida);
        veredictos
    }

    /// El estado de cada motor registrado.
    #[must_use]
    pub fn estado(&self) -> Vec<EstadoMotor> {
        self.motores.iter().map(|r| r.estado.clone()).collect()
    }

    /// Los motores que no se registraron, y por que.
    #[must_use]
    pub fn omitidos(&self) -> &[Omitido] {
        &self.omitidos
    }

    /// Lo que tarda el arbitro entero por evento: el camino caliente del agente.
    #[must_use]
    pub fn por_evento(&self) -> &Histograma {
        &self.por_evento
    }

    /// Expedientes abiertos.
    #[must_use]
    pub fn expedientes(&self) -> usize {
        self.expedientes.len()
    }

    /// Expedientes expulsados por el techo.
    #[must_use]
    pub fn expulsados(&self) -> u64 {
        self.expulsados
    }

    /// Veredictos emitidos.
    #[must_use]
    pub fn veredictos(&self) -> u64 {
        self.veredictos
    }

    /// Las fichas de los motores registrados.
    #[must_use]
    pub fn fichas(&self) -> Vec<Ficha> {
        self.motores.iter().map(|r| r.ficha.clone()).collect()
    }
}

#[cfg(test)]
mod pruebas {
    use std::time::Duration;

    use aegis_entidad::entidad::maquina;
    use aegis_entidad::Motor as Firma;

    use super::*;
    use crate::contrato::Presupuesto;

    struct Ev {
        quien: Eid,
        ns: u64,
        dice: Option<Juicio>,
    }

    impl Evento for Ev {
        fn entidad(&self) -> Eid {
            self.quien.clone()
        }
        fn cuando_ns(&self) -> u64 {
            self.ns
        }
    }

    fn ev(quien: &str, dice: Option<Juicio>) -> Ev {
        Ev {
            quien: maquina(quien),
            ns: 1,
            dice,
        }
    }

    /// Motor de prueba: repite lo que dice el evento, en nombre de `firma`.
    struct Eco {
        nombre: &'static str,
        firma: Firma,
        espera: Duration,
        memoria: usize,
        requisitos: &'static [Requisito],
    }

    fn eco(nombre: &'static str, firma: Firma) -> Eco {
        Eco {
            nombre,
            firma,
            espera: Duration::ZERO,
            memoria: 0,
            requisitos: &[],
        }
    }

    impl Motor<Ev> for Eco {
        fn ficha(&self) -> Ficha {
            Ficha {
                nombre: self.nombre,
                firma: self.firma,
                camino: Camino::Caliente,
                presupuesto: Presupuesto {
                    tiempo: Duration::from_millis(5),
                    memoria: 1024,
                    tolerancia: 2,
                    suspension: Duration::from_secs(60),
                },
                requisitos: self.requisitos,
            }
        }
        fn evaluar(&mut self, e: &Ev, _plazo: &Plazo) -> Dictamen {
            std::thread::sleep(self.espera);
            match e.dice {
                None => Dictamen::NoAplica,
                Some(j) => Dictamen::Senales(vec![Senal::nueva(
                    self.firma,
                    e.quien.clone(),
                    j,
                    Severidad::Alta,
                    Confianza::ALTA,
                    format!("{} dice {}", self.nombre, j.nombre()),
                    e.ns,
                )]),
            }
        }
        fn memoria(&self) -> usize {
            self.memoria
        }
    }

    struct TodoVale;
    impl Host for TodoVale {
        fn ofrece(&self, _: Requisito) -> Result<(), String> {
            Ok(())
        }
    }

    struct SinLsm;
    impl Host for SinLsm {
        fn ofrece(&self, r: Requisito) -> Result<(), String> {
            if r == Requisito::BpfLsm {
                Err("bpf no esta en lsm=".into())
            } else {
                Ok(())
            }
        }
    }

    fn arbitro() -> Arbitro<Ev> {
        Arbitro::nuevo(ConfigArbitro::default())
    }

    #[test]
    fn sin_motores_no_hay_veredicto() {
        let mut a = arbitro();
        assert!(a.procesar(&ev("m", Some(Juicio::Malicioso))).is_none());
    }

    #[test]
    fn un_testigo_de_ejecucion_que_acusa_produce_veredicto() {
        let mut a = arbitro();
        a.registrar(Box::new(eco("conducta", Firma::Conductual)), &TodoVale)
            .unwrap();
        let v = a.procesar(&ev("m", Some(Juicio::Sospechoso))).unwrap();
        assert_eq!(v.resultado, Resultado::Sospechoso);
        assert!(!v.porque.is_empty());
    }

    #[test]
    fn el_mismo_veredicto_repetido_no_se_vuelve_a_emitir() {
        let mut a = arbitro();
        a.registrar(Box::new(eco("conducta", Firma::Conductual)), &TodoVale)
            .unwrap();
        assert!(a.procesar(&ev("m", Some(Juicio::Sospechoso))).is_some());
        assert!(a.procesar(&ev("m", Some(Juicio::Sospechoso))).is_none());
        assert_eq!(a.veredictos(), 1);
    }

    #[test]
    fn dos_planos_que_acusan_llegan_a_malicioso() {
        let mut a = arbitro();
        a.registrar(Box::new(eco("conducta", Firma::Conductual)), &TodoVale)
            .unwrap();
        a.registrar(Box::new(eco("memoria", Firma::MemHunter)), &TodoVale)
            .unwrap();
        let v = a.procesar(&ev("m", Some(Juicio::Malicioso))).unwrap();
        assert_eq!(v.resultado, Resultado::Malicioso);
        assert_eq!(v.corroboracion(), 2);
    }

    #[test]
    fn testigos_que_se_contradicen_quedan_en_disputa() {
        let mut a = arbitro();
        a.registrar(Box::new(eco("conducta", Firma::Conductual)), &TodoVale)
            .unwrap();
        let quien = maquina("m");
        a.registrar(Box::new(eco("memoria", Firma::MemHunter)), &TodoVale)
            .unwrap();
        let limpio = Senal::nueva(
            Firma::MemHunter,
            quien.clone(),
            Juicio::Limpio,
            Severidad::Info,
            Confianza::ALTA,
            "memoria limpia",
            1,
        );
        a.aportar("memoria", &quien, Dictamen::Senales(vec![limpio]), 1);
        let acusa = Senal::nueva(
            Firma::Conductual,
            quien.clone(),
            Juicio::Malicioso,
            Severidad::Alta,
            Confianza::ALTA,
            "cifra en masa",
            2,
        );
        let v = a
            .aportar("conducta", &quien, Dictamen::Senales(vec![acusa]), 2)
            .unwrap();
        assert_eq!(v.resultado, Resultado::EnDisputa);
    }

    #[test]
    fn un_motor_no_puede_firmar_en_nombre_de_otro() {
        struct Impostor;
        impl Motor<Ev> for Impostor {
            fn ficha(&self) -> Ficha {
                eco("impostor", Firma::Aprendizaje).ficha()
            }
            fn evaluar(&mut self, e: &Ev, _: &Plazo) -> Dictamen {
                // Se hace pasar por el detonador, que tiene el tope mas alto.
                Dictamen::Senales(vec![Senal::nueva(
                    Firma::Detonate,
                    e.quien.clone(),
                    Juicio::Malicioso,
                    Severidad::Critica,
                    Confianza::CIERTA,
                    "confia en mi",
                    e.ns,
                )])
            }
        }
        let mut a = arbitro();
        a.registrar(Box::new(Impostor), &TodoVale).unwrap();
        assert!(a.procesar(&ev("m", Some(Juicio::Malicioso))).is_none());
        assert_eq!(a.estado()[0].firmas_ajenas, 1);
        assert_eq!(a.estado()[0].senales, 0);
    }

    #[test]
    fn el_motor_que_no_puede_correr_en_el_host_queda_declarado() {
        let mut a = arbitro();
        let mut m = eco("lsm", Firma::Conductual);
        m.requisitos = &[Requisito::BpfLsm];
        let omitido = a.registrar(Box::new(m), &SinLsm).unwrap_err();
        assert_eq!(omitido.requisito, Requisito::BpfLsm);
        assert_eq!(a.omitidos().len(), 1);
        assert!(a.estado().is_empty());
    }

    #[test]
    fn el_motor_lento_se_suspende_y_su_ausencia_es_sin_datos() {
        let mut a = arbitro();
        let mut lento = eco("lento", Firma::Conductual);
        lento.espera = Duration::from_millis(8);
        a.registrar(Box::new(lento), &TodoVale).unwrap();
        // Tolerancia 2: dos excesos seguidos lo suspenden.
        a.procesar(&ev("m", Some(Juicio::Limpio)));
        a.procesar(&ev("m", Some(Juicio::Limpio)));
        let e = &a.estado()[0];
        assert_eq!(e.excesos, 2);
        assert_eq!(e.suspensiones, 1);
        assert!(e.suspendido);
        // Suspendido: no se le llama, y lo que le tocaba mirar es SinDatos.
        a.procesar(&ev("m", Some(Juicio::Malicioso)));
        let e = &a.estado()[0];
        assert_eq!(e.evaluaciones, 2);
        assert_eq!(e.sin_datos.get("suspendido"), Some(&1));
        // El contador va con su motivo, para que alguien pueda actuar.
        assert!(
            e.ultimo_sin_datos
                .as_deref()
                .is_some_and(|m| m.contains("suspendido")),
            "{:?}",
            e.ultimo_sin_datos
        );
    }

    #[test]
    fn solo_sin_datos_no_es_limpio_ni_produce_veredicto() {
        struct Ciego;
        impl Motor<Ev> for Ciego {
            fn ficha(&self) -> Ficha {
                eco("ciego", Firma::Conductual).ficha()
            }
            fn evaluar(&mut self, _: &Ev, _: &Plazo) -> Dictamen {
                Dictamen::SinDatos(Causa::TrabajadorCaido("murio".into()))
            }
        }
        let mut a = arbitro();
        a.registrar(Box::new(Ciego), &TodoVale).unwrap();
        assert!(a.procesar(&ev("m", None)).is_none());
        assert_eq!(a.estado()[0].sin_datos.get("trabajador"), Some(&1));
        assert_eq!(a.expedientes(), 1);
    }

    #[test]
    fn el_motor_que_se_pasa_de_memoria_se_suspende() {
        let mut a = arbitro();
        let mut gordo = eco("gordo", Firma::Conductual);
        gordo.memoria = 4096;
        a.registrar(Box::new(gordo), &TodoVale).unwrap();
        a.procesar(&ev("m", Some(Juicio::Limpio)));
        let e = &a.estado()[0];
        assert_eq!(e.sin_datos.get("memoria"), Some(&1));
        assert!(e.suspendido);
    }

    #[test]
    fn los_expedientes_tienen_techo_y_se_cuentan_las_expulsiones() {
        let mut a: Arbitro<Ev> = Arbitro::nuevo(ConfigArbitro {
            max_entidades: 16,
            vida_ns: u64::MAX,
        });
        a.registrar(Box::new(eco("conducta", Firma::Conductual)), &TodoVale)
            .unwrap();
        for i in 0..100u64 {
            let mut e = ev(&format!("m{i}"), Some(Juicio::Limpio));
            e.ns = i;
            a.procesar(&e);
        }
        assert!(a.expedientes() <= 16);
        assert!(a.expulsados() >= 84);
    }

    #[test]
    fn lo_caducado_se_olvida() {
        let mut a: Arbitro<Ev> = Arbitro::nuevo(ConfigArbitro {
            max_entidades: 16,
            vida_ns: 10,
        });
        a.registrar(Box::new(eco("conducta", Firma::Conductual)), &TodoVale)
            .unwrap();
        a.procesar(&ev("m", Some(Juicio::Limpio)));
        a.mantener(100);
        assert_eq!(a.expedientes(), 0);
    }

    #[test]
    fn la_latencia_se_mide_por_motor_y_por_evento() {
        let mut a = arbitro();
        a.registrar(Box::new(eco("conducta", Firma::Conductual)), &TodoVale)
            .unwrap();
        for _ in 0..50 {
            a.procesar(&ev("m", None));
        }
        assert_eq!(a.estado()[0].latencia.cuenta(), 50);
        assert_eq!(a.por_evento().cuenta(), 50);
    }
}
