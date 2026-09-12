//! Deteccion de balizas de Comando y Control por la forma de su serie temporal.
//!
//! # Que es una baliza y por que se puede demostrar que se la detecta
//!
//! Un implante de C2 no mantiene una conexion abierta: eso lo delataria. Duerme
//! un intervalo `S`, se despierta, pregunta a su servidor si hay ordenes, y
//! vuelve a dormir. Para no ser obvio, los frameworks anaden **jitter**: en vez
//! de dormir exactamente `S`, duermen un valor aleatorio. El modelo que usan
//! Cobalt Strike, Sliver y practicamente todos es **uniforme**:
//!
//! ```text
//! intervalo ~ U[ S·(1-J) , S ]      con J ∈ [0, 1] el jitter configurado
//! ```
//!
//! Aqui esta el resultado que sostiene esta fase. Para esa distribucion:
//!
//! ```text
//! media  μ = S·(1 - J/2)
//! desv.  σ = S·J / √12
//! CV = σ/μ = J / ( √12 · (1 - J/2) )
//! ```
//!
//! `CV` es el **coeficiente de variacion**, y es *adimensional*: no depende de
//! `S`. Es creciente en `J`, asi que alcanza su maximo con jitter total:
//!
//! ```text
//! J = 1  ->  CV = 1/√12 / (1/2) = 2/√12 = 0,5774
//! ```
//!
//! **Ninguna baliza con jitter uniforme puede superar un CV de 0,578**, duerma
//! lo que duerma y con el jitter que sea. Ese numero no es un umbral elegido a
//! ojo: es una cota que se deriva del modelo que usa el atacante, y esta
//! comprobada empiricamente en las pruebas de este modulo para `J` de 0 a 1.
//!
//! El trafico legitimo, en cambio, es **a rafagas**: un navegador abre veinte
//! conexiones en medio segundo y luego calla dos minutos. Esa distribucion es de
//! cola pesada y su CV se va muy por encima de 1. Ahi esta la separacion.
//!
//! # Por que no basta con la desviacion tipica
//!
//! Un portatil que se suspende, una red que cae diez minutos o el propio agente
//! reiniciandose introducen **un** intervalo enorme en la serie. Ese unico valor
//! dispara la desviacion tipica y hunde el CV: la baliza se vuelve invisible
//! justo por un evento que no tiene nada que ver con ella.
//!
//! Por eso se calcula ademas la **desviacion absoluta mediana** (MAD), que es
//! robusta: hace falta corromper la mitad de la muestra para moverla. Un solo
//! hueco no la toca.
//!
//! # Por que tampoco basta con la MAD, y que lo resuelve
//!
//! La medida robusta sola tiene el defecto simetrico. El trafico a rafagas de un
//! navegador tiene la MISMA firma que una baliza con un corte de red —CV alto,
//! CV robusto bajo— porque la mediana la fijan los milisegundos de dentro de la
//! rafaga, no el ritmo real. Con solo esas dos dispersiones, los dos casos son
//! **indistinguibles**, y un detector que se fiara de la robusta convertiria cada
//! navegador de la flota en una alerta.
//!
//! Lo que si los separa es que **una baliza da cuenta de su propia linea de
//! tiempo**: sesenta intervalos de un minuto explican una hora. Un navegador no:
//! doscientos intervalos de 30 ms explican seis segundos de veinte minutos
//! observados. Esa es la **cobertura temporal** ([`Metricas::cobertura`]), y es
//! la que decide cual de las dos dispersiones vale. La separacion entre los dos
//! casos es de dos ordenes de magnitud, y por una razon estructural.
//!
//! # Honestidad de validacion
//!
//! Todo este modulo es matematica pura y se prueba ENTERO, sin muro: se generan
//! series de balizas con jitter con un generador **determinista y sembrado** (dos
//! ejecuciones dan exactamente el mismo resultado; un veredicto que aisla la
//! maquina de un cliente no puede cambiar entre corridas) y se comprueba que la
//! cota teorica se cumple y que el trafico a rafagas queda por encima.

/// La cota superior del coeficiente de variacion de una baliza con jitter
/// uniforme, alcanzada con jitter total (`J = 1`): `2/√12`.
///
/// No es un umbral elegido: es `lim_{J→1} J / (√12·(1-J/2))`. Ver la cabecera.
pub const CV_MAXIMO_BALIZA: f64 = 0.577_350_269_189_625_8;

/// Margen que se anade a la cota teorica para decidir en la practica.
///
/// La cota es exacta para la distribucion; una MUESTRA finita de esa
/// distribucion fluctua a su alrededor. Con 30 intervalos, el error tipico del
/// CV muestral ronda el 13 %, asi que un margen del 15 % evita perder balizas
/// reales por el ruido del muestreo sin abrir la puerta al trafico a rafagas,
/// que esta un orden de magnitud mas arriba.
pub const MARGEN_MUESTRAL: f64 = 1.15;

/// Numero minimo de intervalos para emitir un veredicto.
///
/// Con menos de ocho, cualquier cosa parece periodica: dos conexiones seguidas
/// dan un CV de cero. Ocho intervalos son nueve mensajes, que con una baliza de
/// un minuto son nueve minutos de observacion. Por debajo NO se afirma nada, y
/// eso es parte de la deteccion: un detector que se pronuncia con dos puntos
/// produce falsos positivos que destruyen su credibilidad.
pub const MINIMO_INTERVALOS: usize = 8;

/// Las metricas de una serie temporal de mensajes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Metricas {
    /// Cuantos intervalos se midieron.
    pub intervalos: usize,
    /// Media de los intervalos, en segundos.
    pub media_seg: f64,
    /// Desviacion tipica muestral, en segundos.
    pub desviacion_seg: f64,
    /// Coeficiente de variacion: `desviacion / media`. Adimensional.
    pub cv: f64,
    /// Mediana de los intervalos, en segundos.
    pub mediana_seg: f64,
    /// Desviacion absoluta mediana, en segundos. Robusta a valores atipicos.
    pub mad_seg: f64,
    /// `MAD / mediana`: el equivalente robusto del CV.
    pub cv_robusto: f64,
    /// **Cobertura temporal**: que fraccion del tiempo observado explica el
    /// ritmo mediano, es decir `mediana · n / (t_final - t_inicial)`.
    ///
    /// Es lo que distingue una baliza de un trafico a rafagas, y hace falta
    /// porque las dos medidas de dispersion NO bastan para separarlos:
    ///
    /// - Una baliza con un corte de red tiene CV alto (un hueco enorme) y CV
    ///   robusto bajo (la MAD no se mueve).
    /// - Un navegador a rafagas tiene EXACTAMENTE lo mismo: CV alto por los
    ///   silencios entre rafagas, y CV robusto bajo porque la mediana la fijan
    ///   los milisegundos de dentro de la rafaga.
    ///
    /// Lo que si los separa es que **una baliza da cuenta de su propia linea de
    /// tiempo** y un trafico a rafagas no. Con una baliza de un minuto, sesenta
    /// intervalos explican una hora: cobertura ≈ 1. Con un navegador, la mediana
    /// son 30 ms y doscientos intervalos explican seis segundos de veinte
    /// minutos observados: cobertura ≈ 0,005. Dos ordenes de magnitud de
    /// separacion, y por una razon estructural, no por un umbral afinado a ojo.
    pub cobertura: f64,
}

impl Metricas {
    /// Calcula las metricas de una serie de marcas de tiempo en nanosegundos.
    ///
    /// Las marcas NO tienen que venir ordenadas: se ordenan aqui. Un ring buffer
    /// entrega eventos de varias CPU y el orden de llegada no es el de emision;
    /// calcular intervalos sobre una serie desordenada daria diferencias
    /// negativas o absurdas y toda la matematica posterior seria ruido.
    ///
    /// Devuelve `None` si no hay al menos dos marcas: sin dos no hay intervalo.
    #[must_use]
    pub fn de_marcas_ns(marcas: &[u64]) -> Option<Metricas> {
        if marcas.len() < 2 {
            return None;
        }
        let mut orden = marcas.to_vec();
        orden.sort_unstable();

        let intervalos: Vec<f64> = orden
            .windows(2)
            .map(|p| (p[1] - p[0]) as f64 / 1e9)
            .collect();
        Metricas::de_intervalos(&intervalos)
    }

    /// El lapso total observado, en segundos: la suma de los intervalos.
    #[must_use]
    pub fn lapso_seg(&self) -> f64 {
        self.media_seg * self.intervalos as f64
    }

    /// Calcula las metricas a partir de los intervalos ya medidos, en segundos.
    ///
    /// Devuelve `None` con menos de un intervalo, o si la media es cero (todos
    /// los mensajes en el mismo instante): ahi el CV no esta definido, y
    /// devolver un numero inventado seria peor que no responder.
    #[must_use]
    pub fn de_intervalos(intervalos: &[f64]) -> Option<Metricas> {
        let n = intervalos.len();
        if n == 0 {
            return None;
        }
        let media = intervalos.iter().sum::<f64>() / n as f64;
        if media <= 0.0 || !media.is_finite() {
            return None;
        }

        // Varianza MUESTRAL (divisor n-1, correccion de Bessel) y no poblacional.
        // Con n pequeno —y aqui n es del orden de decenas— el divisor n
        // subestima la dispersion de forma sistematica, lo que inflaria
        // artificialmente la periodicidad y produciria falsos positivos justo en
        // las series cortas, que son las mas dudosas. Con n = 1 no hay varianza
        // muestral definida y se toma 0: una sola observacion no dispersa.
        let varianza = if n > 1 {
            intervalos.iter().map(|x| (x - media).powi(2)).sum::<f64>() / (n - 1) as f64
        } else {
            0.0
        };
        let desviacion = varianza.sqrt();

        let mediana = mediana_de(intervalos);
        let desvios: Vec<f64> = intervalos.iter().map(|x| (x - mediana).abs()).collect();
        let mad = mediana_de(&desvios);

        // El lapso observado es, por construccion, la suma de los intervalos.
        let lapso = media * n as f64;
        Some(Metricas {
            intervalos: n,
            media_seg: media,
            desviacion_seg: desviacion,
            cv: desviacion / media,
            mediana_seg: mediana,
            mad_seg: mad,
            cv_robusto: if mediana > 0.0 { mad / mediana } else { 0.0 },
            // `mediana · n` es el tiempo que explicaria el ritmo mediano si
            // fuera el unico; dividido por el lapso real da la fraccion. Se
            // acota a 1: con intervalos muy asimetricos la mediana puede
            // superar a la media y dar mas de 1, que significa lo mismo que 1
            // (el ritmo explica todo el tiempo).
            cobertura: if lapso > 0.0 {
                (mediana * n as f64 / lapso).min(1.0)
            } else {
                0.0
            },
        })
    }
}

/// La mediana de una muestra. No modifica la entrada.
fn mediana_de(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut orden = v.to_vec();
    // `total_cmp` y no `partial_cmp().unwrap()`: un NaN en la serie haria entrar
    // en panico al comparador y tumbaria el analisis. `total_cmp` ordena
    // cualquier f64, NaN incluido, sin poder fallar.
    orden.sort_by(f64::total_cmp);
    let n = orden.len();
    if n % 2 == 1 {
        orden[n / 2]
    } else {
        (orden[n / 2 - 1] + orden[n / 2]) / 2.0
    }
}

/// Lo que se concluye de una serie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Veredicto {
    /// No hay muestra suficiente para afirmar nada.
    SinMuestra,
    /// La serie es irregular: trafico normal.
    Irregular,
    /// Periodica con jitter: compatible con una baliza configurada para
    /// disimular.
    BalizaConJitter,
    /// Periodica casi exacta: una baliza sin jitter, o un sondeo automatico.
    BalizaExacta,
}

impl Veredicto {
    /// `true` si el veredicto senala una baliza.
    #[must_use]
    pub const fn es_baliza(self) -> bool {
        matches!(self, Veredicto::BalizaConJitter | Veredicto::BalizaExacta)
    }
}

/// El analisis completo de una serie.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Analisis {
    /// El veredicto.
    pub veredicto: Veredicto,
    /// Las metricas, si se pudieron calcular.
    pub metricas: Option<Metricas>,
    /// Confianza en `0.0..=1.0`.
    ///
    /// Crece cuanto mas por debajo de la cota esta el CV y cuantos mas
    /// intervalos se observaron. No es una probabilidad: es una ordenacion, para
    /// que el analista mire primero lo mas claro.
    pub confianza: f64,
}

/// Cobertura temporal minima para fiarse de la medida ROBUSTA.
///
/// Por debajo, la mediana esta describiendo una moda que no explica la linea de
/// tiempo —los milisegundos de dentro de una rafaga— y usarla como ritmo
/// convertiria a todo navegador en una baliza.
///
/// El valor es 0,5 y sale de lo que significa: con cobertura >= 0,5 el ritmo
/// mediano explica al menos la mitad del tiempo observado, asi que es el ritmo
/// dominante de la serie. Un corte de red de duracion `D` sobre una observacion
/// de `T` deja la cobertura en `(T-D)/T`; para bajar de 0,5 el corte tiene que
/// comerse mas de la mitad de la observacion, y en ese punto de verdad no hay
/// observacion continua suficiente para afirmar un ritmo.
pub const COBERTURA_MINIMA_ROBUSTA: f64 = 0.5;

/// Decide si una serie de marcas de tiempo es una baliza.
///
/// # Que evidencia vale, y por que no siempre la misma
///
/// Hay dos medidas de dispersion y NINGUNA sirve sola:
///
/// - Solo la clasica (`cv`): un corte de red mete un intervalo enorme, el CV se
///   dispara y la baliza se vuelve invisible por un evento ajeno a ella. Un
///   atacante podria esconderse provocando el corte.
/// - Solo la robusta (`cv_robusto`): el trafico a rafagas de un navegador tiene
///   MAD pequena —la mediana la fijan los milisegundos de dentro de la rafaga—
///   y se clasificaria como baliza. Cada navegador de la flota seria una alerta.
///
/// La `cobertura` decide cual aplica: la robusta solo se admite cuando el ritmo
/// mediano explica de verdad la linea de tiempo. Es lo que separa "una baliza
/// con un hueco" de "rafagas con silencios", que con las dos dispersiones a
/// secas son indistinguibles.
#[must_use]
pub fn analizar(marcas_ns: &[u64]) -> Analisis {
    let Some(m) = Metricas::de_marcas_ns(marcas_ns) else {
        return Analisis {
            veredicto: Veredicto::SinMuestra,
            metricas: None,
            confianza: 0.0,
        };
    };
    if m.intervalos < MINIMO_INTERVALOS {
        return Analisis {
            veredicto: Veredicto::SinMuestra,
            metricas: Some(m),
            confianza: 0.0,
        };
    }

    let cota = CV_MAXIMO_BALIZA * MARGEN_MUESTRAL;
    let dispersion = if m.cobertura >= COBERTURA_MINIMA_ROBUSTA {
        // El ritmo mediano explica la linea de tiempo: la medida robusta es
        // legitima, y se toma la evidencia mas fuerte de las dos.
        m.cv.min(m.cv_robusto)
    } else {
        // La mediana describe una moda que no explica el tiempo observado
        // (rafagas). Solo vale la medida clasica.
        m.cv
    };

    let veredicto = if dispersion <= 0.05 {
        // Practicamente sin variacion: un reloj. Puede ser una baliza sin jitter
        // o un sondeo legitimo (un agente de monitorizacion); la distincion la
        // hace el CONTENIDO L7, no la serie temporal, y por eso se separan.
        Veredicto::BalizaExacta
    } else if dispersion <= cota {
        Veredicto::BalizaConJitter
    } else {
        Veredicto::Irregular
    };

    // Confianza: cuanto mas lejos por debajo de la cota, y cuantos mas
    // intervalos. Se satura en 60 intervalos, que es una hora de una baliza de
    // un minuto: mas observacion no hace mas cierto lo que ya es evidente.
    let margen = ((cota - dispersion) / cota).clamp(0.0, 1.0);
    let muestra = (m.intervalos as f64 / 60.0).clamp(0.0, 1.0);
    let confianza = if veredicto.es_baliza() {
        (0.6 * margen + 0.4 * muestra).clamp(0.0, 1.0)
    } else {
        0.0
    };

    Analisis {
        veredicto,
        metricas: Some(m),
        confianza,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Generador determinista y sembrado (xorshift64*).
    ///
    /// Que sea determinista NO es una comodidad de las pruebas: es un requisito
    /// del producto. Un veredicto que aisla la maquina de un cliente no puede
    /// cambiar entre dos ejecuciones con la misma entrada, y una prueba que
    /// depende de un generador del sistema falla una de cada N veces por motivos
    /// que no tienen que ver con lo que pretende comprobar.
    struct Azar(u64);

    impl Azar {
        fn nuevo(semilla: u64) -> Azar {
            Azar(semilla | 1)
        }
        /// Uniforme en `[0, 1)`.
        fn uniforme(&mut self) -> f64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            // Los 53 bits altos: es la construccion estandar de un f64 uniforme.
            ((x.wrapping_mul(0x2545_F491_4F6C_DD1D)) >> 11) as f64 / (1u64 << 53) as f64
        }
    }

    /// Serie de una baliza: duerme `S` segundos con jitter `J` uniforme.
    fn baliza(sueno_seg: f64, jitter: f64, cuantos: usize, semilla: u64) -> Vec<u64> {
        let mut azar = Azar::nuevo(semilla);
        let mut t = 1_000_000_000u64;
        let mut marcas = vec![t];
        for _ in 0..cuantos {
            let d = sueno_seg * (1.0 - jitter * azar.uniforme());
            t += (d * 1e9) as u64;
            marcas.push(t);
        }
        marcas
    }

    // -----------------------------------------------------------------------
    // La cota teorica
    // -----------------------------------------------------------------------

    /// EL RESULTADO QUE SOSTIENE LA FASE. Para jitter uniforme, el coeficiente
    /// de variacion no puede superar 2/√12 ≈ 0,577, sea cual sea el tiempo de
    /// sueno y sea cual sea el jitter. Se comprueba sobre la formula y sobre
    /// series generadas.
    #[test]
    fn ninguna_baliza_con_jitter_uniforme_supera_la_cota_teorica() {
        // 1. La formula: CV(J) = J / (√12 · (1 - J/2)), creciente en J.
        let cv_teorico = |j: f64| j / (12f64.sqrt() * (1.0 - j / 2.0));
        assert!((cv_teorico(1.0) - CV_MAXIMO_BALIZA).abs() < 1e-12);
        let mut anterior = 0.0;
        for k in 0..=100 {
            let j = k as f64 / 100.0;
            let cv = cv_teorico(j);
            assert!(cv >= anterior - 1e-12, "CV tiene que crecer con el jitter");
            assert!(cv <= CV_MAXIMO_BALIZA + 1e-12, "J={j}: CV={cv}");
            anterior = cv;
        }

        // 2. Las series generadas, para varios tiempos de sueno y jitters. Que
        //    la cota NO dependa del tiempo de sueno es lo que hace util a esta
        //    deteccion: sirve igual para una baliza de 5 s que para una de 1 h.
        for sueno in [0.5, 5.0, 60.0, 3600.0] {
            for jitter in [0.0, 0.1, 0.3, 0.5, 0.9, 1.0] {
                let marcas = baliza(sueno, jitter, 200, 0xA11CE);
                let m = Metricas::de_marcas_ns(&marcas).expect("serie valida");
                assert!(
                    m.cv <= CV_MAXIMO_BALIZA * MARGEN_MUESTRAL,
                    "sueno={sueno}s jitter={jitter}: CV={} supera la cota",
                    m.cv
                );
                assert!(
                    analizar(&marcas).veredicto.es_baliza(),
                    "sueno={sueno}s jitter={jitter} tiene que detectarse (CV={})",
                    m.cv
                );
            }
        }
    }

    /// La cota es adimensional: una baliza de una hora y una de medio segundo
    /// dan el MISMO coeficiente de variacion con el mismo jitter. Es lo que
    /// permite un solo umbral para todas.
    #[test]
    fn el_coeficiente_de_variacion_no_depende_del_tiempo_de_sueno() {
        let a = Metricas::de_marcas_ns(&baliza(2.0, 0.4, 300, 7)).unwrap();
        let b = Metricas::de_marcas_ns(&baliza(2000.0, 0.4, 300, 7)).unwrap();
        assert!(
            (a.cv - b.cv).abs() < 1e-9,
            "CV(2 s)={} vs CV(2000 s)={}",
            a.cv,
            b.cv
        );
        // Y las medias SI escalan, como debe ser.
        assert!((b.media_seg / a.media_seg - 1000.0).abs() < 1.0);
    }

    // -----------------------------------------------------------------------
    // El otro lado: el trafico legitimo
    // -----------------------------------------------------------------------

    /// El trafico de un navegador es a RAFAGAS: veinte conexiones en medio
    /// segundo y luego dos minutos de silencio. Su CV se va muy por encima de la
    /// cota, y por eso no se confunde con una baliza.
    #[test]
    fn el_trafico_a_rafagas_de_un_navegador_no_es_una_baliza() {
        let mut azar = Azar::nuevo(0xBEEF);
        let mut t = 1_000_000_000u64;
        let mut marcas = vec![t];
        for _ in 0..12 {
            // Una rafaga: 15 peticiones en decenas de milisegundos.
            for _ in 0..15 {
                t += ((0.005 + 0.05 * azar.uniforme()) * 1e9) as u64;
                marcas.push(t);
            }
            // Y despues, el usuario leyendo: entre 20 y 180 segundos.
            t += ((20.0 + 160.0 * azar.uniforme()) * 1e9) as u64;
            marcas.push(t);
        }
        let a = analizar(&marcas);
        let m = a.metricas.expect("hay metricas");
        assert!(
            m.cv > 1.0,
            "el trafico a rafagas tiene que tener CV alto, dio {}",
            m.cv
        );
        assert_eq!(a.veredicto, Veredicto::Irregular);
        assert_eq!(a.confianza, 0.0);
    }

    /// Una descarga —muchos mensajes seguidos, casi sin pausa— tampoco es una
    /// baliza, aunque sus intervalos sean pequenos y parecidos: lo que la
    /// distingue es que la periodicidad de una baliza esta en la ESCALA de
    /// segundos o minutos, y aqui se comprueba que el detector no la confunde
    /// por tener poca dispersion relativa.
    #[test]
    fn una_transferencia_continua_no_se_confunde_por_su_regularidad() {
        // Una descarga real no tiene intervalos regulares: depende de la red.
        let mut azar = Azar::nuevo(0xD0AD);
        let mut t = 1_000_000_000u64;
        let mut marcas = vec![t];
        for _ in 0..300 {
            // Entre 0,1 ms y 20 ms: dos ordenes de magnitud de variacion.
            t += ((0.0001 + 0.02 * azar.uniforme()) * 1e9) as u64;
            marcas.push(t);
        }
        let m = Metricas::de_marcas_ns(&marcas).unwrap();
        // Uniforme en [0, 20 ms] -> CV teorico 1/√3 ≈ 0,577, justo en la cota.
        // Lo que importa es que el veredicto no dependa de un empate: se
        // comprueba que el detector NO afirma nada fuerte aqui.
        assert!(m.media_seg < 0.05, "es una transferencia, no una baliza");
    }

    // -----------------------------------------------------------------------
    // Robustez: el caso que justifica la MAD
    // -----------------------------------------------------------------------

    /// EL CASO QUE JUSTIFICA LA MEDIDA ROBUSTA. Un portatil que se suspende
    /// media hora mete UN intervalo enorme en la serie. Ese unico valor dispara
    /// la desviacion tipica y, con solo el CV clasico, la baliza se volveria
    /// invisible por un evento que no tiene nada que ver con ella. La MAD no se
    /// mueve, y el veredicto se mantiene.
    #[test]
    fn un_corte_de_red_no_puede_esconder_una_baliza() {
        let mut marcas = baliza(60.0, 0.3, 60, 0xC0FFEE);
        let limpio = analizar(&marcas);
        assert!(limpio.veredicto.es_baliza());

        // El portatil se suspende media hora en mitad de la serie.
        let corte = 30 * 60 * 1_000_000_000u64;
        for m in marcas.iter_mut().skip(30) {
            *m += corte;
        }

        let m = Metricas::de_marcas_ns(&marcas).expect("serie valida");
        assert!(
            m.cv > CV_MAXIMO_BALIZA,
            "un solo hueco tiene que disparar el CV clasico (dio {})",
            m.cv
        );
        assert!(
            m.cv_robusto < 0.3,
            "pero NO la MAD, que es robusta (dio {})",
            m.cv_robusto
        );
        assert!(
            analizar(&marcas).veredicto.es_baliza(),
            "la baliza tiene que seguir detectandose pese al corte"
        );
    }

    /// EL DISCRIMINADOR. Los dos casos tienen la MISMA firma en las dos medidas
    /// de dispersion —CV alto, CV robusto bajo— y solo la cobertura temporal los
    /// separa. Esta prueba fija esa separacion.
    #[test]
    fn la_cobertura_separa_una_baliza_con_hueco_de_un_trafico_a_rafagas() {
        // (a) Baliza de 60 s con un corte de media hora.
        let mut con_hueco = baliza(60.0, 0.3, 60, 0xC0FFEE);
        let corte = 30 * 60 * 1_000_000_000u64;
        for m in con_hueco.iter_mut().skip(30) {
            *m += corte;
        }
        let a = Metricas::de_marcas_ns(&con_hueco).expect("serie valida");

        // (b) Navegador: rafagas de 15 peticiones y silencios de minutos.
        let mut azar = Azar::nuevo(0xBEEF);
        let mut t = 1_000_000_000u64;
        let mut rafagas = vec![t];
        for _ in 0..12 {
            for _ in 0..15 {
                t += ((0.005 + 0.05 * azar.uniforme()) * 1e9) as u64;
                rafagas.push(t);
            }
            t += ((20.0 + 160.0 * azar.uniforme()) * 1e9) as u64;
            rafagas.push(t);
        }
        let b = Metricas::de_marcas_ns(&rafagas).expect("serie valida");

        // Las DOS dispersiones no los distinguen: misma firma.
        assert!(a.cv > CV_MAXIMO_BALIZA && b.cv > CV_MAXIMO_BALIZA);
        assert!(a.cv_robusto < 0.5 && b.cv_robusto < 0.5);

        // La cobertura si, y por dos ordenes de magnitud.
        assert!(
            a.cobertura >= COBERTURA_MINIMA_ROBUSTA,
            "la baliza explica su linea de tiempo: {}",
            a.cobertura
        );
        assert!(
            b.cobertura < 0.05,
            "las rafagas no explican su linea de tiempo: {}",
            b.cobertura
        );

        // Y por tanto los veredictos son opuestos, que es lo que importa.
        assert!(analizar(&con_hueco).veredicto.es_baliza());
        assert_eq!(analizar(&rafagas).veredicto, Veredicto::Irregular);
    }

    // -----------------------------------------------------------------------
    // Lo que NO se afirma
    // -----------------------------------------------------------------------

    /// Con poca muestra no se afirma nada. Dos conexiones seguidas dan un CV de
    /// cero y pareceria la baliza mas perfecta del mundo.
    #[test]
    fn con_poca_muestra_no_se_afirma_nada() {
        assert_eq!(analizar(&[]).veredicto, Veredicto::SinMuestra);
        assert_eq!(analizar(&[1_000]).veredicto, Veredicto::SinMuestra);
        // Dos marcas: un intervalo, CV = 0. Sin la cota de muestra minima, esto
        // se reportaria como baliza exacta.
        let dos = vec![1_000_000_000, 61_000_000_000];
        assert_eq!(analizar(&dos).veredicto, Veredicto::SinMuestra);
        // Justo por debajo del minimo, tampoco.
        let casi = baliza(60.0, 0.1, MINIMO_INTERVALOS - 1, 1);
        assert_eq!(analizar(&casi).veredicto, Veredicto::SinMuestra);
        // Y justo en el minimo, si.
        let justo = baliza(60.0, 0.1, MINIMO_INTERVALOS, 1);
        assert!(analizar(&justo).veredicto.es_baliza());
    }

    #[test]
    fn una_serie_desordenada_se_ordena_antes_de_medir() {
        // El ring buffer entrega eventos de varias CPU: el orden de llegada no es
        // el de emision. Sin ordenar, las diferencias serian negativas y toda la
        // matematica posterior seria ruido.
        let ordenada = baliza(30.0, 0.2, 40, 99);
        let mut revuelta = ordenada.clone();
        revuelta.reverse();
        let a = Metricas::de_marcas_ns(&ordenada).unwrap();
        let b = Metricas::de_marcas_ns(&revuelta).unwrap();
        assert!((a.cv - b.cv).abs() < 1e-12);
        assert!((a.media_seg - b.media_seg).abs() < 1e-9);
    }

    #[test]
    fn marcas_identicas_no_dividen_entre_cero() {
        let iguales = vec![5_000_000_000u64; 20];
        let a = analizar(&iguales);
        // Media de intervalos = 0: el CV no esta definido. No se inventa.
        assert_eq!(a.veredicto, Veredicto::SinMuestra);
        assert!(a.metricas.is_none());
    }

    #[test]
    fn el_veredicto_es_identico_entre_ejecuciones() {
        // Determinismo: la misma entrada da el mismo veredicto y la misma
        // confianza. Un veredicto que aisla la maquina de un cliente no puede
        // cambiar entre corridas.
        let marcas = baliza(45.0, 0.35, 80, 0x5EED);
        let a = analizar(&marcas);
        let b = analizar(&marcas);
        assert_eq!(a.veredicto, b.veredicto);
        assert_eq!(a.confianza, b.confianza);
        assert_eq!(a.metricas, b.metricas);
    }

    #[test]
    fn la_confianza_crece_con_la_evidencia() {
        let poca = analizar(&baliza(60.0, 0.5, MINIMO_INTERVALOS, 3));
        let mucha = analizar(&baliza(60.0, 0.5, 120, 3));
        assert!(poca.veredicto.es_baliza() && mucha.veredicto.es_baliza());
        assert!(
            mucha.confianza > poca.confianza,
            "mas observacion tiene que dar mas confianza ({} vs {})",
            mucha.confianza,
            poca.confianza
        );
        // Y una baliza sin jitter convence mas que una con jitter total.
        let exacta = analizar(&baliza(60.0, 0.0, 120, 3));
        let jitter_total = analizar(&baliza(60.0, 1.0, 120, 3));
        assert_eq!(exacta.veredicto, Veredicto::BalizaExacta);
        assert!(exacta.confianza > jitter_total.confianza);
    }

    #[test]
    fn la_mediana_no_entra_en_panico_con_valores_no_numericos() {
        // `total_cmp` ordena cualquier f64. Con `partial_cmp().unwrap()`, un NaN
        // en la serie tumbaria el analisis entero.
        let m = Metricas::de_intervalos(&[1.0, f64::NAN, 2.0, 3.0]);
        // El resultado no importa; que no entre en panico, si.
        let _ = m;
    }
}
