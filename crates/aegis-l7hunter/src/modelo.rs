//! Extraccion de caracteristicas de una sesion y clasificacion con TinyML.
//!
//! # Por que hacen falta las dos mitades
//!
//! Ni la serie temporal ni el contenido bastan por separado, y cada una produce
//! el falso positivo que la otra descarta:
//!
//! - **Solo la serie temporal**: un agente de monitorizacion (Prometheus, un
//!   health-check, el propio agente de respaldo) es PERFECTAMENTE periodico, con
//!   mensajes pequenos y constantes, contra un solo host. Por la forma es
//!   indistinguible de una baliza sin jitter. Un clasificador que decidiera asi
//!   marcaria toda la observabilidad del cliente.
//! - **Solo el contenido**: una baliza que imita bien una peticion normal no
//!   tiene nada raro en un mensaje suelto. Lo que la delata es que ese mensaje
//!   normal se repita cada sesenta segundos durante horas.
//!
//! El modelo combina las dos, y su calibracion esta hecha justo para separar esos
//! dos casos: la comprobacion que corre al generarlo exige que una baliza con
//! jitter supere 0,85 **y** que un agente de monitorizacion, que es igual de
//! periodico, se quede por debajo de 0,35.
//!
//! # Por que la clasificacion ocurre en el agente
//!
//! Porque una baliza con jitter solo se distingue mirando la SERIE TEMPORAL
//! COMPLETA, y esa serie no se puede subir entera a la nube: son miles de eventos
//! por proceso y por hora. Lo que sube es el veredicto y la evidencia que lo
//! sostiene. Ademas, un endpoint aislado —una fabrica sin salida, un portatil en
//! un avion— tiene que seguir decidiendo.

use crate::abi::{Direccion, EventoL7};
use crate::baliza::{self, Veredicto as VeredictoTemporal};
use crate::l7::{self, Protocolo};
use tract_onnx::prelude::*;

/// Dimension del vector de caracteristicas. Espejo de `DIM` en
/// `tools/build_c2_model.py`; si divergen, el modelo recibe basura.
pub const DIM: usize = 32;

// --- Indices del vector, espejo EXACTO de build_c2_model.py ---------------
// Se declaran como constantes con nombre y no como numeros sueltos porque un
// indice desplazado hace que el modelo lea "entropia" donde hay "fraccion de
// POST": no rompe nada, simplemente el clasificador deja de funcionar y nadie
// se entera. El nombre en los dos lados es lo que permite auditarlo.

/// Regularidad temporal `0..1` (1 = perfectamente periodica).
pub const F_REGULARIDAD: usize = 0;
/// `1 - min(1, cv)`: periodicidad segun la dispersion clasica.
pub const F_CV_INV: usize = 1;
/// `1 - min(1, cv_robusto)`: periodicidad segun la dispersion robusta.
pub const F_CV_ROBUSTO_INV: usize = 2;
/// Cobertura temporal `0..1`.
pub const F_COBERTURA: usize = 3;
/// Periodo mediano normalizado en escala logaritmica.
pub const F_PERIODO_NORM: usize = 4;
/// Volumen saliente medio, normalizado.
pub const F_BYTES_SAL_NORM: usize = 5;
/// Volumen entrante medio, normalizado.
pub const F_BYTES_ENT_NORM: usize = 6;
/// `1 - min(1, cv del tamano)`: 1 = todos los mensajes miden lo mismo.
pub const F_TAM_CONSTANTE: usize = 7;
/// Proporcion entrante/saliente, acotada.
pub const F_RATIO_ENT_SAL: usize = 8;
/// Fraccion de mensajes por debajo de 1 KiB.
pub const F_FRAC_PEQUENOS: usize = 9;
/// Fraccion de mensajes reconocidos como HTTP.
pub const F_FRAC_HTTP: usize = 10;
/// Fraccion de mensajes que NO son HTTP.
pub const F_FRAC_DESCONOCIDO: usize = 11;
/// Hay cookies con aspecto de datos codificados.
pub const F_COOKIE_B64: usize = 12;
/// Hay URIs con segmentos con aspecto de datos codificados.
pub const F_URI_B64: usize = 13;
/// Entropia media de la carga, normalizada a `0..1`.
pub const F_ENTROPIA: usize = 14;
/// Fraccion de peticiones sin `User-Agent`.
pub const F_SIN_AGENTE: usize = 15;
/// El `User-Agent` no es de ningun navegador ni herramienta conocida.
pub const F_AGENTE_RARO: usize = 16;
/// Fraccion de peticiones `POST`.
pub const F_FRAC_POST: usize = 17;
/// Concentracion en un solo host `0..1` (1 = siempre el mismo).
pub const F_UN_SOLO_HOST: usize = 18;
/// Estabilidad de la URI `0..1` (1 = siempre la misma ruta legible).
pub const F_URI_ESTABLE: usize = 19;
/// Tamano de la muestra, normalizado.
pub const F_MUESTRA_NORM: usize = 20;
/// El proceso es un navegador conocido.
pub const F_PROC_NAVEGADOR: usize = 21;

/// Procesos cuyo trafico TLS es, por definicion, variado y hacia muchos hosts.
const NAVEGADORES: &[&str] = &[
    "chrome", "chromium", "firefox", "msedge", "safari", "epiphany", "brave",
];

/// Fragmentos de `User-Agent` de clientes legitimos habituales.
///
/// Su ausencia NO prueba nada por si sola —un agente puede mandar cualquier
/// cosa—, pero su presencia si resta: un implante que se molesta en poner un
/// `User-Agent` creible ya esta imitando trafico normal, y entonces lo que lo
/// delata es la serie temporal, no la cabecera.
const AGENTES_CONOCIDOS: &[&str] = &[
    "mozilla",
    "chrome",
    "safari",
    "firefox",
    "edge",
    "curl",
    "wget",
    "python-requests",
    "go-http-client",
    "okhttp",
    "apache-httpclient",
    "java",
    "prometheus",
    "zabbix",
    "kube-probe",
    "grpc",
    "postman",
    "libwww",
    "apt",
    "dnf",
    "yum",
];

/// Un fallo del motor de inferencia.
#[derive(Debug, thiserror::Error)]
pub enum ModeloError {
    /// El modelo no se pudo cargar o preparar.
    #[error("cargando el modelo: {0}")]
    Carga(String),
    /// La inferencia fallo.
    #[error("la inferencia fallo: {0}")]
    Inferencia(String),
    /// El vector de entrada no tiene la dimension esperada.
    #[error("vector de {encontrado} features; se esperaban {esperado}")]
    Dimension {
        /// La que llego.
        encontrado: usize,
        /// La que el modelo espera.
        esperado: usize,
    },
}

/// El resumen de una sesion antes de convertirla en vector.
///
/// Se expone porque es la EVIDENCIA que acompana al veredicto: el analista tiene
/// que poder ver por que se clasifico asi sin reejecutar nada.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Resumen {
    /// Mensajes observados.
    pub mensajes: usize,
    /// El analisis temporal.
    pub temporal: Option<baliza::Metricas>,
    /// El veredicto temporal.
    pub veredicto_temporal: VeredictoTemporal,
    /// Bytes medios por mensaje saliente.
    pub bytes_salientes: f64,
    /// Bytes medios por mensaje entrante.
    pub bytes_entrantes: f64,
    /// Hosts distintos contactados.
    pub hosts: usize,
    /// Rutas distintas pedidas.
    pub rutas: usize,
    /// Fraccion de mensajes que no son HTTP.
    pub fraccion_no_http: f64,
    /// Entropia media de la carga, en bits por byte.
    pub entropia_media: f64,
    /// Sobre que direccion se midio el ritmo. Ver [`extraer`].
    pub direccion_del_ritmo: Direccion,
}

/// Extrae el resumen y el vector de caracteristicas de una sesion.
///
/// `proceso` es el nombre del ejecutable (`comm`), que se usa solo para el
/// discriminador de navegadores.
#[must_use]
pub fn extraer(eventos: &[EventoL7], proceso: &str) -> (Resumen, [f32; DIM]) {
    let mut v = [0.0f32; DIM];
    let mut r = Resumen {
        mensajes: eventos.len(),
        ..Default::default()
    };
    if eventos.is_empty() {
        return (r, v);
    }

    // --- 1. Temporal ------------------------------------------------------
    //
    // EL RITMO SE MIDE SOBRE UNA SOLA DIRECCION, Y ESTO NO ES UN DETALLE.
    //
    // Una iteracion de baliza son DOS eventos: la peticion, y la respuesta unas
    // decenas de milisegundos despues. La serie mezclada alterna 0,03 s y 60 s,
    // es decir, es BIMODAL, y sus metricas salen exactamente como las del
    // trafico a rafagas de un navegador: CV alto (1,02 medido) y cobertura
    // ridicula (0,001). Una baliza perfecta, sin jitter, se clasificaria como
    // trafico irregular.
    //
    // El ritmo pertenece al lado que INICIA: el implante decide cuando pregunta;
    // cuando llega la respuesta lo deciden el servidor y la red. Midiendo solo
    // las peticiones, esa misma baliza da CV = 0,0000.
    //
    // Se elige la direccion con mas eventos —y la saliente en caso de empate—
    // porque no siempre se ven las dos: enganchar solo `SSL_write` da solo
    // salientes, y observar un servicio que recibe da sobre todo entrantes.
    let salientes_t: Vec<u64> = eventos
        .iter()
        .filter(|e| e.direccion == Direccion::Saliente)
        .map(|e| e.tiempo_ns)
        .collect();
    let entrantes_t: Vec<u64> = eventos
        .iter()
        .filter(|e| e.direccion == Direccion::Entrante)
        .map(|e| e.tiempo_ns)
        .collect();
    let (marcas, direccion_ritmo) = if salientes_t.len() >= entrantes_t.len() {
        (salientes_t, Direccion::Saliente)
    } else {
        (entrantes_t, Direccion::Entrante)
    };
    r.direccion_del_ritmo = direccion_ritmo;
    let analisis = baliza::analizar(&marcas);
    r.temporal = analisis.metricas;
    r.veredicto_temporal = analisis.veredicto;
    if let Some(m) = analisis.metricas {
        v[F_CV_INV] = (1.0 - m.cv.min(1.0)) as f32;
        v[F_CV_ROBUSTO_INV] = (1.0 - m.cv_robusto.min(1.0)) as f32;
        v[F_COBERTURA] = m.cobertura as f32;
        // La regularidad usa la MISMA regla que el decisor temporal (cual de las
        // dos dispersiones vale segun la cobertura). Si aqui se usara otra, el
        // modelo y el analisis temporal podrian contradecirse sobre la misma
        // sesion, y el analista no tendria forma de saber cual creer.
        let dispersion = if m.cobertura >= baliza::COBERTURA_MINIMA_ROBUSTA {
            m.cv.min(m.cv_robusto)
        } else {
            m.cv
        };
        let cota = baliza::CV_MAXIMO_BALIZA * baliza::MARGEN_MUESTRAL;
        v[F_REGULARIDAD] = ((cota - dispersion) / cota).clamp(0.0, 1.0) as f32;
        // Periodo en escala logaritmica: de 1 s a 1 h en 0..1. Un periodo de un
        // segundo y uno de una hora son cosas distintas, pero la diferencia
        // interesante es de orden de magnitud, no lineal.
        v[F_PERIODO_NORM] = normalizar_log(m.mediana_seg, 1.0, 3600.0) as f32;
    }

    // --- 2. Volumen -------------------------------------------------------
    let salientes: Vec<f64> = eventos
        .iter()
        .filter(|e| e.direccion == Direccion::Saliente)
        .map(|e| e.longitud_total as f64)
        .collect();
    let entrantes: Vec<f64> = eventos
        .iter()
        .filter(|e| e.direccion == Direccion::Entrante)
        .map(|e| e.longitud_total as f64)
        .collect();
    r.bytes_salientes = media(&salientes);
    r.bytes_entrantes = media(&entrantes);
    v[F_BYTES_SAL_NORM] = normalizar_log(r.bytes_salientes, 64.0, 10_000_000.0) as f32;
    v[F_BYTES_ENT_NORM] = normalizar_log(r.bytes_entrantes, 64.0, 10_000_000.0) as f32;
    v[F_RATIO_ENT_SAL] = if r.bytes_salientes > 0.0 {
        (r.bytes_entrantes / r.bytes_salientes).clamp(0.0, 1.0) as f32
    } else {
        0.0
    };
    // Constancia del tamano: un implante manda siempre casi lo mismo.
    let todos: Vec<f64> = eventos.iter().map(|e| e.longitud_total as f64).collect();
    let m_tam = media(&todos);
    v[F_TAM_CONSTANTE] = if m_tam > 0.0 {
        (1.0 - (desviacion(&todos, m_tam) / m_tam).min(1.0)) as f32
    } else {
        0.0
    };
    v[F_FRAC_PEQUENOS] = fraccion(eventos.len(), todos.iter().filter(|b| **b < 1024.0).count());

    // --- 3. Contenido L7 --------------------------------------------------
    let mut http = 0usize;
    let mut desconocidos = 0usize;
    let mut peticiones = 0usize;
    let mut posts = 0usize;
    let mut sin_agente = 0usize;
    let mut agente_raro = 0usize;
    let mut cookie_b64 = false;
    let mut uri_b64 = false;
    let mut entropia_total = 0.0f64;
    let mut hosts = std::collections::BTreeSet::new();
    let mut rutas = std::collections::BTreeSet::new();

    for e in eventos {
        entropia_total += l7::entropia(&e.carga);
        let m = l7::analizar(&e.carga);
        if m.es_http() {
            http += 1;
        }
        if m.protocolo == Protocolo::Desconocido {
            desconocidos += 1;
        }
        if let Some(h) = m.host() {
            hosts.insert(h.to_string());
        }
        if m.protocolo != Protocolo::HttpPeticion {
            continue;
        }
        peticiones += 1;
        if m.metodo.as_deref() == Some("POST") {
            posts += 1;
        }
        match m.agente() {
            None => sin_agente += 1,
            Some(a) => {
                let a = a.to_ascii_lowercase();
                if !AGENTES_CONOCIDOS.iter().any(|c| a.contains(c)) {
                    agente_raro += 1;
                }
            }
        }
        if let Some(c) = m.cabecera("cookie") {
            // El valor de la cookie, no el nombre: la metadata viaja en el valor.
            if c.split(&[';', '='][..]).any(l7::parece_base64) {
                cookie_b64 = true;
            }
        }
        if let Some(u) = &m.uri {
            rutas.insert(u.clone());
            if u.split(&['/', '?', '&', '='][..]).any(l7::parece_base64) {
                uri_b64 = true;
            }
        }
    }

    r.hosts = hosts.len();
    r.rutas = rutas.len();
    r.fraccion_no_http = f64::from(fraccion(eventos.len(), desconocidos));
    r.entropia_media = entropia_total / eventos.len() as f64;

    v[F_FRAC_HTTP] = fraccion(eventos.len(), http);
    v[F_FRAC_DESCONOCIDO] = fraccion(eventos.len(), desconocidos);
    v[F_COOKIE_B64] = f32::from(u8::from(cookie_b64));
    v[F_URI_B64] = f32::from(u8::from(uri_b64));
    v[F_ENTROPIA] = (r.entropia_media / 8.0).clamp(0.0, 1.0) as f32;
    v[F_SIN_AGENTE] = fraccion(peticiones.max(1), sin_agente);
    v[F_AGENTE_RARO] = fraccion(peticiones.max(1), agente_raro);
    v[F_FRAC_POST] = fraccion(peticiones.max(1), posts);
    // Concentracion: 1 con un solo host, decreciendo con la variedad. Sin hosts
    // observados (trafico no-HTTP) se toma 1: un canal binario va a un sitio.
    v[F_UN_SOLO_HOST] = if hosts.is_empty() {
        1.0
    } else {
        (1.0 / hosts.len() as f32).clamp(0.0, 1.0)
    };
    // Estabilidad de URI. Significa "peticiones predecibles, legibles y SIN
    // metadata", que es lo que hace un health-check; no significa solo "siempre
    // la misma ruta".
    //
    // La distincion importa y costo un fallo: una baliza que lleva su metadata
    // en la COOKIE tambien pide siempre la misma URI. Con la condicion puesta
    // solo sobre la URI, esta feature valia 1 para esa baliza y —al restar 3,0 en
    // los conceptos de baliza— la protegia justo a ella. Por eso cualquier
    // metadata codificada, este donde este, anula la estabilidad.
    v[F_URI_ESTABLE] = if rutas.is_empty() || uri_b64 || cookie_b64 {
        0.0
    } else {
        (1.0 / rutas.len() as f32).clamp(0.0, 1.0)
    };

    // --- 4. Contexto ------------------------------------------------------
    v[F_MUESTRA_NORM] = (eventos.len() as f32 / 60.0).clamp(0.0, 1.0);
    let p = proceso.to_ascii_lowercase();
    v[F_PROC_NAVEGADOR] = f32::from(u8::from(NAVEGADORES.iter().any(|n| p.contains(n))));

    (r, v)
}

/// Media de una muestra; 0 si esta vacia.
fn media(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.iter().sum::<f64>() / v.len() as f64
}

/// Desviacion tipica muestral.
fn desviacion(v: &[f64], media: f64) -> f64 {
    if v.len() < 2 {
        return 0.0;
    }
    (v.iter().map(|x| (x - media).powi(2)).sum::<f64>() / (v.len() - 1) as f64).sqrt()
}

/// Fraccion `parte/total` acotada a `0..1`.
fn fraccion(total: usize, parte: usize) -> f32 {
    if total == 0 {
        return 0.0;
    }
    (parte as f32 / total as f32).clamp(0.0, 1.0)
}

/// Normaliza un valor a `0..1` en escala logaritmica entre `min` y `max`.
///
/// Logaritmica y no lineal porque los rangos que interesan abarcan varios ordenes
/// de magnitud: entre una baliza de un segundo y una de una hora hay un factor
/// 3600, y en escala lineal las dos quedarian aplastadas contra el mismo extremo.
fn normalizar_log(x: f64, min: f64, max: f64) -> f64 {
    if x <= min || !x.is_finite() {
        return 0.0;
    }
    if x >= max {
        return 1.0;
    }
    (x / min).ln() / (max / min).ln()
}

type Plan = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

/// El veredicto accionable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Veredicto {
    /// Trafico normal.
    Benigno,
    /// Sospechoso: elevar telemetria y vigilar, sin cortar todavia.
    Sospechoso,
    /// Canal de Comando y Control: cortar.
    CanalC2,
}

/// El resultado de clasificar una sesion.
#[derive(Debug, Clone)]
pub struct Clasificacion {
    /// Riesgo `0..1`.
    pub riesgo: f32,
    /// El veredicto derivado.
    pub veredicto: Veredicto,
    /// La evidencia que lo sostiene.
    pub resumen: Resumen,
}

/// El clasificador de canales C2, cargado y listo para inferir en el borde.
pub struct ModeloC2 {
    plan: Plan,
    umbral_c2: f32,
    umbral_sospechoso: f32,
}

impl ModeloC2 {
    /// Carga el modelo embebido en el binario.
    ///
    /// # Errores
    /// [`ModeloError::Carga`] si el modelo embebido no es un ONNX valido.
    pub fn embebido() -> Result<ModeloC2, ModeloError> {
        Self::desde_bytes(crate::MODELO_C2)
    }

    /// Carga un modelo desde bytes ONNX.
    ///
    /// # Errores
    /// [`ModeloError::Carga`] si el grafo no se puede leer, no acepta la forma de
    /// entrada `[1, DIM]` o no se puede optimizar.
    pub fn desde_bytes(bytes: &[u8]) -> Result<ModeloC2, ModeloError> {
        let mut cursor = std::io::Cursor::new(bytes);
        let plan = tract_onnx::onnx()
            .model_for_read(&mut cursor)
            .map_err(|e| ModeloError::Carga(e.to_string()))?
            .with_input_fact(0, f32::fact([1, DIM]).into())
            .map_err(|e| ModeloError::Carga(format!("forma de entrada [1,{DIM}]: {e}")))?
            .into_optimized()
            .map_err(|e| ModeloError::Carga(format!("optimizacion: {e}")))?
            .into_runnable()
            .map_err(|e| ModeloError::Carga(format!("preparacion: {e}")))?;
        Ok(ModeloC2 {
            plan,
            umbral_c2: 0.85,
            umbral_sospechoso: 0.50,
        })
    }

    /// Ajusta los umbrales de decision.
    #[must_use]
    pub fn con_umbrales(mut self, sospechoso: f32, c2: f32) -> ModeloC2 {
        self.umbral_sospechoso = sospechoso;
        self.umbral_c2 = c2;
        self
    }

    /// Infiere sobre un vector ya extraido.
    ///
    /// # Errores
    /// [`ModeloError::Dimension`] si el vector no mide [`DIM`], o
    /// [`ModeloError::Inferencia`] si el grafo falla.
    pub fn inferir(&self, features: &[f32]) -> Result<f32, ModeloError> {
        if features.len() != DIM {
            return Err(ModeloError::Dimension {
                encontrado: features.len(),
                esperado: DIM,
            });
        }
        let entrada = tract_ndarray::Array2::from_shape_vec((1, DIM), features.to_vec())
            .map_err(|e| ModeloError::Inferencia(e.to_string()))?;
        let tensor: Tensor = entrada.into();
        let salida = self
            .plan
            .run(tvec!(tensor.into()))
            .map_err(|e| ModeloError::Inferencia(e.to_string()))?;
        salida[0]
            .to_array_view::<f32>()
            .map_err(|e| ModeloError::Inferencia(e.to_string()))?
            .iter()
            .next()
            .copied()
            .ok_or_else(|| ModeloError::Inferencia("salida vacia".to_string()))
    }

    /// Clasifica una sesion entera: extrae, infiere y decide.
    ///
    /// # Errores
    /// [`ModeloError::Inferencia`] si el grafo falla.
    pub fn clasificar(
        &self,
        eventos: &[EventoL7],
        proceso: &str,
    ) -> Result<Clasificacion, ModeloError> {
        let (resumen, features) = extraer(eventos, proceso);
        let riesgo = self.inferir(&features)?;
        let veredicto = if riesgo >= self.umbral_c2 {
            Veredicto::CanalC2
        } else if riesgo >= self.umbral_sospechoso {
            Veredicto::Sospechoso
        } else {
            Veredicto::Benigno
        };
        Ok(Clasificacion {
            riesgo,
            veredicto,
            resumen,
        })
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Construye un evento con carga y momento dados.
    fn ev(t_ns: u64, carga: &[u8], saliente: bool, total: u64) -> EventoL7 {
        EventoL7 {
            tiempo_ns: t_ns,
            inicio_tarea_ns: 1,
            longitud_total: total,
            pid: 100,
            tid: 100,
            direccion: if saliente {
                Direccion::Saliente
            } else {
                Direccion::Entrante
            },
            comm: "proc".to_string(),
            carga: carga.to_vec(),
        }
    }

    /// Generador determinista, como en `baliza`.
    struct Azar(u64);
    impl Azar {
        fn nuevo(s: u64) -> Azar {
            Azar(s | 1)
        }
        fn uniforme(&mut self) -> f64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            ((x.wrapping_mul(0x2545_F491_4F6C_DD1D)) >> 11) as f64 / (1u64 << 53) as f64
        }
    }

    /// Una baliza de Cobalt Strike: duerme 60 s con jitter, pide siempre la
    /// misma ruta y lleva su metadata en una cookie codificada.
    fn sesion_baliza(jitter: f64, n: usize) -> Vec<EventoL7> {
        let mut azar = Azar::nuevo(0xC0BA17);
        let mut t = 1_000_000_000u64;
        let mut out = Vec::new();
        for _ in 0..n {
            let peticion = b"GET /updates HTTP/1.1\r\n\
                Host: cdn.actualizaciones.net\r\n\
                Cookie: SESSIONID=dXNlcj1hZG1pbjtob3N0PVdJTjEwMjM0NTY3\r\n\r\n";
            out.push(ev(t, peticion, true, peticion.len() as u64));
            let respuesta = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnoop";
            out.push(ev(t + 30_000_000, respuesta, false, respuesta.len() as u64));
            t += ((60.0 * (1.0 - jitter * azar.uniforme())) * 1e9) as u64;
        }
        out
    }

    /// EL CASO DIFICIL: un agente de monitorizacion. Igual de periodico, con
    /// mensajes igual de pequenos y constantes, contra un solo host.
    fn sesion_sondeo(n: usize) -> Vec<EventoL7> {
        let mut t = 1_000_000_000u64;
        let mut out = Vec::new();
        for _ in 0..n {
            let peticion = b"GET /metrics HTTP/1.1\r\n\
                Host: metrics.interno.corp\r\n\
                User-Agent: Prometheus/2.45.0\r\n\r\n";
            out.push(ev(t, peticion, true, peticion.len() as u64));
            let respuesta = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nup 1";
            out.push(ev(t + 20_000_000, respuesta, false, respuesta.len() as u64));
            t += 15_000_000_000; // exactamente 15 s, sin jitter
        }
        out
    }

    /// Un navegador: irregular, muchos hosts, agente conocido.
    fn sesion_navegador(n: usize) -> Vec<EventoL7> {
        let mut azar = Azar::nuevo(0xBEBE);
        let mut t = 1_000_000_000u64;
        let mut out = Vec::new();
        for i in 0..n {
            let peticion = format!(
                "GET /articulo/{i}/imagen.png HTTP/1.1\r\n\
                 Host: www.sitio{}.com\r\n\
                 User-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/120\r\n\r\n",
                i % 17
            );
            out.push(ev(t, peticion.as_bytes(), true, peticion.len() as u64));
            let cuerpo = 5_000 + (azar.uniforme() * 500_000.0) as u64;
            let respuesta = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n";
            out.push(ev(t + 10_000_000, respuesta, false, cuerpo));
            // Rafagas y silencios.
            t += if i % 15 == 0 {
                ((20.0 + 160.0 * azar.uniforme()) * 1e9) as u64
            } else {
                ((0.005 + 0.05 * azar.uniforme()) * 1e9) as u64
            };
        }
        out
    }

    fn modelo() -> ModeloC2 {
        ModeloC2::embebido().expect("el modelo embebido tiene que cargar")
    }

    #[test]
    fn el_modelo_embebido_carga_y_responde() {
        let m = modelo();
        let r = m.inferir(&[0.0f32; DIM]).expect("inferencia");
        assert!((0.0..=1.0).contains(&r), "riesgo fuera de rango: {r}");
    }

    #[test]
    fn una_dimension_equivocada_se_rechaza_en_vez_de_inferir_basura() {
        let m = modelo();
        assert!(matches!(
            m.inferir(&[0.0f32; DIM - 1]),
            Err(ModeloError::Dimension { .. })
        ));
        assert!(matches!(
            m.inferir(&[0.0f32; DIM + 1]),
            Err(ModeloError::Dimension { .. })
        ));
    }

    #[test]
    fn una_baliza_clasica_se_clasifica_como_canal_c2() {
        let c = modelo()
            .clasificar(&sesion_baliza(0.0, 40), "svchost")
            .expect("clasificacion");
        assert_eq!(c.veredicto, Veredicto::CanalC2, "riesgo {}", c.riesgo);
        assert!(c.riesgo > 0.85);
        assert!(c.resumen.veredicto_temporal.es_baliza());
    }

    #[test]
    fn una_baliza_con_jitter_del_cuarenta_por_ciento_tambien() {
        let c = modelo()
            .clasificar(&sesion_baliza(0.4, 40), "svchost")
            .expect("clasificacion");
        assert!(
            c.veredicto >= Veredicto::Sospechoso,
            "una baliza con jitter no puede pasar por benigna: {}",
            c.riesgo
        );
        assert!(c.resumen.veredicto_temporal.es_baliza());
    }

    /// EL CASO QUE DEFINE LA CALIBRACION. Un agente de monitorizacion es TAN
    /// periodico como una baliza sin jitter. Si el clasificador decidiera por la
    /// forma temporal, marcaria toda la observabilidad del cliente y a la semana
    /// nadie miraria las alertas.
    #[test]
    fn un_agente_de_monitorizacion_no_es_un_canal_c2() {
        let sondeo = sesion_sondeo(40);
        // PREMISA DE LA PRUEBA: el sondeo es temporalmente INDISTINGUIBLE de una
        // baliza. Se comprueba sobre la misma serie que usa el extractor —la del
        // lado que inicia—, porque es ahi donde vive el ritmo. Sin esta
        // comprobacion, la prueba podria estar pasando simplemente porque el
        // sondeo no parece periodico, que no demostraria nada.
        let (r_sondeo, _) = extraer(&sondeo, "prometheus");
        assert_eq!(
            r_sondeo.veredicto_temporal,
            VeredictoTemporal::BalizaExacta,
            "el sondeo tiene que ser temporalmente indistinguible de una baliza"
        );

        let c = modelo().clasificar(&sondeo, "prometheus").expect("clasif");
        assert_eq!(
            c.veredicto,
            Veredicto::Benigno,
            "un agente de monitorizacion puntuo {}: el modelo decide por \
             periodicidad en vez de por contenido",
            c.riesgo
        );

        // Y la separacion frente a la baliza tiene que ser amplia.
        let baliza_c = modelo()
            .clasificar(&sesion_baliza(0.0, 40), "svchost")
            .expect("clasif");
        assert!(
            baliza_c.riesgo - c.riesgo > 0.5,
            "no separa una baliza ({}) de un sondeo ({})",
            baliza_c.riesgo,
            c.riesgo
        );
    }

    #[test]
    fn un_navegador_no_es_un_canal_c2() {
        let c = modelo()
            .clasificar(&sesion_navegador(120), "chrome")
            .expect("clasif");
        assert_eq!(c.veredicto, Veredicto::Benigno, "riesgo {}", c.riesgo);
        assert!(c.resumen.hosts > 5, "un navegador va a muchos hosts");
    }

    /// Un canal binario propio dentro de TLS es sospechoso aunque NO sea
    /// periodico: un operador tecleando en una shell interactiva no tiene ritmo.
    #[test]
    fn un_canal_binario_propio_se_detecta_sin_periodicidad() {
        let mut azar = Azar::nuevo(0xB1);
        let mut t = 1_000_000_000u64;
        let mut eventos = Vec::new();
        for _ in 0..40 {
            // Carga de entropia maxima: contenido cifrado dentro del TLS.
            let carga: Vec<u8> = (0..256).map(|_| (azar.uniforme() * 256.0) as u8).collect();
            eventos.push(ev(t, &carga, true, carga.len() as u64));
            t += ((0.1 + 30.0 * azar.uniforme()) * 1e9) as u64; // irregular
        }
        let c = modelo().clasificar(&eventos, "servidor").expect("clasif");
        assert!(
            c.veredicto >= Veredicto::Sospechoso,
            "un canal binario de alta entropia dentro de TLS es una senal: {}",
            c.riesgo
        );
        assert!(c.resumen.fraccion_no_http > 0.9);
        assert!(c.resumen.entropia_media > 6.0);
    }

    #[test]
    fn una_sesion_vacia_no_afirma_nada() {
        let c = modelo().clasificar(&[], "x").expect("clasif");
        assert_eq!(c.resumen.mensajes, 0);
        assert_eq!(c.resumen.veredicto_temporal, VeredictoTemporal::SinMuestra);
        assert_eq!(c.veredicto, Veredicto::Benigno);
    }

    /// EL HALLAZGO QUE CORRIGIO EL MODELO. Una iteracion de baliza son dos
    /// eventos —peticion y respuesta 30 ms despues—, asi que la serie MEZCLADA
    /// alterna 0,03 s y 60 s: es bimodal y sus metricas son identicas a las del
    /// trafico a rafagas. Una baliza perfecta se clasificaria como irregular.
    /// Midiendo solo el lado que inicia, la misma serie da CV = 0.
    #[test]
    fn el_ritmo_se_mide_sobre_la_direccion_que_inicia() {
        let s = sesion_baliza(0.0, 40);

        // La serie mezclada: irregular, como un navegador.
        let mezcladas: Vec<u64> = s.iter().map(|e| e.tiempo_ns).collect();
        let mezclada = baliza::analizar(&mezcladas);
        assert_eq!(
            mezclada.veredicto,
            VeredictoTemporal::Irregular,
            "la serie mezclada NO parece periodica: ese es el problema"
        );

        // La del lado que inicia: una baliza exacta.
        let (r, _) = extraer(&s, "svchost");
        assert_eq!(r.direccion_del_ritmo, Direccion::Saliente);
        assert_eq!(r.veredicto_temporal, VeredictoTemporal::BalizaExacta);
        let m = r.temporal.expect("hay metricas");
        assert!(m.cv < 0.01, "CV sobre las peticiones = {}", m.cv);
        assert!(m.cobertura > 0.9, "cobertura = {}", m.cobertura);
    }

    #[test]
    fn la_extraccion_es_determinista() {
        let s = sesion_baliza(0.3, 30);
        let (r1, v1) = extraer(&s, "svchost");
        let (r2, v2) = extraer(&s, "svchost");
        assert_eq!(v1, v2);
        assert_eq!(r1, r2);
    }

    #[test]
    fn todas_las_features_quedan_en_el_rango_del_modelo() {
        // Un valor fuera de 0..1 no rompe la inferencia, pero descalibra los
        // sesgos: un concepto se encenderia por un feature que vale 40 en vez
        // de 1. Se comprueba sobre sesiones de naturaleza muy distinta.
        for (s, p) in [
            (sesion_baliza(0.0, 40), "svchost"),
            (sesion_baliza(1.0, 40), "svchost"),
            (sesion_sondeo(40), "prometheus"),
            (sesion_navegador(80), "chrome"),
        ] {
            let (_, v) = extraer(&s, p);
            for (i, x) in v.iter().enumerate() {
                assert!(
                    (0.0..=1.0).contains(x) && x.is_finite(),
                    "feature {i} = {x} fuera de 0..1 en '{p}'"
                );
            }
        }
    }

    #[test]
    fn la_normalizacion_logaritmica_cubre_los_extremos() {
        assert_eq!(normalizar_log(0.5, 1.0, 3600.0), 0.0);
        assert_eq!(normalizar_log(1.0, 1.0, 3600.0), 0.0);
        assert_eq!(normalizar_log(7200.0, 1.0, 3600.0), 1.0);
        let medio = normalizar_log(60.0, 1.0, 3600.0);
        // 60 s es la raiz cuadrada de 3600: en escala logaritmica, la mitad.
        assert!((medio - 0.5).abs() < 1e-9, "{medio}");
        assert_eq!(normalizar_log(f64::NAN, 1.0, 10.0), 0.0);
    }
}
