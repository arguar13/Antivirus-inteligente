//! # `aegis-predict` — AegisPredict: predecir el ataque y contenerlo antes (FASE 69)
//!
//! ## De reaccionar a anticipar
//!
//! Todo lo anterior del producto responde **después**: algo pasó, se detectó, se
//! remedió. Esta fase responde otra pregunta, la que hace un CISO:
//!
//! > Dado cómo está montada mi organización, **¿por dónde va a entrar y hasta
//! > dónde llega?**
//!
//! El plano de control ya tiene lo que hace falta para contestarla: el **grafo de
//! identidad** de la [FASE 58](58-dop.md) —quién puede actuar como quién— y la
//! topología de red. Lo que faltaba era unirlos y calcular sobre ellos.
//!
//! ## Las tres preguntas y sus tres respuestas exactas
//!
//! | Pregunta | Método | Por qué ése |
//! |---|---|---|
//! | ¿Cuál es el camino de ataque más probable? | [`caminos`] — Dijkstra sobre `−log p` | El logaritmo convierte maximizar un **producto** en minimizar una **suma** de pesos no negativos: el resultado es el **óptimo exacto**, no una heurística |
//! | ¿Hasta dónde llega? | [`radio`] — percolación Monte Carlo sembrada | La pregunta exacta es **#P-completa**; el muestreo es *la* forma de responderla, y el resultado lleva su **margen de error** dentro |
//! | ¿Qué activos importan de verdad? | [`criticidad`] — *message passing* amortiguado | Un portátil de becario vale lo que valen las cosas a las que da acceso |
//!
//! ## Lo que este motor autoriza, y por qué eso lo cambia todo
//!
//! AegisPredict no escribe informes: **propone aislar máquinas de producción**.
//! Esa frase gobierna cada decisión de diseño del crate.
//!
//! **Por eso nada aquí está entrenado.** Ni las probabilidades de las aristas, ni
//! los pesos de la criticidad. Están puestos a mano, documentados con su razón, y
//! el resultado se puede imprimir en una frase: *«alice tiene credenciales
//! cacheadas de svc-backup, que es miembro de Domain Admins; p = 0,94»*. Un
//! analista puede leer eso y decir que no. Un vector de activaciones no se
//! discute, y lo que no se discute no se pone delante de un cliente cuya máquina
//! se va a quedar sin red.
//!
//! **Y por eso todo es determinista.** Mismo grafo, mismo camino, mismo radio,
//! misma propuesta — desempates incluidos. No es comodidad: el informe que
//! justifica aislar una máquina el lunes tiene que dar lo mismo cuando alguien lo
//! audite el martes.
//!
//! ## Los dos peligros de la contención preventiva
//!
//! **(a) El modelo se equivoca y la cura es la enfermedad.** Aislar doscientas
//! máquinas por una predicción es una denegación de servicio auto-infligida. Por
//! encima de cierto tamaño **la contención ES la interrupción**, así que hay un
//! tope duro: pasado él, el motor **no actúa, escala a una persona**.
//!
//! **(b) El atacante dirige la predicción.** Él es quien se mueve lateralmente,
//! quien se autentica, quien deja credenciales cacheadas: **fabrica aristas**. Si
//! el motor actuara sobre cualquier camino, un adversario podría construirse uno
//! *a través de la máquina que quiere tirar* y lograr que la propia defensa la
//! aísle — AegisPredict convertido en denegación de servicio manejada por el
//! adversario. Es el problema de la FASE 68 en otra capa, y se resuelve igual: la
//! evidencia **débil no mueve nada automáticamente**. Una arista vista una vez,
//! hace diez minutos y por un solo observador, pesa un tercio y nunca dispara una
//! acción sola.
//!
//! ## Los cinco frenos
//!
//! 1. Un activo **protegido** (plano de control, controladores de dominio) no se
//!    toca jamás: cortar la capacidad de respuesta del defensor es el objetivo
//!    del atacante, no del EDR.
//! 2. **Tope de radio**: por encima, se escala a una persona.
//! 3. **Sólo evidencia corroborada** mueve una acción automática.
//! 4. **Umbral de probabilidad**: un camino improbable no justifica nada.
//! 5. **Mínima y reversible**: se prefiere cortar la *identidad* (revocar
//!    tickets, matar el proceso que cachea credenciales) a *aislar la máquina*.
//!    Aislar es el último recurso, no el primero.
//!
//! Y una diferencia que no se borra: una **detección** confirmada dispara el
//! playbook entero de la FASE 64; una **predicción** dispara como mucho **una**
//! acción acotada. En un caso ha pasado algo; en el otro podría pasar.
//!
//! ## Honestidad de validación
//!
//! | Pieza | Verificable aquí | Cómo |
//! |---|---|---|
//! | Camino más probable | **sí** | contra un producto calculado a mano, y con el caso donde el camino óptimo **no** es el más corto |
//! | Radio de explosión | **sí** | converge al valor **analítico** `p + p²` con error < 0,02 |
//! | El margen encoge como `1/√n` | **sí** | medido con 200 y 20 000 pasadas |
//! | Criticidad | **sí** | valor exacto a mano, y un ciclo **converge** en vez de dispararse |
//! | Determinismo | **sí** | decenas de repeticiones, empates exactos incluidos |
//! | Los cinco frenos | **sí** | uno por uno, incluido el ataque de aristas fabricadas |
//! | Que segmentar **reduce** el radio | **sí** | si no, el modelo aconsejaría al revés |
//! | Calibración de las probabilidades contra brechas reales | — | exigiría un corpus etiquetado de esta organización, que no existe. Los números son **explícitos y discutibles** a propósito: están en [`grafo::probabilidad`] con su razón, no dentro de un modelo |
//!
//! Esa última fila es el límite honesto de la fase. El motor no sabe si `0,60`
//! es la probabilidad real de que alguien se autentique en otro host de **esta**
//! empresa; sabe que autenticarse cuesta más que heredar un grupo y menos que
//! cruzar un firewall, y ese **orden** —que sí se prueba— es lo que hace que el
//! ranking y los caminos sean útiles aunque los valores absolutos se ajusten.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod caminos;
pub mod contencion;
pub mod criticidad;
pub mod error;
pub mod grafo;
pub mod radio;

pub use caminos::{camino_mas_probable, caminos_a_las_joyas, CaminoAtaque};
pub use contencion::{decidir, ConfigContencion, Motivo, Veredicto};
pub use criticidad::{propagar, Criticidades};
pub use error::ErrorPrediccion;
pub use grafo::{Activo, ClaseActivo, Evidencia, GrafoAtaque, Paso, Via};
pub use radio::{radio_de_explosion, RadioExplosion};

/// El informe completo de un análisis preventivo.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct InformePrediccion {
    /// Desde qué activo se analizó.
    pub origen: String,
    /// Los caminos a las joyas de la corona, de más probable a menos.
    pub caminos: Vec<CaminoAtaque>,
    /// El radio de explosión estimado.
    pub radio: RadioExplosion,
    /// Qué se propone hacer.
    pub veredicto: Veredicto,
}

impl InformePrediccion {
    /// El camino más probable, si hay alguno.
    #[must_use]
    pub fn camino_principal(&self) -> Option<&CaminoAtaque> {
        self.caminos.first()
    }
}

/// Analiza un activo de principio a fin: caminos, radio y propuesta.
///
/// # Errores
/// [`ErrorPrediccion::ActivoDesconocido`] si el origen no está en el grafo, o
/// [`ErrorPrediccion::SinJoyasDeLaCorona`] si no hay nada declarado como crítico.
pub fn analizar(
    g: &GrafoAtaque,
    origen: &str,
    config: &ConfigContencion,
) -> Result<InformePrediccion, ErrorPrediccion> {
    let caminos = caminos_a_las_joyas(g, origen)?;
    let radio = radio_de_explosion(g, origen, radio::PASADAS_POR_DEFECTO)?;
    let veredicto = decidir(g, caminos.first(), &radio, config)?;
    Ok(InformePrediccion {
        origen: origen.to_string(),
        caminos,
        radio,
        veredicto,
    })
}
