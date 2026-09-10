//! Transporte NATIVO de la flota: el que hablan los agentes reales.
//!
//! El agente (`aegis-fleet`, FASE 34) envia protobuf con el enmarcado de gRPC
//! —prefijo de cinco bytes— sobre un canal mTLS crudo, NO sobre HTTP/2. Este
//! modulo implementa el trait [`ManejadorFlota`] que define ese crate, asi que
//! el servidor decodifica exactamente con el mismo codigo con el que el agente
//! codifica. La compatibilidad de cable no es una promesa: es la misma
//! implementacion en los dos extremos.
//!
//! # El puente sincrono/asincrono
//!
//! El trait es SINCRONO (el listener del agente atiende cada conexion en su
//! propio hilo) y la persistencia es ASINCRONA (sqlx sobre tokio). El puente es
//! `Handle::block_on`, que es correcto AQUI precisamente porque estos metodos
//! corren en hilos propios del listener y no en un worker de tokio —bloquear un
//! worker seria un error grave que tokio detecta y castiga con un panico—.

use std::sync::Arc;
use std::time::Duration;

use aegis_fleet::proto::{
    AckCaza, AckEvento, AckGrafo, AckLatido, AckStix, EmpujePolitica, Latido, ReporteCaza,
    ReporteEvento, ReporteGrafo, ReporteStix, RespuestaEnrolamiento, SolicitudEnrolamiento,
};
use aegis_fleet::servidor::ManejadorFlota;
use tokio::runtime::Handle;

use crate::dominio::ServicioFlota;
use crate::pizarra::{Atendido, ListaCuarentena, Pizarra};

/// Manejador de flota respaldado por PostgreSQL.
pub struct ManejadorPersistente {
    servicio: Arc<ServicioFlota>,
    handle: Handle,
    /// Estado que se difunde a los canales de suscripcion.
    ///
    /// POR QUE LA CUARENTENA NO SE CONSULTA POR AGENTE
    /// ----------------------------------------------
    /// La cuarentena es IGUAL para toda la flota, y difundirla despierta los
    /// diez mil canales a la vez. Consultarla por canal convertia una orden de
    /// contencion en diez mil consultas sobre un pool de treinta y dos
    /// conexiones: medido, 418.162 transacciones y 5,3 segundos hasta el ultimo
    /// endpoint, cuando el objetivo son 200 ms. Durante esos segundos la maquina
    /// comprometida sigue teniendo por donde moverse.
    ///
    /// Con la pizarra, un cambio de cuarentena es UNA lectura de base de datos y
    /// diez mil escrituras en sockets. Ver [`crate::pizarra`] para por que la
    /// espera es de hilo y no de tokio.
    pizarra: Arc<Pizarra>,
    /// Si este plano de control difunde de verdad.
    ///
    /// Sin notificador no hay nadie que publique en la pizarra, asi que el canal
    /// de suscripcion se cierra de forma ordenada en vez de dejar al agente
    /// esperando algo que no llegaria.
    difunde: bool,
    /// Instrumentacion de la difusion. Ver [`DifusionCuarentena`].
    difusion: Arc<DifusionCuarentena>,
}

/// Cuanto tarda el plano de control en poner una orden de contencion EN EL CABLE
/// para toda la flota.
///
/// QUE MIDE ESTO Y QUE NO
/// ----------------------
/// El simulador mide cuando cada agente RECIBE la orden, que es lo que le
/// importa al cliente. Pero en un banco de pruebas de UNA SOLA MAQUINA ese
/// numero incluye tambien lo que tardan diez mil agentes virtuales en despertar
/// y leer sus sockets, compitiendo por los mismos nucleos que el servidor. En
/// produccion esos diez mil agentes estan en diez mil maquinas distintas y no le
/// quitan un solo ciclo al plano de control.
///
/// Esta medida es la del PRODUCTO: desde que la lista nueva se publica hasta que
/// el ultimo de los canales ha escrito el empuje. Es lo unico que el plano de
/// control controla, y es lo que sigue valiendo cuando la flota es real.
///
/// Las dos se publican juntas. Dar solo una de ellas seria enganoso en las dos
/// direcciones: solo la del producto esconde el coste real del banco, y solo la
/// del banco atribuye al producto un coste que es del banco.
#[derive(Debug)]
pub struct DifusionCuarentena {
    /// Origen comun de todos los tiempos. Inmutable: se lee sin cerrojo desde
    /// los diez mil hilos de canal.
    origen: std::time::Instant,
    /// Generacion que se esta midiendo.
    gen: std::sync::atomic::AtomicU64,
    /// Instante de publicacion de esa generacion, en us desde `origen`.
    inicio_us: std::sync::atomic::AtomicU64,
    /// Canales que ya la han escrito.
    escritos: std::sync::atomic::AtomicU64,
    /// Retraso del ULTIMO de ellos, en us.
    ///
    /// El maximo y no la media: hasta que el ultimo endpoint no aplica la regla,
    /// la maquina comprometida todavia tiene por donde moverse.
    ultimo_us: std::sync::atomic::AtomicU64,
    /// Reparto de retrasos en cubos de [`MS_POR_CUBO`] ms; el ultimo desborda.
    ///
    /// POR QUE UN REPARTO Y NO SOLO EL MAXIMO
    /// -------------------------------------
    /// El maximo dice SI se cumple el objetivo; el reparto dice POR QUE no. Son
    /// dos diagnosticos opuestos con el mismo maximo: si la mediana esta cerca
    /// del maximo, la difusion va al ritmo que da la maquina y el cuello esta en
    /// el coste por canal; si la mediana esta muy por debajo, la difusion es
    /// rapida y hay un punado de rezagados, que es otro problema y tiene otra
    /// solucion. Sin esto, elegir entre las dos seria adivinar.
    reparto: [std::sync::atomic::AtomicU32; CUBOS],
}

/// Anchura de cada cubo del reparto, en milisegundos.
const MS_POR_CUBO: u64 = 2;
/// Numero de cubos. Los 254 primeros cubren medio segundo; el ultimo desborda.
const CUBOS: usize = 256;

impl Default for DifusionCuarentena {
    fn default() -> DifusionCuarentena {
        DifusionCuarentena {
            origen: std::time::Instant::now(),
            gen: std::sync::atomic::AtomicU64::new(0),
            inicio_us: std::sync::atomic::AtomicU64::new(0),
            escritos: std::sync::atomic::AtomicU64::new(0),
            ultimo_us: std::sync::atomic::AtomicU64::new(0),
            reparto: std::array::from_fn(|_| std::sync::atomic::AtomicU32::new(0)),
        }
    }
}

impl DifusionCuarentena {
    /// Marca el instante en que la lista `gen` queda publicada.
    ///
    /// Se llama ANTES de publicarla: si se llamara despues, un canal rapido
    /// podria anotarse contra un instante de salida que aun no existe y su
    /// retraso saldria absurdo.
    fn abrir(&self, gen: u64) {
        let ahora = self.origen.elapsed().as_micros() as u64;
        self.inicio_us
            .store(ahora, std::sync::atomic::Ordering::Relaxed);
        self.escritos.store(0, std::sync::atomic::Ordering::Relaxed);
        self.ultimo_us
            .store(0, std::sync::atomic::Ordering::Relaxed);
        for c in &self.reparto {
            c.store(0, std::sync::atomic::Ordering::Relaxed);
        }
        // La generacion se publica la ULTIMA, con `Release`, para que ningun
        // canal se anote antes de que los contadores esten a cero.
        self.gen.store(gen, std::sync::atomic::Ordering::Release);
    }

    /// Anota que un canal acaba de escribir el empuje de la generacion `gen`.
    ///
    /// Sin cerrojo a proposito: lo ejecutan diez mil hilos a la vez y un mutex
    /// aqui convertiria la medicion en el cuello de botella que pretende medir.
    fn anotar(&self, gen: u64) {
        if gen == 0 || self.gen.load(std::sync::atomic::Ordering::Acquire) != gen {
            return; // de una orden anterior: no se mezcla
        }
        let inicio = self.inicio_us.load(std::sync::atomic::Ordering::Relaxed);
        let ahora = self.origen.elapsed().as_micros() as u64;
        let retraso = ahora.saturating_sub(inicio);
        self.escritos
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.ultimo_us
            .fetch_max(retraso, std::sync::atomic::Ordering::Relaxed);
        let cubo = ((retraso / 1_000) / MS_POR_CUBO) as usize;
        self.reparto[cubo.min(CUBOS - 1)].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Cota superior del percentil `p`, en ms, o `None` si no hay muestras.
    ///
    /// Es una COTA SUPERIOR, nunca una estimacion optimista: se devuelve el
    /// techo del cubo en que cae la muestra. Un percentil que se quedara corto
    /// aqui haria pasar por bueno un objetivo que no se cumple.
    pub fn percentil_ms(&self, p: f64) -> Option<f64> {
        let total: u64 = self
            .reparto
            .iter()
            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed) as u64)
            .sum();
        if total == 0 {
            return None;
        }
        let objetivo = ((p / 100.0) * total as f64).ceil().max(1.0) as u64;
        let mut acumulado = 0u64;
        for (i, c) in self.reparto.iter().enumerate() {
            acumulado += c.load(std::sync::atomic::Ordering::Relaxed) as u64;
            if acumulado >= objetivo {
                return Some(((i + 1) as u64 * MS_POR_CUBO) as f64);
            }
        }
        None
    }

    /// Lectura de la difusion en curso: `(generacion, canales, us del ultimo)`.
    pub fn instantanea(&self) -> (u64, u64, u64) {
        (
            self.gen.load(std::sync::atomic::Ordering::Acquire),
            self.escritos.load(std::sync::atomic::Ordering::Relaxed),
            self.ultimo_us.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

impl ManejadorPersistente {
    /// Crea el manejador con el runtime sobre el que ejecutar la persistencia.
    ///
    /// Sin notificador NO hay empuje: el canal de suscripcion se cerrara de
    /// forma ordenada en vez de dejar al agente esperando algo que no llegaria.
    pub fn nuevo(servicio: Arc<ServicioFlota>, handle: Handle) -> ManejadorPersistente {
        ManejadorPersistente {
            servicio,
            handle,
            pizarra: Arc::new(Pizarra::default()),
            difunde: false,
            difusion: Arc::new(DifusionCuarentena::default()),
        }
    }

    /// Instrumentacion de la difusion de cuarentena, para exponerla por la API.
    pub fn difusion(&self) -> Arc<DifusionCuarentena> {
        self.difusion.clone()
    }

    /// Habilita el empuje con el notificador dado.
    ///
    /// Arranca DOS tareas, y ninguna de las dos vive en los canales:
    ///
    /// - la que traslada a la pizarra los avisos de politica y caceria;
    /// - la que mantiene al dia la lista de cuarentena. Es UNA tarea para todo
    ///   el proceso: lee la lista cuando cambia y la publica de una vez a los
    ///   diez mil canales, en vez de que cada canal la consulte por su cuenta.
    pub fn con_avisos(
        mut self,
        notificador: &crate::notificador::Notificador,
    ) -> ManejadorPersistente {
        let mut avisos = notificador.suscriptor();
        let mut avisos_cuarentena = notificador.suscriptor_cuarentena();
        let servicio = self.servicio.clone();
        let difusion = self.difusion.clone();

        let pizarra = self.pizarra.clone();
        self.handle.spawn(async move {
            // El estado inicial, antes de esperar ningun aviso: un agente que
            // conecta al arrancar el servicio tiene que ver la politica vigente.
            pizarra.publicar_aviso(*avisos.borrow_and_update());
            while avisos.changed().await.is_ok() {
                let aviso = *avisos.borrow_and_update();
                pizarra.publicar_aviso(aviso);
            }
        });

        let pizarra = self.pizarra.clone();
        self.handle.spawn(async move {
            let leer = |servicio: Arc<ServicioFlota>| async move {
                match servicio.almacen().cuarentena_vigente().await {
                    Ok(v) => Some(
                        v.iter()
                            .map(|c| c.direccion.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                    ),
                    Err(e) => {
                        tracing::error!(error = %e, "no se pudo leer la cuarentena vigente");
                        None
                    }
                }
            };

            // Se publica antes de esperar ningun aviso: un agente que conecta al
            // arrancar el servicio tiene que recibir la cuarentena que ya estaba
            // en vigor. La generacion cero es ese estado inicial: no la provoco
            // ninguna orden, asi que no se mide.
            if let Some(lista) = leer(servicio.clone()).await {
                pizarra.publicar_cuarentena(Arc::new(ListaCuarentena { lista, gen: 0 }));
            }

            let mut secuencia: u64 = 0;
            while avisos_cuarentena.changed().await.is_ok() {
                if let Some(lista) = leer(servicio.clone()).await {
                    secuencia += 1;
                    // El cronometro arranca ANTES de publicar: la lectura de la
                    // base de datos ya termino, y lo que queda por medir es
                    // exactamente la difusion.
                    difusion.abrir(secuencia);
                    pizarra.publicar_cuarentena(Arc::new(ListaCuarentena {
                        lista,
                        gen: secuencia,
                    }));
                }
            }
        });

        self.difunde = true;
        self
    }
}

impl ManejadorFlota for ManejadorPersistente {
    fn enrolar(&self, cn: &str, req: &SolicitudEnrolamiento) -> RespuestaEnrolamiento {
        let servicio = self.servicio.clone();
        // Una copia para el closure y otra, acotada, para el registro: el CN lo
        // controla el par y no debe volcarse entero en el log.
        let cn_log = cn_seguro(cn);
        let cn_owned = cn.to_string();
        let req = req.clone();

        let resultado = self.handle.block_on(async move {
            servicio
                .enrolar(
                    &cn_owned,
                    &req.id_agente,
                    &req.hostname,
                    &req.version_agente,
                    &req.huella_cert,
                )
                .await
        });

        match resultado {
            Ok(id_flota) => RespuestaEnrolamiento {
                aceptado: true,
                id_flota,
                intervalo_latido_seg: self.servicio.intervalo_latido_seg(),
                motivo: String::new(),
            },
            Err(e) => {
                // Un fallo de la base de datos se convierte en un rechazo CON
                // motivo, no en una conexion cortada: el agente reintentara y,
                // mientras tanto, el operador ve por que no entra.
                tracing::error!(cn = %cn_log, error = %e, "enrolamiento fallido");
                RespuestaEnrolamiento {
                    aceptado: false,
                    id_flota: String::new(),
                    intervalo_latido_seg: self.servicio.intervalo_latido_seg(),
                    motivo: "el plano de control no pudo registrar el agente".to_string(),
                }
            }
        }
    }

    fn latido(&self, cn: &str, req: &Latido) -> AckLatido {
        let servicio = self.servicio.clone();
        let cn_owned = cn.to_string();
        let req = req.clone();

        let resultado = self.handle.block_on(async move {
            servicio
                .latido(
                    &cn_owned,
                    req.rss_kb,
                    req.amenazas_activas,
                    req.version_politica,
                )
                .await
        });

        match resultado {
            Ok(estado) => AckLatido {
                recibido: true,
                version_politica_disponible: estado.version_politica.max(0) as u64,
                hay_comando: estado.hay_comando,
            },
            Err(e) => {
                tracing::warn!(error = %e, "latido no persistido");
                // `recibido: false` le dice al agente que su latido no quedo
                // registrado; seguira latiendo y el inventario se recuperara
                // solo en cuanto la base de datos vuelva.
                AckLatido {
                    recibido: false,
                    version_politica_disponible: 0,
                    hay_comando: false,
                }
            }
        }
    }

    fn stix(&self, cn: &str, req: &ReporteStix) -> AckStix {
        let servicio = self.servicio.clone();
        let cn_owned = cn.to_string();
        let bundle = req.bundle_json.clone();
        let momento = req.momento_unix;

        let resultado = self
            .handle
            .block_on(async move { servicio.ingerir_stix(&cn_owned, &bundle, momento).await });

        match resultado {
            Ok(ingesta) => AckStix {
                recibido: true,
                objetos_ingeridos: ingesta.objetos,
                motivo: String::new(),
            },
            Err(e) => {
                tracing::warn!(error = %e, "bundle STIX rechazado");
                AckStix {
                    recibido: false,
                    objetos_ingeridos: 0,
                    // El motivo viaja al agente: un endpoint que sabe POR QUE se
                    // le rechaza puede corregir; uno que solo recibe un no,
                    // reintenta lo mismo para siempre.
                    motivo: format!("{e}"),
                }
            }
        }
    }

    fn grafo(&self, cn: &str, req: &ReporteGrafo) -> AckGrafo {
        let servicio = self.servicio.clone();
        let cn_owned = cn.to_string();
        let raiz = req.raiz;
        let momento = req.momento_unix;
        let nodos = req.nodos.clone();

        let resultado = self.handle.block_on(async move {
            servicio
                .ingerir_grafo(&cn_owned, raiz, momento, &nodos)
                .await
        });

        match resultado {
            Ok((id, n)) => AckGrafo {
                recibido: true,
                id_grafo: id.to_string(),
                nodos_ingeridos: n,
            },
            Err(e) => {
                tracing::error!(error = %e, "LINAJE DE PROCESOS NO PERSISTIDO");
                AckGrafo::default()
            }
        }
    }

    fn esperar_empuje(
        &self,
        cn: &str,
        estado: &mut aegis_fleet::servidor::EstadoCanal,
        plazo: Duration,
    ) -> Option<EmpujePolitica> {
        // Sin notificador no hay empuje: se cierra el canal en vez de dejar al
        // agente esperando indefinidamente algo que no va a llegar.
        if !self.difunde {
            return None;
        }
        let version_conocida = estado.version_entregada;

        // EL CAMINO RAPIDO NO ENTRA EN EL RUNTIME
        //
        // Este hilo es uno de los diez mil que atienden un canal. Entrar en
        // tokio para dormir obliga a inscribirse en las esperas y a dar de alta
        // un temporizador en cada vuelta del bucle; con diez mil hilos, ese
        // trabajo lo paga en serie quien publica, mientras los endpoints
        // esperan. Aqui se duerme con la primitiva que corresponde a un hilo
        // bloqueado, y solo se entra en el runtime si hay que consultar la base
        // de datos. Ver el modulo `pizarra`.
        let atendido = Atendido {
            gen_politica: estado.gen_politica_vista,
            gen_caza: estado.gen_caza_vista,
            cuarentena: estado.cuarentena_entregada.as_deref(),
        };

        // Un canal recien abierto se pone al dia SIEMPRE: tiene que recibir la
        // politica que el agente no tiene, sus comandos pendientes, la caceria
        // abierta y la cuarentena en vigor. Eso cuesta varias consultas, y esta
        // bien: ocurre UNA vez, cuando el endpoint conecta.
        //
        // Lo que no puede ocurrir es repetirlo en cada vuelta. Medido: con diez
        // mil canales dando doce vueltas cada uno eran 426.084 transacciones
        // para difundir una sola orden de contencion.
        let difundido = if estado.al_dia {
            match self.pizarra.esperar(atendido, plazo) {
                Some(d) => d,
                // Vencio el plazo: latido de canal. Sin el, un canal sano y uno
                // muerto son indistinguibles para los dos extremos.
                None => {
                    return Some(EmpujePolitica {
                        version: version_conocida,
                        es_keepalive: true,
                        ..Default::default()
                    })
                }
            }
        } else {
            self.pizarra.leer()
        };

        // UNA CUARENTENA NUEVA NO TOCA LA BASE DE DATOS
        //
        // La lista esta en la pizarra y es identica para toda la flota. Es la
        // diferencia entre difundir una orden de contencion con una consulta o
        // con diez mil.
        if estado.al_dia
            && estado.cuarentena_entregada.as_deref() != Some(&difundido.cuarentena.lista)
        {
            estado.cuarentena_entregada = Some(difundido.cuarentena.lista.clone());
            return Some(EmpujePolitica {
                // La version que el agente YA tiene: este empuje no trae
                // politica, y decir otra cosa le haria creer que se perdio una.
                version: version_conocida,
                cuarentena: difundido.cuarentena.lista.clone(),
                cuarentena_valida: true,
                ..Default::default()
            });
        }

        // Lo demas —politica, comandos, cacerias— si necesita la base de datos,
        // y por eso este es el unico tramo que entra en el runtime.
        let caza_entregada = estado.caza_entregada.clone();
        let cn_owned = cn.to_string();
        let empuje = self.handle.block_on(self.componer_empuje(
            &cn_owned,
            difundido.aviso.version_politica,
            version_conocida,
            &caza_entregada,
        ));

        // Se anota hasta donde se ha atendido ANTES de decidir si hay algo que
        // enviar: la consulta ya se hizo, y repetirla en la vuelta siguiente
        // seria pagarla dos veces por nada.
        estado.gen_politica_vista = difundido.aviso.gen_politica;
        estado.gen_caza_vista = difundido.aviso.gen_caza;

        let cuarentena_cambio = empuje.cuarentena_valida
            && estado.cuarentena_entregada.as_deref() != Some(empuje.cuarentena.as_str());
        if !empuje.politica_json.is_empty()
            || !empuje.comandos_json.is_empty()
            || !empuje.caza_ql.is_empty()
            || cuarentena_cambio
        {
            return Some(empuje);
        }

        // No habia nada. Se vuelve a esperar en vez de devolver un latido de
        // inmediato: un canal que contestara aqui giraria en vacio.
        let atendido = Atendido {
            gen_politica: estado.gen_politica_vista,
            gen_caza: estado.gen_caza_vista,
            cuarentena: Some(empuje.cuarentena.as_str()),
        };
        match self.pizarra.esperar(atendido, plazo) {
            Some(d) if estado.cuarentena_entregada.as_deref() != Some(&d.cuarentena.lista) => {
                estado.cuarentena_entregada = Some(d.cuarentena.lista.clone());
                Some(EmpujePolitica {
                    version: version_conocida,
                    cuarentena: d.cuarentena.lista.clone(),
                    cuarentena_valida: true,
                    ..Default::default()
                })
            }
            // Hubo aviso de politica o caceria: se atiende en la vuelta
            // siguiente, que ya no tomara el camino de puesta al dia.
            Some(_) => Some(EmpujePolitica {
                version: version_conocida,
                es_keepalive: true,
                ..Default::default()
            }),
            None => Some(EmpujePolitica {
                version: version_conocida,
                es_keepalive: true,
                ..Default::default()
            }),
        }
    }

    /// Un empuje ya escrito en el socket de un agente.
    ///
    /// Es el punto en que la orden de contencion sale de verdad del plano de
    /// control, y por eso es aqui —y no cuando se compone— donde se cierra el
    /// cronometro de la difusion.
    fn empuje_escrito(&self, _cn: &str, empuje: &EmpujePolitica) {
        if !empuje.cuarentena_valida {
            return;
        }
        // Se anota contra la generacion vigente solo si lo escrito ES esa
        // generacion. Un empuje que llevaba una lista anterior —un canal lento
        // que la compuso antes de la orden— no puede contar como difundido.
        let vigente = self.pizarra.leer().cuarentena;
        if empuje.cuarentena == vigente.lista {
            self.difusion.anotar(vigente.gen);
        }
    }

    fn visto_en(&self, cn: &str, direccion: std::net::SocketAddr) {
        let servicio = self.servicio.clone();
        let cn = cn.to_string();
        let ip = direccion.ip();
        // No se espera al resultado: registrar el inventario de red no puede
        // retrasar el dialogo con el agente, y si falla se reintentara en la
        // siguiente conexion, que llega en el proximo latido.
        self.handle.spawn(async move {
            if let Err(e) = servicio.almacen().registrar_direccion(&cn, ip).await {
                tracing::debug!(error = %e, cn = %cn, "no se pudo registrar la direccion");
            }
        });
    }

    fn caza(&self, cn: &str, req: &ReporteCaza) -> AckCaza {
        let servicio = self.servicio.clone();
        let cn = cn.to_string();
        let req = req.clone();

        self.handle.block_on(async move {
            let Ok(caza_id) = uuid::Uuid::parse_str(&req.caza_id) else {
                return AckCaza {
                    recibido: false,
                    motivo: "identificador de caceria invalido".to_string(),
                };
            };

            // Las filas se guardan como array de arrays de texto. El tipo de
            // cada columna ya lo declara el esquema de AegisQL.
            let filas = serde_json::Value::Array(
                req.filas
                    .iter()
                    .map(|f| {
                        serde_json::Value::Array(
                            f.celdas
                                .iter()
                                .map(|c| serde_json::Value::String(c.clone()))
                                .collect(),
                        )
                    })
                    .collect(),
            );

            let almacen = servicio.almacen();
            if let Err(e) = almacen
                .guardar_respuesta_caza(
                    caza_id,
                    &cn,
                    &filas,
                    req.coincidencias as i64,
                    req.examinadas as i64,
                    req.inaccesibles as i64,
                    req.incompleto,
                    req.agotado,
                    req.duracion_ms as i64,
                    &req.error,
                )
                .await
            {
                // Se DICE que no se guardo. Responder "recibido" haria creer al
                // agente que su trabajo sirvio, y el resultado se perderia sin
                // que nadie se enterara.
                tracing::error!(error = %e, cn = %cn, "no se pudo guardar la respuesta de caza");
                return AckCaza {
                    recibido: false,
                    motivo: "el plano de control no pudo guardar la respuesta".to_string(),
                };
            }

            // El panel se entera al instante: una caceria sobre diez mil
            // endpoints se ve llegar, no se espera a que termine.
            servicio
                .bus()
                .publicar(crate::eventos::EventoPanel::CazaRespuesta {
                    caza_id: req.caza_id.clone(),
                    cn: cn.clone(),
                    coincidencias: req.coincidencias as i64,
                    inaccesibles: req.inaccesibles as i64,
                    agotado: req.agotado,
                    error: req.error.clone(),
                });

            AckCaza {
                recibido: true,
                motivo: String::new(),
            }
        })
    }

    fn evento(&self, cn: &str, req: &ReporteEvento) -> AckEvento {
        let servicio = self.servicio.clone();
        let cn_owned = cn.to_string();
        let req = req.clone();

        let resultado = self.handle.block_on(async move {
            servicio
                .evento(
                    &cn_owned,
                    req.severidad,
                    &req.categoria,
                    &req.descripcion,
                    req.momento_unix,
                )
                .await
        });

        match resultado {
            Ok(id) => AckEvento {
                recibido: true,
                id_incidente: id.to_string(),
            },
            Err(e) => {
                // Un evento que no se persiste es una alerta perdida: se deja
                // constancia en el log del servidor con nivel de error.
                tracing::error!(error = %e, "EVENTO DE SEGURIDAD NO PERSISTIDO");
                AckEvento {
                    recibido: false,
                    id_incidente: String::new(),
                }
            }
        }
    }
}

impl ManejadorPersistente {
    /// Construye el empuje con la politica vigente y los comandos del agente.
    ///
    /// `version_conocida` es la que el agente declaro tener. Si la vigente no es
    /// mas nueva, el cuerpo de la politica NO viaja: solo su numero de version.
    ///
    /// Importa mas de lo que parece. Desde que las cacerias comparten canal con
    /// la politica, cualquier caceria despierta los canales de TODA la flota; si
    /// cada uno de esos despertares reenviara la politica completa, lanzar una
    /// consulta de rutina costaria diez mil copias de una politica que los
    /// agentes ya tienen. El agente distingue los dos casos por el numero de
    /// version, que siempre viaja.
    async fn componer_empuje(
        &self,
        cn: &str,
        version: i64,
        version_conocida: u64,
        caza_entregada: &str,
    ) -> EmpujePolitica {
        let almacen = self.servicio.almacen();
        let (v, politica) = almacen
            .politica_activa()
            .await
            .unwrap_or((version, serde_json::Value::Null));

        // Los comandos se toman AQUI y se marcan entregados: `FOR UPDATE SKIP
        // LOCKED` garantiza que, con varias instancias atendiendo la misma
        // flota, ninguno se entrega dos veces.
        let mut comandos = Vec::new();
        while comandos.len() < 32 {
            match almacen.tomar_comando_pendiente(cn).await {
                Ok(Some(c)) => comandos.push(serde_json::json!({
                    "id": c.id, "accion": c.accion, "parametros": c.parametros
                })),
                _ => break,
            }
        }

        // Caceria pendiente para ESTE agente. Va en el mismo empuje que la
        // politica porque el canal es el mismo, y eso significa que un endpoint
        // que reconecta despues de estar apagado recibe a la vez la politica que
        // se perdio y la caceria que se lanzo mientras no estaba.
        // Si es la MISMA que este canal ya le entrego, no se reenvia: el agente
        // sigue trabajando en ella. Reenviarla seria un bucle cerrado entre el
        // canal y un agente que aun no ha terminado de contestar.
        let (caza_id, caza_ql) = match almacen.caza_pendiente_para(cn).await {
            Ok(Some((id, ql))) if id.to_string() != caza_entregada => (id.to_string(), ql),
            _ => (String::new(), String::new()),
        };

        // El conjunto COMPLETO de direcciones vigentes, leido de la cache en
        // memoria: es identico para toda la flota, asi que consultarlo por
        // agente convertiria una orden de contencion en diez mil consultas.
        //
        // La lista va ENTERA, incluida la direccion del propio agente si la
        // tuviera. Excluirla aqui obligaria a saber cual es —otra consulta por
        // agente, y ademas solo conoceriamos la que vimos en el handshake—.
        // Quien sabe TODAS las direcciones de una maquina es la maquina: el
        // segmentador del endpoint se salta las suyas antes de aplicar nada.
        let cuarentena = self.pizarra.leer().cuarentena.lista.clone();
        let cuarentena_valida = self.difunde;

        let hay_politica_nueva = v.max(0) as u64 > version_conocida;
        EmpujePolitica {
            caza_id,
            caza_ql,
            cuarentena,
            cuarentena_valida,
            version: v.max(0) as u64,
            politica_json: if politica.is_null() || !hay_politica_nueva {
                String::new()
            } else {
                politica.to_string()
            },
            comandos_json: if comandos.is_empty() {
                String::new()
            } else {
                serde_json::Value::Array(comandos).to_string()
            },
            es_keepalive: false,
        }
    }
}

/// Evita volcar en el log un CN de longitud arbitraria controlado por el par.
fn cn_seguro(cn: &str) -> String {
    cn.chars().take(64).collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_cn_del_log_queda_acotado() {
        assert_eq!(cn_seguro(&"a".repeat(500)).chars().count(), 64);
    }

    #[test]
    fn una_difusion_cuenta_solo_los_canales_de_su_generacion() {
        let d = DifusionCuarentena::default();
        d.abrir(1);
        d.anotar(1);
        d.anotar(1);
        // Un canal lento que aun llevaba la lista anterior: no es esta difusion.
        d.anotar(0);
        // Una generacion futura tampoco: si contara, el recuento de la orden en
        // curso incluiria endpoints que recibieron OTRA orden.
        d.anotar(2);
        let (gen, canales, _) = d.instantanea();
        assert_eq!((gen, canales), (1, 2));
    }

    #[test]
    fn una_orden_nueva_no_hereda_el_recuento_de_la_anterior() {
        // Sin esto, la segunda orden empezaria con diez mil canales ya contados
        // y pareceria instantanea.
        let d = DifusionCuarentena::default();
        d.abrir(1);
        d.anotar(1);
        d.anotar(1);
        d.abrir(2);
        assert_eq!(d.instantanea(), (2, 0, 0));
        d.anotar(2);
        assert_eq!(d.instantanea().1, 1);
    }

    #[test]
    fn el_tiempo_publicado_es_el_del_ultimo_canal_y_no_el_de_ninguno_antes() {
        // El maximo y no la media: hasta que el ultimo endpoint no aplica la
        // regla, la maquina comprometida todavia tiene por donde moverse.
        let d = DifusionCuarentena::default();
        d.abrir(1);
        d.anotar(1);
        let primero = d.instantanea().2;
        std::thread::sleep(std::time::Duration::from_millis(20));
        d.anotar(1);
        let ultimo = d.instantanea().2;
        assert!(
            ultimo >= primero + 15_000,
            "el ultimo ({ultimo} us) tenia que reflejar la espera, no el primero ({primero} us)"
        );
    }

    #[test]
    fn una_difusion_recien_abierta_no_afirma_haber_llegado_a_nadie() {
        // Un cero en `canales` con `generacion` puesta significa "ordenada y
        // todavia sin difundir". Confundirlo con "difundida a cero endpoints en
        // cero milisegundos" haria pasar la prueba de propagacion sin haber
        // propagado nada.
        let d = DifusionCuarentena::default();
        assert_eq!(d.instantanea(), (0, 0, 0));
        d.abrir(7);
        assert_eq!(d.instantanea(), (7, 0, 0));
    }
}
