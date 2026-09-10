//! La caceria AegisQL de extremo a extremo, sobre el transporte mTLS real.
//!
//! Se levanta un servidor de flota autentico, se conecta un cliente autentico
//! con su certificado, la consulta baja por el canal de suscripcion y el
//! resultado sube por una llamada unaria. No hay atajos: si el enmarcado, los
//! numeros de campo o el handshake divergieran, esta prueba fallaria.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_fleet::pki::AutoridadCertificadora;
use aegis_fleet::proto::{
    AckCaza, AckEvento, AckLatido, EmpujePolitica, FilaCaza, Latido, ReporteCaza, ReporteEvento,
    RespuestaEnrolamiento, SolicitudEnrolamiento,
};
use aegis_fleet::servidor::{ManejadorFlota, ServidorFlota};
use aegis_fleet::{ClienteFlota, EmisorLocal, PoliticaRotacion, RotadorCertificados};

/// Plano de control de prueba que lanza UNA caceria y recoge lo que llegue.
struct PlanoDeCaza {
    consulta: String,
    /// Informes recibidos, en orden de llegada.
    informes: Mutex<Vec<ReporteCaza>>,
    /// Cuantas veces se ha entregado ya la consulta.
    entregas: AtomicUsize,
}

impl ManejadorFlota for PlanoDeCaza {
    fn enrolar(&self, _cn: &str, _req: &SolicitudEnrolamiento) -> RespuestaEnrolamiento {
        RespuestaEnrolamiento {
            aceptado: true,
            ..Default::default()
        }
    }

    fn latido(&self, _cn: &str, _req: &Latido) -> AckLatido {
        AckLatido::default()
    }

    fn evento(&self, _cn: &str, _req: &ReporteEvento) -> AckEvento {
        AckEvento::default()
    }

    fn esperar_empuje(
        &self,
        _cn: &str,
        _version_conocida: u64,
        _plazo: Duration,
    ) -> Option<EmpujePolitica> {
        // Solo la primera vez lleva caceria; las siguientes son latidos del
        // canal. Asi la prueba comprueba tambien que un agente no reejecuta la
        // misma consulta en bucle.
        if self.entregas.fetch_add(1, Ordering::SeqCst) == 0 {
            Some(EmpujePolitica {
                version: 1,
                caza_id: "caza-1".to_string(),
                caza_ql: self.consulta.clone(),
                ..Default::default()
            })
        } else {
            Some(EmpujePolitica {
                es_keepalive: true,
                ..Default::default()
            })
        }
    }

    fn caza(&self, cn: &str, req: &ReporteCaza) -> AckCaza {
        // La identidad del agente la pone el CERTIFICADO, no lo que el agente
        // declare de si mismo: es lo unico que no puede falsificar.
        let mut informe = req.clone();
        informe.id_agente = cn.to_string();
        self.informes.lock().unwrap().push(informe);
        AckCaza {
            recibido: true,
            motivo: String::new(),
        }
    }
}

/// Levanta servidor y cliente conectados por mTLS con una CA de una sola vez.
fn banco(
    plano: Arc<PlanoDeCaza>,
) -> (
    aegis_fleet::servidor::ServidorEnEjecucion,
    Arc<AutoridadCertificadora>,
    std::net::SocketAddr,
) {
    let ca = Arc::new(AutoridadCertificadora::nueva("CA de prueba").expect("CA"));
    let id_srv = ca
        .emitir("control-plane", 3600)
        .expect("identidad del servidor");
    let ejecutando = ServidorFlota::nuevo(&id_srv, &ca.cert_der(), plano)
        .expect("servidor")
        .escuchar("127.0.0.1:0")
        .expect("escuchar");
    let dir = ejecutando.direccion();
    (ejecutando, ca, dir)
}

fn cliente(ca: &Arc<AutoridadCertificadora>, dir: std::net::SocketAddr, cn: &str) -> ClienteFlota {
    let emisor = Arc::new(EmisorLocal::nuevo(ca.clone()));
    let rotador = Arc::new(
        RotadorCertificados::nuevo(cn, PoliticaRotacion::default(), emisor).expect("rotador"),
    );
    ClienteFlota::nuevo(dir, ca.cert_der(), rotador, cn, "1.0.0")
}

#[test]
fn una_caza_baja_por_el_canal_y_el_resultado_sube_por_mtls() {
    let plano = Arc::new(PlanoDeCaza {
        consulta: "SELECT pid, path FROM processes WHERE uid = 0 LIMIT 5".to_string(),
        informes: Mutex::new(Vec::new()),
        entregas: AtomicUsize::new(0),
    });
    let (servidor, ca, dir) = banco(plano.clone());

    // 1. El agente se enrola y abre su canal de suscripcion.
    let agente = cliente(&ca, dir, "endpoint-01");
    agente
        .abrir_sesion()
        .expect("sesion")
        .enrolar(&agente.solicitud_enrolamiento().expect("solicitud"))
        .expect("enrolar");

    let mut canal = agente
        .abrir_sesion()
        .expect("sesion")
        .suscribir_politica(0)
        .expect("suscribir");

    // 2. Por el canal baja la caceria.
    let empuje = canal.siguiente().expect("recibir el empuje");
    assert_eq!(empuje.caza_id, "caza-1");
    assert!(
        empuje.caza_ql.starts_with("SELECT pid, path"),
        "la consulta no llego intacta: {}",
        empuje.caza_ql
    );

    // 3. El agente responde por una conexion aparte.
    let ack = agente
        .abrir_sesion()
        .expect("sesion")
        .reportar_caza(&ReporteCaza {
            id_agente: "endpoint-01".into(),
            caza_id: empuje.caza_id.clone(),
            columnas: vec!["pid".into(), "path".into()],
            filas: vec![FilaCaza {
                celdas: vec!["1".into(), "/sbin/init".into()],
            }],
            coincidencias: 1,
            examinadas: 312,
            duracion_ms: 4,
            ..Default::default()
        })
        .expect("reportar");
    assert!(ack.recibido, "el plano de control rechazo el informe");

    // 4. El plano de control lo tiene, atribuido al CN del certificado.
    let informes = plano.informes.lock().unwrap();
    assert_eq!(informes.len(), 1);
    assert_eq!(informes[0].id_agente, "endpoint-01");
    assert_eq!(informes[0].caza_id, "caza-1");
    assert_eq!(informes[0].filas[0].celdas[1], "/sbin/init");
    assert_eq!(informes[0].examinadas, 312);

    drop(informes);
    servidor.parar();
}

#[test]
fn un_informe_de_caza_sobrevive_la_ida_y_vuelta_con_todos_sus_contadores() {
    // Los contadores son lo que permite al analista distinguir "no hay nada" de
    // "no pude mirar". Si se perdieran en el cable, el informe mentiria.
    let plano = Arc::new(PlanoDeCaza {
        consulta: "SELECT COUNT(*) FROM processes".to_string(),
        informes: Mutex::new(Vec::new()),
        entregas: AtomicUsize::new(0),
    });
    let (servidor, ca, dir) = banco(plano.clone());

    let agente = cliente(&ca, dir, "endpoint-02");
    agente
        .abrir_sesion()
        .expect("sesion")
        .enrolar(&agente.solicitud_enrolamiento().expect("solicitud"))
        .expect("enrolar");

    let original = ReporteCaza {
        id_agente: "endpoint-02".into(),
        caza_id: "caza-9".into(),
        columnas: vec!["count".into()],
        filas: vec![FilaCaza {
            celdas: vec!["0".into()],
        }],
        coincidencias: 0,
        examinadas: 4096,
        inaccesibles: 17,
        incompleto: true,
        agotado: true,
        duracion_ms: 5001,
        error: String::new(),
    };
    agente
        .abrir_sesion()
        .expect("sesion")
        .reportar_caza(&original)
        .expect("reportar");

    let informes = plano.informes.lock().unwrap();
    let r = &informes[0];
    assert_eq!(r.inaccesibles, 17, "se perdio la cuenta de inaccesibles");
    assert!(r.incompleto);
    assert!(r.agotado, "se perdio el aviso de presupuesto agotado");
    assert_eq!(r.duracion_ms, 5001);
    assert_eq!(r.examinadas, 4096);

    drop(informes);
    servidor.parar();
}

#[test]
fn un_endpoint_que_no_puede_ejecutar_la_consulta_lo_dice() {
    // Si un endpoint que rechaza la consulta se limitara a callar, seria
    // indistinguible de uno apagado, y el analista creeria que su caceria
    // cubrio una flota que no cubrio.
    let plano = Arc::new(PlanoDeCaza {
        consulta: "SELECT pid FROM processes".to_string(),
        informes: Mutex::new(Vec::new()),
        entregas: AtomicUsize::new(0),
    });
    let (servidor, ca, dir) = banco(plano.clone());

    let agente = cliente(&ca, dir, "endpoint-03");
    agente
        .abrir_sesion()
        .expect("sesion")
        .reportar_caza(&ReporteCaza {
            caza_id: "caza-1".into(),
            error: "sin privilegios para leer /proc de otros usuarios".into(),
            ..Default::default()
        })
        .expect("reportar");

    let informes = plano.informes.lock().unwrap();
    assert!(informes[0].error.contains("sin privilegios"));
    assert!(informes[0].filas.is_empty());

    drop(informes);
    servidor.parar();
}
