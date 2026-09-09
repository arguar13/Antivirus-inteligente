//! Pruebas del motor de decepcion.
//!
//! Los senuelos se prueban con SOCKETS DE VERDAD: se levantan, se conecta a
//! ellos, se lee el saludo que envian y se comprueba que la interaccion queda
//! registrada con el origen y el puerto correctos. Lo que no se puede fabricar
//! con trafico real —un ataque que venga de la puerta de enlace— se inyecta como
//! interaccion sintetica, porque la propiedad que se quiere fijar ahi es la de
//! la barandilla, no la del socket.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

use aegis_deception::decoy::{DecoyConfig, DecoyKind, DecoyNet, Interaction, SkipReason};
use aegis_deception::engine::{DeceptionConfig, DeceptionEngine};
use aegis_deception::guard::{parse_routes, Guard};
use aegis_deception::sensor::{clasificar, AlertKind, ReconSensor, SensorConfig};
use aegis_scal::netfilter::{BlockReason, BlockedAddress, NetworkFilter};
use aegis_scal::platform::Platform;
use aegis_scal::ScalError;

// ---------------------------------------------------------------------------
// Doble de pruebas del filtro de red
// ---------------------------------------------------------------------------

/// Filtro que anota lo que le piden en vez de tocar el sistema.
///
/// No sustituye a la prueba con `nftables` de verdad —esa esta mas abajo—: sirve
/// para poder comprobar QUE se pide y con que motivo, que con el filtro real
/// solo se ve el resultado final.
#[derive(Debug, Default)]
struct FiltroDeMentira {
    bloqueadas: Mutex<Vec<(IpAddr, BlockReason, Option<Duration>)>>,
}

impl NetworkFilter for FiltroDeMentira {
    fn platform(&self) -> Platform {
        Platform::Linux
    }
    fn available(&self) -> bool {
        true
    }
    fn block(
        &self,
        addr: IpAddr,
        reason: BlockReason,
        ttl: Option<Duration>,
    ) -> Result<(), ScalError> {
        self.bloqueadas.lock().unwrap().push((addr, reason, ttl));
        Ok(())
    }
    fn unblock(&self, addr: IpAddr) -> Result<(), ScalError> {
        self.bloqueadas
            .lock()
            .unwrap()
            .retain(|(a, _, _)| *a != addr);
        Ok(())
    }
    fn blocked(&self) -> Result<Vec<BlockedAddress>, ScalError> {
        Ok(self
            .bloqueadas
            .lock()
            .unwrap()
            .iter()
            .map(|(a, r, t)| BlockedAddress {
                addr: *a,
                reason: *r,
                ttl: *t,
            })
            .collect())
    }
    fn flush(&self) -> Result<(), ScalError> {
        self.bloqueadas.lock().unwrap().clear();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Utillaje
// ---------------------------------------------------------------------------

fn config_local(servicios: &[DecoyKind]) -> DecoyConfig {
    DecoyConfig {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        // Puerto 0: el sistema asigna uno libre, asi la prueba no choca con
        // nada de la maquina ni necesita privilegios.
        services: servicios.iter().map(|k| (*k, 0u16)).collect(),
        speak_timeout: Duration::from_millis(80),
        max_evidence: 128,
        max_per_poll: 16,
    }
}

fn interaccion(peer: &str, kind: DecoyKind, ts: u64) -> Interaction {
    Interaction {
        peer: peer.parse().unwrap(),
        peer_port: 40000,
        kind,
        port: kind.default_port(),
        ts_ns: ts,
        evidence: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Senuelos reales
// ---------------------------------------------------------------------------

#[test]
fn un_senuelo_registra_la_conexion_con_su_origen() {
    let net = DecoyNet::bind(config_local(&[DecoyKind::Ssh]));
    let activos = net.active();
    assert_eq!(activos.len(), 1, "el senuelo tiene que levantarse");
    let (kind, puerto) = activos[0];
    assert_eq!(kind, DecoyKind::Ssh);
    assert!(puerto > 0, "el sistema asigno un puerto real");

    let cliente = TcpStream::connect((Ipv4Addr::LOCALHOST, puerto)).expect("conecta");
    let origen = cliente.local_addr().unwrap();

    let vistas = net.poll(Duration::from_millis(500), 1_000);
    assert_eq!(vistas.len(), 1, "la conexion tiene que verse");
    assert_eq!(vistas[0].peer, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(vistas[0].peer_port, origen.port());
    assert_eq!(vistas[0].port, puerto);
    assert_eq!(vistas[0].kind, DecoyKind::Ssh);
    assert_eq!(vistas[0].ts_ns, 1_000);
}

#[test]
fn el_senuelo_de_ssh_saluda_como_un_ssh_de_verdad() {
    // Un escaner que no recibe nada anota "puerto abierto, servicio
    // desconocido" y sigue. Uno que recibe un saludo creible anota servicio y
    // version y VUELVE con un exploit concreto, que es la informacion valiosa.
    let net = DecoyNet::bind(config_local(&[DecoyKind::Ssh]));
    let (_, puerto) = net.active()[0];

    let mut cliente = TcpStream::connect((Ipv4Addr::LOCALHOST, puerto)).unwrap();
    cliente
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    // El saludo lo envia el senuelo al aceptar, que ocurre dentro de `poll`.
    let _ = net.poll(Duration::from_millis(500), 1);

    let mut saludo = [0u8; 64];
    let n = cliente
        .read(&mut saludo)
        .expect("el senuelo tiene que saludar");
    let texto = String::from_utf8_lossy(&saludo[..n]);
    assert!(
        texto.starts_with("SSH-2.0-"),
        "el saludo tiene que parecer un SSH real, llego {texto:?}"
    );
}

#[test]
fn lo_que_el_atacante_envia_queda_como_evidencia() {
    // Es lo que distingue un barrido —conecta y cierra— de un intento de
    // explotacion, que manda una peticion concreta.
    let net = DecoyNet::bind(config_local(&[DecoyKind::Smb]));
    let (_, puerto) = net.active()[0];

    let mut cliente = TcpStream::connect((Ipv4Addr::LOCALHOST, puerto)).unwrap();
    cliente.write_all(b"\x00\x00\x00\x85\xffSMBr").unwrap();
    cliente.flush().unwrap();

    let vistas = net.poll(Duration::from_millis(500), 1);
    assert_eq!(vistas.len(), 1);
    assert!(vistas[0].spoke(), "el cliente hablo");
    assert!(
        vistas[0].evidence.starts_with(b"\x00\x00\x00\x85\xffSMB"),
        "la evidencia tiene que ser lo que envio: {:?}",
        vistas[0].evidence
    );
}

#[test]
fn un_senuelo_jamas_tapa_un_servicio_de_verdad() {
    // Si el 22 lo tiene el sshd real, tomarlo dejaria la maquina sin
    // administracion remota. Un producto de seguridad que corta el acceso
    // legitimo se desinstala el mismo dia.
    let real = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ocupado = real.local_addr().unwrap().port();

    let cfg = DecoyConfig {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        services: vec![(DecoyKind::Ssh, ocupado), (DecoyKind::Rdp, 0)],
        ..config_local(&[])
    };
    let net = DecoyNet::bind(cfg);

    assert_eq!(net.active().len(), 1, "solo el que estaba libre");
    assert_eq!(net.active()[0].0, DecoyKind::Rdp);
    assert_eq!(net.skipped().len(), 1);
    assert_eq!(net.skipped()[0].kind, DecoyKind::Ssh);
    assert_eq!(net.skipped()[0].port, ocupado);
    assert_eq!(net.skipped()[0].reason, SkipReason::InUse);

    // Y el servicio de verdad sigue funcionando.
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, ocupado)).is_ok());
    drop(real);
}

#[test]
fn los_puertos_del_catalogo_son_los_que_todo_el_mundo_espera() {
    assert_eq!(DecoyKind::Ssh.default_port(), 22);
    assert_eq!(DecoyKind::Smb.default_port(), 445);
    assert_eq!(DecoyKind::Rdp.default_port(), 3389);
    // Dos senuelos con el mismo puerto no se podrian levantar a la vez.
    let mut puertos: Vec<u16> = aegis_deception::CATALOGO
        .iter()
        .map(|k| k.default_port())
        .collect();
    puertos.sort_unstable();
    let antes = puertos.len();
    puertos.dedup();
    assert_eq!(puertos.len(), antes, "hay puertos repetidos en el catalogo");
}

// ---------------------------------------------------------------------------
// Correlacion
// ---------------------------------------------------------------------------

#[test]
fn la_gravedad_solo_sube_y_no_se_repite_la_misma_alerta() {
    // Repetir la misma alerta por cada paquete convierte la consola en ruido y
    // entrena al analista a ignorarla.
    let mut s = ReconSensor::new(SensorConfig::default());
    let a = s
        .observe(&interaccion("203.0.113.7", DecoyKind::Ssh, 1))
        .unwrap();
    assert_eq!(a.kind, AlertKind::Contact);
    assert!(
        !a.block,
        "una sola conexion todavia puede ser un inventario"
    );

    // Otra vez el mismo senuelo: nada nuevo que decir.
    assert!(s
        .observe(&interaccion("203.0.113.7", DecoyKind::Ssh, 2))
        .is_none());

    // Un segundo servicio de acceso remoto ya es movimiento lateral.
    let b = s
        .observe(&interaccion("203.0.113.7", DecoyKind::Smb, 3))
        .unwrap();
    assert_eq!(b.kind, AlertKind::LateralMovement);
    assert!(b.block, "a la tercera interaccion ya no hay excusa");
    assert_eq!(b.decoys, vec![DecoyKind::Ssh, DecoyKind::Smb]);
    assert_eq!(b.interactions, 3);

    // Y no vuelve a alertar por lo mismo.
    assert!(s
        .observe(&interaccion("203.0.113.7", DecoyKind::Rdp, 4))
        .is_none());
    assert_eq!(s.tracked(), 1);
}

#[test]
fn la_clasificacion_distingue_reconocimiento_de_movimiento_lateral() {
    // Un solo servicio de acceso remoto todavia puede ser un inventario.
    assert_eq!(clasificar(&[DecoyKind::Ssh], false, 3), AlertKind::Contact);
    // Dos ya no: alguien busca por donde saltar al siguiente equipo.
    assert_eq!(
        clasificar(&[DecoyKind::Ssh, DecoyKind::Rdp], false, 3),
        AlertKind::LateralMovement
    );
    // Tres servicios cualesquiera son un barrido.
    assert_eq!(
        clasificar(
            &[DecoyKind::Ftp, DecoyKind::MySql, DecoyKind::Postgres],
            false,
            3
        ),
        AlertKind::PortSweep
    );
    // Hablar agrava un contacto suelto.
    assert_eq!(clasificar(&[DecoyKind::Ftp], true, 3), AlertKind::Probe);
}

#[test]
fn el_sensor_no_crece_sin_limite_ante_una_inundacion() {
    // Con direcciones falsificadas, un atacante podria convertir al detector en
    // el objetivo.
    let mut s = ReconSensor::new(SensorConfig {
        max_peers: 16,
        ..SensorConfig::default()
    });
    for i in 0..200u32 {
        let ip = format!("198.51.100.{}", i % 250);
        s.observe(&interaccion(&ip, DecoyKind::Ssh, i as u64));
    }
    assert!(s.tracked() <= 16, "seguidos: {}", s.tracked());
}

#[test]
fn los_origenes_inactivos_se_olvidan() {
    let mut s = ReconSensor::new(SensorConfig {
        forget_after: Duration::from_secs(1),
        ..SensorConfig::default()
    });
    s.observe(&interaccion("198.51.100.9", DecoyKind::Ssh, 0));
    assert_eq!(s.tracked(), 1);
    assert_eq!(s.prune(500_000_000), 0, "medio segundo no basta");
    assert_eq!(s.prune(2_000_000_000), 1);
    assert_eq!(s.tracked(), 0);
}

// ---------------------------------------------------------------------------
// La barandilla
// ---------------------------------------------------------------------------

#[test]
fn la_puerta_de_enlace_se_lee_en_el_orden_de_bytes_del_host() {
    // El fichero lleva las direcciones en el orden del HOST. Leerlas como
    // big-endian da `1.2.0.192` donde hay un `192.0.2.1`, y la barandilla
    // dejaria de proteger la puerta de enlace de verdad.
    let texto =
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                 eth0\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
                 eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
    let gws = parse_routes(texto);
    assert_eq!(gws, vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
}

#[test]
fn la_barandilla_protege_lo_que_no_se_puede_bloquear_jamas() {
    let gw: IpAddr = "192.0.2.1".parse().unwrap();
    let excluida: IpAddr = "203.0.113.50".parse().unwrap();
    let g = Guard::with_gateways(vec![excluida], vec![gw]);

    // Bloquear la puerta de enlace deja la maquina incomunicada, INCLUIDO el
    // arreglo de quitar el bloqueo.
    assert!(!g.may_block(gw));
    assert!(g.refusal(gw).unwrap().contains("incomunicada"));

    assert!(!g.may_block("127.0.0.1".parse().unwrap()));
    assert!(!g.may_block("0.0.0.0".parse().unwrap()));
    assert!(!g.may_block("255.255.255.255".parse().unwrap()));
    // En la nube, la red de enlace local es el servicio de metadatos: cortarlo
    // deja la instancia sin credenciales ni DNS.
    assert!(!g.may_block("169.254.169.254".parse().unwrap()));
    assert!(!g.may_block("224.0.0.1".parse().unwrap()));
    assert!(!g.may_block(excluida));

    // Y un atacante cualquiera si se puede bloquear.
    assert!(g.may_block("198.51.100.66".parse().unwrap()));
}

#[test]
fn la_barandilla_detecta_la_puerta_de_enlace_de_esta_maquina() {
    let g = Guard::detect(Vec::new());
    for gw in g.gateways() {
        assert!(
            !g.may_block(*gw),
            "la puerta de enlace detectada {gw} tiene que estar protegida"
        );
    }
}

// ---------------------------------------------------------------------------
// El motor
// ---------------------------------------------------------------------------

fn motor(autonomo: bool) -> DeceptionEngine<FiltroDeMentira> {
    DeceptionEngine::start(
        DeceptionConfig {
            decoys: config_local(&[DecoyKind::Ssh, DecoyKind::Rdp]),
            sensor: SensorConfig::default(),
            allowlist: vec!["203.0.113.50".parse().unwrap()],
            block_ttl: Some(Duration::from_secs(600)),
            autonomous: autonomo,
        },
        FiltroDeMentira::default(),
    )
}

#[test]
fn el_movimiento_lateral_acaba_en_bloqueo_con_su_motivo() {
    let mut m = motor(true);
    let atacante = "198.51.100.77";
    let r = m.ingest(
        vec![
            interaccion(atacante, DecoyKind::Ssh, 1),
            interaccion(atacante, DecoyKind::Rdp, 2),
        ],
        2,
    );

    assert_eq!(r.alerts.len(), 2, "contacto y despues movimiento lateral");
    assert_eq!(r.alerts[1].kind, AlertKind::LateralMovement);
    assert_eq!(r.blocked, vec![atacante.parse::<IpAddr>().unwrap()]);
    assert!(r.refused.is_empty());

    let anotadas = m.filter().blocked().unwrap();
    assert_eq!(anotadas.len(), 1);
    assert_eq!(anotadas[0].reason, BlockReason::LateralMovement);
    assert_eq!(
        anotadas[0].ttl,
        Some(Duration::from_secs(600)),
        "un bloqueo permanente por un barrido convierte una deteccion en una \
         interrupcion permanente"
    );
    assert_eq!(m.stats().blocked, 1);
}

#[test]
fn el_motor_nunca_bloquea_la_puerta_de_enlace_ni_a_los_excluidos() {
    let mut m = motor(true);
    let gw = m.guard().gateways().first().copied();

    let mut interacciones = vec![
        interaccion("203.0.113.50", DecoyKind::Ssh, 1),
        interaccion("203.0.113.50", DecoyKind::Rdp, 2),
    ];
    if let Some(g) = gw {
        interacciones.push(Interaction {
            peer: g,
            ..interaccion("198.51.100.1", DecoyKind::Ssh, 3)
        });
        interacciones.push(Interaction {
            peer: g,
            ..interaccion("198.51.100.1", DecoyKind::Rdp, 4)
        });
    }
    let r = m.ingest(interacciones, 4);

    assert!(r.blocked.is_empty(), "no se puede bloquear nada de esto");
    assert!(
        !r.refused.is_empty(),
        "y el rechazo se reporta, no se calla"
    );
    assert!(r
        .refused
        .iter()
        .any(|(_, motivo)| motivo.contains("exclusion")));
    if gw.is_some() {
        assert!(r
            .refused
            .iter()
            .any(|(_, motivo)| motivo.contains("incomunicada")));
    }
    assert_eq!(m.stats().blocked, 0);
    assert!(m.stats().refused > 0);
}

#[test]
fn en_modo_observacion_se_alerta_pero_no_se_corta() {
    let mut m = motor(false);
    let r = m.ingest(
        vec![
            interaccion("198.51.100.88", DecoyKind::Ssh, 1),
            interaccion("198.51.100.88", DecoyKind::Smb, 2),
        ],
        2,
    );
    assert_eq!(r.alerts.last().unwrap().kind, AlertKind::LateralMovement);
    assert!(
        r.alerts.last().unwrap().block,
        "la alerta sigue diciendo que ESTO merecia bloqueo"
    );
    assert!(r.blocked.is_empty(), "pero no se bloquea");
    assert_eq!(m.stats().blocked, 0);
}

#[test]
fn una_conexion_real_a_un_senuelo_recorre_el_motor_entero() {
    // De extremo a extremo con trafico de verdad. El origen es la propia
    // maquina, asi que la barandilla impide el bloqueo: es exactamente la
    // proteccion que se quiere y se comprueba aqui con trafico real.
    let mut m = motor(true);
    let activos = m.active();
    assert_eq!(activos.len(), 2);

    for (_, puerto) in &activos {
        let _ = TcpStream::connect((Ipv4Addr::LOCALHOST, *puerto)).unwrap();
    }

    let mut alertas = Vec::new();
    let mut rechazos = Vec::new();
    for _ in 0..10 {
        let r = m.tick(Duration::from_millis(200), 1_000);
        alertas.extend(r.alerts);
        rechazos.extend(r.refused);
        if alertas.len() >= 2 {
            break;
        }
    }

    assert!(!alertas.is_empty(), "el trafico real tiene que alertar");
    assert_eq!(alertas[0].peer, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(m.stats().interactions >= 2);
    assert_eq!(m.stats().blocked, 0, "no se bloquea a la propia maquina");
    assert!(
        rechazos.iter().any(|(_, r)| r.contains("propia maquina")),
        "y el motivo del rechazo se dice: {rechazos:?}"
    );
}

// ---------------------------------------------------------------------------
// Con el cortafuegos de verdad
// ---------------------------------------------------------------------------

#[test]
fn el_bloqueo_llega_al_cortafuegos_de_verdad() {
    let filtro = aegis_scal::linux::netfilter::NftablesFilter::new();
    if !filtro.available() {
        eprintln!("OMITIDA: nftables no esta disponible en esta maquina");
        return;
    }
    filtro.flush().unwrap();

    let mut m = DeceptionEngine::start(
        DeceptionConfig {
            decoys: DecoyConfig {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                services: Vec::new(), // no hacen falta senuelos: se inyecta
                ..config_local(&[])
            },
            ..DeceptionConfig::default()
        },
        filtro,
    );

    // TEST-NET-2 (RFC 5737): jamas enrutada, no es la de esta maquina ni la de
    // su puerta de enlace.
    let atacante: IpAddr = "198.51.100.123".parse().unwrap();
    let r = m.ingest(
        vec![
            Interaction {
                peer: atacante,
                ..interaccion("198.51.100.123", DecoyKind::Ssh, 1)
            },
            Interaction {
                peer: atacante,
                ..interaccion("198.51.100.123", DecoyKind::Smb, 2)
            },
        ],
        2,
    );
    assert_eq!(r.blocked, vec![atacante]);

    let vigentes = m.filter().blocked().unwrap();
    assert!(
        vigentes.iter().any(|b| b.addr == atacante),
        "la direccion tiene que estar en nftables: {vigentes:?}"
    );
    assert_eq!(
        vigentes.iter().find(|b| b.addr == atacante).unwrap().reason,
        BlockReason::LateralMovement
    );

    m.filter().flush().unwrap();
    assert!(m.filter().blocked().unwrap().is_empty());
}

#[test]
fn el_senuelo_escucha_donde_se_le_dice() {
    // Ligarse a 0.0.0.0 en una maquina compartida seria exponer los senuelos a
    // toda la red sin pedirlo; la direccion es configuracion, no una constante.
    let net = DecoyNet::bind(DecoyConfig {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        services: vec![(DecoyKind::Vnc, 0)],
        ..config_local(&[])
    });
    let (_, puerto) = net.active()[0];
    let destino = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), puerto);
    assert!(TcpStream::connect(destino).is_ok());
}
