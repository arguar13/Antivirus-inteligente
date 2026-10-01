//! Cuarentena de enjambre contra el kernel REAL (FASE 44).
//!
//! Comprueba que la orden que baja del plano de control acaba en una regla del
//! kernel que descarta paquetes de verdad. Se usa `BPF_PROG_TEST_RUN`, que
//! ejecuta el programa XDP cargado contra tramas fabricadas: es la unica forma
//! determinista de comprobarlo. Generar trafico real depende del entorno, no es
//! reproducible, y arriesga la conectividad de la maquina donde corre el CI.
//!
//! Si no hay privilegios, se salta con aviso. Una prueba que falla por el
//! entorno ensena al equipo a ignorar el rojo del CI.

#![cfg(all(target_os = "linux", feature = "xdp"))]

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use aegis_net::packet::PacketBuilder;
use aegis_net::segmentacion::{analizar_lista, BloqueoEntrante, BloqueoSaliente, Segmentador};
use aegis_net::xdp::{XdpAction, XdpConfig, XdpFilter};
use aegis_net::NetError;
use aegis_prueba::{omitir, Requisito};

/// El filtro XDP real, como capa de entrada del segmentador.
struct EntradaXdp<'a>(&'a XdpFilter);

impl BloqueoEntrante for EntradaXdp<'_> {
    fn bloquear(&self, addr: Ipv4Addr, ttl: Option<Duration>) -> Result<(), String> {
        self.0
            .block(addr, ttl, aegis_net::xdp::BlockReason::Manual)
            .map_err(|e| e.to_string())
    }
    fn desbloquear(&self, addr: Ipv4Addr) -> Result<(), String> {
        self.0.unblock(addr).map_err(|e| e.to_string())
    }
}

/// Capa de salida que solo anota. La de verdad es nftables, y su
/// comportamiento se prueba en `aegis-scal`; lo que se ejercita AQUI es que la
/// orden del plano de control llegue hasta el kernel por la capa de entrada.
#[derive(Default)]
struct SalidaAnotada(std::cell::RefCell<Vec<IpAddr>>);

impl BloqueoSaliente for SalidaAnotada {
    fn bloquear(&self, addr: IpAddr, _ttl: Option<Duration>) -> Result<(), String> {
        self.0.borrow_mut().push(addr);
        Ok(())
    }
    fn desbloquear(&self, addr: IpAddr) -> Result<(), String> {
        self.0.borrow_mut().retain(|x| *x != addr);
        Ok(())
    }
}

fn cargar() -> Option<XdpFilter> {
    match XdpFilter::load(&XdpConfig::default()) {
        Ok(f) => Some(f),
        Err(NetError::InsufficientPrivileges) => {
            omitir("hacen falta CAP_BPF y CAP_NET_ADMIN", Requisito::Root);
            None
        }
        Err(e) => panic!("no se pudo cargar el filtro XDP: {e}"),
    }
}

/// Trama que simula un paquete VENIDO de la maquina comprometida.
fn desde(origen: Ipv4Addr) -> Vec<u8> {
    PacketBuilder::tcp_syn(origen, Ipv4Addr::new(10, 0, 0, 99), 44444, 445)
}

#[test]
fn la_orden_del_plano_de_control_acaba_descartando_paquetes_reales() {
    let Some(filtro) = cargar() else { return };
    let comprometida = Ipv4Addr::new(10, 0, 0, 5);
    let sana = Ipv4Addr::new(10, 0, 0, 6);

    // Antes de la orden, la maquina comprometida habla con nosotros con
    // normalidad: es el estado del que se parte en un incidente real.
    let mut f = filtro;
    assert_eq!(
        f.test_packet(&desde(comprometida)).unwrap(),
        XdpAction::Pass
    );

    // El plano de control ordena la cuarentena. Llega como texto en el empuje,
    // exactamente igual que por el cable.
    let (direcciones, invalidas) = analizar_lista("10.0.0.5");
    assert_eq!(invalidas, 0);

    let salida = SalidaAnotada::default();
    {
        let entrada = EntradaXdp(&f);
        let mut seg = Segmentador::nuevo(entrada, &salida);
        let r = seg.reconciliar(&direcciones, None);
        assert_eq!(r.anadidas, vec![IpAddr::V4(comprometida)]);
        assert!(
            r.completa(),
            "la cuarentena tiene que quedar en los dos sentidos"
        );
    }

    // Y el kernel descarta sus paquetes.
    assert_eq!(
        f.test_packet(&desde(comprometida)).unwrap(),
        XdpAction::Drop,
        "el kernel deberia estar descartando los paquetes de la maquina aislada"
    );
    // Sin tocar a las demas: una cuarentena que aisla de mas es una caida de
    // servicio provocada por el propio EDR.
    assert_eq!(
        f.test_packet(&desde(sana)).unwrap(),
        XdpAction::Pass,
        "una maquina sana no puede quedar aislada de rebote"
    );
    // Y la capa de salida recibio la misma direccion: sin ella, la maquina
    // comprometida no puede hablarnos pero nosotros si podriamos hablarle.
    assert_eq!(*salida.0.borrow(), vec![IpAddr::V4(comprometida)]);
}

#[test]
fn levantar_la_cuarentena_le_devuelve_la_red_a_la_maquina() {
    let Some(mut f) = cargar() else { return };
    let maquina = Ipv4Addr::new(10, 0, 0, 7);
    let salida = SalidaAnotada::default();

    // `test_packet` necesita `&mut`, asi que el segmentador se usa en tramos
    // acotados: la alternativa seria mantenerlo vivo y no poder inspeccionar el
    // kernel entre paso y paso, que es justo lo que la prueba quiere hacer.
    {
        let mut seg = Segmentador::nuevo(EntradaXdp(&f), &salida);
        seg.reconciliar(&[IpAddr::V4(maquina)], None);
    }
    assert_eq!(f.test_packet(&desde(maquina)).unwrap(), XdpAction::Drop);

    {
        // El plano de control envia el conjunto vacio: no queda ninguna.
        let mut seg = Segmentador::nuevo(EntradaXdp(&f), &salida);
        // El segmentador es nuevo, asi que no cree tener nada aplicado. Se le
        // ensena el estado actual reconciliando primero contra el, igual que
        // hace un agente que acaba de arrancar y lee la lista del kernel.
        seg.reconciliar(&[IpAddr::V4(maquina)], None);
        let r = seg.reconciliar(&[], None);
        assert_eq!(r.retiradas, vec![IpAddr::V4(maquina)]);
    }

    assert_eq!(
        f.test_packet(&desde(maquina)).unwrap(),
        XdpAction::Pass,
        "al levantar la cuarentena la maquina tiene que recuperar la red"
    );
    assert!(salida.0.borrow().is_empty());
}

#[test]
fn una_cuarentena_con_caducidad_deja_de_aplicarse_sola() {
    // Una cuarentena permanente que nadie revisa acaba siendo una regla de
    // firewall fantasma: en tres meses alguien reinstala esa maquina y no
    // entiende por que no tiene red. El plazo lo aplica el propio kernel.
    let Some(mut f) = cargar() else { return };
    let maquina = Ipv4Addr::new(10, 0, 0, 8);
    let salida = SalidaAnotada::default();

    {
        let entrada = EntradaXdp(&f);
        let mut seg = Segmentador::nuevo(entrada, &salida);
        seg.reconciliar(&[IpAddr::V4(maquina)], Some(Duration::from_millis(300)));
    }
    assert_eq!(f.test_packet(&desde(maquina)).unwrap(), XdpAction::Drop);

    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(
        f.test_packet(&desde(maquina)).unwrap(),
        XdpAction::Pass,
        "pasado el plazo, el kernel tiene que dejar de descartar"
    );
}

#[test]
fn reconciliar_dos_veces_no_reescribe_el_kernel() {
    // El plano de control reenvia el conjunto completo en cada empuje. Si cada
    // uno reaplicara todo, diez mil endpoints pagarian una escritura al kernel
    // por cada latido del canal.
    let Some(f) = cargar() else { return };
    let salida = SalidaAnotada::default();
    let entrada = EntradaXdp(&f);
    let mut seg = Segmentador::nuevo(entrada, &salida);

    let orden = [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))];
    assert_eq!(seg.reconciliar(&orden, None).anadidas.len(), 1);
    let segunda = seg.reconciliar(&orden, None);
    assert!(segunda.anadidas.is_empty());
    assert!(segunda.retiradas.is_empty());
}
