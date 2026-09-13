//! El plano de aplicacion: baja los veredictos al kernel y los engancha.
//!
//! # Que hace este modulo y que NO hace
//!
//! No decide nada. Decidir es de [`crate::decisor`], que es *sans-io* a
//! proposito para que cada caso se pueda probar sin privilegios. Aqui solo se
//! traduce una decision ya tomada a los bytes que el programa TC espera, y se
//! engancha el programa a una interfaz.
//!
//! # Por que los bytes se escriben a mano y no con un `transmute`
//!
//! El crate es `#![forbid(unsafe_code)]`, asi que no hay forma de reinterpretar
//! una estructura como bytes. Podria parecer una molestia; es una ventaja: el
//! serializado explicito deja el **contrato de ABI a la vista**, campo a campo y
//! con su relleno. Cuando alguien cambie el `struct` del lado C y se olvide de
//! este lado, lo que falla es una prueba de tamano, no un mapa que se lee torcido
//! en produccion.
//!
//! Los tamanos estan comprobados en el header con `AEGIS_BPF_STATIC_ASSERT` y
//! aqui con constantes que las pruebas contrastan.
//!
//! # Endianismo
//!
//! Los campos de los mapas se escriben en el orden NATIVO de la maquina, porque
//! productor y consumidor son el mismo equipo. Las direcciones IP, en cambio,
//! van en orden de RED, porque el programa las lee tal cual vienen del paquete.
//! Confundir las dos cosas hace que el veredicto se escriba en una clave que no
//! existe y que el corte no ocurra nunca, en silencio.

use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsFd;

use libbpf_rs::{MapCore, MapFlags, Object, ObjectBuilder};

use crate::error::ErrorIps;
use crate::modo::Modo;
use crate::protegidos::MotivoProteccion;
use crate::veredicto::{Accion, Flujo};

/// El bytecode, incrustado en el binario.
///
/// Se incrusta y no se lee de disco por la misma razon que el resto del agente:
/// un fichero que se lee en arranque es un fichero que alguien con permisos de
/// escritura puede sustituir — y aqui eso significaria decidir que se corta.
///
/// Sale de `OUT_DIR`, donde lo deja el script de construccion, y no del arbol de
/// `drivers/`: en la secuencia de `make ci` los pasos de Rust van ANTES que la
/// compilacion de los programas eBPF, asi que leer de `drivers/` fallaria en la
/// primera compilacion de un clon limpio.
const OBJETO: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/aegis_ips.bpf.o"));

/// Tamano de `struct aegis_ips_flujo` en el lado C.
pub const TAM_FLUJO: usize = 16;
/// Tamano de `struct aegis_ips_veredicto` en el lado C.
pub const TAM_VEREDICTO: usize = 32;
/// Tamano de `struct aegis_ips_protegido` en el lado C.
pub const TAM_PROTEGIDO: usize = 16;
/// Tamano de `struct aegis_ips_config` en el lado C.
pub const TAM_CONFIG: usize = 16;

/// `AEGIS_IPS_CFG_ENABLED`.
const CFG_HABILITADO: u32 = 0x0000_0001;
/// `AEGIS_IPS_VEREDICTO_PERMITIR`.
const VEREDICTO_PERMITIR: u32 = 0;
/// `AEGIS_IPS_VEREDICTO_CORTAR`.
const VEREDICTO_CORTAR: u32 = 1;

/// Indices de `enum aegis_ips_stat`.
const STAT_PAQUETES: u32 = 0;
const STAT_CORTADOS: u32 = 1;
const STAT_HABRIA_CORTADO: u32 = 2;
const STAT_PROTEGIDOS: u32 = 3;
const STAT_CACHE_ACIERTO: u32 = 4;
const STAT_CACHE_FALLO: u32 = 5;
const STAT_NO_CLASIFICADOS: u32 = 6;
const STAT_CADUCADOS: u32 = 7;
const STAT_MAX: u32 = 8;

/// Lo que el programa del kernel ha contado.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContadoresKernel {
    /// Paquetes vistos por el programa.
    pub paquetes: u64,
    /// Paquetes cortados de verdad.
    pub cortados: u64,
    /// Paquetes que se HABRIAN cortado y no se cortaron, por el modo.
    ///
    /// Es la cifra que un cliente mira antes de atreverse a activar el bloqueo.
    pub habria_cortado: u64,
    /// Veces que la lista de protegidos evito un corte.
    ///
    /// Si esto sube, el motor de decision se esta equivocando en algo grave.
    pub protegidos: u64,
    /// Aciertos de la cache de veredictos.
    ///
    /// Demuestra que bloquear no cuesta subir a userland por paquete: si la
    /// cache acierta, el corte lo resolvio el kernel solo.
    pub cache_acierto: u64,
    /// Fallos de la cache.
    pub cache_fallo: u64,
    /// Paquetes sin clave de flujo (IPv6, sin puertos, truncados).
    pub no_clasificados: u64,
    /// Veredictos encontrados pero ya caducados.
    pub caducados: u64,
}

/// El plano de aplicacion del IPS.
pub struct PlanoIps {
    obj: Object,
    enlaces: Vec<libbpf_rs::TcHook>,
}

impl std::fmt::Debug for PlanoIps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlanoIps")
            .field("enganches", &self.enlaces.len())
            .finish_non_exhaustive()
    }
}

fn err_mapa(mapa: &'static str, e: &libbpf_rs::Error) -> ErrorIps {
    ErrorIps::Mapa {
        mapa,
        detalle: e.to_string(),
    }
}

impl PlanoIps {
    /// Carga el programa y escribe la configuracion inicial.
    ///
    /// Cargar NO engancha: son operaciones distintas a proposito, porque cargar
    /// es inocuo y enganchar afecta al trafico de una interfaz real.
    pub fn cargar(modo: Modo, habilitado: bool) -> Result<PlanoIps, ErrorIps> {
        let mut constructor = ObjectBuilder::default();
        let abierto = constructor
            .open_memory(OBJETO)
            .map_err(|e| ErrorIps::Carga {
                programa: "aegis_ips",
                detalle: e.to_string(),
            })?;
        let obj = abierto.load().map_err(|e| ErrorIps::Carga {
            programa: "aegis_ips",
            detalle: e.to_string(),
        })?;

        let plano = PlanoIps {
            obj,
            enlaces: Vec::new(),
        };
        plano.configurar(modo, habilitado)?;
        Ok(plano)
    }

    fn mapa(&self, nombre: &'static str) -> Result<libbpf_rs::Map<'_>, ErrorIps> {
        self.obj
            .maps()
            .find(|m| m.name() == OsStr::new(nombre))
            .ok_or(ErrorIps::MapaAusente(nombre))
    }

    /// Escribe el modo y el interruptor general.
    ///
    /// El modo lo comprueba el KERNEL antes de cortar: ver la doctrina de
    /// [`crate::modo`]. Escribirlo aqui es lo que hace que «modo aprendizaje»
    /// sea una promesa sostenible y no una intencion de userland.
    pub fn configurar(&self, modo: Modo, habilitado: bool) -> Result<(), ErrorIps> {
        let flags: u32 = if habilitado { CFG_HABILITADO } else { 0 };
        let mut bytes = Vec::with_capacity(TAM_CONFIG);
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&modo.codigo().to_ne_bytes());
        bytes.extend_from_slice(&0u64.to_ne_bytes()); // reservado
        debug_assert_eq!(bytes.len(), TAM_CONFIG);

        self.mapa("aegis_ips_config")?
            .update(&0u32.to_ne_bytes(), &bytes, MapFlags::ANY)
            .map_err(|e| err_mapa("aegis_ips_config", &e))
    }

    /// Engancha el programa a una interfaz, en ingreso Y en egreso.
    ///
    /// Los dos, siempre. Enganchar solo el ingreso dejaria pasar la baliza al
    /// C2, la exfiltracion y el movimiento lateral, que es justo el trafico que
    /// confirma que la maquina ya esta comprometida.
    pub fn enganchar(&mut self, interfaz: &str) -> Result<(), ErrorIps> {
        let ifindex = indice_de_interfaz(interfaz)?;

        for (nombre, punto, gancho) in [
            ("aegis_ips_ingreso", libbpf_rs::TC_INGRESS, "ingreso"),
            ("aegis_ips_egreso", libbpf_rs::TC_EGRESS, "egreso"),
        ] {
            let prog = self
                .obj
                .progs()
                .find(|p| p.name() == OsStr::new(nombre))
                .ok_or(ErrorIps::MapaAusente(nombre))?;

            let mut constructor = libbpf_rs::TcHookBuilder::new(prog.as_fd());
            constructor
                .ifindex(ifindex)
                .replace(true)
                .handle(1)
                .priority(1);
            let mut hook = constructor.hook(punto);

            // `create` monta el qdisc clsact si no estaba. Es idempotente y hay
            // que llamarlo una vez por interfaz; llamarlo por gancho es
            // inofensivo y evita depender del orden.
            if let Err(e) = hook.create() {
                // EEXIST significa que el qdisc ya estaba, que es lo normal
                // cuando se engancha el segundo gancho de la misma interfaz.
                if e.kind() != libbpf_rs::ErrorKind::AlreadyExists {
                    return Err(ErrorIps::Enganche {
                        programa: nombre,
                        interfaz: interfaz.to_string(),
                        gancho,
                        detalle: format!("no se pudo crear el qdisc clsact: {e}"),
                    });
                }
            }

            let enlace = hook.attach().map_err(|e| ErrorIps::Enganche {
                programa: nombre,
                interfaz: interfaz.to_string(),
                gancho,
                detalle: e.to_string(),
            })?;
            self.enlaces.push(enlace);
        }
        Ok(())
    }

    /// Serializa una clave de flujo con el mismo criterio que el programa.
    ///
    /// El criterio tiene que ser EL MISMO a los dos lados. Si no lo fuera, el
    /// veredicto se escribiria en una clave que el kernel nunca busca y el corte
    /// no ocurriria jamas, sin ningun error visible.
    fn clave(flujo: &Flujo) -> Result<Vec<u8>, ErrorIps> {
        let (IpAddr::V4(a), IpAddr::V4(b)) = (flujo.ip_a, flujo.ip_b) else {
            return Err(ErrorIps::SoloIpv4(format!(
                "{}:{} <-> {}:{}",
                flujo.ip_a, flujo.puerto_a, flujo.ip_b, flujo.puerto_b
            )));
        };
        // El programa compara `__u32` leidos del paquete, es decir en orden de
        // RED. Aqui se reproduce exactamente eso.
        let (ip_a, pto_a, ip_b, pto_b) = ordenar(a, flujo.puerto_a, b, flujo.puerto_b);

        let mut clave = Vec::with_capacity(TAM_FLUJO);
        clave.extend_from_slice(&ip_a);
        clave.extend_from_slice(&ip_b);
        clave.extend_from_slice(&pto_a.to_ne_bytes());
        clave.extend_from_slice(&pto_b.to_ne_bytes());
        clave.push(flujo.protocolo);
        clave.extend_from_slice(&[0u8; 3]); // relleno
        debug_assert_eq!(clave.len(), TAM_FLUJO);
        Ok(clave)
    }

    /// Baja un veredicto al kernel.
    ///
    /// `vigencia_ns` es la duracion, no un instante: el instante de caducidad lo
    /// calcula este metodo contra el reloj monotonico del sistema, que es la
    /// base que usa el programa. Pasar un instante calculado con otro reloj es
    /// como un bloqueo acaba caducando en el ano que viene o hace un rato.
    pub fn escribir_veredicto(
        &self,
        flujo: &Flujo,
        accion: Accion,
        motivo: u32,
        regla: u64,
        vigencia_ns: u64,
    ) -> Result<(), ErrorIps> {
        let clave = Self::clave(flujo)?;
        let until_ns = if vigencia_ns == 0 {
            0
        } else {
            aegis_net::xdp::boottime_ns().saturating_add(vigencia_ns)
        };
        let veredicto = match accion {
            Accion::Cortar => VEREDICTO_CORTAR,
            Accion::Alertar => VEREDICTO_PERMITIR,
        };

        let mut valor = Vec::with_capacity(TAM_VEREDICTO);
        valor.extend_from_slice(&until_ns.to_ne_bytes());
        valor.extend_from_slice(&0u64.to_ne_bytes()); // hits, lo lleva el kernel
        valor.extend_from_slice(&veredicto.to_ne_bytes());
        valor.extend_from_slice(&motivo.to_ne_bytes());
        valor.extend_from_slice(&regla.to_ne_bytes());
        debug_assert_eq!(valor.len(), TAM_VEREDICTO);

        self.mapa("aegis_ips_veredictos")?
            .update(&clave, &valor, MapFlags::ANY)
            .map_err(|e| err_mapa("aegis_ips_veredictos", &e))
    }

    /// Aplica un veredicto ya decidido.
    ///
    /// Solo baja al kernel lo que de verdad hay que cortar. Escribir tambien los
    /// «permitir» llenaria la cache de entradas que no hacen nada y expulsaria,
    /// por presion de LRU, justo los cortes que si importan.
    pub fn aplicar(
        &self,
        veredicto: &crate::veredicto::Veredicto,
        motivo: u32,
        vigencia_ns: u64,
    ) -> Result<bool, ErrorIps> {
        if veredicto.accion != Accion::Cortar {
            return Ok(false);
        }
        self.escribir_veredicto(
            &veredicto.flujo,
            Accion::Cortar,
            motivo,
            veredicto.regla,
            vigencia_ns,
        )?;
        Ok(true)
    }

    /// Baja al kernel la lista entera de protegidos.
    ///
    /// Las direcciones IPv6 se saltan y se CUENTAN en el valor devuelto, en vez
    /// de fallar la sincronizacion entera o —peor— pasar en silencio: creer que
    /// un activo esta protegido abajo cuando no lo esta es justo la clase de
    /// error que esta lista existe para no cometer.
    pub fn sincronizar_protegidos(
        &self,
        protegidos: &crate::protegidos::Protegidos,
    ) -> Result<(usize, usize), ErrorIps> {
        let mut bajados = 0usize;
        let mut omitidos_ipv6 = 0usize;
        for (ip, motivo) in protegidos.iter() {
            match ip {
                IpAddr::V4(v4) => {
                    self.proteger(*v4, *motivo)?;
                    bajados += 1;
                }
                IpAddr::V6(_) => omitidos_ipv6 += 1,
            }
        }
        Ok((bajados, omitidos_ipv6))
    }

    /// Retira el veredicto de un flujo.
    pub fn retirar_veredicto(&self, flujo: &Flujo) -> Result<(), ErrorIps> {
        let clave = Self::clave(flujo)?;
        match self.mapa("aegis_ips_veredictos")?.delete(&clave) {
            Ok(()) => Ok(()),
            // Que no estuviera no es un fallo: retirar algo que ya no esta es
            // el resultado que se buscaba.
            Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(err_mapa("aegis_ips_veredictos", &e)),
        }
    }

    /// Cuantos paquetes lleva cortados un veredicto, si sigue en el mapa.
    pub fn hits(&self, flujo: &Flujo) -> Result<Option<u64>, ErrorIps> {
        let clave = Self::clave(flujo)?;
        let valor = self
            .mapa("aegis_ips_veredictos")?
            .lookup(&clave, MapFlags::ANY)
            .map_err(|e| err_mapa("aegis_ips_veredictos", &e))?;
        Ok(valor.and_then(|v| leer_u64(&v, 8)))
    }

    /// Baja una direccion protegida al kernel.
    ///
    /// La comprobacion se hace aqui arriba Y abajo: una salvaguarda que depende
    /// de que el codigo de decision este bien no protege del caso que importa.
    pub fn proteger(&self, ip: Ipv4Addr, motivo: MotivoProteccion) -> Result<(), ErrorIps> {
        let mut valor = Vec::with_capacity(TAM_PROTEGIDO);
        valor.extend_from_slice(&0u64.to_ne_bytes()); // salvadas, lo lleva el kernel
        valor.extend_from_slice(&motivo.numero().to_ne_bytes());
        valor.extend_from_slice(&0u32.to_ne_bytes()); // relleno
        debug_assert_eq!(valor.len(), TAM_PROTEGIDO);

        self.mapa("aegis_ips_protegidos")?
            .update(&ip.octets(), &valor, MapFlags::ANY)
            .map_err(|e| err_mapa("aegis_ips_protegidos", &e))
    }

    /// Retira una proteccion.
    pub fn desproteger(&self, ip: Ipv4Addr) -> Result<(), ErrorIps> {
        match self.mapa("aegis_ips_protegidos")?.delete(&ip.octets()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == libbpf_rs::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(err_mapa("aegis_ips_protegidos", &e)),
        }
    }

    /// Cuantas veces una entrada protegida ha evitado un corte.
    pub fn salvadas(&self, ip: Ipv4Addr) -> Result<Option<u64>, ErrorIps> {
        let valor = self
            .mapa("aegis_ips_protegidos")?
            .lookup(&ip.octets(), MapFlags::ANY)
            .map_err(|e| err_mapa("aegis_ips_protegidos", &e))?;
        Ok(valor.and_then(|v| leer_u64(&v, 0)))
    }

    /// Lee los contadores del kernel, sumando todas las CPU.
    pub fn contadores(&self) -> Result<ContadoresKernel, ErrorIps> {
        let mapa = self.mapa("aegis_ips_stats")?;
        let mut valores = [0u64; STAT_MAX as usize];
        for (i, ranura) in valores.iter_mut().enumerate() {
            let por_cpu = mapa
                .lookup_percpu(&(i as u32).to_ne_bytes(), MapFlags::ANY)
                .map_err(|e| err_mapa("aegis_ips_stats", &e))?;
            let Some(por_cpu) = por_cpu else { continue };
            // El mapa es PERCPU: cada CPU lleva su propia cuenta y el total es
            // la suma. Leer solo la CPU cero daria una cifra que parece correcta
            // y que en una maquina con carga es una fraccion de la real.
            *ranura = por_cpu
                .iter()
                .filter_map(|c| leer_u64(c, 0))
                .fold(0u64, u64::saturating_add);
        }
        Ok(ContadoresKernel {
            paquetes: valores[STAT_PAQUETES as usize],
            cortados: valores[STAT_CORTADOS as usize],
            habria_cortado: valores[STAT_HABRIA_CORTADO as usize],
            protegidos: valores[STAT_PROTEGIDOS as usize],
            cache_acierto: valores[STAT_CACHE_ACIERTO as usize],
            cache_fallo: valores[STAT_CACHE_FALLO as usize],
            no_clasificados: valores[STAT_NO_CLASIFICADOS as usize],
            caducados: valores[STAT_CADUCADOS as usize],
        })
    }

    /// Ejecuta el programa contra una trama sintetica, SIN engancharlo.
    ///
    /// Es la forma correcta de probar un clasificador: generar trafico real
    /// depende del entorno y arriesga la conectividad de la maquina, mientras
    /// que esto ejercita el MISMO codigo de kernel de forma determinista.
    ///
    /// Devuelve el codigo de accion de TC: 0 es dejar pasar, 2 es cortar.
    pub fn probar_paquete(&mut self, egreso: bool, trama: &[u8]) -> Result<u32, ErrorIps> {
        let nombre = if egreso {
            "aegis_ips_egreso"
        } else {
            "aegis_ips_ingreso"
        };

        // El kernel exige al menos una cabecera Ethernet para ejecutar un
        // programa de tipo sched_cls, y un buffer de salida donde escribir.
        let mut entrada = trama.to_vec();
        if entrada.len() < 14 {
            entrada.resize(14, 0);
        }
        let mut salida = vec![0u8; entrada.len().max(128)];

        let prog = self
            .obj
            .progs_mut()
            .find(|p| p.name() == OsStr::new(nombre))
            .ok_or(ErrorIps::MapaAusente(nombre))?;

        let resultado = prog
            .test_run(libbpf_rs::ProgramInput {
                data_in: Some(&entrada),
                data_out: Some(&mut salida),
                ..Default::default()
            })
            .map_err(|e| ErrorIps::Carga {
                programa: "aegis_ips",
                detalle: format!("no se pudo ejecutar la prueba: {e}"),
            })?;
        Ok(resultado.return_value)
    }
}

/// Ordena los dos extremos con el mismo criterio que el programa eBPF.
fn ordenar(a: Ipv4Addr, pa: u16, b: Ipv4Addr, pb: u16) -> ([u8; 4], u16, [u8; 4], u16) {
    let (oa, ob) = (a.octets(), b.octets());
    // El programa compara los `__u32` tal y como los lee del paquete, es decir
    // en orden de red. `u32::from_be_bytes` reproduce ese mismo valor.
    let (na, nb) = (u32::from_be_bytes(oa), u32::from_be_bytes(ob));
    if na < nb || (na == nb && pa <= pb) {
        (oa, pa, ob, pb)
    } else {
        (ob, pb, oa, pa)
    }
}

/// Lee un `u64` nativo de un desplazamiento, sin `unsafe` y sin panico.
fn leer_u64(bytes: &[u8], desde: usize) -> Option<u64> {
    let trozo = bytes.get(desde..desde + 8)?;
    let arr: [u8; 8] = trozo.try_into().ok()?;
    Some(u64::from_ne_bytes(arr))
}

/// Traduce un nombre de interfaz a su indice.
///
/// Se delega en `aegis-net`, que ya tiene la llamada a libc auditada. Repetirla
/// aqui obligaria a meter `unsafe` en un crate que es `#![forbid(unsafe_code)]`
/// y dejaria dos copias de lo mismo que revisar.
fn indice_de_interfaz(nombre: &str) -> Result<i32, ErrorIps> {
    let idx = aegis_net::xdp::if_nametoindex(nombre).map_err(|e| ErrorIps::Enganche {
        programa: "aegis_ips",
        interfaz: nombre.to_string(),
        gancho: "-",
        detalle: e.to_string(),
    })?;
    i32::try_from(idx).map_err(|_| ErrorIps::Enganche {
        programa: "aegis_ips",
        interfaz: nombre.to_string(),
        gancho: "-",
        detalle: "indice de interfaz fuera de rango".to_string(),
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// LOS TAMANOS SON UN CONTRATO con el header de C, comprobado alli con
    /// `AEGIS_BPF_STATIC_ASSERT`. Si alguien cambia un lado y no el otro, el
    /// mapa se escribe torcido y el corte no ocurre nunca, en silencio.
    #[test]
    fn los_tamanos_de_abi_son_los_declarados() {
        assert_eq!(TAM_FLUJO, 16);
        assert_eq!(TAM_VEREDICTO, 32);
        assert_eq!(TAM_PROTEGIDO, 16);
        assert_eq!(TAM_CONFIG, 16);
    }

    /// La clave serializada mide exactamente lo que el mapa espera.
    #[test]
    fn la_clave_de_flujo_mide_lo_que_debe() {
        let f = Flujo::normalizado(
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50_000),
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
            6,
        );
        let clave = PlanoIps::clave(&f).unwrap();
        assert_eq!(clave.len(), TAM_FLUJO);
    }

    /// LOS DOS SENTIDOS DAN LA MISMA CLAVE. Si no, un veredicto escrito viendo
    /// la ida no cortaria la vuelta y el corte seria a medias sin decirlo.
    #[test]
    fn los_dos_sentidos_serializan_a_la_misma_clave() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 9));
        let ida = Flujo::normalizado((a, 50_000), (b, 443), 6);
        let vuelta = Flujo::normalizado((b, 443), (a, 50_000), 6);
        assert_eq!(
            PlanoIps::clave(&ida).unwrap(),
            PlanoIps::clave(&vuelta).unwrap()
        );
    }

    /// El orden se decide en orden de RED, igual que el programa. Con orden de
    /// host, `10.0.0.1` y `1.0.0.10` se ordenarian al reves en una maquina
    /// little-endian y la clave no coincidiria con la que busca el kernel.
    #[test]
    fn el_orden_se_hace_en_orden_de_red_como_el_programa() {
        let (ip_a, _, ip_b, _) =
            ordenar(Ipv4Addr::new(10, 0, 0, 1), 1, Ipv4Addr::new(2, 0, 0, 1), 2);
        assert_eq!(ip_a, [2, 0, 0, 1], "gana el menor EN ORDEN DE RED");
        assert_eq!(ip_b, [10, 0, 0, 1]);
    }

    /// Un flujo IPv6 no se puede bajar a este plano de datos, y se DICE con un
    /// error propio en vez de fallar en silencio: creer que un flujo quedo
    /// cubierto cuando no lo esta es peor que saber que no lo esta.
    #[test]
    fn un_flujo_ipv6_se_rechaza_diciendo_por_que() {
        let f = Flujo::normalizado(
            ("2001:db8::1".parse().unwrap(), 1),
            ("2001:db8::2".parse().unwrap(), 2),
            6,
        );
        let e = PlanoIps::clave(&f).unwrap_err();
        assert!(matches!(e, ErrorIps::SoloIpv4(_)), "{e}");
        assert!(e.to_string().contains("IPv4"), "{e}");
    }

    #[test]
    fn leer_un_u64_fuera_de_rango_no_provoca_panico() {
        assert_eq!(leer_u64(&[1, 2, 3], 0), None);
        assert_eq!(leer_u64(&[0u8; 8], 4), None);
        assert_eq!(leer_u64(&[0u8; 16], 8), Some(0));
    }
}
