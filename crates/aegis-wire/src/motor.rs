//! El motor: una maquina de estados **sin entrada/salida**.
//!
//! # Sans-io, y por que eso es lo que hace verificable la fase
//!
//! Este tipo no abre sockets, no toca la NIC y no tiene reloj propio: el tiempo
//! entra como parametro. Se le dan bytes de un paquete y devuelve **hechos**.
//!
//! La consecuencia practica es la que importa: **cada ataque de esta fase se
//! construye entero en una prueba**. La evasion por solape de segmentos, el
//! bucle de punteros DNS, la cadena interminable de cabeceras IPv6, el
//! contrabando de peticiones HTTP — todos se ejercen de verdad, sin red, sin
//! privilegios y sin condiciones de carrera. Si el motor abriera el socket, cada
//! uno de esos seria «no se puede ejercitar aqui», y la fase entera se quedaria
//! en una declaracion de intenciones.
//!
//! # La identificacion del protocolo va por CONTENIDO, no por puerto
//!
//! Es la decision que mas cambia lo que el sensor ve. Identificar por puerto es
//! comodo y falla exactamente donde importa: el malware pone su C2 en el 443
//! precisamente porque todo el mundo asume que el 443 es TLS. Un sensor que
//! confie en el puerto disecara como TLS algo que no lo es, no reconocera nada,
//! y no dira nada.
//!
//! Aqui el puerto es **una pista de desempate**, nunca la respuesta. Primero se
//! mira el contenido; si el contenido no dice nada, se mira el puerto; y si
//! tampoco, el protocolo queda `Desconocido` — que es una respuesta honesta y,
//! en un puerto conocido, **una senal por si misma**.
//!
//! # El orden de trabajo
//!
//! 1. Capa 3 y 4: se saca la clave de flujo. Sin esto no hay contexto.
//! 2. Flujo: se recupera o se crea, con las cotas de la tabla.
//! 3. TCP: al reensamblador, que devuelve bytes **en orden**.
//! 4. Aplicacion: se identifica y se disecta.
//!
//! Nunca al reves. Disecar antes de reensamblar es, literalmente, el fallo que
//! hace posible la evasion por solape.

use std::net::{IpAddr, Ipv6Addr};

use aegis_net::packet::{EthHeader, Ipv4Header, TcpHeader, UdpHeader};

use crate::flujo::TablaFlujos;
use crate::hecho::{ClaveFlujo, Direccion, Hecho, HechoConContexto, ProtocoloApp, Transporte};
use crate::ipv6;
use crate::reensamblado::Politica;
use crate::registro::{Cierre, RegistroConexion};
use crate::{directorio, dns, http, smb, texto, tls, udp};

/// Bytes de un sentido que se acumulan antes de rendirse identificando.
///
/// Con menos de esto puede que aun no haya llegado la firma del protocolo; con
/// mucho mas, seguir intentandolo por cada paquete es trabajo tirado.
pub const BYTES_PARA_IDENTIFICAR: usize = 4096;

/// Tope de bytes de un sentido que se conservan para volver a intentar disecar.
pub const MAX_BUFER_APP: usize = 64 * 1024;

/// Tope de bytes en TODOS los bufers de aplicacion a la vez.
///
/// Misma razon que [`crate::flujo::MAX_MEMORIA`]: la cota por sentido multiplicada
/// por el numero de sentidos no es una cota, es un producto que el atacante
/// controla. Cuatro megas es la parte del presupuesto del agente que puede ir a
/// mensajes de aplicacion a medio construir.
pub const MAX_MEMORIA_APP: usize = 4 * 1024 * 1024;

/// Mensajes de aplicacion que se disecan de un mismo tramo de flujo.
///
/// Con reutilizacion de conexion caben varios mensajes seguidos en el mismo
/// tramo y hay que verlos todos. Pero el numero lo elige quien manda, asi que se
/// acota: treinta y dos cubre cualquier rafaga real y corta de raiz que un tramo
/// con miles de respuestas vacias monopolice el camino de paquete.
pub const MAX_MENSAJES_POR_TRAMO: usize = 32;

/// Configuracion del motor.
#[derive(Debug, Clone)]
pub struct ConfigMotor {
    /// Politica de reensamblado ante solapes.
    ///
    /// Se elige a proposito segun el sistema operativo que predomine en el
    /// segmento vigilado: imitar al destino es lo que cierra la evasion.
    pub politica: Politica,
    /// Tope de flujos simultaneos.
    pub max_flujos: usize,
    /// Tope de bytes retenidos por los reensamblados de todos los flujos.
    pub max_memoria: usize,
    /// Tope de bytes en todos los bufers de aplicacion.
    pub max_memoria_app: usize,
    /// Si se disecan los protocolos de aplicacion.
    ///
    /// Apagarlo deja solo los registros de conexion: util en un sensor de muy
    /// poca CPU, y es una decision que el cliente toma sabiendo lo que pierde.
    pub disecar_aplicacion: bool,
}

impl Default for ConfigMotor {
    fn default() -> ConfigMotor {
        ConfigMotor {
            politica: Politica::PrimeroGana,
            max_flujos: crate::flujo::MAX_FLUJOS,
            max_memoria: crate::flujo::MAX_MEMORIA,
            max_memoria_app: MAX_MEMORIA_APP,
            disecar_aplicacion: true,
        }
    }
}

/// Contadores del motor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContadoresMotor {
    /// Paquetes entregados al motor.
    pub paquetes: u64,
    /// Paquetes que no se pudieron analizar hasta la capa 4.
    pub paquetes_ilegibles: u64,
    /// Paquetes IPv6 descartados por una cadena de extensiones interminable.
    ///
    /// Se cuenta aparte porque **es una tecnica de evasion**, no un error: un
    /// numero que sube aqui significa que alguien esta intentando que el sensor
    /// se rinda.
    pub ipv6_cadena_excesiva: u64,
    /// Paquetes fragmentados, cuyo contenido esta incompleto por definicion.
    pub fragmentados: u64,
    /// Hechos emitidos.
    pub hechos: u64,
    /// Bufers de aplicacion soltados por llegar al techo global.
    ///
    /// Es un agujero de visibilidad medido: cada uno es un mensaje a medio
    /// construir que ya no se va a poder interpretar.
    pub bufers_soltados: u64,
}

/// El motor de diseccion.
pub struct Motor {
    config: ConfigMotor,
    tabla: TablaFlujos,
    contadores: ContadoresMotor,
    /// Buffer de aplicacion por flujo y sentido, para disecar sobre el mensaje
    /// completo y no sobre trozos sueltos.
    bufers: std::collections::BTreeMap<(ClaveFlujo, bool), Vec<u8>>,
    /// Bytes sumados de todos los bufers de aplicacion.
    bytes_app: usize,
    /// Ficheros en curso de transferencia, por flujo y sentido.
    ///
    /// Su coste es fijo por transferencia —ver [`crate::ficheros`]— asi que no
    /// entra en el techo de memoria de aplicacion: no crece con el tamano del
    /// fichero, solo con el numero de transferencias vivas, que ya esta acotado
    /// por el numero de flujos.
    transferencias: std::collections::BTreeMap<(ClaveFlujo, bool), Transferencia>,
}

/// Una transferencia de fichero en curso.
struct Transferencia {
    extractor: crate::ficheros::Extractor,
    /// Bytes que faltan segun la longitud declarada.
    restantes: Option<u64>,
}

/// Lo que se pudo hacer con un tramo del flujo de aplicacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Avance {
    /// Se entendio un mensaje completo que ocupaba estos bytes.
    Consumido(usize),
    /// Se abrio una transferencia: lo que venga ya no se acumula, atraviesa.
    CuerpoEnCurso,
    /// Todavia no hay un mensaje completo: se acumula y se espera.
    Incompleto,
}

/// Si entre los hechos hay alguno que signifique «este tramo se entendio».
///
/// [`Hecho::NoAnalizable`] NO cuenta: es justo lo que emite un mensaje que llego
/// a medias, y darlo por entendido tiraria el principio del mensaje —por ejemplo
/// un `ClientHello` partido entre dos paquetes— y con el, la unica oportunidad de
/// leerlo. [`Hecho::ProtocoloIdentificado`] tampoco: acompana a los demas y por
/// si solo no dice que el mensaje este completo.
fn hay_hecho_concluyente(hechos: &[Hecho]) -> bool {
    hechos.iter().any(|h| {
        !matches!(
            h,
            Hecho::NoAnalizable { .. } | Hecho::ProtocoloIdentificado(_)
        )
    })
}

/// Saca el nombre de fichero de una cabecera `Content-Disposition`.
///
/// Lo que salga de aqui es **lo que dice el emisor**, no una verdad: se usa para
/// contrastarlo con el contenido real, nunca para decidir nada.
fn nombre_de_disposicion(valor: &str) -> String {
    for parte in valor.split(';') {
        let parte = parte.trim();
        let Some((clave, v)) = parte.split_once('=') else {
            continue;
        };
        if !clave.trim().eq_ignore_ascii_case("filename") {
            continue;
        }
        let v = v.trim().trim_matches('"');
        // Un nombre con separadores de ruta es un intento de escritura fuera de
        // sitio: se queda solo el ultimo componente, y de los DOS separadores,
        // porque un agente en Windows sufre la barra invertida.
        let limpio = v.rsplit(['/', '\\']).next().unwrap_or(v);
        if !limpio.is_empty() {
            return limpio.to_string();
        }
    }
    String::new()
}

impl Motor {
    /// Un motor con la configuracion dada.
    #[must_use]
    pub fn nuevo(config: ConfigMotor) -> Motor {
        let tabla = TablaFlujos::con_topes(config.politica, config.max_flujos, config.max_memoria);
        Motor {
            config,
            tabla,
            contadores: ContadoresMotor::default(),
            bufers: std::collections::BTreeMap::new(),
            bytes_app: 0,
            transferencias: std::collections::BTreeMap::new(),
        }
    }

    /// Bytes reservados ahora mismo por el motor entero.
    ///
    /// Reensamblado mas bufers de aplicacion. Es la cifra que hay que comparar
    /// con el presupuesto del agente, y por eso se expone: una cota que no se
    /// puede medir desde fuera no se puede verificar.
    #[must_use]
    pub fn memoria(&self) -> usize {
        self.tabla.bytes_reservados() + self.bytes_app
    }

    /// Suelta lo que el motor tenga asociado a los flujos que la tabla expulso.
    ///
    /// Sin esto, expulsar un flujo dejaria su bufer de aplicacion vivo para
    /// siempre: una fuga, no un peor caso.
    fn soltar_expulsados(&mut self) {
        for k in self.tabla.drenar_expulsadas() {
            for sentido in [true, false] {
                if let Some(b) = self.bufers.remove(&(k, sentido)) {
                    self.bytes_app = self.bytes_app.saturating_sub(b.len());
                }
                // Y la transferencia en curso, por la misma razon: dejarla viva
                // seria la misma fuga con otro nombre.
                self.transferencias.remove(&(k, sentido));
            }
        }
    }

    /// Suelta bufers de aplicacion hasta volver por debajo del techo global.
    ///
    /// Se sueltan los MAS GRANDES primero: un bufer grande es el que esta mas
    /// cerca de su propia cota sin haber producido un mensaje completo, que es
    /// justo la forma de un mensaje interminable a proposito.
    fn aplicar_techo_app(&mut self) {
        while self.bytes_app > self.config.max_memoria_app {
            let victima = self
                .bufers
                .iter()
                .max_by_key(|(_, b)| b.len())
                .map(|(k, _)| *k);
            let Some(k) = victima else {
                break;
            };
            if let Some(b) = self.bufers.remove(&k) {
                self.bytes_app = self.bytes_app.saturating_sub(b.len());
                self.contadores.bufers_soltados += 1;
            }
        }
    }

    /// Contadores.
    #[must_use]
    pub fn contadores(&self) -> &ContadoresMotor {
        &self.contadores
    }

    /// Flujos vivos.
    #[must_use]
    pub fn flujos_vivos(&self) -> usize {
        self.tabla.vivos()
    }

    /// La tabla, para consultarla.
    #[must_use]
    pub fn tabla(&self) -> &TablaFlujos {
        &self.tabla
    }

    /// Entrega una trama Ethernet completa.
    pub fn alimentar_ethernet(&mut self, momento_us: u64, trama: &[u8]) -> Vec<HechoConContexto> {
        let Ok(eth) = EthHeader::parse(trama) else {
            self.contadores.paquetes += 1;
            self.contadores.paquetes_ilegibles += 1;
            return Vec::new();
        };
        let carga = &trama[aegis_net::packet::ETH_HDR_LEN.min(trama.len())..];
        match eth.ethertype {
            aegis_net::packet::ETHERTYPE_IPV4 | aegis_net::packet::ETHERTYPE_IPV6 => {
                self.alimentar_ip(momento_us, carga)
            }
            _ => {
                self.contadores.paquetes += 1;
                Vec::new()
            }
        }
    }

    /// Entrega un paquete IP (v4 o v6) sin cabecera de enlace.
    ///
    /// Es el embudo unico: [`Motor::alimentar_ethernet`] acaba aqui. Por eso el
    /// barrido de flujos expulsados se hace en este punto y solo en este punto.
    pub fn alimentar_ip(&mut self, momento_us: u64, paquete: &[u8]) -> Vec<HechoConContexto> {
        let salida = self.procesar_ip(momento_us, paquete);
        // Lo que la tabla expulso mientras se procesaba el paquete deja de
        // ocupar sitio AHORA, no cuando alguien se acuerde.
        self.soltar_expulsados();
        salida
    }

    fn procesar_ip(&mut self, momento_us: u64, paquete: &[u8]) -> Vec<HechoConContexto> {
        self.contadores.paquetes += 1;
        let Some(&primero) = paquete.first() else {
            self.contadores.paquetes_ilegibles += 1;
            return Vec::new();
        };

        match primero >> 4 {
            4 => self.alimentar_ipv4(momento_us, paquete),
            6 => self.alimentar_ipv6(momento_us, paquete),
            _ => {
                self.contadores.paquetes_ilegibles += 1;
                Vec::new()
            }
        }
    }

    fn alimentar_ipv4(&mut self, momento_us: u64, paquete: &[u8]) -> Vec<HechoConContexto> {
        let Ok(ip) = Ipv4Header::parse(paquete) else {
            self.contadores.paquetes_ilegibles += 1;
            return Vec::new();
        };
        // `header_len` ya viene validado contra el tamano del buffer por
        // `Ipv4Header::parse`, que rechaza IHL < 5 y cabeceras truncadas.
        let Some(carga) = paquete.get(ip.header_len..) else {
            self.contadores.paquetes_ilegibles += 1;
            return Vec::new();
        };
        // Un datagrama troceado lleva contenido incompleto por definicion: se
        // cuenta y su carga no se disecta, porque disecar media carga produce
        // hechos falsos. Hacen falta LAS DOS banderas: el primer fragmento
        // lleva desplazamiento cero y solo MF lo delata.
        let fragmentado = ip.is_fragment || ip.mas_fragmentos;
        if fragmentado {
            self.contadores.fragmentados += 1;
        }
        // Un fragmento posterior no lleva cabecera de transporte: leerlo como
        // TCP interpretaria carga util como puertos y numero de secuencia, e
        // inyectaria basura en el reensamblador. Se cuenta y se descarta.
        if ip.is_fragment {
            return Vec::new();
        }
        self.despachar_transporte(
            momento_us,
            IpAddr::V4(ip.src),
            IpAddr::V4(ip.dst),
            ip.protocol,
            carga,
            fragmentado,
        )
    }

    fn alimentar_ipv6(&mut self, momento_us: u64, paquete: &[u8]) -> Vec<HechoConContexto> {
        let c = match ipv6::analizar(paquete) {
            Ok(c) => c,
            Err(crate::error::ErrorDiseccion::AnidamientoExcesivo { .. }) => {
                // ES UNA TECNICA DE EVASION, no un error: alguien esta
                // intentando que el sensor se rinda. Se cuenta aparte.
                self.contadores.ipv6_cadena_excesiva += 1;
                self.contadores.paquetes_ilegibles += 1;
                return Vec::new();
            }
            Err(_) => {
                self.contadores.paquetes_ilegibles += 1;
                return Vec::new();
            }
        };
        if c.fragmentado {
            self.contadores.fragmentados += 1;
        }
        let Some(carga) = paquete.get(c.inicio_carga..) else {
            self.contadores.paquetes_ilegibles += 1;
            return Vec::new();
        };
        // Mismo motivo que en IPv4: un fragmento posterior no lleva cabecera de
        // transporte y leerlo como tal inyecta carga util en el reensamblador.
        if c.desplazamiento_fragmento != 0 {
            return Vec::new();
        }
        self.despachar_transporte(
            momento_us,
            IpAddr::V6(Ipv6Addr::from(c.origen)),
            IpAddr::V6(Ipv6Addr::from(c.destino)),
            c.transporte,
            carga,
            c.fragmentado,
        )
    }

    fn despachar_transporte(
        &mut self,
        momento_us: u64,
        origen: IpAddr,
        destino: IpAddr,
        protocolo: u8,
        carga: &[u8],
        fragmentado: bool,
    ) -> Vec<HechoConContexto> {
        match protocolo {
            aegis_net::packet::IPPROTO_TCP => {
                let Ok(tcp) = TcpHeader::parse(carga) else {
                    self.contadores.paquetes_ilegibles += 1;
                    return Vec::new();
                };
                // `header_len` ya viene en bytes y validado por `TcpHeader::parse`.
                let datos = carga.get(tcp.header_len..).unwrap_or(&[]);
                self.tcp(
                    momento_us,
                    (origen, tcp.src_port),
                    (destino, tcp.dst_port),
                    tcp.seq,
                    tcp.flags.0,
                    datos,
                    fragmentado,
                )
            }
            aegis_net::packet::IPPROTO_UDP => {
                let Ok(u) = UdpHeader::parse(carga) else {
                    self.contadores.paquetes_ilegibles += 1;
                    return Vec::new();
                };
                let datos = carga.get(aegis_net::packet::UDP_HDR_LEN..).unwrap_or(&[]);
                self.udp(
                    momento_us,
                    (origen, u.src_port),
                    (destino, u.dst_port),
                    datos,
                    fragmentado,
                )
            }
            _ => Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn tcp(
        &mut self,
        momento_us: u64,
        origen: (IpAddr, u16),
        destino: (IpAddr, u16),
        secuencia: u32,
        banderas: u8,
        datos: &[u8],
        fragmentado: bool,
    ) -> Vec<HechoConContexto> {
        use aegis_net::packet::TcpFlags;

        let (clave, invertida) = ClaveFlujo::normalizada(origen, destino, Transporte::Tcp);
        let desde_a = !invertida;
        let syn = banderas & TcpFlags::SYN != 0;
        let ack = banderas & TcpFlags::ACK != 0;
        let fin = banderas & TcpFlags::FIN != 0;
        let rst = banderas & TcpFlags::RST != 0;

        let disecar = self.config.disecar_aplicacion && !fragmentado;
        let (ordenados, direccion) = self.tabla.con_flujo(clave, momento_us, |f| {
            if desde_a {
                f.bytes_ab += datos.len() as u64;
                f.paquetes_ab += 1;
            } else {
                f.bytes_ba += datos.len() as u64;
                f.paquetes_ba += 1;
            }

            // EL SYN SIN ACK es lo unico que dice con certeza quien abrio. Con el
            // SYN+ACK se sabe lo contrario. Sin ninguno de los dos, no se sabe, y
            // eso se conserva como Indeterminada en vez de adivinarse.
            if syn && !ack {
                f.inicio_visto = true;
                f.cliente_es_a = desde_a;
            } else if syn && ack && !f.inicio_visto {
                f.inicio_visto = true;
                f.cliente_es_a = !desde_a;
            }

            let sentido = if desde_a {
                &mut f.sentido_ab
            } else {
                &mut f.sentido_ba
            };
            if syn {
                sentido.sincronizar(secuencia);
            }
            let ordenados = if datos.is_empty() {
                Vec::new()
            } else {
                sentido.incorporar(secuencia, datos)
            };
            if fin || rst {
                sentido.cerrar();
            }
            (ordenados, f.direccion_de(desde_a))
        });

        if !disecar || ordenados.is_empty() {
            return Vec::new();
        }
        self.aplicacion(
            clave, desde_a, direccion, momento_us, &ordenados, destino.1, origen.1,
        )
    }

    fn udp(
        &mut self,
        momento_us: u64,
        origen: (IpAddr, u16),
        destino: (IpAddr, u16),
        datos: &[u8],
        fragmentado: bool,
    ) -> Vec<HechoConContexto> {
        let (clave, invertida) = ClaveFlujo::normalizada(origen, destino, Transporte::Udp);
        let desde_a = !invertida;
        self.tabla.con_flujo(clave, momento_us, |f| {
            if desde_a {
                f.bytes_ab += datos.len() as u64;
                f.paquetes_ab += 1;
            } else {
                f.bytes_ba += datos.len() as u64;
                f.paquetes_ba += 1;
            }
            // En UDP el primer datagrama que se ve define el sentido: no hay
            // apreton de manos del que deducirlo.
            if !f.inicio_visto {
                f.inicio_visto = true;
                f.cliente_es_a = desde_a;
            }
        });
        if !self.config.disecar_aplicacion || fragmentado || datos.is_empty() {
            return Vec::new();
        }
        let direccion = self
            .tabla
            .obtener(&clave)
            .map_or(Direccion::Indeterminada, |f| f.direccion_de(desde_a));

        // Un datagrama es un mensaje completo: no se acumula nada.
        let hechos = self.disecar_udp(datos, destino.1, origen.1);
        self.envolver(clave, direccion, momento_us, hechos)
    }

    /// Acumula y disecta el flujo de aplicacion de un sentido TCP.
    #[allow(clippy::too_many_arguments)]
    fn aplicacion(
        &mut self,
        clave: ClaveFlujo,
        desde_a: bool,
        direccion: Direccion,
        momento_us: u64,
        nuevos: &[u8],
        puerto_destino: u16,
        puerto_origen: u16,
    ) -> Vec<HechoConContexto> {
        // SI HAY UN CUERPO EN CURSO, los bytes son del cuerpo y NO pasan por el
        // bufer de aplicacion: un fichero de doscientos megas no tiene por que
        // reservar nada, solo atravesar el extractor.
        let mut hechos_cuerpo = Vec::new();
        let mut resto = nuevos;
        if self.transferencias.contains_key(&(clave, desde_a)) {
            let (consumidos, cerrados) = self.alimentar_cuerpo(clave, desde_a, nuevos);
            hechos_cuerpo = cerrados;
            resto = &nuevos[consumidos.min(nuevos.len())..];
            if resto.is_empty() {
                return self.envolver(clave, direccion, momento_us, hechos_cuerpo);
            }
        }
        let nuevos = resto;

        let bufer = self.bufers.entry((clave, desde_a)).or_default();
        let antes = bufer.len();
        bufer.extend_from_slice(nuevos);
        // COTA POR SENTIDO: el buffer de aplicacion no puede crecer sin limite.
        // Se conserva la COLA y no la cabeza, porque en un protocolo de flujo lo
        // ultimo es lo que aun no se ha interpretado.
        if bufer.len() > MAX_BUFER_APP {
            let sobra = bufer.len() - MAX_BUFER_APP;
            bufer.drain(..sobra);
        }
        let despues = bufer.len();
        let datos = bufer.clone();
        if despues >= antes {
            self.bytes_app = self.bytes_app.saturating_add(despues - antes);
        } else {
            self.bytes_app = self.bytes_app.saturating_sub(antes - despues);
        }
        // COTA GLOBAL: la de arriba sola no acota nada, porque el numero de
        // sentidos lo elige el atacante.
        self.aplicar_techo_app();

        let del_cliente = direccion != Direccion::ServidorACliente;
        let mut hechos = hechos_cuerpo;

        // BUCLE DE MENSAJES, no un mensaje y ya. Con reutilizacion de conexion
        // —que es lo normal desde HTTP/1.1— en un mismo tramo de flujo caben
        // varias peticiones o respuestas seguidas. Quedarse con la primera
        // dejaria al sensor ciego para el resto de la sesion, que es justo lo
        // que busca quien encadena la descarga detras de algo inocente.
        let mut desde = 0usize;
        let mut acumular = true;
        for _ in 0..MAX_MENSAJES_POR_TRAMO {
            let tramo = &datos[desde.min(datos.len())..];
            if tramo.is_empty() {
                break;
            }
            let vistos = self.disecar_tcp(tramo, del_cliente, puerto_destino, puerto_origen);
            let (mas, avance) = self.consumir_mensaje(clave, desde_a, tramo, &vistos);
            hechos.extend(vistos);
            hechos.extend(mas);
            match avance {
                // PROGRESO ESTRICTO: una vuelta que no avanza para el bucle. Sin
                // esto, un mensaje de longitud cero seria un bucle infinito
                // servido por el atacante.
                Avance::Consumido(n) if n > 0 => desde += n,
                Avance::CuerpoEnCurso => {
                    acumular = false;
                    break;
                }
                _ => break,
            }
        }

        // EL BUFER SE QUEDA SOLO CON LO QUE NO SE ENTENDIO. Si se conservara lo
        // ya interpretado, el siguiente paquete volveria a disecar el mismo
        // mensaje y emitiria los mismos hechos otra vez —ruido que entierra lo
        // que si es nuevo— y ademas nunca se llegaria al mensaje siguiente,
        // porque el disector siempre empieza por el principio del bufer.
        let cola = if acumular {
            datos.get(desde.min(datos.len())..).unwrap_or(&[])
        } else {
            &[]
        };
        self.fijar_bufer(clave, desde_a, cola);

        // Si se reconocio el protocolo, se anota en el flujo para el registro.
        if let Some(p) = hechos.iter().find_map(|h| match h {
            Hecho::ProtocoloIdentificado(p) => Some(*p),
            _ => None,
        }) {
            self.tabla.con_flujo(clave, momento_us, |f| {
                // El primero que se reconoce manda: un flujo no cambia de
                // protocolo a mitad, y dejar que lo haga permitiria enmascarar
                // el protocolo real mandando basura de otro despues.
                if f.protocolo == ProtocoloApp::Desconocido {
                    f.protocolo = p;
                }
            });
        }

        self.envolver(clave, direccion, momento_us, hechos)
    }

    /// Entrega bytes al cuerpo en curso y lo cierra si ya esta completo.
    ///
    /// Devuelve cuantos bytes se comio el cuerpo y los hechos del cierre. Lo que
    /// sobra vuelve al camino normal: en HTTP con reutilizacion de conexion,
    /// detras de un cuerpo viene el siguiente mensaje, y perderlo dejaria ciego
    /// al sensor para todo el resto de la sesion.
    fn alimentar_cuerpo(
        &mut self,
        clave: ClaveFlujo,
        desde_a: bool,
        datos: &[u8],
    ) -> (usize, Vec<Hecho>) {
        let Some(t) = self.transferencias.get_mut(&(clave, desde_a)) else {
            return (0, Vec::new());
        };
        let cuanto = match t.restantes {
            Some(n) => (n as usize).min(datos.len()),
            None => datos.len(),
        };
        t.extractor.incorporar(&datos[..cuanto]);
        if let Some(n) = t.restantes {
            t.restantes = Some(n - cuanto as u64);
        }
        let terminado = t.restantes == Some(0);
        if !terminado {
            return (cuanto, Vec::new());
        }
        let Some(t) = self.transferencias.remove(&(clave, desde_a)) else {
            return (cuanto, Vec::new());
        };
        (cuanto, t.extractor.cerrar())
    }

    /// Decide que hacer con un tramo ya disecado: consumirlo, abrir una
    /// transferencia, o seguir esperando.
    ///
    /// # Por que hay que consumir y no solo disecar
    ///
    /// El disector siempre empieza por el principio del bufer. Si lo ya
    /// interpretado se queda ahi, cada paquete nuevo vuelve a producir los
    /// MISMOS hechos —ruido que entierra lo que si es nuevo— y ademas el segundo
    /// mensaje de una conexion reutilizada no se llega a ver nunca, porque el
    /// primero no se aparta. Las dos cosas juntas dejan al sensor repitiendo la
    /// primera peticion de una sesion y ciego para todo lo demas.
    fn consumir_mensaje(
        &mut self,
        clave: ClaveFlujo,
        desde_a: bool,
        datos: &[u8],
        hechos: &[Hecho],
    ) -> (Vec<Hecho>, Avance) {
        if self.transferencias.contains_key(&(clave, desde_a)) {
            return (Vec::new(), Avance::CuerpoEnCurso);
        }
        // Un mensaje HTTP se enmarca de verdad: cabeceras hasta la linea en
        // blanco, y cuerpo de la longitud declarada. Con eso se sabe EXACTAMENTE
        // donde acaba, que es lo unico que permite pasar al siguiente.
        //
        // Se comprueba ANTES que sea HTTP. `separar` enmarca cualquier cosa que
        // lleve una linea en blanco dentro, y un flujo cifrado la lleva tarde o
        // temprano por pura estadistica: enmarcarlo como HTTP partiria el flujo
        // por un sitio inventado.
        let es_http = http::parece_peticion(datos) || http::parece_respuesta(datos);
        if let Some(m) = http::separar(datos).filter(|_| es_http) {
            let longitud = m
                .cabecera("Content-Length")
                .and_then(|v| v.trim().parse::<u64>().ok());
            match longitud {
                Some(0) | None => {
                    // Sin cuerpo declarado: el mensaje acaba en las cabeceras.
                    // Un cuerpo SIN longitud —troceado, o terminado al cerrar la
                    // conexion— no se enmarca aqui, y eso esta declarado en la
                    // tabla de honestidad en vez de fingir que se cubre.
                    if longitud.is_none() && !hay_hecho_concluyente(hechos) {
                        return (Vec::new(), Avance::Incompleto);
                    }
                    return (Vec::new(), Avance::Consumido(m.inicio_cuerpo));
                }
                Some(n) => return self.arrancar_cuerpo(clave, desde_a, datos, &m, n),
            }
        }

        // TLS se enmarca por registro, y eso incluye los registros CIFRADOS, que
        // son la mayor parte del trafico. De un registro de datos de aplicacion
        // no hay nada que sacar, pero apartarlo es lo unico que evita que el
        // motor acumule cada byte cifrado de cada sesion esperando entenderlo.
        if let Some(n) = tls::largo_registro(datos) {
            // Un registro de HANDSHAKE solo se aparta si se pudo leer: un saludo
            // partido entre varios registros necesita seguir juntandose, y
            // tirarlo perderia la unica ocasion de sacar su huella.
            if !tls::es_handshake(datos) || hay_hecho_concluyente(hechos) {
                return (Vec::new(), Avance::Consumido(n));
            }
            return (Vec::new(), Avance::Incompleto);
        }

        // Ni HTTP ni TLS —o el mensaje aun no esta entero—. Si el disector saco
        // algo CONCLUYENTE, entendio el tramo y no hay que conservarlo: lo unico
        // que daria es el mismo hecho otra vez. Si solo saco un «no analizable»,
        // el mensaje viene a medias y hay que seguir juntando.
        if hay_hecho_concluyente(hechos) {
            (Vec::new(), Avance::Consumido(datos.len()))
        } else {
            (Vec::new(), Avance::Incompleto)
        }
    }

    /// Abre la extraccion del cuerpo de un mensaje HTTP con longitud declarada.
    fn arrancar_cuerpo(
        &mut self,
        clave: ClaveFlujo,
        desde_a: bool,
        datos: &[u8],
        m: &http::Mensaje,
        longitud: u64,
    ) -> (Vec<Hecho>, Avance) {
        let tipo = m.cabecera("Content-Type").unwrap_or("");
        let nombre = nombre_de_disposicion(m.cabecera("Content-Disposition").unwrap_or(""));
        let mut extractor =
            crate::ficheros::Extractor::nuevo(ProtocoloApp::Http, &nombre, tipo, Some(longitud));

        // El cuerpo que YA venia pegado a las cabeceras en este mismo tramo.
        let ya = datos.get(m.inicio_cuerpo..).unwrap_or(&[]);
        let cuanto = usize::try_from(longitud)
            .unwrap_or(usize::MAX)
            .min(ya.len());
        extractor.incorporar(&ya[..cuanto]);
        let restantes = longitud - cuanto as u64;

        if restantes == 0 {
            // El cuerpo cupo entero: se dice donde acaba el mensaje para que el
            // llamante siga por el siguiente, que en una conexion reutilizada
            // viene pegado detras.
            return (
                extractor.cerrar(),
                Avance::Consumido(m.inicio_cuerpo.saturating_add(cuanto)),
            );
        }
        // El cuerpo sigue llegando: a partir de aqui los bytes ATRAVIESAN el
        // extractor sin acumularse, que es lo que permite mirar ficheros grandes
        // sin pagar su tamano en memoria.
        self.transferencias.insert(
            (clave, desde_a),
            Transferencia {
                extractor,
                restantes: Some(restantes),
            },
        );
        (Vec::new(), Avance::CuerpoEnCurso)
    }

    /// Deja el bufer de un sentido con exactamente `contenido`, ajustando la
    /// cuenta global de bytes de aplicacion.
    ///
    /// Toda la contabilidad del bufer pasa por aqui a proposito: repartirla por
    /// varios sitios es como se descuadra.
    fn fijar_bufer(&mut self, clave: ClaveFlujo, desde_a: bool, contenido: &[u8]) {
        let antes = self
            .bufers
            .get(&(clave, desde_a))
            .map_or(0, |b: &Vec<u8>| b.len());
        if contenido.is_empty() {
            self.bufers.remove(&(clave, desde_a));
        } else {
            self.bufers.insert((clave, desde_a), contenido.to_vec());
        }
        let despues = contenido.len();
        if despues >= antes {
            self.bytes_app = self.bytes_app.saturating_add(despues - antes);
        } else {
            self.bytes_app = self.bytes_app.saturating_sub(antes - despues);
        }
    }

    /// Elige el disector de un flujo TCP.
    ///
    /// El CONTENIDO manda; el puerto es solo desempate. Ver la doctrina del
    /// modulo: confiar en el puerto es lo que hace que un C2 en el 443 pase
    /// desapercibido.
    fn disecar_tcp(
        &self,
        datos: &[u8],
        del_cliente: bool,
        puerto_destino: u16,
        puerto_origen: u16,
    ) -> Vec<Hecho> {
        // 1. Por contenido.
        if tls::parece_tls(datos) {
            return tls::analizar(datos, del_cliente);
        }
        if http::parece_peticion(datos) {
            return http::analizar_peticion(datos);
        }
        if http::parece_respuesta(datos) {
            return http::analizar_respuesta(datos);
        }
        if texto::parece_ssh(datos) {
            return texto::analizar_ssh(datos);
        }
        if smb::parece_smb(datos) {
            return smb::analizar(datos);
        }
        if directorio::parece_kerberos(datos) {
            return directorio::analizar_kerberos(datos);
        }
        if directorio::parece_ldap(datos) {
            return directorio::analizar_ldap(datos);
        }

        // 2. Por puerto, como PISTA. Y si el contenido no encaja con lo que el
        //    puerto promete, el resultado sera vacio — que en un puerto conocido
        //    es una senal, no un silencio.
        let puertos = [puerto_destino, puerto_origen];
        if puertos.contains(&25) || puertos.contains(&587) {
            let h = texto::analizar_smtp(datos);
            if !h.is_empty() {
                return h;
            }
        }
        if puertos.contains(&21) {
            let h = texto::analizar_ftp(datos);
            if !h.is_empty() {
                return h;
            }
        }
        if puertos.contains(&53) && datos.len() > 2 {
            // DNS sobre TCP lleva longitud de dos bytes por delante.
            return dns::analizar(&datos[2..]);
        }
        Vec::new()
    }

    /// Elige el disector de un datagrama UDP.
    fn disecar_udp(&self, datos: &[u8], puerto_destino: u16, puerto_origen: u16) -> Vec<Hecho> {
        if udp::parece_dhcp(datos) {
            return udp::analizar_dhcp(datos);
        }
        if udp::parece_quic(datos) {
            return udp::analizar_quic(datos);
        }
        let puertos = [puerto_destino, puerto_origen];
        if puertos.contains(&53) || puertos.contains(&5353) {
            let h = dns::analizar(datos);
            if !h.is_empty() {
                return h;
            }
        }
        if puertos.contains(&123) && udp::parece_ntp(datos) {
            return udp::analizar_ntp(datos);
        }
        if puertos.contains(&88) && directorio::parece_kerberos(datos) {
            return directorio::analizar_kerberos(datos);
        }
        // Sin pista de puerto, se intenta DNS por contenido: es el unico que se
        // reconoce con fiabilidad suficiente para no generar ruido.
        if puertos.contains(&53) {
            return dns::analizar(datos);
        }
        Vec::new()
    }

    fn envolver(
        &mut self,
        flujo: ClaveFlujo,
        direccion: Direccion,
        momento_us: u64,
        hechos: Vec<Hecho>,
    ) -> Vec<HechoConContexto> {
        self.contadores.hechos += hechos.len() as u64;
        hechos
            .into_iter()
            .map(|hecho| HechoConContexto {
                flujo,
                direccion,
                momento_us,
                hecho,
            })
            .collect()
    }

    /// Cierra los flujos muertos y devuelve sus registros.
    pub fn recolectar(&mut self, ahora_us: u64) -> Vec<RegistroConexion> {
        let muertos = self.tabla.recolectar(ahora_us);
        let mut salida = Vec::with_capacity(muertos.len());
        for f in muertos {
            for sentido in [true, false] {
                if let Some(b) = self.bufers.remove(&(f.clave, sentido)) {
                    self.bytes_app = self.bytes_app.saturating_sub(b.len());
                }
                self.transferencias.remove(&(f.clave, sentido));
            }
            let cierre = if f.terminado() {
                Cierre::Limpio
            } else {
                Cierre::Expirado
            };
            salida.push(RegistroConexion::de_flujo(&f, cierre));
        }
        salida
    }

    /// Cierra todo y devuelve los registros de lo que quedaba.
    pub fn vaciar(&mut self) -> Vec<RegistroConexion> {
        self.bufers.clear();
        self.bytes_app = 0;
        self.transferencias.clear();
        let _ = self.tabla.drenar_expulsadas();
        self.tabla
            .vaciar()
            .iter()
            .map(|f| RegistroConexion::de_flujo(f, Cierre::Expirado))
            .collect()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Construye un paquete IPv4 + TCP de verdad, byte a byte.
    fn tcp_ipv4(
        origen: (u8, u16),
        destino: (u8, u16),
        secuencia: u32,
        banderas: u8,
        carga: &[u8],
    ) -> Vec<u8> {
        let total = 20 + 20 + carga.len();
        let mut p = vec![
            0x45,
            0x00,
            (total >> 8) as u8,
            total as u8,
            0x00,
            0x01,
            0x00,
            0x00,
            64,
            aegis_net::packet::IPPROTO_TCP,
            0x00,
            0x00,
            10,
            0,
            0,
            origen.0,
            10,
            0,
            0,
            destino.0,
        ];
        p.extend_from_slice(&origen.1.to_be_bytes());
        p.extend_from_slice(&destino.1.to_be_bytes());
        p.extend_from_slice(&secuencia.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes()); // ack
        p.push(5 << 4); // desplazamiento de datos
        p.push(banderas);
        p.extend_from_slice(&65535u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes()); // suma
        p.extend_from_slice(&0u16.to_be_bytes()); // urgente
        p.extend_from_slice(carga);
        p
    }

    fn udp_ipv4(origen: (u8, u16), destino: (u8, u16), carga: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + carga.len();
        let mut p = vec![
            0x45,
            0x00,
            (total >> 8) as u8,
            total as u8,
            0x00,
            0x01,
            0x00,
            0x00,
            64,
            aegis_net::packet::IPPROTO_UDP,
            0x00,
            0x00,
            10,
            0,
            0,
            origen.0,
            10,
            0,
            0,
            destino.0,
        ];
        p.extend_from_slice(&origen.1.to_be_bytes());
        p.extend_from_slice(&destino.1.to_be_bytes());
        p.extend_from_slice(&((8 + carga.len()) as u16).to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(carga);
        p
    }

    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    const PSH: u8 = 0x08;
    const FIN: u8 = 0x01;

    #[test]
    fn una_conexion_http_completa_produce_sus_hechos_y_su_registro() {
        let mut m = Motor::nuevo(ConfigMotor::default());

        // Apreton de manos: ahora se sabe quien es el cliente.
        m.alimentar_ip(1_000, &tcp_ipv4((1, 50_000), (2, 80), 1000, SYN, &[]));
        m.alimentar_ip(1_100, &tcp_ipv4((2, 80), (1, 50_000), 5000, SYN | ACK, &[]));

        let peticion =
            b"GET /secreto HTTP/1.1\r\nHost: interno.local\r\nUser-Agent: curl/8\r\n\r\n";
        let hechos = m.alimentar_ip(
            1_200,
            &tcp_ipv4((1, 50_000), (2, 80), 1001, PSH | ACK, peticion),
        );

        assert!(
            hechos.iter().any(|h| matches!(
                &h.hecho,
                Hecho::PeticionHttp { uri, host, .. } if uri == "/secreto" && host == "interno.local"
            )),
            "{hechos:?}"
        );
        // Y el contexto viaja PEGADO al hecho: de que flujo y en que sentido.
        assert!(hechos
            .iter()
            .all(|h| h.direccion == Direccion::ClienteAServidor));

        // Cierre y registro.
        m.alimentar_ip(2_000, &tcp_ipv4((1, 50_000), (2, 80), 1100, FIN | ACK, &[]));
        m.alimentar_ip(2_100, &tcp_ipv4((2, 80), (1, 50_000), 5001, FIN | ACK, &[]));
        let registros = m.recolectar(3_000);
        assert_eq!(registros.len(), 1);
        let r = &registros[0];
        assert_eq!(r.origen, "10.0.0.1");
        assert_eq!(r.puerto_destino, 80);
        assert_eq!(r.protocolo, "http");
        assert_eq!(r.cierre, "limpio");
        assert!(r.bytes_subida > 0);
    }

    /// LA DECISION QUE MAS CAMBIA LO QUE EL SENSOR VE: el contenido manda sobre
    /// el puerto. Un C2 que pone HTTP en claro en el 443 se reconoce como HTTP,
    /// no se intenta disecar como TLS y se pierde.
    #[test]
    fn el_contenido_manda_sobre_el_puerto() {
        let mut m = Motor::nuevo(ConfigMotor::default());
        m.alimentar_ip(1, &tcp_ipv4((1, 50_000), (2, 443), 1000, SYN, &[]));

        let peticion = b"POST /beacon HTTP/1.1\r\nHost: c2.example\r\n\r\n";
        let hechos = m.alimentar_ip(
            2,
            &tcp_ipv4((1, 50_000), (2, 443), 1001, PSH | ACK, peticion),
        );
        assert!(
            hechos.iter().any(|h| matches!(
                &h.hecho,
                Hecho::PeticionHttp { uri, .. } if uri == "/beacon"
            )),
            "HTTP en el 443 tiene que reconocerse igual: {hechos:?}"
        );
    }

    /// Y al reves: TLS en un puerto raro tambien se reconoce.
    #[test]
    fn tls_en_un_puerto_inesperado_se_reconoce_igual() {
        let mut m = Motor::nuevo(ConfigMotor::default());
        m.alimentar_ip(1, &tcp_ipv4((1, 50_000), (2, 8080), 1000, SYN, &[]));

        // Un ClientHello minimo pero valido.
        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[0x11; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&0x1301u16.to_be_bytes());
        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(&0u16.to_be_bytes());

        let mut hs = vec![1u8];
        let l = hello.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&hello);
        let mut registro = vec![22u8, 0x03, 0x01];
        registro.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        registro.extend_from_slice(&hs);

        let hechos = m.alimentar_ip(
            2,
            &tcp_ipv4((1, 50_000), (2, 8080), 1001, PSH | ACK, &registro),
        );
        assert!(
            hechos
                .iter()
                .any(|h| matches!(&h.hecho, Hecho::SaludoClienteTls { .. })),
            "{hechos:?}"
        );
    }

    /// EL ATAQUE DE EVASION, de extremo a extremo por el motor: el atacante
    /// manda "GET /publico" y luego solapa con "GET /secreto". El sensor tiene
    /// que quedarse con lo mismo que el destino, y DELATAR el solape.
    #[test]
    fn la_evasion_por_solape_se_resuelve_y_se_delata_a_traves_del_motor() {
        let mut m = Motor::nuevo(ConfigMotor::default());
        m.alimentar_ip(1, &tcp_ipv4((1, 50_000), (2, 80), 1000, SYN, &[]));
        m.alimentar_ip(2, &tcp_ipv4((2, 80), (1, 50_000), 5000, SYN | ACK, &[]));

        // Primero un hueco: se manda el SEGUNDO trozo, que queda retenido.
        let cola = b"o HTTP/1.1\r\nHost: v\r\n\r\n";
        m.alimentar_ip(3, &tcp_ipv4((1, 50_000), (2, 80), 1001 + 12, PSH, cola));
        // Y ahora dos versiones del PRIMER trozo, contradictorias.
        m.alimentar_ip(
            4,
            &tcp_ipv4((1, 50_000), (2, 80), 1001, PSH, b"GET /publico"),
        );
        m.alimentar_ip(
            5,
            &tcp_ipv4((1, 50_000), (2, 80), 1001, PSH, b"GET /secreto"),
        );

        m.alimentar_ip(6, &tcp_ipv4((1, 50_000), (2, 80), 1100, FIN | ACK, &[]));
        m.alimentar_ip(7, &tcp_ipv4((2, 80), (1, 50_000), 5001, FIN | ACK, &[]));
        let registros = m.recolectar(8);

        assert_eq!(registros.len(), 1);
        assert!(
            registros[0].hay_indicio_de_evasion(),
            "el solape contradictorio TIENE que llegar al registro: {:?}",
            registros[0]
        );
    }

    #[test]
    fn una_consulta_dns_por_udp_produce_su_hecho() {
        let mut m = Motor::nuevo(ConfigMotor::default());
        let mut consulta = Vec::new();
        consulta.extend_from_slice(&0x1234u16.to_be_bytes());
        consulta.extend_from_slice(&0x0100u16.to_be_bytes());
        consulta.extend_from_slice(&1u16.to_be_bytes());
        consulta.extend_from_slice(&[0u8; 6]);
        for etiqueta in ["malicioso", "example", "com"] {
            consulta.push(etiqueta.len() as u8);
            consulta.extend_from_slice(etiqueta.as_bytes());
        }
        consulta.push(0);
        consulta.extend_from_slice(&1u16.to_be_bytes());
        consulta.extend_from_slice(&1u16.to_be_bytes());

        let hechos = m.alimentar_ip(1, &udp_ipv4((1, 50_000), (2, 53), &consulta));
        assert!(
            hechos.iter().any(|h| matches!(
                &h.hecho,
                Hecho::ConsultaDns { nombre, .. } if nombre == "malicioso.example.com"
            )),
            "{hechos:?}"
        );
    }

    /// Una cadena de extensiones IPv6 interminable NO se da por limpia: se
    /// cuenta aparte, porque es una tecnica de evasion y no un error.
    #[test]
    fn una_cadena_ipv6_interminable_se_cuenta_como_evasion_y_no_como_error_comun() {
        let mut m = Motor::nuevo(ConfigMotor::default());
        let mut ext = Vec::new();
        for _ in 0..200 {
            ext.extend_from_slice(&[ipv6::NH_DESTINO, 0, 0, 0, 0, 0, 0, 0]);
        }
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        p.push(ipv6::NH_DESTINO);
        p.push(64);
        p.extend_from_slice(&[0x20; 16]);
        p.extend_from_slice(&[0x30; 16]);
        p.extend_from_slice(&ext);

        m.alimentar_ip(1, &p);
        assert_eq!(
            m.contadores().ipv6_cadena_excesiva,
            1,
            "una cadena interminable es evasion, y se cuenta como tal"
        );
    }

    /// LA COTA DEL MOTOR: abrir cien mil flujos no puede tumbar al sensor.
    #[test]
    fn abrir_muchisimos_flujos_no_tumba_el_motor() {
        let mut m = Motor::nuevo(ConfigMotor {
            max_flujos: 500,
            ..Default::default()
        });
        for i in 0..20_000u32 {
            let puerto = (i % 60_000) as u16 + 1024;
            m.alimentar_ip(
                u64::from(i),
                &tcp_ipv4((1, puerto), (2, 80), 1000, SYN, &[]),
            );
        }
        assert!(m.flujos_vivos() <= 500, "vivos = {}", m.flujos_vivos());
    }

    /// Un fichero descargado por HTTP se extrae de extremo a extremo, troceado
    /// en varios paquetes, con su hash y su tipo REAL.
    #[test]
    fn un_fichero_descargado_por_http_se_extrae_con_su_hash() {
        let mut m = Motor::nuevo(ConfigMotor::default());
        m.alimentar_ip(1, &tcp_ipv4((1, 50_000), (2, 80), 1000, SYN, &[]));
        m.alimentar_ip(2, &tcp_ipv4((2, 80), (1, 50_000), 5000, SYN | ACK, &[]));

        // Un PE de 300 bytes, entregado como si fuera un PDF.
        let mut cuerpo = b"MZ".to_vec();
        cuerpo.resize(300, 0x41);
        let cabeceras = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n\
             Content-Disposition: attachment; filename=\"factura.pdf\"\r\n\
             Content-Length: {}\r\n\r\n",
            cuerpo.len()
        );

        let mut sec = 5001u32;
        let mut hechos = m.alimentar_ip(
            3,
            &tcp_ipv4((2, 80), (1, 50_000), sec, PSH | ACK, cabeceras.as_bytes()),
        );
        sec = sec.wrapping_add(cabeceras.len() as u32);
        // El cuerpo llega en trozos de 64: la magia queda en el primero pero el
        // fichero no se completa hasta el ultimo.
        for trozo in cuerpo.chunks(64) {
            hechos.extend(m.alimentar_ip(4, &tcp_ipv4((2, 80), (1, 50_000), sec, PSH, trozo)));
            sec = sec.wrapping_add(trozo.len() as u32);
        }

        let fichero = hechos
            .iter()
            .find_map(|h| match &h.hecho {
                Hecho::FicheroTransferido {
                    nombre,
                    tamano,
                    sha256,
                    ..
                } => Some((nombre.clone(), *tamano, sha256.clone())),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no se extrajo el fichero: {hechos:?}"));

        assert_eq!(fichero.1, cuerpo.len(), "el tamano tiene que ser el real");
        assert_eq!(fichero.0, "factura.pdf");
        // El hash tiene que ser el del fichero entero, no el de un trozo.
        let esperado = {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(&cuerpo))
        };
        assert_eq!(fichero.2, esperado, "hash del fichero entero");

        // Y LA SENAL: se anuncia PDF pero es un ejecutable.
        assert!(
            hechos.iter().any(|h| matches!(
                &h.hecho,
                Hecho::AnomaliaDeFlujo {
                    codigo: "fichero-tipo-contradictorio",
                    ..
                }
            )),
            "{hechos:?}"
        );
    }

    /// Un cuerpo enorme NO puede hacer crecer la memoria del motor: atraviesa el
    /// extractor sin acumularse. Es la diferencia entre poder mirar ficheros
    /// grandes y morir al intentarlo.
    #[test]
    fn un_cuerpo_enorme_atraviesa_sin_acumularse() {
        let mut m = Motor::nuevo(ConfigMotor::default());
        m.alimentar_ip(1, &tcp_ipv4((1, 50_000), (2, 80), 1000, SYN, &[]));
        m.alimentar_ip(2, &tcp_ipv4((2, 80), (1, 50_000), 5000, SYN | ACK, &[]));

        const TAMANO: usize = 8 * 1024 * 1024;
        let cabeceras = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {TAMANO}\r\n\r\n"
        );
        let mut sec = 5001u32;
        m.alimentar_ip(
            3,
            &tcp_ipv4((2, 80), (1, 50_000), sec, PSH | ACK, cabeceras.as_bytes()),
        );
        sec = sec.wrapping_add(cabeceras.len() as u32);

        let trozo = vec![0x5Au8; 1400];
        let mut enviados = 0usize;
        while enviados < TAMANO {
            let cuanto = trozo.len().min(TAMANO - enviados);
            m.alimentar_ip(
                4,
                &tcp_ipv4((2, 80), (1, 50_000), sec, PSH, &trozo[..cuanto]),
            );
            sec = sec.wrapping_add(cuanto as u32);
            enviados += cuanto;
            assert!(
                m.memoria() <= 256 * 1024,
                "a los {enviados} bytes ya reservaba {}",
                m.memoria()
            );
        }
    }

    /// Detras del cuerpo viene el SIGUIENTE mensaje: con reutilizacion de
    /// conexion, perderlo dejaria al sensor ciego para el resto de la sesion.
    #[test]
    fn tras_un_cuerpo_el_siguiente_mensaje_se_sigue_viendo() {
        let mut m = Motor::nuevo(ConfigMotor::default());
        m.alimentar_ip(1, &tcp_ipv4((1, 50_000), (2, 80), 1000, SYN, &[]));
        m.alimentar_ip(2, &tcp_ipv4((2, 80), (1, 50_000), 5000, SYN | ACK, &[]));

        let mut flujo = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n".to_vec();
        flujo.extend_from_slice(b"AAAA");
        // Pegado detras, la siguiente respuesta de la misma conexion.
        flujo.extend_from_slice(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");

        let hechos = m.alimentar_ip(3, &tcp_ipv4((2, 80), (1, 50_000), 5001, PSH | ACK, &flujo));
        assert!(
            hechos
                .iter()
                .any(|h| matches!(&h.hecho, Hecho::RespuestaHttp { estado: 404, .. })),
            "el segundo mensaje tiene que verse: {hechos:?}"
        );
    }

    /// EL ATAQUE DE RETENCION, que la cota por flujo NO para: pocos miles de
    /// flujos, cada uno reteniendo datos fuera de orden que nunca se completan.
    /// Con solo la cota por flujo esto reservaria gigabytes; el techo global es
    /// lo unico que lo convierte en una cifra que cabe en el presupuesto.
    #[test]
    fn retener_en_muchos_flujos_a_la_vez_respeta_el_techo_global() {
        const TECHO: usize = 256 * 1024;
        let mut m = Motor::nuevo(ConfigMotor {
            max_memoria: TECHO,
            max_memoria_app: TECHO,
            ..ConfigMotor::default()
        });

        let trozo = vec![b'X'; 1400];
        for i in 0..3_000u32 {
            let puerto = (i % 60_000) as u16 + 1024;
            // SYN para sincronizar, y luego un segmento MUY por delante: deja un
            // hueco que no se tapa nunca, asi que se retiene.
            m.alimentar_ip(
                u64::from(i),
                &tcp_ipv4((1, puerto), (2, 80), 1000, SYN, &[]),
            );
            m.alimentar_ip(
                u64::from(i),
                &tcp_ipv4((1, puerto), (2, 80), 500_000, PSH, &trozo),
            );
        }

        assert!(
            m.tabla().bytes_reservados() <= TECHO,
            "reensamblado = {}, techo = {TECHO}",
            m.tabla().bytes_reservados()
        );
        assert!(
            m.contadores().paquetes > 0,
            "el motor tiene que haber seguido trabajando, no rendirse"
        );
        assert!(
            m.tabla().contadores().expulsados_por_memoria > 0,
            "y la expulsion por memoria tiene que CONTARSE: {:?}",
            m.tabla().contadores()
        );
    }

    /// Expulsar un flujo tiene que soltar TAMBIEN su bufer de aplicacion. Si no,
    /// cada expulsion deja basura viva: no es un peor caso, es una fuga.
    #[test]
    fn expulsar_un_flujo_suelta_su_bufer_de_aplicacion() {
        let mut m = Motor::nuevo(ConfigMotor {
            max_flujos: 4,
            ..ConfigMotor::default()
        });
        // Cada flujo deja datos a medio interpretar en su bufer.
        for i in 0..200u32 {
            let puerto = (i % 60_000) as u16 + 1024;
            m.alimentar_ip(
                u64::from(i),
                &tcp_ipv4((1, puerto), (2, 80), 1000, SYN, &[]),
            );
            m.alimentar_ip(
                u64::from(i),
                &tcp_ipv4((1, puerto), (2, 80), 1001, PSH, b"GET /a"),
            );
        }
        assert!(m.flujos_vivos() <= 4);
        assert!(
            m.bufers.len() <= 8,
            "un bufer por sentido de flujo VIVO, no uno por flujo que existio: {}",
            m.bufers.len()
        );
        let suma: usize = m.bufers.values().map(Vec::len).sum();
        assert_eq!(
            m.bytes_app, suma,
            "la cuenta de bytes de aplicacion tiene que cuadrar con la realidad"
        );
    }

    /// La contabilidad de memoria no puede descuadrar tras un ciclo completo de
    /// alta, datos, cierre y recoleccion.
    #[test]
    fn la_contabilidad_de_memoria_cuadra_tras_recolectar() {
        let mut m = Motor::nuevo(ConfigMotor::default());
        for i in 0..50u32 {
            let puerto = 1024 + i as u16;
            m.alimentar_ip(1, &tcp_ipv4((1, puerto), (2, 80), 1000, SYN, &[]));
            m.alimentar_ip(
                2,
                &tcp_ipv4((1, puerto), (2, 80), 1001, PSH, b"GET /x HTTP/1.1\r\n"),
            );
            // Un hueco que se queda retenido.
            m.alimentar_ip(3, &tcp_ipv4((1, puerto), (2, 80), 90_000, PSH, b"colgado"));
        }
        assert!(m.memoria() > 0, "algo tiene que haber reservado");

        let _ = m.vaciar();
        assert_eq!(m.memoria(), 0, "vaciar tiene que dejar la cuenta en cero");
        assert_eq!(m.tabla().bytes_reservados(), 0);
        assert_eq!(m.bytes_app, 0);
    }

    /// El buffer de aplicacion tampoco puede crecer sin limite.
    #[test]
    fn el_bufer_de_aplicacion_esta_acotado() {
        let mut m = Motor::nuevo(ConfigMotor::default());
        m.alimentar_ip(1, &tcp_ipv4((1, 50_000), (2, 80), 1000, SYN, &[]));
        let trozo = vec![b'A'; 1400];
        let mut sec = 1001u32;
        for i in 0..500u32 {
            m.alimentar_ip(
                u64::from(i) + 2,
                &tcp_ipv4((1, 50_000), (2, 80), sec, PSH, &trozo),
            );
            sec = sec.wrapping_add(trozo.len() as u32);
        }
        let total: usize = m.bufers.values().map(Vec::len).sum();
        assert!(total <= MAX_BUFER_APP * 2, "buffers = {total}");
    }

    #[test]
    fn un_paquete_arbitrario_no_provoca_panico() {
        let mut m = Motor::nuevo(ConfigMotor::default());
        let mut semilla = 0x4D4F_544F_5231_3233u64;
        for i in 0..20_000u64 {
            semilla = semilla
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let largo = (semilla >> 32) as usize % 200;
            let mut datos: Vec<u8> = (0..largo).map(|j| (semilla >> (j % 8)) as u8).collect();
            // Un tercio con version IP valida, para llegar mas adentro.
            if !datos.is_empty() {
                datos[0] = match i % 3 {
                    0 => 0x45,
                    1 => 0x60,
                    _ => datos[0],
                };
            }
            let _ = m.alimentar_ip(i, &datos);
            let _ = m.alimentar_ethernet(i, &datos);
        }
        let _ = m.vaciar();
    }

    #[test]
    fn apagar_la_diseccion_deja_solo_los_registros() {
        let mut m = Motor::nuevo(ConfigMotor {
            disecar_aplicacion: false,
            ..Default::default()
        });
        m.alimentar_ip(1, &tcp_ipv4((1, 50_000), (2, 80), 1000, SYN, &[]));
        let hechos = m.alimentar_ip(
            2,
            &tcp_ipv4((1, 50_000), (2, 80), 1001, PSH, b"GET / HTTP/1.1\r\n\r\n"),
        );
        assert!(
            hechos.is_empty(),
            "sin diseccion no hay hechos de aplicacion"
        );

        let registros = m.vaciar();
        assert_eq!(registros.len(), 1, "pero el registro SI se emite");
        assert!(registros[0].bytes_subida > 0);
    }
}
