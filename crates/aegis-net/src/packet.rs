//! Analizador de cabeceras de red sin copias.
//!
//! Escrito a mano y no sobre una biblioteca de terceros por dos razones. La
//! primera es de superficie de ataque: este codigo procesa bytes que controla
//! integramente un atacante remoto, y en un producto de seguridad esa frontera
//! debe ser auditable de un vistazo. La segunda es de correccion: casi todo
//! parser generico acepta cabeceras que un atacante usa precisamente para
//! confundir a los analizadores intermedios (IHL por debajo del minimo,
//! longitud total menor que la cabecera, offset de datos TCP invalido). Aqui
//! esos casos se rechazan de forma explicita, y cada rechazo tiene su prueba.
//!
//! Todo acceso pasa por comprobacion de limites. No hay `unsafe` en el modulo.

use std::net::Ipv4Addr;

/// Ethertype de IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// Ethertype de IPv6.
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
/// Ethertype de una etiqueta VLAN 802.1Q.
pub const ETHERTYPE_VLAN: u16 = 0x8100;

/// Numero de protocolo de TCP.
pub const IPPROTO_TCP: u8 = 6;
/// Numero de protocolo de UDP.
pub const IPPROTO_UDP: u8 = 17;
/// Numero de protocolo de ICMP.
pub const IPPROTO_ICMP: u8 = 1;

/// Longitud de una cabecera Ethernet sin etiquetas.
pub const ETH_HDR_LEN: usize = 14;
/// Longitud minima legal de una cabecera IPv4.
pub const IPV4_MIN_HDR_LEN: usize = 20;
/// Longitud minima legal de una cabecera TCP.
pub const TCP_MIN_HDR_LEN: usize = 20;
/// Longitud de una cabecera UDP.
pub const UDP_HDR_LEN: usize = 8;

/// Error al analizar un paquete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// El buffer es mas corto que la cabecera que dice contener.
    TooShort {
        /// Que se estaba analizando.
        layer: &'static str,
        /// Bytes necesarios.
        needed: usize,
        /// Bytes disponibles.
        available: usize,
    },
    /// El campo de version de IP no es 4.
    NotIpv4 {
        /// Version encontrada.
        version: u8,
    },
    /// `IHL` declara una cabecera mas corta que el minimo legal.
    ///
    /// Es una tecnica de evasion: un analizador que confia en `ihl` sin
    /// comprobarlo lee los campos desplazados o fuera del buffer.
    BadIhl {
        /// Valor de `ihl` encontrado.
        ihl: u8,
    },
    /// `total_length` es menor que la propia cabecera IP.
    BadTotalLength {
        /// Longitud total declarada.
        total: u16,
        /// Longitud de la cabecera.
        header: usize,
    },
    /// El offset de datos de TCP declara una cabecera invalida.
    BadDataOffset {
        /// Valor encontrado.
        offset: u8,
    },
    /// El ethertype no corresponde a un protocolo que se analice.
    UnsupportedEthertype {
        /// Ethertype encontrado.
        ethertype: u16,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::TooShort {
                layer,
                needed,
                available,
            } => write!(
                f,
                "{layer}: hacen falta {needed} bytes y solo hay {available}"
            ),
            ParseError::NotIpv4 { version } => write!(f, "version IP {version}, se esperaba 4"),
            ParseError::BadIhl { ihl } => {
                write!(f, "IHL {ihl} por debajo del minimo legal de 5")
            }
            ParseError::BadTotalLength { total, header } => write!(
                f,
                "longitud total {total} menor que la cabecera de {header} bytes"
            ),
            ParseError::BadDataOffset { offset } => {
                write!(f, "offset de datos TCP {offset} fuera del rango 5..=15")
            }
            ParseError::UnsupportedEthertype { ethertype } => {
                write!(f, "ethertype 0x{ethertype:04x} no analizado")
            }
        }
    }
}

impl std::error::Error for ParseError {}

fn u16_be(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn u32_be(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Cabecera Ethernet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthHeader {
    /// MAC destino.
    pub dst: [u8; 6],
    /// MAC origen.
    pub src: [u8; 6],
    /// Ethertype, ya en orden de host.
    pub ethertype: u16,
    /// Bytes consumidos, incluyendo etiquetas VLAN.
    pub header_len: usize,
}

impl EthHeader {
    /// Analiza una cabecera Ethernet, saltando hasta dos etiquetas VLAN.
    ///
    /// Saltar las etiquetas importa: un atacante puede encapsular en VLAN para
    /// que un analizador que solo mira el primer ethertype no vea el IP que hay
    /// detras y deje pasar el paquete sin inspeccionar.
    pub fn parse(buf: &[u8]) -> Result<EthHeader, ParseError> {
        if buf.len() < ETH_HDR_LEN {
            return Err(ParseError::TooShort {
                layer: "ethernet",
                needed: ETH_HDR_LEN,
                available: buf.len(),
            });
        }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&buf[0..6]);
        src.copy_from_slice(&buf[6..12]);

        let mut off = 12;
        let mut ethertype = u16_be(buf, off);
        off += 2;

        // Hasta dos niveles de VLAN (QinQ). Mas de dos se considera anomalo y
        // se deja de analizar en vez de recorrer indefinidamente.
        for _ in 0..2 {
            if ethertype != ETHERTYPE_VLAN {
                break;
            }
            if buf.len() < off + 4 {
                return Err(ParseError::TooShort {
                    layer: "vlan",
                    needed: off + 4,
                    available: buf.len(),
                });
            }
            off += 2; // TCI
            ethertype = u16_be(buf, off);
            off += 2;
        }

        Ok(EthHeader {
            dst,
            src,
            ethertype,
            header_len: off,
        })
    }
}

/// Cabecera IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    /// Longitud de la cabecera en bytes (`ihl * 4`).
    pub header_len: usize,
    /// Longitud total del datagrama declarada.
    pub total_length: u16,
    /// Identificador.
    pub id: u16,
    /// Tiempo de vida.
    pub ttl: u8,
    /// Protocolo de la capa superior.
    pub protocol: u8,
    /// Suma de comprobacion declarada.
    pub checksum: u16,
    /// Direccion origen.
    pub src: Ipv4Addr,
    /// Direccion destino.
    pub dst: Ipv4Addr,
    /// Indica si el paquete es un fragmento que no es el primero.
    pub is_fragment: bool,
    /// Bandera MF (`More Fragments`): quedan fragmentos por llegar.
    ///
    /// Es distinta de `is_fragment`. El PRIMER fragmento de un datagrama
    /// troceado lleva desplazamiento cero —y por tanto `is_fragment == false`,
    /// porque ese fragmento trae cabecera de transporte y se puede analizar—
    /// pero lleva MF a uno. Quien quiera saber si un datagrama viene troceado
    /// necesita las dos banderas; quien solo quiera saber si puede analizar
    /// transporte necesita `is_fragment`.
    pub mas_fragmentos: bool,
}

impl Ipv4Header {
    /// Analiza una cabecera IPv4 con validacion estricta.
    pub fn parse(buf: &[u8]) -> Result<Ipv4Header, ParseError> {
        if buf.len() < IPV4_MIN_HDR_LEN {
            return Err(ParseError::TooShort {
                layer: "ipv4",
                needed: IPV4_MIN_HDR_LEN,
                available: buf.len(),
            });
        }
        let version = buf[0] >> 4;
        if version != 4 {
            return Err(ParseError::NotIpv4 { version });
        }
        let ihl = buf[0] & 0x0F;
        if ihl < 5 {
            return Err(ParseError::BadIhl { ihl });
        }
        let header_len = ihl as usize * 4;
        if buf.len() < header_len {
            return Err(ParseError::TooShort {
                layer: "ipv4 opciones",
                needed: header_len,
                available: buf.len(),
            });
        }

        let total_length = u16_be(buf, 2);
        // Una longitud total menor que la cabecera es imposible en un paquete
        // legitimo y se usa para desincronizar analizadores.
        if (total_length as usize) < header_len {
            return Err(ParseError::BadTotalLength {
                total: total_length,
                header: header_len,
            });
        }

        let flags_frag = u16_be(buf, 6);
        let frag_offset = flags_frag & 0x1FFF;

        Ok(Ipv4Header {
            header_len,
            total_length,
            id: u16_be(buf, 4),
            ttl: buf[8],
            protocol: buf[9],
            checksum: u16_be(buf, 10),
            src: Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]),
            dst: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]),
            // Los fragmentos posteriores no llevan cabecera de transporte, asi
            // que analizarlos como TCP leeria datos de carga util como puertos.
            is_fragment: frag_offset != 0,
            mas_fragmentos: flags_frag & 0x2000 != 0,
        })
    }

    /// Calcula la suma de comprobacion de la cabecera.
    pub fn compute_checksum(buf: &[u8]) -> u16 {
        let mut suma: u32 = 0;
        let mut i = 0;
        while i + 1 < buf.len() {
            // El campo de checksum (offset 10) se toma como cero al calcular.
            let palabra = if i == 10 { 0 } else { u16_be(buf, i) };
            suma += u32::from(palabra);
            i += 2;
        }
        if i < buf.len() {
            suma += u32::from(buf[i]) << 8;
        }
        while suma >> 16 != 0 {
            suma = (suma & 0xFFFF) + (suma >> 16);
        }
        !(suma as u16)
    }

    /// Indica si la suma de comprobacion declarada es correcta.
    pub fn checksum_valid(&self, buf: &[u8]) -> bool {
        if buf.len() < self.header_len {
            return false;
        }
        Ipv4Header::compute_checksum(&buf[..self.header_len]) == self.checksum
    }
}

/// Banderas de un segmento TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    /// FIN.
    pub const FIN: u8 = 0x01;
    /// SYN.
    pub const SYN: u8 = 0x02;
    /// RST.
    pub const RST: u8 = 0x04;
    /// PSH.
    pub const PSH: u8 = 0x08;
    /// ACK.
    pub const ACK: u8 = 0x10;
    /// URG.
    pub const URG: u8 = 0x20;

    /// Indica si esta puesta la bandera dada.
    pub fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// Apertura de conexion: SYN sin ACK.
    pub fn is_syn_only(self) -> bool {
        self.has(Self::SYN) && !self.has(Self::ACK)
    }

    /// Combinaciones que no existen en TCP legitimo y que solo aparecen en
    /// barridos de reconocimiento o en intentos de evadir cortafuegos.
    pub fn is_anomalous(self) -> bool {
        let f = self.0;
        // NULL scan: ninguna bandera.
        if f == 0 {
            return true;
        }
        // XMAS scan: FIN + PSH + URG.
        if self.has(Self::FIN) && self.has(Self::PSH) && self.has(Self::URG) {
            return true;
        }
        // SYN+FIN: abrir y cerrar a la vez no tiene sentido.
        if self.has(Self::SYN) && self.has(Self::FIN) {
            return true;
        }
        // SYN+RST.
        if self.has(Self::SYN) && self.has(Self::RST) {
            return true;
        }
        false
    }
}

/// Cabecera TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    /// Puerto origen.
    pub src_port: u16,
    /// Puerto destino.
    pub dst_port: u16,
    /// Numero de secuencia.
    pub seq: u32,
    /// Numero de acuse.
    pub ack: u32,
    /// Longitud de la cabecera en bytes.
    pub header_len: usize,
    /// Banderas.
    pub flags: TcpFlags,
    /// Ventana anunciada.
    pub window: u16,
}

impl TcpHeader {
    /// Analiza una cabecera TCP.
    pub fn parse(buf: &[u8]) -> Result<TcpHeader, ParseError> {
        if buf.len() < TCP_MIN_HDR_LEN {
            return Err(ParseError::TooShort {
                layer: "tcp",
                needed: TCP_MIN_HDR_LEN,
                available: buf.len(),
            });
        }
        let data_offset = buf[12] >> 4;
        if !(5..=15).contains(&data_offset) {
            return Err(ParseError::BadDataOffset {
                offset: data_offset,
            });
        }
        let header_len = data_offset as usize * 4;
        if buf.len() < header_len {
            return Err(ParseError::TooShort {
                layer: "tcp opciones",
                needed: header_len,
                available: buf.len(),
            });
        }
        Ok(TcpHeader {
            src_port: u16_be(buf, 0),
            dst_port: u16_be(buf, 2),
            seq: u32_be(buf, 4),
            ack: u32_be(buf, 8),
            header_len,
            flags: TcpFlags(buf[13]),
            window: u16_be(buf, 14),
        })
    }
}

/// Cabecera UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    /// Puerto origen.
    pub src_port: u16,
    /// Puerto destino.
    pub dst_port: u16,
    /// Longitud declarada, cabecera incluida.
    pub length: u16,
}

impl UdpHeader {
    /// Analiza una cabecera UDP.
    pub fn parse(buf: &[u8]) -> Result<UdpHeader, ParseError> {
        if buf.len() < UDP_HDR_LEN {
            return Err(ParseError::TooShort {
                layer: "udp",
                needed: UDP_HDR_LEN,
                available: buf.len(),
            });
        }
        Ok(UdpHeader {
            src_port: u16_be(buf, 0),
            dst_port: u16_be(buf, 2),
            length: u16_be(buf, 4),
        })
    }
}

/// Capa de transporte reconocida.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Segmento TCP.
    Tcp(TcpHeader),
    /// Datagrama UDP.
    Udp(UdpHeader),
    /// Otro protocolo, identificado por su numero.
    Other(u8),
    /// Fragmento IP posterior al primero: no hay cabecera de transporte.
    Fragment,
}

/// Paquete completo analizado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    /// Cabecera Ethernet.
    pub eth: EthHeader,
    /// Cabecera IPv4.
    pub ip: Ipv4Header,
    /// Capa de transporte.
    pub transport: Transport,
}

impl Packet {
    /// Analiza una trama Ethernet completa.
    pub fn parse(buf: &[u8]) -> Result<Packet, ParseError> {
        let eth = EthHeader::parse(buf)?;
        if eth.ethertype != ETHERTYPE_IPV4 {
            return Err(ParseError::UnsupportedEthertype {
                ethertype: eth.ethertype,
            });
        }
        let resto = &buf[eth.header_len..];
        let ip = Ipv4Header::parse(resto)?;

        let transport = if ip.is_fragment {
            // Analizar un fragmento posterior como TCP leeria bytes de carga
            // util interpretandolos como puertos, que es justo la evasion que
            // la fragmentacion permite.
            Transport::Fragment
        } else {
            let l4 = &resto[ip.header_len..];
            match ip.protocol {
                IPPROTO_TCP => Transport::Tcp(TcpHeader::parse(l4)?),
                IPPROTO_UDP => Transport::Udp(UdpHeader::parse(l4)?),
                otro => Transport::Other(otro),
            }
        };

        Ok(Packet { eth, ip, transport })
    }

    /// Puerto destino, si el transporte lo tiene.
    pub fn dst_port(&self) -> Option<u16> {
        match self.transport {
            Transport::Tcp(t) => Some(t.dst_port),
            Transport::Udp(u) => Some(u.dst_port),
            _ => None,
        }
    }

    /// Puerto origen, si el transporte lo tiene.
    pub fn src_port(&self) -> Option<u16> {
        match self.transport {
            Transport::Tcp(t) => Some(t.src_port),
            Transport::Udp(u) => Some(u.src_port),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Construccion de paquetes
// ---------------------------------------------------------------------------

/// Construye tramas sinteticas.
///
/// Existe para poder ejercitar el programa XDP con `BPF_PROG_TEST_RUN`, que
/// ejecuta el programa contra paquetes fabricados sin necesidad de una interfaz
/// de red real. Es la unica forma de probar de manera determinista que el filtro
/// descarta lo que debe: generar trafico real contra una interfaz depende del
/// entorno y arriesga la conectividad de la maquina.
#[derive(Debug)]
pub struct PacketBuilder;

impl PacketBuilder {
    /// Construye una trama Ethernet + IPv4 + TCP.
    pub fn tcp(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_ip = IPV4_MIN_HDR_LEN + TCP_MIN_HDR_LEN + payload.len();
        let mut b = Vec::with_capacity(ETH_HDR_LEN + total_ip);

        // Ethernet
        b.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // destino
        b.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // origen
        b.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

        // IPv4
        let ip_off = b.len();
        b.push(0x45); // version 4, IHL 5
        b.push(0); // DSCP/ECN
        b.extend_from_slice(&(total_ip as u16).to_be_bytes());
        b.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        b.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
        b.push(64); // TTL
        b.push(IPPROTO_TCP);
        b.extend_from_slice(&0u16.to_be_bytes()); // checksum, se rellena luego
        b.extend_from_slice(&src.octets());
        b.extend_from_slice(&dst.octets());

        let ck = Ipv4Header::compute_checksum(&b[ip_off..ip_off + IPV4_MIN_HDR_LEN]);
        b[ip_off + 10..ip_off + 12].copy_from_slice(&ck.to_be_bytes());

        // TCP
        b.extend_from_slice(&src_port.to_be_bytes());
        b.extend_from_slice(&dst_port.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes()); // seq
        b.extend_from_slice(&0u32.to_be_bytes()); // ack
        b.push(5 << 4); // offset 5, sin opciones
        b.push(flags);
        b.extend_from_slice(&64240u16.to_be_bytes()); // ventana
        b.extend_from_slice(&0u16.to_be_bytes()); // checksum TCP (no se valida aqui)
        b.extend_from_slice(&0u16.to_be_bytes()); // urgent
        b.extend_from_slice(payload);

        b
    }

    /// Trama TCP SYN, el caso que dispara la deteccion de barridos.
    pub fn tcp_syn(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
        Self::tcp(src, dst, src_port, dst_port, TcpFlags::SYN, &[])
    }

    /// Trama Ethernet con un ethertype arbitrario y carga opaca.
    pub fn raw_ethertype(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::with_capacity(ETH_HDR_LEN + payload.len());
        b.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        b.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
        b.extend_from_slice(&ethertype.to_be_bytes());
        b.extend_from_slice(payload);
        b
    }
}
