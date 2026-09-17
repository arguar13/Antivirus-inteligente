//! Proveedores de las tablas de red.
//!
//! # La trampa de las direcciones en `/proc`
//!
//! `/proc/net/route` y `/proc/net/arp` escriben las direcciones en hexadecimal
//! con el orden de bytes del ANFITRION, no el de red. Es exactamente la misma
//! trampa que tenia `aegis-scal::linux::net` —y donde tenia un defecto real que
//! la FASE 81 corrigio: decodificaba IPv6 con `to_be_bytes` y convertia `::1` en
//! `::100:0`—. Aqui se deshace igual y por el mismo motivo: `to_ne_bytes`, que
//! vale en las dos endianidades.
//!
//! Una direccion mal decodificada en una tabla de red no es un error cosmetico.
//! Es una fila que dice que la puerta de enlace es otra, o que el vecino con esa
//! MAC tiene otra IP, y quien actue sobre ella actua contra una maquina que no
//! tiene nada que ver.

use std::net::{Ipv4Addr, Ipv6Addr};

use aegis_entidad::Clase;
use aegis_parser::esquema::{red as esq, Coste, Tabla as Esquema};

use crate::contexto::{desde_scal, Contexto};
use crate::tabla::{Constructor, Filas, Filtro, MotivoNoLeible, Tabla};

/// Decodifica una direccion IPv4 del formato hexadecimal de `/proc`.
///
/// Ver la cabecera del modulo sobre por que es `to_ne_bytes`.
fn ipv4_de_hex(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let palabra = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(palabra.to_ne_bytes()))
}

/// Decodifica una direccion IPv6 del formato de `/proc/net/ipv6_route`.
///
/// Ojo: este fichero NO usa el mismo formato que `/proc/net/tcp6`. Aqui la
/// direccion viene como 32 digitos hexadecimales en orden de RED, byte a byte,
/// sin la vuelta por palabras de 32 bits del anfitrion. Tratarlos igual es el
/// error que produce direcciones inventadas.
fn ipv6_de_hex_plano(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octetos = [0u8; 16];
    for (i, o) in octetos.iter_mut().enumerate() {
        *o = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(Ipv6Addr::from(octetos))
}

// ---------------------------------------------------------------------------
// routes
// ---------------------------------------------------------------------------

/// La tabla de encaminamiento.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rutas;

/// Una ruta ya descompuesta, para poder probar el analizador sin el sistema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruta {
    /// Interfaz de salida.
    pub interfaz: String,
    /// Red de destino.
    pub destino: String,
    /// Puerta de enlace.
    pub puerta: String,
    /// Mascara.
    pub mascara: String,
    /// Metrica.
    pub metrica: i64,
    /// Familia: ipv4 o ipv6.
    pub familia: &'static str,
}

/// Analiza `/proc/net/route` (IPv4).
pub fn analizar_rutas_v4(texto: &str) -> Vec<Ruta> {
    let mut salida = Vec::new();
    for linea in texto.lines().skip(1) {
        let campos: Vec<&str> = linea.split_whitespace().collect();
        if campos.len() < 8 {
            continue;
        }
        let (Some(destino), Some(puerta), Some(mascara)) = (
            ipv4_de_hex(campos[1]),
            ipv4_de_hex(campos[2]),
            ipv4_de_hex(campos[7]),
        ) else {
            continue;
        };
        salida.push(Ruta {
            interfaz: campos[0].to_string(),
            destino: destino.to_string(),
            puerta: puerta.to_string(),
            mascara: mascara.to_string(),
            metrica: campos[6].parse().unwrap_or(0),
            familia: "ipv4",
        });
    }
    salida
}

/// Analiza `/proc/net/ipv6_route`.
pub fn analizar_rutas_v6(texto: &str) -> Vec<Ruta> {
    let mut salida = Vec::new();
    for linea in texto.lines() {
        let campos: Vec<&str> = linea.split_whitespace().collect();
        if campos.len() < 10 {
            continue;
        }
        let (Some(destino), Some(puerta)) =
            (ipv6_de_hex_plano(campos[0]), ipv6_de_hex_plano(campos[4]))
        else {
            continue;
        };
        let prefijo = u32::from_str_radix(campos[1], 16).unwrap_or(0);
        salida.push(Ruta {
            interfaz: campos[9].to_string(),
            destino: destino.to_string(),
            puerta: puerta.to_string(),
            mascara: format!("/{prefijo}"),
            metrica: i64::from_str_radix(campos[5], 16).unwrap_or(0),
            familia: "ipv6",
        });
    }
    salida
}

impl Tabla for Rutas {
    fn esquema(&self) -> &'static Esquema {
        &esq::ROUTES
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let v4 = ctx.leer_texto("proc/net/route")?;
        let mut rutas = analizar_rutas_v4(&v4);
        let mut salida = Filas::default();

        // IPv6 puede no estar compilado en el nucleo. No es un fallo de la
        // tabla: es una maquina sin IPv6, y se declara como hueco.
        match ctx.leer_texto_opcional("proc/net/ipv6_route")? {
            Some(t) => rutas.extend(analizar_rutas_v6(&t)),
            None => salida.avisar(
                "/proc/net/ipv6_route",
                MotivoNoLeible::NoExisteEnEsteNucleo {
                    interfaz: "IPv6 (/proc/net/ipv6_route)",
                },
            ),
        }

        let mut c = Constructor::nuevo(self.esquema());
        for r in rutas {
            salida.examinadas += 1;
            let por_defecto = r.destino == "0.0.0.0" || r.destino == "::";
            c.texto("destination", r.destino);
            c.texto("netmask", r.mascara);
            c.texto("gateway", r.puerta);
            c.texto("interface", r.interfaz);
            c.entero("metric", r.metrica);
            c.texto("family", r.familia);
            c.booleano("is_default", por_defecto);
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// interfaces
// ---------------------------------------------------------------------------

/// Bandera `IFF_PROMISC` en `/sys/class/net/<if>/flags`.
const IFF_PROMISC: u64 = 0x100;

/// Las interfaces de red.
#[derive(Debug, Clone, Copy, Default)]
pub struct Interfaces;

/// Tipo de interfaz por su numero `ARPHRD` y su nombre.
fn clase_de_interfaz(tipo: u32, nombre: &str, hay_directorio_tunel: bool) -> &'static str {
    match tipo {
        772 => "loopback",
        768 | 776 | 778 => "tunnel",
        1 if nombre.starts_with("veth") => "veth",
        1 if nombre.starts_with("br") || nombre.starts_with("docker") => "bridge",
        1 => "ethernet",
        65534 if hay_directorio_tunel => "wireguard",
        65534 => "tunnel",
        _ => "other",
    }
}

impl Tabla for Interfaces {
    fn esquema(&self) -> &'static Esquema {
        &esq::INTERFACES
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let directorios = ctx.listar("sys/class/net")?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());

        for dir in directorios {
            let Some(nombre) = dir.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            salida.examinadas += 1;
            let leer = |hoja: &str| {
                std::fs::read_to_string(dir.join(hoja))
                    .ok()
                    .map(|s| s.trim().to_string())
            };

            c.texto("name", nombre);
            c.texto_opcional("mac", leer("address"));
            c.texto_opcional("state", leer("operstate"));
            if let Some(mtu) = leer("mtu").and_then(|s| s.parse::<i64>().ok()) {
                c.entero("mtu", mtu);
            }

            let tipo = leer("type")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            let tunel = dir.join("tun_flags").exists() || dir.join("wireguard").exists();
            c.texto("kind", clase_de_interfaz(tipo, nombre, tunel));

            // Las banderas vienen en hexadecimal con prefijo `0x`.
            match leer("flags")
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            {
                Some(banderas) => c.booleano("promiscuous", banderas & IFF_PROMISC != 0),
                // Sin banderas no se afirma que NO esta en promiscuo: seria
                // decir que nadie captura cuando no se ha podido comprobar.
                None => c.pon("promiscuous", aegis_parser::valor::Valor::Ausente),
            };

            for (columna, hoja) in [
                ("rx_bytes", "statistics/rx_bytes"),
                ("tx_bytes", "statistics/tx_bytes"),
            ] {
                if let Some(n) = leer(hoja).and_then(|s| s.parse::<i64>().ok()) {
                    c.entero(columna, n);
                }
            }
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// arp_cache
// ---------------------------------------------------------------------------

/// La tabla de vecinos.
#[derive(Debug, Clone, Copy, Default)]
pub struct Arp;

/// Una entrada de la tabla de vecinos, ya descompuesta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vecino {
    /// Direccion IP.
    pub direccion: String,
    /// Direccion fisica.
    pub mac: String,
    /// Interfaz.
    pub interfaz: String,
    /// Banderas en hexadecimal.
    pub banderas: String,
    /// Entrada estatica.
    pub permanente: bool,
}

/// Bandera `ATF_PERM` de una entrada ARP estatica.
const ATF_PERM: u64 = 0x04;

/// Analiza `/proc/net/arp`.
pub fn analizar_arp(texto: &str) -> Vec<Vecino> {
    let mut salida = Vec::new();
    for linea in texto.lines().skip(1) {
        let campos: Vec<&str> = linea.split_whitespace().collect();
        if campos.len() < 6 {
            continue;
        }
        let banderas = u64::from_str_radix(campos[2].trim_start_matches("0x"), 16).unwrap_or(0);
        salida.push(Vecino {
            direccion: campos[0].to_string(),
            mac: campos[3].to_string(),
            interfaz: campos[5].to_string(),
            banderas: campos[2].to_string(),
            permanente: banderas & ATF_PERM != 0,
        });
    }
    salida
}

impl Tabla for Arp {
    fn esquema(&self) -> &'static Esquema {
        &esq::ARP_CACHE
    }

    fn coste(&self) -> Coste {
        Coste::Barato
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let texto = ctx.leer_texto("proc/net/arp")?;
        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());
        for v in analizar_arp(&texto) {
            salida.examinadas += 1;
            c.texto("address", v.direccion);
            c.texto("mac", v.mac);
            c.texto("interface", v.interfaz);
            c.texto("flags", v.banderas);
            c.booleano("permanent", v.permanente);
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// firewall_rules
// ---------------------------------------------------------------------------

/// Las reglas del cortafuegos del sistema.
#[derive(Debug, Clone, Copy, Default)]
pub struct Cortafuegos;

impl Tabla for Cortafuegos {
    fn esquema(&self) -> &'static Esquema {
        &esq::FIREWALL_RULES
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn leer(&self, ctx: &Contexto, _filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        use aegis_scal::netfilter::NetworkFilter;

        if !ctx.es_el_sistema_real() {
            return Err(MotivoNoLeible::NoAplicaEnEstaPlataforma {
                interfaz: "el cortafuegos del nucleo; no se puede redirigir a otra raiz",
            });
        }

        let filtro_del_sistema = aegis_scal::linux::netfilter::NftablesFilter::new();
        // Las reglas propias del producto. Lo que NO se puede hacer sin lanzar
        // `nft` es enumerar el ruleset AJENO entero, y eso se DECLARA abajo en
        // vez de fingir que el cortafuegos del cliente esta vacio.
        let bloqueadas = filtro_del_sistema.blocked().map_err(desde_scal)?;

        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());
        for (i, b) in bloqueadas.iter().enumerate() {
            salida.examinadas += 1;
            c.texto("backend", "nftables");
            c.texto("table", aegis_scal::linux::netfilter::TABLA);
            c.texto("chain", "blocked");
            c.texto(
                "rule",
                format!("drop ip saddr {} # {}", b.addr, b.reason.as_str()),
            );
            c.entero("position", i as i64);
            c.booleano("is_ours", true);
            salida.filas.push(c.fin());
        }

        // EL MURO, declarado en la propia respuesta: esta tabla ve lo que puso
        // AegisCore, no la politica entera del cliente. Decirlo es la diferencia
        // entre una tabla incompleta y una tabla que engaña.
        salida.avisar(
            "el ruleset completo del sistema",
            MotivoNoLeible::NoExisteEnEsteNucleo {
                interfaz: "netlink de nftables; solo se enumeran las reglas propias de AegisCore",
            },
        );
        Ok(salida)
    }
}

// ---------------------------------------------------------------------------
// unix_sockets
// ---------------------------------------------------------------------------

/// Los sockets de dominio UNIX.
#[derive(Debug, Clone, Copy, Default)]
pub struct SocketsUnix;

/// Un socket de dominio UNIX, ya descompuesto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketUnix {
    /// Inodo.
    pub inodo: u64,
    /// Ruta, vacia si es anonimo.
    pub ruta: String,
    /// Estado.
    pub estado: &'static str,
    /// Tipo.
    pub clase: &'static str,
    /// Vive en el espacio de nombres abstracto.
    pub abstracto: bool,
}

/// Bandera de `/proc/net/unix` que marca un socket a la escucha.
const SO_ACCEPTCON: u64 = 0x0001_0000;

/// Analiza `/proc/net/unix`.
pub fn analizar_unix(texto: &str) -> Vec<SocketUnix> {
    let mut salida = Vec::new();
    for linea in texto.lines().skip(1) {
        let campos: Vec<&str> = linea.split_whitespace().collect();
        if campos.len() < 7 {
            continue;
        }
        let banderas = u64::from_str_radix(campos[3], 16).unwrap_or(0);
        let clase = match u32::from_str_radix(campos[4], 16).unwrap_or(0) {
            1 => "stream",
            2 => "datagram",
            5 => "seqpacket",
            _ => "other",
        };
        let estado = match u32::from_str_radix(campos[5], 16).unwrap_or(0) {
            1 if banderas & SO_ACCEPTCON != 0 => "listening",
            1 => "disconnected",
            2 => "connecting",
            3 => "connected",
            _ => "unknown",
        };
        let ruta = campos.get(7).copied().unwrap_or("");
        // Un socket abstracto empieza por un byte nulo, que /proc escribe como
        // `@`. No tiene fichero: ninguna tabla de ficheros lo vera nunca.
        let abstracto = ruta.starts_with('@');
        salida.push(SocketUnix {
            inodo: campos[6].parse().unwrap_or(0),
            ruta: ruta.to_string(),
            estado,
            clase,
            abstracto,
        });
    }
    salida
}

impl Tabla for SocketsUnix {
    fn esquema(&self) -> &'static Esquema {
        &esq::UNIX_SOCKETS
    }

    fn coste(&self) -> Coste {
        Coste::Medio
    }

    fn clase(&self) -> Option<Clase> {
        Some(Clase::Flujo)
    }

    fn leer(&self, ctx: &Contexto, filtro: &Filtro) -> Result<Filas, MotivoNoLeible> {
        let texto = ctx.leer_texto("proc/net/unix")?;
        let sockets = analizar_unix(&texto);

        // El indice inodo -> pid es la parte cara: se construye UNA vez y solo
        // si la consulta necesita la columna `pid`.
        let indice = if filtro.necesita("pid") && ctx.es_el_sistema_real() {
            aegis_scal::linux::net::indice_de_inodos()
        } else {
            std::collections::HashMap::new()
        };

        let mut salida = Filas::default();
        let mut c = Constructor::nuevo(self.esquema());
        for s in sockets {
            salida.examinadas += 1;
            c.texto("path", s.ruta);
            c.entero("inode", i64::try_from(s.inodo).unwrap_or(i64::MAX));
            c.texto("state", s.estado);
            c.texto("kind", s.clase);
            c.booleano("abstract_ns", s.abstracto);
            // Sin proceso atribuido el valor queda AUSENTE, no a cero: el pid 0
            // existe y decir que un socket es del pid 0 seria falso.
            if let Some(pid) = indice.get(&s.inodo) {
                c.entero("pid", i64::from(*pid));
            }
            salida.filas.push(c.fin());
        }
        Ok(salida)
    }
}

/// Las cinco tablas de esta familia, para el catalogo.
pub fn tablas() -> Vec<Box<dyn Tabla>> {
    vec![
        Box::new(Rutas),
        Box::new(Interfaces),
        Box::new(Arp),
        Box::new(Cortafuegos),
        Box::new(SocketsUnix),
    ]
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ctx() -> Contexto {
        Contexto::del_sistema(aegis_entidad::entidad::maquina("prueba"), 0, 0)
    }

    fn columna(t: &dyn Tabla, nombre: &str) -> usize {
        t.esquema()
            .columnas
            .iter()
            .position(|c| c.nombre == nombre)
            .unwrap_or_else(|| panic!("falta {nombre} en {}", t.nombre()))
    }

    #[test]
    fn una_direccion_v4_de_proc_se_decodifica_al_derecho() {
        // `0100007F` es 127.0.0.1 en little-endian. Leerlo al reves da
        // 1.0.0.127, que es una direccion de otro.
        assert_eq!(ipv4_de_hex("0100007F"), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(ipv4_de_hex("00000000"), Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(ipv4_de_hex("corto"), None);
    }

    #[test]
    fn la_ruta_ipv6_usa_orden_de_red_y_no_el_del_anfitrion() {
        // `/proc/net/ipv6_route` NO usa el mismo formato que `/proc/net/tcp6`.
        // Tratarlos igual produce direcciones inventadas, que es el defecto que
        // esta fase corrigio en `aegis-scal`.
        assert_eq!(
            ipv6_de_hex_plano("00000000000000000000000000000001"),
            Some(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            ipv6_de_hex_plano("20010db8000000000000000000000000"),
            Some(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0))
        );
        assert_eq!(ipv6_de_hex_plano("corto"), None);
    }

    #[test]
    fn la_tabla_de_rutas_v4_se_analiza() {
        let texto = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0";
        let rutas = analizar_rutas_v4(texto);
        assert_eq!(rutas.len(), 2);
        assert_eq!(rutas[0].destino, "0.0.0.0");
        assert_eq!(rutas[0].puerta, "172.17.0.1");
        assert_eq!(rutas[0].metrica, 100);
        assert_eq!(rutas[1].destino, "172.17.0.0");
        assert_eq!(rutas[1].puerta, "0.0.0.0");
    }

    #[test]
    fn una_linea_de_rutas_truncada_se_salta() {
        assert!(analizar_rutas_v4("cabecera\neth0 00").is_empty());
        assert!(analizar_rutas_v4("").is_empty());
    }

    #[test]
    fn en_esta_maquina_hay_rutas_y_alguna_es_la_de_por_defecto() {
        let c = ctx();
        let r = Rutas.leer(&c, &Filtro::ninguno()).expect("leer rutas");
        assert!(!r.filas.is_empty(), "una maquina en red tiene rutas");
        let i = columna(&Rutas, "is_default");
        let hay_defecto = r
            .filas
            .iter()
            .any(|f| f.valor(i) == &aegis_parser::valor::Valor::Booleano(true));
        assert!(hay_defecto, "no se encontro ruta por defecto");
    }

    #[test]
    fn las_interfaces_de_esta_maquina_incluyen_loopback() {
        let c = ctx();
        let r = Interfaces
            .leer(&c, &Filtro::ninguno())
            .expect("leer interfaces");
        let i_nombre = columna(&Interfaces, "name");
        let i_kind = columna(&Interfaces, "kind");
        let lo = r
            .filas
            .iter()
            .find(|f| f.valor(i_nombre).a_texto() == "lo")
            .expect("toda maquina tiene loopback");
        assert_eq!(lo.valor(i_kind).a_texto(), "loopback");
    }

    #[test]
    fn el_tipo_de_interfaz_se_deduce_del_numero_y_del_nombre() {
        assert_eq!(clase_de_interfaz(772, "lo", false), "loopback");
        assert_eq!(clase_de_interfaz(1, "eth0", false), "ethernet");
        assert_eq!(clase_de_interfaz(1, "veth1234", false), "veth");
        assert_eq!(clase_de_interfaz(1, "docker0", false), "bridge");
        assert_eq!(clase_de_interfaz(65534, "wg0", true), "wireguard");
        assert_eq!(clase_de_interfaz(65534, "tun0", false), "tunnel");
    }

    #[test]
    fn la_tabla_arp_se_analiza_con_su_bandera_de_permanente() {
        let texto = "\
IP address       HW type     Flags       HW address            Mask     Device
172.17.0.1       0x1         0x2         02:42:ab:cd:ef:01     *        eth0
172.17.0.9       0x1         0x6         02:42:ab:cd:ef:09     *        eth0";
        let vs = analizar_arp(texto);
        assert_eq!(vs.len(), 2);
        assert_eq!(vs[0].direccion, "172.17.0.1");
        assert_eq!(vs[0].mac, "02:42:ab:cd:ef:01");
        assert!(!vs[0].permanente, "0x2 no lleva ATF_PERM");
        assert!(vs[1].permanente, "0x6 si lleva ATF_PERM");
    }

    #[test]
    fn dos_vecinos_con_la_misma_mac_son_visibles_en_la_tabla() {
        // Es la firma del envenenamiento ARP, y la tabla tiene que dejar verla.
        let texto = "\
IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
10.0.0.2         0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0";
        let vs = analizar_arp(texto);
        assert_eq!(vs.len(), 2);
        assert_eq!(vs[0].mac, vs[1].mac);
        assert_ne!(vs[0].direccion, vs[1].direccion);
    }

    #[test]
    fn los_sockets_unix_se_analizan_con_su_estado_y_su_tipo() {
        let texto = "\
Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 12345 /run/systemd/private
0000000000000000: 00000003 00000000 00000000 0001 03 12346 /run/docker.sock
0000000000000000: 00000002 00000000 00010000 0002 01 12347 @abstracto";
        let ss = analizar_unix(texto);
        assert_eq!(ss.len(), 3);

        assert_eq!(ss[0].estado, "listening");
        assert_eq!(ss[0].clase, "stream");
        assert_eq!(ss[0].inodo, 12_345);
        assert!(!ss[0].abstracto);

        assert_eq!(ss[1].estado, "connected");

        assert_eq!(ss[2].clase, "datagram");
        assert!(ss[2].abstracto, "el que empieza por @ es abstracto");
    }

    #[test]
    fn un_socket_sin_ruta_no_rompe_el_analisis() {
        // Los sockets anonimos no traen la ultima columna.
        let texto = "\
Num       RefCount Protocol Flags    Type St Inode
0000000000000000: 00000002 00000000 00000000 0001 03 999";
        let ss = analizar_unix(texto);
        assert_eq!(ss.len(), 1);
        assert_eq!(ss[0].ruta, "");
        assert!(!ss[0].abstracto);
    }

    #[test]
    fn en_esta_maquina_hay_sockets_unix() {
        let c = ctx();
        let r = SocketsUnix
            .leer(&c, &Filtro::ninguno())
            .expect("leer sockets unix");
        assert!(
            !r.filas.is_empty(),
            "una maquina viva tiene sockets locales"
        );
    }

    #[test]
    fn el_cortafuegos_declara_lo_que_no_puede_ver() {
        // La tabla ve las reglas propias; el ruleset ajeno completo NO, y eso
        // se dice en la respuesta en vez de fingir que esta vacio.
        let c = ctx();
        match Cortafuegos.leer(&c, &Filtro::ninguno()) {
            Ok(r) => {
                assert!(
                    r.avisos.iter().any(|a| a.sujeto.contains("ruleset")),
                    "no declaro el muro"
                );
            }
            // Sin `nft` instalado, el motivo tambien es una respuesta correcta.
            Err(m) => assert!(!m.frase().is_empty()),
        }
    }

    #[test]
    fn ninguna_tabla_de_red_entra_en_panico_con_entrada_basura() {
        // Estas tablas leen texto que escribe el nucleo, pero un nucleo raro o
        // un /proc montado a mano no pueden tumbar el agente.
        for basura in ["", "\n\n\n", "cabecera\n\0\0\0", "a b c d e f g h i j k"] {
            let _ = analizar_rutas_v4(basura);
            let _ = analizar_rutas_v6(basura);
            let _ = analizar_arp(basura);
            let _ = analizar_unix(basura);
        }
    }
}
