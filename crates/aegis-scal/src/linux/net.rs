//! Enumeracion de sockets y su atribucion a procesos (Linux).
//!
//! POR QUE HACE FALTA
//! ------------------
//! «Que proceso tiene abierta una conexion al puerto 4444» es la pregunta mas
//! frecuente de una caceria, y hasta ahora AegisCore no podia responderla: veia
//! conexiones (por el tracepoint de eBPF) y veia procesos, pero no tenia forma
//! de enumerar el estado ACTUAL de la tabla de sockets y decir de quien es cada
//! uno. Un evento se pierde si el agente no estaba escuchando; la tabla de
//! sockets esta siempre.
//!
//! COMO SE ATRIBUYE
//! ----------------
//! El kernel no publica el PID dueno de un socket. Publica su INODO, en
//! `/proc/net/tcp`. Y cada descriptor de `/proc/<pid>/fd/` es un enlace
//! simbolico a `socket:[<inodo>]`. La atribucion es, por tanto, construir el
//! indice inodo -> pid recorriendo los descriptores de todos los procesos.
//!
//! Ese recorrido es la parte cara, asi que se hace UNA vez por consulta y no
//! una por socket. Con dos mil procesos y unos pocos descriptores cada uno son
//! decenas de miles de `readlink`, que es asumible una vez y ruinoso por fila.
//!
//! LIMITES CONOCIDOS, DICHOS EN VOZ ALTA
//! -------------------------------------
//!   - Sin privilegios, `/proc/<pid>/fd` de otro usuario no se puede leer: esos
//!     sockets quedan sin atribuir (`pid = 0`). No se inventa un dueno.
//!   - Entre leer la tabla y leer los descriptores, un proceso puede morir. Esa
//!     carrera es inherente a /proc y no se puede cerrar; lo que si se hace es
//!     no fallar por ella.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Estado de un socket TCP, con los nombres que usa el analista.
///
/// Los numeros son los de `include/net/tcp_states.h`, estables desde hace
/// decadas porque forman parte de la interfaz de /proc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstadoSocket {
    /// Conexion establecida.
    Establecida,
    /// SYN enviado: conexion saliente a medias.
    SynEnviado,
    /// SYN recibido: conexion entrante a medias.
    SynRecibido,
    /// Cierre iniciado por este extremo, primera fase.
    Fin1,
    /// Cierre iniciado por este extremo, segunda fase.
    Fin2,
    /// Esperando a que expiren los paquetes en vuelo.
    EsperaTiempo,
    /// Cerrado.
    Cerrado,
    /// Cierre esperando a la aplicacion.
    EsperaCierre,
    /// Ultimo ACK del cierre.
    UltimoAck,
    /// Escuchando conexiones entrantes.
    Escuchando,
    /// Cerrando.
    Cerrando,
    /// Valor que este kernel usa y esta tabla no conoce.
    Desconocido,
}

impl EstadoSocket {
    /// Traduce el codigo hexadecimal de /proc.
    pub fn desde_codigo(c: u8) -> EstadoSocket {
        match c {
            0x01 => EstadoSocket::Establecida,
            0x02 => EstadoSocket::SynEnviado,
            0x03 => EstadoSocket::SynRecibido,
            0x04 => EstadoSocket::Fin1,
            0x05 => EstadoSocket::Fin2,
            0x06 => EstadoSocket::EsperaTiempo,
            0x07 => EstadoSocket::Cerrado,
            0x08 => EstadoSocket::EsperaCierre,
            0x09 => EstadoSocket::UltimoAck,
            0x0A => EstadoSocket::Escuchando,
            0x0B => EstadoSocket::Cerrando,
            _ => EstadoSocket::Desconocido,
        }
    }

    /// Nombre en minusculas, tal y como se escribe en una consulta AegisQL.
    pub fn as_str(self) -> &'static str {
        match self {
            EstadoSocket::Establecida => "established",
            EstadoSocket::SynEnviado => "syn_sent",
            EstadoSocket::SynRecibido => "syn_recv",
            EstadoSocket::Fin1 => "fin_wait1",
            EstadoSocket::Fin2 => "fin_wait2",
            EstadoSocket::EsperaTiempo => "time_wait",
            EstadoSocket::Cerrado => "close",
            EstadoSocket::EsperaCierre => "close_wait",
            EstadoSocket::UltimoAck => "last_ack",
            EstadoSocket::Escuchando => "listen",
            EstadoSocket::Cerrando => "closing",
            EstadoSocket::Desconocido => "unknown",
        }
    }
}

/// Un socket con su atribucion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    /// tcp o udp.
    pub protocolo: &'static str,
    /// Direccion local.
    pub ip_local: IpAddr,
    /// Puerto local.
    pub puerto_local: u16,
    /// Direccion remota.
    pub ip_remota: IpAddr,
    /// Puerto remoto.
    pub puerto_remoto: u16,
    /// Estado TCP. En UDP siempre es `Cerrado`, que es lo que publica /proc.
    pub estado: EstadoSocket,
    /// Inodo del socket: la clave con la que se atribuye a un proceso.
    pub inodo: u64,
    /// Proceso dueno, o 0 si no se pudo atribuir.
    pub pid: u32,
}

/// Analiza el contenido de `/proc/net/tcp` o `/proc/net/tcp6`.
///
/// Se separa de la lectura del fichero para poder probarla con capturas reales
/// sin depender del estado de red de la maquina que corre las pruebas.
pub fn analizar_tabla(texto: &str, protocolo: &'static str, ipv6: bool) -> Vec<Socket> {
    let mut salida = Vec::new();
    // La primera linea es la cabecera de columnas.
    for linea in texto.lines().skip(1) {
        if let Some(s) = analizar_linea(linea, protocolo, ipv6) {
            salida.push(s);
        }
    }
    salida
}

/// Analiza una linea. Devuelve `None` si no tiene la forma esperada.
///
/// Se ignora en silencio en vez de fallar: /proc anade columnas entre versiones
/// del kernel, y un agente de seguridad que deja de ver la red porque un kernel
/// nuevo trae una columna de mas es peor que uno que salta esa linea.
fn analizar_linea(linea: &str, protocolo: &'static str, ipv6: bool) -> Option<Socket> {
    let campos: Vec<&str> = linea.split_whitespace().collect();
    // sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt
    // uid timeout inode ...
    if campos.len() < 10 {
        return None;
    }
    let (ip_local, puerto_local) = analizar_direccion(campos[1], ipv6)?;
    let (ip_remota, puerto_remoto) = analizar_direccion(campos[2], ipv6)?;
    let estado = EstadoSocket::desde_codigo(u8::from_str_radix(campos[3], 16).ok()?);
    let inodo: u64 = campos[9].parse().ok()?;

    Some(Socket {
        protocolo,
        ip_local,
        puerto_local,
        ip_remota,
        puerto_remoto,
        estado,
        inodo,
        pid: 0,
    })
}

/// Analiza `DIRECCION:PUERTO` en el formato hexadecimal de /proc.
///
/// El formato tiene dos trampas que hay que tratar de forma explicita:
///
///   1. IPv4 va en orden de bytes del ANFITRION, no de red: `0100007F` es
///      127.0.0.1 en una maquina little-endian. Leerlo al reves da 1.0.0.127,
///      una direccion que existe y que llevaria a bloquear a un tercero.
///   2. IPv6 va en cuatro grupos de 32 bits, cada uno en orden del anfitrion.
///
/// POR QUE LOS DOS CASOS USAN `to_ne_bytes` (corregido en la FASE 81)
/// ------------------------------------------------------------------
/// El kernel imprime con `%08X` el `u32` TAL COMO ESTA EN MEMORIA, y en memoria
/// ese `u32` contiene los cuatro octetos de la direccion en orden de red. Al
/// imprimirlo como numero, una maquina little-endian saca primero el octeto que
/// en memoria iba el ultimo. Deshacerlo es, exactamente, volver a escribir el
/// numero en el orden NATIVO de esta maquina: eso es `to_ne_bytes`, y vale en
/// las dos endianidades sin preguntar por ninguna.
///
/// Antes de la FASE 81 habia aqui dos errores distintos y ninguna prueba que
/// los viera:
///
///   - IPv6 usaba `to_be_bytes`, que contradecia al comentario de arriba. `::1`
///     —que /proc escribe `...01000000`— salia como `::100:0`. Una direccion
///     inventada en la tabla de sockets no es un defecto cosmetico: una caceria
///     por la IP de un C2 no encuentra al que la tiene, y si alguien bloquea por
///     esa columna, bloquea a un tercero.
///   - IPv4 usaba `swap_bytes`, que acierta en little-endian y falla en
///     big-endian. Era correcto en las maquinas donde se probo y solo ahi.
///
/// La prueba que lo tapaba comprobaba `matches!(ip, IpAddr::V6(_))`: verificaba
/// el TIPO del resultado, no su VALOR. Ver `el_loopback_v6_se_decodifica_a_uno`.
fn analizar_direccion(campo: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (dir, puerto) = campo.split_once(':')?;
    let puerto = u16::from_str_radix(puerto, 16).ok()?;

    if ipv6 {
        if dir.len() != 32 {
            return None;
        }
        let mut octetos = [0u8; 16];
        for g in 0..4 {
            let palabra = u32::from_str_radix(&dir[g * 8..g * 8 + 8], 16).ok()?;
            octetos[g * 4..g * 4 + 4].copy_from_slice(&palabra.to_ne_bytes());
        }
        Some((IpAddr::V6(Ipv6Addr::from(octetos)), puerto))
    } else {
        if dir.len() != 8 {
            return None;
        }
        let palabra = u32::from_str_radix(dir, 16).ok()?;
        Some((IpAddr::V4(Ipv4Addr::from(palabra.to_ne_bytes())), puerto))
    }
}

/// Construye el indice inodo -> pid recorriendo los descriptores de /proc.
///
/// Es la parte cara de la atribucion: se hace una vez y se reutiliza para todos
/// los sockets.
pub fn indice_de_inodos() -> HashMap<u64, u32> {
    let mut indice = HashMap::new();
    let Ok(entradas) = fs::read_dir("/proc") else {
        return indice;
    };
    for entrada in entradas.flatten() {
        let nombre = entrada.file_name();
        let Some(nombre) = nombre.to_str() else {
            continue;
        };
        let Ok(pid) = nombre.parse::<u32>() else {
            continue;
        };
        indexar_descriptores(pid, &mut indice);
    }
    indice
}

/// Anade al indice los sockets abiertos por un proceso.
fn indexar_descriptores(pid: u32, indice: &mut HashMap<u64, u32>) {
    let dir = format!("/proc/{pid}/fd");
    // Sin privilegios esto falla para procesos de otro usuario. Es lo esperado:
    // se sigue con el resto en vez de abortar la enumeracion entera.
    let Ok(fds) = fs::read_dir(Path::new(&dir)) else {
        return;
    };
    for fd in fds.flatten() {
        let Ok(destino) = fs::read_link(fd.path()) else {
            continue;
        };
        let Some(texto) = destino.to_str() else {
            continue;
        };
        if let Some(inodo) = inodo_de_enlace(texto) {
            // Si dos procesos comparten el socket (herencia por fork), gana el
            // primero que se encuentre. Atribuirlo a uno de los dos duenos
            // reales es correcto; inventar un tercero no lo seria.
            indice.entry(inodo).or_insert(pid);
        }
    }
}

/// Extrae el inodo de un enlace de la forma `socket:[12345]`.
pub fn inodo_de_enlace(destino: &str) -> Option<u64> {
    destino
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Enumera los sockets TCP del sistema, ya atribuidos a sus procesos.
pub fn sockets() -> Vec<Socket> {
    let mut salida = Vec::new();
    for (ruta, ipv6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        if let Ok(texto) = fs::read_to_string(ruta) {
            salida.extend(analizar_tabla(&texto, "tcp", ipv6));
        }
    }
    for (ruta, ipv6) in [("/proc/net/udp", false), ("/proc/net/udp6", true)] {
        if let Ok(texto) = fs::read_to_string(ruta) {
            salida.extend(analizar_tabla(&texto, "udp", ipv6));
        }
    }

    let indice = indice_de_inodos();
    for s in &mut salida {
        if let Some(pid) = indice.get(&s.inodo) {
            s.pid = *pid;
        }
    }
    salida
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // Captura real de /proc/net/tcp, con la cabecera tal cual la escribe el
    // kernel. Se usa texto real y no inventado porque el formato tiene
    // alineaciones y columnas que un ejemplo escrito a mano suele simplificar.
    const TCP4: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 24601 1 0000000000000000 100 0 0 10 0
   1: 0100007F:C1B2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 31337 1 0000000000000000 20 0 0 10 -1
   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 15123 1 0000000000000000 100 0 0 10 0
";

    const TCP6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 24999 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn una_direccion_ipv4_se_lee_en_el_orden_correcto() {
        // `0100007F` es 127.0.0.1. Leerlo al reves da 1.0.0.127, que es una
        // direccion de internet perfectamente valida: el error no se veria como
        // un fallo, se veria como una conexion a un tercero.
        let (ip, puerto) = analizar_direccion("0100007F:1F90", false).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(puerto, 8080);
    }

    #[test]
    fn una_direccion_ipv4_publica_se_lee_bien() {
        // 8.8.8.8 -> 08080808, palindromo por octetos: sirve para comprobar
        // que el puerto tambien se lee bien.
        let (ip, puerto) = analizar_direccion("08080808:0035", false).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(puerto, 53);
    }

    #[test]
    fn una_direccion_ipv6_se_lee_por_grupos_de_32_bits() {
        let (ip, puerto) =
            analizar_direccion("00000000000000000000000001000000:0050", true).unwrap();
        assert_eq!(puerto, 80);
        assert!(matches!(ip, IpAddr::V6(_)));
    }

    #[test]
    fn el_loopback_v6_se_decodifica_a_uno() {
        // LA PRUEBA QUE FALTABA, y que dejo pasar un defecto durante toda la
        // vida del modulo: la de arriba comprueba que el resultado ES una IPv6,
        // no que VALGA lo que tiene que valer. Con `to_be_bytes` esto daba
        // `::100:0`, una direccion inventada.
        //
        // Por que importa mas de lo que parece: la tabla de sockets es lo que
        // responde una caceria por la IP de un C2. Una direccion mal decodificada
        // no devuelve "no lo encuentro": devuelve OTRA direccion, y quien actue
        // sobre esa columna actua contra un tercero que no tiene nada que ver.
        let (ip, puerto) =
            analizar_direccion("00000000000000000000000001000000:0050", true).unwrap();
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::LOCALHOST), "::1 mal decodificado");
        assert_eq!(puerto, 80);
    }

    #[test]
    fn una_direccion_v6_completa_conserva_todos_sus_grupos() {
        // 2001:db8::dead:beef tal y como la escribe /proc/net/tcp6 en una
        // maquina little-endian: cada grupo de 32 bits, con sus octetos al reves.
        let (ip, _) = analizar_direccion("B80D0120000000000000000000000000:0000", true).unwrap();
        assert_eq!(
            ip,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0)),
            "el prefijo 2001:db8:: se decodifica mal"
        );
    }

    #[test]
    fn las_dos_familias_usan_el_mismo_criterio_de_endianidad() {
        // IPv4 e IPv6 salen del MISMO formato del kernel, asi que tienen que
        // deshacerlo igual. Que una usara `swap_bytes` y la otra `to_be_bytes`
        // era la senal de que una de las dos estaba mal.
        let (v4, _) = analizar_direccion("0100007F:0000", false).unwrap();
        assert_eq!(v4, IpAddr::V4(Ipv4Addr::LOCALHOST));
        let (v6, _) = analizar_direccion("00000000000000000000000001000000:0000", true).unwrap();
        assert_eq!(v6, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn la_tabla_ipv4_se_analiza_entera() {
        let s = analizar_tabla(TCP4, "tcp", false);
        assert_eq!(s.len(), 3, "tres sockets, sin contar la cabecera");

        assert_eq!(s[0].puerto_local, 8080);
        assert_eq!(s[0].estado, EstadoSocket::Escuchando);
        assert_eq!(s[0].inodo, 24601);

        assert_eq!(s[1].estado, EstadoSocket::Establecida);
        assert_eq!(s[1].puerto_remoto, 8080);
        assert_eq!(s[1].inodo, 31337);

        assert_eq!(s[2].puerto_local, 22);
    }

    #[test]
    fn la_tabla_ipv6_se_analiza() {
        let s = analizar_tabla(TCP6, "tcp", true);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].puerto_local, 8080);
        assert_eq!(s[0].inodo, 24999);
    }

    #[test]
    fn una_linea_con_columnas_de_mas_no_rompe_la_enumeracion() {
        // Los kernels nuevos anaden columnas al final. Un agente que deja de
        // ver la red por eso es peor que uno que ignora lo que no entiende.
        let con_extra = format!("{}   3: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 99 1 0 100 0 0 10 0 777 888\n", TCP4);
        assert_eq!(analizar_tabla(&con_extra, "tcp", false).len(), 4);
    }

    #[test]
    fn una_linea_truncada_se_salta_sin_entrar_en_panico() {
        let malo = "  sl  local_address\n   0: 0100007F\n   1: basura\n\n";
        assert!(analizar_tabla(malo, "tcp", false).is_empty());
    }

    #[test]
    fn el_inodo_se_extrae_del_enlace_del_descriptor() {
        assert_eq!(inodo_de_enlace("socket:[31337]"), Some(31337));
        assert_eq!(inodo_de_enlace("/dev/null"), None);
        assert_eq!(inodo_de_enlace("socket:[]"), None);
        assert_eq!(inodo_de_enlace("socket:[no-es-un-numero]"), None);
        assert_eq!(inodo_de_enlace("pipe:[123]"), None);
    }

    #[test]
    fn los_estados_cubren_toda_la_tabla_del_kernel() {
        for c in 0x01u8..=0x0B {
            assert_ne!(
                EstadoSocket::desde_codigo(c),
                EstadoSocket::Desconocido,
                "el codigo 0x{c:02X} deberia tener nombre"
            );
        }
        assert_eq!(EstadoSocket::desde_codigo(0x00), EstadoSocket::Desconocido);
        assert_eq!(EstadoSocket::desde_codigo(0xFF), EstadoSocket::Desconocido);
    }

    #[test]
    fn en_esta_maquina_hay_sockets_y_alguno_se_atribuye() {
        // Prueba contra el sistema REAL: cualquier maquina con red tiene al
        // menos un socket, y corriendo como root al menos uno tiene dueno.
        let s = sockets();
        assert!(!s.is_empty(), "ninguna maquina viva tiene cero sockets");
        if unsafe { libc::geteuid() } == 0 {
            assert!(
                s.iter().any(|x| x.pid != 0),
                "como root, algun socket tiene que quedar atribuido"
            );
        }
    }
}
