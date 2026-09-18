//! Ficheros y ejecucion remota: DCERPC, NFS, WebDAV, RDP, VNC y WinRM.
//!
//! # El hecho que los ata
//!
//! El movimiento lateral no se reconoce por el protocolo. Se reconoce porque
//! alguien ejecuto algo en otra maquina, y eso pasa por WinRM, por DCERPC, por
//! SSH y por RDP indistintamente. Los seis emiten [`Hecho::EjecucionRemota`], de
//! modo que «cuantas maquinas ejecutaron algo en otra esta semana» es una
//! consulta y no un proyecto de correlacion.
//!
//! # DCERPC: el interfaz **es** la tecnica
//!
//! De un `bind` de DCERPC sale el UUID del interfaz que el cliente pide, y ese
//! UUID nombra el ataque. `drsuapi` es DCSync; `netlogon` con su patron es
//! Zerologon; `efsrpc` es PetitPotam; `svcctl` es como PsExec crea su servicio;
//! `atsvc` es una tarea programada a distancia. Un sensor que solo diga «vi
//! DCERPC al 135» tiene delante la tecnica y no la nombra.
//!
//! El catalogo de [`INTERFACES`] es lo que convierte dieciseis bytes en una
//! frase que un analista puede leer.

use aegis_wire::error::{ErrorDiseccion, Resultado};
use aegis_wire::hecho::{Hecho, ProtocoloApp};
use aegis_wire::lector::Lector;

use crate::disector::{Contexto, Disector, Fuerza, Salida};
use crate::texto;

// ════════════════════════════════════════════════════════════════════════════
// DCERPC
// ════════════════════════════════════════════════════════════════════════════

/// Puerto del asignador de puntos finales de DCERPC.
pub const PUERTO_EPMAPPER: u16 = 135;

/// Un identificador de interfaz, escrito como se documenta.
///
/// Los cuatro campos son los de la forma canonica `aaaaaaaa-bbbb-cccc-dddd-
/// eeeeeeeeeeee`, y estan asi —y no como dieciseis bytes sueltos— porque en el
/// cable los tres primeros van en el orden del emisor: escribirlos a mano ya
/// invertidos es la clase de error que nadie encuentra revisando.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uuid(pub u32, pub u16, pub u16, pub [u8; 8]);

impl Uuid {
    /// Lee un UUID del cable, respetando el orden que declara el emisor.
    fn leer(l: &mut Lector<'_>, poco_significativo_primero: bool) -> Resultado<Uuid> {
        let (a, b, c) = if poco_significativo_primero {
            (
                l.u32_le("dcerpc.uuid")?,
                l.u16_le("dcerpc.uuid")?,
                l.u16_le("dcerpc.uuid")?,
            )
        } else {
            (
                l.u32("dcerpc.uuid")?,
                l.u16("dcerpc.uuid")?,
                l.u16("dcerpc.uuid")?,
            )
        };
        let resto = l.tomar(8, "dcerpc.uuid")?;
        let mut cola = [0u8; 8];
        cola.copy_from_slice(resto);
        Ok(Uuid(a, b, c, cola))
    }

    /// Como se escribe en un informe.
    #[must_use]
    pub fn texto(&self) -> String {
        let c: String = self.3.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "{:08x}-{:04x}-{:04x}-{}-{}",
            self.0,
            self.1,
            self.2,
            &c[..4],
            &c[4..]
        )
    }
}

/// Los interfaces de DCERPC que nombran una tecnica.
///
/// Cada fila es `(uuid, nombre, para que se usa de verdad)`. La tercera columna
/// no es documentacion de cortesia: es lo que aparece en la alerta, y sin ella
/// el analista tiene dieciseis bytes en hexadecimal.
pub static INTERFACES: &[(Uuid, &str, &str)] = &[
    (
        Uuid(0xe1af_8308, 0x5d1f, 0x11c9, [0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa]),
        "epmapper",
        "el asignador de puntos finales: se pregunta primero para saber por que puerto va todo lo demas",
    ),
    (
        Uuid(0x367a_bb81, 0x9844, 0x35f1, [0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03]),
        "svcctl",
        "el gestor de servicios: crear un servicio a distancia es como PsExec ejecuta codigo en otra maquina",
    ),
    (
        Uuid(0x1ff7_0682, 0x0a51, 0x30e8, [0x07, 0x6d, 0x74, 0x0b, 0xe8, 0xce, 0xf9, 0x8c]),
        "atsvc",
        "el planificador antiguo: una tarea programada a distancia que ejecuta lo que le digan",
    ),
    (
        Uuid(0x86d3_5949, 0x83c9, 0x4044, [0xb4, 0x24, 0xdb, 0x36, 0x32, 0x31, 0xfd, 0x0c]),
        "itaskschedulerservice",
        "el planificador moderno, con el mismo efecto que el anterior",
    ),
    (
        Uuid(0xe351_4235, 0x4b06, 0x11d1, [0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2]),
        "drsuapi",
        "la replicacion del directorio: es por donde se saca el hash de todas las cuentas del dominio (DCSync)",
    ),
    (
        Uuid(0x1234_5778, 0x1234, 0xabcd, [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab]),
        "lsarpc",
        "la autoridad de seguridad local: enumera dominios, confianzas y secretos de politica",
    ),
    (
        Uuid(0x1234_5778, 0x1234, 0xabcd, [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac]),
        "samr",
        "el gestor de cuentas: enumera usuarios y grupos, y cambia contrasenas",
    ),
    (
        Uuid(0x1234_5678, 0x1234, 0xabcd, [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb]),
        "netlogon",
        "el canal seguro del dominio: el fallo de Zerologon vivia aqui y sigue siendo el sitio donde se suplanta a un controlador",
    ),
    (
        Uuid(0x4b32_4fc8, 0x1670, 0x01d3, [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88]),
        "srvsvc",
        "el servicio de servidor: lista los recursos compartidos y las sesiones abiertas",
    ),
    (
        Uuid(0x6bff_d098, 0xa112, 0x3610, [0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a]),
        "wkssvc",
        "el servicio de estacion: dice que usuarios tienen sesion iniciada, que es medio reconocimiento de dominio",
    ),
    (
        Uuid(0x338c_d001, 0x2244, 0x31f1, [0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03]),
        "winreg",
        "el registro remoto: leerlo saca credenciales guardadas y escribirlo deja persistencia",
    ),
    (
        Uuid(0xc681_d488, 0xd850, 0x11d0, [0x8c, 0x52, 0x00, 0xc0, 0x4f, 0xd9, 0x0f, 0x7e]),
        "efsrpc",
        "el sistema de ficheros cifrado: se usa para obligar a una maquina a autenticarse contra otra (PetitPotam)",
    ),
    (
        Uuid(0xdf19_41c5, 0xfe89, 0x4e79, [0xbf, 0x10, 0x46, 0x36, 0x57, 0xac, 0xf4, 0x4d]),
        "efsrpc-alterno",
        "el mismo interfaz por su otro identificador, que es como se evita un filtro que solo mire el primero",
    ),
    (
        Uuid(0x1234_5678, 0x1234, 0xabcd, [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab]),
        "spoolss",
        "la cola de impresion: el interfaz de PrintNightmare y de la coaccion por el servicio de impresion",
    ),
    (
        Uuid(0x8227_3fdc, 0xe32a, 0x18c3, [0x3f, 0x78, 0x82, 0x79, 0x29, 0xdc, 0x23, 0xea]),
        "eventlog",
        "el registro de sucesos remoto: leerlo es reconocimiento y borrarlo es tapar el rastro",
    ),
    (
        Uuid(0x0000_01a0, 0x0000, 0x0000, [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]),
        "iremotescmactivator",
        "la activacion remota de DCOM: por aqui pasa la ejecucion por objetos (MMC20, ShellWindows)",
    ),
    (
        Uuid(0x99fc_fec4, 0x5260, 0x101b, [0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a]),
        "ioxidresolver",
        "el resolutor de DCOM: contestando a esto una maquina revela todas sus direcciones de red",
    ),
    (
        Uuid(0x9556_dc99, 0x828c, 0x11cf, [0xa3, 0x7e, 0x00, 0xaa, 0x00, 0x32, 0x40, 0xc7]),
        "iwbemservices",
        "WMI: ejecutar un metodo por aqui crea un proceso en la maquina de enfrente",
    ),
];

/// Busca un interfaz en el catalogo.
#[must_use]
pub fn interfaz(u: &Uuid) -> Option<(&'static str, &'static str)> {
    INTERFACES
        .iter()
        .find(|(c, _, _)| c == u)
        .map(|(_, n, p)| (*n, *p))
}

/// El tipo de PDU de DCERPC.
fn tipo_dcerpc(t: u8) -> Option<&'static str> {
    Some(match t {
        0 => "peticion",
        2 => "respuesta",
        3 => "fallo",
        11 => "vinculacion",
        12 => "vinculacion-aceptada",
        13 => "vinculacion-rechazada",
        14 => "cambio-de-contexto",
        15 => "cambio-de-contexto-aceptado",
        16 => "autenticacion-en-tres-pasos",
        17 => "cancelar",
        18 => "huerfano",
        _ => return None,
    })
}

/// Disector de DCERPC.
#[derive(Debug, Default, Clone, Copy)]
pub struct Dcerpc;

impl Dcerpc {
    /// La cabecera comun: `(tipo, poco_significativo_primero, longitud)`.
    fn cabecera(datos: &[u8]) -> Resultado<(u8, bool, usize)> {
        let mut l = Lector::nuevo(datos);
        let version = l.u8("dcerpc.version")?;
        if version != 5 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("dcerpc"));
        }
        let menor = l.u8("dcerpc.version-menor")?;
        // Solo existen la 5.0 y la 5.1.
        if menor > 1 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("dcerpc"));
        }
        let tipo = l.u8("dcerpc.tipo")?;
        if tipo_dcerpc(tipo).is_none() {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("dcerpc"));
        }
        let _banderas = l.u8("dcerpc.banderas")?;
        // LOS CUATRO BYTES DE LA REPRESENTACION DE DATOS SON FIJOS, y exigirlos
        // enteros no es rigor de mas: sin ellos, «version 5, tipo conocido,
        // longitud razonable» le pasa a cualquier cosa. Se midio: una peticion
        // de SOCKS 5 encajaba como una peticion de DCERPC.
        //
        //   byte 0, nibble alto: orden de los enteros (0 grande, 1 pequeno)
        //   byte 0, nibble bajo: juego de caracteres (0 ASCII, 1 EBCDIC)
        //   byte 1:             coma flotante (0 IEEE, 1 VAX, 2 Cray, 3 IBM)
        //   bytes 2 y 3:        reservados, y valen cero
        let representacion = l.u8("dcerpc.representacion")?;
        let orden = representacion >> 4;
        if orden > 1 || (representacion & 0x0F) > 1 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("dcerpc"));
        }
        let poco = orden == 1;
        let flotante = l.u8("dcerpc.representacion-de-flotante")?;
        if flotante > 3 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("dcerpc"));
        }
        let reservado = l.tomar(2, "dcerpc.representacion-reservada")?;
        if reservado != [0, 0] {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("dcerpc"));
        }
        let largo = if poco {
            l.u16_le("dcerpc.longitud")? as usize
        } else {
            l.u16("dcerpc.longitud")? as usize
        };
        if largo < 16 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "dcerpc.longitud",
                valor: largo as u64,
            });
        }
        // La longitud de autenticacion es parte del fragmento: mayor que el
        // fragmento entero no la escribe ningun emisor que cumpla la norma.
        let autenticacion = if poco {
            l.u16_le("dcerpc.longitud-de-autenticacion")? as usize
        } else {
            l.u16("dcerpc.longitud-de-autenticacion")? as usize
        };
        if autenticacion >= largo {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("dcerpc"));
        }
        Ok((tipo, poco, largo))
    }

    fn analizar(datos: &[u8]) -> Resultado<Vec<Hecho>> {
        let (tipo, poco, largo) = Dcerpc::cabecera(datos)?;
        let nombre = tipo_dcerpc(tipo).unwrap_or("desconocido");
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Dcerpc)];

        // Solo la vinculacion y el cambio de contexto llevan los UUID. En una
        // peticion ya solo va el numero de contexto, y el interfaz esta en el
        // estado del flujo: por eso el registro guarda estado.
        if !matches!(tipo, 11 | 14) {
            hechos.push(Hecho::EjecucionRemota {
                via: ProtocoloApp::Dcerpc,
                orden: nombre.to_owned(),
                objetivo: String::new(),
            });
            return Ok(hechos);
        }

        let mut l = Lector::nuevo(&datos[..largo.min(datos.len())]);
        l.ir_a(16, "dcerpc.cuerpo")?;
        let _max_envio = l.u16_le("dcerpc.maximo-de-envio")?;
        let _max_recepcion = l.u16_le("dcerpc.maximo-de-recepcion")?;
        let _grupo = l.u32_le("dcerpc.grupo")?;
        let contextos = l.u8("dcerpc.numero-de-contextos")?;
        l.saltar(3, "dcerpc.relleno")?;
        // El numero de contextos lo escribe el cliente: sin tope, un 255 con el
        // buffer cortado haria doscientas cincuenta y cinco lecturas fallidas
        // por paquete. Con el, el coste esta acotado y los casos raros de verdad
        // (mas de ocho contextos en un bind) se ven igual.
        for _ in 0..contextos.min(16) {
            if l.restante() < 24 {
                break;
            }
            let _id = l.u16_le("dcerpc.contexto")?;
            let sintaxis = l.u8("dcerpc.numero-de-sintaxis")?;
            l.saltar(1, "dcerpc.reservado")?;
            let u = Uuid::leer(&mut l, poco)?;
            let version = if poco {
                l.u32_le("dcerpc.version-del-interfaz")?
            } else {
                l.u32("dcerpc.version-del-interfaz")?
            };
            match interfaz(&u) {
                Some((nombre_interfaz, para_que)) => {
                    hechos.push(Hecho::EjecucionRemota {
                        via: ProtocoloApp::Dcerpc,
                        orden: format!("vincular-a-{nombre_interfaz}"),
                        objetivo: para_que.to_owned(),
                    });
                }
                None => {
                    hechos.push(Hecho::EjecucionRemota {
                        via: ProtocoloApp::Dcerpc,
                        orden: "vincular-a-interfaz-no-catalogado".to_owned(),
                        objetivo: format!("{} version {version}", u.texto()),
                    });
                }
            }
            // Cada sintaxis de transferencia son otros veinte bytes.
            for _ in 0..sintaxis.min(8) {
                if l.restante() < 20 {
                    break;
                }
                l.saltar(20, "dcerpc.sintaxis-de-transferencia")?;
            }
        }
        Ok(hechos)
    }
}

impl Disector for Dcerpc {
    /// Version cinco, tipo conocido y longitud minima.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "dcerpc"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Dcerpc::cabecera(datos).is_ok()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        Salida::de_resultado(Dcerpc::analizar(datos))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la cabecera comun con su tipo y su orden de bytes",
            "la vinculacion y el cambio de contexto, con todos sus interfaces",
            "el catalogo de interfaces que nombran una tecnica: drsuapi, netlogon, svcctl, atsvc, efsrpc, winreg, spoolss, WMI",
            "los interfaces no catalogados, por su identificador y su version",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el cuerpo de una peticion: los argumentos van en NDR y son propios de cada interfaz",
            "el numero de operacion de una peticion, que sin el interfaz del bind no dice nada",
            "la autenticacion y el sellado del canal (el nivel de proteccion de RPC)",
            "el reensamblado de las PDU partidas en varios fragmentos",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// NFS y su ONC RPC
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de NFS.
pub const PUERTO_NFS: u16 = 2049;

/// El programa de ONC RPC, por su numero.
fn programa_onc(p: u32) -> Option<&'static str> {
    Some(match p {
        100_000 => "portmap",
        100_003 => "nfs",
        100_005 => "mount",
        100_021 => "nlm",
        100_024 => "status",
        100_227 => "nfs-acl",
        _ => return None,
    })
}

/// El procedimiento de NFS version 3.
fn procedimiento_nfs3(p: u32) -> Option<(&'static str, bool)> {
    Some(match p {
        0 => ("nulo", false),
        1 => ("atributos", false),
        2 => ("poner-atributos", true),
        3 => ("buscar", false),
        4 => ("acceso", false),
        5 => ("enlace-simbolico", false),
        6 => ("leer", false),
        7 => ("escribir", true),
        8 => ("crear", true),
        9 => ("crear-directorio", true),
        10 => ("crear-enlace-simbolico", true),
        11 => ("crear-nodo", true),
        12 => ("borrar", true),
        13 => ("borrar-directorio", true),
        14 => ("renombrar", true),
        15 => ("enlazar", true),
        16 => ("leer-directorio", false),
        17 => ("leer-directorio-con-atributos", false),
        18 => ("estadisticas-del-sistema", false),
        21 => ("confirmar", true),
        _ => return None,
    })
}

/// Disector de NFS sobre ONC RPC.
#[derive(Debug, Default, Clone, Copy)]
pub struct Nfs;

impl Nfs {
    /// Salta la marca de registro de ONC RPC sobre TCP, si la hay.
    ///
    /// Sobre TCP cada mensaje va precedido de cuatro bytes: el bit alto dice si
    /// es el ultimo fragmento y los treinta y uno restantes su longitud. Sobre
    /// UDP no hay marca, y confundir las dos cosas desplaza todo el mensaje.
    fn inicio(datos: &[u8], ordenado: bool) -> usize {
        if !ordenado || datos.len() < 4 {
            return 0;
        }
        let marca = u32::from_be_bytes([datos[0], datos[1], datos[2], datos[3]]);
        let largo = (marca & 0x7FFF_FFFF) as usize;
        if marca & 0x8000_0000 != 0 && largo >= 24 && largo <= datos.len().saturating_sub(4) + 4 {
            4
        } else {
            0
        }
    }

    /// `(programa, version, procedimiento, posicion tras la cabecera)`.
    fn llamada(datos: &[u8], ordenado: bool) -> Resultado<(u32, u32, u32, usize)> {
        let base = Nfs::inicio(datos, ordenado);
        let mut l = Lector::nuevo(datos);
        l.ir_a(base, "onc.inicio")?;
        let _xid = l.u32("onc.xid")?;
        let tipo = l.u32("onc.tipo")?;
        if tipo != 0 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("onc-llamada"));
        }
        let version_rpc = l.u32("onc.version-de-rpc")?;
        if version_rpc != 2 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("onc"));
        }
        let programa = l.u32("onc.programa")?;
        if programa_onc(programa).is_none() {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("onc-programa"));
        }
        let version = l.u32("onc.version")?;
        let procedimiento = l.u32("onc.procedimiento")?;
        Ok((programa, version, procedimiento, l.posicion()))
    }

    /// El usuario que el cliente **dice** ser, si la credencial es AUTH_UNIX.
    ///
    /// Lo entrecomillado es el punto entero: en AUTH_UNIX el cliente declara su
    /// propio uid y el servidor se lo cree. Un uid cero desde una maquina que no
    /// deberia montar nada es el ataque clasico de NFS, y sin leer esto el
    /// sensor ve «trafico al 2049».
    fn credencial(l: &mut Lector<'_>) -> Resultado<Option<(u32, u32, String)>> {
        let sabor = l.u32("onc.sabor")?;
        let largo = l.u32("onc.longitud-de-credencial")? as usize;
        if largo > 1024 {
            return Err(ErrorDiseccion::LimiteExcedido {
                campo: "onc.longitud-de-credencial",
                valor: largo,
                tope: 1024,
            });
        }
        let cuerpo = l.tomar(largo, "onc.credencial")?;
        if sabor != 1 {
            return Ok(None);
        }
        let mut c = Lector::nuevo(cuerpo);
        let _sello = c.u32("onc.sello")?;
        let nombre_largo = c.u32("onc.longitud-del-nombre")? as usize;
        if nombre_largo > 255 {
            return Err(ErrorDiseccion::LimiteExcedido {
                campo: "onc.longitud-del-nombre",
                valor: nombre_largo,
                tope: 255,
            });
        }
        let nombre = c.tomar(nombre_largo, "onc.nombre")?;
        // XDR rellena cada cadena hasta el siguiente multiplo de cuatro.
        let relleno = (4 - (nombre_largo % 4)) % 4;
        if relleno > 0 {
            c.saltar(relleno, "onc.relleno")?;
        }
        let uid = c.u32("onc.uid")?;
        let gid = c.u32("onc.gid")?;
        Ok(Some((uid, gid, aegis_wire::lector::ascii_legible(nombre))))
    }

    fn analizar(datos: &[u8], ctx: &Contexto) -> Resultado<Vec<Hecho>> {
        let (programa, version, procedimiento, pos) = Nfs::llamada(datos, ctx.ordenado)?;
        let nombre_programa = programa_onc(programa).unwrap_or("desconocido");
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Nfs)];

        let mut l = Lector::nuevo(datos);
        l.ir_a(pos, "onc.credencial")?;
        let credencial = Nfs::credencial(&mut l)?;

        let (operacion, escribe) = if programa == 100_003 && version == 3 {
            procedimiento_nfs3(procedimiento).unwrap_or(("procedimiento-no-catalogado", false))
        } else {
            ("llamada", false)
        };

        let (usuario, detalle) = match &credencial {
            Some((uid, gid, equipo)) => (
                format!("uid {uid} gid {gid}"),
                format!("declarado por {equipo}"),
            ),
            None => (String::new(), "sin credencial de unix".to_owned()),
        };

        hechos.push(Hecho::EjecucionRemota {
            via: ProtocoloApp::Nfs,
            orden: format!("{nombre_programa}.{operacion}"),
            objetivo: format!("{usuario} {detalle}").trim().to_owned(),
        });

        // En AUTH_UNIX el cliente declara su propio uid y el servidor se lo cree.
        // Un cero declarado no es un veredicto —hay montajes legitimos con root
        // permitido—, pero es la observacion que hace falta para verlo. Que la
        // operacion ademas modifique el sistema de ficheros va en el detalle:
        // un `getattr` como root y un `write` como root no son lo mismo.
        if let Some((0, _, equipo)) = &credencial {
            hechos.push(Hecho::AnomaliaDeFlujo {
                codigo: "nfs-uid-cero-declarado",
                detalle: format!(
                    "el cliente {equipo} dice ser root para {operacion}, y en AUTH_UNIX eso \
                     lo elige el cliente{}",
                    if escribe {
                        "; la operacion modifica el sistema de ficheros"
                    } else {
                        ""
                    }
                ),
            });
        }
        Ok(hechos)
    }
}

impl Disector for Nfs {
    /// Cabecera de ONC RPC con version dos y un programa conocido.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "nfs"
    }

    fn reconoce(&self, datos: &[u8], ctx: &Contexto) -> bool {
        Nfs::llamada(datos, ctx.ordenado).is_ok()
    }

    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida {
        Salida::de_resultado(Nfs::analizar(datos, ctx))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la cabecera de ONC RPC, con y sin marca de registro sobre TCP",
            "los programas portmap, nfs, mount, nlm y status",
            "los procedimientos de NFS version 3, con si escriben",
            "la credencial AUTH_UNIX: el uid, el gid y el equipo que el cliente declara",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "los argumentos de cada procedimiento: los manejadores de fichero y los nombres",
            "NFS version 4 y sus operaciones compuestas",
            "las respuestas del servidor",
            "las credenciales RPCSEC_GSS (Kerberos sobre NFS)",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// WebDAV
// ════════════════════════════════════════════════════════════════════════════

/// Los metodos que solo existen en WebDAV.
const METODOS_WEBDAV: [&str; 8] = [
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "SEARCH",
];

/// Disector de WebDAV.
#[derive(Debug, Default, Clone, Copy)]
pub struct Webdav;

impl Disector for Webdav {
    /// Un metodo HTTP que solo existe en WebDAV.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Marca
    }

    fn nombre(&self) -> &'static str {
        "webdav"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        texto::peticion_http(datos).is_some_and(|(m, _, _)| METODOS_WEBDAV.contains(&m.as_str()))
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        let Some((metodo, ruta, _)) = texto::peticion_http(datos) else {
            return Salida::sin_analizar(crate::cobertura::Motivo::NoReconocido);
        };
        if !METODOS_WEBDAV.contains(&metodo.as_str()) {
            return Salida::sin_analizar(crate::cobertura::Motivo::NoReconocido);
        }
        let mut hechos = vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Webdav),
            Hecho::EjecucionRemota {
                via: ProtocoloApp::Webdav,
                orden: metodo.clone(),
                objetivo: ruta.clone(),
            },
        ];
        // Un destino en otra maquina convierte un COPY o un MOVE en una
        // transferencia entre servidores que el cliente ni toca.
        if let Some(destino) = texto::cabecera(datos, "Destination") {
            hechos.push(Hecho::AnomaliaDeFlujo {
                codigo: "webdav-destino-declarado",
                detalle: destino,
            });
        }
        Salida::entendido(hechos)
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "los ocho metodos propios de WebDAV",
            "la ruta sobre la que se piden",
            "la cabecera Destination de COPY y MOVE",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el cuerpo XML de PROPFIND y PROPPATCH",
            "la respuesta multiestado (207) y sus propiedades",
            "los testigos de bloqueo y su duracion",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// RDP
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de RDP.
pub const PUERTO_RDP: u16 = 3389;

/// Disector de RDP.
///
/// # Lo que se ve en el primer paquete
///
/// La peticion de conexion de RDP lleva **el nombre de usuario en claro** en su
/// cookie `mstshash`, antes de cualquier cifrado, y los protocolos de seguridad
/// que el cliente acepta. Un `requestedProtocols` de cero significa que el
/// cliente se conforma con la seguridad antigua de RDP, que es la condicion que
/// necesita media docena de ataques conocidos contra este servicio.
#[derive(Debug, Default, Clone, Copy)]
pub struct Rdp;

impl Rdp {
    /// La peticion de conexion, si lo es: `(cookie, protocolos)`.
    fn conexion(datos: &[u8]) -> Resultado<(String, Option<u32>)> {
        let mut l = Lector::nuevo(datos);
        let version = l.u8("tpkt.version")?;
        if version != 0x03 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("rdp"));
        }
        l.saltar(1, "tpkt.reservado")?;
        let total = l.u16("tpkt.longitud")? as usize;
        if total < 11 || total > datos.len() {
            return Err(ErrorDiseccion::LongitudImposible {
                campo: "tpkt.longitud",
                declarada: total,
                disponible: datos.len(),
            });
        }
        let _largo_cotp = l.u8("cotp.longitud")?;
        let tipo = l.u8("cotp.tipo")?;
        if tipo != 0xE0 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("rdp"));
        }
        l.saltar(5, "cotp.peticion-de-conexion")?;
        let resto = &datos[l.posicion()..total];

        let cookie = resto
            .windows(9)
            .position(|v| v == b"mstshash=")
            .and_then(|p| {
                let desde = &resto[p + 9..];
                let fin = desde
                    .iter()
                    .position(|&b| b == b'\r' || b == b'\n' || b == 0)
                    .unwrap_or(desde.len());
                if fin == 0 || fin > 128 {
                    return None;
                }
                Some(aegis_wire::lector::ascii_legible(&desde[..fin]))
            })
            .unwrap_or_default();

        // Tras la cookie, si la hay, va la peticion de negociacion: tipo 0x01,
        // banderas, longitud 8 en orden poco significativo primero, y los
        // protocolos pedidos.
        let protocolos = resto.windows(8).find_map(|v| {
            if v[0] == 0x01 && u16::from_le_bytes([v[2], v[3]]) == 8 {
                Some(u32::from_le_bytes([v[4], v[5], v[6], v[7]]))
            } else {
                None
            }
        });
        Ok((cookie, protocolos))
    }
}

impl Disector for Rdp {
    /// TPKT con peticion de conexion COTP; la cookie y la negociacion refuerzan.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "rdp"
    }

    fn reconoce(&self, datos: &[u8], ctx: &Contexto) -> bool {
        match Rdp::conexion(datos) {
            // Con cookie o con peticion de negociacion es RDP sin discusion. Sin
            // ninguna de las dos, una peticion de conexion COTP tambien puede ser
            // S7comm, y ahi el puerto es lo unico que queda — declarado como
            // desempate, que es lo que el contexto es.
            Ok((c, p)) => !c.is_empty() || p.is_some() || ctx.algun_puerto(PUERTO_RDP),
            Err(_) => false,
        }
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        let (cookie, protocolos) = match Rdp::conexion(datos) {
            Ok(v) => v,
            Err(e) => return Salida::sin_analizar(crate::cobertura::Motivo::de_error(&e)),
        };
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Rdp)];
        if !cookie.is_empty() {
            hechos.push(Hecho::AutenticacionVista {
                mecanismo: "rdp-cookie".to_owned(),
                usuario: cookie,
                dominio: String::new(),
                resultado: "peticion".to_owned(),
            });
        }
        match protocolos {
            Some(p) => {
                let mut cuales = Vec::new();
                if p == 0 {
                    cuales.push("seguridad-antigua-de-rdp");
                }
                if p & 0x01 != 0 {
                    cuales.push("tls");
                }
                if p & 0x02 != 0 {
                    cuales.push("credssp");
                }
                if p & 0x08 != 0 {
                    cuales.push("rdstls");
                }
                hechos.push(Hecho::EjecucionRemota {
                    via: ProtocoloApp::Rdp,
                    orden: "conexion".to_owned(),
                    objetivo: cuales.join("+"),
                });
                // Sin autenticacion a nivel de red el servidor pinta el escritorio
                // antes de saber quien llama. Es la condicion que necesitan varios
                // ataques conocidos contra este servicio.
                if p & 0x02 == 0 {
                    hechos.push(Hecho::AnomaliaDeFlujo {
                        codigo: "rdp-sin-autenticacion-de-red",
                        detalle:
                            "el cliente no pidio CredSSP: el servidor atiende antes de autenticar"
                                .to_owned(),
                    });
                }
                Salida::entendido(hechos)
            }
            // Se reconocio la conexion y no llevaba negociacion: es RDP antiguo
            // y no se puede decir mas. Declararlo es distinto de callarlo.
            None => Salida::no_implementado(hechos),
        }
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la peticion de conexion con su cookie mstshash, que lleva el usuario en claro",
            "la peticion de negociacion y los protocolos de seguridad que el cliente acepta",
            "la ausencia de CredSSP, que es la condicion de varios ataques contra este servicio",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el resto de la sesion, que va sobre TLS desde la respuesta del servidor",
            "los canales virtuales (portapapeles, unidades, impresoras)",
            "el intercambio de licencias",
            "las ordenes de dibujo del escritorio",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// VNC / RFB
// ════════════════════════════════════════════════════════════════════════════

/// Puerto habitual del primer escritorio de VNC.
pub const PUERTO_VNC: u16 = 5900;

/// Disector de VNC (protocolo RFB).
#[derive(Debug, Default, Clone, Copy)]
pub struct Vnc;

impl Vnc {
    /// La version anunciada, si esto es un saludo RFB.
    ///
    /// El saludo son doce bytes exactos: `RFB xxx.yyy\n`. Comprobar la forma
    /// entera —y no solo las tres primeras letras— es lo que impide que
    /// cualquier flujo que empiece por `RFB` pase por VNC.
    fn saludo(datos: &[u8]) -> Option<String> {
        if datos.len() < 12 || !datos.starts_with(b"RFB ") || datos[11] != b'\n' {
            return None;
        }
        let v = &datos[4..11];
        if !(v[0..3].iter().all(u8::is_ascii_digit)
            && v[3] == b'.'
            && v[4..7].iter().all(u8::is_ascii_digit))
        {
            return None;
        }
        Some(aegis_wire::lector::ascii_legible(v))
    }
}

impl Disector for Vnc {
    /// Los doce bytes exactos del saludo RFB.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Marca
    }

    fn nombre(&self) -> &'static str {
        "vnc"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Vnc::saludo(datos).is_some()
    }

    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida {
        let Some(version) = Vnc::saludo(datos) else {
            return Salida::sin_analizar(crate::cobertura::Motivo::NoReconocido);
        };
        let mut hechos = vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Vnc),
            Hecho::EjecucionRemota {
                via: ProtocoloApp::Vnc,
                orden: "saludo".to_owned(),
                objetivo: format!("version {version}"),
            },
        ];
        // Tras el saludo del servidor viene la lista de tipos de seguridad. El
        // tipo 1 es «ninguna»: un escritorio entero sin contrasena.
        if !ctx.del_cliente && datos.len() > 12 {
            let cuantos = datos[12] as usize;
            if cuantos > 0 && datos.len() >= 13 + cuantos {
                let tipos = &datos[13..13 + cuantos.min(32)];
                if tipos.contains(&1) {
                    hechos.push(Hecho::AnomaliaDeFlujo {
                        codigo: "vnc-sin-autenticacion",
                        detalle: "el servidor ofrece el tipo de seguridad «ninguna»".to_owned(),
                    });
                }
                let nombres: Vec<String> = tipos.iter().map(|t| t.to_string()).collect();
                hechos.push(Hecho::AutenticacionVista {
                    mecanismo: "vnc-tipos-de-seguridad".to_owned(),
                    usuario: String::new(),
                    dominio: String::new(),
                    resultado: nombres.join(","),
                });
            }
        }
        Salida::entendido(hechos)
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "el saludo RFB con su version",
            "la lista de tipos de seguridad del servidor",
            "el tipo «ninguna», que es un escritorio entero sin contrasena",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el reto de la autenticacion de VNC y su respuesta",
            "la inicializacion de cliente y servidor con el nombre del escritorio",
            "las actualizaciones de imagen y sus codificaciones",
            "los sucesos de teclado y raton",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// WinRM
// ════════════════════════════════════════════════════════════════════════════

/// Puertos de WinRM: sin cifrar y sobre TLS.
pub const PUERTOS_WINRM: [u16; 2] = [5985, 5986];

/// Disector de WinRM.
#[derive(Debug, Default, Clone, Copy)]
pub struct Winrm;

impl Winrm {
    /// Las acciones de WS-Management que importan, por el final de su URI.
    const ACCIONES: [(&'static str, &'static str); 6] = [
        ("shell/Command", "ejecutar-orden"),
        ("shell/Create", "crear-interprete"),
        ("shell/Send", "mandar-entrada"),
        ("shell/Receive", "recoger-salida"),
        ("shell/Signal", "senalar"),
        ("shell/Delete", "cerrar-interprete"),
    ];

    fn accion(datos: &[u8]) -> Option<(String, &'static str)> {
        let (metodo, ruta, _) = texto::peticion_http(datos)?;
        let bajo = ruta.to_ascii_lowercase();
        if !(bajo.contains("/wsman") || bajo.contains("/powershell")) {
            return None;
        }
        let tope = datos.len().min(32 * 1024);
        let cuerpo = &datos[..tope];
        for (marca, nombre) in Winrm::ACCIONES {
            if cuerpo
                .windows(marca.len())
                .any(|v| v.eq_ignore_ascii_case(marca.as_bytes()))
            {
                return Some((format!("{metodo} {ruta}"), nombre));
            }
        }
        Some((format!("{metodo} {ruta}"), "mensaje-de-ws-management"))
    }
}

impl Disector for Winrm {
    /// Una peticion HTTP a /wsman o /powershell.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Marca
    }

    fn nombre(&self) -> &'static str {
        "winrm"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Winrm::accion(datos).is_some()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        let Some((donde, accion)) = Winrm::accion(datos) else {
            return Salida::sin_analizar(crate::cobertura::Motivo::NoReconocido);
        };
        let mut hechos = vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Winrm),
            Hecho::EjecucionRemota {
                via: ProtocoloApp::Winrm,
                orden: accion.to_owned(),
                objetivo: donde,
            },
        ];
        if let Some(a) = texto::cabecera(datos, "Authorization") {
            let mecanismo = a.split(' ').next().unwrap_or("").to_ascii_lowercase();
            hechos.push(Hecho::AutenticacionVista {
                mecanismo: format!("winrm-{mecanismo}"),
                usuario: String::new(),
                dominio: String::new(),
                resultado: "peticion".to_owned(),
            });
        }
        // El cuerpo cifrado con SPNEGO es el caso normal de WinRM: se ve que hubo
        // una orden y no que orden fue. Eso no se arregla escribiendo codigo.
        let cifrado = texto::cabecera(datos, "Content-Type")
            .is_some_and(|t| t.to_ascii_lowercase().contains("encrypted"));
        if cifrado {
            return Salida {
                hechos,
                cobertura: {
                    let mut c = crate::cobertura::Cobertura::nueva();
                    c.sin_analizar(crate::cobertura::Motivo::Cifrado);
                    c
                },
            };
        }
        Salida::entendido(hechos)
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "las peticiones a /wsman y a /powershell",
            "las acciones de interprete: crear, ejecutar orden, mandar entrada, recoger salida y cerrar",
            "el mecanismo declarado en la cabecera Authorization",
            "el cuerpo cifrado con SPNEGO, que se declara cifrado y no se cuenta como entendido",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el SOAP completo del mensaje de WS-Management",
            "la orden concreta y sus argumentos cuando el cuerpo va cifrado",
            "los flujos de PowerShell Remoting sobre el mismo canal",
            "la respuesta con el codigo de salida del proceso",
        ]
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ejecucion(s: &Salida) -> Option<(&str, &str)> {
        s.hechos.iter().find_map(|h| match h {
            Hecho::EjecucionRemota {
                orden, objetivo, ..
            } => Some((orden.as_str(), objetivo.as_str())),
            _ => None,
        })
    }

    /// Un `bind` de DCERPC contra `drsuapi`, que es como se pide la replicacion
    /// del directorio — o sea, todos los hashes del dominio.
    fn bind_drsuapi() -> Vec<u8> {
        let mut v = vec![
            0x05, 0x00, 0x0B, 0x03, // version 5.0, bind, ultimo fragmento
            0x10, 0x00, 0x00, 0x00, // poco significativo primero
        ];
        v.extend_from_slice(&72u16.to_le_bytes()); // longitud
        v.extend_from_slice(&0u16.to_le_bytes()); // longitud de autenticacion
        v.extend_from_slice(&1u32.to_le_bytes()); // identificador de llamada
        v.extend_from_slice(&4280u16.to_le_bytes()); // maximo de envio
        v.extend_from_slice(&4280u16.to_le_bytes()); // maximo de recepcion
        v.extend_from_slice(&0u32.to_le_bytes()); // grupo
        v.push(1); // un contexto
        v.extend_from_slice(&[0, 0, 0]); // relleno
        v.extend_from_slice(&0u16.to_le_bytes()); // identificador de contexto
        v.push(1); // una sintaxis de transferencia
        v.push(0); // reservado
                   // drsuapi e3514235-4b06-11d1-ab04-00c04fc2dcd2, en el cable del reves.
        v.extend_from_slice(&0xe351_4235u32.to_le_bytes());
        v.extend_from_slice(&0x4b06u16.to_le_bytes());
        v.extend_from_slice(&0x11d1u16.to_le_bytes());
        v.extend_from_slice(&[0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2]);
        v.extend_from_slice(&4u32.to_le_bytes()); // version del interfaz
        v.extend_from_slice(&[0u8; 20]); // sintaxis de transferencia
        v
    }

    /// LA prestacion del modulo: el UUID **es** la tecnica. Un sensor que solo
    /// diga «vi DCERPC al 135» tiene delante DCSync y no lo nombra.
    #[test]
    fn dcerpc_nombra_la_tecnica_que_pide_el_interfaz() {
        let d = Dcerpc;
        let b = bind_drsuapi();
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_EPMAPPER)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_EPMAPPER));
        assert!(s.cobertura.completa(), "{:?}", s.cobertura);
        let (orden, para_que) = ejecucion(&s).expect("una ejecucion");
        assert_eq!(orden, "vincular-a-drsuapi");
        assert!(para_que.contains("DCSync"), "{para_que}");
    }

    #[test]
    fn dcerpc_lee_el_uuid_en_el_orden_que_declara_el_emisor() {
        // Leerlo al reves invierte el identificador y el catalogo no acierta: el
        // sensor veria un interfaz desconocido donde hay una tecnica conocida.
        let d = Dcerpc;
        let mut b = bind_drsuapi();
        // Se pasa a orden de red: cambia la representacion y los tres campos.
        // El UUID empieza en el byte 32: dieciseis de cabecera comun, ocho de
        // cabecera de vinculacion, cuatro de contexto y cuatro de sintaxis.
        b[4] = 0x00;
        b[8..10].copy_from_slice(&72u16.to_be_bytes());
        b[32..36].copy_from_slice(&0xe351_4235u32.to_be_bytes());
        b[36..38].copy_from_slice(&0x4b06u16.to_be_bytes());
        b[38..40].copy_from_slice(&0x11d1u16.to_be_bytes());
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_EPMAPPER));
        assert_eq!(
            ejecucion(&s).map(|(o, _)| o),
            Some("vincular-a-drsuapi"),
            "el mismo interfaz en el otro orden de bytes"
        );
    }

    /// «Version 5, tipo conocido, longitud razonable» le pasa a cualquier cosa.
    /// Se midio: una peticion de SOCKS 5 encajaba como una de DCERPC, y con el
    /// registro entero se la quitaba al disector que si la entiende.
    #[test]
    fn dcerpc_exige_los_cuatro_bytes_de_la_representacion_de_datos() {
        let d = Dcerpc;
        let mut socks = vec![5u8, 1, 0, 1, 10, 0, 0, 1];
        socks.extend_from_slice(&445u16.to_be_bytes());
        assert!(!d.reconoce(&socks, &Contexto::tcp_cliente(1080)));

        // Y cada campo por separado, para que quitar uno duela.
        for (indice, valor) in [(4usize, 0x2Au8), (4, 0x0A), (5, 9), (6, 1), (7, 1), (1, 9)] {
            let mut b = bind_drsuapi();
            b[indice] = valor;
            assert!(
                !d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_EPMAPPER)),
                "el byte {indice} a {valor:#04x} deberia descartarlo"
            );
        }
    }

    #[test]
    fn dcerpc_declara_un_interfaz_que_no_esta_en_el_catalogo() {
        // No catalogado no es «no visto»: sale su identificador y su version,
        // que es lo que hace falta para anadirlo despues.
        let d = Dcerpc;
        let mut b = bind_drsuapi();
        b[32..36].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_EPMAPPER));
        let (orden, objetivo) = ejecucion(&s).expect("una ejecucion");
        assert_eq!(orden, "vincular-a-interfaz-no-catalogado");
        assert!(objetivo.starts_with("deadbeef-"), "{objetivo}");
    }

    #[test]
    fn el_catalogo_de_interfaces_no_repite_identificadores() {
        // Dos filas con el mismo UUID harian que una de las dos no apareciera
        // nunca, y nadie se enteraria.
        for (i, (u, n, p)) in INTERFACES.iter().enumerate() {
            assert!(p.len() > 30, "{n}: la explicacion no dice para que se usa");
            for (v, m, _) in &INTERFACES[i + 1..] {
                assert_ne!(u, v, "{n} y {m} comparten identificador");
            }
        }
    }

    #[test]
    fn el_uuid_se_escribe_como_se_documenta() {
        let u = Uuid(
            0xe351_4235,
            0x4b06,
            0x11d1,
            [0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2],
        );
        assert_eq!(u.texto(), "e3514235-4b06-11d1-ab04-00c04fc2dcd2");
    }

    /// Una llamada NFSv3 de escritura con credencial AUTH_UNIX y uid cero.
    fn nfs_escritura(uid: u32) -> Vec<u8> {
        let equipo = b"portatil";
        let mut cuerpo = Vec::new();
        cuerpo.extend_from_slice(&1u32.to_be_bytes()); // xid
        cuerpo.extend_from_slice(&0u32.to_be_bytes()); // llamada
        cuerpo.extend_from_slice(&2u32.to_be_bytes()); // rpc version 2
        cuerpo.extend_from_slice(&100_003u32.to_be_bytes()); // nfs
        cuerpo.extend_from_slice(&3u32.to_be_bytes()); // version 3
        cuerpo.extend_from_slice(&7u32.to_be_bytes()); // escribir
        cuerpo.extend_from_slice(&1u32.to_be_bytes()); // AUTH_UNIX
        let relleno = (4 - (equipo.len() % 4)) % 4;
        let largo_cred = 4 + 4 + equipo.len() + relleno + 4 + 4 + 4;
        cuerpo.extend_from_slice(&(largo_cred as u32).to_be_bytes());
        cuerpo.extend_from_slice(&0u32.to_be_bytes()); // sello
        cuerpo.extend_from_slice(&(equipo.len() as u32).to_be_bytes());
        cuerpo.extend_from_slice(equipo);
        cuerpo.extend(std::iter::repeat_n(0u8, relleno));
        cuerpo.extend_from_slice(&uid.to_be_bytes());
        cuerpo.extend_from_slice(&0u32.to_be_bytes()); // gid
        cuerpo.extend_from_slice(&0u32.to_be_bytes()); // sin grupos adicionales

        let mut v = ((cuerpo.len() as u32) | 0x8000_0000).to_be_bytes().to_vec();
        v.extend_from_slice(&cuerpo);
        v
    }

    #[test]
    fn nfs_lee_el_uid_que_el_cliente_se_atribuye() {
        // En AUTH_UNIX el cliente declara su propio uid y el servidor se lo cree.
        // Sin leer esto, el sensor ve «trafico al 2049».
        let d = Nfs;
        let b = nfs_escritura(0);
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_NFS)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_NFS));
        assert!(s.cobertura.completa(), "{:?}", s.cobertura);
        let (orden, objetivo) = ejecucion(&s).expect("una ejecucion");
        assert_eq!(orden, "nfs.escribir");
        assert!(objetivo.contains("uid 0"), "{objetivo}");
        assert!(
            s.hechos.iter().any(
                |h| matches!(h, Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "nfs-uid-cero-declarado")
            ),
            "{:?}",
            s.hechos
        );
    }

    #[test]
    fn nfs_no_acusa_a_un_uid_corriente() {
        let d = Nfs;
        let s = d.disecar(&nfs_escritura(1000), &Contexto::tcp_cliente(PUERTO_NFS));
        assert!(
            !s.hechos.iter().any(
                |h| matches!(h, Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "nfs-uid-cero-declarado")
            ),
            "un uid corriente no es una acusacion"
        );
    }

    #[test]
    fn webdav_ve_el_destino_de_una_copia_entre_servidores() {
        let d = Webdav;
        let b = b"MOVE /a.txt HTTP/1.1\r\nHost: x\r\nDestination: http://otro/b.txt\r\n\r\n";
        assert!(d.reconoce(b, &Contexto::tcp_cliente(80)));
        let s = d.disecar(b, &Contexto::tcp_cliente(80));
        let (orden, objetivo) = ejecucion(&s).expect("una ejecucion");
        assert_eq!(orden, "MOVE");
        assert_eq!(objetivo, "/a.txt");
        assert!(s.hechos.iter().any(
            |h| matches!(h, Hecho::AnomaliaDeFlujo { detalle, .. } if detalle.contains("otro"))
        ));
    }

    #[test]
    fn webdav_no_se_queda_con_un_get_corriente() {
        let d = Webdav;
        assert!(!d.reconoce(b"GET /a.txt HTTP/1.1\r\n\r\n", &Contexto::tcp_cliente(80)));
    }

    /// Una peticion de conexion de RDP con la cookie del usuario y la
    /// negociacion pidiendo solo la seguridad antigua.
    fn rdp_conexion(protocolos: u32) -> Vec<u8> {
        let cookie = b"Cookie: mstshash=administrador\r\n";
        let total = 4 + 7 + cookie.len() + 8;
        let mut v = vec![0x03, 0x00];
        v.extend_from_slice(&(total as u16).to_be_bytes());
        v.push((total - 5) as u8);
        v.push(0xE0);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
        v.extend_from_slice(cookie);
        v.push(0x01); // peticion de negociacion
        v.push(0x00); // banderas
        v.extend_from_slice(&8u16.to_le_bytes());
        v.extend_from_slice(&protocolos.to_le_bytes());
        v
    }

    #[test]
    fn rdp_saca_el_usuario_en_claro_del_primer_paquete() {
        let d = Rdp;
        let b = rdp_conexion(0x0000_0002);
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_RDP)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_RDP));
        let usuario = s.hechos.iter().find_map(|h| match h {
            Hecho::AutenticacionVista { usuario, .. } => Some(usuario.as_str()),
            _ => None,
        });
        assert_eq!(usuario, Some("administrador"));
        assert_eq!(ejecucion(&s).map(|(_, o)| o), Some("credssp"));
    }

    #[test]
    fn rdp_dice_cuando_el_servidor_atiende_antes_de_autenticar() {
        let d = Rdp;
        let s = d.disecar(&rdp_conexion(0), &Contexto::tcp_cliente(PUERTO_RDP));
        assert!(
            s.hechos.iter().any(
                |h| matches!(h, Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "rdp-sin-autenticacion-de-red")
            ),
            "{:?}",
            s.hechos
        );
    }

    #[test]
    fn vnc_ve_un_escritorio_sin_contrasena() {
        let d = Vnc;
        let mut b = b"RFB 003.008\n".to_vec();
        b.push(2); // dos tipos de seguridad
        b.push(1); // ninguna
        b.push(2); // autenticacion de vnc
        assert!(d.reconoce(&b, &Contexto::tcp_servidor(PUERTO_VNC)));
        let s = d.disecar(&b, &Contexto::tcp_servidor(PUERTO_VNC));
        assert!(
            s.hechos.iter().any(
                |h| matches!(h, Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "vnc-sin-autenticacion")
            ),
            "{:?}",
            s.hechos
        );
    }

    #[test]
    fn vnc_no_se_queda_con_cualquier_cosa_que_empiece_por_rfb() {
        // Comprobar la forma entera del saludo es lo que impide que un flujo
        // cualquiera que empiece por «RFB» pase por VNC.
        let d = Vnc;
        assert!(!d.reconoce(
            b"RFB pero no un saludo",
            &Contexto::tcp_servidor(PUERTO_VNC)
        ));
        assert!(!d.reconoce(b"RFB 00x.008\n", &Contexto::tcp_servidor(PUERTO_VNC)));
    }

    #[test]
    fn winrm_ve_la_ejecucion_de_una_orden() {
        let d = Winrm;
        let b = b"POST /wsman?PSVersion=5.1 HTTP/1.1\r\nHost: pc\r\nAuthorization: Negotiate abc\r\nContent-Type: application/soap+xml\r\n\r\n<a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>";
        assert!(d.reconoce(b, &Contexto::tcp_cliente(PUERTOS_WINRM[0])));
        let s = d.disecar(b, &Contexto::tcp_cliente(PUERTOS_WINRM[0]));
        assert_eq!(ejecucion(&s).map(|(o, _)| o), Some("ejecutar-orden"));
        assert!(s.cobertura.completa());
    }

    #[test]
    fn winrm_declara_cifrado_lo_que_va_cifrado_y_no_lo_llama_no_implementado() {
        // Uno se arregla escribiendo codigo y el otro no: mezclarlos haria que
        // la cifra de cobertura pareciera un problema de esfuerzo.
        let d = Winrm;
        let b = b"POST /wsman HTTP/1.1\r\nHost: pc\r\nContent-Type: multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\"\r\n\r\n";
        let s = d.disecar(b, &Contexto::tcp_cliente(PUERTOS_WINRM[0]));
        assert_eq!(
            s.cobertura
                .sin_analizar
                .get(&crate::cobertura::Motivo::Cifrado),
            Some(&1)
        );
        assert_eq!(s.cobertura.perdidos_por_falta_de_codigo(), 0);
    }

    #[test]
    fn los_seis_de_ejecucion_remota_declaran_sus_dos_mitades() {
        let ds: Vec<Box<dyn Disector>> = vec![
            Box::new(Dcerpc),
            Box::new(Nfs),
            Box::new(Webdav),
            Box::new(Rdp),
            Box::new(Vnc),
            Box::new(Winrm),
        ];
        for d in &ds {
            assert!(!d.mensajes_que_entiende().is_empty(), "{}", d.nombre());
            assert!(!d.mensajes_que_no_analiza().is_empty(), "{}", d.nombre());
        }
    }
}
