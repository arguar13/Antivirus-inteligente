//! Nube: el servicio de metadatos de instancia.
//!
//! # Por que una direccion de enlace local merece un disector
//!
//! Porque `169.254.169.254` es donde una maquina virtual pide **sus propias
//! credenciales**, y desde dentro de la red esa peticion no necesita
//! autenticacion ninguna: el hecho de poder hacerla ya es la autorizacion. De
//! ahi que el patron que vacio mas de una cuenta sea tan corto: se encuentra un
//! servidor web que acepta una URL del usuario, se le pide esa direccion, y la
//! respuesta trae una credencial con la que hablar con la nube entera.
//!
//! Un sensor que solo mire salidas a internet no ve nada: la peticion no sale de
//! la maquina. Y un sensor que mire toda la red tampoco, si no sabe que esa
//! direccion significa algo.
//!
//! # Lo que se mira y lo que no se decide
//!
//! Se mira **quien** pregunta, **que** recurso pide y **si** lo que va o vuelve
//! lleva una credencial. Que sea legitimo o no depende de si lo pidio el agente
//! de la nube al arrancar o una peticion reenviada por un servidor web, y eso lo
//! sabe el arbitro, que tiene el proceso. Aqui se emite el hecho con sus datos.

use aegis_wire::hecho::{Hecho, ProtocoloApp};

use crate::cobertura::Motivo;
use crate::disector::{Contexto, Disector, Fuerza, Salida};
use crate::texto;

/// La direccion del servicio de metadatos, igual en casi todas las nubes.
pub const DIRECCION_ESTANDAR: &str = "169.254.169.254";

/// Los proveedores, por lo que aparece en la peticion.
///
/// Cada fila es `(marca, proveedor)`. Se mira **el anfitrion y la ruta**, no una
/// direccion de origen: el mismo servicio se alcanza por su nombre interno y por
/// su direccion, y quedarse con uno de los dos deja la mitad sin ver.
pub static PROVEEDORES: &[(&str, &str)] = &[
    ("metadata.google.internal", "gcp"),
    ("/computemetadata/v1", "gcp"),
    ("/latest/meta-data/iam/security-credentials", "aws"),
    ("/latest/meta-data", "aws"),
    ("/latest/api/token", "aws"),
    ("/latest/dynamic/instance-identity", "aws"),
    ("/metadata/instance", "azure"),
    ("/metadata/identity/oauth2/token", "azure"),
    ("100.100.100.200", "alibaba"),
    ("/latest/meta-data/ram/security-credentials", "alibaba"),
    ("/opc/v2/instance/identity", "oracle"),
    ("/opc/v2/instance", "oracle"),
    ("/metadata/v1", "digitalocean"),
    (DIRECCION_ESTANDAR, "por-la-direccion-estandar"),
];

/// Las rutas que devuelven una credencial, no una descripcion.
///
/// Es la distincion que hace util el hecho: pedir el tipo de instancia es
/// inventario, y pedir esto es llevarse las llaves.
pub static RUTAS_DE_CREDENCIAL: &[&str] = &[
    "/iam/security-credentials",
    "/identity/oauth2/token",
    "/service-accounts/",
    "/token",
    "/ram/security-credentials",
    "/instance/identity/",
];

/// Lo que delata una credencial dentro de una respuesta.
static MARCAS_DE_CREDENCIAL: &[&str] = &[
    "SecretAccessKey",
    "access_token",
    "\"Token\"",
    "SessionToken",
    "client_secret",
    "-----BEGIN",
];

/// Disector del servicio de metadatos de instancia.
#[derive(Debug, Default, Clone, Copy)]
pub struct MetadatosDeNube;

/// Lo que se vio de un acceso a los metadatos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acceso {
    /// Proveedor deducido.
    pub proveedor: String,
    /// Recurso pedido.
    pub recurso: String,
    /// Si la peticion pide una credencial o la respuesta lleva una.
    pub con_credencial: bool,
    /// Si la peticion usa el protocolo de dos pasos con testigo (IMDSv2).
    pub con_testigo: bool,
}

impl MetadatosDeNube {
    /// Lee un acceso, si esto lo es.
    #[must_use]
    pub fn leer(datos: &[u8]) -> Option<Acceso> {
        let tope = datos.len().min(32 * 1024);
        let vista = &datos[..tope];

        let (metodo, ruta, _) = texto::peticion_http(vista)?;
        let anfitrion = texto::cabecera(vista, "Host").unwrap_or_default();
        let bajo_ruta = ruta.to_ascii_lowercase();
        let bajo_anfitrion = anfitrion.to_ascii_lowercase();

        // Gana la marca MAS LARGA, no la primera. Sin eso,
        // `/latest/meta-data/ram/security-credentials` —que es de Alibaba— cae en
        // la fila de `/latest/meta-data`, que es de AWS, y el informe nombra al
        // proveedor equivocado en el unico sitio donde eso importa.
        let proveedor = PROVEEDORES
            .iter()
            .filter(|(marca, _)| bajo_anfitrion.contains(marca) || bajo_ruta.contains(marca))
            .max_by_key(|(marca, _)| marca.len())
            .map(|(_, quien)| (*quien).to_owned())?;

        // El protocolo de dos pasos de AWS: primero un PUT que pide un testigo
        // con su tiempo de vida, y luego un GET que lo presenta. Verlo importa
        // porque su ausencia es lo que deja a la maquina expuesta al patron de
        // peticion reenviada.
        let con_testigo = texto::cabecera(vista, "X-aws-ec2-metadata-token").is_some()
            || texto::cabecera(vista, "X-aws-ec2-metadata-token-ttl-seconds").is_some()
            || texto::cabecera(vista, "Metadata-Flavor").is_some()
            || texto::cabecera(vista, "Metadata").is_some();

        let pide_credencial = RUTAS_DE_CREDENCIAL
            .iter()
            .any(|r| bajo_ruta.contains(&r.to_ascii_lowercase()));

        // Y en el cuerpo —de la peticion o de lo que venga pegado detras— puede
        // venir ya la credencial devuelta.
        let trae_credencial = texto::fin_de_cabecera(vista).is_some_and(|p| {
            let cuerpo = &vista[p..];
            MARCAS_DE_CREDENCIAL.iter().any(|m| {
                cuerpo
                    .windows(m.len())
                    .any(|v| v.eq_ignore_ascii_case(m.as_bytes()))
            })
        });

        Some(Acceso {
            proveedor,
            recurso: format!("{metodo} {ruta}"),
            con_credencial: pide_credencial || trae_credencial,
            con_testigo,
        })
    }
}

impl Disector for MetadatosDeNube {
    /// Un anfitrion o una ruta del servicio de metadatos.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Marca
    }

    fn nombre(&self) -> &'static str {
        "metadatos-de-nube"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        MetadatosDeNube::leer(datos).is_some()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        let Some(a) = MetadatosDeNube::leer(datos) else {
            return Salida::sin_analizar(Motivo::NoReconocido);
        };
        let mut hechos = vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::MetadatosDeNube),
            Hecho::AccesoAMetadatosDeNube {
                proveedor: a.proveedor.clone(),
                recurso: a.recurso.clone(),
                con_credencial: a.con_credencial,
            },
        ];
        // Sin la cabecera del protocolo de dos pasos, cualquiera que consiga que
        // el servidor haga una peticion se lleva la respuesta. No es un
        // veredicto —hay agentes antiguos que aun no la mandan—, es el dato.
        if !a.con_testigo {
            hechos.push(Hecho::AnomaliaDeFlujo {
                codigo: "metadatos-sin-cabecera-de-proteccion",
                detalle: "la peticion no lleva la cabecera que exige el modo protegido del \
                          servicio de metadatos"
                    .to_owned(),
            });
        }
        if a.con_credencial {
            hechos.push(Hecho::AutenticacionVista {
                mecanismo: format!("credencial-de-instancia-{}", a.proveedor),
                usuario: String::new(),
                dominio: a.proveedor,
                resultado: a.recurso,
            });
        }
        Salida::entendido(hechos)
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "las peticiones al servicio de metadatos de AWS, Azure, GCP, Oracle, Alibaba y DigitalOcean",
            "el proveedor, por el anfitrion o por la ruta",
            "las rutas que devuelven una credencial, separadas de las que devuelven inventario",
            "las cabeceras del modo protegido, y su ausencia",
            "las credenciales que aparecen en el cuerpo de una respuesta",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el contenido de la credencial: se registra que la hubo, nunca su valor",
            "el JSON completo del documento de identidad de la instancia",
            "el acceso al servicio de metadatos por HTTPS, donde no se ve la ruta",
            "quien hizo la peticion dentro de la maquina, que lo sabe el arbitro y no el sensor",
        ]
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn acceso(s: &Salida) -> Option<(&str, &str, bool)> {
        s.hechos.iter().find_map(|h| match h {
            Hecho::AccesoAMetadatosDeNube {
                proveedor,
                recurso,
                con_credencial,
            } => Some((proveedor.as_str(), recurso.as_str(), *con_credencial)),
            _ => None,
        })
    }

    /// El patron que vacio mas de una cuenta: un servidor web acepta una URL del
    /// usuario, se le pide el servicio de metadatos, y la respuesta trae una
    /// credencial con la que hablar con la nube entera.
    #[test]
    fn se_ve_la_peticion_que_pide_las_llaves() {
        let d = MetadatosDeNube;
        let b = b"GET /latest/meta-data/iam/security-credentials/rol-web HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n";
        assert!(d.reconoce(b, &Contexto::tcp_cliente(80)));
        let s = d.disecar(b, &Contexto::tcp_cliente(80));
        assert!(s.cobertura.completa());
        let (proveedor, recurso, credencial) = acceso(&s).expect("un acceso");
        assert_eq!(proveedor, "aws");
        assert!(recurso.contains("security-credentials"), "{recurso}");
        assert!(credencial, "pedir esto es llevarse las llaves");
    }

    #[test]
    fn se_separa_el_inventario_de_la_credencial() {
        // Pedir el tipo de instancia es inventario; pedir la otra ruta es otra
        // cosa. Contarlas juntas entierra la segunda bajo la primera.
        let d = MetadatosDeNube;
        let b = b"GET /latest/meta-data/instance-type HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token: AQ==\r\n\r\n";
        let s = d.disecar(b, &Contexto::tcp_cliente(80));
        let (_, _, credencial) = acceso(&s).expect("un acceso");
        assert!(!credencial);
        assert!(
            !s.hechos.iter().any(|h| matches!(
                h,
                Hecho::AnomaliaDeFlujo { codigo, .. }
                    if *codigo == "metadatos-sin-cabecera-de-proteccion"
            )),
            "con la cabecera del modo protegido no hay nada que decir"
        );
    }

    #[test]
    fn se_dice_cuando_falta_la_cabecera_del_modo_protegido() {
        // Sin ella, cualquiera que consiga que el servidor haga una peticion se
        // lleva la respuesta.
        let d = MetadatosDeNube;
        let b = b"GET /latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n";
        let s = d.disecar(b, &Contexto::tcp_cliente(80));
        assert!(
            s.hechos.iter().any(|h| matches!(
                h,
                Hecho::AnomaliaDeFlujo { codigo, .. }
                    if *codigo == "metadatos-sin-cabecera-de-proteccion"
            )),
            "{:?}",
            s.hechos
        );
    }

    #[test]
    fn se_reconocen_los_seis_proveedores_por_su_forma() {
        let d = MetadatosDeNube;
        for (peticion, esperado) in [
            (
                &b"GET /computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1\r\nHost: metadata.google.internal\r\nMetadata-Flavor: Google\r\n\r\n"[..],
                "gcp",
            ),
            (
                &b"GET /metadata/identity/oauth2/token?api-version=2018-02-01 HTTP/1.1\r\nHost: 169.254.169.254\r\nMetadata: true\r\n\r\n"[..],
                "azure",
            ),
            (
                &b"GET /opc/v2/instance/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n"[..],
                "oracle",
            ),
            (
                &b"GET /latest/meta-data/ram/security-credentials/rol HTTP/1.1\r\nHost: 100.100.100.200\r\n\r\n"[..],
                "alibaba",
            ),
        ] {
            let s = d.disecar(peticion, &Contexto::tcp_cliente(80));
            let (proveedor, _, _) = acceso(&s).expect("un acceso");
            assert_eq!(proveedor, esperado, "{}", String::from_utf8_lossy(peticion));
        }
    }

    #[test]
    fn una_credencial_en_el_cuerpo_se_ve_y_no_se_guarda() {
        // Se registra que la hubo, nunca su valor.
        let d = MetadatosDeNube;
        let b = b"GET /latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n{\"SecretAccessKey\":\"ESTONOPUEDESALIR\"}";
        let s = d.disecar(b, &Contexto::tcp_cliente(80));
        let (_, _, credencial) = acceso(&s).expect("un acceso");
        assert!(credencial);
        assert!(
            !s.hechos
                .iter()
                .any(|h| format!("{h:?}").contains("ESTONOPUEDESALIR")),
            "el valor de la credencial no puede acabar en ningun hecho"
        );
    }

    #[test]
    fn una_peticion_web_corriente_no_pasa_por_esto() {
        let d = MetadatosDeNube;
        assert!(!d.reconoce(
            b"GET /index.html HTTP/1.1\r\nHost: ejemplo.es\r\n\r\n",
            &Contexto::tcp_cliente(80)
        ));
    }

    #[test]
    fn el_disector_declara_sus_dos_mitades() {
        let d = MetadatosDeNube;
        assert!(!d.mensajes_que_entiende().is_empty());
        assert!(!d.mensajes_que_no_analiza().is_empty());
    }
}
