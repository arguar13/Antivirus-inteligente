//! El registro de conexion: lo que queda cuando un flujo muere.
//!
//! # Por que un registro y no solo alertas
//!
//! Una alerta cuenta lo que el motor creyo importante **en ese momento**. Un
//! registro de conexion cuenta lo que paso, importante o no. La diferencia
//! aparece siempre en la misma situacion: el analista sabe el martes que una
//! maquina estuvo comprometida el lunes, y necesita saber con quien hablo — no
//! con quien hablo *que resultara sospechoso segun las reglas del lunes*.
//!
//! Por eso el registro se emite para **todos** los flujos, no solo para los que
//! dispararon algo. Es lo que convierte el sensor en una herramienta de caza
//! retrospectiva en vez de un generador de alarmas.
//!
//! # El formato es un contrato
//!
//! Estos campos acaban en el SIEM del cliente y en sus consultas guardadas.
//! Cambiar un nombre o quitar un campo rompe su trabajo, asi que el formato va
//! **versionado** y los nombres son estables. Una prueba lo fija.

use crate::flujo::Flujo;
use crate::hecho::{Direccion, ProtocoloApp};

/// Version del formato del registro.
///
/// Se incrementa cuando cambia la forma, nunca cuando cambia el contenido: quien
/// consuma el registro tiene que poder saber si lo entiende.
pub const VERSION_FORMATO: u32 = 1;

/// Como acabo un flujo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cierre {
    /// Los dos lados cerraron limpiamente.
    Limpio,
    /// Se corto con RST.
    Reiniciado,
    /// Expiro por inactividad sin cerrarse.
    Expirado,
    /// Se expulso de la tabla por falta de sitio.
    ///
    /// Que exista esta variante es deliberado: un flujo expulsado es un agujero
    /// de visibilidad, y decir «expirado» cuando en realidad se tiro por falta
    /// de memoria seria ocultar que el sensor se quedo corto.
    Expulsado,
}

impl Cierre {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Cierre::Limpio => "limpio",
            Cierre::Reiniciado => "reiniciado",
            Cierre::Expirado => "expirado",
            Cierre::Expulsado => "expulsado",
        }
    }
}

/// El registro de una conexion terminada.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistroConexion {
    /// Version del formato.
    pub version: u32,
    /// Extremo que inicio, si se supo.
    pub origen: String,
    /// Puerto de origen.
    pub puerto_origen: u16,
    /// Extremo que acepto.
    pub destino: String,
    /// Puerto de destino.
    pub puerto_destino: u16,
    /// Transporte.
    pub transporte: &'static str,
    /// Protocolo de aplicacion reconocido.
    pub protocolo: &'static str,
    /// Momento del primer paquete, en microsegundos Unix.
    pub inicio_us: u64,
    /// Duracion observada, en microsegundos.
    pub duracion_us: u64,
    /// Bytes del cliente al servidor.
    pub bytes_subida: u64,
    /// Bytes del servidor al cliente.
    pub bytes_bajada: u64,
    /// Paquetes del cliente al servidor.
    pub paquetes_subida: u64,
    /// Paquetes del servidor al cliente.
    pub paquetes_bajada: u64,
    /// Como acabo.
    pub cierre: &'static str,
    /// Si se vio el inicio del flujo.
    ///
    /// Cuando es falso, los sentidos son [`Direccion::Indeterminada`] y las
    /// cuentas de subida y bajada son «del extremo menor» y «del mayor», no del
    /// cliente y del servidor. Decirlo evita que alguien lea el registro al
    /// reves sin saberlo.
    pub inicio_visto: bool,
    /// Solapes con contenido distinto: indicio de evasion.
    pub solapes_contradictorios: u64,
    /// Bytes que se dieron por perdidos en el reensamblado.
    pub bytes_perdidos: u64,
}

impl RegistroConexion {
    /// Construye el registro de un flujo terminado.
    #[must_use]
    pub fn de_flujo(f: &Flujo, cierre: Cierre) -> RegistroConexion {
        // Si se vio el inicio, «subida» es del cliente al servidor. Si no, se
        // conserva el orden de la clave y se DICE con `inicio_visto`.
        let cliente_es_a = !f.inicio_visto || f.cliente_es_a;
        let (origen, puerto_origen, destino, puerto_destino) = if cliente_es_a {
            (f.clave.a.0, f.clave.a.1, f.clave.b.0, f.clave.b.1)
        } else {
            (f.clave.b.0, f.clave.b.1, f.clave.a.0, f.clave.a.1)
        };
        let (subida, bajada, p_subida, p_bajada) = if cliente_es_a {
            (f.bytes_ab, f.bytes_ba, f.paquetes_ab, f.paquetes_ba)
        } else {
            (f.bytes_ba, f.bytes_ab, f.paquetes_ba, f.paquetes_ab)
        };

        RegistroConexion {
            version: VERSION_FORMATO,
            origen: origen.to_string(),
            puerto_origen,
            destino: destino.to_string(),
            puerto_destino,
            transporte: f.clave.transporte.nombre(),
            protocolo: f.protocolo.nombre(),
            inicio_us: f.inicio_us,
            duracion_us: f.duracion_us(),
            bytes_subida: subida,
            bytes_bajada: bajada,
            paquetes_subida: p_subida,
            paquetes_bajada: p_bajada,
            cierre: cierre.nombre(),
            inicio_visto: f.inicio_visto,
            solapes_contradictorios: f.sentido_ab.anomalias().solapes_contradictorios
                + f.sentido_ba.anomalias().solapes_contradictorios,
            bytes_perdidos: f.sentido_ab.anomalias().bytes_perdidos
                + f.sentido_ba.anomalias().bytes_perdidos,
        }
    }

    /// Si el registro lleva indicios de que alguien intento evadir el sensor.
    #[must_use]
    pub fn hay_indicio_de_evasion(&self) -> bool {
        self.solapes_contradictorios > 0
    }

    /// Si el sensor no vio el flujo entero.
    ///
    /// Es distinto de «no paso nada»: un flujo con bytes perdidos pudo llevar
    /// cualquier cosa en el hueco, y el registro tiene que permitir saberlo.
    #[must_use]
    pub fn incompleto(&self) -> bool {
        self.bytes_perdidos > 0 || !self.inicio_visto
    }

    /// Los nombres de los campos, en orden, para la cabecera de un volcado.
    ///
    /// Es un CONTRATO con el SIEM del cliente: cambiarlo rompe sus consultas
    /// guardadas.
    #[must_use]
    pub fn campos() -> &'static [&'static str] {
        &[
            "version",
            "origen",
            "puerto_origen",
            "destino",
            "puerto_destino",
            "transporte",
            "protocolo",
            "inicio_us",
            "duracion_us",
            "bytes_subida",
            "bytes_bajada",
            "paquetes_subida",
            "paquetes_bajada",
            "cierre",
            "inicio_visto",
            "solapes_contradictorios",
            "bytes_perdidos",
        ]
    }

    /// Una linea separada por tabuladores, en el orden de [`RegistroConexion::campos`].
    ///
    /// Se elige tabulador y no coma porque ningun campo de aqui puede contener
    /// uno: las direcciones, los puertos y los nombres de protocolo son
    /// cerrados. Con comas habria que escapar, y escapar mal es como se cuela
    /// una inyeccion en el SIEM que consume esto.
    #[must_use]
    pub fn linea(&self) -> String {
        [
            self.version.to_string(),
            self.origen.clone(),
            self.puerto_origen.to_string(),
            self.destino.clone(),
            self.puerto_destino.to_string(),
            self.transporte.to_string(),
            self.protocolo.to_string(),
            self.inicio_us.to_string(),
            self.duracion_us.to_string(),
            self.bytes_subida.to_string(),
            self.bytes_bajada.to_string(),
            self.paquetes_subida.to_string(),
            self.paquetes_bajada.to_string(),
            self.cierre.to_string(),
            self.inicio_visto.to_string(),
            self.solapes_contradictorios.to_string(),
            self.bytes_perdidos.to_string(),
        ]
        .join("\t")
    }
}

/// Traduce la direccion de un hecho a «subida» o «bajada» legible.
#[must_use]
pub fn sentido_legible(d: Direccion) -> &'static str {
    match d {
        Direccion::ClienteAServidor => "subida",
        Direccion::ServidorACliente => "bajada",
        Direccion::Indeterminada => "indeterminado",
    }
}

/// Nombre del protocolo, para quien solo tenga el enumerado.
#[must_use]
pub fn nombre_protocolo(p: ProtocoloApp) -> &'static str {
    p.nombre()
}

#[cfg(test)]
mod pruebas {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::hecho::{ClaveFlujo, Transporte};
    use crate::reensamblado::Politica;

    fn flujo_de_prueba(inicio_visto: bool, cliente_es_a: bool) -> Flujo {
        let (k, _) = ClaveFlujo::normalizada(
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50_000),
            (IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            Transporte::Tcp,
        );
        let mut f = Flujo::nuevo(k, 1_000_000, Politica::PrimeroGana);
        f.ultimo_us = 3_000_000;
        f.bytes_ab = 500;
        f.bytes_ba = 12_000;
        f.paquetes_ab = 7;
        f.paquetes_ba = 15;
        f.inicio_visto = inicio_visto;
        f.cliente_es_a = cliente_es_a;
        f.protocolo = ProtocoloApp::Tls;
        f
    }

    #[test]
    fn un_registro_recoge_lo_que_paso_en_el_flujo() {
        let f = flujo_de_prueba(true, true);
        let r = RegistroConexion::de_flujo(&f, Cierre::Limpio);
        assert_eq!(r.version, VERSION_FORMATO);
        assert_eq!(r.origen, "10.0.0.1");
        assert_eq!(r.puerto_origen, 50_000);
        assert_eq!(r.destino, "93.184.216.34");
        assert_eq!(r.puerto_destino, 443);
        assert_eq!(r.protocolo, "tls");
        assert_eq!(r.transporte, "tcp");
        assert_eq!(r.duracion_us, 2_000_000);
        assert_eq!(r.bytes_subida, 500);
        assert_eq!(r.bytes_bajada, 12_000);
        assert_eq!(r.cierre, "limpio");
        assert!(!r.incompleto());
    }

    /// Cuando el CLIENTE es el otro extremo, subida y bajada se dan la vuelta.
    /// Si no lo hicieran, todos los registros de flujos capturados desde el lado
    /// del servidor estarian del reves.
    #[test]
    fn cuando_el_cliente_es_el_otro_extremo_la_subida_se_da_la_vuelta() {
        let f = flujo_de_prueba(true, false);
        let r = RegistroConexion::de_flujo(&f, Cierre::Limpio);
        assert_eq!(r.origen, "93.184.216.34");
        assert_eq!(r.puerto_origen, 443);
        assert_eq!(
            r.bytes_subida, 12_000,
            "lo del extremo b es ahora la subida"
        );
        assert_eq!(r.bytes_bajada, 500);
    }

    /// Sin haber visto el inicio NO se finge saber quien es el cliente: se
    /// conserva el orden de la clave y se DICE. Que alguien lea el registro al
    /// reves sin saberlo es peor que no tener el registro.
    #[test]
    fn sin_ver_el_inicio_el_registro_lo_declara() {
        let f = flujo_de_prueba(false, true);
        let r = RegistroConexion::de_flujo(&f, Cierre::Expirado);
        assert!(!r.inicio_visto);
        assert!(r.incompleto(), "un flujo sin inicio visto NO esta completo");
    }

    /// «Expulsado» existe como cierre propio a proposito: decir «expirado»
    /// cuando en realidad se tiro por falta de memoria ocultaria que el sensor
    /// se quedo corto.
    #[test]
    fn una_expulsion_por_memoria_no_se_disfraza_de_expiracion() {
        let f = flujo_de_prueba(true, true);
        let expulsado = RegistroConexion::de_flujo(&f, Cierre::Expulsado);
        let expirado = RegistroConexion::de_flujo(&f, Cierre::Expirado);
        assert_eq!(expulsado.cierre, "expulsado");
        assert_eq!(expirado.cierre, "expirado");
        assert_ne!(expulsado.cierre, expirado.cierre);
    }

    /// El indicio de evasion del reensamblado LLEGA al registro: si se quedara
    /// en el reensamblador, nadie lo veria nunca.
    #[test]
    fn el_indicio_de_evasion_llega_hasta_el_registro() {
        let mut f = flujo_de_prueba(true, true);
        f.sentido_ab.sincronizar(1000);
        // Se construye el solape contradictorio de verdad.
        f.sentido_ab.incorporar(1005, b"GET ");
        f.sentido_ab.incorporar(1005, b"PUT ");

        let r = RegistroConexion::de_flujo(&f, Cierre::Limpio);
        assert_eq!(r.solapes_contradictorios, 1);
        assert!(r.hay_indicio_de_evasion());
    }

    /// EL CONTRATO: los nombres de campo acaban en las consultas guardadas del
    /// cliente. Esta prueba existe para que cambiarlos duela.
    #[test]
    fn los_campos_del_registro_son_un_contrato_estable() {
        let campos = RegistroConexion::campos();
        assert_eq!(campos[0], "version");
        assert_eq!(campos[1], "origen");
        assert_eq!(campos[5], "transporte");
        assert_eq!(campos[6], "protocolo");
        assert_eq!(campos[13], "cierre");
        assert_eq!(campos.len(), 17);

        // Y la linea tiene exactamente tantos campos como la cabecera.
        let f = flujo_de_prueba(true, true);
        let r = RegistroConexion::de_flujo(&f, Cierre::Limpio);
        assert_eq!(r.linea().split('\t').count(), campos.len());
    }

    /// Ningun campo puede contener un tabulador: si pudiera, la linea se partiria
    /// mal en el SIEM y ahi es donde se cuela una inyeccion.
    #[test]
    fn ningun_campo_puede_romper_el_separador() {
        let f = flujo_de_prueba(true, true);
        let r = RegistroConexion::de_flujo(&f, Cierre::Limpio);
        for parte in r.linea().split('\t') {
            assert!(!parte.contains('\n'), "salto de linea en {parte:?}");
            assert!(!parte.contains('\r'), "retorno en {parte:?}");
        }
    }

    #[test]
    fn el_sentido_se_traduce_a_algo_legible() {
        assert_eq!(sentido_legible(Direccion::ClienteAServidor), "subida");
        assert_eq!(sentido_legible(Direccion::ServidorACliente), "bajada");
        assert_eq!(sentido_legible(Direccion::Indeterminada), "indeterminado");
    }
}
