//! El agente: `AegisFleetClient`.
//!
//! Se conecta al plano de control por mTLS presentando su certificado de flota,
//! se enrola, late periodicamente y reporta eventos. Antes de cada conexion
//! asegura que su certificado no esta a punto de caducar y, si lo esta, lo rota
//! —clave nueva en memoria, la vieja borrada—. La identidad con la que se
//! autentica es siempre la vigente en ese instante.

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConnection, StreamOwned};

use crate::error::{FleetError, Resultado};
use crate::proto::{
    AckEvento, AckLatido, Latido, ReporteEvento, RespuestaEnrolamiento, SolicitudEnrolamiento,
};
use crate::proto::{
    AckGrafo, AckStix, EmpujePolitica, ReporteGrafo, ReporteStix, SuscripcionPolitica,
};
use crate::rotacion::RotadorCertificados;
use crate::rpc::{escribir_marco, leer_marco, llamada_unaria, Metodo, ESTADO_OK};
use crate::tls::{cn_del_par, config_cliente};

/// Nombre de servidor que presenta el agente en el SNI.
///
/// Los certificados de flota se emiten con este SAN; el agente lo usa para
/// validar el certificado del plano de control.
const NOMBRE_SERVIDOR: &str = "localhost";

/// Una sesion mTLS abierta contra el plano de control.
///
/// Sobre ella se hacen las llamadas unarias del servicio. Se cierra al soltarse.
pub struct SesionFlota {
    tls: StreamOwned<ClientConnection, TcpStream>,
    cn_servidor: Option<String>,
}

impl SesionFlota {
    /// CN del certificado del servidor, si el handshake ya lo expuso.
    pub fn servidor_autenticado(&self) -> Option<&str> {
        self.cn_servidor.as_deref()
    }

    /// Enrola al agente.
    pub fn enrolar(&mut self, req: &SolicitudEnrolamiento) -> Resultado<RespuestaEnrolamiento> {
        let cuerpo = llamada_unaria(&mut self.tls, Metodo::Enrolar, &req.codificar())?;
        self.actualizar_servidor();
        RespuestaEnrolamiento::decodificar(&cuerpo)
    }

    /// Emite un latido.
    pub fn latir(&mut self, req: &Latido) -> Resultado<AckLatido> {
        let cuerpo = llamada_unaria(&mut self.tls, Metodo::Latir, &req.codificar())?;
        AckLatido::decodificar(&cuerpo)
    }

    /// Reporta un evento de seguridad.
    pub fn reportar_evento(&mut self, req: &ReporteEvento) -> Resultado<AckEvento> {
        let cuerpo = llamada_unaria(&mut self.tls, Metodo::ReportarEvento, &req.codificar())?;
        AckEvento::decodificar(&cuerpo)
    }

    /// Entrega un bundle de inteligencia STIX 2.1.
    pub fn reportar_stix(&mut self, req: &ReporteStix) -> Resultado<AckStix> {
        let cuerpo = llamada_unaria(&mut self.tls, Metodo::ReportarStix, &req.codificar())?;
        AckStix::decodificar(&cuerpo)
    }

    /// Entrega el subgrafo de linaje que rodea a una deteccion.
    pub fn reportar_grafo(&mut self, req: &ReporteGrafo) -> Resultado<AckGrafo> {
        let cuerpo = llamada_unaria(&mut self.tls, Metodo::ReportarGrafo, &req.codificar())?;
        AckGrafo::decodificar(&cuerpo)
    }

    /// Convierte esta sesion en un canal de politica y devuelve el canal.
    ///
    /// A partir de aqui la sesion deja de servir para llamadas unarias: la
    /// conexion pertenece al canal, que solo lee lo que el servidor empuje. Por
    /// eso consume `self` —el sistema de tipos impide usarla mal despues—.
    pub fn suscribir_politica(mut self, version_conocida: u64) -> Resultado<CanalPolitica> {
        let req = SuscripcionPolitica {
            id_agente: String::new(),
            version_conocida,
        };
        escribir_marco(
            &mut self.tls,
            Metodo::SuscribirPolitica.codigo(),
            &req.codificar(),
        )?;
        Ok(CanalPolitica { sesion: self })
    }

    /// Tras el primer intercambio, el certificado del servidor ya esta a mano.
    fn actualizar_servidor(&mut self) {
        if self.cn_servidor.is_none() {
            self.cn_servidor = cn_del_par(self.tls.conn.peer_certificates());
        }
    }
}

/// Canal por el que el agente RECIBE politica empujada por el servidor.
///
/// Cada llamada a [`CanalPolitica::siguiente`] bloquea hasta que el plano de
/// control escribe algo: politica nueva, comandos para este endpoint, o un
/// latido del canal. Es lo que hace que una orden global —"bloquear el puerto
/// 445 en toda la flota"— llegue en milisegundos en vez de esperar al siguiente
/// latido del agente.
pub struct CanalPolitica {
    sesion: SesionFlota,
}

impl CanalPolitica {
    /// Espera el siguiente empuje del servidor.
    ///
    /// Bloquea. El servidor envia un latido de canal periodicamente, asi que un
    /// silencio mas largo que ese periodo significa que la conexion murio.
    pub fn siguiente(&mut self) -> Resultado<EmpujePolitica> {
        let (estado, cuerpo) = leer_marco(&mut self.sesion.tls)?;
        if estado != ESTADO_OK {
            return Err(FleetError::Protocolo(format!(
                "el plano de control cerro el canal de politica con estado {estado}"
            )));
        }
        EmpujePolitica::decodificar(&cuerpo)
    }

    /// CN del servidor autenticado.
    pub fn servidor_autenticado(&self) -> Option<&str> {
        self.sesion.servidor_autenticado()
    }
}

/// El cliente-agente de flota.
pub struct ClienteFlota {
    hostname: String,
    version: String,
    servidor: SocketAddr,
    ca_der: CertificateDer<'static>,
    rotador: Arc<RotadorCertificados>,
}

impl ClienteFlota {
    /// Crea un agente que se conecta a `servidor`, confiando en `ca_der` y
    /// autenticandose con la identidad que gestiona `rotador`.
    pub fn nuevo(
        servidor: SocketAddr,
        ca_der: CertificateDer<'static>,
        rotador: Arc<RotadorCertificados>,
        hostname: &str,
        version: &str,
    ) -> ClienteFlota {
        ClienteFlota {
            hostname: hostname.to_string(),
            version: version.to_string(),
            servidor,
            ca_der,
            rotador,
        }
    }

    /// CN (identidad estable) del agente.
    pub fn cn(&self) -> &str {
        self.rotador.cn()
    }

    /// Abre una sesion mTLS nueva, rotando el certificado antes si procede.
    pub fn abrir_sesion(&self) -> Resultado<SesionFlota> {
        // Rotacion perezosa: si el certificado esta por caducar, se renueva
        // ahora, y la sesion se abre con la identidad nueva.
        let identidad = self.rotador.asegurar_vigencia()?;
        let cfg = config_cliente(&identidad, &self.ca_der)?;

        let sock = TcpStream::connect(self.servidor).map_err(|e| FleetError::Red {
            op: "connect",
            source: e,
        })?;
        let nombre = ServerName::try_from(NOMBRE_SERVIDOR)
            .map_err(|e| FleetError::ConfigTls(format!("nombre de servidor: {e}")))?;
        let conn = ClientConnection::new(cfg, nombre).map_err(|e| FleetError::Tls {
            op: "ClientConnection::new",
            detail: e.to_string(),
        })?;
        Ok(SesionFlota {
            tls: StreamOwned::new(conn, sock),
            cn_servidor: None,
        })
    }

    /// Construye la solicitud de enrolamiento con la identidad vigente.
    pub fn solicitud_enrolamiento(&self) -> Resultado<SolicitudEnrolamiento> {
        let id = self.rotador.actual()?;
        Ok(SolicitudEnrolamiento {
            id_agente: self.cn().to_string(),
            hostname: self.hostname.clone(),
            version_agente: self.version.clone(),
            huella_cert: id.huella(),
        })
    }

    /// Huella del certificado vigente.
    pub fn huella_actual(&self) -> Resultado<Vec<u8>> {
        Ok(self.rotador.actual()?.huella())
    }
}
