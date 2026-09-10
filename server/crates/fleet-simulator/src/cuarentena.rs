//! Medicion de la propagacion de una cuarentena de enjambre (FASE 44).
//!
//! QUE SE MIDE Y POR QUE ASI
//! -------------------------
//! El encargo pide demostrar que una orden de micro-segmentacion llega a diez
//! mil endpoints en menos de 200 ms. Medir eso exige tres cosas:
//!
//!   1. Un instante de salida (T0) fiable: el momento en que el plano de control
//!      ACEPTA la orden, no el momento en que el operador la escribio. Lo que se
//!      esta midiendo es la difusion, no el tiempo de tecleo.
//!   2. Un instante de llegada por CADA agente: cuando ESE endpoint ve por
//!      primera vez la direccion en su cuarentena. Un promedio no sirve: lo que
//!      importa es el ultimo, porque hasta que el ultimo no aplica la regla, la
//!      maquina comprometida todavia tiene por donde moverse.
//!   3. Que ambos relojes sean el mismo. Por eso la orden la emite el propio
//!      simulador: con dos procesos y dos relojes, la diferencia mediria tambien
//!      la deriva entre ellos.
//!
//! POR QUE UN CLIENTE HTTP A MANO
//! ------------------------------
//! Hace falta una sola peticion POST contra un servicio en la misma maquina.
//! Traerse una biblioteca HTTP completa para eso metaria decenas de crates en el
//! arbol de dependencias de una herramienta de PRUEBA, y el objetivo de FASE 42
//! fue justamente mantener ese arbol corto y auditable. Son cuarenta lineas de
//! HTTP/1.1 sin sorpresas.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Resultado de emitir la orden.
pub struct Orden {
    /// Codigo HTTP que devolvio el plano de control.
    pub codigo: u16,
    /// Cuerpo, para poder explicar un rechazo.
    pub cuerpo: String,
}

/// Abre sesion en la API y devuelve el testigo.
pub async fn abrir_sesion(
    api: std::net::SocketAddr,
    usuario: &str,
    clave: &str,
) -> Result<String, String> {
    let cuerpo = format!(r#"{{"usuario":"{usuario}","clave":"{clave}"}}"#);
    let r = peticion(api, "POST", "/api/sesion", None, Some(&cuerpo)).await?;
    if r.codigo != 200 {
        return Err(format!(
            "la API rechazo la sesion: {} {}",
            r.codigo, r.cuerpo
        ));
    }
    // Se extrae sin analizador de JSON: la respuesta es un objeto de un solo
    // campo que produce este mismo proyecto. Un analizador completo aqui seria
    // una dependencia mas para leer una cadena hexadecimal.
    let marca = "\"token\":\"";
    let i = r
        .cuerpo
        .find(marca)
        .ok_or_else(|| format!("respuesta de sesion inesperada: {}", r.cuerpo))?
        + marca.len();
    let j = r.cuerpo[i..]
        .find('"')
        .ok_or_else(|| "testigo sin cerrar".to_string())?;
    Ok(r.cuerpo[i..i + j].to_string())
}

/// Ordena la cuarentena de enjambre contra una direccion.
pub async fn ordenar(
    api: std::net::SocketAddr,
    testigo: &str,
    direccion: &str,
    motivo: &str,
) -> Result<Orden, String> {
    let cuerpo = format!(r#"{{"direccion":"{direccion}","motivo":"{motivo}"}}"#);
    peticion(api, "POST", "/api/cuarentena", Some(testigo), Some(&cuerpo)).await
}

/// Levanta la cuarentena.
pub async fn levantar(
    api: std::net::SocketAddr,
    testigo: &str,
    direccion: &str,
) -> Result<Orden, String> {
    let ruta = format!("/api/cuarentena?levantar={direccion}");
    peticion(api, "GET", &ruta, Some(testigo), None).await
}

/// Lo que el PLANO DE CONTROL dice haber difundido.
///
/// POR QUE HACEN FALTA DOS MEDIDAS Y NO UNA
/// ---------------------------------------
/// La medida de arriba —cuando cada agente VE la orden— es la que le importa al
/// cliente, y es la que se sigue publicando. Pero en un banco de pruebas de UNA
/// SOLA MAQUINA incluye tambien lo que tardan diez mil agentes virtuales en
/// despertar y leer sus sockets, compitiendo por los mismos nucleos que el
/// servidor. En produccion esos diez mil agentes estan en diez mil maquinas
/// distintas y no le quitan un ciclo al plano de control.
///
/// Esta segunda medida la da el propio servidor: desde que la lista nueva queda
/// publicada hasta que el ultimo canal termino de ESCRIBIRLA en su socket. Es la
/// parte que el producto controla, y la unica que sigue valiendo cuando la flota
/// es real.
///
/// Se publican las dos. Dar solo la del banco atribuye al producto un coste que
/// es del banco; dar solo la del producto esconde lo que el banco cuesta.
pub struct Difusion {
    /// Orden que se esta midiendo. Cero significa "ninguna todavia".
    pub generacion: u64,
    /// Canales que ya la escribieron.
    pub canales: u64,
    /// Retraso del ULTIMO de ellos.
    pub ultimo_ms: f64,
    /// Reparto: mediana y cola. Distingue "va al ritmo que da la maquina" de
    /// "va rapido y hay unos pocos rezagados".
    pub p50_ms: f64,
    /// Cota del 90 % de los canales.
    pub p90_ms: f64,
    /// Cota del 99 % de los canales.
    pub p99_ms: f64,
}

/// Consulta la difusion en curso al plano de control.
pub async fn difusion(api: std::net::SocketAddr, testigo: &str) -> Result<Difusion, String> {
    let r = peticion(api, "GET", "/api/cuarentena/difusion", Some(testigo), None).await?;
    if r.codigo != 200 {
        return Err(format!(
            "el plano de control no publica la difusion: {} {}",
            r.codigo, r.cuerpo
        ));
    }
    Ok(Difusion {
        generacion: numero(&r.cuerpo, "generacion")? as u64,
        canales: numero(&r.cuerpo, "canales")? as u64,
        ultimo_ms: numero(&r.cuerpo, "ultimo_ms")?,
        p50_ms: numero(&r.cuerpo, "p50_ms").unwrap_or(0.0),
        p90_ms: numero(&r.cuerpo, "p90_ms").unwrap_or(0.0),
        p99_ms: numero(&r.cuerpo, "p99_ms").unwrap_or(0.0),
    })
}

/// Extrae un numero de un objeto JSON plano.
///
/// El mismo criterio que en `abrir_sesion`: la respuesta la produce este
/// proyecto y tiene tres campos numericos. Un analizador completo seria una
/// dependencia mas en el arbol de una herramienta de prueba.
fn numero(cuerpo: &str, campo: &str) -> Result<f64, String> {
    let marca = format!("\"{campo}\":");
    let i = cuerpo
        .find(&marca)
        .ok_or_else(|| format!("falta '{campo}' en: {cuerpo}"))?
        + marca.len();
    let resto = &cuerpo[i..];
    let fin = resto
        .find(|c: char| c != '-' && c != '.' && !c.is_ascii_digit())
        .unwrap_or(resto.len());
    resto[..fin]
        .parse()
        .map_err(|_| format!("'{campo}' no es un numero en: {cuerpo}"))
}

/// Una peticion HTTP/1.1 con cierre de conexion.
async fn peticion(
    api: std::net::SocketAddr,
    metodo: &str,
    ruta: &str,
    testigo: Option<&str>,
    cuerpo: Option<&str>,
) -> Result<Orden, String> {
    let mut sock = TcpStream::connect(api)
        .await
        .map_err(|e| format!("no se pudo conectar con la API: {e}"))?;

    let mut cab = format!("{metodo} {ruta} HTTP/1.1\r\nHost: {api}\r\nConnection: close\r\n");
    if let Some(t) = testigo {
        cab.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    match cuerpo {
        Some(c) => {
            cab.push_str("Content-Type: application/json\r\n");
            cab.push_str(&format!("Content-Length: {}\r\n\r\n", c.len()));
            cab.push_str(c);
        }
        None => cab.push_str("\r\n"),
    }

    sock.write_all(cab.as_bytes())
        .await
        .map_err(|e| format!("no se pudo enviar: {e}"))?;

    // `Connection: close` hace que el servidor cierre al terminar, asi que leer
    // hasta EOF es suficiente y no hace falta interpretar el troceado.
    let mut respuesta = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), sock.read_to_end(&mut respuesta))
        .await
        .map_err(|_| "la API no respondio a tiempo".to_string())?
        .map_err(|e| format!("no se pudo leer la respuesta: {e}"))?;

    let texto = String::from_utf8_lossy(&respuesta);
    let codigo = texto
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("respuesta HTTP ilegible: {}", &texto[..texto.len().min(80)]))?;
    let cuerpo = texto
        .split_once("\r\n\r\n")
        .map(|(_, c)| c.to_string())
        .unwrap_or_default();

    Ok(Orden { codigo, cuerpo })
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use tokio::io::AsyncBufReadExt;
    use tokio::net::TcpListener;

    /// Un servidor HTTP minimo que devuelve lo que se le diga.
    ///
    /// No sustituye al plano de control: sustituye a la RED, para poder
    /// comprobar que este cliente arma bien la peticion y lee bien la
    /// respuesta sin depender de que haya un servidor levantado.
    async fn servidor(
        respuesta: &'static str,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dir = l.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let (sock, _) = l.accept().await.unwrap();
            let (lectura, mut escritura) = sock.into_split();
            let mut lineas = tokio::io::BufReader::new(lectura).lines();
            let mut peticion = String::new();
            while let Ok(Some(linea)) = lineas.next_line().await {
                peticion.push_str(&linea);
                peticion.push('\n');
                if linea.is_empty() {
                    break;
                }
            }
            escritura.write_all(respuesta.as_bytes()).await.unwrap();
            peticion
        });
        (dir, h)
    }

    #[tokio::test]
    async fn la_peticion_lleva_el_testigo_y_el_cuerpo() {
        let (dir, h) = servidor("HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\n\r\n{}").await;
        let r = ordenar(dir, "abc123", "10.0.0.5", "ransomware")
            .await
            .unwrap();
        assert_eq!(r.codigo, 202);

        let peticion = h.await.unwrap();
        assert!(peticion.contains("POST /api/cuarentena HTTP/1.1"));
        assert!(peticion.contains("Authorization: Bearer abc123"));
        assert!(peticion.contains("Content-Type: application/json"));
    }

    #[tokio::test]
    async fn el_testigo_se_extrae_de_la_respuesta_de_sesion() {
        let (dir, _h) =
            servidor("HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\n{\"token\":\"deadbeef1234\"}")
                .await;
        assert_eq!(
            abrir_sesion(dir, "admin", "admin").await.unwrap(),
            "deadbeef1234"
        );
    }

    #[tokio::test]
    async fn un_rechazo_se_devuelve_con_su_motivo_y_no_se_confunde_con_exito() {
        // Que la API rechace la orden es un resultado LEGITIMO —por ejemplo, si
        // la direccion es la del propio plano de control—. Tratarlo como exito
        // haria que la medicion contara una propagacion que nunca ocurrio.
        let (dir, _h) = servidor(
            "HTTP/1.1 409 Conflict\r\nContent-Length: 30\r\n\r\n{\"error\":\"es la del control\"}",
        )
        .await;
        let r = ordenar(dir, "t", "127.0.0.1", "prueba").await.unwrap();
        assert_eq!(r.codigo, 409);
        assert!(r.cuerpo.contains("es la del control"));
    }

    #[tokio::test]
    async fn la_difusion_del_plano_de_control_se_lee_entera() {
        let (dir, _h) = servidor(
            "HTTP/1.1 200 OK\r\nContent-Length: 58\r\n\r\n             {\"generacion\":3,\"canales\":10000,\"ultimo_ms\":41.375}",
        )
        .await;
        let d = difusion(dir, "t").await.unwrap();
        assert_eq!((d.generacion, d.canales), (3, 10000));
        assert!((d.ultimo_ms - 41.375).abs() < 1e-9);
    }

    #[tokio::test]
    async fn una_difusion_sin_generacion_no_se_lee_como_un_cero() {
        // Un plano de control que no atiende el transporte de flota responde
        // 503. Leerlo como ceros diria "difundida al instante" y la prueba de
        // propagacion pasaria sin haber propagado nada.
        let (dir, _h) = servidor(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 20\r\n\r\n{\"error\":\"sin flota\"}",
        )
        .await;
        assert!(difusion(dir, "t").await.is_err());
    }

    #[tokio::test]
    async fn una_api_que_no_responde_no_cuelga_la_medicion() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dir = l.local_addr().unwrap();
        // Se acepta y no se contesta nunca.
        let _mudo = tokio::spawn(async move {
            let _c = l.accept().await;
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        let inicio = std::time::Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(20), ordenar(dir, "t", "10.0.0.5", "x"))
            .await
            .expect("el cliente tiene que rendirse solo");
        assert!(r.is_err());
        assert!(inicio.elapsed() < Duration::from_secs(20));
    }
}
