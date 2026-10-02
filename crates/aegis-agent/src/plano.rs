//! El agente y el plano de control (H-23, E6.5 del MP-16), en solo-auditoria.
//!
//! # Lo que hace
//!
//! Enrola al agente con su certificado de flota, le hace latir con el estado de
//! sus motores y entrega cada veredicto del arbitro al plano de control. Todo
//! ocurre en el hilo del enlace ([`aegis_fleet::enlace`]): el bucle de eventos
//! solo clona el veredicto —que ya se emite rara vez: cuando el de una entidad
//! cambia a algo que hay que atender— y lo deja en una cola acotada.
//!
//! # Lo que NO hace
//!
//! - **No obedece.** Solo auditoria: ni politica, ni comandos, ni aislamiento.
//! - **No es obligatorio.** Sin fichero de configuracion no hay conexion: el
//!   agente protege en local y lo dice al arrancar.
//! - **No trae su propio TLS.** El transporte es el cliente de `aegis-fleet`,
//!   con la CA de flota como unica raiz de confianza; el plano de control
//!   identifica al agente por el CN de su certificado, nunca por lo que diga el
//!   mensaje.
//!
//! # Configuracion
//!
//! ```toml
//! # /etc/aegiscore/plano-control.toml
//! [flota]
//! servidor = "aegis-flota.empresa.local:8443"   # o "mtls://host:puerto"
//! ca = "/etc/aegiscore/pki/flota-ca.crt"
//! certificado = "/etc/aegiscore/pki/agente.crt"
//! clave = "/etc/aegiscore/pki/agente.key"       # PKCS#8, modo 0600
//! reintento_max_seg = 300                        # opcional
//! plazo_red_seg = 10                             # opcional
//! ```
//!
//! El analizador es estricto a proposito: una clave desconocida o repetida es un
//! error que se ve al arrancar, no un ajuste que se ignora en silencio.
//!
//! # Memoria
//!
//! La cola se lleva un octavo del margen sin asignar del reposo
//! ([`Componente::Margen`]), entre [`COLA_MINIMA`] y [`COLA_MAXIMA`]. En cada
//! latido el agente se mide ([`aegis_presupuesto::uso_propio`]) y, si entra en
//! contencion, el techo de la cola baja al que permite el regimen —el 25 % en
//! contencion, nada si se excede—: lo que sobra se suelta contado, empezando
//! por lo menos grave. La memoria medida viaja en el latido.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_entidad::{Resultado, Severidad, Veredicto};
use aegis_fleet::enlace::{
    cadena_json, recortar, Admision, ConectorFlota, ConfigEnlace, Enlace, Instantanea, Medida,
    Reportable, MAX_ESTADO_AGENTE,
};
use aegis_fleet::proto::ReporteEvento;
use aegis_fleet::{
    ahora_unix, certificado_desde_pem, EmisorFichero, PoliticaRotacion, RotadorCertificados,
};
use aegis_motor::{EstadoMotor, Omitido};
use aegis_presupuesto::{Componente, Presupuesto, Regimen, Vigilante};

/// Donde busca el agente la configuracion si no se le da otra.
pub const CONFIG_POR_DEFECTO: &str = "/etc/aegiscore/plano-control.toml";

/// Categoria con la que llega un veredicto del arbitro al plano de control.
pub const CATEGORIA: &str = "veredicto-arbitro";

/// Techo minimo de la cola, en bytes.
pub const COLA_MINIMA: usize = 64 * 1024;

/// Techo maximo de la cola, en bytes.
pub const COLA_MAXIMA: usize = 4 * 1024 * 1024;

/// Parte del margen sin asignar que se lleva la cola: un octavo.
const FRACCION_DEL_MARGEN: u64 = 8;

/// Largo maximo de cada texto libre de los detalles.
///
/// El plano de control admite 512 bytes por valor; se deja margen.
const MAX_TEXTO: usize = 400;

/// Largo maximo de los detalles enteros. El plano de control admite 4096.
const MAX_DETALLES: usize = 4000;

/// Largo maximo de la descripcion.
const MAX_DESCRIPCION: usize = 1024;

/// Espera maxima entre reintentos por defecto, en segundos.
const REINTENTO_MAX_DEFECTO: u64 = 300;

/// Plazo de red por defecto, en segundos.
const PLAZO_RED_DEFECTO: u64 = 10;

/// Ventana de las «amenazas activas» que declara el latido.
const HORA: Duration = Duration::from_secs(3600);

/// Muestras que se guardan para esa ventana.
const MAX_HISTORIA: usize = 4096;

/// La configuracion del enlace con el plano de control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPlano {
    /// `host:puerto` del transporte nativo de flota.
    pub servidor: String,
    /// Certificado de la CA de flota, en PEM: la unica raiz de confianza.
    pub ca: PathBuf,
    /// Certificado del agente, en PEM.
    pub certificado: PathBuf,
    /// Clave del agente, PKCS#8 en PEM, modo 0600.
    pub clave: PathBuf,
    /// Espera maxima entre reintentos.
    pub reintento_max: Duration,
    /// Plazo de conexion y de cada lectura o escritura.
    pub plazo_red: Duration,
}

/// Lee la configuracion.
///
/// Devuelve `Ok(None)` si el fichero no existe y no se pidio de forma
/// explicita: es el agente sin plano de control, que protege en local. Si se
/// pidio con `--plano-control` y no existe, es un error.
pub fn cargar(ruta: &Path, explicita: bool) -> Result<Option<ConfigPlano>, String> {
    match std::fs::read_to_string(ruta) {
        Ok(texto) => analizar(&texto)
            .map(Some)
            .map_err(|m| format!("{}: {m}", ruta.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !explicita => Ok(None),
        Err(e) => Err(format!("no se pudo leer {}: {e}", ruta.display())),
    }
}

/// Analiza el texto de la configuracion.
pub fn analizar(texto: &str) -> Result<ConfigPlano, String> {
    let mut en_flota = false;
    let mut servidor: Option<String> = None;
    let mut ca: Option<PathBuf> = None;
    let mut certificado: Option<PathBuf> = None;
    let mut clave: Option<PathBuf> = None;
    let mut reintento: Option<u64> = None;
    let mut plazo: Option<u64> = None;

    for (n, bruta) in texto.lines().enumerate() {
        let num = n + 1;
        let linea = bruta.trim();
        if linea.is_empty() || linea.starts_with('#') {
            continue;
        }
        if let Some(seccion) = linea.strip_prefix('[') {
            let nombre = seccion
                .strip_suffix(']')
                .map(str::trim)
                .ok_or_else(|| format!("linea {num}: seccion mal cerrada"))?;
            if nombre != "flota" {
                return Err(format!(
                    "linea {num}: seccion desconocida [{nombre}]; solo existe [flota]"
                ));
            }
            if en_flota {
                return Err(format!("linea {num}: [flota] repetida"));
            }
            en_flota = true;
            continue;
        }
        if !en_flota {
            return Err(format!("linea {num}: clave fuera de [flota]"));
        }
        let (nombre, valor) = linea
            .split_once('=')
            .ok_or_else(|| format!("linea {num}: se esperaba «clave = valor»"))?;
        let (nombre, valor) = (nombre.trim(), valor.trim());
        match nombre {
            "servidor" => fijar(&mut servidor, texto_toml(valor, num)?, nombre, num)?,
            "ca" | "certificado" | "clave" => {
                let ruta = ruta_absoluta(texto_toml(valor, num)?, nombre, num)?;
                let hueco = match nombre {
                    "ca" => &mut ca,
                    "certificado" => &mut certificado,
                    _ => &mut clave,
                };
                fijar(hueco, ruta, nombre, num)?;
            }
            "reintento_max_seg" => {
                fijar(&mut reintento, entero(valor, num, 1, 3600)?, nombre, num)?
            }
            "plazo_red_seg" => fijar(&mut plazo, entero(valor, num, 1, 120)?, nombre, num)?,
            otra => return Err(format!("linea {num}: clave desconocida «{otra}»")),
        }
    }

    let falta = |que: &str| format!("falta «{que}» en [flota]");
    Ok(ConfigPlano {
        servidor: normalizar_servidor(&servidor.ok_or_else(|| falta("servidor"))?)?,
        ca: ca.ok_or_else(|| falta("ca"))?,
        certificado: certificado.ok_or_else(|| falta("certificado"))?,
        clave: clave.ok_or_else(|| falta("clave"))?,
        reintento_max: Duration::from_secs(reintento.unwrap_or(REINTENTO_MAX_DEFECTO)),
        plazo_red: Duration::from_secs(plazo.unwrap_or(PLAZO_RED_DEFECTO)),
    })
}

fn fijar<T>(hueco: &mut Option<T>, valor: T, que: &str, num: usize) -> Result<(), String> {
    if hueco.is_some() {
        return Err(format!("linea {num}: «{que}» repetida"));
    }
    *hueco = Some(valor);
    Ok(())
}

/// Una cadena entre comillas dobles, sin escapes, con un comentario opcional
/// detras.
fn texto_toml(valor: &str, num: usize) -> Result<String, String> {
    let resto = valor
        .strip_prefix('"')
        .ok_or_else(|| format!("linea {num}: el valor tiene que ir entre comillas dobles"))?;
    let (dentro, detras) = resto
        .split_once('"')
        .ok_or_else(|| format!("linea {num}: comillas sin cerrar"))?;
    if dentro.contains('\\') {
        return Err(format!("linea {num}: no se admiten secuencias de escape"));
    }
    let detras = detras.trim();
    if !detras.is_empty() && !detras.starts_with('#') {
        return Err(format!("linea {num}: sobra «{detras}» detras del valor"));
    }
    if dentro.is_empty() {
        return Err(format!("linea {num}: valor vacio"));
    }
    Ok(dentro.to_string())
}

fn entero(valor: &str, num: usize, min: u64, max: u64) -> Result<u64, String> {
    let limpio = valor.split('#').next().unwrap_or("").trim();
    let n: u64 = limpio
        .parse()
        .map_err(|_| format!("linea {num}: «{limpio}» no es un entero"))?;
    if !(min..=max).contains(&n) {
        return Err(format!("linea {num}: {n} fuera de {min}..={max}"));
    }
    Ok(n)
}

fn ruta_absoluta(valor: String, que: &str, num: usize) -> Result<PathBuf, String> {
    let ruta = PathBuf::from(valor);
    if !ruta.is_absolute() {
        return Err(format!(
            "linea {num}: «{que}» tiene que ser una ruta absoluta (el servicio arranca en /)"
        ));
    }
    Ok(ruta)
}

/// `host:puerto`, aceptando el esquema `mtls://` y rechazando cualquier otro.
fn normalizar_servidor(s: &str) -> Result<String, String> {
    let sin_esquema = match s.split_once("://") {
        None => s,
        Some(("mtls", resto)) => resto,
        Some((otro, _)) => {
            return Err(format!(
                "servidor: el esquema «{otro}» no vale; el transporte de flota es mTLS \
                 nativo (host:puerto o mtls://host:puerto)"
            ))
        }
    };
    let limpio = sin_esquema.trim_end_matches('/');
    let (host, puerto) = limpio
        .rsplit_once(':')
        .ok_or_else(|| format!("servidor: falta el puerto en «{s}»"))?;
    if host.is_empty() || !matches!(puerto.parse::<u16>(), Ok(p) if p != 0) {
        return Err(format!("servidor: «{s}» no es host:puerto"));
    }
    Ok(limpio.to_string())
}

/// Un veredicto del arbitro esperando su turno para salir.
pub struct VeredictoEnCola {
    veredicto: Veredicto,
    arranque: u64,
    secuencia: u64,
    momento_unix: u64,
}

impl VeredictoEnCola {
    /// Envuelve un veredicto con su identidad de envio.
    pub fn nuevo(
        veredicto: Veredicto,
        arranque: u64,
        secuencia: u64,
        momento_unix: u64,
    ) -> VeredictoEnCola {
        VeredictoEnCola {
            veredicto,
            arranque,
            secuencia,
            momento_unix,
        }
    }

    /// Identificador del veredicto: el arranque del agente y su numero de
    /// orden. Un reenvio tras un corte lleva el mismo, y con el se deduplica.
    pub fn id(&self) -> String {
        format!("{:x}-{}", self.arranque, self.secuencia)
    }
}

/// La severidad de la escala comun en la del cable (0 informativa .. 4 critica).
pub fn severidad_de_cable(s: Severidad) -> u64 {
    match s {
        Severidad::Info => 0,
        Severidad::Baja => 1,
        Severidad::Media => 2,
        Severidad::Alta => 3,
        Severidad::Critica => 4,
    }
}

impl Reportable for VeredictoEnCola {
    fn peso(&self) -> usize {
        let v = &self.veredicto;
        std::mem::size_of::<Self>()
            + v.porque.capacity()
            + v.planos.capacity() * std::mem::size_of::<aegis_entidad::Plano>()
            + v.senales.capacity() * std::mem::size_of::<aegis_entidad::Senal>()
            + v.senales.iter().map(|s| s.porque.capacity()).sum::<usize>()
    }

    fn prioridad(&self) -> u8 {
        let base = severidad_de_cable(self.veredicto.severidad) as u8 * 2;
        base + u8::from(self.veredicto.resultado == Resultado::Malicioso)
    }

    fn reporte(&self, id_agente: &str) -> ReporteEvento {
        let v = &self.veredicto;
        ReporteEvento {
            id_agente: id_agente.to_string(),
            severidad: severidad_de_cable(v.severidad),
            categoria: CATEGORIA.to_string(),
            descripcion: recortar(&format!("{} {}", v.entidad, v.resumen()), MAX_DESCRIPCION),
            momento_unix: self.momento_unix,
            detalles_json: detalles(self),
        }
    }
}

/// Los atributos del veredicto, dentro de los limites del plano de control:
/// escalares, a lo sumo 512 bytes por valor y 4096 en total.
fn detalles(e: &VeredictoEnCola) -> String {
    let completo = detalles_con(e, MAX_TEXTO);
    if completo.len() <= MAX_DETALLES {
        completo
    } else {
        // Solo pasa con textos llenos de caracteres que el JSON escapa.
        detalles_con(e, 64)
    }
}

fn detalles_con(e: &VeredictoEnCola, max: usize) -> String {
    let v = &e.veredicto;
    let planos: Vec<&str> = v.planos.iter().map(|p| p.nombre()).collect();
    let motores: Vec<String> = v
        .senales
        .iter()
        .map(|s| {
            format!(
                "{}:{}:{}",
                s.motor.nombre(),
                s.juicio.nombre(),
                s.severidad.nombre()
            )
        })
        .collect();
    format!(
        "{{\"id_veredicto\":{},\"entidad\":{},\"resultado\":{},\"severidad\":{},\
         \"confianza\":{},\"planos\":{},\"corroboracion\":{},\"motores\":{},\"porque\":{},\
         \"solo_auditoria\":true}}",
        cadena_json(&e.id()),
        cadena_json(&recortar(&v.entidad.texto(), max)),
        cadena_json(v.resultado.nombre()),
        cadena_json(v.severidad.nombre()),
        v.confianza.centesimas(),
        cadena_json(&recortar(&planos.join(","), max)),
        v.planos.len(),
        cadena_json(&recortar(&motores.join(","), max)),
        cadena_json(&recortar(&v.porque, max)),
    )
}

/// El estado de los motores como objeto JSON, para el latido.
pub fn estado_motores_json(
    motores: &[EstadoMotor],
    omitidos: &[Omitido],
    veredictos: u64,
    expedientes: usize,
    expulsados: u64,
) -> String {
    let mut s = String::with_capacity(256 + motores.len() * 256);
    let _ = write!(
        s,
        "{{\"veredictos\":{veredictos},\"expedientes\":{expedientes},\
         \"expulsados\":{expulsados},\"motores\":["
    );
    for (i, m) in motores.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let sin_datos: u64 = m.sin_datos.values().sum();
        let _ = write!(
            s,
            "{{\"nombre\":{},\"camino\":{},\"evaluaciones\":{},\"senales\":{},\
             \"sin_datos\":{},\"ultimo_sin_datos\":{},\"excesos\":{},\"suspensiones\":{},\
             \"suspendido\":{},\"memoria\":{},\"p99_ns\":{}}}",
            cadena_json(m.nombre),
            cadena_json(m.camino.nombre()),
            m.evaluaciones,
            m.senales,
            sin_datos,
            m.ultimo_sin_datos
                .as_deref()
                .map_or_else(|| "null".to_string(), |u| cadena_json(&recortar(u, 120))),
            m.excesos,
            m.suspensiones,
            m.suspendido,
            m.memoria,
            m.latencia.percentil(99.0),
        );
    }
    s.push_str("],\"omitidos\":[");
    for (i, o) in omitidos.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            "{{\"motor\":{},\"requisito\":{},\"motivo\":{}}}",
            cadena_json(o.motor),
            cadena_json(o.requisito.nombre()),
            cadena_json(&recortar(&o.motivo, 120)),
        );
    }
    s.push_str("]}");
    if s.len() > MAX_ESTADO_AGENTE {
        return format!(
            "{{\"recortado\":true,\"motores\":{},\"omitidos\":{}}}",
            motores.len(),
            omitidos.len()
        );
    }
    s
}

/// Techo de la cola (bytes y elementos) que sale del presupuesto del host.
pub fn capacidad_de(p: &Presupuesto) -> (usize, usize) {
    let bytes = usize::try_from(p.cuota(Componente::Margen) / FRACCION_DEL_MARGEN)
        .unwrap_or(COLA_MAXIMA)
        .clamp(COLA_MINIMA, COLA_MAXIMA);
    (bytes, (bytes / 256).clamp(64, 8192))
}

/// Techo de la cola que permite el regimen de memoria del momento.
fn capacidad_segun(regimen: Regimen, vigilante: &Vigilante, maxima: usize) -> usize {
    if regimen.admite_trabajo_pesado() {
        return maxima;
    }
    usize::try_from(vigilante.permitido(Componente::Margen) / FRACCION_DEL_MARGEN)
        .unwrap_or(0)
        .min(maxima)
}

/// Lo que el enlace mide del agente en cada latido, en su propio hilo.
fn medidor(
    presupuesto: Presupuesto,
    capacidad_maxima: usize,
    acusadores: Arc<AtomicU64>,
) -> Box<dyn FnMut() -> Medida + Send> {
    let mut vigilante = Vigilante::nuevo(presupuesto);
    // La cuenta de acusaciones hace una hora; al arrancar, cero.
    let mut historia: VecDeque<(Instant, u64)> = VecDeque::from([(Instant::now(), 0)]);
    Box::new(move || {
        let uso = aegis_presupuesto::uso_propio();
        let capacidad_bytes = uso.map(|u| {
            let regimen = vigilante.observar(&u);
            capacidad_segun(regimen, &vigilante, capacidad_maxima)
        });
        let total = acusadores.load(Ordering::Relaxed);
        let ahora = Instant::now();
        historia.push_back((ahora, total));
        while historia.len() > MAX_HISTORIA
            || historia
                .front()
                .is_some_and(|(t, _)| ahora.duration_since(*t) > HORA)
        {
            historia.pop_front();
        }
        let base = historia.front().map_or(total, |(_, n)| *n);
        Medida {
            rss_kb: uso.map_or(0, |u| u.total() / 1024),
            amenazas_activas: total.saturating_sub(base),
            capacidad_bytes,
        }
    })
}

fn nombre_de_maquina() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "desconocida".to_string())
}

/// El enlace del agente con el plano de control.
pub struct PlanoControl {
    enlace: Enlace<VeredictoEnCola>,
    arranque: u64,
    secuencia: AtomicU64,
    acusadores: Arc<AtomicU64>,
    cn: String,
    capacidad_bytes: usize,
}

impl PlanoControl {
    /// Arranca el enlace con el presupuesto efectivo de este host.
    ///
    /// Devuelve tambien los avisos que hay que registrar (un certificado fuera
    /// de vigencia, por ejemplo), que no impiden arrancar.
    pub fn arrancar(
        cfg: &ConfigPlano,
        version: &str,
    ) -> Result<(PlanoControl, Vec<String>), String> {
        Self::arrancar_con(cfg, aegis_presupuesto::efectivo(), version)
    }

    /// Arranca el enlace con un presupuesto dado.
    pub fn arrancar_con(
        cfg: &ConfigPlano,
        presupuesto: Presupuesto,
        version: &str,
    ) -> Result<(PlanoControl, Vec<String>), String> {
        let mut avisos = Vec::new();
        let ca_pem = std::fs::read_to_string(&cfg.ca)
            .map_err(|e| format!("no se pudo leer la CA {}: {e}", cfg.ca.display()))?;
        let ca_der =
            certificado_desde_pem(&ca_pem).map_err(|e| format!("CA {}: {e}", cfg.ca.display()))?;

        let emisor = EmisorFichero::nuevo(&cfg.certificado, &cfg.clave);
        let inicial = emisor
            .leer()
            .map_err(|e| format!("identidad del agente: {e}"))?;
        let ahora = ahora_unix();
        if !inicial.vigente(ahora) {
            avisos.push(format!(
                "el certificado {} no esta vigente ahora (de {} a {}, unix): el enlace \
                 reintentara y volvera a leer los ficheros",
                cfg.certificado.display(),
                inicial.no_antes_unix,
                inicial.no_despues_unix
            ));
        }
        let cn = inicial.cn.clone();
        // La politica de rotacion con la vida del certificado provisionado: a
        // partir del 60 % se relee el fichero antes de cada conexion, para que
        // un certificado renovado en disco se use sin reiniciar el agente.
        let vida = inicial
            .no_despues_unix
            .saturating_sub(inicial.no_antes_unix)
            .max(1);
        drop(inicial);
        let rotador = RotadorCertificados::nuevo(
            &cn,
            PoliticaRotacion {
                validez_seg: vida,
                renovar_al_pct: 60,
            },
            Arc::new(emisor),
        )
        .map_err(|e| format!("identidad del agente: {e}"))?;

        let conector = ConectorFlota::nuevo(
            &cfg.servidor,
            ca_der,
            Arc::new(rotador),
            &nombre_de_maquina(),
            version,
            cfg.plazo_red,
        );
        let (capacidad_bytes, capacidad_elementos) = capacidad_de(&presupuesto);
        let acusadores = Arc::new(AtomicU64::new(0));
        let enlace = Enlace::arrancar(
            conector,
            ConfigEnlace {
                capacidad_bytes,
                capacidad_elementos,
                reintento_tope: cfg.reintento_max,
                ..ConfigEnlace::default()
            },
            medidor(presupuesto, capacidad_bytes, Arc::clone(&acusadores)),
        )
        .map_err(|e| format!("enlace: {e}"))?;

        Ok((
            PlanoControl {
                enlace,
                arranque: ahora,
                secuencia: AtomicU64::new(0),
                acusadores,
                cn,
                capacidad_bytes,
            },
            avisos,
        ))
    }

    /// Entrega un veredicto del arbitro. No bloquea mas que un cerrojo corto.
    pub fn ofrecer(&self, v: &Veredicto) -> Admision {
        if matches!(v.resultado, Resultado::Malicioso | Resultado::Sospechoso) {
            self.acusadores.fetch_add(1, Ordering::Relaxed);
        }
        let secuencia = self.secuencia.fetch_add(1, Ordering::Relaxed) + 1;
        self.enlace.ofrecer(VeredictoEnCola::nuevo(
            v.clone(),
            self.arranque,
            secuencia,
            ahora_unix(),
        ))
    }

    /// Publica el estado de los motores; viaja con el siguiente latido.
    pub fn publicar_estado(&self, json: String) {
        self.enlace.publicar_estado(json);
    }

    /// Las cuentas del enlace.
    pub fn instantanea(&self) -> Instantanea {
        self.enlace.instantanea()
    }

    /// El CN del certificado con el que se presenta el agente.
    pub fn cn(&self) -> &str {
        &self.cn
    }

    /// Techo de bytes de la cola al arrancar.
    pub fn capacidad_bytes(&self) -> usize {
        self.capacidad_bytes
    }

    /// Una linea para el informe periodico del agente.
    pub fn informe(&self) -> String {
        resumen(&self.instantanea())
    }

    /// Para el enlace y devuelve las cuentas finales.
    pub fn parar(self) -> Instantanea {
        self.enlace.parar()
    }
}

/// Las cuentas del enlace en una linea.
pub fn resumen(i: &Instantanea) -> String {
    format!(
        "plano de control: conectado={} ofrecidos={} enviados={} en_cola={} \
         bytes_en_cola={} capacidad={} perdidos={} (tope={} prioridad={} memoria={} \
         enormes={} servidor={}) reenviados={} conexiones={} fallos_conexion={} latidos={} \
         comandos_ignorados={} cuadra={} ultimo_error={}",
        i.conectado,
        i.ofrecidos,
        i.enviados,
        i.en_cola,
        i.bytes_en_cola,
        i.capacidad_bytes,
        i.perdidos(),
        i.perdidos_por_tope,
        i.desalojados_por_prioridad,
        i.perdidos_por_memoria,
        i.enormes,
        i.rechazados_por_servidor,
        i.reenviados,
        i.conexiones,
        i.fallos_conexion,
        i.latidos,
        i.comandos_ignorados,
        i.cuadra(),
        i.ultimo_error.as_deref().unwrap_or("-"),
    )
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::entidad::maquina;
    use aegis_entidad::{Confianza, Juicio, Motor, Plano, Senal};

    const BUENA: &str = r#"
# Plano de control de prueba
[flota]
servidor = "mtls://flota.ejemplo:8443/"   # con esquema y barra
ca = "/etc/aegiscore/pki/flota-ca.crt"
certificado = "/etc/aegiscore/pki/agente.crt"
clave = "/etc/aegiscore/pki/agente.key"
plazo_red_seg = 5 # corto
"#;

    #[test]
    fn la_configuracion_buena_se_entiende_con_sus_defectos() {
        let c = analizar(BUENA).expect("configuracion");
        assert_eq!(c.servidor, "flota.ejemplo:8443");
        assert_eq!(c.ca, PathBuf::from("/etc/aegiscore/pki/flota-ca.crt"));
        assert_eq!(c.clave, PathBuf::from("/etc/aegiscore/pki/agente.key"));
        assert_eq!(c.plazo_red, Duration::from_secs(5));
        assert_eq!(c.reintento_max, Duration::from_secs(REINTENTO_MAX_DEFECTO));
    }

    #[test]
    fn la_configuracion_dudosa_se_rechaza_diciendo_por_que() {
        let casos = [
            (BUENA.replace("[flota]", "[otra]"), "seccion desconocida"),
            (
                BUENA.replace("plazo_red_seg", "plazo_red"),
                "clave desconocida",
            ),
            (format!("{BUENA}ca = \"/x\"\n"), "repetida"),
            (BUENA.replace("mtls://", "https://"), "esquema"),
            (BUENA.replace(":8443/", "/"), "puerto"),
            (
                BUENA.replace("\"/etc/aegiscore/pki/agente.key\"", "\"agente.key\""),
                "absoluta",
            ),
            (BUENA.replace("= 5 # corto", "= 500"), "fuera de"),
            (
                BUENA.replace("clave = \"/etc/aegiscore/pki/agente.key\"\n", ""),
                "falta «clave»",
            ),
            (format!("servidor = \"a:1\"\n{BUENA}"), "fuera de [flota]"),
            (
                BUENA.replace("\"/etc/aegiscore/pki/flota-ca.crt\"", "/sin/comillas"),
                "comillas",
            ),
        ];
        for (texto, motivo) in casos {
            let e = analizar(&texto).expect_err(motivo);
            assert!(e.contains(motivo), "esperaba «{motivo}» y dijo «{e}»");
        }
    }

    #[test]
    fn sin_fichero_no_hay_plano_salvo_que_se_pidiera() {
        let ruta = Path::new("/no/existe/aegis-plano-control.toml");
        assert_eq!(cargar(ruta, false), Ok(None));
        assert!(cargar(ruta, true).is_err());
    }

    fn veredicto(porque: &str) -> Veredicto {
        let entidad = maquina("prueba");
        Veredicto {
            entidad: entidad.clone(),
            resultado: Resultado::Malicioso,
            severidad: Severidad::Critica,
            confianza: Confianza::ALTA,
            porque: porque.to_string(),
            planos: vec![Plano::Conductual, Plano::Memoria],
            senales: vec![Senal {
                motor: Motor::Conductual,
                entidad,
                juicio: Juicio::Malicioso,
                severidad: Severidad::Critica,
                confianza: Confianza::ALTA,
                porque: porque.to_string(),
                cuando_ns: 1,
            }],
        }
    }

    #[test]
    fn el_veredicto_viaja_con_sus_atributos_dentro_de_los_limites_del_servidor() {
        let e = VeredictoEnCola::nuevo(veredicto("cifra ficheros"), 0xabc, 7, 1_700_000_000);
        let r = e.reporte("agente-1");
        assert_eq!((r.severidad, r.categoria.as_str()), (4, CATEGORIA));
        assert_eq!(r.momento_unix, 1_700_000_000);
        let d: serde_json::Value = serde_json::from_str(&r.detalles_json).expect("JSON valido");
        assert_eq!(d["id_veredicto"], "abc-7");
        assert_eq!(d["resultado"], "malicioso");
        assert_eq!(d["corroboracion"], 2);
        assert_eq!(d["motores"], "conductual:malicioso:critica");
        assert_eq!(d["solo_auditoria"], true);

        // Un «porque» hostil: enorme, con comillas y controles. Sigue siendo JSON
        // valido, plano, y cabe en los limites de `normalizar_detalles`.
        let hostil = "\"\u{1}\\\n".repeat(2000);
        let r = VeredictoEnCola::nuevo(veredicto(&hostil), 1, 1, 0).reporte("a");
        assert!(r.detalles_json.len() <= 4096, "{}", r.detalles_json.len());
        let d: serde_json::Value = serde_json::from_str(&r.detalles_json).expect("JSON valido");
        let objeto = d.as_object().expect("objeto");
        assert!(objeto.len() <= 32);
        for (k, v) in objeto {
            assert!(!v.is_object() && !v.is_array(), "{k} no es escalar");
            if let Some(s) = v.as_str() {
                assert!(s.len() <= 512, "{k} mide {}", s.len());
            }
        }
        assert!(r.descripcion.len() <= MAX_DESCRIPCION);
    }

    #[test]
    fn lo_mas_grave_tiene_mas_prioridad_en_la_cola() {
        let critico = VeredictoEnCola::nuevo(veredicto("x"), 1, 1, 0);
        let mut v = veredicto("x");
        v.resultado = Resultado::Sospechoso;
        v.severidad = Severidad::Alta;
        let alto = VeredictoEnCola::nuevo(v, 1, 2, 0);
        assert!(critico.prioridad() > alto.prioridad());
        assert!(critico.peso() > std::mem::size_of::<VeredictoEnCola>());
    }

    #[test]
    fn la_cola_cabe_en_el_margen_del_reposo_en_todo_host() {
        const MIB: u64 = 1024 * 1024;
        for mib in [512, 1024, 2048, 8192, 16_384, 65_536, 786_432] {
            let p = Presupuesto::para(mib * MIB);
            let (bytes, elementos) = capacidad_de(&p);
            assert!((COLA_MINIMA..=COLA_MAXIMA).contains(&bytes), "{mib} MiB");
            assert!((64..=8192).contains(&elementos));
            // Coste fijo del enlace mas su cola, dentro del margen sin asignar.
            let coste = (aegis_fleet::enlace::COSTE_FIJO + bytes) as u64;
            assert!(
                coste <= p.cuota(Componente::Margen),
                "{mib} MiB: el enlace ({coste}) no cabe en el margen ({})",
                p.cuota(Componente::Margen)
            );
        }
    }

    #[test]
    fn bajo_contencion_la_cola_encoge_y_excedido_no_retiene_nada() {
        let p = Presupuesto::para(16 * 1024 * 1024 * 1024);
        let (maxima, _) = capacidad_de(&p);
        let mut holgado = Vigilante::nuevo(p);
        let r = holgado.observar_bytes(p.reposo / 2);
        assert_eq!(capacidad_segun(r, &holgado, maxima), maxima);
        let mut contenido = Vigilante::nuevo(p);
        let r = contenido.observar_bytes(p.pico + 1);
        let c = capacidad_segun(r, &contenido, maxima);
        assert!(c < maxima && c > 0, "{c} de {maxima}");
        let mut excedido = Vigilante::nuevo(p);
        let r = excedido.observar_bytes(p.techo + 1);
        assert_eq!(capacidad_segun(r, &excedido, maxima), 0);
    }

    #[test]
    fn el_estado_de_los_motores_es_json_y_dice_lo_omitido() {
        let omitidos = [Omitido {
            motor: "memoria",
            requisito: aegis_motor::Requisito::MemoriaAjena,
            motivo: "sin CAP_SYS_PTRACE \"efectiva\"".to_string(),
        }];
        let j = estado_motores_json(&[], &omitidos, 3, 2, 0);
        let v: serde_json::Value = serde_json::from_str(&j).expect("JSON valido");
        assert_eq!(v["veredictos"], 3);
        assert_eq!(v["omitidos"][0]["motor"], "memoria");
        assert!(v["motores"].as_array().is_some_and(Vec::is_empty));
    }
}
