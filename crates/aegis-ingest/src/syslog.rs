//! syslog: RFC 5424 y RFC 3164.
//!
//! # Esto es la superficie mas expuesta del producto
//!
//! Un puerto 514 abierto acepta una trama de cualquiera que llegue a la red. No
//! hay autenticacion en el protocolo, no la hubo nunca y no la va a haber. Asi
//! que todo lo de este modulo esta escrito suponiendo que quien manda la trama
//! quiere romper al que la lee:
//!
//! * **Ninguna reserva depende de lo que declare un campo.** El unico `Vec` que
//!   crece lo hace por bytes ya recibidos.
//! * **Topes en todo**, y los del RFC —48 bytes de `APP-NAME`, 255 de
//!   `HOSTNAME`— se aplican de verdad en vez de confiar en que el emisor los
//!   respete.
//! * **Coste lineal**. Sin retroceso y sin estructuras anidadas sin fondo.
//! * **Los bytes invalidos no son un error.** syslog transporta lo que sea; la
//!   conversion es tolerante y el original se conserva en
//!   [`crate::esquema::Evento::crudo`], asi que no se pierde evidencia.
//!
//! # Los dos formatos, y por que hay que aguantar los dos
//!
//! RFC 5424 (2009) es el bueno: fecha con zona horaria, estructura de datos
//! tipada, longitudes acotadas. RFC 3164 (2001) es el que **de verdad llega**:
//! lo emiten routers, conmutadores, cortafuegos y cualquier aparato cuyo
//! firmware se escribio una vez. Un producto que solo acepte 5424 no ingiere la
//! mitad del centro de datos de un cliente.
//!
//! La diferencia que mas duele es la fecha: RFC 3164 **no lleva ano**. Ver
//! [`crate::tiempo::ano_probable`] para lo que eso implica cada 31 de diciembre.

use std::collections::BTreeMap;

use crate::clasifica::clasificar;
use crate::error::{ErrorIngesta, Resultado};
use crate::esquema::{
    confianza, recortar, Evento, Origen, Severidad, Valor, MAX_CAMPO, MAX_CAMPOS, MAX_CRUDO,
    MAX_MENSAJE, VERSION,
};
use crate::tiempo::{ano_probable, desde_rfc3339, instante_utc, mes_abreviado};
use crate::Contexto;

/// Bytes maximos de una trama.
///
/// RFC 5425 obliga a aceptar 2048 y recomienda 8192. Aqui se aceptan 64 KiB
/// porque los emisores modernos mandan trazas de aplicacion largas, pero el tope
/// existe: sin el, un emisor que nunca mande el delimitador hace crecer el bufer
/// del receptor hasta que la maquina muere, y eso es un ataque de una linea.
pub const MAX_TRAMA: usize = 64 * 1024;

/// Bytes maximos de `HOSTNAME` segun RFC 5424.
pub const MAX_ANFITRION: usize = 255;
/// Bytes maximos de `APP-NAME` segun RFC 5424.
pub const MAX_APP: usize = 48;
/// Bytes maximos de `PROCID` segun RFC 5424.
pub const MAX_PROCID: usize = 128;
/// Bytes maximos de `MSGID` segun RFC 5424.
pub const MAX_MSGID: usize = 32;
/// Elementos de datos estructurados que se conservan como maximo.
pub const MAX_SD_ELEMENTOS: usize = 16;
/// Parametros por elemento que se conservan como maximo.
pub const MAX_SD_PARAMS: usize = 32;

/// El valor nulo de RFC 5424.
const NULO: &str = "-";

/// Facilidad de syslog: quien dice que genero el registro.
///
/// No se confia en ella para clasificar —cualquiera pone la que quiera— pero se
/// conserva porque en una red bien montada distingue el trafico del cortafuegos
/// del de las aplicaciones sin mirar el texto.
#[must_use]
pub fn nombre_facilidad(f: u8) -> &'static str {
    match f {
        0 => "kernel",
        1 => "usuario",
        2 => "correo",
        3 => "demonio",
        4 => "autenticacion",
        5 => "syslog",
        6 => "impresion",
        7 => "noticias",
        8 => "uucp",
        9 => "reloj",
        10 => "autenticacion-privada",
        11 => "ftp",
        12 => "ntp",
        13 => "auditoria",
        14 => "alerta",
        15 => "reloj-2",
        16..=23 => "local",
        _ => "desconocida",
    }
}

/// Severidad de syslog a la del esquema.
///
/// Las tres primeras se funden en `Critica` a proposito: la distincion entre
/// «emergencia», «alerta» y «critico» es de los anos ochenta y ningun emisor
/// moderno la respeta. Fingir que se conserva informacion que no llega seria
/// peor que unirlas.
#[must_use]
pub fn severidad_de(s: u8) -> Severidad {
    match s {
        0..=2 => Severidad::Critica,
        3 => Severidad::Alta,
        4 => Severidad::Media,
        5 => Severidad::Baja,
        _ => Severidad::Info,
    }
}

/// Cabecera comun a los dos formatos, ya analizada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cabecera {
    /// Facilidad declarada (0-23).
    pub facilidad: u8,
    /// Severidad declarada (0-7).
    pub severidad: u8,
    /// Version del formato: 1 para RFC 5424, 0 para RFC 3164.
    pub version: u8,
    /// Hora de ocurrencia en nanosegundos, si el registro la traia y era valida.
    pub ocurrio_ns: Option<u64>,
    /// Maquina que lo emitio, si lo dice.
    pub anfitrion: Option<String>,
    /// Programa que lo emitio, si lo dice.
    pub app: Option<String>,
    /// Identificador de proceso, si lo dice.
    pub procid: Option<String>,
    /// Identificador de mensaje (RFC 5424).
    pub msgid: Option<String>,
    /// Datos estructurados (RFC 5424), aplanados a `sdid.parametro`.
    pub estructurados: BTreeMap<String, String>,
    /// El mensaje.
    pub mensaje: String,
}

/// Analiza una trama de syslog en cualquiera de los dos formatos.
///
/// El formato se decide por el primer byte despues de `<PRI>`: RFC 5424 pone ahi
/// la version, que es un digito, y RFC 3164 pone el mes abreviado, que empieza
/// por letra. No hay ambiguedad posible entre los dos.
pub fn analizar_cabecera(datos: &[u8], observado_ns: u64) -> Resultado<Cabecera> {
    if datos.len() > MAX_TRAMA {
        return Err(ErrorIngesta::Excedido {
            que: "trama de syslog",
            tamano: datos.len(),
            tope: MAX_TRAMA,
        });
    }
    let (prival, resto) = prioridad(datos)?;
    let facilidad = prival / 8;
    let severidad = prival % 8;

    match resto.first() {
        Some(c) if c.is_ascii_digit() => cabecera_5424(facilidad, severidad, resto),
        _ => Ok(cabecera_3164(facilidad, severidad, resto, observado_ns)),
    }
}

/// `<PRI>`: uno a tres digitos entre angulos, con valor 0..=191.
///
/// La validacion es estricta a proposito. Aceptar `<0034>` o `<+34>` seria
/// «tolerante», pero abre una via de evasion conocida: dos analizadores que
/// difieren en lo que aceptan permiten mandar una trama que el recolector lee de
/// una forma y el motor de deteccion de otra.
fn prioridad(datos: &[u8]) -> Resultado<(u8, &[u8])> {
    if datos.first() != Some(&b'<') {
        return Err(ErrorIngesta::Malformado {
            origen: "syslog",
            motivo: "no empieza por '<'".into(),
        });
    }
    let mut valor: u32 = 0;
    let mut digitos = 0usize;
    let mut i = 1usize;
    while i < datos.len() && datos[i].is_ascii_digit() {
        valor = valor * 10 + u32::from(datos[i] - b'0');
        digitos += 1;
        i += 1;
        if digitos > 3 {
            break;
        }
    }
    if digitos == 0 || digitos > 3 || datos.get(i) != Some(&b'>') {
        return Err(ErrorIngesta::Malformado {
            origen: "syslog",
            motivo: "prioridad mal formada".into(),
        });
    }
    // Un cero a la izquierda no es legal: `<034>` y `<34>` tienen que ser
    // distinguibles, o dos analizadores discrepan.
    if digitos > 1 && datos[1] == b'0' {
        return Err(ErrorIngesta::Malformado {
            origen: "syslog",
            motivo: "prioridad con cero a la izquierda".into(),
        });
    }
    if valor > 191 {
        return Err(ErrorIngesta::Malformado {
            origen: "syslog",
            motivo: format!("prioridad {valor} fuera de rango"),
        });
    }
    let valor = u8::try_from(valor).map_err(|_| ErrorIngesta::Malformado {
        origen: "syslog",
        motivo: "prioridad fuera de rango".into(),
    })?;
    Ok((valor, &datos[i + 1..]))
}

fn cabecera_5424(facilidad: u8, severidad: u8, resto: &[u8]) -> Resultado<Cabecera> {
    let mut campos = Campos::nuevo(resto);
    let version_txt = campos.siguiente().ok_or_else(|| ErrorIngesta::Malformado {
        origen: "syslog-5424",
        motivo: "sin version".into(),
    })?;
    let version: u8 = texto(version_txt)
        .parse()
        .map_err(|_| ErrorIngesta::Malformado {
            origen: "syslog-5424",
            motivo: "version no numerica".into(),
        })?;
    if version != 1 {
        // Una version futura no se analiza con las reglas de esta: leerla mal
        // produciria campos desplazados que nadie detecta.
        return Err(ErrorIngesta::Malformado {
            origen: "syslog-5424",
            motivo: format!("version {version} desconocida"),
        });
    }

    let marca = campos.siguiente().unwrap_or(b"-");
    let ocurrio_ns = if marca == NULO.as_bytes() {
        None
    } else {
        desde_rfc3339(&texto(marca))
    };

    let anfitrion = opcional(campos.siguiente(), MAX_ANFITRION);
    let app = opcional(campos.siguiente(), MAX_APP);
    let procid = opcional(campos.siguiente(), MAX_PROCID);
    let msgid = opcional(campos.siguiente(), MAX_MSGID);

    let cola = campos.cola();
    let (estructurados, mensaje) = datos_estructurados(cola)?;

    Ok(Cabecera {
        facilidad,
        severidad,
        version: 1,
        ocurrio_ns,
        anfitrion,
        app,
        procid,
        msgid,
        estructurados,
        mensaje: recortar(&sin_bom(&texto(mensaje)), MAX_MENSAJE),
    })
}

/// RFC 3164: `Mmm dd hh:mm:ss HOSTNAME TAG[pid]: CONTENT`.
///
/// No falla nunca: los aparatos que emiten este formato se saltan partes con
/// frecuencia —sin fecha, sin maquina, con la etiqueta pegada al mensaje— y
/// rechazar la trama perderia registros de cortafuegos y conmutadores que a
/// menudo son los unicos que ven un movimiento lateral. Lo que no se pudo leer
/// se queda a `None` y el mensaje se conserva entero.
fn cabecera_3164(facilidad: u8, severidad: u8, resto: &[u8], observado_ns: u64) -> Cabecera {
    let mut i = 0usize;
    let mut ocurrio_ns = None;
    let mut anfitrion = None;

    // La fecha ocupa exactamente quince bytes: «Oct 11 22:14:15», con el dia
    // rellenado con espacio si es de una cifra.
    if resto.len() >= 15 {
        if let Some(t) = fecha_3164(&resto[..15], observado_ns) {
            ocurrio_ns = Some(t);
            i = 15;
            if resto.get(i) == Some(&b' ') {
                i += 1;
            }
            // Detras de la fecha va la maquina, si la hay.
            let (palabra, siguiente) = hasta_espacio(&resto[i..]);
            if !palabra.is_empty() && !palabra.contains(&b':') {
                anfitrion = opcional(Some(palabra), MAX_ANFITRION);
                i += siguiente;
            }
        }
    }

    let cuerpo = &resto[i.min(resto.len())..];
    let (app, procid, mensaje) = etiqueta_3164(cuerpo);

    Cabecera {
        facilidad,
        severidad,
        version: 0,
        ocurrio_ns,
        anfitrion,
        app,
        procid,
        msgid: None,
        estructurados: BTreeMap::new(),
        mensaje: recortar(&sin_bom(&texto(mensaje)), MAX_MENSAJE),
    }
}

/// `Mmm dd hh:mm:ss` a nanosegundos, poniendo el ano que falta.
fn fecha_3164(b: &[u8], observado_ns: u64) -> Option<u64> {
    if b.len() < 15 {
        return None;
    }
    let mes = mes_abreviado(&b[0..3])?;
    if b[3] != b' ' {
        return None;
    }
    // El dia va rellenado con espacio: «Oct  1» tiene dos espacios.
    let dia_txt = std::str::from_utf8(&b[4..6]).ok()?.trim();
    let dia: u32 = dia_txt.parse().ok()?;
    if b[6] != b' ' || b[9] != b':' || b[12] != b':' {
        return None;
    }
    let hora: u32 = std::str::from_utf8(&b[7..9]).ok()?.parse().ok()?;
    let minuto: u32 = std::str::from_utf8(&b[10..12]).ok()?.parse().ok()?;
    let segundo: u32 = std::str::from_utf8(&b[13..15]).ok()?.parse().ok()?;
    let ano = ano_probable(mes, dia, observado_ns);
    instante_utc(ano, mes, dia, hora, minuto, segundo, 0)
}

/// `TAG[pid]: mensaje`, `TAG: mensaje` o directamente el mensaje.
///
/// RFC 3164 define la etiqueta como alfanumerica y terminada por el primer
/// caracter que no lo sea. Muchos emisores meten guiones y barras, asi que se
/// aceptan: rechazarlos dejaria sin clasificar a `postfix/smtpd`, que es de los
/// que mas hablan en un servidor de correo.
fn etiqueta_3164(cuerpo: &[u8]) -> (Option<String>, Option<String>, &[u8]) {
    let tope = cuerpo.len().min(64);
    let mut fin = 0usize;
    while fin < tope {
        let c = cuerpo[fin];
        if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'/' || c == b'.' {
            fin += 1;
        } else {
            break;
        }
    }
    if fin == 0 {
        return (None, None, cuerpo);
    }
    let app = opcional(Some(&cuerpo[..fin]), MAX_APP);
    let mut i = fin;
    let mut procid = None;
    if cuerpo.get(i) == Some(&b'[') {
        if let Some(cierre) = cuerpo[i..].iter().position(|&c| c == b']') {
            procid = opcional(Some(&cuerpo[i + 1..i + cierre]), MAX_PROCID);
            i += cierre + 1;
        }
    }
    if cuerpo.get(i) == Some(&b':') {
        i += 1;
    } else if procid.is_none() {
        // NO HAY ETIQUETA. RFC 3164 la termina con un caracter que no sea
        // alfanumerico, y en la practica eso son los dos puntos o el «[pid]».
        // Sin ninguno de los dos, la primera palabra es parte del mensaje:
        // tomarla como etiqueta se come una palabra de cada linea de todos los
        // aparatos que no ponen etiqueta, y nadie lo nota porque el resto del
        // mensaje sigue leyendose bien.
        return (None, None, cuerpo);
    }
    while cuerpo.get(i) == Some(&b' ') {
        i += 1;
    }
    (app, procid, &cuerpo[i.min(cuerpo.len())..])
}

/// `SD-ELEMENT*` o `-`, seguido del mensaje.
///
/// # El unico sitio con estructura anidada, y por eso el mas vigilado
///
/// Los datos estructurados son el unico campo del protocolo con delimitadores
/// que se abren y se cierran. La forma de romper un analizador aqui es clasica:
/// mandar cien mil elementos, o un valor entrecomillado que nunca cierra. Los
/// dos casos estan acotados —[`MAX_SD_ELEMENTOS`], [`MAX_SD_PARAMS`] y el fin de
/// la trama— y ni uno ni otro reserva memoria por adelantado.
fn datos_estructurados(datos: &[u8]) -> Resultado<(BTreeMap<String, String>, &[u8])> {
    let mut mapa = BTreeMap::new();
    if datos.is_empty() {
        return Ok((mapa, datos));
    }
    if datos[0] == b'-' {
        let resto = if datos.len() > 1 && datos[1] == b' ' {
            &datos[2..]
        } else {
            &datos[1..]
        };
        return Ok((mapa, resto));
    }
    if datos[0] != b'[' {
        return Err(ErrorIngesta::Malformado {
            origen: "syslog-5424",
            motivo: "datos estructurados no empiezan por '[' ni son '-'".into(),
        });
    }

    let mut i = 0usize;
    let mut elementos = 0usize;
    while i < datos.len() && datos[i] == b'[' {
        if elementos >= MAX_SD_ELEMENTOS {
            // Se para de guardar, pero no se rechaza la trama: el mensaje que
            // viene detras puede ser la evidencia.
            break;
        }
        i += 1;
        let inicio_id = i;
        while i < datos.len() && datos[i] != b' ' && datos[i] != b']' {
            i += 1;
        }
        let sdid = recortar(&texto(&datos[inicio_id..i]), 32);
        let mut params = 0usize;
        while i < datos.len() && datos[i] != b']' {
            i += 1; // el espacio
            let inicio_nombre = i;
            while i < datos.len() && datos[i] != b'=' && datos[i] != b']' && datos[i] != b' ' {
                i += 1;
            }
            if i >= datos.len() || datos[i] != b'=' {
                continue;
            }
            let nombre = texto(&datos[inicio_nombre..i]);
            i += 1; // el '='
            if datos.get(i) != Some(&b'"') {
                continue;
            }
            i += 1;
            let mut valor = String::new();
            while i < datos.len() && datos[i] != b'"' {
                // Las tres secuencias de escape del RFC, y solo esas: una
                // barra delante de cualquier otra cosa es literal.
                if datos[i] == b'\\' && i + 1 < datos.len() {
                    let s = datos[i + 1];
                    if s == b'"' || s == b'\\' || s == b']' {
                        if valor.len() < MAX_CAMPO {
                            valor.push(char::from(s));
                        }
                        i += 2;
                        continue;
                    }
                }
                if valor.len() < MAX_CAMPO {
                    valor.push_str(&texto(&datos[i..i + 1]));
                }
                i += 1;
            }
            if i < datos.len() {
                i += 1; // la comilla de cierre
            }
            if params < MAX_SD_PARAMS && mapa.len() < MAX_CAMPOS {
                mapa.insert(format!("{sdid}.{nombre}"), valor);
                params += 1;
            }
        }
        if i < datos.len() {
            i += 1; // el ']'
        }
        elementos += 1;
    }
    // Saltar lo que quede de datos estructurados si se dejo de guardar por tope.
    while i < datos.len() && datos[i] == b'[' {
        let mut prof = 0usize;
        while i < datos.len() {
            match datos[i] {
                b'\\' => i += 1,
                b'[' => prof += 1,
                b']' => {
                    prof -= 1;
                    if prof == 0 {
                        i += 1;
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
    if datos.get(i) == Some(&b' ') {
        i += 1;
    }
    Ok((mapa, &datos[i.min(datos.len())..]))
}

/// Recorre campos separados por un espacio.
struct Campos<'a> {
    datos: &'a [u8],
    i: usize,
}

impl<'a> Campos<'a> {
    fn nuevo(datos: &'a [u8]) -> Campos<'a> {
        Campos { datos, i: 0 }
    }

    fn siguiente(&mut self) -> Option<&'a [u8]> {
        if self.i >= self.datos.len() {
            return None;
        }
        let inicio = self.i;
        while self.i < self.datos.len() && self.datos[self.i] != b' ' {
            self.i += 1;
        }
        let campo = &self.datos[inicio..self.i];
        if self.i < self.datos.len() {
            self.i += 1;
        }
        Some(campo)
    }

    fn cola(self) -> &'a [u8] {
        &self.datos[self.i.min(self.datos.len())..]
    }
}

/// Un campo que puede ser `-` (nulo) y tiene tope.
fn opcional(campo: Option<&[u8]>, tope: usize) -> Option<String> {
    let c = campo?;
    if c.is_empty() || c == NULO.as_bytes() {
        return None;
    }
    let s = recortar(&texto(c), tope);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Bytes a texto sin fallar.
///
/// syslog transporta lo que sea: hay aparatos que mandan latin-1 y otros que
/// mandan binario dentro de un mensaje. Rechazar la trama por eso perderia el
/// registro entero; el original se conserva en `crudo`, asi que la sustitucion
/// no pierde evidencia.
fn texto(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// RFC 5424 permite una marca de orden de bytes delante del mensaje.
fn sin_bom(s: &str) -> String {
    s.strip_prefix('\u{feff}').unwrap_or(s).to_string()
}

fn hasta_espacio(datos: &[u8]) -> (&[u8], usize) {
    let mut i = 0usize;
    while i < datos.len() && datos[i] != b' ' {
        i += 1;
    }
    let palabra = &datos[..i];
    if i < datos.len() {
        i += 1;
    }
    (palabra, i)
}

/// Analiza una trama completa y la normaliza al esquema comun.
///
/// `ancla` identifica este registro dentro de su origen. Para syslog sobre TCP
/// es la posicion en el flujo; para UDP, el remitente y un contador. Ver
/// [`crate::esquema::Evento::ancla`] para por que no puede faltar.
pub fn normalizar(datos: &[u8], ancla: &str, ctx: &Contexto) -> Resultado<Evento> {
    let cab = analizar_cabecera(datos, ctx.observado_ns)?;
    let origen = if cab.version == 1 {
        Origen::Syslog5424
    } else {
        Origen::Syslog3164
    };

    let productor = cab.app.clone().unwrap_or_else(|| "desconocido".to_string());
    let clas = clasificar(&productor, &cab.mensaje);

    let (ocurrio_ns, reloj) = confianza(cab.ocurrio_ns, ctx.observado_ns);

    let mut campos = clas.campos;
    // La severidad del transporte se conserva siempre: un fallo de
    // autenticacion llega como «info» porque el demonio lo considera rutina, y
    // poder ver las dos cosas es lo que permite auditar la regla despues.
    campos.insert(
        "syslog.facilidad".into(),
        Valor::Texto(nombre_facilidad(cab.facilidad).into()),
    );
    campos.insert(
        "syslog.severidad".into(),
        Valor::Entero(i64::from(cab.severidad)),
    );
    if let Some(p) = &cab.procid {
        if let Ok(n) = p.parse::<i64>() {
            campos.insert("pid".into(), Valor::Entero(n));
        } else {
            campos.insert("procid".into(), Valor::Texto(p.clone()));
        }
    }
    if let Some(m) = &cab.msgid {
        campos.insert("syslog.msgid".into(), Valor::Texto(m.clone()));
    }
    for (k, v) in cab.estructurados {
        if campos.len() >= MAX_CAMPOS {
            break;
        }
        campos.insert(
            recortar(&k, MAX_CAMPO),
            Valor::Texto(recortar(&v, MAX_CAMPO)),
        );
    }

    let mut evento = Evento {
        version: VERSION,
        id: String::new(),
        ancla: recortar(ancla, MAX_CAMPO),
        ocurrio_ns,
        observado_ns: ctx.observado_ns,
        reloj,
        clase: clas.clase,
        resultado: clas.resultado,
        // La regla manda sobre el transporte cuando sabe mas: un fallo de
        // autenticacion no es «informativo» aunque el demonio lo escriba asi.
        severidad: clas
            .severidad
            .unwrap_or_else(|| severidad_de(cab.severidad)),
        origen,
        anfitrion: cab
            .anfitrion
            .unwrap_or_else(|| ctx.anfitrion_por_defecto.clone()),
        inquilino: ctx.inquilino.clone(),
        productor,
        mensaje: cab.mensaje,
        campos,
        crudo: ctx
            .conservar_crudo
            .then(|| datos[..datos.len().min(MAX_CRUDO)].to_vec()),
    };
    evento.sellar();
    Ok(evento)
}

/// Desenmarca una trama de un flujo TCP segun RFC 6587.
///
/// # Los dos enmarcados, y por que hay que distinguirlos sin adivinar
///
/// RFC 6587 define dos formas de separar tramas en un flujo: **contada**
/// (`LONGITUD SP TRAMA`) y **no transparente** (delimitada por salto de linea).
/// Un emisor usa una u otra y no lo negocia.
///
/// Mezclarlas es una via de evasion real: si el receptor adivina mal, el
/// atacante mete un salto de linea dentro de una trama contada y **parte un
/// registro en dos**, con la segunda mitad interpretada como una trama nueva
/// cuya prioridad y cuya maquina elige el. La deteccion ve dos lineas inocuas
/// donde habia una acusatoria.
///
/// Aqui no se adivina: el primer byte decide. Un digito significa contada, y a
/// partir de ahi el salto de linea dentro de la trama es contenido, no
/// separador. Cualquier otro byte significa delimitada.
///
/// Devuelve `None` cuando todavia no hay una trama entera en el bufer.
#[must_use]
pub fn desenmarcar(bufer: &[u8]) -> Option<(usize, usize)> {
    if bufer.is_empty() {
        return None;
    }
    if bufer[0].is_ascii_digit() {
        let mut longitud: usize = 0;
        let mut i = 0usize;
        while i < bufer.len() && bufer[i].is_ascii_digit() {
            longitud = longitud
                .saturating_mul(10)
                .saturating_add(usize::from(bufer[i] - b'0'));
            i += 1;
            if longitud > MAX_TRAMA {
                // El emisor declara mas de lo que se admite. Devolver el tope
                // hace que el lector corte la conexion en vez de esperar para
                // siempre una trama que nunca va a caber.
                return Some((i, MAX_TRAMA + 1));
            }
        }
        if i >= bufer.len() || bufer[i] != b' ' {
            return None; // la longitud todavia no esta completa
        }
        let inicio = i + 1;
        if bufer.len() < inicio + longitud {
            return None;
        }
        return Some((inicio, longitud));
    }
    let fin = bufer.iter().position(|&c| c == b'\n')?;
    // Un `\r\n` deja el retorno pegado al final del mensaje.
    let largo = if fin > 0 && bufer[fin - 1] == b'\r' {
        fin - 1
    } else {
        fin
    };
    Some((0, largo))
}

/// Cuantos bytes consume la trama que devolvio [`desenmarcar`].
///
/// Va aparte porque el enmarcado contado consume el prefijo de longitud y el
/// delimitado consume el salto de linea: quien lea tiene que avanzar distinto, y
/// calcularlo en el sitio de la llamada es como se pierden bytes.
#[must_use]
pub fn consumido(bufer: &[u8], inicio: usize, largo: usize) -> usize {
    if inicio > 0 {
        // Contada: prefijo + trama.
        inicio + largo
    } else {
        // Delimitada: la trama mas el delimitador —y el `\r` si lo habia—.
        let fin = bufer.iter().position(|&c| c == b'\n').unwrap_or(largo);
        fin + 1
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const SEG: u64 = 1_000_000_000;

    fn ctx() -> Contexto {
        Contexto {
            inquilino: "cliente-1".into(),
            anfitrion_por_defecto: "recolector".into(),
            observado_ns: instante_utc(2023, 10, 11, 22, 14, 20, 0).unwrap(),
            conservar_crudo: true,
        }
    }

    // --- RFC 5424, contra los ejemplos literales del RFC ---------------------

    #[test]
    fn el_ejemplo_1_del_rfc_5424_se_analiza_campo_a_campo() {
        // Copiado literal de la seccion 6.5 del RFC 5424.
        let t = b"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \
                  'su root' failed for lonvick on /dev/pts/8";
        let c = analizar_cabecera(t, 0).unwrap();
        assert_eq!(c.facilidad, 4, "auth");
        assert_eq!(c.severidad, 2, "critical");
        assert_eq!(c.version, 1);
        assert_eq!(c.anfitrion.as_deref(), Some("mymachine.example.com"));
        assert_eq!(c.app.as_deref(), Some("su"));
        assert_eq!(c.procid, None, "el '-' es nulo, no la cadena '-'");
        assert_eq!(c.msgid.as_deref(), Some("ID47"));
        assert!(c.estructurados.is_empty());
        assert_eq!(c.mensaje, "'su root' failed for lonvick on /dev/pts/8");
        assert_eq!(
            c.ocurrio_ns,
            Some(instante_utc(2003, 10, 11, 22, 14, 15, 3_000_000).unwrap())
        );
    }

    #[test]
    fn el_ejemplo_3_del_rfc_5424_con_datos_estructurados() {
        let t = b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 \
                  [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] \
                  An application event log entry...";
        let c = analizar_cabecera(t, 0).unwrap();
        assert_eq!(c.estructurados["exampleSDID@32473.iut"], "3");
        assert_eq!(
            c.estructurados["exampleSDID@32473.eventSource"],
            "Application"
        );
        assert_eq!(c.estructurados["exampleSDID@32473.eventID"], "1011");
        assert_eq!(c.mensaje, "An application event log entry...");
    }

    #[test]
    fn dos_elementos_estructurados_seguidos() {
        let t = b"<165>1 2003-10-11T22:14:15.003Z host app - ID [a@1 x=\"1\"][b@2 y=\"2\"] msg";
        let c = analizar_cabecera(t, 0).unwrap();
        assert_eq!(c.estructurados["a@1.x"], "1");
        assert_eq!(c.estructurados["b@2.y"], "2");
        assert_eq!(c.mensaje, "msg");
    }

    #[test]
    fn las_tres_secuencias_de_escape_del_rfc_y_solo_esas() {
        let t = br#"<34>1 - - - - - [id@1 v="a\"b\\c\]d\ne"] fin"#;
        let c = analizar_cabecera(t, 0).unwrap();
        // `\"`, `\\` y `\]` se desescapan. `\n` NO: el RFC define exactamente
        // tres secuencias, asi que la barra se queda literal delante de la ene.
        // Inventarse mas escapes es como dos analizadores acaban leyendo cosas
        // distintas del mismo byte.
        assert_eq!(c.estructurados["id@1.v"], "a\"b\\c]d\\ne");
        assert_eq!(c.mensaje, "fin");
    }

    #[test]
    fn la_marca_de_orden_de_bytes_no_aparece_en_el_mensaje() {
        let mut t = b"<34>1 - - - - - - ".to_vec();
        t.extend_from_slice("\u{feff}hola".as_bytes());
        let c = analizar_cabecera(&t, 0).unwrap();
        assert_eq!(c.mensaje, "hola");
    }

    #[test]
    fn una_version_futura_no_se_analiza_con_las_reglas_de_esta() {
        // Leerla mal produciria campos desplazados que nadie detecta.
        let t = b"<34>2 2003-10-11T22:14:15Z host app - - mensaje";
        assert!(analizar_cabecera(t, 0).is_err());
    }

    // --- La prioridad, que es donde se evade ---------------------------------

    #[test]
    fn la_prioridad_se_valida_estricta_para_que_no_haya_dos_lecturas() {
        // Dos analizadores que difieren en lo que aceptan permiten mandar una
        // trama que el recolector lee de una forma y el motor de deteccion de
        // otra. Es una via de evasion conocida.
        assert!(prioridad(b"<034>1 x").is_err(), "cero a la izquierda");
        assert!(prioridad(b"<+34>1 x").is_err(), "signo");
        assert!(prioridad(b"<192>1 x").is_err(), "fuera de rango");
        assert!(prioridad(b"<1234>1 x").is_err(), "cuatro digitos");
        assert!(prioridad(b"<>1 x").is_err(), "vacia");
        assert!(prioridad(b"34>1 x").is_err(), "sin abrir");
        assert!(prioridad(b"<34 1 x").is_err(), "sin cerrar");
        assert_eq!(prioridad(b"<0>x").unwrap().0, 0);
        assert_eq!(prioridad(b"<191>x").unwrap().0, 191);
    }

    // --- RFC 3164, el que de verdad llega ------------------------------------

    #[test]
    fn el_ejemplo_del_rfc_3164_se_analiza() {
        let t = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
        let c = analizar_cabecera(t, ctx().observado_ns).unwrap();
        assert_eq!(c.version, 0);
        assert_eq!(c.anfitrion.as_deref(), Some("mymachine"));
        assert_eq!(c.app.as_deref(), Some("su"));
        assert_eq!(c.mensaje, "'su root' failed for lonvick on /dev/pts/8");
        assert_eq!(
            c.ocurrio_ns,
            Some(instante_utc(2023, 10, 11, 22, 14, 15, 0).unwrap())
        );
    }

    #[test]
    fn el_dia_de_una_cifra_va_rellenado_con_espacio() {
        // «Oct  1» tiene DOS espacios. Un analizador que parta por espacios se
        // desalinea entero a partir de aqui.
        let t = b"<34>Oct  1 09:05:03 router1 kernel: algo";
        let c = analizar_cabecera(t, ctx().observado_ns).unwrap();
        assert_eq!(c.anfitrion.as_deref(), Some("router1"));
        assert_eq!(c.app.as_deref(), Some("kernel"));
        assert_eq!(c.mensaje, "algo");
    }

    #[test]
    fn la_etiqueta_con_pid_se_separa() {
        let t = b"<38>Jun 15 12:00:00 servidor sshd[4242]: Accepted publickey for op from 1.2.3.4 port 22 ssh2";
        let c = analizar_cabecera(t, ctx().observado_ns).unwrap();
        assert_eq!(c.app.as_deref(), Some("sshd"));
        assert_eq!(c.procid.as_deref(), Some("4242"));
        assert!(c.mensaje.starts_with("Accepted publickey"));
    }

    #[test]
    fn una_etiqueta_con_barra_se_acepta() {
        // Rechazarla dejaria sin clasificar a `postfix/smtpd`, que es de los que
        // mas hablan en un servidor de correo.
        let t = b"<22>Jun 15 12:00:00 mx postfix/smtpd[9]: connect from unknown[1.2.3.4]";
        let c = analizar_cabecera(t, ctx().observado_ns).unwrap();
        assert_eq!(c.app.as_deref(), Some("postfix/smtpd"));
        assert_eq!(c.procid.as_deref(), Some("9"));
    }

    #[test]
    fn un_aparato_que_no_manda_fecha_ni_maquina_no_pierde_su_registro() {
        // Los cortafuegos y conmutadores viejos hacen esto, y a menudo son los
        // unicos que ven un movimiento lateral.
        let t = b"<13>no hay fecha aqui";
        let c = analizar_cabecera(t, ctx().observado_ns).unwrap();
        assert_eq!(c.ocurrio_ns, None);
        assert_eq!(c.anfitrion, None);
        assert_eq!(c.mensaje, "no hay fecha aqui");
    }

    #[test]
    fn una_sola_palabra_sin_dos_puntos_es_el_mensaje_y_no_la_etiqueta() {
        let t = b"<13>arrancando";
        let c = analizar_cabecera(t, ctx().observado_ns).unwrap();
        assert_eq!(c.mensaje, "arrancando");
        assert_eq!(c.app, None);
    }

    // --- El enmarcado en TCP, que es otra via de evasion ----------------------

    #[test]
    fn el_enmarcado_contado_no_se_parte_por_un_salto_de_linea_interior() {
        // LA EVASION: si el receptor adivina el enmarcado, el atacante mete un
        // salto de linea dentro de una trama contada y parte el registro en dos,
        // con la segunda mitad leida como trama nueva cuya prioridad elige el.
        let bufer = b"25 <34>1 - - - - - - a\nb fin";
        let (inicio, largo) = desenmarcar(bufer).unwrap();
        assert_eq!(largo, 25);
        let trama = &bufer[inicio..inicio + largo];
        assert!(trama.contains(&b'\n'), "el salto va DENTRO de la trama");
        let c = analizar_cabecera(trama, 0).unwrap();
        assert!(c.mensaje.contains('\n'));
    }

    #[test]
    fn el_enmarcado_delimitado_corta_por_el_salto() {
        let bufer = b"<34>1 - - - - - - primera\n<34>1 - - - - - - segunda\n";
        let (inicio, largo) = desenmarcar(bufer).unwrap();
        assert_eq!(inicio, 0);
        let c = analizar_cabecera(&bufer[inicio..inicio + largo], 0).unwrap();
        assert_eq!(c.mensaje, "primera");
        let consumido = consumido(bufer, inicio, largo);
        let (i2, l2) = desenmarcar(&bufer[consumido..]).unwrap();
        let c2 = analizar_cabecera(&bufer[consumido + i2..consumido + i2 + l2], 0).unwrap();
        assert_eq!(c2.mensaje, "segunda");
    }

    #[test]
    fn el_retorno_de_carro_no_se_queda_pegado_al_mensaje() {
        let bufer = b"<34>1 - - - - - - hola\r\n";
        let (inicio, largo) = desenmarcar(bufer).unwrap();
        let c = analizar_cabecera(&bufer[inicio..inicio + largo], 0).unwrap();
        assert_eq!(c.mensaje, "hola", "sin el \\r al final");
    }

    #[test]
    fn una_trama_incompleta_no_se_analiza_a_medias() {
        assert!(desenmarcar(b"25 <34>1 corta").is_none());
        assert!(desenmarcar(b"<34>1 sin salto").is_none());
        assert!(desenmarcar(b"").is_none());
        assert!(desenmarcar(b"12").is_none(), "la longitud no esta completa");
    }

    #[test]
    fn una_longitud_declarada_absurda_corta_en_vez_de_esperar_para_siempre() {
        let (_, largo) = desenmarcar(b"999999999999 x").unwrap();
        assert!(largo > MAX_TRAMA, "el lector tiene que cortar la conexion");
    }

    // --- Entrada hostil ------------------------------------------------------

    #[test]
    fn cien_mil_elementos_estructurados_no_hacen_crecer_la_memoria() {
        // Tantos elementos como caben en una trama: el tope de trama y el de
        // elementos son dos cotas distintas y aqui se ejercita la segunda.
        let mut t = b"<34>1 - - - - - ".to_vec();
        let mut i = 0;
        while t.len() + 32 < MAX_TRAMA {
            t.extend_from_slice(format!("[e{i}@1 k=\"v\"]").as_bytes());
            i += 1;
        }
        t.extend_from_slice(b" mensaje");
        assert!(i > 1_000, "la prueba necesita muchos elementos, son {i}");
        let c = analizar_cabecera(&t, 0).unwrap();
        assert!(
            c.estructurados.len() <= MAX_SD_ELEMENTOS * MAX_SD_PARAMS,
            "guardo {}",
            c.estructurados.len()
        );
    }

    #[test]
    fn un_valor_entrecomillado_que_nunca_cierra_no_cuelga() {
        let t = b"<34>1 - - - - - [id@1 v=\"sin cerrar y sin fin";
        let c = analizar_cabecera(t, 0).unwrap();
        assert!(c.estructurados.contains_key("id@1.v"));
    }

    #[test]
    fn un_corchete_sin_cerrar_no_cuelga() {
        let t = b"<34>1 - - - - - [[[[[[[[[[[[[[";
        let _ = analizar_cabecera(t, 0);
    }

    #[test]
    fn una_trama_mas_larga_que_el_tope_se_rechaza_con_nombre() {
        // Sin el tope, un emisor que nunca mande el delimitador hace crecer el
        // bufer del receptor hasta que la maquina muere.
        let t = vec![b'x'; MAX_TRAMA + 1];
        let e = analizar_cabecera(&t, 0).unwrap_err();
        assert!(matches!(e, ErrorIngesta::Excedido { .. }));
        assert!(e.es_del_registro(), "no para el flujo entero");
    }

    #[test]
    fn los_bytes_que_no_son_utf8_no_pierden_el_registro() {
        // Hay aparatos que mandan latin-1 y otros que mandan binario dentro de
        // un mensaje. El original se conserva en `crudo`.
        let mut t = b"<34>1 - - - - - - ".to_vec();
        t.extend_from_slice(&[0xff, 0xfe, 0x80, 0x41]);
        let e = normalizar(&t, "udp:1.2.3.4#1", &ctx()).unwrap();
        assert!(e.mensaje.contains('A'));
        assert_eq!(e.crudo.as_deref(), Some(&t[..]));
    }

    #[test]
    fn los_topes_del_rfc_se_aplican_de_verdad() {
        // Confiar en que el emisor los respete es confiar en el atacante.
        let largo = "a".repeat(1000);
        let t = format!("<34>1 - {largo} {largo} {largo} {largo} - mensaje");
        let c = analizar_cabecera(t.as_bytes(), 0).unwrap();
        assert!(c.anfitrion.unwrap().len() <= MAX_ANFITRION);
        assert!(c.app.unwrap().len() <= MAX_APP);
        assert!(c.procid.unwrap().len() <= MAX_PROCID);
        assert!(c.msgid.unwrap().len() <= MAX_MSGID);
    }

    #[test]
    fn un_mensaje_gigante_se_recorta_al_tope() {
        let mut t = b"<34>1 - - - - - - ".to_vec();
        t.extend_from_slice(&vec![b'x'; MAX_MENSAJE * 2]);
        t.truncate(MAX_TRAMA);
        let c = analizar_cabecera(&t, 0).unwrap();
        assert!(c.mensaje.len() <= MAX_MENSAJE);
    }

    // --- La normalizacion completa -------------------------------------------

    #[test]
    fn un_fallo_de_ssh_llega_al_esquema_con_todo_lo_que_importa() {
        let t = b"<38>1 2023-10-11T22:14:15Z servidor-1 sshd 1234 - - \
                  Failed password for root from 10.0.0.9 port 54321 ssh2";
        let e = normalizar(t, "tcp:10.0.0.1:514#7", &ctx()).unwrap();
        assert_eq!(e.clase, crate::esquema::Clase::Autenticacion);
        assert_eq!(e.resultado, crate::esquema::Resultado::Fallo);
        assert_eq!(e.anfitrion, "servidor-1");
        assert_eq!(e.inquilino, "cliente-1");
        assert_eq!(e.productor, "sshd");
        assert_eq!(e.campos["usuario"], Valor::Texto("root".into()));
        assert_eq!(e.campos["pid"], Valor::Entero(1234));
        assert_eq!(e.origen, Origen::Syslog5424);
        assert!(e.sello_valido());
    }

    #[test]
    fn la_regla_manda_sobre_la_severidad_del_transporte_pero_no_la_borra() {
        // Un fallo de autenticacion llega como «info» (severidad 6) porque el
        // demonio lo considera rutina. Para un EDR no lo es; y poder ver las dos
        // cosas es lo que permite auditar la regla despues.
        let t = b"<38>1 2023-10-11T22:14:15Z h sshd - - - \
                  Failed password for root from 10.0.0.9 port 1 ssh2";
        let e = normalizar(t, "a#1", &ctx()).unwrap();
        assert_eq!(e.severidad, Severidad::Media, "la regla sabe mas");
        assert_eq!(e.campos["syslog.severidad"], Valor::Entero(6));
        assert_eq!(
            e.campos["syslog.facilidad"],
            Valor::Texto("autenticacion".into())
        );
    }

    #[test]
    fn sin_maquina_en_la_trama_se_usa_la_del_recolector_y_no_una_vacia() {
        let e = normalizar(b"<13>mensaje suelto", "a#1", &ctx()).unwrap();
        assert_eq!(e.anfitrion, "recolector");
    }

    #[test]
    fn la_hora_ausente_se_marca_como_de_llegada() {
        let e = normalizar(b"<13>sin fecha", "a#1", &ctx()).unwrap();
        assert_eq!(e.reloj, crate::esquema::ConfianzaReloj::DeLlegada);
        assert_eq!(e.ocurrio_ns, ctx().observado_ns);
        assert!(!e.reloj.sirve_para_ordenar());
    }

    #[test]
    fn una_fecha_de_hace_dos_anos_se_marca_sospechosa_pero_entra() {
        let t = b"<34>1 2019-01-01T00:00:00Z h app - - - viejo";
        let e = normalizar(t, "a#1", &ctx()).unwrap();
        assert_eq!(e.reloj, crate::esquema::ConfianzaReloj::Sospechosa);
        assert_eq!(
            e.ocurrio_ns,
            instante_utc(2019, 1, 1, 0, 0, 0, 0).unwrap(),
            "la hora del registro se conserva tal cual"
        );
    }

    #[test]
    fn la_misma_trama_produce_siempre_el_mismo_evento() {
        // Determinismo: es lo que hace que la deduplicacion del plano de control
        // funcione y que una regresion en el analizador se vea.
        let t = b"<38>1 2023-10-11T22:14:15Z h sshd 9 - [a@1 x=\"1\"][b@2 y=\"2\"] \
                  Accepted password for op from 10.0.0.1 port 2 ssh2";
        let a = normalizar(t, "ancla#1", &ctx()).unwrap();
        let b = normalizar(t, "ancla#1", &ctx()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn el_ancla_distingue_dos_entregas_de_dos_hechos() {
        let t = b"<38>Oct 11 22:14:15 h sshd[9]: Failed password for root from 1.2.3.4 port 2 ssh2";
        let primera = normalizar(t, "fichero:/var/log/auth.log@0", &ctx()).unwrap();
        let reenvio = normalizar(t, "fichero:/var/log/auth.log@0", &ctx()).unwrap();
        let segunda = normalizar(t, "fichero:/var/log/auth.log@96", &ctx()).unwrap();
        assert_eq!(primera.id, reenvio.id, "misma entrega");
        assert_ne!(primera.id, segunda.id, "dos intentos distintos");
    }

    #[test]
    fn el_lote_de_un_endpoint_apagado_conserva_su_orden_real() {
        // Si se ordenara por llegada, un ataque repartido en dos dias pareceria
        // un pico de un segundo.
        let mut c = ctx();
        c.observado_ns = instante_utc(2023, 10, 13, 9, 0, 0, 0).unwrap();
        let viejo =
            normalizar(b"<34>1 2023-10-11T22:14:15Z h app - - - primero", "a#1", &c).unwrap();
        let nuevo =
            normalizar(b"<34>1 2023-10-12T22:14:15Z h app - - - segundo", "a#2", &c).unwrap();
        assert!(viejo.ocurrio_ns < nuevo.ocurrio_ns);
        assert_eq!(viejo.observado_ns, nuevo.observado_ns, "llegaron juntos");
        assert!(viejo.retraso_ns() > 24 * 3600 * SEG);
    }
}
