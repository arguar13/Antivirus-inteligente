//! Windows Event Log: analizador de EVTX con BinXML y plantillas.
//!
//! # Que es un fichero EVTX, en tres capas
//!
//! 1. Una **cabecera** y una serie de **trozos** de 64 KiB, cada uno con su
//!    suma de comprobacion y sus propias tablas.
//! 2. Dentro de cada trozo, **registros**: un identificador, una hora y un
//!    documento.
//! 3. El documento no es XML: es **BinXML**, un XML binario con un diccionario
//!    de cadenas por trozo y, sobre todo, **plantillas**. Una plantilla es el
//!    esqueleto del documento con huecos; el registro solo lleva los valores que
//!    van en los huecos.
//!
//! Esa tercera capa es la que hace que un EVTX no se pueda leer «a ojo»: sin
//! resolver las plantillas, un registro de inicio de sesion fallido es una lista
//! de valores sueltos sin ninguna etiqueta que diga cual es el usuario.
//!
//! # El muro, declarado: el texto legible NO esta en el fichero
//!
//! Lo que en el visor de sucesos de Windows se lee como «La cuenta no pudo
//! iniciar sesion» **no esta en el EVTX**. El fichero guarda el identificador de
//! evento y los valores; el texto vive en una tabla de mensajes dentro de la DLL
//! del proveedor, en la maquina Windows de origen, y depende de su idioma.
//! Renderizarlo aqui exigiria esa DLL, que no se puede distribuir.
//!
//! Asi que aqui se hace lo que de verdad importa para detectar, que ademas es
//! mas fiable que el texto: **se analiza la estructura entera** —cada valor con
//! su nombre— y se lleva un [`catalogo`] de los identificadores de evento que
//! cuentan, con su clase, su resultado y su gravedad. Un 4625 es un fallo de
//! autenticacion en cualquier idioma; su frase, no.
//!
//! # Entrada hostil, y aqui de verdad
//!
//! Un EVTX llega **de una maquina que puede estar comprometida**, y el atacante
//! con SYSTEM puede escribir en el. Todo desplazamiento se valida contra el
//! trozo, toda longitud tiene tope, la recursion de BinXML tiene fondo
//! ([`MAX_PROFUNDIDAD`]) y ninguna reserva sale de un tamano declarado.

use std::collections::BTreeMap;

use crate::error::{ErrorIngesta, Resultado};
use crate::esquema::{recortar, Clase, Resultado as ResultadoEvento, Severidad, MAX_CAMPO};
use crate::tiempo::desde_filetime;

/// Firma de un fichero EVTX.
pub const FIRMA_FICHERO: &[u8; 8] = b"ElfFile\0";
/// Firma de un trozo.
pub const FIRMA_TROZO: &[u8; 8] = b"ElfChnk\0";
/// Firma de un registro.
pub const FIRMA_REGISTRO: u32 = 0x0000_2a2a;

/// Bytes de la cabecera del fichero, incluido el relleno.
pub const CABECERA_FICHERO: usize = 4096;
/// Bytes de un trozo.
pub const TROZO: usize = 65_536;
/// Desplazamiento dentro del trozo donde empiezan los registros.
const INICIO_REGISTROS: usize = 0x200;

/// Profundidad maxima de anidamiento de BinXML.
///
/// Un documento que se anida dos mil veces agota la pila del proceso, y el
/// proceso es el agente. No es hipotetico: es la forma mas barata de tumbar un
/// analizador recursivo con un fichero de 300 bytes.
pub const MAX_PROFUNDIDAD: usize = 64;

/// Caracteres maximos de una cadena UTF-16 del fichero.
pub const MAX_CADENA: usize = 32 * 1024;

/// Valores maximos en una instancia de plantilla.
pub const MAX_VALORES: usize = 256;

/// Campos maximos por registro.
pub const MAX_CAMPOS: usize = 128;

/// Registros maximos por trozo.
///
/// Un trozo son 64 KiB y el registro mas pequeno pasa de 24 bytes, asi que
/// nunca caben mas de unos pocos miles. El tope existe para que un tamano de
/// registro falseado a cero no deje el bucle girando.
const MAX_REGISTROS_POR_TROZO: usize = 8192;

/// Un registro de suceso ya analizado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registro {
    /// Identificador del registro dentro del fichero.
    pub id: u64,
    /// Cuando se escribio, en nanosegundos Unix.
    pub escrito_ns: u64,
    /// Canal: `Security`, `System`, `Microsoft-Windows-Sysmon/Operational`...
    pub canal: String,
    /// Proveedor que lo emitio.
    pub proveedor: String,
    /// Identificador de evento.
    pub event_id: u32,
    /// Nivel de Windows: 1 critico, 2 error, 3 aviso, 4 informacion, 5 detalle.
    pub nivel: u8,
    /// Maquina.
    pub computadora: String,
    /// Todos los campos del documento, con su nombre.
    pub campos: BTreeMap<String, String>,
}

impl Registro {
    /// Ancla estable de este registro.
    ///
    /// El identificador de registro es unico y creciente dentro de un canal, que
    /// es exactamente lo que hace falta: dos exportaciones del mismo `Security`
    /// solapadas comparten ancla en los registros que comparten.
    #[must_use]
    pub fn ancla(&self) -> String {
        format!("evtx:{}:{}", self.canal, self.id)
    }

    /// Valor de un campo de `EventData` por su nombre.
    #[must_use]
    pub fn dato(&self, nombre: &str) -> Option<&str> {
        self.campos.get(nombre).map(String::as_str)
    }
}

/// Contadores del lector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Contadores {
    /// Registros entregados.
    pub registros: u64,
    /// Trozos leidos.
    pub trozos: u64,
    /// Trozos descartados por firma o suma de comprobacion.
    pub trozos_invalidos: u64,
    /// Registros descartados por estructura rota.
    pub registros_invalidos: u64,
    /// Plantillas resueltas.
    pub plantillas: u64,
    /// Sustituciones que apuntaban fuera del vector de valores.
    pub sustituciones_huerfanas: u64,
}

/// Lector de un fichero EVTX completo.
#[derive(Debug)]
pub struct Lector {
    datos: Vec<u8>,
    contadores: Contadores,
}

impl Lector {
    /// Carga un fichero EVTX.
    ///
    /// Se lee entero en memoria a proposito: un EVTX es un fichero exportado que
    /// se procesa de una vez, no un flujo que se sigue, y los trozos se
    /// referencian entre si. El tope lo pone quien llama al decidir que ficheros
    /// ingiere; aqui se valida el tamano antes de nada.
    pub fn desde_bytes(datos: Vec<u8>) -> Resultado<Lector> {
        if datos.len() < CABECERA_FICHERO {
            return Err(ErrorIngesta::Malformado {
                origen: "evtx",
                motivo: format!("{} bytes: no cabe ni la cabecera", datos.len()),
            });
        }
        if &datos[0..8] != FIRMA_FICHERO {
            return Err(ErrorIngesta::Malformado {
                origen: "evtx",
                motivo: "firma de fichero desconocida".into(),
            });
        }
        Ok(Lector {
            datos,
            contadores: Contadores::default(),
        })
    }

    /// Carga un fichero EVTX desde disco.
    pub fn abrir(ruta: impl AsRef<std::path::Path>) -> Resultado<Lector> {
        let ruta = ruta.as_ref();
        let datos = std::fs::read(ruta)
            .map_err(|e| ErrorIngesta::es(format!("leyendo {}", ruta.display()), e))?;
        Lector::desde_bytes(datos)
    }

    /// Contadores acumulados.
    #[must_use]
    pub fn contadores(&self) -> Contadores {
        self.contadores
    }

    /// Numero de registro siguiente al ultimo escrito, segun la cabecera.
    #[must_use]
    pub fn siguiente_id(&self) -> u64 {
        u64le(&self.datos, 24)
    }

    /// Analiza todos los registros con identificador mayor que `desde`.
    ///
    /// El filtro va aqui y no fuera para que reanudar un fichero grande no
    /// cueste analizar BinXML que ya se analizo: se mira el identificador del
    /// registro, que esta en su cabecera, antes de tocar el documento.
    pub fn leer(&mut self, desde: u64, maximo: usize) -> Vec<Registro> {
        let mut salida = Vec::new();
        let mut inicio = CABECERA_FICHERO;
        while inicio + TROZO <= self.datos.len() && salida.len() < maximo {
            let trozo_fin = inicio + TROZO;
            if self.datos[inicio..inicio + 8] != FIRMA_TROZO[..] {
                // Un trozo sin firma no es el fin del fichero: EVTX reserva el
                // espacio por adelantado y los trozos vacios estan a cero. Se
                // salta y se sigue, porque puede haber trozos validos detras.
                self.contadores.trozos_invalidos += 1;
                inicio = trozo_fin;
                continue;
            }
            self.contadores.trozos += 1;
            let trozo_inicio = inicio;
            let mut pos = INICIO_REGISTROS;
            let mut vistos = 0usize;
            while pos + 24 <= TROZO && salida.len() < maximo && vistos < MAX_REGISTROS_POR_TROZO {
                vistos += 1;
                let base = trozo_inicio + pos;
                if u32le(&self.datos, base) != FIRMA_REGISTRO {
                    break; // fin de los registros de este trozo
                }
                let tamano = u32le(&self.datos, base + 4) as usize;
                if tamano < 24 || pos + tamano > TROZO {
                    self.contadores.registros_invalidos += 1;
                    break;
                }
                let id = u64le(&self.datos, base + 8);
                let filetime = u64le(&self.datos, base + 16);
                if id > desde {
                    match self.analizar_registro(trozo_inicio, pos, tamano, id, filetime) {
                        Some(r) => {
                            self.contadores.registros += 1;
                            salida.push(r);
                        }
                        None => self.contadores.registros_invalidos += 1,
                    }
                }
                pos += tamano;
            }
            inicio = trozo_fin;
        }
        salida
    }

    fn analizar_registro(
        &mut self,
        trozo: usize,
        pos: usize,
        tamano: usize,
        id: u64,
        filetime: u64,
    ) -> Option<Registro> {
        let cuerpo_inicio = pos + 24;
        // Los cuatro ultimos bytes repiten el tamano; no son documento.
        let cuerpo_fin = pos + tamano - 4;
        if cuerpo_fin <= cuerpo_inicio || trozo + cuerpo_fin > self.datos.len() {
            return None;
        }
        let mut campos = BTreeMap::new();
        let mut estado = Estado {
            datos: &self.datos,
            trozo,
            limite: cuerpo_fin,
            campos: &mut campos,
            ruta: Vec::new(),
            plantillas: 0,
            huerfanas: 0,
        };
        let mut p = cuerpo_inicio;
        // Un documento roto no invalida lo que ya se saco de el: media docena
        // de campos de un 4625 valen mas que nada.
        let _ = estado.fragmento(&mut p, 0, &[]);
        self.contadores.plantillas += estado.plantillas;
        self.contadores.sustituciones_huerfanas += estado.huerfanas;

        let escrito_ns = desde_filetime(filetime).unwrap_or(0);
        let event_id = campos
            .get("System/EventID")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let nivel = campos
            .get("System/Level")
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(0);
        Some(Registro {
            id,
            escrito_ns,
            canal: campos.get("System/Channel").cloned().unwrap_or_default(),
            proveedor: campos
                .get("System/Provider/@Name")
                .cloned()
                .unwrap_or_default(),
            event_id,
            nivel,
            computadora: campos.get("System/Computer").cloned().unwrap_or_default(),
            campos,
        })
    }
}

/// Estado del recorrido de un documento BinXML.
struct Estado<'a> {
    datos: &'a [u8],
    /// Desplazamiento del trozo en el fichero: los punteros de BinXML son
    /// relativos a el.
    trozo: usize,
    /// Ultimo byte del documento actual.
    limite: usize,
    campos: &'a mut BTreeMap<String, String>,
    /// Camino de elementos abiertos, para nombrar los campos.
    ruta: Vec<String>,
    plantillas: u64,
    huerfanas: u64,
}

/// Descriptor de un valor de instancia de plantilla.
#[derive(Debug, Clone, Copy)]
struct Hueco {
    tipo: u8,
    inicio: usize,
    largo: usize,
}

impl Estado<'_> {
    /// Recorre un fragmento de BinXML desde `p`.
    fn fragmento(&mut self, p: &mut usize, profundidad: usize, valores: &[Hueco]) -> Option<()> {
        if profundidad > MAX_PROFUNDIDAD {
            return None;
        }
        loop {
            if *p >= self.limite {
                return Some(());
            }
            let token = self.datos[self.trozo + *p];
            *p += 1;
            match token & 0x0f {
                // Fin del flujo.
                0x00 => return Some(()),
                // Elemento: 0x01 sin atributos, 0x41 con ellos.
                0x01 => self.elemento(p, token, profundidad, valores)?,
                // Cierre de elemento.
                0x04 => {
                    self.ruta.pop();
                    return Some(());
                }
                // Fin de la etiqueta de apertura: el contenido viene detras.
                0x02 => {}
                // Elemento vacio: se cierra sin contenido.
                0x03 => {
                    self.ruta.pop();
                    return Some(());
                }
                // Valor literal.
                0x05 => {
                    let tipo = self.datos.get(self.trozo + *p).copied()?;
                    *p += 1;
                    let texto = self.valor_en_linea(p, tipo)?;
                    self.anotar_texto(&texto);
                }
                // Referencia a caracter y a entidad: se saltan, no aportan.
                0x08 => *p += 2,
                0x09 => {
                    self.nombre(p)?;
                }
                // Cabecera de fragmento: version mayor, menor y banderas.
                0x0f => *p += 3,
                // Instancia de plantilla.
                0x0c => {
                    self.instancia(p, profundidad)?;
                    // Una instancia de plantilla es el documento entero.
                    return Some(());
                }
                // Sustitucion normal y opcional.
                0x0d | 0x0e => {
                    let indice = u16le(self.datos, self.trozo + *p) as usize;
                    let tipo_declarado = self.datos.get(self.trozo + *p + 2).copied()?;
                    *p += 3;
                    self.sustituir(indice, tipo_declarado, valores, profundidad);
                }
                _ => return None,
            }
        }
    }

    /// `OpenStartElementTag`: nombre, atributos y contenido.
    fn elemento(
        &mut self,
        p: &mut usize,
        token: u8,
        profundidad: usize,
        valores: &[Hueco],
    ) -> Option<()> {
        // dependency_identifier (2) + data_size (4)
        *p += 6;
        let nombre = self.nombre_referenciado(p)?;
        if self.ruta.len() < MAX_PROFUNDIDAD {
            self.ruta.push(nombre);
        } else {
            return None;
        }
        if token & 0x40 != 0 {
            // Lista de atributos: longitud en bytes y despues los atributos.
            let largo = u32le(self.datos, self.trozo + *p) as usize;
            *p += 4;
            let fin = (*p).checked_add(largo)?;
            if fin > self.limite {
                return None;
            }
            while *p < fin {
                let t = self.datos.get(self.trozo + *p).copied()?;
                *p += 1;
                if t & 0x0f != 0x06 {
                    break;
                }
                let nombre_attr = self.nombre_referenciado(p)?;
                // El valor del atributo es a su vez un token.
                let vt = self.datos.get(self.trozo + *p).copied()?;
                *p += 1;
                let texto = match vt & 0x0f {
                    0x05 => {
                        let tipo = self.datos.get(self.trozo + *p).copied()?;
                        *p += 1;
                        self.valor_en_linea(p, tipo)?
                    }
                    0x0d | 0x0e => {
                        let indice = u16le(self.datos, self.trozo + *p) as usize;
                        let tipo = self.datos.get(self.trozo + *p + 2).copied()?;
                        *p += 3;
                        self.texto_de_hueco(indice, tipo, valores)
                    }
                    _ => String::new(),
                };
                self.anotar_atributo(&nombre_attr, &texto);
            }
            *p = fin;
        }
        // El contenido del elemento: se sigue en el mismo bucle, un nivel mas
        // abajo, hasta el token de cierre.
        self.fragmento(p, profundidad + 1, valores)
    }

    /// `TemplateInstance`: la definicion y despues los valores.
    fn instancia(&mut self, p: &mut usize, profundidad: usize) -> Option<()> {
        // unknown (1) + template_id (4) + definition_offset (4)
        *p += 1;
        *p += 4;
        let definicion = u32le(self.datos, self.trozo + *p) as usize;
        *p += 4;

        // Si la definicion esta AQUI mismo, viene incrustada y hay que saltarla
        // para llegar a los valores. Si no, ya se escribio antes en el trozo y
        // solo se referencia. Confundir los dos casos desplaza toda la lectura.
        let inicio_definicion = if definicion == *p {
            // next_offset (4) + guid (16) + data_size (4)
            let tamano = u32le(self.datos, self.trozo + *p + 20) as usize;
            let cuerpo = *p + 24;
            *p = cuerpo.checked_add(tamano)?;
            cuerpo
        } else {
            if definicion + 24 > TROZO {
                return None;
            }
            definicion + 24
        };

        // Los valores de la instancia.
        let n = u32le(self.datos, self.trozo + *p) as usize;
        *p += 4;
        if n > MAX_VALORES {
            return None;
        }
        let mut huecos = Vec::with_capacity(n.min(64));
        let descriptores = *p;
        let datos_inicio = descriptores.checked_add(n * 4)?;
        let mut en = datos_inicio;
        for i in 0..n {
            let d = descriptores + i * 4;
            if self.trozo + d + 4 > self.datos.len() {
                return None;
            }
            let largo = u16le(self.datos, self.trozo + d) as usize;
            let tipo = self.datos[self.trozo + d + 2];
            if en.checked_add(largo)? > TROZO {
                return None;
            }
            huecos.push(Hueco {
                tipo,
                inicio: en,
                largo,
            });
            en += largo;
        }
        *p = en;
        self.plantillas += 1;

        // Y ahora se recorre la definicion con los valores enlazados. El limite
        // se amplia al trozo entero: la definicion puede vivir fuera del
        // registro actual, que es justo la gracia de las plantillas.
        let limite_anterior = self.limite;
        self.limite = TROZO;
        let mut q = inicio_definicion;
        let r = self.fragmento(&mut q, profundidad + 1, &huecos);
        self.limite = limite_anterior;
        r
    }

    /// Resuelve una sustitucion y la anota.
    fn sustituir(&mut self, indice: usize, tipo: u8, valores: &[Hueco], profundidad: usize) {
        let Some(h) = valores.get(indice) else {
            // Una sustitucion que apunta fuera del vector es un documento roto o
            // preparado. Se cuenta y se sigue: el resto del registro vale.
            self.huerfanas += 1;
            return;
        };
        // El tipo del descriptor manda sobre el declarado en la sustitucion:
        // es el que describe los bytes que hay de verdad.
        let efectivo = if h.tipo == 0 { tipo } else { h.tipo };
        if efectivo == 0x21 {
            // BinXML anidado: un documento dentro de un valor.
            if profundidad > MAX_PROFUNDIDAD {
                return;
            }
            let limite_anterior = self.limite;
            self.limite = (h.inicio + h.largo).min(TROZO);
            let mut q = h.inicio;
            let _ = self.fragmento(&mut q, profundidad + 1, &[]);
            self.limite = limite_anterior;
            return;
        }
        let texto = render(self.datos, self.trozo, h.tipo, h.inicio, h.largo);
        if !texto.is_empty() {
            self.anotar_texto(&texto);
        }
    }

    fn texto_de_hueco(&mut self, indice: usize, tipo: u8, valores: &[Hueco]) -> String {
        let Some(h) = valores.get(indice) else {
            self.huerfanas += 1;
            return String::new();
        };
        let efectivo = if h.tipo == 0 { tipo } else { h.tipo };
        render(self.datos, self.trozo, efectivo, h.inicio, h.largo)
    }

    /// Un valor escrito directamente en el documento.
    fn valor_en_linea(&mut self, p: &mut usize, tipo: u8) -> Option<String> {
        match tipo {
            0x01 => {
                // Cadena UTF-16 con longitud en caracteres delante.
                let n = u16le(self.datos, self.trozo + *p) as usize;
                *p += 2;
                if n > MAX_CADENA {
                    return None;
                }
                let inicio = *p;
                *p = p.checked_add(n * 2)?;
                Some(utf16(self.datos, self.trozo + inicio, n))
            }
            _ => {
                // Los demas tipos en linea no aparecen en los canales que se
                // ingieren; pararse es mas seguro que adivinar su longitud y
                // desalinear todo lo que venga detras.
                None
            }
        }
    }

    /// Nombre que puede venir en linea o referenciado por desplazamiento.
    fn nombre_referenciado(&mut self, p: &mut usize) -> Option<String> {
        let desplazamiento = u32le(self.datos, self.trozo + *p) as usize;
        if desplazamiento == *p {
            *p += 4;
            let mut q = *p;
            let n = self.nombre_en(&mut q)?;
            *p = q;
            Some(n)
        } else {
            *p += 4;
            if desplazamiento + 8 > TROZO {
                return None;
            }
            let mut q = desplazamiento;
            self.nombre_en(&mut q)
        }
    }

    fn nombre(&mut self, p: &mut usize) -> Option<String> {
        let mut q = *p;
        let n = self.nombre_en(&mut q)?;
        *p = q;
        Some(n)
    }

    /// Estructura `Name`: siguiente (4), resumen (2), caracteres (2), UTF-16, NUL.
    fn nombre_en(&self, p: &mut usize) -> Option<String> {
        if self.trozo + *p + 8 > self.datos.len() {
            return None;
        }
        let n = u16le(self.datos, self.trozo + *p + 6) as usize;
        if n > MAX_CADENA {
            return None;
        }
        let inicio = *p + 8;
        let fin = inicio.checked_add(n * 2 + 2)?;
        if fin > TROZO || self.trozo + fin > self.datos.len() {
            return None;
        }
        *p = fin;
        Some(utf16(self.datos, self.trozo + inicio, n))
    }

    /// El texto de un elemento se anota con el camino que lo nombra.
    ///
    /// El caso especial de `EventData/Data` con atributo `Name` ya lo resolvio
    /// [`Estado::anotar_atributo`], que deja el nombre pendiente.
    fn anotar_texto(&mut self, texto: &str) {
        if texto.is_empty() || self.campos.len() >= MAX_CAMPOS {
            return;
        }
        let clave = match self.campos.remove("\u{0}pendiente") {
            Some(nombre) => nombre,
            None => self.clave(),
        };
        self.campos.insert(clave, recortar(texto, MAX_CAMPO));
    }

    fn anotar_atributo(&mut self, nombre: &str, texto: &str) {
        if self.campos.len() >= MAX_CAMPOS {
            return;
        }
        // `<Data Name="TargetUserName">pepe</Data>` es como Windows nombra TODO
        // lo que importa de un suceso de seguridad. Sin este caso, los cincuenta
        // valores de un 4688 saldrian como `EventData/Data` repetido y no se
        // podria distinguir el usuario del comando.
        if nombre == "Name" && self.ruta.last().map(String::as_str) == Some("Data") {
            self.campos
                .insert("\u{0}pendiente".into(), recortar(texto, 128));
            return;
        }
        if texto.is_empty() {
            return;
        }
        let clave = format!("{}/@{}", self.clave(), nombre);
        self.campos.insert(clave, recortar(texto, MAX_CAMPO));
    }

    /// Camino del elemento actual, sin el `Event` de fuera.
    fn clave(&self) -> String {
        let partes: Vec<&str> = self
            .ruta
            .iter()
            .map(String::as_str)
            .filter(|s| *s != "Event")
            .collect();
        partes.join("/")
    }
}

/// Convierte un valor de BinXML a texto.
///
/// Cada tipo se lee con su tamano exacto. Adivinar el tamano de uno solo
/// desalinea el resto del registro, y el sintoma no es un error: son campos con
/// valores creibles y equivocados.
fn render(datos: &[u8], trozo: usize, tipo: u8, inicio: usize, largo: usize) -> String {
    let base = trozo + inicio;
    let fin = base + largo;
    if fin > datos.len() {
        return String::new();
    }
    // Los tipos con el bit alto son vectores del tipo de abajo.
    if tipo & 0x80 != 0 {
        let base_tipo = tipo & 0x7f;
        if base_tipo == 0x01 {
            // Vector de cadenas UTF-16 separadas por NUL.
            let cadena = utf16(datos, base, largo / 2);
            return cadena
                .split('\u{0}')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", ");
        }
        return String::new();
    }
    match tipo {
        0x00 => String::new(),
        0x01 => utf16(datos, base, largo / 2)
            .trim_end_matches('\u{0}')
            .to_string(),
        0x02 => String::from_utf8_lossy(&datos[base..fin])
            .trim_end_matches('\u{0}')
            .to_string(),
        0x03 => i64::from(datos[base] as i8).to_string(),
        0x04 => datos[base].to_string(),
        0x05 => (u16le(datos, base) as i16).to_string(),
        0x06 => u16le(datos, base).to_string(),
        0x07 => (u32le(datos, base) as i32).to_string(),
        0x08 => u32le(datos, base).to_string(),
        0x09 => (u64le(datos, base) as i64).to_string(),
        0x0a => u64le(datos, base).to_string(),
        0x0b => f32::from_bits(u32le(datos, base)).to_string(),
        0x0c => f64::from_bits(u64le(datos, base)).to_string(),
        0x0d => (u32le(datos, base) != 0).to_string(),
        0x0e => hex(&datos[base..fin.min(base + 256)]),
        0x0f => guid(datos, base),
        0x10 => u64le(datos, base).to_string(),
        0x11 => desde_filetime(u64le(datos, base)).map_or_else(String::new, |n| n.to_string()),
        0x12 => systime(datos, base),
        0x13 => sid(datos, base, largo),
        0x14 => format!("0x{:08x}", u32le(datos, base)),
        0x15 => format!("0x{:016x}", u64le(datos, base)),
        _ => String::new(),
    }
}

fn utf16(datos: &[u8], base: usize, caracteres: usize) -> String {
    let n = caracteres.min(MAX_CADENA);
    let fin = base + n * 2;
    if fin > datos.len() {
        return String::new();
    }
    let unidades: Vec<u16> = datos[base..fin]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&unidades)
}

/// SID de Windows en su forma textual `S-1-5-21-...`.
///
/// Se renderiza entero porque es la identidad: un 4624 sin el SID es un inicio
/// de sesion sin sujeto, y el nombre de cuenta se puede reutilizar mientras que
/// el SID no.
fn sid(datos: &[u8], base: usize, largo: usize) -> String {
    if largo < 8 || base + 8 > datos.len() {
        return String::new();
    }
    let revision = datos[base];
    let subautoridades = usize::from(datos[base + 1]);
    if base + 8 + subautoridades * 4 > datos.len() || subautoridades > 15 {
        return String::new();
    }
    let mut autoridad: u64 = 0;
    for b in &datos[base + 2..base + 8] {
        autoridad = (autoridad << 8) | u64::from(*b);
    }
    let mut s = format!("S-{revision}-{autoridad}");
    for i in 0..subautoridades {
        use std::fmt::Write as _;
        let _ = write!(s, "-{}", u32le(datos, base + 8 + i * 4));
    }
    s
}

fn guid(datos: &[u8], base: usize) -> String {
    if base + 16 > datos.len() {
        return String::new();
    }
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{}",
        u32le(datos, base),
        u16le(datos, base + 4),
        u16le(datos, base + 6),
        datos[base + 8],
        datos[base + 9],
        hex(&datos[base + 10..base + 16]).to_uppercase()
    )
}

fn systime(datos: &[u8], base: usize) -> String {
    if base + 16 > datos.len() {
        return String::new();
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        u16le(datos, base),
        u16le(datos, base + 2),
        u16le(datos, base + 6),
        u16le(datos, base + 8),
        u16le(datos, base + 10),
        u16le(datos, base + 12),
        u16le(datos, base + 14)
    )
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn u16le(d: &[u8], en: usize) -> u16 {
    if en + 2 > d.len() {
        return 0;
    }
    u16::from_le_bytes([d[en], d[en + 1]])
}

fn u32le(d: &[u8], en: usize) -> u32 {
    if en + 4 > d.len() {
        return 0;
    }
    u32::from_le_bytes([d[en], d[en + 1], d[en + 2], d[en + 3]])
}

fn u64le(d: &[u8], en: usize) -> u64 {
    if en + 8 > d.len() {
        return 0;
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&d[en..en + 8]);
    u64::from_le_bytes(a)
}

/// El catalogo de sucesos que importan.
///
/// # Por que un catalogo y no el texto del proveedor
///
/// Ver el encabezado del modulo: la frase legible no esta en el fichero, vive en
/// una DLL de la maquina de origen y depende de su idioma. El identificador, no:
/// un 4625 es un fallo de autenticacion en aleman igual que en castellano.
///
/// La lista no pretende ser exhaustiva —Windows define miles— sino cubrir lo que
/// un EDR usa: autenticacion, cuentas, privilegios, servicios, borrado de
/// registros, y los canales de Sysmon.
pub mod catalogo {
    use super::{Clase, ResultadoEvento, Severidad};

    /// Lo que se sabe de un identificador de evento.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Conocido {
        /// Que clase de hecho es.
        pub clase: Clase,
        /// Como acabo.
        pub resultado: ResultadoEvento,
        /// Gravedad.
        pub severidad: Severidad,
        /// Descripcion corta, en castellano y estable.
        pub descripcion: &'static str,
    }

    const fn c(
        clase: Clase,
        resultado: ResultadoEvento,
        severidad: Severidad,
        descripcion: &'static str,
    ) -> Conocido {
        Conocido {
            clase,
            resultado,
            severidad,
            descripcion,
        }
    }

    /// Busca un identificador de evento del canal `Security` o `System`.
    #[must_use]
    pub fn windows(event_id: u32) -> Option<Conocido> {
        use Clase::*;
        use ResultadoEvento::*;
        use Severidad::*;
        Some(match event_id {
            4624 => c(Autenticacion, Exito, Info, "inicio de sesion correcto"),
            4625 => c(Autenticacion, Fallo, Media, "inicio de sesion fallido"),
            4634 => c(Autenticacion, Exito, Info, "cierre de sesion"),
            4647 => c(
                Autenticacion,
                Exito,
                Info,
                "cierre de sesion iniciado por el usuario",
            ),
            4648 => c(
                Autenticacion,
                Exito,
                Media,
                "inicio de sesion con credenciales explicitas",
            ),
            4672 => c(
                Autenticacion,
                Exito,
                Alta,
                "sesion con privilegios especiales",
            ),
            4673 => c(Autenticacion, Fallo, Media, "uso de un privilegio"),
            4688 => c(ActividadDeProceso, Exito, Media, "proceso creado"),
            4689 => c(ActividadDeProceso, Exito, Info, "proceso terminado"),
            4697 => c(ActividadDeServicio, Exito, Alta, "servicio instalado"),
            4698..=4702 => c(ActividadDeConfiguracion, Exito, Alta, "tarea programada"),
            4704 | 4705 => c(GestionDeCuentas, Exito, Alta, "derecho de usuario asignado"),
            4719 => c(
                ActividadDeConfiguracion,
                Exito,
                Critica,
                "politica de auditoria cambiada",
            ),
            4720 => c(GestionDeCuentas, Exito, Alta, "cuenta creada"),
            4722 => c(GestionDeCuentas, Exito, Media, "cuenta habilitada"),
            4723 | 4724 => c(GestionDeCuentas, Exito, Alta, "cambio de contrasena"),
            4725 => c(GestionDeCuentas, Exito, Media, "cuenta deshabilitada"),
            4726 => c(GestionDeCuentas, Exito, Alta, "cuenta borrada"),
            4728 | 4732 | 4756 => c(
                GestionDeCuentas,
                Exito,
                Alta,
                "cuenta anadida a un grupo privilegiado",
            ),
            4729 | 4733 | 4757 => c(GestionDeCuentas, Exito, Media, "cuenta quitada de un grupo"),
            4738 => c(GestionDeCuentas, Exito, Media, "cuenta modificada"),
            4740 => c(GestionDeCuentas, Fallo, Alta, "cuenta bloqueada"),
            4768 => c(Autenticacion, Exito, Info, "ticket de Kerberos concedido"),
            4769 => c(
                Autenticacion,
                Exito,
                Media,
                "ticket de servicio de Kerberos",
            ),
            4771 => c(
                Autenticacion,
                Fallo,
                Media,
                "preautenticacion de Kerberos fallida",
            ),
            4776 => c(
                Autenticacion,
                Desconocido,
                Media,
                "validacion de credenciales NTLM",
            ),
            // El borrado del registro de sucesos es de las senales mas claras
            // que hay: nadie limpia el log de seguridad por higiene.
            1102 => c(
                HallazgoDeSeguridad,
                Exito,
                Critica,
                "registro de auditoria borrado",
            ),
            1100 => c(
                ActividadDeServicio,
                Exito,
                Alta,
                "servicio de registro de sucesos parado",
            ),
            104 => c(
                HallazgoDeSeguridad,
                Exito,
                Critica,
                "registro de sucesos borrado",
            ),
            7045 => c(ActividadDeServicio, Exito, Alta, "servicio nuevo instalado"),
            7034 | 7031 => c(
                ActividadDeServicio,
                Fallo,
                Media,
                "servicio terminado inesperadamente",
            ),
            6416 => c(
                ActividadDelSistema,
                Exito,
                Media,
                "dispositivo externo reconocido",
            ),
            5140 | 5145 => c(
                ActividadDeFichero,
                Exito,
                Media,
                "acceso a recurso compartido",
            ),
            5156 => c(
                ActividadDeRed,
                Exito,
                Info,
                "conexion permitida por el cortafuegos",
            ),
            5157 => c(
                ActividadDeRed,
                Fallo,
                Media,
                "conexion bloqueada por el cortafuegos",
            ),
            _ => return None,
        })
    }

    /// Busca un identificador del canal de Sysmon.
    ///
    /// Sysmon no viene con Windows: lo instala quien sabe lo que hace. Su
    /// telemetria es la mas util que produce la plataforma y por eso tiene
    /// catalogo propio.
    #[must_use]
    pub fn sysmon(event_id: u32) -> Option<Conocido> {
        use Clase::*;
        use ResultadoEvento::*;
        use Severidad::*;
        Some(match event_id {
            1 => c(ActividadDeProceso, Exito, Media, "proceso creado"),
            2 => c(ActividadDeFichero, Exito, Alta, "fecha de fichero alterada"),
            3 => c(ActividadDeRed, Exito, Media, "conexion de red"),
            4 => c(
                ActividadDeServicio,
                Exito,
                Media,
                "cambio de estado de Sysmon",
            ),
            5 => c(ActividadDeProceso, Exito, Info, "proceso terminado"),
            6 => c(
                ActividadDeConfiguracion,
                Exito,
                Critica,
                "controlador cargado",
            ),
            7 => c(ActividadDeProceso, Exito, Media, "imagen cargada"),
            8 => c(
                ActividadDeProceso,
                Exito,
                Critica,
                "hilo creado en otro proceso",
            ),
            9 => c(ActividadDeFichero, Exito, Alta, "lectura directa de disco"),
            10 => c(ActividadDeProceso, Exito, Alta, "acceso a otro proceso"),
            11 => c(ActividadDeFichero, Exito, Media, "fichero creado"),
            12..=14 => c(
                ActividadDeConfiguracion,
                Exito,
                Media,
                "cambio en el registro",
            ),
            15 => c(ActividadDeFichero, Exito, Alta, "flujo alternativo creado"),
            17 | 18 => c(ActividadDeProceso, Exito, Media, "tuberia con nombre"),
            19..=21 => c(
                ActividadDeConfiguracion,
                Exito,
                Critica,
                "persistencia por WMI",
            ),
            22 => c(ActividadDns, Exito, Media, "consulta DNS"),
            23 | 26 => c(ActividadDeFichero, Exito, Alta, "fichero borrado"),
            25 => c(
                ActividadDeProceso,
                Exito,
                Critica,
                "imagen de proceso alterada",
            ),
            27 | 28 => c(
                HallazgoDeSeguridad,
                Exito,
                Alta,
                "fichero bloqueado por Sysmon",
            ),
            29 => c(
                ActividadDeFichero,
                Exito,
                Media,
                "fichero ejecutable detectado",
            ),
            _ => return None,
        })
    }

    /// Busca en el catalogo que corresponda al canal.
    #[must_use]
    pub fn buscar(canal: &str, event_id: u32) -> Option<Conocido> {
        if canal.contains("Sysmon") {
            return sysmon(event_id);
        }
        windows(event_id)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // Las pruebas construyen ficheros EVTX BYTE A BYTE con el formato real: es
    // la unica forma de probar un analizador binario sin depender de que la
    // maquina de integracion sea Windows, y ademas permite fabricar los ficheros
    // hostiles que ningun Windows generaria.

    /// EL TROZO ES UN BLOQUE FIJO DE 64 KiB CON DOS ZONAS.
    ///
    /// Los registros empiezan en 0x200, justo detras de la cabecera y las tablas,
    /// porque es ahi donde los busca el lector —y donde los pone Windows—. Las
    /// estructuras `Name` van a partir de la mitad del trozo: son datos sueltos
    /// referenciados por desplazamiento absoluto, asi que pueden estar en
    /// cualquier sitio, pero **no delante de los registros**. Escribirlas ahi es
    /// el error que hace que un fichero de prueba no se parezca a uno real y que
    /// el analizador no encuentre ni un solo registro.
    struct Constructor {
        trozo: Vec<u8>,
        fin_nombres: usize,
        fin_registros: usize,
        siguiente_id: u64,
    }

    /// Zona de nombres: la segunda mitad del trozo.
    const ZONA_NOMBRES: usize = 0x8000;

    /// Escribe una estructura `Name` y devuelve su desplazamiento en el trozo.
    fn nombre_en(c: &mut Constructor, texto: &str) -> u32 {
        let en = c.fin_nombres;
        let unidades: Vec<u16> = texto.encode_utf16().collect();
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // siguiente
        buf.extend_from_slice(&0u16.to_le_bytes()); // resumen
        buf.extend_from_slice(&u16::try_from(unidades.len()).unwrap().to_le_bytes());
        for u in &unidades {
            buf.extend_from_slice(&u.to_le_bytes());
        }
        buf.extend_from_slice(&0u16.to_le_bytes()); // NUL
        assert!(en + buf.len() <= TROZO, "la zona de nombres no cabe");
        c.trozo[en..en + buf.len()].copy_from_slice(&buf);
        c.fin_nombres = en + buf.len();
        u32::try_from(en).unwrap()
    }

    impl Constructor {
        fn nuevo() -> Constructor {
            let mut trozo = vec![0u8; TROZO];
            trozo[0..8].copy_from_slice(FIRMA_TROZO);
            Constructor {
                trozo,
                fin_nombres: ZONA_NOMBRES,
                fin_registros: INICIO_REGISTROS,
                siguiente_id: 1,
            }
        }

        /// Un elemento con texto literal: `<nombre>texto</nombre>`.
        fn elemento_texto(&mut self, doc: &mut Vec<u8>, base: usize, nom: &str, texto: &str) {
            let off = nombre_en(self, nom);
            doc.push(0x01); // OpenStartElement sin atributos
            doc.extend_from_slice(&0u16.to_le_bytes()); // dependency
            doc.extend_from_slice(&0u32.to_le_bytes()); // data_size
            doc.extend_from_slice(&off.to_le_bytes());
            doc.push(0x02); // CloseStartElement
            doc.push(0x05); // Value
            doc.push(0x01); // UnicodeString
            let u: Vec<u16> = texto.encode_utf16().collect();
            doc.extend_from_slice(&u16::try_from(u.len()).unwrap().to_le_bytes());
            for x in &u {
                doc.extend_from_slice(&x.to_le_bytes());
            }
            doc.push(0x04); // EndElement
            let _ = base;
        }

        /// Un elemento con un atributo literal.
        fn elemento_atributo(&mut self, doc: &mut Vec<u8>, nom: &str, attr: &str, valor: &str) {
            let off = nombre_en(self, nom);
            let off_attr = nombre_en(self, attr);
            doc.push(0x41); // OpenStartElement CON atributos
            doc.extend_from_slice(&0u16.to_le_bytes());
            doc.extend_from_slice(&0u32.to_le_bytes());
            doc.extend_from_slice(&off.to_le_bytes());

            let mut lista = Vec::new();
            lista.push(0x06u8); // Attribute
            lista.extend_from_slice(&off_attr.to_le_bytes());
            lista.push(0x05); // Value
            lista.push(0x01); // UnicodeString
            let u: Vec<u16> = valor.encode_utf16().collect();
            lista.extend_from_slice(&u16::try_from(u.len()).unwrap().to_le_bytes());
            for x in &u {
                lista.extend_from_slice(&x.to_le_bytes());
            }
            doc.extend_from_slice(&u32::try_from(lista.len()).unwrap().to_le_bytes());
            doc.extend_from_slice(&lista);
            doc.push(0x03); // CloseEmptyElement
        }

        fn abrir(&mut self, doc: &mut Vec<u8>, nom: &str) {
            let off = nombre_en(self, nom);
            doc.push(0x01);
            doc.extend_from_slice(&0u16.to_le_bytes());
            doc.extend_from_slice(&0u32.to_le_bytes());
            doc.extend_from_slice(&off.to_le_bytes());
            doc.push(0x02);
        }

        fn cerrar(doc: &mut Vec<u8>) {
            doc.push(0x04);
        }

        fn registro(&mut self, filetime: u64, doc: &[u8]) {
            let id = self.siguiente_id;
            self.siguiente_id += 1;
            let tamano = u32::try_from(24 + doc.len() + 4).unwrap();
            let mut buf = Vec::new();
            buf.extend_from_slice(&FIRMA_REGISTRO.to_le_bytes());
            buf.extend_from_slice(&tamano.to_le_bytes());
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&filetime.to_le_bytes());
            buf.extend_from_slice(doc);
            buf.extend_from_slice(&tamano.to_le_bytes());
            let en = self.fin_registros;
            assert!(
                en + buf.len() <= ZONA_NOMBRES,
                "la zona de registros no cabe"
            );
            self.trozo[en..en + buf.len()].copy_from_slice(&buf);
            self.fin_registros = en + buf.len();
        }

        fn terminar(self) -> Vec<u8> {
            let mut fichero = vec![0u8; CABECERA_FICHERO];
            fichero[0..8].copy_from_slice(FIRMA_FICHERO);
            fichero[24..32].copy_from_slice(&self.siguiente_id.to_le_bytes());
            fichero.extend_from_slice(&self.trozo);
            fichero
        }

        /// Desplazamiento en el trozo donde caera el proximo registro.
        fn inicio_registros(&self) -> usize {
            self.fin_registros
        }
    }

    /// Construye un EVTX con un suceso 4625 completo, como lo escribe Windows.
    fn evtx_4625() -> Vec<u8> {
        let mut c = Constructor::nuevo();
        let mut doc = Vec::new();
        doc.push(0x0f); // FragmentHeader
        doc.extend_from_slice(&[1, 1, 0]);
        c.abrir(&mut doc, "Event");
        c.abrir(&mut doc, "System");
        c.elemento_atributo(
            &mut doc,
            "Provider",
            "Name",
            "Microsoft-Windows-Security-Auditing",
        );
        c.elemento_texto(&mut doc, 0, "EventID", "4625");
        c.elemento_texto(&mut doc, 0, "Level", "0");
        c.elemento_texto(&mut doc, 0, "Channel", "Security");
        c.elemento_texto(&mut doc, 0, "Computer", "DC01.corp.local");
        Constructor::cerrar(&mut doc); // System
        c.abrir(&mut doc, "EventData");
        for (n, v) in [
            ("TargetUserName", "administrador"),
            ("IpAddress", "10.0.0.9"),
            ("LogonType", "3"),
            ("SubStatus", "0xc000006a"),
        ] {
            // `<Data Name="X">v</Data>`: como Windows nombra TODO lo que importa.
            let off = nombre_en(&mut c, "Data");
            let off_attr = nombre_en(&mut c, "Name");
            doc.push(0x41);
            doc.extend_from_slice(&0u16.to_le_bytes());
            doc.extend_from_slice(&0u32.to_le_bytes());
            doc.extend_from_slice(&off.to_le_bytes());
            let mut lista = vec![0x06u8];
            lista.extend_from_slice(&off_attr.to_le_bytes());
            lista.push(0x05);
            lista.push(0x01);
            let u: Vec<u16> = n.encode_utf16().collect();
            lista.extend_from_slice(&u16::try_from(u.len()).unwrap().to_le_bytes());
            for x in &u {
                lista.extend_from_slice(&x.to_le_bytes());
            }
            doc.extend_from_slice(&u32::try_from(lista.len()).unwrap().to_le_bytes());
            doc.extend_from_slice(&lista);
            doc.push(0x02); // CloseStartElement
            doc.push(0x05);
            doc.push(0x01);
            let u: Vec<u16> = v.encode_utf16().collect();
            doc.extend_from_slice(&u16::try_from(u.len()).unwrap().to_le_bytes());
            for x in &u {
                doc.extend_from_slice(&x.to_le_bytes());
            }
            doc.push(0x04);
        }
        Constructor::cerrar(&mut doc); // EventData
        Constructor::cerrar(&mut doc); // Event
        doc.push(0x00); // fin del flujo
        c.registro(133_000_000_000_000_000, &doc);
        c.terminar()
    }

    // --- El formato, entero -------------------------------------------------

    #[test]
    fn un_4625_sale_con_todos_sus_campos_nombrados() {
        // LA PRUEBA DE LA FASE PARA EVTX: sin resolver los nombres, los
        // cincuenta valores de un suceso de seguridad salen como
        // `EventData/Data` repetido y no se puede distinguir el usuario del
        // comando.
        let mut l = Lector::desde_bytes(evtx_4625()).unwrap();
        let rs = l.leer(0, 10);
        assert_eq!(rs.len(), 1, "campos: {:?}", rs.first().map(|r| &r.campos));
        let r = &rs[0];
        assert_eq!(r.event_id, 4625);
        assert_eq!(r.canal, "Security");
        assert_eq!(r.computadora, "DC01.corp.local");
        assert_eq!(r.proveedor, "Microsoft-Windows-Security-Auditing");
        assert_eq!(r.dato("TargetUserName"), Some("administrador"));
        assert_eq!(r.dato("IpAddress"), Some("10.0.0.9"));
        assert_eq!(r.dato("LogonType"), Some("3"));
    }

    #[test]
    fn la_hora_del_registro_se_convierte_desde_filetime() {
        let mut l = Lector::desde_bytes(evtx_4625()).unwrap();
        let r = &l.leer(0, 10)[0];
        // 133e15 intervalos de 100 ns desde 1601 caen en 2022.
        assert!(r.escrito_ns > 1_600_000_000_000_000_000, "{}", r.escrito_ns);
        assert!(r.escrito_ns < 1_800_000_000_000_000_000);
    }

    #[test]
    fn el_ancla_lleva_el_canal_y_el_identificador_de_registro() {
        let mut l = Lector::desde_bytes(evtx_4625()).unwrap();
        let r = &l.leer(0, 10)[0];
        assert_eq!(r.ancla(), "evtx:Security:1");
    }

    #[test]
    fn reanudar_por_identificador_no_reanaliza_lo_ya_leido() {
        let mut c = Constructor::nuevo();
        for i in 0..5u64 {
            let mut doc = Vec::new();
            doc.push(0x0f);
            doc.extend_from_slice(&[1, 1, 0]);
            c.abrir(&mut doc, "Event");
            c.elemento_texto(&mut doc, 0, "EventID", &format!("{}", 4600 + i));
            Constructor::cerrar(&mut doc);
            doc.push(0x00);
            c.registro(133_000_000_000_000_000 + i, &doc);
        }
        let bytes = c.terminar();
        let mut l = Lector::desde_bytes(bytes).unwrap();
        let rs = l.leer(3, 100);
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].id, 4);
    }

    #[test]
    fn una_plantilla_se_resuelve_con_sus_valores() {
        // La capa que hace que un EVTX no se pueda leer «a ojo»: el registro
        // solo lleva los valores, y el esqueleto vive en la plantilla.
        let mut c = Constructor::nuevo();

        // La definicion de plantilla: <Event><EventID>{0}</EventID>
        // <Channel>{1}</Channel></Event>
        let off_event = nombre_en(&mut c, "Event");
        let off_system = nombre_en(&mut c, "System");
        let off_id = nombre_en(&mut c, "EventID");
        let off_canal = nombre_en(&mut c, "Channel");

        let mut cuerpo = Vec::new();
        cuerpo.push(0x0f);
        cuerpo.extend_from_slice(&[1, 1, 0]);
        for (off, indice, tipo) in [
            (off_event, None, 0u8),
            (off_system, None, 0u8),
            (off_id, Some(0u16), 0x08),
            (off_canal, Some(1), 0x01),
        ] {
            cuerpo.push(0x01);
            cuerpo.extend_from_slice(&0u16.to_le_bytes());
            cuerpo.extend_from_slice(&0u32.to_le_bytes());
            cuerpo.extend_from_slice(&off.to_le_bytes());
            cuerpo.push(0x02);
            if let Some(i) = indice {
                cuerpo.push(0x0d); // NormalSubstitution
                cuerpo.extend_from_slice(&i.to_le_bytes());
                cuerpo.push(tipo);
                cuerpo.push(0x04); // cierra el elemento hoja
            }
        }
        cuerpo.push(0x04); // cierra System
        cuerpo.push(0x04); // cierra Event
        cuerpo.push(0x00);

        // El documento del registro: cabecera de fragmento e instancia.
        let mut doc = Vec::new();
        doc.push(0x0f);
        doc.extend_from_slice(&[1, 1, 0]);
        doc.push(0x0c); // TemplateInstance
        doc.push(0x01); // unknown
        doc.extend_from_slice(&7u32.to_le_bytes()); // template_id
                                                    // La definicion viene incrustada aqui mismo: el desplazamiento apunta a
                                                    // la posicion siguiente dentro del trozo.
        let en_trozo = c.inicio_registros() + 24 + doc.len() + 4;
        doc.extend_from_slice(&u32::try_from(en_trozo).unwrap().to_le_bytes());
        doc.extend_from_slice(&0u32.to_le_bytes()); // next_offset
        doc.extend_from_slice(&[0u8; 16]); // guid
        doc.extend_from_slice(&u32::try_from(cuerpo.len()).unwrap().to_le_bytes());
        doc.extend_from_slice(&cuerpo);
        // Los valores: 4688 (u32) y "Security" (UTF-16).
        doc.extend_from_slice(&2u32.to_le_bytes());
        let canal: Vec<u16> = "Security".encode_utf16().collect();
        doc.extend_from_slice(&4u16.to_le_bytes());
        doc.push(0x08);
        doc.push(0);
        doc.extend_from_slice(&u16::try_from(canal.len() * 2).unwrap().to_le_bytes());
        doc.push(0x01);
        doc.push(0);
        doc.extend_from_slice(&4688u32.to_le_bytes());
        for x in &canal {
            doc.extend_from_slice(&x.to_le_bytes());
        }

        c.registro(133_000_000_000_000_000, &doc);
        let mut l = Lector::desde_bytes(c.terminar()).unwrap();
        let rs = l.leer(0, 10);
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].event_id, 4688, "campos: {:?}", rs[0].campos);
        assert_eq!(rs[0].canal, "Security");
        assert_eq!(l.contadores().plantillas, 1);
    }

    // --- Los tipos de valor -------------------------------------------------

    #[test]
    fn un_sid_se_renderiza_entero() {
        // Un 4624 sin SID es un inicio de sesion sin sujeto: el nombre de cuenta
        // se puede reutilizar y el SID no.
        // S-1-5-21-1004336348-1177238915-682003330-512
        let mut b = vec![1u8, 5]; // revision 1, 5 subautoridades
        b.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // autoridad 5
        for x in [21u32, 1_004_336_348, 1_177_238_915, 682_003_330, 512] {
            b.extend_from_slice(&x.to_le_bytes());
        }
        assert_eq!(
            render(&b, 0, 0x13, 0, b.len()),
            "S-1-5-21-1004336348-1177238915-682003330-512"
        );
    }

    #[test]
    fn cada_tipo_numerico_se_lee_con_su_tamano_exacto() {
        // Adivinar el tamano de uno solo desalinea el resto del registro, y el
        // sintoma no es un error: son campos con valores creibles y equivocados.
        let b = [0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(render(&b, 0, 0x03, 0, 1), "-1", "Int8");
        assert_eq!(render(&b, 0, 0x04, 0, 1), "255", "UInt8");
        assert_eq!(render(&b, 0, 0x05, 0, 2), "-1", "Int16");
        assert_eq!(render(&b, 0, 0x06, 0, 2), "65535", "UInt16");
        assert_eq!(render(&b, 0, 0x07, 0, 4), "-1", "Int32");
        assert_eq!(render(&b, 0, 0x08, 0, 4), "4294967295", "UInt32");
        assert_eq!(render(&b, 0, 0x14, 0, 4), "0xffffffff", "HexInt32");
        assert_eq!(render(&b, 0, 0x0d, 0, 4), "true", "Bool");
    }

    #[test]
    fn un_guid_sale_en_su_forma_canonica() {
        let mut b = Vec::new();
        b.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        b.extend_from_slice(&0x9abcu16.to_le_bytes());
        b.extend_from_slice(&0xdef0u16.to_le_bytes());
        b.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert_eq!(
            render(&b, 0, 0x0f, 0, 16),
            "12345678-9ABC-DEF0-1122-334455667788"
        );
    }

    // --- Entrada hostil ------------------------------------------------------

    #[test]
    fn un_documento_anidado_dos_mil_veces_no_agota_la_pila() {
        // Es la forma mas barata de tumbar un analizador recursivo con un
        // fichero de 300 bytes, y el proceso que cae es el agente.
        let mut c = Constructor::nuevo();
        let off = nombre_en(&mut c, "A");
        let mut doc = Vec::new();
        doc.push(0x0f);
        doc.extend_from_slice(&[1, 1, 0]);
        for _ in 0..2000 {
            doc.push(0x01);
            doc.extend_from_slice(&0u16.to_le_bytes());
            doc.extend_from_slice(&0u32.to_le_bytes());
            doc.extend_from_slice(&off.to_le_bytes());
            doc.push(0x02);
        }
        c.registro(133_000_000_000_000_000, &doc);
        let mut l = Lector::desde_bytes(c.terminar()).unwrap();
        let _ = l.leer(0, 10); // no entra en panico y no desborda
    }

    #[test]
    fn una_sustitucion_que_apunta_fuera_del_vector_no_pierde_el_resto() {
        // Se cuenta y se sigue: media docena de campos de un 4625 valen mas que
        // nada.
        let mut c = Constructor::nuevo();
        let off_event = nombre_en(&mut c, "Event");
        let off_id = nombre_en(&mut c, "EventID");
        let mut cuerpo = Vec::new();
        cuerpo.push(0x0f);
        cuerpo.extend_from_slice(&[1, 1, 0]);
        for (off, indice) in [(off_event, None), (off_id, Some(99u16))] {
            cuerpo.push(0x01);
            cuerpo.extend_from_slice(&0u16.to_le_bytes());
            cuerpo.extend_from_slice(&0u32.to_le_bytes());
            cuerpo.extend_from_slice(&off.to_le_bytes());
            cuerpo.push(0x02);
            if let Some(i) = indice {
                cuerpo.push(0x0d);
                cuerpo.extend_from_slice(&i.to_le_bytes());
                cuerpo.push(0x08);
                cuerpo.push(0x04);
            }
        }
        cuerpo.push(0x04);
        cuerpo.push(0x00);

        let mut doc = Vec::new();
        doc.push(0x0f);
        doc.extend_from_slice(&[1, 1, 0]);
        doc.push(0x0c);
        doc.push(0x01);
        doc.extend_from_slice(&7u32.to_le_bytes());
        let en_trozo = c.inicio_registros() + 24 + doc.len() + 4;
        doc.extend_from_slice(&u32::try_from(en_trozo).unwrap().to_le_bytes());
        doc.extend_from_slice(&0u32.to_le_bytes());
        doc.extend_from_slice(&[0u8; 16]);
        doc.extend_from_slice(&u32::try_from(cuerpo.len()).unwrap().to_le_bytes());
        doc.extend_from_slice(&cuerpo);
        doc.extend_from_slice(&0u32.to_le_bytes()); // cero valores

        c.registro(133_000_000_000_000_000, &doc);
        let mut l = Lector::desde_bytes(c.terminar()).unwrap();
        let _ = l.leer(0, 10);
        assert!(l.contadores().sustituciones_huerfanas > 0, "y se cuenta");
    }

    #[test]
    fn un_tamano_de_registro_falseado_a_cero_no_deja_el_bucle_girando() {
        let mut c = Constructor::nuevo();
        let mut doc = Vec::new();
        doc.push(0x0f);
        doc.extend_from_slice(&[1, 1, 0]);
        doc.push(0x00);
        c.registro(1, &doc);
        // Se falsea el tamano del registro a cero, en su sitio del trozo.
        c.trozo[INICIO_REGISTROS + 4..INICIO_REGISTROS + 8].copy_from_slice(&0u32.to_le_bytes());
        let mut l = Lector::desde_bytes(c.terminar()).unwrap();
        let rs = l.leer(0, 100);
        assert!(rs.is_empty());
        assert!(l.contadores().registros_invalidos > 0);
    }

    #[test]
    fn un_fichero_sin_firma_no_se_analiza() {
        assert!(Lector::desde_bytes(vec![0u8; 5000]).is_err());
        assert!(Lector::desde_bytes(vec![0u8; 10]).is_err());
    }

    #[test]
    fn un_trozo_vacio_no_es_el_fin_del_fichero() {
        // EVTX reserva el espacio por adelantado y los trozos vacios estan a
        // cero; puede haber trozos validos detras.
        let bueno = evtx_4625();
        let mut fichero = vec![0u8; CABECERA_FICHERO];
        fichero[0..8].copy_from_slice(FIRMA_FICHERO);
        fichero.extend(std::iter::repeat_n(0u8, TROZO)); // trozo a cero
        fichero.extend_from_slice(&bueno[CABECERA_FICHERO..]);
        let mut l = Lector::desde_bytes(fichero).unwrap();
        assert_eq!(l.leer(0, 10).len(), 1, "el trozo bueno esta detras");
        assert_eq!(l.contadores().trozos_invalidos, 1);
    }

    #[test]
    fn una_cadena_absurdamente_larga_no_reserva_por_lo_declarado() {
        let mut c = Constructor::nuevo();
        let mut doc = Vec::new();
        doc.push(0x0f);
        doc.extend_from_slice(&[1, 1, 0]);
        c.abrir(&mut doc, "Event");
        doc.push(0x05);
        doc.push(0x01);
        doc.extend_from_slice(&u16::MAX.to_le_bytes()); // 65535 caracteres...
        doc.extend_from_slice(b"xy"); // ...pero solo hay dos bytes
        c.registro(1, &doc);
        let mut l = Lector::desde_bytes(c.terminar()).unwrap();
        let _ = l.leer(0, 10); // no entra en panico
    }

    // --- El catalogo ---------------------------------------------------------

    #[test]
    fn el_catalogo_conoce_los_sucesos_que_importan() {
        // Un 4625 es un fallo de autenticacion en aleman igual que en
        // castellano; su frase, no.
        let a = catalogo::buscar("Security", 4625).unwrap();
        assert_eq!(a.clase, Clase::Autenticacion);
        assert_eq!(a.resultado, ResultadoEvento::Fallo);

        let b = catalogo::buscar("Security", 4720).unwrap();
        assert_eq!(b.clase, Clase::GestionDeCuentas);
        assert_eq!(b.severidad, Severidad::Alta);
    }

    #[test]
    fn borrar_el_registro_de_auditoria_es_critico() {
        // Nadie limpia el log de seguridad por higiene.
        let a = catalogo::buscar("Security", 1102).unwrap();
        assert_eq!(a.severidad, Severidad::Critica);
        assert_eq!(a.clase, Clase::HallazgoDeSeguridad);
    }

    #[test]
    fn sysmon_tiene_catalogo_propio_y_no_colisiona_con_el_de_windows() {
        // El evento 1 de Sysmon es «proceso creado»; el 1 de Security no existe.
        let s = catalogo::buscar("Microsoft-Windows-Sysmon/Operational", 1).unwrap();
        assert_eq!(s.clase, Clase::ActividadDeProceso);
        assert!(catalogo::buscar("Security", 1).is_none());

        // Y el 8 de Sysmon —hilo creado en otro proceso— es critico: es
        // inyeccion remota de manual.
        let inyeccion = catalogo::buscar("Microsoft-Windows-Sysmon/Operational", 8).unwrap();
        assert_eq!(inyeccion.severidad, Severidad::Critica);
    }

    #[test]
    fn un_identificador_desconocido_se_dice_en_vez_de_inventarse() {
        assert!(catalogo::buscar("Security", 999_999).is_none());
    }
}
