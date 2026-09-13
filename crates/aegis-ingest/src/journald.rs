//! journald: lectura del diario binario de systemd, con cursor.
//!
//! # Por que se lee el formato binario y no se llama a `journalctl`
//!
//! Llamar a `journalctl -o json -f` y leer su salida es lo que hace casi todo el
//! mundo, y tiene tres problemas que en un EDR no son detalles:
//!
//! 1. **Un proceso hijo por maquina, permanente.** En una flota de cien mil
//!    endpoints eso es cien mil procesos mas, con su memoria y su supervision, y
//!    un punto de fallo que no se controla.
//! 2. **El texto de `journalctl` es un contrato que nadie prometio.** Cambia
//!    entre versiones de systemd, y el recolector se entera cuando deja de
//!    clasificar.
//! 3. **Un atacante con permiso para ejecutar puede interponerse.** Un
//!    `journalctl` falso en el `PATH` del agente le deja decidir que ve el EDR.
//!    Leer el fichero es leer el fichero.
//!
//! # El formato, y lo que se valida de el
//!
//! Un fichero de diario es una cabecera y despues una arena de **objetos** con
//! desplazamiento absoluto. Los tipos que importan aqui: la **entrada**
//! (`ENTRY`), que es un registro con su hora y una lista de referencias; el
//! **dato** (`DATA`), que es un `CLAVE=valor`; y el **vector de entradas**
//! (`ENTRY_ARRAY`), que encadena todas las entradas del fichero.
//!
//! El fichero lo escribe un servicio del sistema, pero se lee **como entrada
//! hostil de todas formas**: un atacante con permiso de escritura en
//! `/var/log/journal` —o simplemente un fichero corrupto por un corte de luz—
//! puede dejar desplazamientos que apuntan a cualquier sitio, tamanos absurdos y
//! cadenas de vectores que se muerden la cola. Aqui **todo desplazamiento se
//! valida contra el tamano real del fichero antes de usarse**, ninguna reserva
//! sale de un tamano declarado, y el recorrido de cadenas tiene tope.
//!
//! # El muro de la compresion, declarado
//!
//! systemd comprime los campos que pasan de cierto tamano. El formato admite
//! tres algoritmos y aqui se descomprime **LZ4**, que esta implementado en este
//! mismo fichero —son cuarenta lineas de LZ77 y no anade ninguna dependencia—.
//!
//! **XZ y ZSTD no se descomprimen.** Meter un descompresor de zstd en el agente
//! significa anadir varios miles de lineas de analisis de formato binario al
//! proceso mas privilegiado de la maquina, y eso es una decision que se toma a
//! proposito o no se toma. El campo afectado **no desaparece en silencio**: se
//! entrega marcado con el algoritmo que haria falta y se cuenta, asi que la
//! cifra de cobertura lo refleja. Y como systemd solo comprime por encima de
//! 512 bytes, lo que se pierde son trazas largas, no las claves con las que se
//! clasifica.

use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use crate::error::{ErrorIngesta, Resultado};
use crate::esquema::{recortar, MAX_CAMPO, MAX_MENSAJE};

/// Firma de un fichero de diario de systemd.
pub const FIRMA: &[u8; 8] = b"LPKSHHRH";

/// Bytes de la cabecera de un objeto: tipo, banderas, reservado y tamano.
const CABECERA_OBJETO: u64 = 16;

/// Tamano minimo de la cabecera del fichero que se sabe leer.
const MIN_CABECERA: u64 = 240;

/// Tipos de objeto.
const TIPO_DATA: u8 = 1;
const TIPO_ENTRY: u8 = 3;
const TIPO_ENTRY_ARRAY: u8 = 6;

/// Banderas de objeto: el algoritmo con el que se comprimio su carga.
const COMP_XZ: u8 = 1;
const COMP_LZ4: u8 = 2;
const COMP_ZSTD: u8 = 4;

/// Bandera incompatible `COMPACT`: los desplazamientos de los vectores y de los
/// elementos de entrada pasan de 64 a 32 bits.
///
/// Leerla mal desplaza TODO el recorrido y produce basura con aspecto de datos,
/// que es peor que un error: no se nota.
const INCOMPATIBLE_COMPACT: u32 = 1 << 4;

/// Vectores de entradas que se recorren como maximo.
///
/// Una cadena que se muerde la cola —por corrupcion o a proposito— dejaria el
/// recolector girando para siempre sobre el mismo fichero, sin leer nada nuevo y
/// sin fallar. Es la forma mas barata de cegar la ingesta de una maquina.
pub const MAX_VECTORES: usize = 65_536;

/// Campos por entrada que se conservan como maximo.
pub const MAX_CAMPOS_ENTRADA: usize = 128;

/// Bytes maximos de la carga de un objeto que se lee.
pub const MAX_CARGA: usize = 1024 * 1024;

/// Una entrada del diario, ya resuelta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entrada {
    /// Numero de secuencia dentro de su flujo.
    pub seqnum: u64,
    /// Identificador del flujo de secuencia, en hexadecimal.
    pub seqnum_id: String,
    /// Identificador de arranque, en hexadecimal.
    pub boot_id: String,
    /// Hora del reloj de pared, en nanosegundos Unix.
    pub realtime_ns: u64,
    /// Hora monotona desde el arranque, en nanosegundos.
    pub monotonic_ns: u64,
    /// Resumen de los datos, tal y como lo guarda systemd.
    pub xor_hash: u64,
    /// Desplazamiento del objeto en el fichero: es lo que hace el ancla estable.
    pub desplazamiento: u64,
    /// Los campos `CLAVE=valor`.
    pub campos: BTreeMap<String, String>,
    /// Campos que venian comprimidos con un algoritmo que no se descomprime.
    ///
    /// Se declaran en vez de desaparecer: ver el encabezado del modulo.
    pub sin_descomprimir: Vec<String>,
}

impl Entrada {
    /// Cursor en el formato de systemd, compatible con `journalctl --cursor`.
    ///
    /// Se emite en ese formato a proposito: un operador puede pegar el cursor
    /// del punto de control en `journalctl --after-cursor` y ver exactamente lo
    /// mismo que va a leer el agente. Un formato propio obligaria a creerse lo
    /// que diga el panel.
    #[must_use]
    pub fn cursor(&self) -> String {
        format!(
            "s={};i={:x};b={};m={:x};t={:x};x={:x}",
            self.seqnum_id,
            self.seqnum,
            self.boot_id,
            self.monotonic_ns / 1000,
            self.realtime_ns / 1000,
            self.xor_hash
        )
    }

    /// Ancla estable de esta entrada.
    ///
    /// Lleva el identificador de flujo y el numero de secuencia, no el
    /// desplazamiento: systemd puede rotar el fichero y el mismo registro
    /// aparecer en otro sitio, pero su secuencia no cambia.
    #[must_use]
    pub fn ancla(&self) -> String {
        format!("journald:{}:{}", self.seqnum_id, self.seqnum)
    }

    /// Quien lo escribio.
    #[must_use]
    pub fn productor(&self) -> String {
        for clave in ["SYSLOG_IDENTIFIER", "_COMM", "UNIT", "_SYSTEMD_UNIT"] {
            if let Some(v) = self.campos.get(clave) {
                if !v.is_empty() {
                    return v.clone();
                }
            }
        }
        "desconocido".to_string()
    }

    /// El texto del registro.
    #[must_use]
    pub fn mensaje(&self) -> String {
        recortar(
            self.campos.get("MESSAGE").map_or("", String::as_str),
            MAX_MENSAJE,
        )
    }
}

/// Contadores del lector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Contadores {
    /// Entradas entregadas.
    pub entradas: u64,
    /// Objetos descartados por apuntar fuera del fichero o tener tamano absurdo.
    pub objetos_invalidos: u64,
    /// Campos que venian con XZ o ZSTD.
    pub sin_descomprimir: u64,
    /// Campos descomprimidos con LZ4.
    pub lz4: u64,
    /// Vectores de entradas recorridos.
    pub vectores: u64,
}

/// Lector de un fichero de diario.
#[derive(Debug)]
pub struct Lector {
    ruta: PathBuf,
    fichero: File,
    tamano: u64,
    compacto: bool,
    seqnum_id: String,
    entry_array_offset: u64,
    /// La cadena de vectores, ya recorrida y validada.
    ///
    /// # Por que se cachea y no se recorre cada vez
    ///
    /// Resolver la entrada `n` recorriendo la cadena desde el principio cuesta
    /// O(n) por entrada y O(n^2) por fichero. Un diario de doscientas mil
    /// entradas —lo normal en un servidor— serian miles de millones de lecturas
    /// de ocho bytes. Se recorre una vez, se comprueba que no se muerde la cola,
    /// y despues cada entrada se localiza con una busqueda binaria.
    cadena: Vec<Eslabon>,
    /// Entradas totales de la cadena.
    total: u64,
    /// Por donde va: indice global dentro de la cadena de vectores.
    indice: u64,
    contadores: Contadores,
}

/// Un vector de la cadena, con cuantas entradas lleva acumuladas por delante.
#[derive(Debug, Clone, Copy)]
struct Eslabon {
    /// Desplazamiento del objeto en el fichero.
    vector: u64,
    /// Indice global de su primera entrada.
    base: u64,
    /// Cuantas entradas caben en el.
    n: u64,
}

impl Lector {
    /// Abre un fichero de diario.
    pub fn abrir(ruta: impl Into<PathBuf>) -> Resultado<Lector> {
        let ruta = ruta.into();
        let fichero = File::open(&ruta)
            .map_err(|e| ErrorIngesta::es(format!("abriendo {}", ruta.display()), e))?;
        let meta = fichero
            .metadata()
            .map_err(|e| ErrorIngesta::es("consultando el diario", e))?;
        let tamano = meta.len();
        if tamano < MIN_CABECERA {
            return Err(ErrorIngesta::Malformado {
                origen: "journald",
                motivo: format!("fichero de {tamano} bytes: no cabe ni la cabecera"),
            });
        }

        let mut cab = vec![0u8; usize::try_from(MIN_CABECERA).unwrap_or(240)];
        fichero
            .read_exact_at(&mut cab, 0)
            .map_err(|e| ErrorIngesta::es("leyendo la cabecera del diario", e))?;
        if &cab[0..8] != FIRMA {
            return Err(ErrorIngesta::Malformado {
                origen: "journald",
                motivo: "firma desconocida".into(),
            });
        }
        let incompatibles = u32(&cab, 12);
        let compacto = incompatibles & INCOMPATIBLE_COMPACT != 0;
        // Las banderas incompatibles que no se conocen tienen ese nombre por
        // algo: seguir leyendo produciria campos desplazados con aspecto de
        // datos. Se para.
        let conocidas = INCOMPATIBLE_COMPACT | 1 | 2 | 4 | 8;
        if incompatibles & !conocidas != 0 {
            return Err(ErrorIngesta::Malformado {
                origen: "journald",
                motivo: format!("banderas incompatibles desconocidas: {incompatibles:#x}"),
            });
        }

        // seqnum_id esta en el desplazamiento 48 (tras file_id y machine_id...);
        // el orden de la cabecera de systemd es: firma(8) compat(4) incompat(4)
        // estado(1) reservado(7) file_id(16) machine_id(16) boot/tail_entry(16)
        // seqnum_id(16) header_size(8) arena_size(8) ...
        let seqnum_id = hex(&cab[56..72]);
        let header_size = u64x(&cab, 88);
        let entry_array_offset = u64x(&cab, 160);
        if header_size < CABECERA_OBJETO || header_size > tamano {
            return Err(ErrorIngesta::Malformado {
                origen: "journald",
                motivo: format!("cabecera de {header_size} bytes en un fichero de {tamano}"),
            });
        }

        let mut lector = Lector {
            ruta,
            fichero,
            tamano,
            compacto,
            seqnum_id,
            entry_array_offset,
            cadena: Vec::new(),
            total: 0,
            indice: 0,
            contadores: Contadores::default(),
        };
        lector.recorrer_cadena()?;
        Ok(lector)
    }

    /// Ruta del fichero.
    #[must_use]
    pub fn ruta(&self) -> &Path {
        &self.ruta
    }

    /// Si el fichero usa desplazamientos de 32 bits.
    #[must_use]
    pub fn compacto(&self) -> bool {
        self.compacto
    }

    /// Identificador del flujo de secuencia.
    #[must_use]
    pub fn seqnum_id(&self) -> &str {
        &self.seqnum_id
    }

    /// Contadores acumulados.
    #[must_use]
    pub fn contadores(&self) -> Contadores {
        self.contadores
    }

    /// Posiciona el lector justo despues de la entrada de un cursor.
    ///
    /// Se busca por numero de secuencia y no por desplazamiento: un diario
    /// rotado deja el mismo registro en otro sitio, y reanudar por
    /// desplazamiento leeria basura o saltaria un tramo.
    pub fn situar_tras_cursor(&mut self, cursor: &str) -> Resultado<bool> {
        let Some(seqnum) = campo_cursor(cursor, "i=") else {
            return Err(ErrorIngesta::Malformado {
                origen: "journald",
                motivo: "cursor sin numero de secuencia".into(),
            });
        };
        let objetivo = u64::from_str_radix(&seqnum, 16).map_err(|_| ErrorIngesta::Malformado {
            origen: "journald",
            motivo: "numero de secuencia ilegible en el cursor".into(),
        })?;
        self.indice = 0;
        let mut visto = false;
        // Busqueda lineal: los ficheros de diario estan ordenados por secuencia,
        // asi que se para en cuanto se pasa. Una busqueda binaria sobre la
        // cadena de vectores seria mas rapida, pero la cadena la escribe alguien
        // que puede mentir sobre el orden y una binaria sobre datos no ordenados
        // salta tramos en silencio.
        loop {
            let Some(entrada) = self.siguiente_en(self.indice)? else {
                break;
            };
            // Se para ANTES de avanzar sobre una entrada posterior al cursor: el
            // cursor dice «ya entregue hasta aqui», asi que lo que viene despues
            // todavia no se ha entregado. Avanzar primero y comprobar despues se
            // salta exactamente una entrada, y ese salto no deja rastro.
            if entrada.seqnum > objetivo {
                break;
            }
            self.indice += 1;
            if entrada.seqnum == objetivo {
                visto = true;
                break;
            }
        }
        Ok(visto)
    }

    /// Lee hasta `maximo` entradas a partir de donde este.
    pub fn leer(&mut self, maximo: usize) -> Resultado<Vec<Entrada>> {
        let mut salida = Vec::new();
        while salida.len() < maximo {
            match self.siguiente_en(self.indice)? {
                Some(e) => {
                    self.indice += 1;
                    self.contadores.entradas += 1;
                    salida.push(e);
                }
                None => break,
            }
        }
        Ok(salida)
    }

    /// Resuelve la entrada que ocupa la posicion `indice` de la cadena.
    fn siguiente_en(&mut self, indice: u64) -> Resultado<Option<Entrada>> {
        let Some(desplazamiento) = self.desplazamiento_de(indice)? else {
            return Ok(None);
        };
        self.entrada_en(desplazamiento)
    }

    /// Recorre la cadena de vectores una vez y la valida.
    ///
    /// Un fichero preparado —o corrupto por un corte de luz— puede tener una
    /// cadena que se muerde la cola. Sin la comprobacion, el recolector gira
    /// sobre el mismo fichero entregando las mismas entradas para siempre: no
    /// falla, no avanza, y nadie se entera. Es la forma mas barata de cegar la
    /// ingesta de una maquina.
    fn recorrer_cadena(&mut self) -> Resultado<()> {
        let mut vistos = std::collections::BTreeSet::new();
        let mut vector = self.entry_array_offset;
        let ancho = if self.compacto { 4u64 } else { 8u64 };
        let mut base = 0u64;
        while vector != 0 {
            if self.cadena.len() >= MAX_VECTORES {
                return Err(ErrorIngesta::Malformado {
                    origen: "journald",
                    motivo: format!("cadena de mas de {MAX_VECTORES} eslabones"),
                });
            }
            if !vistos.insert(vector) {
                return Err(ErrorIngesta::Malformado {
                    origen: "journald",
                    motivo: format!("la cadena de vectores se muerde la cola en {vector}"),
                });
            }
            let Some((tipo, tamano)) = self.cabecera_objeto(vector)? else {
                self.contadores.objetos_invalidos += 1;
                break;
            };
            if tipo != TIPO_ENTRY_ARRAY {
                self.contadores.objetos_invalidos += 1;
                break;
            }
            let cuerpo = tamano.saturating_sub(CABECERA_OBJETO);
            if cuerpo < 8 {
                self.contadores.objetos_invalidos += 1;
                break;
            }
            let n = (cuerpo - 8) / ancho;
            let siguiente = self.leer_u64(vector + CABECERA_OBJETO)?;
            self.cadena.push(Eslabon { vector, base, n });
            self.contadores.vectores += 1;
            base += n;
            vector = siguiente;
        }
        self.total = base;
        Ok(())
    }

    /// Desplazamiento de la entrada numero `indice`, con busqueda binaria.
    fn desplazamiento_de(&mut self, indice: u64) -> Resultado<Option<u64>> {
        if indice >= self.total {
            return Ok(None);
        }
        let pos = self.cadena.partition_point(|e| e.base + e.n <= indice);
        let Some(e) = self.cadena.get(pos).copied() else {
            return Ok(None);
        };
        let ancho = if self.compacto { 4u64 } else { 8u64 };
        let en = e.vector + CABECERA_OBJETO + 8 + (indice - e.base) * ancho;
        let valor = if self.compacto {
            u64::from(self.leer_u32(en)?)
        } else {
            self.leer_u64(en)?
        };
        // Un cero dentro del vector es un hueco: systemd los deja al reservar
        // por adelantado. No es un objeto en el desplazamiento cero.
        if valor == 0 {
            return Ok(None);
        }
        Ok(Some(valor))
    }

    /// Lee y resuelve un objeto de entrada.
    fn entrada_en(&mut self, desplazamiento: u64) -> Resultado<Option<Entrada>> {
        let Some((tipo, tamano)) = self.cabecera_objeto(desplazamiento)? else {
            self.contadores.objetos_invalidos += 1;
            return Ok(None);
        };
        if tipo != TIPO_ENTRY {
            self.contadores.objetos_invalidos += 1;
            return Ok(None);
        }
        // seqnum(8) realtime(8) monotonic(8) boot_id(16) xor_hash(8) = 48
        const FIJO: u64 = 48;
        if tamano < CABECERA_OBJETO + FIJO {
            self.contadores.objetos_invalidos += 1;
            return Ok(None);
        }
        let base = desplazamiento + CABECERA_OBJETO;
        let seqnum = self.leer_u64(base)?;
        let realtime_us = self.leer_u64(base + 8)?;
        let monotonic_us = self.leer_u64(base + 16)?;
        let mut boot = [0u8; 16];
        self.leer_en(base + 24, &mut boot)?;
        let xor_hash = self.leer_u64(base + 40)?;

        let ancho = if self.compacto { 4u64 } else { 16u64 };
        let n = (tamano - CABECERA_OBJETO - FIJO) / ancho;
        let mut campos = BTreeMap::new();
        let mut sin_descomprimir = Vec::new();
        for i in 0..n.min(MAX_CAMPOS_ENTRADA as u64) {
            let en = base + FIJO + i * ancho;
            let ref_dato = if self.compacto {
                u64::from(self.leer_u32(en)?)
            } else {
                self.leer_u64(en)?
            };
            if ref_dato == 0 {
                continue;
            }
            match self.dato_en(ref_dato)? {
                Dato::Texto(t) => {
                    if let Some((k, v)) = t.split_once('=') {
                        campos.insert(recortar(k, 128), recortar(v, MAX_CAMPO));
                    }
                }
                Dato::Comprimido(alg) => {
                    self.contadores.sin_descomprimir += 1;
                    sin_descomprimir.push(alg.to_string());
                }
                Dato::Invalido => {
                    self.contadores.objetos_invalidos += 1;
                }
            }
        }

        Ok(Some(Entrada {
            seqnum,
            seqnum_id: self.seqnum_id.clone(),
            boot_id: hex(&boot),
            // systemd guarda las horas en MICROsegundos.
            realtime_ns: realtime_us.saturating_mul(1000),
            monotonic_ns: monotonic_us.saturating_mul(1000),
            xor_hash,
            desplazamiento,
            campos,
            sin_descomprimir,
        }))
    }

    /// Lee un objeto de dato y devuelve su `CLAVE=valor`.
    fn dato_en(&mut self, desplazamiento: u64) -> Resultado<Dato> {
        let Some((tipo, tamano)) = self.cabecera_objeto(desplazamiento)? else {
            return Ok(Dato::Invalido);
        };
        if tipo != TIPO_DATA {
            return Ok(Dato::Invalido);
        }
        let mut banderas = [0u8; 1];
        self.leer_en(desplazamiento + 1, &mut banderas)?;
        // hash(8) next_hash(8) next_field(8) entry(8) entry_array(8) n_entries(8)
        // = 48 en formato normal; en compacto los dos ultimos campos son de 32
        // bits y suman 40.
        let fijo: u64 = if self.compacto { 40 } else { 48 };
        if tamano < CABECERA_OBJETO + fijo {
            return Ok(Dato::Invalido);
        }
        let carga = tamano - CABECERA_OBJETO - fijo;
        if carga == 0 || carga > MAX_CARGA as u64 {
            return Ok(Dato::Invalido);
        }
        let alg = banderas[0] & (COMP_XZ | COMP_LZ4 | COMP_ZSTD);
        let mut bruto = vec![0u8; usize::try_from(carga).unwrap_or(0)];
        self.leer_en(desplazamiento + CABECERA_OBJETO + fijo, &mut bruto)?;

        match alg {
            0 => Ok(Dato::Texto(String::from_utf8_lossy(&bruto).into_owned())),
            COMP_LZ4 => match descomprimir_lz4(&bruto) {
                Some(claro) => {
                    self.contadores.lz4 += 1;
                    Ok(Dato::Texto(String::from_utf8_lossy(&claro).into_owned()))
                }
                None => Ok(Dato::Invalido),
            },
            COMP_XZ => Ok(Dato::Comprimido("xz")),
            COMP_ZSTD => Ok(Dato::Comprimido("zstd")),
            _ => Ok(Dato::Invalido),
        }
    }

    /// Cabecera de un objeto, validando que cabe en el fichero.
    ///
    /// **Todo** desplazamiento pasa por aqui. Es la unica razon por la que un
    /// fichero corrupto o preparado no puede hacer que se lea fuera del fichero
    /// ni reservar por un tamano inventado.
    fn cabecera_objeto(&self, desplazamiento: u64) -> Resultado<Option<(u8, u64)>> {
        if desplazamiento < MIN_CABECERA
            || desplazamiento
                .checked_add(CABECERA_OBJETO)
                .is_none_or(|fin| fin > self.tamano)
        {
            return Ok(None);
        }
        let mut cab = [0u8; 16];
        self.leer_en(desplazamiento, &mut cab)?;
        let tipo = cab[0];
        let tamano = u64x(&cab, 8);
        if tamano < CABECERA_OBJETO
            || desplazamiento
                .checked_add(tamano)
                .is_none_or(|fin| fin > self.tamano)
        {
            return Ok(None);
        }
        Ok(Some((tipo, tamano)))
    }

    fn leer_en(&self, desplazamiento: u64, destino: &mut [u8]) -> Resultado<()> {
        let fin = desplazamiento
            .checked_add(destino.len() as u64)
            .ok_or_else(|| ErrorIngesta::Malformado {
                origen: "journald",
                motivo: "desplazamiento que desborda".into(),
            })?;
        if fin > self.tamano {
            return Err(ErrorIngesta::Malformado {
                origen: "journald",
                motivo: format!("lectura hasta {fin} en un fichero de {}", self.tamano),
            });
        }
        self.fichero
            .read_exact_at(destino, desplazamiento)
            .map_err(|e| ErrorIngesta::es("leyendo el diario", e))
    }

    fn leer_u64(&self, desplazamiento: u64) -> Resultado<u64> {
        let mut b = [0u8; 8];
        self.leer_en(desplazamiento, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn leer_u32(&self, desplazamiento: u64) -> Resultado<u32> {
        let mut b = [0u8; 4];
        self.leer_en(desplazamiento, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }
}

/// Lo que puede salir de un objeto de dato.
enum Dato {
    /// Un `CLAVE=valor` legible.
    Texto(String),
    /// Venia comprimido con un algoritmo que no se descomprime aqui.
    Comprimido(&'static str),
    /// No se pudo usar.
    Invalido,
}

/// Descomprime un bloque LZ4 tal y como lo escribe systemd.
///
/// # El formato, entero
///
/// systemd antepone el tamano descomprimido en ocho bytes little-endian y
/// despues escribe un **bloque LZ4 crudo**, sin las cabeceras del formato de
/// marco. El bloque es LZ77 puro y se lee asi:
///
/// ```text
///   token = un byte: 4 bits altos = literales, 4 bits bajos = longitud de copia
///   si literales == 15: se suman bytes de 255 hasta uno que no lo sea
///   [literales] bytes tal cual
///   offset: dos bytes little-endian, distancia hacia atras en la salida
///   si copia == 15: se suman bytes igual
///   longitud de copia = copia + 4
/// ```
///
/// Esta escrito aqui, y no traido de una biblioteca, porque son cuarenta lineas
/// y la alternativa es meter una dependencia mas en el proceso mas privilegiado
/// de la maquina para leer un fichero del sistema.
///
/// **La copia es byte a byte a proposito.** LZ4 permite que la distancia sea
/// menor que la longitud —es como codifica una repeticion— y copiar en bloque
/// daria un resultado distinto. Es el error clasico de las implementaciones a
/// mano y produce datos corruptos solo en algunas entradas.
#[must_use]
pub fn descomprimir_lz4(bruto: &[u8]) -> Option<Vec<u8>> {
    if bruto.len() < 8 {
        return None;
    }
    let declarado = u64::from_le_bytes(bruto[0..8].try_into().ok()?);
    // El tamano declarado lo escribe el fichero: no se reserva por el, se acota.
    if declarado > MAX_CARGA as u64 {
        return None;
    }
    let esperado = usize::try_from(declarado).ok()?;
    let entrada = &bruto[8..];
    let mut salida: Vec<u8> = Vec::with_capacity(esperado.min(64 * 1024));
    let mut i = 0usize;

    while i < entrada.len() {
        let token = entrada[i];
        i += 1;
        let mut literales = usize::from(token >> 4);
        if literales == 15 {
            loop {
                let b = *entrada.get(i)?;
                i += 1;
                literales = literales.checked_add(usize::from(b))?;
                if b != 255 {
                    break;
                }
                if literales > esperado {
                    return None;
                }
            }
        }
        if literales > 0 {
            let fin = i.checked_add(literales)?;
            if fin > entrada.len() || salida.len() + literales > esperado {
                return None;
            }
            salida.extend_from_slice(&entrada[i..fin]);
            i = fin;
        }
        if i >= entrada.len() {
            break; // el ultimo bloque es solo literales
        }
        if i + 2 > entrada.len() {
            return None;
        }
        let distancia = usize::from(u16::from_le_bytes([entrada[i], entrada[i + 1]]));
        i += 2;
        if distancia == 0 || distancia > salida.len() {
            return None;
        }
        let mut copia = usize::from(token & 0x0f);
        if copia == 15 {
            loop {
                let b = *entrada.get(i)?;
                i += 1;
                copia = copia.checked_add(usize::from(b))?;
                if b != 255 {
                    break;
                }
                if copia > esperado {
                    return None;
                }
            }
        }
        copia += 4;
        if salida.len() + copia > esperado {
            return None;
        }
        let inicio = salida.len() - distancia;
        for k in 0..copia {
            let b = salida[inicio + k];
            salida.push(b);
        }
    }
    if salida.len() != esperado {
        return None;
    }
    Some(salida)
}

/// Busca los ficheros de diario de una maquina.
///
/// Mira primero el diario persistente y luego el volatil. El orden importa: en
/// una maquina sin `/var/log/journal` el diario vive en `/run` y **se pierde al
/// reiniciar**, lo cual es una observacion de seguridad en si misma —un
/// atacante que reinicie se lleva el log por delante— y por eso se distingue.
pub fn descubrir(raiz: &Path) -> Vec<PathBuf> {
    let mut salida = Vec::new();
    for base in ["var/log/journal", "run/log/journal"] {
        let dir = raiz.join(base);
        let Ok(maquinas) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut encontrados = Vec::new();
        for maquina in maquinas.flatten() {
            let Ok(ficheros) = std::fs::read_dir(maquina.path()) else {
                continue;
            };
            for f in ficheros.flatten() {
                let p = f.path();
                if p.extension().is_some_and(|e| e == "journal") {
                    encontrados.push(p);
                }
            }
        }
        // Orden estable: sin esto el mismo sistema produce lecturas en distinto
        // orden segun lo que devuelva el sistema de ficheros, y el determinismo
        // de la normalizacion deja de poderse comprobar.
        encontrados.sort();
        salida.extend(encontrados);
    }
    salida
}

fn campo_cursor(cursor: &str, clave: &str) -> Option<String> {
    cursor
        .split(';')
        .find_map(|p| p.trim().strip_prefix(clave))
        .map(str::to_string)
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn u32(b: &[u8], en: usize) -> u32 {
    u32::from_le_bytes([b[en], b[en + 1], b[en + 2], b[en + 3]])
}

fn u64x(b: &[u8], en: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[en..en + 8]);
    u64::from_le_bytes(a)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::io::Write;

    // Las pruebas construyen ficheros de diario BYTE A BYTE con el formato real
    // de systemd. Es la unica forma de probar un analizador binario sin depender
    // de que la maquina de integracion tenga systemd, y ademas permite fabricar
    // los ficheros hostiles que ningun systemd generaria.

    struct Constructor {
        bytes: Vec<u8>,
        compacto: bool,
    }

    impl Constructor {
        fn nuevo(compacto: bool) -> Constructor {
            let mut bytes = vec![0u8; usize::try_from(MIN_CABECERA).unwrap()];
            bytes[0..8].copy_from_slice(FIRMA);
            if compacto {
                bytes[12..16].copy_from_slice(&INCOMPATIBLE_COMPACT.to_le_bytes());
            }
            // seqnum_id en 56..72
            for (i, b) in bytes[56..72].iter_mut().enumerate() {
                *b = u8::try_from(i).unwrap();
            }
            // header_size en 88
            bytes[88..96].copy_from_slice(&MIN_CABECERA.to_le_bytes());
            Constructor { bytes, compacto }
        }

        fn alinear(&mut self) {
            while !self.bytes.len().is_multiple_of(8) {
                self.bytes.push(0);
            }
        }

        /// Escribe un objeto DATA con `clave=valor` y devuelve su desplazamiento.
        fn dato(&mut self, texto: &str) -> u64 {
            self.alinear();
            let en = self.bytes.len() as u64;
            let fijo: usize = if self.compacto { 40 } else { 48 };
            let tamano = CABECERA_OBJETO + fijo as u64 + texto.len() as u64;
            self.bytes.push(TIPO_DATA);
            self.bytes.push(0); // banderas
            self.bytes.extend_from_slice(&[0u8; 6]);
            self.bytes.extend_from_slice(&tamano.to_le_bytes());
            self.bytes.extend(std::iter::repeat_n(0u8, fijo));
            self.bytes.extend_from_slice(texto.as_bytes());
            en
        }

        /// Escribe un objeto DATA comprimido con LZ4.
        fn dato_lz4(&mut self, texto: &str) -> u64 {
            self.alinear();
            let en = self.bytes.len() as u64;
            let comprimido = comprimir_lz4_solo_literales(texto.as_bytes());
            let fijo: usize = if self.compacto { 40 } else { 48 };
            let tamano = CABECERA_OBJETO + fijo as u64 + comprimido.len() as u64;
            self.bytes.push(TIPO_DATA);
            self.bytes.push(COMP_LZ4);
            self.bytes.extend_from_slice(&[0u8; 6]);
            self.bytes.extend_from_slice(&tamano.to_le_bytes());
            self.bytes.extend(std::iter::repeat_n(0u8, fijo));
            self.bytes.extend_from_slice(&comprimido);
            en
        }

        fn dato_zstd(&mut self, cuantos: usize) -> u64 {
            self.alinear();
            let en = self.bytes.len() as u64;
            let fijo: usize = if self.compacto { 40 } else { 48 };
            let tamano = CABECERA_OBJETO + fijo as u64 + cuantos as u64;
            self.bytes.push(TIPO_DATA);
            self.bytes.push(COMP_ZSTD);
            self.bytes.extend_from_slice(&[0u8; 6]);
            self.bytes.extend_from_slice(&tamano.to_le_bytes());
            self.bytes.extend(std::iter::repeat_n(0u8, fijo));
            self.bytes.extend(std::iter::repeat_n(0xABu8, cuantos));
            en
        }

        fn entrada(&mut self, seqnum: u64, realtime_us: u64, datos: &[u64]) -> u64 {
            self.alinear();
            let en = self.bytes.len() as u64;
            let ancho: usize = if self.compacto { 4 } else { 16 };
            let tamano = CABECERA_OBJETO + 48 + (datos.len() * ancho) as u64;
            self.bytes.push(TIPO_ENTRY);
            self.bytes.push(0);
            self.bytes.extend_from_slice(&[0u8; 6]);
            self.bytes.extend_from_slice(&tamano.to_le_bytes());
            self.bytes.extend_from_slice(&seqnum.to_le_bytes());
            self.bytes.extend_from_slice(&realtime_us.to_le_bytes());
            self.bytes
                .extend_from_slice(&(realtime_us / 2).to_le_bytes());
            self.bytes.extend_from_slice(&[0x77u8; 16]); // boot_id
            self.bytes.extend_from_slice(&0xdeadbeefu64.to_le_bytes());
            for d in datos {
                if self.compacto {
                    self.bytes
                        .extend_from_slice(&u32::try_from(*d).unwrap().to_le_bytes());
                } else {
                    self.bytes.extend_from_slice(&d.to_le_bytes());
                    self.bytes.extend_from_slice(&0u64.to_le_bytes()); // hash
                }
            }
            en
        }

        fn vector(&mut self, siguiente: u64, entradas: &[u64]) -> u64 {
            self.alinear();
            let en = self.bytes.len() as u64;
            let ancho: usize = if self.compacto { 4 } else { 8 };
            let tamano = CABECERA_OBJETO + 8 + (entradas.len() * ancho) as u64;
            self.bytes.push(TIPO_ENTRY_ARRAY);
            self.bytes.push(0);
            self.bytes.extend_from_slice(&[0u8; 6]);
            self.bytes.extend_from_slice(&tamano.to_le_bytes());
            self.bytes.extend_from_slice(&siguiente.to_le_bytes());
            for e in entradas {
                if self.compacto {
                    self.bytes
                        .extend_from_slice(&u32::try_from(*e).unwrap().to_le_bytes());
                } else {
                    self.bytes.extend_from_slice(&e.to_le_bytes());
                }
            }
            en
        }

        fn raiz(&mut self, vector: u64) {
            self.bytes[160..168].copy_from_slice(&vector.to_le_bytes());
        }

        fn guardar(&self, dir: &Path, nombre: &str) -> PathBuf {
            let p = dir.join(nombre);
            let mut f = File::create(&p).unwrap();
            f.write_all(&self.bytes).unwrap();
            p
        }
    }

    /// LZ4 de una sola secuencia de literales.
    ///
    /// Es el unico bloque de solo literales que LZ4 admite: una secuencia sin
    /// copia solo puede ser la ULTIMA del bloque, porque detras de cualquier
    /// otra el formato exige el desplazamiento de dos bytes. Partirlo en varias
    /// —que es lo intuitivo— produce un bloque invalido que ningun
    /// descompresor correcto acepta.
    fn comprimir_lz4_solo_literales(claro: &[u8]) -> Vec<u8> {
        let mut v = (claro.len() as u64).to_le_bytes().to_vec();
        let n = claro.len();
        if n < 15 {
            v.push(u8::try_from(n).unwrap() << 4);
        } else {
            v.push(0xf0);
            let mut sobra = n - 15;
            while sobra >= 255 {
                v.push(255);
                sobra -= 255;
            }
            v.push(u8::try_from(sobra).unwrap());
        }
        v.extend_from_slice(claro);
        v
    }

    fn diario_de_prueba(dir: &Path, compacto: bool) -> PathBuf {
        let mut c = Constructor::nuevo(compacto);
        let mut entradas = Vec::new();
        for i in 1..=5u64 {
            let msg = c.dato(&format!("MESSAGE=linea numero {i}"));
            let ident = c.dato("SYSLOG_IDENTIFIER=sshd");
            let pid = c.dato(&format!("_PID={}", 1000 + i));
            entradas.push(c.entrada(i, 1_700_000_000_000_000 + i, &[msg, ident, pid]));
        }
        let v = c.vector(0, &entradas);
        c.raiz(v);
        c.guardar(dir, "system.journal")
    }

    // --- El formato, entero -------------------------------------------------

    #[test]
    fn lee_las_entradas_de_un_diario_completo() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = diario_de_prueba(dir.path(), false);
        let mut l = Lector::abrir(&ruta).unwrap();
        let entradas = l.leer(100).unwrap();
        assert_eq!(entradas.len(), 5);
        assert_eq!(entradas[0].mensaje(), "linea numero 1");
        assert_eq!(entradas[0].productor(), "sshd");
        assert_eq!(entradas[0].campos["_PID"], "1001");
        assert_eq!(entradas[4].seqnum, 5);
        // systemd guarda MICROsegundos; el esquema quiere nanosegundos.
        assert_eq!(entradas[0].realtime_ns, 1_700_000_000_000_001_000);
    }

    #[test]
    fn el_formato_compacto_se_lee_con_desplazamientos_de_32_bits() {
        // Leer la bandera mal desplaza TODO el recorrido y produce basura con
        // aspecto de datos, que es peor que un error: no se nota.
        let dir = tempfile::tempdir().unwrap();
        let ruta = diario_de_prueba(dir.path(), true);
        let mut l = Lector::abrir(&ruta).unwrap();
        assert!(l.compacto());
        let entradas = l.leer(100).unwrap();
        assert_eq!(entradas.len(), 5);
        assert_eq!(entradas[2].mensaje(), "linea numero 3");
        assert_eq!(entradas[2].campos["SYSLOG_IDENTIFIER"], "sshd");
    }

    #[test]
    fn una_cadena_de_varios_vectores_se_recorre_entera() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Constructor::nuevo(false);
        let d = c.dato("MESSAGE=x");
        let mut e = Vec::new();
        for i in 1..=9u64 {
            e.push(c.entrada(i, 1_700_000_000_000_000 + i, &[d]));
        }
        // Tres vectores encadenados de tres entradas cada uno, en orden inverso
        // de escritura porque el ultimo tiene que existir antes de enlazarlo.
        let v3 = c.vector(0, &e[6..9]);
        let v2 = c.vector(v3, &e[3..6]);
        let v1 = c.vector(v2, &e[0..3]);
        c.raiz(v1);
        let ruta = c.guardar(dir.path(), "cadena.journal");

        let mut l = Lector::abrir(&ruta).unwrap();
        let leidas = l.leer(100).unwrap();
        assert_eq!(leidas.len(), 9);
        assert_eq!(leidas[8].seqnum, 9);
        assert!(l.contadores().vectores >= 3);
    }

    #[test]
    fn un_hueco_dentro_de_un_vector_es_el_final_y_no_un_objeto_en_el_cero() {
        // systemd reserva vectores por adelantado y los deja a cero.
        let dir = tempfile::tempdir().unwrap();
        let mut c = Constructor::nuevo(false);
        let d = c.dato("MESSAGE=hola");
        let e1 = c.entrada(1, 1, &[d]);
        let e2 = c.entrada(2, 2, &[d]);
        let v = c.vector(0, &[e1, e2, 0, 0]);
        c.raiz(v);
        let ruta = c.guardar(dir.path(), "hueco.journal");
        let mut l = Lector::abrir(&ruta).unwrap();
        assert_eq!(l.leer(100).unwrap().len(), 2);
    }

    // --- El cursor ----------------------------------------------------------

    #[test]
    fn el_cursor_sale_en_el_formato_de_journalctl() {
        // Un operador tiene que poder pegarlo en `journalctl --after-cursor` y
        // ver exactamente lo mismo que va a leer el agente.
        let dir = tempfile::tempdir().unwrap();
        let ruta = diario_de_prueba(dir.path(), false);
        let mut l = Lector::abrir(&ruta).unwrap();
        let e = l.leer(1).unwrap().remove(0);
        let c = e.cursor();
        assert!(c.starts_with("s="), "{c}");
        for parte in ["i=", "b=", "m=", "t=", "x="] {
            assert!(c.contains(parte), "falta {parte} en {c}");
        }
    }

    #[test]
    fn reanudar_por_cursor_no_repite_ni_salta() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = diario_de_prueba(dir.path(), false);
        let mut l = Lector::abrir(&ruta).unwrap();
        let primeras = l.leer(3).unwrap();
        let cursor = primeras[2].cursor();

        let mut l2 = Lector::abrir(&ruta).unwrap();
        assert!(l2.situar_tras_cursor(&cursor).unwrap());
        let resto = l2.leer(100).unwrap();
        assert_eq!(resto.len(), 2, "faltan o sobran");
        assert_eq!(resto[0].seqnum, 4);
    }

    #[test]
    fn reanudar_por_un_cursor_que_ya_roto_no_salta_un_tramo() {
        // Un diario rotado deja el mismo registro en otro sitio; reanudar por
        // desplazamiento leeria basura o saltaria. Se busca por secuencia.
        let dir = tempfile::tempdir().unwrap();
        let ruta = diario_de_prueba(dir.path(), false);
        let mut l = Lector::abrir(&ruta).unwrap();
        // Cursor de una secuencia que no esta en este fichero (rotado): la 0.
        let hallado = l.situar_tras_cursor("s=abc;i=0;b=x;m=1;t=1;x=1").unwrap();
        assert!(!hallado, "no estaba, y se dice");
        let todas = l.leer(100).unwrap();
        assert_eq!(todas.len(), 5, "se lee todo el fichero, sin saltarse nada");
    }

    #[test]
    fn un_cursor_sin_secuencia_se_rechaza() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = diario_de_prueba(dir.path(), false);
        let mut l = Lector::abrir(&ruta).unwrap();
        assert!(l.situar_tras_cursor("s=abc;b=x").is_err());
    }

    #[test]
    fn el_ancla_lleva_la_secuencia_y_no_el_desplazamiento() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = diario_de_prueba(dir.path(), false);
        let mut l = Lector::abrir(&ruta).unwrap();
        let e = l.leer(1).unwrap().remove(0);
        assert!(e.ancla().starts_with("journald:"));
        assert!(e.ancla().ends_with(":1"));
    }

    // --- La compresion ------------------------------------------------------

    #[test]
    fn un_campo_comprimido_con_lz4_se_lee() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Constructor::nuevo(false);
        let largo = format!("MESSAGE={}", "a".repeat(2000));
        let d = c.dato_lz4(&largo);
        let e = c.entrada(1, 1, &[d]);
        let v = c.vector(0, &[e]);
        c.raiz(v);
        let ruta = c.guardar(dir.path(), "lz4.journal");

        let mut l = Lector::abrir(&ruta).unwrap();
        let entradas = l.leer(10).unwrap();
        assert_eq!(entradas[0].campos["MESSAGE"].len(), 2000);
        assert_eq!(l.contadores().lz4, 1);
    }

    #[test]
    fn el_lz4_con_repeticiones_se_copia_byte_a_byte() {
        // LZ4 permite distancia menor que longitud: es como codifica una
        // repeticion. Copiar en bloque da un resultado distinto, y es el error
        // clasico de las implementaciones a mano.
        // «abcabcabcabc»: 3 literales «abc» y una copia de 9 a distancia 3.
        let mut b = 12u64.to_le_bytes().to_vec();
        b.push(0x35); // 3 literales, copia 5 (+4 = 9)
        b.extend_from_slice(b"abc");
        b.extend_from_slice(&3u16.to_le_bytes());
        assert_eq!(descomprimir_lz4(&b).unwrap(), b"abcabcabcabc");
    }

    #[test]
    fn un_campo_con_zstd_se_declara_en_vez_de_desaparecer() {
        // Se entrega marcado con el algoritmo que haria falta y se cuenta, asi
        // que la cifra de cobertura lo refleja.
        let dir = tempfile::tempdir().unwrap();
        let mut c = Constructor::nuevo(false);
        let bueno = c.dato("SYSLOG_IDENTIFIER=sshd");
        let malo = c.dato_zstd(600);
        let e = c.entrada(1, 1, &[bueno, malo]);
        let v = c.vector(0, &[e]);
        c.raiz(v);
        let ruta = c.guardar(dir.path(), "zstd.journal");

        let mut l = Lector::abrir(&ruta).unwrap();
        let entradas = l.leer(10).unwrap();
        assert_eq!(entradas[0].sin_descomprimir, vec!["zstd".to_string()]);
        assert_eq!(l.contadores().sin_descomprimir, 1);
        // Y los campos con los que SI se clasifica siguen llegando: systemd solo
        // comprime por encima de 512 bytes.
        assert_eq!(entradas[0].productor(), "sshd");
    }

    #[test]
    fn un_lz4_que_miente_sobre_su_tamano_no_reserva_por_lo_declarado() {
        let mut b = u64::MAX.to_le_bytes().to_vec();
        b.push(0x10);
        b.push(b'x');
        assert!(descomprimir_lz4(&b).is_none());
    }

    #[test]
    fn un_lz4_con_distancia_imposible_se_rechaza() {
        let mut b = 100u64.to_le_bytes().to_vec();
        b.push(0x05); // 0 literales, copia 5
        b.extend_from_slice(&9999u16.to_le_bytes()); // mas atras que la salida
        assert!(descomprimir_lz4(&b).is_none());
    }

    #[test]
    fn un_lz4_truncado_se_rechaza_en_vez_de_entregar_a_medias() {
        let mut b = 100u64.to_le_bytes().to_vec();
        b.push(0xf0); // 15+ literales...
        b.push(200); // ...doscientos quince
        b.extend_from_slice(b"solo tres"); // pero no estan
        assert!(descomprimir_lz4(&b).is_none());
    }

    // --- Entrada hostil ------------------------------------------------------

    #[test]
    fn un_fichero_sin_la_firma_no_se_analiza() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("falso.journal");
        std::fs::write(&ruta, vec![0u8; 500]).unwrap();
        assert!(Lector::abrir(&ruta).is_err());
    }

    #[test]
    fn una_bandera_incompatible_desconocida_para_la_lectura() {
        // Seguir leyendo produciria campos desplazados con aspecto de datos.
        let dir = tempfile::tempdir().unwrap();
        let mut c = Constructor::nuevo(false);
        c.bytes[12..16].copy_from_slice(&(1u32 << 20).to_le_bytes());
        let ruta = c.guardar(dir.path(), "futuro.journal");
        let e = Lector::abrir(&ruta).unwrap_err();
        assert!(e.to_string().contains("incompatibles"), "{e}");
    }

    #[test]
    fn un_desplazamiento_que_apunta_fuera_del_fichero_no_lee_fuera() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Constructor::nuevo(false);
        let d = c.dato("MESSAGE=bien");
        let e = c.entrada(1, 1, &[d]);
        // Un vector que apunta a un desplazamiento absurdo.
        let v = c.vector(0, &[e, u64::MAX - 8, 9_999_999]);
        c.raiz(v);
        let ruta = c.guardar(dir.path(), "fuera.journal");

        let mut l = Lector::abrir(&ruta).unwrap();
        let entradas = l.leer(100).unwrap();
        assert_eq!(
            entradas.len(),
            1,
            "la buena se lee y las malas se descartan"
        );
        assert!(l.contadores().objetos_invalidos > 0, "y se cuentan");
    }

    #[test]
    fn una_cadena_de_vectores_que_se_muerde_la_cola_no_gira_para_siempre() {
        // Es la forma mas barata de cegar la ingesta de una maquina: el
        // recolector gira sobre el mismo fichero, sin leer nada nuevo y sin
        // fallar.
        let dir = tempfile::tempdir().unwrap();
        let mut c = Constructor::nuevo(false);
        let d = c.dato("MESSAGE=x");
        let e = c.entrada(1, 1, &[d]);
        let v = c.vector(0, &[e]);
        // Se reescribe el «siguiente» del vector para que apunte a si mismo.
        let en = usize::try_from(v + CABECERA_OBJETO).unwrap();
        c.bytes[en..en + 8].copy_from_slice(&v.to_le_bytes());
        c.raiz(v);
        let ruta = c.guardar(dir.path(), "ciclo.journal");

        // El ciclo se detecta al ABRIR, antes de entregar una sola entrada: es
        // donde se recorre y se valida la cadena.
        let e = Lector::abrir(&ruta).unwrap_err();
        assert!(e.to_string().contains("muerde la cola"), "{e}");
    }

    #[test]
    fn un_objeto_con_tamano_absurdo_no_reserva_memoria() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Constructor::nuevo(false);
        let d = c.dato("MESSAGE=bien");
        // Se falsea el tamano del objeto de dato a algo enorme.
        let en = usize::try_from(d + 8).unwrap();
        c.bytes[en..en + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        let e = c.entrada(1, 1, &[d]);
        let v = c.vector(0, &[e]);
        c.raiz(v);
        let ruta = c.guardar(dir.path(), "gordo.journal");

        let mut l = Lector::abrir(&ruta).unwrap();
        let entradas = l.leer(10).unwrap();
        assert_eq!(entradas.len(), 1);
        assert!(entradas[0].campos.is_empty(), "el dato malo se descarto");
    }

    #[test]
    fn un_numero_de_campos_absurdo_esta_acotado() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Constructor::nuevo(false);
        let d = c.dato("K=v");
        let refs: Vec<u64> = std::iter::repeat_n(d, 10_000).collect();
        let e = c.entrada(1, 1, &refs);
        let v = c.vector(0, &[e]);
        c.raiz(v);
        let ruta = c.guardar(dir.path(), "muchos.journal");

        let mut l = Lector::abrir(&ruta).unwrap();
        let entradas = l.leer(10).unwrap();
        assert!(entradas[0].campos.len() <= MAX_CAMPOS_ENTRADA);
    }

    #[test]
    fn un_fichero_vacio_no_entra_en_panico() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("vacio.journal");
        std::fs::write(&ruta, b"").unwrap();
        assert!(Lector::abrir(&ruta).is_err());
    }

    #[test]
    fn el_descubrimiento_da_un_orden_estable() {
        // Sin orden estable, el mismo sistema produce lecturas en distinto orden
        // segun lo que devuelva el sistema de ficheros, y el determinismo de la
        // normalizacion deja de poderse comprobar.
        let dir = tempfile::tempdir().unwrap();
        let maquina = dir.path().join("var/log/journal/abc123");
        std::fs::create_dir_all(&maquina).unwrap();
        for n in ["z.journal", "a.journal", "m.journal", "no.txt"] {
            std::fs::write(maquina.join(n), b"x").unwrap();
        }
        let hallados = descubrir(dir.path());
        let nombres: Vec<_> = hallados
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(nombres, ["a.journal", "m.journal", "z.journal"]);
    }

    #[test]
    fn el_diario_persistente_va_antes_que_el_volatil() {
        // En una maquina sin /var/log/journal el diario vive en /run y se pierde
        // al reiniciar: un atacante que reinicie se lleva el log por delante.
        let dir = tempfile::tempdir().unwrap();
        for base in ["var/log/journal/m1", "run/log/journal/m1"] {
            let d = dir.path().join(base);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("system.journal"), b"x").unwrap();
        }
        let hallados = descubrir(dir.path());
        assert_eq!(hallados.len(), 2);
        assert!(hallados[0].to_string_lossy().contains("var/log"));
        assert!(hallados[1].to_string_lossy().contains("run/log"));
    }
}
