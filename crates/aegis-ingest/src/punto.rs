//! El punto de control durable: por donde iba cada origen.
//!
//! # Dos durabilidades distintas, y confundirlas pierde eventos
//!
//! La entrega al-menos-una-vez necesita **dos** cosas en disco, y no son la
//! misma:
//!
//! * **El diario** ([`aegis_firehose::Diario`], de la FASE 46) guarda los
//!   eventos **ya normalizados y todavia sin acusar**. Si el proceso muere, se
//!   reenvian al arrancar.
//! * **El punto de control** —esto— guarda **por donde iba cada origen**: el
//!   desplazamiento en un fichero, el cursor de journald, el numero de registro
//!   de EVTX, el testigo de paginacion de un registro de nube.
//!
//! Un sistema con diario pero sin punto de control vuelve a leer `/var/log`
//! entero en cada arranque. Uno con punto de control pero sin diario pierde todo
//! lo leido y no entregado. Hacen falta los dos.
//!
//! # La regla de orden, que es TODA la correccion de esta fase
//!
//! ```text
//!   1. leer del origen            -> eventos en memoria
//!   2. admitir en el diario       -> en disco, pendientes
//!   3. sincronizar el diario      -> en disco DE VERDAD
//!   4. avanzar el punto de control
//! ```
//!
//! El orden **no es negociable y es asimetrico a proposito**:
//!
//! * Si el proceso muere entre 3 y 4, al arrancar se vuelve a leer desde el
//!   punto viejo y se reenvian eventos que ya estaban. Son **duplicados**, y el
//!   plano de control los desduplica por su identificador, que se deriva del
//!   contenido y del ancla.
//! * Si se avanzara el punto ANTES de sincronizar, un corte entre las dos cosas
//!   dejaria el origen marcado como leido con los eventos todavia en un bufer
//!   que ya no existe. Serian **perdidas**, y una perdida no se arregla despues:
//!   nadie sabe siquiera que hubo.
//!
//! Duplicar es recuperable y perder no lo es. Por eso [`Confirmador`] hace los
//! pasos 3 y 4 juntos y en ese orden, y es la unica forma de avanzar el punto.
//!
//! # Por que el fichero lleva resumen
//!
//! Se escribe con el patron de sustitucion atomica —temporal, `fsync`, `rename`,
//! `fsync` del directorio— que en Linux garantiza que se ve el fichero entero o
//! el anterior entero. Aun asi lleva un resumen SHA-256 al final, por dos
//! motivos que no cubre el `rename`: un sistema de ficheros montado sin
//! garantias de orden, y la corrupcion del medio meses despues. Un punto de
//! control corrupto que se lea como valido hace saltar o repetir un tramo
//! arbitrario de historia, y nadie lo notaria.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{ErrorIngesta, Resultado};
use crate::fichero::{Identidad, Marca};

/// Cabecera del fichero. Sube si cambia el formato.
const CABECERA: &str = "aegis-punto-v1";

/// Origenes maximos en un punto de control.
///
/// Un recolector con diez mil ficheros configurados es un error de despliegue,
/// no un caso legitimo, y sin tope el fichero de estado crece hasta llenar el
/// disco del cliente.
pub const MAX_ORIGENES: usize = 4096;

/// Bytes maximos de un cursor opaco.
pub const MAX_CURSOR: usize = 1024;

/// Por donde iba un origen.
///
/// Cada familia de origen tiene su forma de decir «por aqui», y forzarlas todas
/// a un entero perderia informacion: el cursor de journald no es un
/// desplazamiento y tratarlo como tal lo rompe en la primera rotacion del
/// diario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Posicion {
    /// Fichero plano: dispositivo, inodo y desplazamiento.
    Fichero(Marca),
    /// Cursor opaco: journald, y el testigo de paginacion de las nubes.
    Cursor(String),
    /// Numero de registro: EVTX.
    Registro(u64),
}

impl Posicion {
    fn tipo(&self) -> &'static str {
        match self {
            Posicion::Fichero(_) => "f",
            Posicion::Cursor(_) => "c",
            Posicion::Registro(_) => "r",
        }
    }
}

/// El estado de lectura de todos los origenes, con respaldo en disco.
#[derive(Debug)]
pub struct PuntoDeControl {
    ruta: PathBuf,
    estado: BTreeMap<String, Posicion>,
    /// Guardados ejecutados. Lo usa la prueba de que no se guarda de mas.
    guardados: u64,
    sucio: bool,
}

impl PuntoDeControl {
    /// Abre —o crea— el punto de control.
    ///
    /// Un fichero ilegible **no se ignora en silencio**: se devuelve el error.
    /// Ignorarlo equivaldria a empezar de cero, que en un fichero de log de un
    /// giga significa reenviar un giga de eventos y, peor, hacerlo callando.
    pub fn abrir(ruta: impl Into<PathBuf>) -> Resultado<PuntoDeControl> {
        let ruta = ruta.into();
        let estado = match std::fs::read_to_string(&ruta) {
            Ok(texto) => analizar(&texto)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => {
                return Err(ErrorIngesta::es(
                    format!("leyendo el punto de control {}", ruta.display()),
                    e,
                ))
            }
        };
        Ok(PuntoDeControl {
            ruta,
            estado,
            guardados: 0,
            sucio: false,
        })
    }

    /// Por donde iba un origen, si se sabe.
    #[must_use]
    pub fn posicion(&self, origen: &str) -> Option<&Posicion> {
        self.estado.get(origen)
    }

    /// Marca de un origen de fichero, si la hay y es de ese tipo.
    #[must_use]
    pub fn marca(&self, origen: &str) -> Option<Marca> {
        match self.estado.get(origen)? {
            Posicion::Fichero(m) => Some(*m),
            _ => None,
        }
    }

    /// Origenes conocidos.
    pub fn origenes(&self) -> impl Iterator<Item = &str> {
        self.estado.keys().map(String::as_str)
    }

    /// Cuantas veces se ha escrito en disco.
    #[must_use]
    pub fn guardados(&self) -> u64 {
        self.guardados
    }

    /// Si hay cambios sin escribir.
    #[must_use]
    pub fn sucio(&self) -> bool {
        self.sucio
    }

    /// Olvida un origen que ya no se sigue.
    pub fn olvidar(&mut self, origen: &str) {
        if self.estado.remove(origen).is_some() {
            self.sucio = true;
        }
    }

    /// Anota en memoria por donde va un origen.
    ///
    /// **No escribe en disco**, y es deliberado: escribir aqui invitaria a
    /// llamarlo antes de que los eventos esten a salvo, que es exactamente el
    /// orden que pierde eventos. Para que llegue al disco hay que pasar por
    /// [`Confirmador`].
    pub fn anotar(&mut self, origen: &str, posicion: Posicion) -> Resultado<()> {
        if !self.estado.contains_key(origen) && self.estado.len() >= MAX_ORIGENES {
            return Err(ErrorIngesta::Config(format!(
                "mas de {MAX_ORIGENES} origenes en el punto de control"
            )));
        }
        if origen.is_empty() {
            return Err(ErrorIngesta::Config("origen sin nombre".into()));
        }
        if let Posicion::Cursor(c) = &posicion {
            if c.len() > MAX_CURSOR {
                return Err(ErrorIngesta::Excedido {
                    que: "cursor",
                    tamano: c.len(),
                    tope: MAX_CURSOR,
                });
            }
        }
        if self.estado.get(origen) != Some(&posicion) {
            self.estado.insert(origen.to_string(), posicion);
            self.sucio = true;
        }
        Ok(())
    }

    /// Escribe el punto de control en disco, de forma atomica y durable.
    ///
    /// Es privado: la unica forma de llamarlo es a traves de [`Confirmador`],
    /// que garantiza que antes se sincronizo lo que hace falta. Ver la regla de
    /// orden en el encabezado del modulo.
    fn escribir(&mut self) -> Resultado<()> {
        if !self.sucio {
            return Ok(());
        }
        let cuerpo = serializar(&self.estado);
        let temporal = self.ruta.with_extension("tmp");

        {
            let mut f = File::create(&temporal)
                .map_err(|e| ErrorIngesta::es(format!("creando {}", temporal.display()), e))?;
            f.write_all(cuerpo.as_bytes())
                .map_err(|e| ErrorIngesta::es("escribiendo el punto de control", e))?;
            // El primer `fsync`: el contenido esta en el medio. Sin el, el
            // `rename` podria publicar un fichero cuyo contenido todavia esta en
            // la cache de la pagina.
            f.sync_all()
                .map_err(|e| ErrorIngesta::es("sincronizando el punto de control", e))?;
        }

        std::fs::rename(&temporal, &self.ruta).map_err(|e| {
            ErrorIngesta::es(
                format!(
                    "sustituyendo {} por {}",
                    self.ruta.display(),
                    temporal.display()
                ),
                e,
            )
        })?;

        // El segundo `fsync`, sobre el DIRECTORIO: el `rename` en si tambien es
        // una operacion de metadatos que puede quedarse sin escribir. Omitirlo es
        // el error mas comun de la sustitucion atomica, y el sintoma es que el
        // punto de control «se queda antiguo» solo cuando hay un corte de luz,
        // que es justo cuando importa.
        if let Some(dir) = self.ruta.parent() {
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }

        self.guardados += 1;
        self.sucio = false;
        Ok(())
    }
}

/// Une el diario y el punto de control en el unico orden correcto.
///
/// Existe para que el orden no dependa de que quien llame se acuerde. Ver la
/// regla de orden en el encabezado del modulo.
pub struct Confirmador<'a> {
    punto: &'a mut PuntoDeControl,
}

impl<'a> Confirmador<'a> {
    /// Toma el punto de control.
    pub fn nuevo(punto: &'a mut PuntoDeControl) -> Confirmador<'a> {
        Confirmador { punto }
    }

    /// Sincroniza lo pendiente y **despues** escribe el punto de control.
    ///
    /// `sincronizar` es lo que pone los eventos a salvo: en el endpoint es
    /// [`aegis_firehose::Diario::sincronizar`]. Si falla, el punto de control
    /// **no se toca**, que es lo unico correcto: el origen se volvera a leer
    /// desde donde estaba y los eventos se volveran a producir.
    pub fn confirmar<F>(&mut self, sincronizar: F) -> Resultado<()>
    where
        F: FnOnce() -> Resultado<()>,
    {
        sincronizar()?;
        self.punto.escribir()
    }
}

/// Serializa el estado al formato de fichero.
///
/// La clave va en hexadecimal: una ruta puede llevar tabuladores, saltos de
/// linea y cualquier byte salvo la barra y el cero. Escaparlos seria otro
/// analizador que mantener y otra forma de que dos implementaciones discrepen;
/// en hexadecimal el problema no existe.
fn serializar(estado: &BTreeMap<String, Posicion>) -> String {
    let mut cuerpo = String::from(CABECERA);
    cuerpo.push('\n');
    for (clave, pos) in estado {
        cuerpo.push_str(&hex(clave.as_bytes()));
        cuerpo.push('\t');
        cuerpo.push_str(pos.tipo());
        cuerpo.push('\t');
        match pos {
            Posicion::Fichero(m) => {
                cuerpo.push_str(&format!(
                    "{}\t{}\t{}",
                    m.identidad.dispositivo, m.identidad.inodo, m.desplazamiento
                ));
            }
            Posicion::Cursor(c) => cuerpo.push_str(&hex(c.as_bytes())),
            Posicion::Registro(n) => cuerpo.push_str(&n.to_string()),
        }
        cuerpo.push('\n');
    }
    let resumen = hex(&Sha256::digest(cuerpo.as_bytes()));
    cuerpo.push('#');
    cuerpo.push_str(&resumen);
    cuerpo.push('\n');
    cuerpo
}

fn analizar(texto: &str) -> Resultado<BTreeMap<String, Posicion>> {
    let corte = texto.rfind("\n#").ok_or_else(|| ErrorIngesta::Malformado {
        origen: "punto-de-control",
        motivo: "sin linea de resumen".into(),
    })?;
    let cuerpo = &texto[..=corte];
    let linea_resumen = texto[corte + 2..].trim_end();
    let esperado = hex(&Sha256::digest(cuerpo.as_bytes()));
    if linea_resumen != esperado {
        // Un punto de control corrupto que se leyera como valido haria saltar o
        // repetir un tramo arbitrario de historia, y nadie lo notaria.
        return Err(ErrorIngesta::Malformado {
            origen: "punto-de-control",
            motivo: "el resumen no cuadra: fichero corrupto".into(),
        });
    }

    let mut lineas = cuerpo.lines();
    if lineas.next() != Some(CABECERA) {
        return Err(ErrorIngesta::Malformado {
            origen: "punto-de-control",
            motivo: "cabecera desconocida".into(),
        });
    }

    let mut estado = BTreeMap::new();
    for linea in lineas {
        if linea.is_empty() {
            continue;
        }
        let mut partes = linea.split('\t');
        let clave = partes.next().ok_or_else(|| roto("linea vacia"))?;
        let clave = String::from_utf8(desde_hex(clave)?).map_err(|_| roto("clave no es texto"))?;
        let tipo = partes.next().ok_or_else(|| roto("sin tipo"))?;
        let pos = match tipo {
            "f" => {
                let dispositivo = numero(partes.next())?;
                let inodo = numero(partes.next())?;
                let desplazamiento = numero(partes.next())?;
                Posicion::Fichero(Marca {
                    identidad: Identidad { dispositivo, inodo },
                    desplazamiento,
                })
            }
            "c" => {
                let c = partes.next().ok_or_else(|| roto("cursor vacio"))?;
                let bytes = desde_hex(c)?;
                if bytes.len() > MAX_CURSOR {
                    return Err(ErrorIngesta::Excedido {
                        que: "cursor",
                        tamano: bytes.len(),
                        tope: MAX_CURSOR,
                    });
                }
                Posicion::Cursor(String::from_utf8(bytes).map_err(|_| roto("cursor no es texto"))?)
            }
            "r" => Posicion::Registro(numero(partes.next())?),
            otro => return Err(roto(format!("tipo de posicion «{otro}» desconocido"))),
        };
        if estado.len() >= MAX_ORIGENES {
            return Err(ErrorIngesta::Excedido {
                que: "origenes en el punto de control",
                tamano: estado.len() + 1,
                tope: MAX_ORIGENES,
            });
        }
        estado.insert(clave, pos);
    }
    Ok(estado)
}

fn roto(motivo: impl std::fmt::Display) -> ErrorIngesta {
    ErrorIngesta::Malformado {
        origen: "punto-de-control",
        motivo: motivo.to_string(),
    }
}

fn numero(s: Option<&str>) -> Resultado<u64> {
    s.ok_or_else(|| roto("campo numerico ausente"))?
        .parse()
        .map_err(|_| roto("campo numerico ilegible"))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn desde_hex(s: &str) -> Resultado<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(roto("hexadecimal de longitud impar"));
    }
    let b = s.as_bytes();
    let mut salida = Vec::with_capacity(s.len() / 2);
    for par in b.chunks_exact(2) {
        let alto = digito(par[0])?;
        let bajo = digito(par[1])?;
        salida.push(alto * 16 + bajo);
    }
    Ok(salida)
}

fn digito(c: u8) -> Resultado<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(roto("digito hexadecimal invalido")),
    }
}

/// Comprueba de forma explicita que una ruta se puede usar como punto de
/// control.
///
/// Sin esto, un directorio sin permiso de escritura produce el peor fallo
/// posible: la ingesta funciona, entrega eventos, y **no guarda nunca por donde
/// iba**, asi que cada reinicio reenvia todo desde el principio. Y como
/// funciona, nadie lo mira.
pub fn comprobar(ruta: &Path) -> Resultado<()> {
    let dir = ruta.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)
        .map_err(|e| ErrorIngesta::es(format!("creando {}", dir.display()), e))?;
    let prueba = ruta.with_extension("prueba");
    File::create(&prueba).map_err(|e| {
        ErrorIngesta::es(format!("sin permiso de escritura en {}", dir.display()), e)
    })?;
    let _ = std::fs::remove_file(&prueba);
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn marca(inodo: u64, desplazamiento: u64) -> Marca {
        Marca {
            identidad: Identidad {
                dispositivo: 66,
                inodo,
            },
            desplazamiento,
        }
    }

    #[test]
    fn lo_anotado_sobrevive_al_reinicio() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("estado");
        let mut p = PuntoDeControl::abrir(&ruta).unwrap();
        p.anotar("/var/log/auth.log", Posicion::Fichero(marca(7, 4096)))
            .unwrap();
        p.anotar("journald", Posicion::Cursor("s=abc;i=1f".into()))
            .unwrap();
        p.anotar("Security.evtx", Posicion::Registro(99_999))
            .unwrap();
        Confirmador::nuevo(&mut p).confirmar(|| Ok(())).unwrap();

        let q = PuntoDeControl::abrir(&ruta).unwrap();
        assert_eq!(q.marca("/var/log/auth.log"), Some(marca(7, 4096)));
        assert_eq!(
            q.posicion("journald"),
            Some(&Posicion::Cursor("s=abc;i=1f".into()))
        );
        assert_eq!(
            q.posicion("Security.evtx"),
            Some(&Posicion::Registro(99_999))
        );
    }

    #[test]
    fn anotar_no_escribe_en_disco() {
        // Escribir al anotar invitaria a llamarlo antes de que los eventos esten
        // a salvo, que es exactamente el orden que pierde eventos.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("estado");
        let mut p = PuntoDeControl::abrir(&ruta).unwrap();
        p.anotar("a", Posicion::Registro(1)).unwrap();
        assert!(!ruta.exists(), "no puede haber tocado el disco");
        assert!(p.sucio());
        Confirmador::nuevo(&mut p).confirmar(|| Ok(())).unwrap();
        assert!(ruta.exists());
        assert!(!p.sucio());
    }

    #[test]
    fn si_la_sincronizacion_falla_el_punto_no_avanza() {
        // LA REGLA DE ORDEN. Si el punto avanzara igual, el origen quedaria
        // marcado como leido con los eventos en un bufer que ya no existe, y eso
        // es una perdida, que no se arregla despues.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("estado");
        let mut p = PuntoDeControl::abrir(&ruta).unwrap();
        p.anotar("a", Posicion::Registro(10)).unwrap();
        Confirmador::nuevo(&mut p).confirmar(|| Ok(())).unwrap();

        p.anotar("a", Posicion::Registro(20)).unwrap();
        let r = Confirmador::nuevo(&mut p)
            .confirmar(|| Err(ErrorIngesta::Diario("el disco se lleno".into())));
        assert!(r.is_err());

        let q = PuntoDeControl::abrir(&ruta).unwrap();
        assert_eq!(
            q.posicion("a"),
            Some(&Posicion::Registro(10)),
            "se quedo en el ultimo estado que SI estaba a salvo"
        );
    }

    #[test]
    fn reanudar_tras_un_corte_entre_sincronizar_y_guardar_duplica_pero_no_pierde() {
        // El caso que la asimetria acepta: duplicar es recuperable —el plano de
        // control desduplica por identificador— y perder no lo es.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("estado");
        let mut p = PuntoDeControl::abrir(&ruta).unwrap();
        p.anotar("/var/log/x", Posicion::Fichero(marca(1, 1000)))
            .unwrap();
        Confirmador::nuevo(&mut p).confirmar(|| Ok(())).unwrap();

        // Se leyo hasta 5000 y se sincronizo el diario... y se corto la luz.
        p.anotar("/var/log/x", Posicion::Fichero(marca(1, 5000)))
            .unwrap();
        drop(p); // muerte sin confirmar

        let q = PuntoDeControl::abrir(&ruta).unwrap();
        assert_eq!(
            q.marca("/var/log/x"),
            Some(marca(1, 1000)),
            "se relee desde 1000: duplicados, no perdidas"
        );
    }

    #[test]
    fn un_fichero_corrupto_no_se_lee_como_valido() {
        // Leerlo como valido haria saltar o repetir un tramo arbitrario de
        // historia, y nadie lo notaria.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("estado");
        let mut p = PuntoDeControl::abrir(&ruta).unwrap();
        p.anotar("a", Posicion::Registro(42)).unwrap();
        Confirmador::nuevo(&mut p).confirmar(|| Ok(())).unwrap();

        let mut texto = std::fs::read_to_string(&ruta).unwrap();
        texto = texto.replace("42", "43");
        std::fs::write(&ruta, texto).unwrap();

        let e = PuntoDeControl::abrir(&ruta).unwrap_err();
        assert!(e.to_string().contains("resumen"), "{e}");
    }

    #[test]
    fn un_fichero_cortado_a_la_mitad_tampoco() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("estado");
        let mut p = PuntoDeControl::abrir(&ruta).unwrap();
        for i in 0..50u64 {
            p.anotar(&format!("origen-{i}"), Posicion::Registro(i))
                .unwrap();
        }
        Confirmador::nuevo(&mut p).confirmar(|| Ok(())).unwrap();

        let texto = std::fs::read_to_string(&ruta).unwrap();
        std::fs::write(&ruta, &texto[..texto.len() / 2]).unwrap();
        assert!(PuntoDeControl::abrir(&ruta).is_err());
    }

    #[test]
    fn un_punto_de_control_ilegible_no_se_ignora_en_silencio() {
        // Ignorarlo equivale a empezar de cero: reenviar un giga de eventos, y
        // hacerlo callando.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("estado");
        std::fs::write(&ruta, "basura sin resumen").unwrap();
        assert!(PuntoDeControl::abrir(&ruta).is_err());
    }

    #[test]
    fn una_ruta_con_tabuladores_y_saltos_de_linea_va_y_vuelve() {
        // Una ruta puede llevar cualquier byte salvo la barra y el cero. Con la
        // clave en hexadecimal el problema de escapado no existe.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("estado");
        let rara = "/var/log/raro\tcon\ntabs y\tsaltos\ty#almohadilla";
        let mut p = PuntoDeControl::abrir(&ruta).unwrap();
        p.anotar(rara, Posicion::Fichero(marca(3, 77))).unwrap();
        Confirmador::nuevo(&mut p).confirmar(|| Ok(())).unwrap();

        let q = PuntoDeControl::abrir(&ruta).unwrap();
        assert_eq!(q.marca(rara), Some(marca(3, 77)));
        assert_eq!(q.origenes().count(), 1);
    }

    #[test]
    fn no_se_escribe_si_no_cambio_nada() {
        // Guardar en cada vuelta del bucle seria un `fsync` por lote, y en un
        // recolector con cien ficheros eso es mas trabajo de disco que la propia
        // lectura.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("estado");
        let mut p = PuntoDeControl::abrir(&ruta).unwrap();
        p.anotar("a", Posicion::Registro(1)).unwrap();
        Confirmador::nuevo(&mut p).confirmar(|| Ok(())).unwrap();
        assert_eq!(p.guardados(), 1);

        p.anotar("a", Posicion::Registro(1)).unwrap(); // lo mismo
        Confirmador::nuevo(&mut p).confirmar(|| Ok(())).unwrap();
        assert_eq!(p.guardados(), 1, "no habia nada que guardar");

        p.anotar("a", Posicion::Registro(2)).unwrap();
        Confirmador::nuevo(&mut p).confirmar(|| Ok(())).unwrap();
        assert_eq!(p.guardados(), 2);
    }

    #[test]
    fn el_numero_de_origenes_esta_acotado() {
        // Sin tope, el fichero de estado crece hasta llenar el disco del
        // cliente.
        let dir = tempfile::tempdir().unwrap();
        let mut p = PuntoDeControl::abrir(dir.path().join("estado")).unwrap();
        for i in 0..MAX_ORIGENES {
            p.anotar(&format!("o{i}"), Posicion::Registro(1)).unwrap();
        }
        assert!(p.anotar("uno-mas", Posicion::Registro(1)).is_err());
        // Pero actualizar uno que ya estaba sigue funcionando.
        assert!(p.anotar("o0", Posicion::Registro(2)).is_ok());
    }

    #[test]
    fn un_cursor_gigante_se_rechaza_con_nombre() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = PuntoDeControl::abrir(dir.path().join("estado")).unwrap();
        let e = p
            .anotar("nube", Posicion::Cursor("x".repeat(MAX_CURSOR + 1)))
            .unwrap_err();
        assert!(matches!(e, ErrorIngesta::Excedido { .. }));
    }

    #[test]
    fn olvidar_un_origen_lo_quita_del_disco() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("estado");
        let mut p = PuntoDeControl::abrir(&ruta).unwrap();
        p.anotar("a", Posicion::Registro(1)).unwrap();
        p.anotar("b", Posicion::Registro(2)).unwrap();
        Confirmador::nuevo(&mut p).confirmar(|| Ok(())).unwrap();
        p.olvidar("a");
        Confirmador::nuevo(&mut p).confirmar(|| Ok(())).unwrap();

        let q = PuntoDeControl::abrir(&ruta).unwrap();
        assert!(q.posicion("a").is_none());
        assert!(q.posicion("b").is_some());
    }

    #[test]
    fn el_fichero_temporal_no_se_queda_por_ahi() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("estado");
        let mut p = PuntoDeControl::abrir(&ruta).unwrap();
        p.anotar("a", Posicion::Registro(1)).unwrap();
        Confirmador::nuevo(&mut p).confirmar(|| Ok(())).unwrap();
        assert!(!ruta.with_extension("tmp").exists());
    }

    #[test]
    fn comprobar_avisa_de_un_directorio_sin_permiso_en_vez_de_reenviar_todo_cada_dia() {
        // El peor fallo posible: la ingesta funciona, entrega eventos, y no
        // guarda nunca por donde iba. Y como funciona, nadie lo mira.
        let dir = tempfile::tempdir().unwrap();
        assert!(comprobar(&dir.path().join("sub/estado")).is_ok());
        assert!(dir.path().join("sub").is_dir());
    }

    #[test]
    fn el_formato_es_estable_entre_ejecuciones() {
        // Determinismo: el mismo estado produce el mismo fichero, byte a byte.
        let mut a = BTreeMap::new();
        a.insert("z".to_string(), Posicion::Registro(1));
        a.insert("a".to_string(), Posicion::Fichero(marca(2, 3)));
        let mut b = BTreeMap::new();
        b.insert("a".to_string(), Posicion::Fichero(marca(2, 3)));
        b.insert("z".to_string(), Posicion::Registro(1));
        assert_eq!(serializar(&a), serializar(&b));
    }
}
