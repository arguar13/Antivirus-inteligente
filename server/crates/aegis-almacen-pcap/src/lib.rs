//! # `aegis-almacen-pcap` — el almacen de captura (FASE 90)
//!
//! Donde vive el trafico retenido, como se busca y como se borra.
//!
//! ## Las tres decisiones de este crate
//!
//! **Una particion es un fichero.** No una tabla, no un indice, no un bloque
//! dentro de otra cosa: un fichero PCAP que Wireshark abre. Eso hace que purgar
//! sea `unlink`, que es una operacion de metadatos —el espacio vuelve entero y de
//! una vez— y que la captura siga sirviendo de prueba fuera de este producto.
//!
//! **Se busca por entidad, no por texto.** El indice del agente
//! ([`aegis_captura::Indice`]) se construye sobre el [`Eid`], que se **deriva** de
//! los hechos. Buscar el trafico de una maquina no es correlacionar campos
//! normalizados: es mirar en su sitio.
//!
//! **Lo que ya no esta se dice.** Una busqueda que devuelve menos de lo que hubo
//! porque una particion se purgo lo declara en [`Respuesta::purgadas`]. Es la
//! misma distincion que la cifra de cobertura de los disectores: «no hubo» y «lo
//! hubo y ya no esta» son cosas distintas, y confundirlas es como se cierra un
//! incidente en falso.
//!
//! ## Lo que este crate NO hace
//!
//! No decide que se guarda: eso lo decide el agente con
//! [`aegis_captura::Autorizacion`], que solo se construye desde un veredicto. El
//! almacen recibe lo que le mandan y no tiene forma de subir una politica.
//!
//! Y no descomprime, no reindexa y no reescribe lo guardado. Un almacen que
//! modifica lo que custodia deja de ser custodia.

#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aegis_captura::indice::{Cursor, Entrada, Indice, Particion};
use aegis_captura::pcap::{self, Escritor};
use aegis_captura::retencion::{Caducidad, Politica};
use aegis_captura::Paquete;
use aegis_entidad::entidad::Eid;

/// Lo que puede salir mal.
#[derive(Debug)]
pub enum Error {
    /// Fallo del sistema de ficheros.
    Fichero(std::io::Error),
    /// Un fichero de particion no es un PCAP legible.
    ///
    /// **No se ignora en silencio**: una particion ilegible es trafico que se
    /// creia tener y no se tiene, y eso hay que decirlo igual que se dice una
    /// purga.
    Ilegible {
        /// Que particion.
        particion: String,
        /// Por que.
        porque: pcap::Error,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Fichero(e) => write!(f, "fallo del sistema de ficheros: {e}"),
            Error::Ilegible { particion, porque } => {
                write!(f, "la particion {particion} no se puede leer: {porque}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Fichero(e)
    }
}

/// Lo que devuelve una busqueda.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Respuesta {
    /// Las entradas encontradas, en orden de tiempo.
    pub entradas: Vec<Entrada>,
    /// Por donde seguir, si hay mas.
    pub siguiente: Option<Cursor>,
    /// Cuantas entradas habia y ya no estan porque su particion se purgo.
    pub purgadas: u64,
    /// Cuantas entradas habia y ya no estan porque el indice se lleno.
    ///
    /// Va aparte de `purgadas` **porque no se arregla igual**: lo purgado se fue
    /// cumpliendo la retencion, y lo desbordado se fue porque el almacen no tenia
    /// sitio en memoria. Lo primero es el producto funcionando; lo segundo es un
    /// almacen mal dimensionado, y hasta que se arregle falta trafico.
    pub desbordadas: u64,
    /// Cuantas particiones se tuvieron que abrir para contestar.
    ///
    /// Es la medida que dice si el reparto por particiones sirve: una busqueda de
    /// una entidad que abra treinta particiones esta recorriendo el almacen
    /// entero, y entonces el reparto no reparte.
    pub particiones_abiertas: usize,
}

impl Respuesta {
    /// Como se cuenta en un informe.
    #[must_use]
    pub fn frase(&self) -> String {
        let base = format!(
            "{} entradas en {} particion(es)",
            self.entradas.len(),
            self.particiones_abiertas
        );
        let mut frase = base;
        if self.purgadas > 0 {
            frase = format!(
                "{frase}. HUBO {} entradas mas de esta entidad y ya no estan: su particion se \
                 purgo por caducidad. Lo que no aparezca aqui puede ser que no ocurriera o puede \
                 ser que estuviera en esas",
                self.purgadas
            );
        }
        if self.desbordadas > 0 {
            frase = format!(
                "{frase}. Y OTRAS {} se cayeron porque el indice se lleno: eso NO es retencion \
                 cumpliendose, es el almacen quedandose corto, y hay que subirle el techo",
                self.desbordadas
            );
        }
        frase
    }
}

/// Cuanto ocupa el almacen, por politica.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ocupacion {
    /// Bytes por politica de retencion.
    pub por_politica: BTreeMap<&'static str, u64>,
    /// Cuantas particiones hay.
    pub particiones: usize,
}

impl Ocupacion {
    /// El total.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.por_politica.values().sum()
    }
}

/// El almacen.
pub struct Almacen {
    raiz: PathBuf,
    indice: Indice,
    /// Lo que ocupa cada particion, para no tener que medir el disco.
    bytes: BTreeMap<Particion, u64>,
}

/// Cuantas entradas de indice sostiene el almacen en memoria.
///
/// # Por que este numero y no «las que hagan falta»
///
/// El techo del indice del agente ([`aegis_captura::indice::MAX_ENTRADAS`]) sale
/// de su presupuesto de memoria, que es pequeno a proposito. El del servidor no:
/// aqui el limite es el disco, y el indice es lo que hace que el disco se pueda
/// consultar. Pero «sin techo» tampoco vale — el servidor recibe lo que le manden
/// mil agentes, y un indice que crece con lo que mandan los demas es la misma
/// arma que en el agente, con mas memoria detras.
///
/// Dos millones de entradas son unos 384 MiB con el coste medido por entrada, que
/// es lo que se le puede pedir a un servidor de captura, y lo que no cabe **se
/// cuenta** en [`Respuesta::desbordadas`] en vez de desaparecer.
pub const ENTRADAS_EN_MEMORIA: usize = 2_000_000;

impl Almacen {
    /// Un almacen bajo `raiz`, con el indice de [`ENTRADAS_EN_MEMORIA`] entradas.
    ///
    /// # Errores
    ///
    /// Si no se puede crear el directorio.
    pub fn nuevo(raiz: &Path) -> Result<Almacen, Error> {
        Almacen::con_tope(raiz, ENTRADAS_EN_MEMORIA)
    }

    /// Un almacen con un techo de indice dicho a mano.
    ///
    /// # Errores
    ///
    /// Si no se puede crear el directorio.
    pub fn con_tope(raiz: &Path, entradas: usize) -> Result<Almacen, Error> {
        std::fs::create_dir_all(raiz)?;
        Ok(Almacen {
            raiz: raiz.to_path_buf(),
            indice: Indice::con_tope(entradas),
            bytes: BTreeMap::new(),
        })
    }

    /// El fichero de una particion.
    #[must_use]
    pub fn camino(&self, p: Particion) -> PathBuf {
        self.raiz.join(format!("{}.pcap", p.nombre()))
    }

    /// Guarda los paquetes de una entidad en su particion.
    ///
    /// Devuelve el cursor de la entrada creada. Los paquetes se **anaden** al
    /// fichero de la particion, en secuencial: no se reescribe nada de lo que ya
    /// habia, que es lo que hace que el coste de guardar no crezca con lo
    /// guardado.
    ///
    /// # Errores
    ///
    /// Si no se puede escribir el fichero.
    pub fn guardar(
        &mut self,
        entidad: &Eid,
        politica: Politica,
        paquetes: &[Paquete],
        bytes_tapados: u64,
    ) -> Result<Option<Cursor>, Error> {
        if paquetes.is_empty() {
            return Ok(None);
        }
        let cuando_ns = paquetes[0].cuando_ns;
        let particion = Particion::de(cuando_ns, politica);
        let camino = self.camino(particion);
        let existia = camino.exists();

        // La cabecera global solo va la primera vez: un PCAP con dos cabeceras
        // no lo lee nadie.
        let mut escritor = Escritor::nuevo(pcap::ENLACE_IP_CRUDA, u32::MAX);
        for p in paquetes {
            escritor.anadir(p.cuando_ns, &p.datos, p.datos.len());
        }
        let contenido = escritor.terminar();
        let cuerpo = if existia {
            &contenido[pcap::CABECERA_GLOBAL..]
        } else {
            &contenido[..]
        };

        let desde = std::fs::metadata(&camino).map(|m| m.len()).unwrap_or(0);
        usar_anexando(&camino, cuerpo)?;
        *self.bytes.entry(particion).or_insert(0) += cuerpo.len() as u64;

        let cursor = self.indice.anadir(Entrada {
            entidad: entidad.clone(),
            cuando_ns,
            particion,
            desde,
            bytes: cuerpo.len() as u64,
            paquetes: paquetes.len() as u32,
            politica,
            caducidad: Caducidad::de_politica(politica),
            bytes_tapados,
        });
        Ok(Some(cursor))
    }

    /// Busca el trafico de una entidad.
    #[must_use]
    pub fn buscar(&self, entidad: &Eid, desde: Option<Cursor>, tope: usize) -> Respuesta {
        let p = self.indice.buscar(entidad, desde, tope);
        let mut particiones: Vec<Particion> = p.entradas.iter().map(|e| e.particion).collect();
        particiones.sort_unstable();
        particiones.dedup();
        Respuesta {
            entradas: p.entradas,
            siguiente: p.siguiente,
            purgadas: p.purgadas,
            desbordadas: p.desbordadas,
            particiones_abiertas: particiones.len(),
        }
    }

    /// Lee los paquetes de una entrada.
    ///
    /// # Errores
    ///
    /// Si el fichero no esta o no es un PCAP legible. Una particion ilegible se
    /// declara y no se ignora: es trafico que se creia tener.
    pub fn leer(&self, e: &Entrada, tope: usize) -> Result<Vec<Paquete>, Error> {
        let camino = self.camino(e.particion);
        let bytes = std::fs::read(&camino)?;
        let desde = usize::try_from(e.desde).unwrap_or(usize::MAX);
        // La entrada apunta a su sitio dentro del fichero; si es la primera, ese
        // sitio incluye la cabecera global.
        let trozo: Vec<u8> = if desde == 0 {
            bytes
        } else {
            let mut v = bytes[..pcap::CABECERA_GLOBAL.min(bytes.len())].to_vec();
            v.extend_from_slice(bytes.get(desde..).unwrap_or(&[]));
            v
        };
        let lectura = pcap::leer(&trozo, tope).map_err(|porque| Error::Ilegible {
            particion: e.particion.nombre(),
            porque,
        })?;
        Ok(lectura
            .paquetes
            .into_iter()
            .map(|l| Paquete {
                cuando_ns: l.cuando_ns,
                datos: l.datos,
            })
            .collect())
    }

    /// Purga una particion: **borra su fichero**.
    ///
    /// Es un `unlink`, no un recorrido de filas. El espacio vuelve entero y de
    /// una vez, que es la unica forma de que la purga acabe en un almacen de
    /// terabytes.
    ///
    /// # Errores
    ///
    /// Si el fichero existe y no se puede borrar. Que no exista **no es un
    /// error**: purgar dos veces lo mismo tiene que ser inocuo, o una purga que
    /// se reintenta despues de un corte deja el almacen bloqueado.
    pub fn purgar(&mut self, p: Particion) -> Result<u64, Error> {
        let camino = self.camino(p);
        match std::fs::remove_file(&camino) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Fichero(e)),
        }
        self.bytes.remove(&p);
        Ok(self.indice.purgar(p))
    }

    /// Purga todo lo caducado a fecha de `hoy_dia`.
    ///
    /// # Errores
    ///
    /// Si alguno de los ficheros no se puede borrar.
    pub fn purgar_caducadas(&mut self, hoy_dia: u32) -> Result<u64, Error> {
        let caducadas: Vec<Particion> = self
            .indice
            .particiones()
            .into_iter()
            .map(|(p, _)| p)
            .filter(|p| p.caducada(hoy_dia, Caducidad::de_politica(p.politica)))
            .collect();
        let mut fuera = 0;
        for p in caducadas {
            fuera += self.purgar(p)?;
        }
        Ok(fuera)
    }

    /// Cuanto ocupa, por politica.
    #[must_use]
    pub fn ocupacion(&self) -> Ocupacion {
        let mut por_politica: BTreeMap<&'static str, u64> = BTreeMap::new();
        for (p, n) in &self.bytes {
            *por_politica.entry(p.politica.nombre()).or_insert(0) += n;
        }
        Ocupacion {
            por_politica,
            particiones: self.bytes.len(),
        }
    }

    /// El indice, para consultarlo.
    #[must_use]
    pub fn indice(&self) -> &Indice {
        &self.indice
    }
}

/// Anexa al final de un fichero, creandolo si no esta.
fn usar_anexando(camino: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(camino)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::entidad;

    fn temporal(nombre: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("aegis-almacen-{nombre}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn paquetes(n: usize, cuando_ns: u64) -> Vec<Paquete> {
        (0..n)
            .map(|i| Paquete {
                cuando_ns: cuando_ns + i as u64,
                datos: format!("paquete numero {i}").into_bytes(),
            })
            .collect()
    }

    fn dia(n: u64) -> u64 {
        n * 86_400_000_000_000
    }

    #[test]
    fn lo_guardado_se_lee_igual_y_lo_lee_cualquier_herramienta() {
        // La captura es una prueba, y una prueba que solo puede leer la
        // herramienta que la produjo no vale delante de nadie.
        let raiz = temporal("ida-y-vuelta");
        let mut a = Almacen::nuevo(&raiz).expect("se crea");
        let m = entidad::maquina("portatil-1");
        let ps = paquetes(5, dia(1));
        a.guardar(&m, Politica::Completo, &ps, 0)
            .expect("se guarda");

        let r = a.buscar(&m, None, 10);
        assert_eq!(r.entradas.len(), 1);
        let leidos = a.leer(&r.entradas[0], 100).expect("se lee");
        assert_eq!(leidos, ps);

        // Y el fichero es un PCAP de verdad, con su cabecera global.
        let bytes = std::fs::read(a.camino(r.entradas[0].particion)).expect("existe");
        assert_eq!(
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            pcap::MAGIA_NANO
        );
        let _ = std::fs::remove_dir_all(&raiz);
    }

    #[test]
    fn dos_guardados_seguidos_no_parten_el_fichero() {
        // Un PCAP con dos cabeceras globales no lo lee nadie, y es el fallo que
        // se comete anexando sin pensar.
        let raiz = temporal("anexar");
        let mut a = Almacen::nuevo(&raiz).expect("se crea");
        let m = entidad::maquina("m");
        a.guardar(&m, Politica::Completo, &paquetes(3, dia(2)), 0)
            .expect("primera");
        a.guardar(&m, Politica::Completo, &paquetes(4, dia(2) + 1000), 0)
            .expect("segunda");

        let bytes =
            std::fs::read(a.camino(Particion::de(dia(2), Politica::Completo))).expect("existe");
        let l = pcap::leer(&bytes, 100).expect("un PCAP con siete paquetes");
        assert_eq!(l.paquetes.len(), 7);
        assert!(!l.cortado);
        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// LA propiedad del almacen: buscar el trafico de una entidad es mirar en su
    /// sitio, y la busqueda dice cuantas particiones tuvo que abrir.
    #[test]
    fn buscar_por_entidad_no_recorre_el_almacen_entero() {
        let raiz = temporal("por-entidad");
        let mut a = Almacen::nuevo(&raiz).expect("se crea");
        let buscada = entidad::maquina("la-que-importa");
        for n in 0..30u64 {
            let otra = entidad::maquina(&format!("otra-{n}"));
            a.guardar(&otra, Politica::Completo, &paquetes(2, dia(n)), 0)
                .expect("se guarda");
        }
        a.guardar(&buscada, Politica::Completo, &paquetes(2, dia(7)), 0)
            .expect("se guarda");

        let r = a.buscar(&buscada, None, 100);
        assert_eq!(r.entradas.len(), 1);
        assert_eq!(
            r.particiones_abiertas, 1,
            "buscar una entidad no puede abrir las treinta particiones"
        );
        let _ = std::fs::remove_dir_all(&raiz);
    }

    #[test]
    fn purgar_es_borrar_un_fichero_y_el_espacio_vuelve_entero() {
        let raiz = temporal("purgar");
        let mut a = Almacen::nuevo(&raiz).expect("se crea");
        let m = entidad::maquina("m");
        a.guardar(&m, Politica::Completo, &paquetes(50, dia(3)), 0)
            .expect("se guarda");
        let p = Particion::de(dia(3), Politica::Completo);
        assert!(a.camino(p).exists());
        assert!(a.ocupacion().total() > 0);

        assert_eq!(a.purgar(p).expect("se purga"), 1);
        assert!(!a.camino(p).exists(), "purgar es borrar el fichero");
        assert_eq!(a.ocupacion().total(), 0);

        // Y purgar dos veces lo mismo es inocuo: una purga que se reintenta
        // despues de un corte no puede dejar el almacen bloqueado.
        assert_eq!(a.purgar(p).expect("otra vez"), 0);
        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// «No hubo» y «lo hubo y ya no esta» son cosas distintas, y confundirlas es
    /// como se cierra un incidente en falso.
    #[test]
    fn una_busqueda_dice_lo_que_ya_no_esta() {
        let raiz = temporal("purgadas");
        let mut a = Almacen::nuevo(&raiz).expect("se crea");
        let m = entidad::maquina("m");
        for n in 0..5u64 {
            a.guardar(&m, Politica::Completo, &paquetes(2, dia(n)), 0)
                .expect("se guarda");
        }
        a.purgar(Particion::de(dia(0), Politica::Completo))
            .expect("se purga");
        a.purgar(Particion::de(dia(1), Politica::Completo))
            .expect("se purga");

        let r = a.buscar(&m, None, 100);
        assert_eq!(r.entradas.len(), 3);
        assert_eq!(r.purgadas, 2);
        assert!(r.frase().contains("ya no estan"), "{}", r.frase());
        let _ = std::fs::remove_dir_all(&raiz);
    }

    #[test]
    fn lo_caducado_se_va_solo_y_cada_politica_a_su_ritmo() {
        let raiz = temporal("caducidad");
        let mut a = Almacen::nuevo(&raiz).expect("se crea");
        let m = entidad::maquina("m");
        a.guardar(&m, Politica::Cabeceras, &paquetes(1, dia(0)), 0)
            .expect("se guarda");
        a.guardar(&m, Politica::Completo, &paquetes(1, dia(0)), 0)
            .expect("se guarda");

        // A los cien dias se va lo de cabeceras (treinta) y no lo completo
        // (ciento ochenta).
        assert_eq!(a.purgar_caducadas(100).expect("purga"), 1);
        let r = a.buscar(&m, None, 10);
        assert_eq!(r.entradas.len(), 1);
        assert_eq!(r.entradas[0].politica, Politica::Completo);

        assert_eq!(a.purgar_caducadas(200).expect("purga"), 1);
        assert_eq!(a.buscar(&m, None, 10).entradas.len(), 0);
        let _ = std::fs::remove_dir_all(&raiz);
    }

    #[test]
    fn la_ocupacion_se_reparte_por_politica() {
        // Es lo que permite contestar «cuanto disco se va en trafico que nadie
        // acuso», que es la pregunta que decide si la retencion selectiva vale.
        let raiz = temporal("ocupacion");
        let mut a = Almacen::nuevo(&raiz).expect("se crea");
        let m = entidad::maquina("m");
        a.guardar(&m, Politica::Completo, &paquetes(100, dia(1)), 0)
            .expect("se guarda");
        a.guardar(&m, Politica::Cabeceras, &paquetes(5, dia(1)), 0)
            .expect("se guarda");
        let o = a.ocupacion();
        assert_eq!(o.particiones, 2);
        assert!(o.por_politica["completo"] > o.por_politica["cabeceras"]);
        assert_eq!(o.total(), o.por_politica.values().sum::<u64>());
        let _ = std::fs::remove_dir_all(&raiz);
    }

    #[test]
    fn guardar_nada_no_crea_una_particion_vacia() {
        let raiz = temporal("vacio");
        let mut a = Almacen::nuevo(&raiz).expect("se crea");
        let m = entidad::maquina("m");
        assert_eq!(
            a.guardar(&m, Politica::Completo, &[], 0).expect("nada"),
            None
        );
        assert_eq!(a.ocupacion().particiones, 0);
        assert_eq!(a.buscar(&m, None, 10).entradas.len(), 0);
        let _ = std::fs::remove_dir_all(&raiz);
    }

    #[test]
    fn una_particion_ilegible_se_declara_y_no_se_ignora() {
        // Una particion que no se puede leer es trafico que se creia tener y no
        // se tiene. Devolver una lista vacia lo convertiria en «no hubo nada».
        let raiz = temporal("ilegible");
        let mut a = Almacen::nuevo(&raiz).expect("se crea");
        let m = entidad::maquina("m");
        a.guardar(&m, Politica::Completo, &paquetes(2, dia(1)), 0)
            .expect("se guarda");
        let e = a.buscar(&m, None, 10).entradas.remove(0);
        std::fs::write(a.camino(e.particion), b"esto ya no es un pcap").expect("se pisa");

        match a.leer(&e, 10) {
            Err(Error::Ilegible { particion, .. }) => {
                assert!(particion.contains("completo"), "{particion}");
            }
            otro => panic!("tenia que declararse ilegible: {otro:?}"),
        }
        let _ = std::fs::remove_dir_all(&raiz);
    }

    #[test]
    fn el_indice_del_almacen_tiene_techo_y_lo_que_se_cae_lo_dice() {
        // El almacen recibe lo que le manden mil agentes. Un indice que crezca
        // con lo que mandan los demas es la misma arma que en el agente, solo que
        // con mas memoria detras. Aqui se comprueba con un techo pequeno, que es
        // el mismo codigo que con el de dos millones.
        let raiz = temporal("techo-indice");
        let mut a = Almacen::con_tope(&raiz, 4).expect("se crea");
        let m = entidad::maquina("la-que-manda-mucho");
        for n in 1..=10u64 {
            a.guardar(&m, Politica::Completo, &paquetes(1, dia(n)), 0)
                .expect("se guarda");
        }

        let r = a.buscar(&m, None, 100);
        assert_eq!(r.entradas.len(), 4, "el indice paso de su techo");
        assert_eq!(r.desbordadas, 6);
        assert_eq!(
            r.purgadas, 0,
            "esto no es caducidad y no se cuenta como tal"
        );

        // Y la frase lo dice con todas las letras, que es lo que lee el analista.
        assert!(
            r.frase().contains("el indice se lleno"),
            "la frase se calla el desbordamiento: {}",
            r.frase()
        );
        assert!(!r.frase().contains("purgo por caducidad"), "{}", r.frase());

        // Lo que sigue en el indice se puede leer de verdad: el desalojo quita la
        // entrada, no rompe el fichero.
        let leidos = a.leer(&r.entradas[0], 10).expect("se lee");
        assert_eq!(leidos.len(), 1);
        let _ = std::fs::remove_dir_all(&raiz);
    }
}
