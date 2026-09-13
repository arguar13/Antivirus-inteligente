//! El lado del anfitrion del canal: todo lo que llega lo escribio el malware.
//!
//! # Por que un error de protocolo cierra el canal y no se resincroniza
//!
//! Lo obvio ante una trama corrupta seria buscar la siguiente marca y seguir. Es
//! justo lo que no se puede hacer: si el invitado puede desincronizar el flujo a
//! voluntad, puede colocar la marca donde quiera y **fabricar tramas** dentro de
//! lo que el anfitrion cree que es carga. Resincronizar convierte un canal en un
//! sitio donde el malware escribe lo que le parece.
//!
//! Asi que un error de protocolo termina la recepcion. Lo recibido hasta ese
//! punto **sigue siendo evidencia valida** —esa es la parte que importa— y la
//! ruptura se anota como anomalia. El invitado tenia un trabajo: hablar el
//! protocolo. Si no lo hace, lo que diga a partir de ahi no vale.
//!
//! # El hueco en la numeracion es evidencia, no un fallo
//!
//! El agente invitado adelanta el numero de secuencia aunque no consiga escribir.
//! Un hueco significa que genero mas de lo que el canal admitia, o que alguien lo
//! mato a mitad. Las dos cosas son hechos del comportamiento de la muestra y van
//! al informe.
//!
//! Abortar ante un hueco seria peor que inutil: le daria al malware una forma
//! trivial de destruir su propio informe —generar eventos a toda velocidad hasta
//! provocar la perdida— y se llama a eso «no hubo traza».
//!
//! # Lo que el invitado dice y lo que de verdad llego
//!
//! La trama final lleva cuantos eventos dice el invitado haber emitido. Es una
//! **afirmacion suya**, no un hecho: se compara con la cuenta real y la
//! discrepancia va al informe. Creersela sin contrastar seria dejar que el
//! malware decida cuanta evidencia parece haber.

use std::io::Read;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::{Duration, Instant};

use aegis_invitado::protocolo::{ErrorProtocolo, Evento, Trama, CABECERA, MAX_CARGA};

/// Algo que no cuadra en lo que subio el invitado.
///
/// Va serializado dentro del informe: las anomalias son parte de la evidencia,
/// no una nota al margen. Un informe que se guarda sin ellas se lee despues como
/// si hubiera sido completo.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Anomalia {
    /// Faltan numeros de secuencia entre dos tramas recibidas.
    Hueco {
        /// Primer numero que falta.
        desde: u64,
        /// Ultimo numero que falta.
        hasta: u64,
    },
    /// Llego dos veces el mismo numero de secuencia.
    ///
    /// No puede pasar con un agente sano, asi que o el canal se duplico o el
    /// invitado esta manipulando la traza. Se anota y la repetida se descarta.
    Repetida(u64),
    /// El flujo dejo de ser el protocolo.
    ProtocoloRoto {
        /// Numero de la ultima trama buena.
        tras_secuencia: u64,
        /// Que paso.
        detalle: String,
    },
    /// Se alcanzo un tope del anfitrion y se dejo de recibir.
    Recortada {
        /// Que tope.
        motivo: String,
    },
    /// El invitado dice haber emitido una cantidad que no cuadra con la recibida.
    DiscrepanciaFin {
        /// Lo que dijo.
        dijo: u64,
        /// Lo que llego.
        recibidos: u64,
    },
    /// El invitado nunca dijo haber terminado.
    ///
    /// Con la frontera cumpliendo su plazo, significa que lo cortaron. Sin la
    /// trama final no se sabe si la muestra acabo o si la mataron a mitad, y esa
    /// diferencia cambia como se lee el informe entero.
    SinFin,
}

impl Anomalia {
    /// Codigo estable para agrupar en el informe.
    #[must_use]
    pub fn codigo(&self) -> &'static str {
        match self {
            Anomalia::Hueco { .. } => "hueco",
            Anomalia::Repetida(_) => "repetida",
            Anomalia::ProtocoloRoto { .. } => "protocolo-roto",
            Anomalia::Recortada { .. } => "recortada",
            Anomalia::DiscrepanciaFin { .. } => "discrepancia-fin",
            Anomalia::SinFin => "sin-fin",
        }
    }

    /// Explicacion para quien lee el informe.
    #[must_use]
    pub fn detalle(&self) -> String {
        match self {
            Anomalia::Hueco { desde, hasta } => format!(
                "faltan los eventos {desde} a {hasta}: el invitado genero mas de lo que el canal \
                 admitia, o lo mataron a mitad"
            ),
            Anomalia::Repetida(s) => {
                format!("el evento {s} llego dos veces: un agente sano no hace eso")
            }
            Anomalia::ProtocoloRoto {
                tras_secuencia,
                detalle,
            } => format!(
                "el flujo dejo de ser el protocolo tras el evento {tras_secuencia} ({detalle}); \
                 no se resincroniza, porque eso le dejaria al invitado fabricar tramas"
            ),
            Anomalia::Recortada { motivo } => {
                format!("se dejo de recibir al llegar al tope de {motivo}")
            }
            Anomalia::DiscrepanciaFin { dijo, recibidos } => {
                format!("el invitado dice haber emitido {dijo} eventos y llegaron {recibidos}")
            }
            Anomalia::SinFin => {
                "el invitado nunca dijo haber terminado: no se sabe si la muestra acabo o si la \
                 mataron a mitad"
                    .to_string()
            }
        }
    }

    /// Si la anomalia deja el informe incompleto.
    #[must_use]
    pub fn deja_hueco(&self) -> bool {
        matches!(
            self,
            Anomalia::Hueco { .. }
                | Anomalia::ProtocoloRoto { .. }
                | Anomalia::Recortada { .. }
                | Anomalia::SinFin
        )
    }
}

/// Topes que el anfitrion aplica a lo que sube el invitado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Topes {
    /// Eventos maximos que se guardan.
    pub max_eventos: u64,
    /// Bytes maximos que se leen del canal.
    pub max_bytes: u64,
}

impl Default for Topes {
    fn default() -> Topes {
        Topes {
            max_eventos: 200_000,
            // 200.000 eventos por una carga media holgada. El tope de bytes
            // existe aparte del de eventos porque un invitado puede mandar pocas
            // tramas enormes en vez de muchas pequenas, y sin este tope esa
            // seria la forma barata de comerse la memoria del anfitrion.
            max_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Lo que se saco del canal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recepcion {
    /// Las tramas buenas, en el orden en que llegaron.
    pub tramas: Vec<Trama>,
    /// Lo que no cuadro.
    pub anomalias: Vec<Anomalia>,
    /// Bytes leidos del canal.
    pub bytes: u64,
}

impl Recepcion {
    /// Eventos recibidos.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tramas.len()
    }

    /// Si no llego nada.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tramas.is_empty()
    }

    /// Si la traza esta completa y sin agujeros.
    ///
    /// Un `false` **no** dice que la muestra sea inofensiva: dice que el informe
    /// esta incompleto. Son cosas distintas y un sandbox honesto no las mezcla.
    #[must_use]
    pub fn completa(&self) -> bool {
        !self.anomalias.iter().any(Anomalia::deja_hueco)
    }

    /// Los eventos, sin la envoltura de trama.
    #[must_use]
    pub fn eventos(&self) -> Vec<&Evento> {
        self.tramas.iter().map(|t| &t.evento).collect()
    }
}

/// Acumula bytes del canal y saca tramas validadas.
#[derive(Debug)]
pub struct Receptor {
    bufer: Vec<u8>,
    recepcion: Recepcion,
    topes: Topes,
    /// Siguiente numero de secuencia esperado.
    esperada: u64,
    /// Si ya se cerro por error o por tope.
    terminado: bool,
    /// Si llego la trama final.
    vio_fin: bool,
}

impl Receptor {
    /// Un receptor con topes explicitos.
    #[must_use]
    pub fn nuevo(topes: Topes) -> Receptor {
        Receptor {
            bufer: Vec::new(),
            recepcion: Recepcion::default(),
            topes,
            esperada: 0,
            terminado: false,
            vio_fin: false,
        }
    }

    /// Si ya no acepta mas.
    #[must_use]
    pub fn terminado(&self) -> bool {
        self.terminado
    }

    /// Mete bytes recien leidos del canal.
    ///
    /// Se acepta cualquier troceado: el canal entrega los bytes cuando le parece,
    /// y una trama puede llegar partida en veinte lecturas.
    pub fn alimentar(&mut self, datos: &[u8]) {
        if self.terminado {
            return;
        }
        self.recepcion.bytes += datos.len() as u64;
        if self.recepcion.bytes > self.topes.max_bytes {
            self.recepcion.anomalias.push(Anomalia::Recortada {
                motivo: "bytes del canal".to_string(),
            });
            self.terminado = true;
            return;
        }
        self.bufer.extend_from_slice(datos);
        self.digerir();
    }

    fn digerir(&mut self) {
        let mut consumido = 0usize;
        loop {
            match Trama::de_bytes(&self.bufer[consumido..]) {
                Ok(Some((trama, n))) => {
                    consumido += n;
                    if !self.anotar(trama) {
                        break;
                    }
                }
                Ok(None) => {
                    // Falta trama por llegar. Pero si el bufer ya acumula mas de
                    // una trama entera sin que salga ninguna, el invitado esta
                    // mandando algo que nunca va a cerrar, y eso es una forma de
                    // llenar la memoria del anfitrion sin romper el protocolo.
                    if self.bufer.len() - consumido > CABECERA + MAX_CARGA {
                        self.recepcion.anomalias.push(Anomalia::ProtocoloRoto {
                            tras_secuencia: self.esperada.saturating_sub(1),
                            detalle: "una trama que no termina nunca".to_string(),
                        });
                        self.terminado = true;
                    }
                    break;
                }
                Err(e) => {
                    self.recepcion.anomalias.push(Anomalia::ProtocoloRoto {
                        tras_secuencia: self.esperada.saturating_sub(1),
                        detalle: describir(&e),
                    });
                    self.terminado = true;
                    break;
                }
            }
        }
        self.bufer.drain(..consumido);
    }

    /// Anota una trama valida. Devuelve si se puede seguir.
    fn anotar(&mut self, trama: Trama) -> bool {
        if self.recepcion.tramas.len() as u64 >= self.topes.max_eventos {
            self.recepcion.anomalias.push(Anomalia::Recortada {
                motivo: "eventos guardados".to_string(),
            });
            self.terminado = true;
            return false;
        }

        if trama.secuencia < self.esperada {
            self.recepcion
                .anomalias
                .push(Anomalia::Repetida(trama.secuencia));
            return true;
        }
        if trama.secuencia > self.esperada {
            self.recepcion.anomalias.push(Anomalia::Hueco {
                desde: self.esperada,
                hasta: trama.secuencia - 1,
            });
        }
        self.esperada = trama.secuencia + 1;

        if let Evento::Fin { emitidos, .. } = &trama.evento {
            self.vio_fin = true;
            // La cuenta que dice el invitado incluye la propia trama final, y la
            // cuenta real tambien la incluira en cuanto se anote debajo.
            let recibidos = self.recepcion.tramas.len() as u64 + 1;
            if *emitidos != self.esperada {
                self.recepcion.anomalias.push(Anomalia::DiscrepanciaFin {
                    dijo: *emitidos,
                    recibidos,
                });
            }
        }

        self.recepcion.tramas.push(trama);
        true
    }

    /// Cierra la recepcion y entrega lo que se saco.
    #[must_use]
    pub fn cerrar(mut self) -> Recepcion {
        if !self.vio_fin {
            self.recepcion.anomalias.push(Anomalia::SinFin);
        }
        self.recepcion
    }
}

fn describir(e: &ErrorProtocolo) -> String {
    format!("{e}")
}

/// Escucha en un socket de dominio Unix hasta que el invitado termine.
///
/// Es el transporte del confinamiento por espacios de nombres, y es ademas
/// **exactamente lo que Firecracker le presenta al anfitrion** al otro lado de un
/// vsock: el hipervisor traduce las conexiones vsock del invitado a conexiones a
/// un socket Unix del anfitrion. Ejercitar esto no es simular el canal, es usar
/// el mismo canal con otro productor.
///
/// # Errores
/// El error de E/S si el socket no se puede crear o aceptar.
pub fn escuchar_unix(
    ruta: &Path,
    topes: Topes,
    plazo: Duration,
) -> Result<Recepcion, std::io::Error> {
    let _ = std::fs::remove_file(ruta);
    let escucha = UnixListener::bind(ruta)?;
    escucha.set_nonblocking(true)?;

    let fin = Instant::now() + plazo;
    let mut receptor = Receptor::nuevo(topes);

    // Se espera al invitado sin bloquear: si nunca llega —porque la muestra mato
    // al agente antes de que conectara— el plazo tiene que vencer igual.
    let flujo = loop {
        match escucha.accept() {
            Ok((f, _)) => break Some(f),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= fin {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(e),
        }
    };

    let Some(mut flujo) = flujo else {
        let _ = std::fs::remove_file(ruta);
        return Ok(receptor.cerrar());
    };

    flujo.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut trozo = [0u8; 16 * 1024];
    while Instant::now() < fin && !receptor.terminado() {
        match flujo.read(&mut trozo) {
            Ok(0) => break,
            Ok(n) => receptor.alimentar(&trozo[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(_) => break,
        }
    }

    let _ = std::fs::remove_file(ruta);
    Ok(receptor.cerrar())
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_invitado::protocolo::{AccionFichero, MAGIA, VERSION};

    fn trama(sec: u64, e: Evento) -> Vec<u8> {
        Trama {
            secuencia: sec,
            evento: e,
        }
        .a_bytes()
    }

    fn llamada(sec: u64) -> Vec<u8> {
        trama(
            sec,
            Evento::Llamada {
                pid: 7,
                numero: sec,
                nombre: "openat".into(),
            },
        )
    }

    fn fin(sec: u64, emitidos: u64) -> Vec<u8> {
        trama(
            sec,
            Evento::Fin {
                codigo: 0,
                emitidos,
                completo: true,
            },
        )
    }

    // --- Lo normal ---------------------------------------------------------

    #[test]
    fn una_traza_sana_llega_entera_y_sin_anomalias() {
        let mut r = Receptor::nuevo(Topes::default());
        for i in 0..10 {
            r.alimentar(&llamada(i));
        }
        r.alimentar(&fin(10, 11));
        let rec = r.cerrar();

        assert_eq!(rec.len(), 11);
        assert!(rec.completa(), "{:?}", rec.anomalias);
        assert!(rec.anomalias.is_empty(), "{:?}", rec.anomalias);
    }

    #[test]
    fn el_canal_puede_entregar_los_bytes_como_le_de_la_gana() {
        // Una trama puede llegar partida en veinte lecturas. Un receptor que
        // exija tramas completas por lectura funciona en la prueba y falla en el
        // primer canal real.
        let mut flujo = Vec::new();
        for i in 0..5 {
            flujo.extend_from_slice(&llamada(i));
        }
        flujo.extend_from_slice(&fin(5, 6));

        let mut r = Receptor::nuevo(Topes::default());
        for b in &flujo {
            r.alimentar(&[*b]);
        }
        let rec = r.cerrar();
        assert_eq!(rec.len(), 6);
        assert!(rec.completa());
    }

    // --- Lo que el invitado puede intentar ---------------------------------

    #[test]
    fn un_hueco_en_la_secuencia_se_anota_y_no_aborta() {
        // Abortar le daria al malware una forma trivial de destruir su propio
        // informe: generar eventos a toda velocidad hasta provocar la perdida.
        let mut r = Receptor::nuevo(Topes::default());
        r.alimentar(&llamada(0));
        r.alimentar(&llamada(5)); // faltan 1..4
        r.alimentar(&fin(6, 7));
        let rec = r.cerrar();

        assert_eq!(rec.len(), 3, "lo recibido sigue siendo evidencia");
        assert!(rec
            .anomalias
            .contains(&Anomalia::Hueco { desde: 1, hasta: 4 }));
        assert!(!rec.completa(), "pero el informe NO es completo");
    }

    #[test]
    fn una_secuencia_repetida_se_descarta_y_se_anota() {
        // Un agente sano no repite. O el canal se duplico o el invitado esta
        // manipulando la traza, y las dos cosas hay que decirlas.
        let mut r = Receptor::nuevo(Topes::default());
        r.alimentar(&llamada(0));
        r.alimentar(&llamada(1));
        r.alimentar(&llamada(1));
        r.alimentar(&fin(2, 3));
        let rec = r.cerrar();

        assert_eq!(rec.len(), 3, "la repetida no entra");
        assert!(rec.anomalias.contains(&Anomalia::Repetida(1)));
    }

    #[test]
    fn el_protocolo_roto_cierra_el_canal_y_no_se_resincroniza() {
        // Resincronizar buscando la siguiente marca le dejaria al invitado
        // colocar la marca donde quiera y fabricar tramas dentro de lo que el
        // anfitrion cree que es carga.
        let mut r = Receptor::nuevo(Topes::default());
        r.alimentar(&llamada(0));
        r.alimentar(b"basura que no es el protocolo");
        // Tramas perfectamente validas DESPUES de la basura: no pueden entrar.
        r.alimentar(&llamada(1));
        r.alimentar(&fin(2, 3));
        let rec = r.cerrar();

        assert_eq!(rec.len(), 1, "solo lo anterior a la ruptura");
        assert!(rec.anomalias.iter().any(|a| a.codigo() == "protocolo-roto"));
        assert!(!rec.completa());
    }

    #[test]
    fn una_longitud_absurda_no_hace_reservar_nada() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIA);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&5u16.to_le_bytes()); // Llamada
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());

        let mut r = Receptor::nuevo(Topes::default());
        r.alimentar(&bytes);
        assert!(r.terminado(), "tiene que cortar, no esperar cuatro gigas");
        let rec = r.cerrar();
        assert!(rec.anomalias.iter().any(|a| a.codigo() == "protocolo-roto"));
    }

    #[test]
    fn una_trama_que_no_termina_nunca_no_llena_la_memoria() {
        // Sin romper el protocolo: una cabecera valida que declara una carga
        // grande y luego bytes que gotean para siempre. Es la forma de llenar la
        // memoria del anfitrion sin que nada parezca mal.
        let mut cabecera = Vec::new();
        cabecera.extend_from_slice(&MAGIA);
        cabecera.extend_from_slice(&VERSION.to_le_bytes());
        cabecera.extend_from_slice(&5u16.to_le_bytes());
        cabecera.extend_from_slice(&0u64.to_le_bytes());
        cabecera.extend_from_slice(&(MAX_CARGA as u32).to_le_bytes());

        let mut r = Receptor::nuevo(Topes::default());
        r.alimentar(&cabecera);
        for _ in 0..200 {
            if r.terminado() {
                break;
            }
            r.alimentar(&vec![0u8; 1024]);
        }
        assert!(r.terminado(), "el bufer no puede crecer sin fin");
    }

    #[test]
    fn el_tope_de_eventos_recorta_y_lo_declara() {
        let mut r = Receptor::nuevo(Topes {
            max_eventos: 5,
            max_bytes: 1 << 30,
        });
        for i in 0..50 {
            r.alimentar(&llamada(i));
        }
        let rec = r.cerrar();
        assert_eq!(rec.len(), 5);
        assert!(rec.anomalias.iter().any(|a| a.codigo() == "recortada"));
        assert!(!rec.completa());
    }

    #[test]
    fn el_tope_de_bytes_corta_aunque_las_tramas_sean_validas() {
        // Pocas tramas enormes en vez de muchas pequenas: sin este tope, seria la
        // forma barata de comerse la memoria del anfitrion.
        let mut r = Receptor::nuevo(Topes {
            max_eventos: 1_000_000,
            max_bytes: 4096,
        });
        for i in 0..200 {
            r.alimentar(&llamada(i));
            if r.terminado() {
                break;
            }
        }
        assert!(r.terminado());
        let rec = r.cerrar();
        assert!(rec.anomalias.iter().any(|a| a.codigo() == "recortada"));
    }

    #[test]
    fn lo_que_el_invitado_dice_haber_emitido_se_contrasta() {
        // Es una afirmacion suya, no un hecho: creersela seria dejar que el
        // malware decida cuanta evidencia parece haber.
        let mut r = Receptor::nuevo(Topes::default());
        r.alimentar(&llamada(0));
        r.alimentar(&llamada(1));
        r.alimentar(&fin(2, 9_999)); // miente
        let rec = r.cerrar();

        match rec
            .anomalias
            .iter()
            .find(|a| a.codigo() == "discrepancia-fin")
        {
            Some(Anomalia::DiscrepanciaFin { dijo, recibidos }) => {
                assert_eq!(*dijo, 9_999);
                assert_eq!(*recibidos, 3);
            }
            otro => panic!("tenia que cazarse la mentira, hubo {otro:?}"),
        }
    }

    #[test]
    fn una_traza_sin_trama_final_se_marca() {
        // Sin el fin no se sabe si la muestra acabo o si la mataron a mitad, y
        // esa diferencia cambia como se lee el informe entero.
        let mut r = Receptor::nuevo(Topes::default());
        r.alimentar(&llamada(0));
        let rec = r.cerrar();
        assert!(rec.anomalias.contains(&Anomalia::SinFin));
        assert!(!rec.completa());
        assert_eq!(rec.len(), 1, "lo recibido sigue valiendo");
    }

    // --- El canal de verdad -------------------------------------------------

    #[test]
    fn el_canal_entero_funciona_contra_un_socket_real() {
        // Sin simulacion: el agente invitado escribe por su canal de verdad y el
        // anfitrion lo lee con su receptor de verdad. El socket de dominio Unix
        // es ademas lo que Firecracker le presenta al anfitrion al otro lado de
        // un vsock.
        use aegis_invitado::canal::Canal;

        let ruta =
            std::env::temp_dir().join(format!("aegis-det-canal-{}.sock", std::process::id()));
        let ruta2 = ruta.clone();

        let receptor = std::thread::spawn(move || {
            escuchar_unix(&ruta2, Topes::default(), Duration::from_secs(10)).unwrap()
        });

        // Se le da al receptor un instante para atarse al socket.
        std::thread::sleep(Duration::from_millis(100));
        let mut c = Canal::unix(&ruta).expect("el invitado tiene que poder conectar");
        c.enviar(Evento::Preparado {
            version: "prueba".into(),
        });
        c.enviar(Evento::Fichero {
            pid: 42,
            accion: AccionFichero::Escribe,
            ruta: "/home/victima/nomina.xlsx.cifrado".into(),
            bytes: 8192,
        });
        c.cerrar(0, true);

        let rec = receptor.join().unwrap();
        assert!(rec.len() >= 3, "llegaron {} tramas", rec.len());
        assert!(rec.completa(), "{:?}", rec.anomalias);
        assert!(rec.eventos().iter().any(|e| matches!(
            e,
            Evento::Fichero { ruta, .. } if ruta.contains("cifrado")
        )));
    }

    #[test]
    fn un_invitado_que_nunca_conecta_no_cuelga_al_anfitrion() {
        // Si la muestra mata al agente antes de que conecte, el anfitrion tiene
        // que vencer el plazo igual. Quedarse esperando seria un puesto de
        // detonacion bloqueado para siempre.
        let ruta = std::env::temp_dir().join(format!("aegis-det-mudo-{}.sock", std::process::id()));
        let inicio = Instant::now();
        let rec = escuchar_unix(&ruta, Topes::default(), Duration::from_millis(300)).unwrap();
        assert!(inicio.elapsed() < Duration::from_secs(5));
        assert!(rec.is_empty());
        assert!(rec.anomalias.contains(&Anomalia::SinFin));
    }
}
