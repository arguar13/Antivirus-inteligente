//! El rasgo que todo disector cumple, y los dos techos que lo hacen seguro.
//!
//! # Sans-IO: entra un `&[u8]`, sale una lista de hechos
//!
//! Ningun disector de este crate abre un socket, lee un fichero ni mira el reloj.
//! Recibe bytes y devuelve hechos.
//!
//! Eso no es purismo. Es lo que permite construir **cada ataque entero** en una
//! prueba: el paquete malformado, la secuencia fuera de orden, el campo de
//! longitud que miente. Sin sans-IO, probar esos casos exige montar un servidor,
//! y entonces la prueba tiene condiciones de carrera y acaba desactivada.
//!
//! # Los dos techos, y por que uno no basta
//!
//! Un disector guarda estado por flujo: lo que lleva visto de un mensaje que
//! todavia no ha terminado. Acotar ese estado por flujo es lo obvio y **no es una
//! cota**: el atacante elige tambien el numero de flujos, asi que mil flujos de
//! un kilobyte cada uno son un megabyte que el atacante decide.
//!
//! De ahi los dos:
//!
//! - [`MAX_ESTADO_POR_FLUJO`], que acota lo que un flujo puede hacer reservar.
//! - [`MAX_ESTADO_GLOBAL`], que acota lo que TODOS juntos pueden. Cuando se llega,
//!   se sueltan estados y **se cuenta**, porque un sensor que suelta estado en
//!   silencio deja de ver cosas sin que nadie se entere.
//!
//! Es la invariante 9 del encargo, y `aegis-wire` ya la cumplia para su propio
//! reensamblado: lo que este crate anade tiene que caber bajo el techo que ya
//! existe, no inventarse uno nuevo al lado.
//!
//! # El sensor no puede ser un amplificador
//!
//! Ningun disector responde, refleja ni genera trafico. El rasgo no tiene forma
//! de hacerlo: devuelve hechos, no bytes para enviar. Es la invariante 10, y se
//! verifica por lo que falta.

use std::collections::BTreeMap;

use aegis_wire::hecho::Hecho;

use crate::cobertura::Cobertura;

/// Lo que un disector necesita saber del flujo para decidir.
///
/// **No incluye forma de responder.** Ver la cabecera del modulo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contexto {
    /// Puerto de destino, como desempate y nunca como criterio principal.
    pub puerto_destino: u16,
    /// Puerto de origen.
    pub puerto_origen: u16,
    /// Si estos bytes van del cliente al servidor.
    pub del_cliente: bool,
    /// Si el transporte garantiza el orden.
    ///
    /// Un disector sobre UDP no puede dar por hecho que el mensaje anterior
    /// llego, y uno que lo diera por hecho leeria el segundo mensaje como la
    /// continuacion del primero.
    pub ordenado: bool,
}

impl Contexto {
    /// Un contexto de TCP del cliente al servidor.
    pub fn tcp_cliente(puerto_destino: u16) -> Contexto {
        Contexto {
            puerto_destino,
            puerto_origen: 40000,
            del_cliente: true,
            ordenado: true,
        }
    }

    /// Un contexto de TCP del servidor al cliente.
    pub fn tcp_servidor(puerto_origen: u16) -> Contexto {
        Contexto {
            puerto_destino: 40000,
            puerto_origen,
            del_cliente: false,
            ordenado: true,
        }
    }

    /// Un contexto de UDP.
    pub fn udp(puerto_destino: u16) -> Contexto {
        Contexto {
            puerto_destino,
            puerto_origen: 40000,
            del_cliente: true,
            ordenado: false,
        }
    }

    /// Si alguno de los dos puertos es este.
    pub fn algun_puerto(&self, p: u16) -> bool {
        self.puerto_destino == p || self.puerto_origen == p
    }
}

/// Lo que sale de disecar unos bytes.
///
/// No deriva `Eq` —y no se fuerza— por la misma razon que [`Hecho`]: uno de sus
/// hechos lleva una entropia en coma flotante, y una igualdad total sobre un
/// `f64` seria una mentira comoda. NaN no es igual ni a si mismo, y una salida
/// que se compare mal acabaria deduplicando alertas que no son la misma.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Salida {
    /// Los hechos, para el arbitro.
    pub hechos: Vec<Hecho>,
    /// Que se entendio y que no.
    pub cobertura: Cobertura,
}

impl Salida {
    /// Nada visto.
    pub fn vacia() -> Salida {
        Salida::default()
    }

    /// Un mensaje entendido, con sus hechos.
    pub fn entendido(hechos: Vec<Hecho>) -> Salida {
        let mut c = Cobertura::nueva();
        c.entendido();
        Salida {
            hechos,
            cobertura: c,
        }
    }

    /// Un mensaje que no se pudo analizar.
    pub fn sin_analizar(m: crate::cobertura::Motivo) -> Salida {
        let mut c = Cobertura::nueva();
        c.sin_analizar(m);
        Salida {
            hechos: Vec::new(),
            cobertura: c,
        }
    }

    /// El resultado de un disector escrito sobre el lector acotado.
    ///
    /// Es el punto por el que pasa TODO error de diseccion de este crate, y por
    /// eso el motivo se traduce una sola vez y no en cada disector: con cuarenta
    /// disectores, una traduccion repetida se convierte en cuarenta criterios
    /// distintos para la misma cifra.
    pub fn de_resultado(r: aegis_wire::error::Resultado<Vec<Hecho>>) -> Salida {
        match r {
            Ok(h) => Salida::entendido(h),
            Err(e) => Salida::sin_analizar(crate::cobertura::Motivo::de_error(&e)),
        }
    }

    /// Un mensaje reconocido cuyo tipo este disector declara no analizar.
    pub fn no_implementado(hechos: Vec<Hecho>) -> Salida {
        let mut c = Cobertura::nueva();
        c.sin_analizar(crate::cobertura::Motivo::TipoNoImplementado);
        Salida {
            hechos,
            cobertura: c,
        }
    }

    /// Junta otra salida con esta.
    pub fn juntar(&mut self, otra: Salida) {
        self.hechos.extend(otra.hechos);
        self.cobertura.sumar(&otra.cobertura);
    }
}

/// Con cuanta seguridad un disector reconoce lo suyo.
///
/// # Por que hace falta declararla
///
/// Porque los protocolos no se reconocen todos igual de bien. Una trama de
/// WebSocket son **dos bytes** de marco: casi cualquier cosa encaja. Una cabecera
/// de Modbus tiene cuatro campos que se comprueban unos con otros. Un mensaje
/// NTLMSSP lleva ocho bytes de firma que no salen por casualidad.
///
/// Si el registro prueba los disectores en el orden en que se anadieron, el mas
/// debil se queda con el trafico del mas fuerte en cuanto vaya antes en la lista
/// — y eso no es una preferencia de estilo: se midio, y una trama de Modbus
/// encajaba como continuacion de WebSocket. Declarar la fuerza y probar de mas
/// fuerte a mas debil es lo que arregla eso **de raiz**, en vez de ordenar la
/// lista a mano y esperar que nadie la toque.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fuerza {
    /// Una firma fija: bytes o palabras que no salen por casualidad.
    Marca,
    /// Una cabecera con varios campos que se comprueban entre si.
    Forma,
    /// Poco marco, un puerto o una medida estadistica.
    ///
    /// Un disector de esta clase **solo** se prueba cuando ninguno de los otros
    /// dos reconocio nada. No es un demerito: hay protocolos que en el cable no
    /// se distinguen mejor, y fingir lo contrario seria peor.
    Indicio,
}

/// Lo que todo disector cumple.
///
/// **Sans-IO**: `disecar` recibe bytes y devuelve hechos. No hay en este rasgo
/// ninguna forma de enviar nada.
pub trait Disector {
    /// El nombre estable del protocolo.
    ///
    /// Aparece en el registro y en el SIEM del cliente: cambiarlo rompe sus
    /// consultas guardadas.
    fn nombre(&self) -> &'static str;

    /// Si estos bytes parecen de este protocolo.
    ///
    /// **Por contenido.** El puerto esta en el contexto y solo vale como
    /// desempate: un servidor HTTP en el 8443 sigue siendo HTTP, y confiar en el
    /// puerto es como se pierde todo lo que se mueve a un puerto raro a
    /// proposito.
    fn reconoce(&self, datos: &[u8], ctx: &Contexto) -> bool;

    /// Disecta los bytes.
    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida;

    /// Si `disecar` acepta mas que `reconoce`, y por que.
    ///
    /// # El contrato normal
    ///
    /// `disecar` **no emite hechos** sobre algo que `reconoce` rechazo. Es lo que
    /// impide que un disector afirme haber visto su protocolo donde no lo habia,
    /// y lo comprueba el barrido hostil contra todos: encontro seis disectores
    /// que lo incumplian antes de que esto estuviera escrito.
    ///
    /// # Y la excepcion, que se declara
    ///
    /// Hay protocolos donde reconocer y disecar son dos preguntas distintas.
    /// WebSocket es el caso: `reconoce` contesta «¿me quedo yo con este flujo?»
    /// y ahi dos bytes de marco no bastan; `disecar` contesta «como se lee esto,
    /// dado que el flujo YA es WebSocket», y ahi hay que poder leer —y contar—
    /// una trama que la norma prohibe, como una de cliente sin mascara.
    ///
    /// Quien este en ese caso lo dice aqui. Declararlo es la diferencia entre una
    /// excepcion pensada y un descuido.
    fn disecar_es_mas_ancho(&self) -> bool {
        false
    }

    /// Con cuanta seguridad reconoce lo suyo. Ver [`Fuerza`].
    ///
    /// El valor por defecto es [`Fuerza::Forma`], que es lo que cumple un
    /// disector escrito como toca: una cabecera con campos que se comprueban
    /// entre si. Quien tenga una firma fija o, al contrario, solo un indicio,
    /// tiene que decirlo.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    /// Los tipos de mensaje que este disector entiende.
    ///
    /// Es la mitad declarada de la cobertura: sirve para saber que se puede
    /// esperar de el **antes** de mandarle trafico.
    fn mensajes_que_entiende(&self) -> &'static [&'static str];

    /// Los que reconoce y no analiza.
    ///
    /// La otra mitad, y la que casi ningun sensor publica. Un disector que
    /// declare una lista vacia aqui esta diciendo que lo entiende todo, y eso hay
    /// que poder comprobarlo.
    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[]
    }
}

/// Cuanto estado puede guardar un solo flujo.
///
/// **Es el mismo tope que el motor ya usaba** para un bufer de aplicacion, y se
/// deriva de el en vez de repetirlo: un numero copiado a mano se separa del
/// original el dia que alguien cambia uno de los dos.
pub const MAX_ESTADO_POR_FLUJO: usize = aegis_wire::motor::MAX_BUFER_APP;

/// Cuanto estado pueden guardar TODOS los flujos juntos.
///
/// # Por que este es el que de verdad protege
///
/// Porque el atacante elige el numero de flujos. Con solo el tope por flujo, cien
/// mil flujos de sesenta y cuatro kilobytes son seis gigas que decide el
/// atacante; con este, son cuatro megas decida lo que decida.
///
/// # Y por que es EL MISMO que el del motor, no otro al lado
///
/// Porque el estado de un disector **es** un mensaje de aplicacion a medio
/// construir: exactamente lo que el motor ya presupuesta en
/// [`aegis_wire::MAX_MEMORIA_APP`]. Un crate nuevo que se declarara su propio
/// techo de treinta y dos megas no estaria cumpliendo la invariante 9, estaria
/// esquivandola: la flota acabaria con dos presupuestos que suman, y el segundo
/// no lo aprobo nadie.
///
/// Se midio antes de escribir esto: el techo de este crate empezo siendo ocho
/// veces el del motor, y la prueba del techo global lo delato.
pub const MAX_ESTADO_GLOBAL: usize = aegis_wire::MAX_MEMORIA_APP;

/// El techo de este crate no puede pasar del que el motor ya presupuestaba.
///
/// Es una comprobacion de **compilacion**, no de prueba: si alguien sube el techo
/// de los disectores por encima del del motor, el crate no compila. Una prueba se
/// puede saltar con `--skip`; esto no.
const _: () = assert!(MAX_ESTADO_GLOBAL <= aegis_wire::MAX_MEMORIA_APP);

/// Y el tope por flujo no puede pasar del global, o el global no acota nada.
const _: () = assert!(MAX_ESTADO_POR_FLUJO <= MAX_ESTADO_GLOBAL);

/// El registro de disectores, con el estado por flujo y sus dos techos.
pub struct Registro {
    disectores: Vec<Box<dyn Disector + Send + Sync>>,
    estado: BTreeMap<u64, Vec<u8>>,
    bytes: usize,
    /// Cuantos estados se soltaron por llegar al techo global.
    ///
    /// Se cuenta y se dice: un sensor que suelta estado en silencio deja de ver
    /// cosas sin que nadie se entere, que es la forma mas limpia de apagarlo.
    pub soltados: u64,
    /// Cuantas veces dos disectores de la misma fuerza reconocieron lo mismo.
    ///
    /// Una ambiguedad no es un fallo del que gana: es que dos disectores se
    /// solapan, y eso hay que saberlo. Sin este contador, el solape se resuelve
    /// en silencio por el orden de la lista, que es justo el defecto que la
    /// [`Fuerza`] viene a quitar.
    pub ambiguos: u64,
    /// Cobertura acumulada de todo lo disecado.
    pub cobertura: Cobertura,
}

impl Default for Registro {
    fn default() -> Self {
        Registro::vacio()
    }
}

impl Registro {
    /// Sin ningun disector.
    pub fn vacio() -> Registro {
        Registro {
            disectores: Vec::new(),
            estado: BTreeMap::new(),
            bytes: 0,
            soltados: 0,
            ambiguos: 0,
            cobertura: Cobertura::nueva(),
        }
    }

    /// Anade un disector.
    pub fn anadir(&mut self, d: Box<dyn Disector + Send + Sync>) {
        self.disectores.push(d);
    }

    /// Cuantos disectores hay.
    pub fn cuantos(&self) -> usize {
        self.disectores.len()
    }

    /// Los nombres de los protocolos cubiertos, ordenados.
    pub fn protocolos(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.disectores.iter().map(|d| d.nombre()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Diseca unos bytes con el disector que los reconozca.
    ///
    /// Se prueba **por contenido**, de mas fuerte a mas debil: primero los de
    /// firma fija, luego los de cabecera comprobable y solo al final los de
    /// indicio. Ver [`Fuerza`] para por que ese orden y no el de la lista.
    ///
    /// Si dentro de la misma fuerza reconoce mas de uno, gana el primero **y se
    /// cuenta**: el solape existe y callarlo lo dejaria escondido tras el orden
    /// de insercion.
    ///
    /// Si ninguno reconoce, se declara no reconocido — que es un hecho y no un
    /// silencio.
    pub fn disecar(&mut self, datos: &[u8], ctx: &Contexto) -> Salida {
        for fuerza in [Fuerza::Marca, Fuerza::Forma, Fuerza::Indicio] {
            let mut ganador: Option<&Box<dyn Disector + Send + Sync>> = None;
            let mut cuantos = 0usize;
            for d in self.disectores.iter().filter(|d| d.fuerza() == fuerza) {
                if d.reconoce(datos, ctx) {
                    cuantos += 1;
                    if ganador.is_none() {
                        ganador = Some(d);
                    }
                }
            }
            if let Some(d) = ganador {
                if cuantos > 1 {
                    self.ambiguos += 1;
                }
                let s = d.disecar(datos, ctx);
                self.cobertura.sumar(&s.cobertura);
                return s;
            }
        }
        let s = Salida::sin_analizar(crate::cobertura::Motivo::NoReconocido);
        self.cobertura.sumar(&s.cobertura);
        s
    }

    /// Cuantos disectores hay de cada fuerza.
    pub fn por_fuerza(&self, f: Fuerza) -> usize {
        self.disectores.iter().filter(|d| d.fuerza() == f).count()
    }

    /// Guarda estado de un flujo, respetando los dos techos.
    ///
    /// Devuelve si cupo. Cuando no cabe globalmente se sueltan los estados mas
    /// antiguos hasta que quepa, y se cuenta.
    pub fn guardar(&mut self, flujo: u64, datos: &[u8]) -> bool {
        if datos.len() > MAX_ESTADO_POR_FLUJO {
            return false;
        }
        let anterior = self.estado.get(&flujo).map(|v| v.len()).unwrap_or(0);
        self.bytes = self.bytes + datos.len() - anterior;
        self.estado.insert(flujo, datos.to_vec());
        // El techo GLOBAL. Sin esto, el tope por flujo lo multiplica el atacante
        // por el numero de flujos, que tambien elige el.
        while self.bytes > MAX_ESTADO_GLOBAL {
            let Some((&viejo, _)) = self.estado.iter().next() else {
                break;
            };
            if viejo == flujo && self.estado.len() == 1 {
                break;
            }
            if let Some(v) = self.estado.remove(&viejo) {
                self.bytes -= v.len();
                self.soltados += 1;
            }
        }
        self.estado.contains_key(&flujo)
    }

    /// El estado guardado de un flujo.
    pub fn estado_de(&self, flujo: u64) -> Option<&[u8]> {
        self.estado.get(&flujo).map(|v| v.as_slice())
    }

    /// Cuantos bytes de estado hay en total.
    pub fn bytes_de_estado(&self) -> usize {
        self.bytes
    }

    /// La frase con la que este registro aparece en un informe.
    pub fn frase(&self) -> String {
        let mut s = format!(
            "{} disectores cubriendo {} protocolos; {}",
            self.disectores.len(),
            self.protocolos().len(),
            self.cobertura.frase()
        );
        if self.ambiguos > 0 {
            s.push_str(&format!(
                ". En {} mensajes reconocio mas de un disector de la misma fuerza: hay \
                 solape y lo resolvio el orden",
                self.ambiguos
            ));
        }
        if self.soltados > 0 {
            s.push_str(&format!(
                ". SE SOLTARON {} estados de flujo por llegar al techo global de memoria: \
                 de esos flujos se dejo de ver lo que faltaba",
                self.soltados
            ));
        }
        s
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::cobertura::Motivo;

    /// Un disector de mentira que reconoce lo que empiece por `AB`.
    struct DeMentira;

    impl Disector for DeMentira {
        fn nombre(&self) -> &'static str {
            "de-mentira"
        }
        fn reconoce(&self, datos: &[u8], _: &Contexto) -> bool {
            datos.starts_with(b"AB")
        }
        fn disecar(&self, datos: &[u8], _: &Contexto) -> Salida {
            if datos.len() < 4 {
                return Salida::sin_analizar(Motivo::Truncado);
            }
            Salida::entendido(Vec::new())
        }
        fn mensajes_que_entiende(&self) -> &'static [&'static str] {
            &["ab-completo"]
        }
        fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
            &["ab-extendido"]
        }
    }

    fn registro() -> Registro {
        let mut r = Registro::vacio();
        r.anadir(Box::new(DeMentira));
        r
    }

    #[test]
    fn lo_que_ningun_disector_reconoce_se_declara_y_no_se_calla() {
        // Un sensor que calle lo que no entiende produce informes que parecen
        // completos. La diferencia entre «no llevaba nada» y «llevaba algo que no
        // supimos leer» es un incidente.
        let mut r = registro();
        let s = r.disecar(b"ZZZZ", &Contexto::tcp_cliente(80));
        assert!(s.hechos.is_empty());
        assert_eq!(
            s.cobertura.sin_analizar.get(&Motivo::NoReconocido),
            Some(&1)
        );
        assert!(!r.cobertura.completa());
    }

    #[test]
    fn el_reconocimiento_es_por_contenido_y_no_por_puerto() {
        // Un servidor en un puerto raro sigue hablando su protocolo, y confiar en
        // el puerto es como se pierde todo lo que se mueve a proposito.
        let mut r = registro();
        for puerto in [80u16, 8443, 31337] {
            let s = r.disecar(b"ABCD", &Contexto::tcp_cliente(puerto));
            assert!(s.cobertura.completa(), "puerto {puerto}");
        }
    }

    #[test]
    fn un_mensaje_truncado_se_declara_truncado_y_no_malformado() {
        // Son cosas distintas: uno llego a medias y el otro esta mal hecho. Quien
        // lea el recuento tiene que poder distinguir un problema de red de un
        // intento de confundir al sensor.
        let mut r = registro();
        let s = r.disecar(b"AB", &Contexto::tcp_cliente(80));
        assert_eq!(s.cobertura.sin_analizar.get(&Motivo::Truncado), Some(&1));
    }

    #[test]
    fn el_estado_de_un_flujo_tiene_tope_propio() {
        let mut r = registro();
        assert!(!r.guardar(1, &vec![0u8; MAX_ESTADO_POR_FLUJO + 1]));
        assert!(r.guardar(1, &vec![0u8; MAX_ESTADO_POR_FLUJO]));
    }

    #[test]
    fn el_techo_global_aguanta_aunque_cada_flujo_respete_el_suyo() {
        // LA invariante 9: una cota por flujo no es una cota, porque el atacante
        // elige tambien el numero de flujos. Aqui cada flujo respeta su tope y
        // entre todos intentan pasarse del global.
        let mut r = registro();
        let trozo = vec![0u8; MAX_ESTADO_POR_FLUJO];
        let cuantos = (MAX_ESTADO_GLOBAL / MAX_ESTADO_POR_FLUJO) as u64 + 50;
        for f in 0..cuantos {
            r.guardar(f, &trozo);
        }
        assert!(
            r.bytes_de_estado() <= MAX_ESTADO_GLOBAL,
            "{} bytes pasan del techo global",
            r.bytes_de_estado()
        );
        assert!(r.soltados > 0, "se tuvo que soltar estado");
        assert!(r.frase().contains("SE SOLTARON"), "{}", r.frase());
    }

    #[test]
    fn guardar_dos_veces_el_mismo_flujo_no_suma_dos_veces() {
        // Si sumara, el contador de bytes crecería sin que creciera la memoria, y
        // el techo saltaria antes de tiempo soltando estado que si cabia.
        let mut r = registro();
        r.guardar(1, &[0u8; 1000]);
        assert_eq!(r.bytes_de_estado(), 1000);
        r.guardar(1, &[0u8; 500]);
        assert_eq!(r.bytes_de_estado(), 500);
    }

    /// Un disector de marco debil no puede quedarse con el trafico de uno de
    /// firma fija por ir antes en la lista. Se midio: una trama de Modbus
    /// encajaba como continuacion de WebSocket.
    #[test]
    fn el_mas_fuerte_gana_aunque_se_anada_el_ultimo() {
        struct Debil;
        impl Disector for Debil {
            fn nombre(&self) -> &'static str {
                "debil"
            }
            fn fuerza(&self) -> Fuerza {
                Fuerza::Indicio
            }
            fn reconoce(&self, datos: &[u8], _: &Contexto) -> bool {
                !datos.is_empty()
            }
            fn disecar(&self, _: &[u8], _: &Contexto) -> Salida {
                Salida::entendido(vec![Hecho::AnomaliaDeFlujo {
                    codigo: "debil",
                    detalle: String::new(),
                }])
            }
            fn mensajes_que_entiende(&self) -> &'static [&'static str] {
                &["cualquier cosa"]
            }
        }
        struct Fuerte;
        impl Disector for Fuerte {
            fn nombre(&self) -> &'static str {
                "fuerte"
            }
            fn fuerza(&self) -> Fuerza {
                Fuerza::Marca
            }
            fn reconoce(&self, datos: &[u8], _: &Contexto) -> bool {
                datos.starts_with(b"FIRMA")
            }
            fn disecar(&self, _: &[u8], _: &Contexto) -> Salida {
                Salida::entendido(vec![Hecho::AnomaliaDeFlujo {
                    codigo: "fuerte",
                    detalle: String::new(),
                }])
            }
            fn mensajes_que_entiende(&self) -> &'static [&'static str] {
                &["lo que lleva la firma"]
            }
        }

        let mut r = Registro::vacio();
        // El debil se anade PRIMERO a proposito: con el orden de la lista, se
        // llevaria todo.
        r.anadir(Box::new(Debil));
        r.anadir(Box::new(Fuerte));
        let s = r.disecar(b"FIRMA y datos", &Contexto::tcp_cliente(80));
        assert_eq!(s.hechos[0].codigo(), "anomalia");
        assert!(
            matches!(&s.hechos[0], Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "fuerte"),
            "{:?}",
            s.hechos
        );
        // Y el debil sigue sirviendo para lo que ninguno reconoce.
        let s = r.disecar(b"otra cosa", &Contexto::tcp_cliente(80));
        assert!(
            matches!(&s.hechos[0], Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "debil"),
            "{:?}",
            s.hechos
        );
        assert_eq!(r.por_fuerza(Fuerza::Marca), 1);
        assert_eq!(r.por_fuerza(Fuerza::Indicio), 1);
    }

    /// Dos disectores de la misma fuerza que reconozcan lo mismo es un solape:
    /// existe, y resolverlo en silencio por el orden lo dejaria escondido.
    #[test]
    fn un_solape_entre_iguales_se_cuenta() {
        struct Ambos(&'static str);
        impl Disector for Ambos {
            fn nombre(&self) -> &'static str {
                self.0
            }
            fn reconoce(&self, datos: &[u8], _: &Contexto) -> bool {
                datos.starts_with(b"AB")
            }
            fn disecar(&self, _: &[u8], _: &Contexto) -> Salida {
                Salida::entendido(Vec::new())
            }
            fn mensajes_que_entiende(&self) -> &'static [&'static str] {
                &["lo que empieza por AB"]
            }
        }
        let mut r = Registro::vacio();
        r.anadir(Box::new(Ambos("uno")));
        r.anadir(Box::new(Ambos("otro")));
        r.disecar(b"ABCD", &Contexto::tcp_cliente(80));
        assert_eq!(r.ambiguos, 1);
        assert!(r.frase().contains("solape"), "{}", r.frase());
    }

    #[test]
    fn todo_disector_declara_lo_que_entiende_y_lo_que_no() {
        // La mitad que casi ningun sensor publica: se puede saber que esperar de
        // un disector antes de mandarle trafico.
        let d = DeMentira;
        assert!(!d.mensajes_que_entiende().is_empty());
        assert!(!d.mensajes_que_no_analiza().is_empty());
    }

    #[test]
    fn el_registro_no_tiene_forma_de_responder() {
        // La invariante 10, comprobada por lo que se puede escribir aqui: si
        // `Salida` llevara bytes para enviar, esta prueba los usaria y habria que
        // cambiarla — que es el momento en que alguien tiene que explicarse.
        let s = Salida::entendido(Vec::new());
        assert!(s.hechos.is_empty());
        assert_eq!(s.cobertura.entendidos, 1);
    }
}
