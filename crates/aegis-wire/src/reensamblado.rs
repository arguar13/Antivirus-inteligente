//! Reensamblado de TCP resistente a evasion.
//!
//! # El ataque que este modulo existe para no sufrir
//!
//! Un IDS que reensambla TCP tiene que decidir que hacer cuando dos segmentos
//! **se solapan con contenido distinto**. Por ejemplo, el atacante manda:
//!
//! ```text
//!   secuencia 100, 4 bytes: "GET "     <- el IDS lo ve
//!   secuencia 100, 4 bytes: "PUT "     <- retransmision con OTRO contenido
//! ```
//!
//! El sistema operativo de la victima aplica **su** politica al decidir cual se
//! queda. Si el IDS aplica una politica distinta, reconstruye un flujo que **no
//! es el que el endpoint va a ver**, y a partir de ahi todas sus reglas miran
//! datos que nunca existieron. Eso no es un fallo de deteccion: es una **evasion
//! completa y silenciosa**, y es la tecnica que Ptacek y Newsham describieron en
//! 1998 y que sigue funcionando contra productos mal hechos.
//!
//! Lo mismo con segmentos que se solapan parcialmente, con los que empiezan
//! antes del final del anterior, y con los que llegan fuera de orden.
//!
//! # La respuesta: la politica es EXPLICITA y se declara
//!
//! No existe «la» politica correcta, porque no hay una: depende del sistema
//! operativo del destino. Lo que si es incorrecto es **tener una politica
//! implicita** —la que salga de como se escribio el bucle— porque entonces nadie
//! sabe cual es y nadie puede razonar sobre la evasion.
//!
//! Aqui la politica es un enumerado ([`Politica`]), se elige a proposito, y el
//! reensamblado **cuenta los solapes contradictorios** que ve. Ese contador es
//! una senal de seguridad de primer orden: el trafico legitimo NO solapa con
//! contenido distinto, practicamente nunca. Cuando pasa, o hay un intermediario
//! roto o alguien esta intentando evadir.
//!
//! # Y las cotas, porque el atacante controla la secuencia
//!
//! El numero de secuencia lo elige el emisor. Sin cotas, mandar un segmento en
//! la secuencia `X` y otro en `X + 2^31` hace que un reensamblador ingenuo
//! reserve dos gigas. Aqui hay tope de huecos, tope de bytes retenidos y
//! expulsion del mas antiguo, y todo ello se cuenta y se declara.

use std::collections::BTreeMap;

/// Politica de resolucion de solapes, por sistema operativo del destino.
///
/// El nombre de cada variante es el del sistema cuyo comportamiento imita, tal y
/// como lo documenta la literatura de normalizacion de trafico.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Politica {
    /// Gana el primero que llego: los bytes ya entregados no se reescriben.
    ///
    /// Es el comportamiento de los BSD y el de la mayoria de pilas modernas de
    /// Linux para datos ya confirmados. Es tambien el **mas seguro por
    /// defecto**: un atacante no puede reescribir hacia atras lo que el IDS ya
    /// analizo, que es justo lo que busca al solapar.
    #[default]
    PrimeroGana,

    /// Gana el ultimo: un segmento nuevo sobrescribe lo que hubiera.
    ///
    /// Lo hacen algunas pilas antiguas de Windows. Se ofrece porque, si el
    /// destino se comporta asi, imitarlo es lo que evita la evasion; elegirlo
    /// sin saber que el destino lo hace ABRE la evasion en vez de cerrarla.
    UltimoGana,
}

/// Tope de huecos simultaneos en un flujo.
///
/// Un flujo legitimo tiene unos pocos huecos transitorios. Cien es holgado y
/// corta de raiz que un atacante mande un byte cada 2^20 posiciones para hacer
/// crecer el mapa.
pub const MAX_HUECOS: usize = 100;

/// Tope de bytes retenidos fuera de orden por sentido.
pub const MAX_RETENIDO: usize = 1024 * 1024;

/// Distancia maxima por delante de la siguiente secuencia esperada.
///
/// Un segmento mas alla de esto no es «fuera de orden», es basura o un intento
/// de reservar memoria: se descarta y se cuenta.
pub const MAX_ADELANTO: u32 = 1 << 22;

/// Ventana de bytes YA ENTREGADOS que se conserva para poder comparar.
///
/// # Por que hace falta conservar nada
///
/// Un reensamblador que tira los bytes en cuanto los entrega solo puede detectar
/// una contradiccion mientras los dos segmentos siguen retenidos, es decir, solo
/// cuando el solape llega **antes** de que el hueco se tape. Pero la forma
/// clasica del ataque es justo la contraria:
///
/// ```text
///   secuencia 100: "GET /publico"   <- se entrega, el IDS la analiza
///   secuencia 100: "GET /secreto"   <- llega DESPUES, sobre terreno entregado
/// ```
///
/// Sin historia, el segundo segmento es indistinguible de una retransmision
/// normal y el ataque pasa contado como ruido. Con historia se compara byte a
/// byte y la contradiccion se delata.
///
/// # Y por que es una ventana y no todo el flujo
///
/// Guardar el flujo entero es exactamente la memoria que el atacante quiere que
/// se reserve. Cuatro kilobytes cubren de sobra la distancia a la que se juega
/// un solape util —una peticion, una orden, una cabecera— y el limite se
/// DECLARA: una contradiccion mas atras de esta ventana se cuenta como
/// retransmision, porque a esa distancia ya no se puede afirmar otra cosa.
pub const MAX_HISTORIA: usize = 4096;

/// Lo que el reensamblado observo y que el analista necesita saber.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Anomalias {
    /// Segmentos que solapaban con **el mismo** contenido: retransmision normal.
    pub solapes_identicos: u64,
    /// Segmentos que solapaban con contenido **DISTINTO**.
    ///
    /// Esta es la senal. El trafico legitimo no hace esto.
    pub solapes_contradictorios: u64,
    /// Segmentos descartados por caer demasiado por delante.
    pub descartes_por_adelanto: u64,
    /// Segmentos descartados porque el flujo ya no tenia sitio.
    pub descartes_por_memoria: u64,
    /// Bytes que se dieron por perdidos al expulsar un hueco.
    pub bytes_perdidos: u64,
    /// Segmentos enteramente por detras de lo ya entregado.
    pub retransmisiones: u64,
}

impl Anomalias {
    /// Si hay indicios de un intento de evasion.
    ///
    /// Un solo solape contradictorio ya basta para decirlo: no es ruido.
    #[must_use]
    pub fn hay_indicio_de_evasion(&self) -> bool {
        self.solapes_contradictorios > 0
    }
}

/// Un sentido de una conexion TCP, reensamblado.
#[derive(Debug, Clone)]
pub struct Sentido {
    politica: Politica,
    /// Siguiente numero de secuencia que se puede entregar.
    siguiente: u32,
    /// Si ya se vio el SYN y por tanto `siguiente` es de fiar.
    sincronizado: bool,
    /// Segmentos retenidos por estar fuera de orden, por secuencia inicial.
    huecos: BTreeMap<u32, Vec<u8>>,
    /// Bytes actualmente retenidos.
    retenido: usize,
    /// Bytes entregados en total.
    entregados: u64,
    /// Ultimos bytes entregados, para poder comparar solapes hacia atras.
    ///
    /// Ver [`MAX_HISTORIA`]: sin esto, la mitad mas peligrosa del ataque de
    /// solape se cuenta como retransmision normal.
    historia: Vec<u8>,
    /// Numero de secuencia del primer byte de `historia`.
    historia_base: u32,
    anomalias: Anomalias,
    /// Si el sentido se cerro (FIN o RST).
    cerrado: bool,
}

/// Resultado de comparar un segmento con los bytes ya entregados.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContraHistoria {
    /// Los bytes coinciden: retransmision legitima.
    Identico,
    /// Los bytes NO coinciden: intento de reescribir lo ya analizado.
    Contradictorio,
    /// Cae fuera de la ventana conservada: no se puede afirmar nada.
    ///
    /// Se distingue a proposito de `Identico`. Decir «identico» cuando en
    /// realidad no se miro es justo la mentira que abre la evasion.
    FueraDeVentana,
}

impl Sentido {
    /// Un sentido nuevo con la politica dada.
    #[must_use]
    pub fn nuevo(politica: Politica) -> Sentido {
        Sentido {
            politica,
            siguiente: 0,
            sincronizado: false,
            huecos: BTreeMap::new(),
            retenido: 0,
            entregados: 0,
            historia: Vec::new(),
            historia_base: 0,
            anomalias: Anomalias::default(),
            cerrado: false,
        }
    }

    /// Bytes que este sentido tiene reservados ahora mismo.
    ///
    /// Lo usa el motor para respetar un techo GLOBAL de memoria: la cota por
    /// flujo no acota nada si el numero de flujos no esta acotado a su vez.
    #[must_use]
    pub fn memoria(&self) -> usize {
        self.retenido + self.historia.len()
    }

    /// Anomalias observadas.
    #[must_use]
    pub fn anomalias(&self) -> &Anomalias {
        &self.anomalias
    }

    /// Bytes entregados.
    #[must_use]
    pub fn entregados(&self) -> u64 {
        self.entregados
    }

    /// Bytes retenidos ahora mismo.
    #[must_use]
    pub fn retenido(&self) -> usize {
        self.retenido
    }

    /// Huecos pendientes.
    #[must_use]
    pub fn huecos(&self) -> usize {
        self.huecos.len()
    }

    /// Si el sentido esta cerrado.
    #[must_use]
    pub fn cerrado(&self) -> bool {
        self.cerrado
    }

    /// Declara el SYN: fija el punto de partida de la secuencia.
    ///
    /// Hasta que esto ocurre, el reensamblado no sabe donde empieza el flujo. Un
    /// flujo capturado a medias (el caso normal al arrancar el sensor) se
    /// sincroniza con el primer segmento de datos que llega, y eso se DICE: los
    /// bytes anteriores no es que fueran limpios, es que no se vieron.
    pub fn sincronizar(&mut self, secuencia_inicial: u32) {
        self.siguiente = secuencia_inicial.wrapping_add(1);
        self.sincronizado = true;
    }

    /// Marca el cierre del sentido.
    pub fn cerrar(&mut self) {
        self.cerrado = true;
    }

    /// Compara un segmento contra los bytes ya entregados.
    ///
    /// Solo compara la parte que efectivamente cae dentro de la ventana; si el
    /// segmento empieza antes del inicio de la ventana, o despues de su final,
    /// devuelve [`ContraHistoria::FueraDeVentana`] en vez de inventarse un
    /// veredicto.
    fn comparar_con_historia(&self, secuencia: u32, datos: &[u8]) -> ContraHistoria {
        if self.historia.is_empty() || datos.is_empty() {
            return ContraHistoria::FueraDeVentana;
        }
        // Una secuencia anterior a la base da un numero enorme al restar en
        // aritmetica modular, y el corte de abajo la manda a FueraDeVentana,
        // que es lo correcto: esos bytes ya no estan para compararlos.
        let inicio = secuencia.wrapping_sub(self.historia_base) as usize;
        if inicio >= self.historia.len() {
            return ContraHistoria::FueraDeVentana;
        }
        let comun = (self.historia.len() - inicio).min(datos.len());
        if self.historia[inicio..inicio + comun] == datos[..comun] {
            ContraHistoria::Identico
        } else {
            ContraHistoria::Contradictorio
        }
    }

    /// Anota un solape contra terreno ya entregado en el contador que toca.
    ///
    /// Un solape contradictorio NO es una retransmision, y contarlo como tal es
    /// exactamente como se pierde el ataque.
    fn anotar_solape_hacia_atras(&mut self, secuencia: u32, datos: &[u8]) {
        match self.comparar_con_historia(secuencia, datos) {
            ContraHistoria::Contradictorio => self.anomalias.solapes_contradictorios += 1,
            ContraHistoria::Identico => self.anomalias.solapes_identicos += 1,
            ContraHistoria::FueraDeVentana => self.anomalias.retransmisiones += 1,
        }
    }

    /// Guarda en la ventana los bytes que se acaban de entregar.
    ///
    /// `inicio` es el numero de secuencia del primer byte de `datos`.
    fn recordar(&mut self, inicio: u32, datos: &[u8]) {
        if datos.is_empty() {
            return;
        }
        // Un bloque mas grande que la ventana entera: se queda solo su cola, sin
        // llegar a reservar el bloque completo.
        let (inicio, datos) = if datos.len() > MAX_HISTORIA {
            let recorte = datos.len() - MAX_HISTORIA;
            self.historia.clear();
            (inicio.wrapping_add(recorte as u32), &datos[recorte..])
        } else {
            (inicio, datos)
        };

        let contiguo = !self.historia.is_empty()
            && self.historia_base.wrapping_add(self.historia.len() as u32) == inicio;
        if !contiguo {
            // Hubo un salto (perdida o vaciado): comparar contra bytes que no
            // son los de al lado daria contradicciones inventadas.
            self.historia.clear();
            self.historia_base = inicio;
        }

        self.historia.extend_from_slice(datos);
        if self.historia.len() > MAX_HISTORIA {
            let sobra = self.historia.len() - MAX_HISTORIA;
            self.historia.drain(..sobra);
            self.historia_base = self.historia_base.wrapping_add(sobra as u32);
        }
    }

    /// Incorpora un segmento y devuelve los bytes **en orden** que ya se pueden
    /// entregar al disector.
    ///
    /// El valor devuelto puede estar vacio (el segmento tapa un hueco futuro) o
    /// ser mas largo que el segmento (este segmento tapo el hueco y desbloqueo
    /// los que esperaban detras).
    pub fn incorporar(&mut self, secuencia: u32, datos: &[u8]) -> Vec<u8> {
        if datos.is_empty() {
            return Vec::new();
        }

        // Flujo capturado a medias: el primer dato define el origen. Se dice en
        // vez de fingir que se vio desde el principio.
        if !self.sincronizado {
            self.siguiente = secuencia;
            self.sincronizado = true;
        }

        let desfase = secuencia.wrapping_sub(self.siguiente);

        // (a) Enteramente por detras: retransmision de algo ya entregado.
        //     Se cuenta y se descarta. NO se reescribe hacia atras: permitirlo
        //     seria dejar que el atacante cambie lo que el IDS ya analizo, que
        //     es el nucleo del ataque de solape.
        let atras = self.siguiente.wrapping_sub(secuencia);
        if desfase > MAX_ADELANTO && atras <= MAX_ADELANTO {
            // AQUI ESTA LA MITAD PELIGROSA DEL ATAQUE. El segmento pisa terreno
            // que ya se entrego y se analizo. Si trae los mismos bytes es una
            // retransmision de libro; si trae OTROS, alguien esta reescribiendo
            // lo que el sensor ya dio por bueno. Las dos cosas se ven igual
            // desde fuera: hay que comparar.
            let ya_visto = atras as usize;
            let solapada = &datos[..ya_visto.min(datos.len())];
            self.anotar_solape_hacia_atras(secuencia, solapada);

            // Se recorta la parte ya entregada y se procesa el resto. NO se
            // reescribe hacia atras: permitirlo seria dejar que el atacante
            // cambie lo que el IDS ya analizo, que es el nucleo del ataque.
            if ya_visto >= datos.len() {
                return Vec::new();
            }
            let resto = &datos[ya_visto..];
            return self.incorporar_alineado(resto);
        }

        // (b) Demasiado por delante: ni fuera de orden ni nada. Es basura o un
        //     intento de hacer reservar memoria por una secuencia inventada.
        if desfase > MAX_ADELANTO {
            self.anomalias.descartes_por_adelanto += 1;
            return Vec::new();
        }

        // (c) Justo lo que tocaba.
        if desfase == 0 {
            return self.incorporar_alineado(datos);
        }

        // (d) Fuera de orden: se retiene, con cotas.
        self.retener(secuencia, datos);
        Vec::new()
    }

    /// Entrega datos que empiezan exactamente en `self.siguiente` y arrastra lo
    /// que quedara desbloqueado detras.
    fn incorporar_alineado(&mut self, datos: &[u8]) -> Vec<u8> {
        // La salida es contigua y arranca justo donde estabamos: se guarda para
        // la ventana de historia antes de mover el puntero.
        let inicio_salida = self.siguiente;
        let mut salida = datos.to_vec();
        self.siguiente = self.siguiente.wrapping_add(datos.len() as u32);

        // Arrastre: mientras el primer hueco empiece donde vamos, se une.
        loop {
            let Some((&inicio, _)) = self.huecos.iter().next() else {
                break;
            };
            let desfase = inicio.wrapping_sub(self.siguiente);
            // El hueco empieza mas adelante: todavia falta lo de en medio.
            if desfase != 0 && desfase <= MAX_ADELANTO {
                break;
            }
            let Some(trozo) = self.huecos.remove(&inicio) else {
                break;
            };
            self.retenido = self.retenido.saturating_sub(trozo.len());

            // El hueco empieza por detras de donde vamos: solapa. Se recorta lo
            // ya entregado, con la politica.
            let ya_visto = self.siguiente.wrapping_sub(inicio) as usize;
            // SOLO si de verdad hay solape. Un trozo que encaja justo donde
            // toca es el caso NORMAL de un hueco que se tapa, y contarlo como
            // retransmision llenaria de ruido un contador que existe para
            // llamar la atencion.
            if ya_visto > 0 {
                // La parte solapada se COMPARA, no se supone igual. Suponerla
                // igual convierte un intento de reescritura en «retransmision».
                let solapada = &trozo[..ya_visto.min(trozo.len())];
                // La comparacion mira la historia mas lo que ya lleva esta misma
                // salida, que todavia no esta en la ventana.
                match self.comparar_con_salida(&salida, inicio_salida, inicio, solapada) {
                    ContraHistoria::Contradictorio => self.anomalias.solapes_contradictorios += 1,
                    ContraHistoria::Identico => self.anomalias.solapes_identicos += 1,
                    ContraHistoria::FueraDeVentana => self.anomalias.retransmisiones += 1,
                }
            }
            if ya_visto >= trozo.len() {
                continue;
            }
            let nuevo = &trozo[ya_visto..];
            salida.extend_from_slice(nuevo);
            self.siguiente = self.siguiente.wrapping_add(nuevo.len() as u32);
        }

        self.entregados += salida.len() as u64;
        self.recordar(inicio_salida, &salida);
        salida
    }

    /// Compara un trozo solapado contra lo ya entregado, incluyendo la salida
    /// que se esta construyendo en esta misma llamada.
    ///
    /// Hace falta porque los bytes recien unidos todavia no estan en la ventana
    /// de historia y son justo los que el solape suele pisar.
    fn comparar_con_salida(
        &self,
        salida: &[u8],
        inicio_salida: u32,
        secuencia: u32,
        datos: &[u8],
    ) -> ContraHistoria {
        if datos.is_empty() {
            return ContraHistoria::FueraDeVentana;
        }
        let dentro = secuencia.wrapping_sub(inicio_salida) as usize;
        if dentro < salida.len() {
            let comun = (salida.len() - dentro).min(datos.len());
            return if salida[dentro..dentro + comun] == datos[..comun] {
                ContraHistoria::Identico
            } else {
                ContraHistoria::Contradictorio
            };
        }
        self.comparar_con_historia(secuencia, datos)
    }

    /// Retiene un segmento fuera de orden, resolviendo solapes con lo retenido.
    fn retener(&mut self, secuencia: u32, datos: &[u8]) {
        // EL PUNTO CRITICO: si ya hay algo retenido en esa secuencia, hay que
        // decidir cual se queda, y ademas DETECTAR si el contenido difiere.
        if let Some(existente) = self.huecos.get(&secuencia) {
            let comun = existente.len().min(datos.len());
            let identico = existente[..comun] == datos[..comun];
            if identico {
                self.anomalias.solapes_identicos += 1;
            } else {
                // LA SENAL. El trafico legitimo no manda dos veces la misma
                // secuencia con contenido distinto.
                self.anomalias.solapes_contradictorios += 1;
            }
            match self.politica {
                // El primero se queda: no se toca nada. El atacante no puede
                // reescribir lo que el IDS ya tiene.
                Politica::PrimeroGana => {
                    // Salvo que el nuevo sea estrictamente mas largo: la parte
                    // que EXTIENDE no solapaba con nada, asi que se conserva.
                    if datos.len() > existente.len() {
                        let extra = datos.len() - existente.len();
                        if self.retenido + extra <= MAX_RETENIDO {
                            let mut fundido = existente.clone();
                            fundido.extend_from_slice(&datos[existente.len()..]);
                            self.retenido += extra;
                            self.huecos.insert(secuencia, fundido);
                        }
                    }
                    return;
                }
                Politica::UltimoGana => {
                    let viejo = existente.len();
                    self.retenido = self.retenido.saturating_sub(viejo);
                    self.huecos.remove(&secuencia);
                }
            }
        }

        // Cotas, ANTES de reservar.
        if self.huecos.len() >= MAX_HUECOS || self.retenido + datos.len() > MAX_RETENIDO {
            // Se expulsa el hueco mas lejano, no el mas cercano: el mas cercano
            // es el que tiene mas probabilidad de completarse y desbloquear el
            // flujo. Tirar el cercano condenaria todo lo que espera detras.
            if let Some((&lejano, _)) = self.huecos.iter().next_back() {
                if lejano.wrapping_sub(self.siguiente) > secuencia.wrapping_sub(self.siguiente) {
                    if let Some(t) = self.huecos.remove(&lejano) {
                        self.retenido = self.retenido.saturating_sub(t.len());
                        self.anomalias.bytes_perdidos += t.len() as u64;
                    }
                } else {
                    // El que llega es el mas lejano de todos: se descarta el.
                    self.anomalias.descartes_por_memoria += 1;
                    return;
                }
            }
            if self.huecos.len() >= MAX_HUECOS || self.retenido + datos.len() > MAX_RETENIDO {
                self.anomalias.descartes_por_memoria += 1;
                return;
            }
        }

        self.retenido += datos.len();
        self.huecos.insert(secuencia, datos.to_vec());
    }

    /// Da por perdido lo que falta y entrega lo retenido, en orden.
    ///
    /// Se llama al cerrar el flujo o al expirar: lo que quedo en huecos no va a
    /// llegar nunca, y entregarlo con el aviso es mas util que tirarlo.
    pub fn vaciar(&mut self) -> Vec<u8> {
        let mut salida = Vec::new();
        let claves: Vec<u32> = self.huecos.keys().copied().collect();
        for k in claves {
            if let Some(t) = self.huecos.remove(&k) {
                self.retenido = self.retenido.saturating_sub(t.len());
                let perdidos = k.wrapping_sub(self.siguiente);
                if perdidos > 0 && perdidos <= MAX_ADELANTO {
                    self.anomalias.bytes_perdidos += u64::from(perdidos);
                }
                salida.extend_from_slice(&t);
                self.siguiente = k.wrapping_add(t.len() as u32);
            }
        }
        self.entregados += salida.len() as u64;
        // La ventana de historia se abandona: lo entregado aqui lleva huecos en
        // medio, y comparar contra bytes que no son contiguos produciria
        // contradicciones inventadas.
        self.historia.clear();
        salida
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn los_segmentos_en_orden_se_entregan_tal_cual() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        assert_eq!(s.incorporar(1001, b"GET "), b"GET ".to_vec());
        assert_eq!(s.incorporar(1005, b"/index"), b"/index".to_vec());
        assert_eq!(s.entregados(), 10);
        assert_eq!(s.huecos(), 0);
    }

    /// UN HUECO QUE SE TAPA JUSTO NO ES NINGUNA ANOMALIA. Es el caso mas normal
    /// que hay —llego un paquete fuera de orden y despues el que faltaba— y
    /// contarlo como retransmision o como solape llenaria de ruido unos
    /// contadores que existen precisamente para llamar la atencion.
    #[test]
    fn tapar_un_hueco_sin_solape_no_cuenta_como_anomalia() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        // Llega el segundo trozo antes que el primero.
        assert!(s.incorporar(1005, b"/index").is_empty());
        // Y ahora el primero, que encaja EXACTAMENTE delante.
        assert_eq!(s.incorporar(1001, b"GET "), b"GET /index".to_vec());

        assert_eq!(
            s.anomalias(),
            &Anomalias::default(),
            "el trafico fuera de orden es normalisimo y no puede levantar nada"
        );
    }

    /// Y con varios huecos encadenados, que es como llega una rafaga reordenada.
    #[test]
    fn una_rafaga_reordenada_no_levanta_ninguna_anomalia() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        for (sec, trozo) in [(1013u32, &b"CCCC"[..]), (1009, b"BBBB"), (1005, b"AAAA")] {
            s.incorporar(sec, trozo);
        }
        assert_eq!(s.incorporar(1001, b"GET "), b"GET AAAABBBBCCCC".to_vec());
        assert_eq!(s.anomalias(), &Anomalias::default());
    }

    /// Fuera de orden: se retiene hasta que llega lo de en medio, y entonces se
    /// entrega TODO junto y en orden.
    #[test]
    fn un_segmento_fuera_de_orden_se_retiene_y_se_desbloquea_al_llegar_el_hueco() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);

        // Llega el tercero antes que el segundo.
        assert!(s.incorporar(1009, b"CCCC").is_empty());
        assert_eq!(s.huecos(), 1);

        // Llega el primero.
        assert_eq!(s.incorporar(1001, b"AAAA"), b"AAAA".to_vec());
        assert_eq!(s.huecos(), 1, "el tercero sigue esperando al segundo");

        // Llega el segundo: se entrega el, y el tercero detras.
        assert_eq!(s.incorporar(1005, b"BBBB"), b"BBBBCCCC".to_vec());
        assert_eq!(s.huecos(), 0);
        assert_eq!(s.entregados(), 12);
    }

    /// EL ATAQUE DE EVASION, construido entero. Dos segmentos en la MISMA
    /// secuencia con contenido DISTINTO: el IDS tiene que quedarse con el mismo
    /// que se quedaria el destino, y ademas DECIRLO.
    #[test]
    fn un_solape_con_contenido_distinto_se_resuelve_por_politica_y_se_delata() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);

        // Hay un hueco delante, asi que los dos se retienen: es el caso donde
        // el solape se resuelve de verdad.
        assert!(s.incorporar(1005, b"GET ").is_empty());
        assert!(s.incorporar(1005, b"PUT ").is_empty());

        assert_eq!(
            s.anomalias().solapes_contradictorios,
            1,
            "un solape con contenido distinto TIENE que contarse"
        );
        assert!(s.anomalias().hay_indicio_de_evasion());

        // Se tapa el hueco y se ve cual gano.
        let entregado = s.incorporar(1001, b"AAAA");
        assert_eq!(
            entregado,
            b"AAAAGET ".to_vec(),
            "con PrimeroGana tiene que sobrevivir el primero"
        );
    }

    /// Y con la politica contraria gana el otro. Que las dos existan y se elijan
    /// a proposito es el punto: imitar al destino es lo que cierra la evasion.
    #[test]
    fn con_la_politica_contraria_gana_el_ultimo() {
        let mut s = Sentido::nuevo(Politica::UltimoGana);
        s.sincronizar(1000);
        assert!(s.incorporar(1005, b"GET ").is_empty());
        assert!(s.incorporar(1005, b"PUT ").is_empty());
        assert_eq!(s.anomalias().solapes_contradictorios, 1);
        assert_eq!(s.incorporar(1001, b"AAAA"), b"AAAAPUT ".to_vec());
    }

    /// Una retransmision IDENTICA es trafico normal y NO puede contarse como
    /// indicio de evasion: si lo hiciera, la senal quedaria enterrada en ruido y
    /// nadie la miraria.
    #[test]
    fn una_retransmision_identica_no_es_indicio_de_evasion() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        assert!(s.incorporar(1005, b"GET ").is_empty());
        assert!(s.incorporar(1005, b"GET ").is_empty());
        assert_eq!(s.anomalias().solapes_identicos, 1);
        assert_eq!(s.anomalias().solapes_contradictorios, 0);
        assert!(!s.anomalias().hay_indicio_de_evasion());
    }

    /// El atacante NO puede reescribir hacia atras lo que el IDS ya analizo.
    #[test]
    fn no_se_puede_reescribir_lo_ya_entregado() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        assert_eq!(s.incorporar(1001, b"GET "), b"GET ".to_vec());

        // Ahora intenta cambiarlo por PUT en la misma secuencia.
        let r = s.incorporar(1001, b"PUT ");
        assert!(
            r.is_empty(),
            "lo ya entregado no se re-entrega ni se reescribe: {r:?}"
        );
        assert_eq!(s.entregados(), 4, "no se ha entregado nada nuevo");
        // Y ademas SE DELATA. No basta con resistir el ataque en silencio: un
        // ataque resistido y no contado es un ataque que nadie investiga.
        assert_eq!(
            s.anomalias().solapes_contradictorios,
            1,
            "reescribir terreno entregado con otro contenido ES la senal"
        );
        assert!(s.anomalias().hay_indicio_de_evasion());
    }

    /// LA MITAD PELIGROSA DEL ATAQUE: el solape llega DESPUES de que los bytes
    /// se hayan entregado y analizado. Sin ventana de historia esto es
    /// indistinguible de una retransmision y el ataque pasa como ruido.
    #[test]
    fn un_solape_contradictorio_sobre_terreno_ya_entregado_se_delata() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        // El hueco se tapa y todo se entrega de golpe.
        assert!(s.incorporar(1013, b"o HTTP/1.1\r\n").is_empty());
        let entregado = s.incorporar(1001, b"GET /publico");
        assert_eq!(entregado, b"GET /publicoo HTTP/1.1\r\n".to_vec());

        // Y ahora, con los bytes ya fuera, la version contradictoria.
        assert!(s.incorporar(1001, b"GET /secreto").is_empty());
        assert_eq!(
            s.anomalias().solapes_contradictorios,
            1,
            "anomalias = {:?}",
            s.anomalias()
        );
    }

    /// Y el reverso exacto: la misma forma pero con el MISMO contenido es una
    /// retransmision de libro y no puede levantar la senal.
    #[test]
    fn una_retransmision_sobre_terreno_ya_entregado_no_levanta_la_senal() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        assert!(s.incorporar(1013, b"o HTTP/1.1\r\n").is_empty());
        assert!(!s.incorporar(1001, b"GET /publico").is_empty());

        assert!(s.incorporar(1001, b"GET /publico").is_empty());
        assert_eq!(s.anomalias().solapes_contradictorios, 0);
        assert_eq!(s.anomalias().solapes_identicos, 1);
        assert!(!s.anomalias().hay_indicio_de_evasion());
    }

    /// Un solape PARCIAL sobre terreno entregado: los bytes viejos difieren
    /// aunque la cola sea nueva. La contradiccion cuenta y la cola se entrega.
    #[test]
    fn un_solape_parcial_contradictorio_cuenta_y_entrega_la_cola() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        assert_eq!(s.incorporar(1001, b"AAAA"), b"AAAA".to_vec());
        // Pisa los dos ultimos con contenido distinto y trae dos nuevos.
        assert_eq!(s.incorporar(1003, b"ZZBB"), b"BB".to_vec());
        assert_eq!(s.anomalias().solapes_contradictorios, 1);
    }

    /// El limite de la ventana se DECLARA, no se disimula: mas atras de
    /// `MAX_HISTORIA` ya no se puede afirmar que haya contradiccion, y se cuenta
    /// como retransmision en vez de mentir en cualquiera de los dos sentidos.
    #[test]
    fn mas_atras_de_la_ventana_no_se_afirma_contradiccion() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        assert_eq!(
            s.incorporar(1001, b"GET /publico"),
            b"GET /publico".to_vec()
        );
        // Se entrega mucho mas que la ventana, empujando el principio fuera.
        let relleno = vec![b'X'; MAX_HISTORIA + 64];
        s.incorporar(1013, &relleno);

        assert!(s.incorporar(1001, b"GET /secreto").is_empty());
        assert_eq!(
            s.anomalias().solapes_contradictorios,
            0,
            "no se puede afirmar lo que ya no se conserva"
        );
        assert_eq!(s.anomalias().retransmisiones, 1, "pero SI se cuenta");
    }

    /// La ventana de historia esta acotada: entregar megabytes no la hace
    /// crecer. Es la cota que hace que conservar historia sea asumible.
    #[test]
    fn la_ventana_de_historia_esta_acotada() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        let trozo = vec![b'A'; 1400];
        let mut sec = 1001u32;
        for _ in 0..2_000 {
            s.incorporar(sec, &trozo);
            sec = sec.wrapping_add(trozo.len() as u32);
        }
        assert!(
            s.memoria() <= MAX_RETENIDO + MAX_HISTORIA,
            "memoria = {}",
            s.memoria()
        );
    }

    /// Un bloque MAS GRANDE que la ventana entera no puede desbordarla ni
    /// dejarla descolocada: se queda su cola y la base se recoloca con ella.
    #[test]
    fn un_bloque_mayor_que_la_ventana_deja_la_base_en_su_sitio() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        let mut grande = vec![b'A'; MAX_HISTORIA + 100];
        // Los ultimos cuatro bytes son reconocibles para poder compararlos.
        let fin = grande.len() - 4;
        grande[fin..].copy_from_slice(b"REAL");
        s.incorporar(1001, &grande);

        let sec_cola = 1001u32 + fin as u32;
        assert!(s.incorporar(sec_cola, b"REAL").is_empty());
        assert_eq!(s.anomalias().solapes_contradictorios, 0);
        assert!(s.incorporar(sec_cola, b"FALS").is_empty());
        assert_eq!(
            s.anomalias().solapes_contradictorios,
            1,
            "la cola de un bloque enorme sigue siendo comparable"
        );
    }

    /// Solape PARCIAL hacia delante: la parte nueva si se entrega, la ya vista
    /// no. Es el caso que un recorte ingenuo se come o duplica.
    #[test]
    fn un_solape_parcial_entrega_solo_la_parte_nueva() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        assert_eq!(s.incorporar(1001, b"AAAA"), b"AAAA".to_vec());
        // Empieza 2 bytes antes del final y trae 2 nuevos.
        assert_eq!(s.incorporar(1003, b"AABB"), b"BB".to_vec());
        assert_eq!(s.entregados(), 6);
    }

    /// LA COTA DE MEMORIA: un atacante que manda un byte en secuencias dispersas
    /// no puede hacer crecer el reensamblado sin limite.
    #[test]
    fn dispersar_segmentos_no_hace_crecer_la_memoria_sin_limite() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        for i in 1..10_000u32 {
            // Todos fuera de orden, nunca se tapa el hueco inicial.
            s.incorporar(1001 + i * 64, b"XXXXXXXX");
        }
        assert!(s.huecos() <= MAX_HUECOS, "huecos = {}", s.huecos());
        assert!(s.retenido() <= MAX_RETENIDO, "retenido = {}", s.retenido());
        assert!(
            s.anomalias().descartes_por_memoria > 0 || s.anomalias().bytes_perdidos > 0,
            "la perdida tiene que DECIRSE, no ocurrir en silencio"
        );
    }

    /// Una secuencia absurdamente por delante no reserva nada.
    #[test]
    fn una_secuencia_absurda_se_descarta_y_se_cuenta() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        s.incorporar(1001u32.wrapping_add(1 << 30), b"basura");
        assert_eq!(s.huecos(), 0);
        assert_eq!(s.anomalias().descartes_por_adelanto, 1);
    }

    /// Al expulsar se tira el hueco MAS LEJANO, no el mas cercano: el cercano es
    /// el que puede desbloquear el flujo, y tirarlo condenaria todo lo de detras.
    #[test]
    fn al_expulsar_se_conserva_el_hueco_mas_cercano() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        // El cercano, que es el que podria desbloquear.
        s.incorporar(1005, b"CERCANO!");
        // Y muchos lejanos que llenan el mapa.
        for i in 1..(MAX_HUECOS as u32 * 3) {
            s.incorporar(1005 + i * 512, b"LEJANOOO");
        }
        // El cercano tiene que seguir ahi.
        assert!(s.huecos() <= MAX_HUECOS);
        let entregado = s.incorporar(1001, b"AAAA");
        assert!(
            entregado.starts_with(b"AAAACERCANO!"),
            "el hueco cercano no puede haberse expulsado: {:?}",
            String::from_utf8_lossy(&entregado)
        );
    }

    /// El envoltorio del numero de secuencia (pasa de 2^32 a 0) es normal en
    /// conexiones largas y NO puede romper el orden.
    #[test]
    fn el_envoltorio_del_numero_de_secuencia_no_rompe_el_orden() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        let cerca_del_tope = u32::MAX - 4;
        s.sincronizar(cerca_del_tope);
        // 1: justo tras el SYN.
        assert_eq!(
            s.incorporar(cerca_del_tope.wrapping_add(1), b"AAAA"),
            b"AAAA".to_vec()
        );
        // 2: ya del otro lado del envoltorio.
        assert_eq!(
            s.incorporar(cerca_del_tope.wrapping_add(5), b"BBBB"),
            b"BBBB".to_vec()
        );
        assert_eq!(s.entregados(), 8);
    }

    /// Un flujo capturado a medias (el sensor arranco tarde) se sincroniza con
    /// el primer dato, y eso NO se disfraza de flujo completo.
    #[test]
    fn un_flujo_capturado_a_medias_se_sincroniza_con_el_primer_dato() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        // Sin SYN.
        assert_eq!(s.incorporar(555_000, b"...datos"), b"...datos".to_vec());
        assert_eq!(s.entregados(), 8);
    }

    /// Al cerrar, lo retenido se entrega con el aviso de lo perdido en vez de
    /// tirarse: media peticion HTTP es mas util que nada.
    #[test]
    fn al_vaciar_se_entrega_lo_retenido_y_se_declara_lo_perdido() {
        let mut s = Sentido::nuevo(Politica::PrimeroGana);
        s.sincronizar(1000);
        s.incorporar(1009, b"FINAL");
        assert!(s.huecos() > 0);
        let resto = s.vaciar();
        assert_eq!(resto, b"FINAL".to_vec());
        assert!(
            s.anomalias().bytes_perdidos > 0,
            "el hueco que nunca llego tiene que declararse"
        );
        assert_eq!(s.huecos(), 0);
    }

    /// Barrido determinista de entrada hostil: ninguna secuencia de segmentos
    /// arbitrarios puede provocar panico ni memoria no acotada.
    #[test]
    fn una_secuencia_hostil_arbitraria_no_provoca_panico_ni_crecimiento() {
        let mut semilla = 0x9E37_79B9_7F4A_7C15u64;
        for politica in [Politica::PrimeroGana, Politica::UltimoGana] {
            let mut s = Sentido::nuevo(politica);
            s.sincronizar(0);
            for _ in 0..20_000 {
                semilla = semilla
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let sec = (semilla >> 16) as u32;
                let largo = ((semilla >> 8) as usize) % 64;
                let datos: Vec<u8> = (0..largo).map(|i| (semilla >> (i % 8)) as u8).collect();
                let _ = s.incorporar(sec, &datos);
                assert!(s.huecos() <= MAX_HUECOS);
                assert!(s.retenido() <= MAX_RETENIDO);
            }
            let _ = s.vaciar();
        }
    }
}
