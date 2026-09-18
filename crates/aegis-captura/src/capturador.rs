//! El capturador: lo que ata la redaccion, la retencion, el anillo y el indice.
//!
//! # El camino entero de un paquete, y por que no hay atajos
//!
//! ```text
//!   bytes del cable
//!        │
//!        ▼
//!   Redactor::limpiar ──────► Limpio   (no hay otro constructor)
//!        │
//!        ▼
//!   Decision de retencion ──► Politica (Completo exige Autorizacion)
//!        │
//!        ▼
//!   Anillo::meter ──────────► contado  (las dos invariantes de `anillo`)
//!        │
//!        ▼
//!   Indice::anadir ─────────► (entidad, cursor)
//! ```
//!
//! Los dos pasos que no se pueden saltar estan en el tipo, no en la disciplina:
//! el anillo solo acepta [`crate::redaccion::Limpio`], y guardar contenido entero
//! exige una [`crate::retencion::Autorizacion`] que solo produce un veredicto.
//!
//! # Lo que el capturador NO hace
//!
//! No abre sockets, no lee interfaces y no mira el reloj. Recibe paquetes con su
//! marca de tiempo y devuelve lo que hizo con ellos. Es la misma disciplina que
//! los disectores de la FASE 89, y por lo mismo: es lo que permite construir la
//! prueba de carga entera —cien mil paquetes con el anillo al limite— sin red,
//! sin privilegios y sin condiciones de carrera.

use aegis_entidad::entidad::Eid;

use crate::anillo::{Anillo, Contadores, Paquete};
use crate::indice::{Cursor, Entrada, Indice, Particion};
use crate::redaccion::{Donde, Redactor};
use crate::retencion::{Caducidad, Decision, Politica};

/// Lo que se hizo con un paquete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suerte {
    /// Se guardo, con su cursor en el indice.
    Guardado(Cursor),
    /// Se conto en el sobre y no se guardo el contenido.
    ///
    /// Es lo que le pasa al noventa y nueve por ciento del trafico, y no es una
    /// perdida: es la decision que hace que el almacen quepa.
    SoloElSobre,
    /// El cliente pidio no retener este trafico.
    ProhibidoPorElCliente,
    /// No cupo en el anillo. Ya esta contado en [`Contadores`].
    NoCupo,
}

/// Lo que se captura de un flujo, con su decision ya tomada.
#[derive(Debug, Clone)]
pub struct Flujo {
    /// De quien es.
    pub entidad: Eid,
    /// Donde ocurre, para decidir si cae en un ambito declarado.
    pub donde: Donde,
    /// Que se guarda de el y por que.
    pub decision: Decision,
    /// Cuantos bytes lleva guardados ya, para respetar el tope de la politica.
    guardados: u64,
    /// Cuantos bytes hubo en el cable, guardados o no.
    vistos: u64,
    /// Cuantos se taparon.
    tapados: u64,
}

impl Flujo {
    /// Un flujo nuevo con la decision por defecto: solo el sobre.
    #[must_use]
    pub fn nuevo(entidad: Eid, donde: Donde) -> Flujo {
        Flujo {
            entidad,
            donde,
            decision: Decision::por_defecto(),
            guardados: 0,
            vistos: 0,
            tapados: 0,
        }
    }

    /// Cambia la decision de retencion de este flujo.
    ///
    /// Se combina con la que ya tenia: gana la mayor, salvo que el cliente haya
    /// prohibido retener, que no lo levanta un veredicto. Ver
    /// [`Decision::combinar`].
    pub fn decidir(&mut self, d: Decision) {
        self.decision = Decision::combinar(self.decision.clone(), d);
    }

    /// Cuantos bytes se han guardado de este flujo.
    #[must_use]
    pub fn guardados(&self) -> u64 {
        self.guardados
    }

    /// Cuantos bytes hubo en el cable.
    #[must_use]
    pub fn vistos(&self) -> u64 {
        self.vistos
    }

    /// Cuantos se taparon.
    #[must_use]
    pub fn tapados(&self) -> u64 {
        self.tapados
    }
}

/// El capturador.
pub struct Capturador {
    redactor: Redactor,
    anillo: Anillo,
    indice: Indice,
    /// Cuantos bytes de contenido se han escrito en total.
    bytes_de_contenido: u64,
    /// Cuantos paquetes se quedaron en el sobre.
    solo_sobre: u64,
    /// Cuantos no se guardaron porque el cliente lo prohibio.
    prohibidos: u64,
}

impl Capturador {
    /// Un capturador con un anillo de `capacidad` bytes y el indice del agente.
    ///
    /// El indice trae el techo de [`crate::indice::MAX_ENTRADAS`], que es el que
    /// cabe en el presupuesto de memoria del agente. **Las dos estructuras que
    /// crecen con el trafico tienen techo**: el anillo por bytes y el indice por
    /// entradas. Lo que no cabe en ninguna de las dos se cuenta.
    #[must_use]
    pub fn nuevo(redactor: Redactor, capacidad: usize) -> Capturador {
        Capturador::con_topes(redactor, capacidad, crate::indice::MAX_ENTRADAS)
    }

    /// Un capturador con los dos techos dichos a mano.
    ///
    /// Para el que drena a otro ritmo que el del agente por defecto: el servidor,
    /// o una prueba que modele el sistema entero en vez de solo el endpoint.
    #[must_use]
    pub fn con_topes(redactor: Redactor, capacidad: usize, entradas: usize) -> Capturador {
        Capturador {
            redactor,
            anillo: Anillo::nuevo(capacidad),
            indice: Indice::con_tope(entradas),
            bytes_de_contenido: 0,
            solo_sobre: 0,
            prohibidos: 0,
        }
    }

    /// Los contadores del anillo.
    #[must_use]
    pub fn contadores(&self) -> Contadores {
        self.anillo.contadores
    }

    /// El indice.
    #[must_use]
    pub fn indice(&self) -> &Indice {
        &self.indice
    }

    /// El indice, para purgar.
    pub fn indice_mut(&mut self) -> &mut Indice {
        &mut self.indice
    }

    /// Cuantos bytes de contenido se han guardado.
    #[must_use]
    pub fn bytes_de_contenido(&self) -> u64 {
        self.bytes_de_contenido
    }

    /// Mete un paquete de un flujo.
    ///
    /// `original` es lo que medía en el cable; puede ser mas que `datos` si el
    /// captador ya venia recortando.
    pub fn capturar(
        &mut self,
        flujo: &mut Flujo,
        cuando_ns: u64,
        datos: &[u8],
        original: usize,
    ) -> Suerte {
        flujo.vistos += original.max(datos.len()) as u64;

        if flujo.decision.politica == Politica::Nada {
            self.prohibidos += 1;
            return Suerte::ProhibidoPorElCliente;
        }

        // El sobre se cuenta SIEMPRE, tambien cuando no se guarda contenido: es
        // lo que permite contestar «esta maquina hablo con esa otra» sin
        // almacenar un solo byte de la conversacion.
        if !flujo.decision.politica.guarda_contenido() {
            self.solo_sobre += 1;
            self.anotar(flujo, cuando_ns, 0, 0, 0);
            return Suerte::SoloElSobre;
        }

        // El tope de la politica: `Cabeceras` guarda los primeros bytes de cada
        // sentido, no el flujo entero. Cuando se pasa, se sigue contando el sobre
        // y se deja de guardar contenido.
        if let Some(tope) = flujo.decision.politica.tope_por_sentido() {
            if flujo.guardados >= tope as u64 {
                self.solo_sobre += 1;
                self.anotar(flujo, cuando_ns, 0, 0, 0);
                return Suerte::SoloElSobre;
            }
        }

        // **El unico camino** de los bytes del cable al anillo.
        let limpio = self.redactor.limpiar(datos, flujo.donde);
        let tapados = limpio.bytes_tapados() as u64;
        if !self.anillo.meter(cuando_ns, &limpio) {
            return Suerte::NoCupo;
        }
        let escritos = limpio.bytes().len() as u64;
        flujo.guardados += escritos;
        flujo.tapados += tapados;
        self.bytes_de_contenido += escritos;

        let cursor = self.anotar(flujo, cuando_ns, escritos, 1, tapados);
        Suerte::Guardado(cursor)
    }

    /// Anota la entrada en el indice.
    fn anotar(
        &mut self,
        flujo: &Flujo,
        cuando_ns: u64,
        bytes: u64,
        paquetes: u32,
        tapados: u64,
    ) -> Cursor {
        let politica = flujo.decision.politica;
        self.indice.anadir(Entrada {
            entidad: flujo.entidad.clone(),
            cuando_ns,
            particion: Particion::de(cuando_ns, politica),
            desde: self.bytes_de_contenido.saturating_sub(bytes),
            bytes,
            paquetes,
            politica,
            caducidad: flujo.decision.caducidad,
            bytes_tapados: tapados,
        })
    }

    /// Saca lo que haya en el anillo, para escribirlo a disco.
    pub fn vaciar(&mut self) -> Vec<Paquete> {
        self.anillo.vaciar()
    }

    /// Como se cuenta esto en un informe.
    #[must_use]
    pub fn frase(&self) -> String {
        format!(
            "{}. Se guardo el contenido de {} bytes; {} paquetes se quedaron en el sobre y {} \
             no se retuvieron porque el cliente lo pidio. El indice tiene {} entradas de {} \
             entidades en {} particiones",
            self.contadores().frase(),
            self.bytes_de_contenido,
            self.solo_sobre,
            self.prohibidos,
            self.indice.cuantas(),
            self.indice.entidades(),
            self.indice.particiones().len()
        )
    }
}

/// Cuanto ahorra la retencion por veredicto, en centesimas.
///
/// # Por que se calcula y no se proclama
///
/// Porque «un orden de magnitud menos de disco» es la clase de afirmacion que se
/// pone en una presentacion y no se comprueba nunca. Aqui sale de contar bytes:
/// los que se guardaron contra los que habria guardado un capturador que lo
/// guarda todo.
///
/// # Por que el redondeo va SIEMPRE en contra de la afirmacion
///
/// Un porcentaje entero tiene un borde peligroso: guardar tres megabytes de
/// seiscientos es el 0,5 por ciento, y una division entera lo convierte en cero,
/// con lo que el ahorro sale «100%» — que leido en voz alta es «no se guardo
/// nada», y si se guardo. Un redondeo que cae del lado de quien presenta la
/// cifra no es un redondeo, es una exageracion con coartada aritmetica.
///
/// Por eso la parte guardada se redondea HACIA ARRIBA: si se guardo un solo byte
/// el resultado es 99, nunca 100. El unico 100 que devuelve esta funcion es el de
/// no haber guardado ni un byte, y el unico 0, el de haberlo guardado todo. La
/// cifra que se publica queda por debajo de la real, que es el lado correcto del
/// que equivocarse.
#[must_use]
pub fn ahorro(bytes_guardados: u64, bytes_vistos: u64) -> u8 {
    if bytes_vistos == 0 {
        return 0;
    }
    let guardados = u128::from(bytes_guardados);
    let vistos = u128::from(bytes_vistos);
    // Division con redondeo hacia arriba: cualquier resto cuenta como una
    // centesima entera de lo guardado, y por tanto una menos de ahorro.
    let guardado = (guardados * 100).div_ceil(vistos);
    (100u128.saturating_sub(guardado)) as u8
}

/// La caducidad que corresponde a una politica, expuesta para el almacen.
#[must_use]
pub fn caducidad_de(p: Politica) -> Caducidad {
    Caducidad::de_politica(p)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::retencion::Autorizacion;
    use aegis_entidad::arbitro::{Resultado, Veredicto};
    use aegis_entidad::entidad;
    use aegis_entidad::escala::{Confianza, Severidad};

    fn veredicto(r: Resultado) -> Veredicto {
        Veredicto {
            entidad: entidad::maquina("m1"),
            resultado: r,
            severidad: Severidad::Alta,
            confianza: Confianza::nueva(90),
            porque: "dos planos independientes".to_owned(),
            planos: Vec::new(),
            senales: Vec::new(),
        }
    }

    #[test]
    fn por_defecto_solo_se_guarda_el_sobre_y_el_sobre_basta_para_saber_quien_hablo() {
        let mut c = Capturador::nuevo(Redactor::nuevo(), 1024 * 1024);
        let mut f = Flujo::nuevo(entidad::maquina("m1"), Donde::default());
        for i in 0..100u64 {
            assert_eq!(
                c.capturar(&mut f, i * 1000, &vec![b'x'; 1400], 1400),
                Suerte::SoloElSobre
            );
        }
        assert_eq!(c.bytes_de_contenido(), 0);
        // Y sin embargo el indice sabe que esa maquina hablo cien veces.
        assert_eq!(c.indice().cuantas(), 100);
        assert_eq!(
            c.indice().buscar(&f.entidad, None, 1000).entradas.len(),
            100
        );
    }

    /// LA prestacion de la fase: se guarda entero lo que el arbitro marco, y solo
    /// el sobre lo demas. El ahorro se cuenta, no se proclama.
    #[test]
    fn la_retencion_por_veredicto_ahorra_un_orden_de_magnitud() {
        let mut c = Capturador::nuevo(Redactor::nuevo(), 8 * 1024 * 1024);
        let a = Autorizacion::del_veredicto(&veredicto(Resultado::Malicioso)).unwrap();

        let mut vistos = 0u64;
        // Cien flujos, y solo uno acusado: es la proporcion de una red real.
        for n in 0..100u32 {
            let mut f = Flujo::nuevo(entidad::maquina(&format!("m{n}")), Donde::default());
            if n == 42 {
                f.decidir(Decision::autorizada(&a));
            }
            for i in 0..20u64 {
                c.capturar(&mut f, i * 1000, &vec![b'x'; 1400], 1400);
            }
            vistos += f.vistos();
        }

        let ahorrado = ahorro(c.bytes_de_contenido(), vistos);
        assert!(
            ahorrado >= 90,
            "solo se ahorro el {ahorrado}% ({} de {vistos} bytes)",
            c.bytes_de_contenido()
        );
        // Y lo que se guardo es exactamente el flujo acusado, entero.
        assert_eq!(c.bytes_de_contenido(), 20 * 1400);
    }

    #[test]
    fn la_politica_de_cabeceras_guarda_el_principio_y_deja_de_guardar() {
        // Cubre el caso que mas aparece al investigar: ver el saludo o la
        // peticion sin arrastrar la descarga entera.
        let mut c = Capturador::nuevo(Redactor::nuevo(), 1024 * 1024);
        let mut f = Flujo::nuevo(entidad::maquina("m1"), Donde::default());
        f.decidir(Decision::cabeceras("flujo vigilado"));
        for i in 0..100u64 {
            c.capturar(&mut f, i * 1000, &vec![b'x'; 1400], 1400);
        }
        let tope = Politica::Cabeceras.tope_por_sentido().unwrap() as u64;
        assert!(f.guardados() >= tope, "{}", f.guardados());
        assert!(
            f.guardados() < tope + 1400,
            "guardo {} con un tope de {tope}",
            f.guardados()
        );
    }

    #[test]
    fn lo_que_el_cliente_prohibio_no_se_guarda_ni_en_el_sobre() {
        let mut c = Capturador::nuevo(Redactor::nuevo(), 1024 * 1024);
        let mut f = Flujo::nuevo(entidad::maquina("m1"), Donde::default());
        f.decidir(Decision::nada("red de la clinica"));
        for i in 0..50u64 {
            assert_eq!(
                c.capturar(&mut f, i, b"lo que sea", 10),
                Suerte::ProhibidoPorElCliente
            );
        }
        assert_eq!(c.indice().cuantas(), 0);
        assert_eq!(c.bytes_de_contenido(), 0);
        assert_eq!(c.contadores().recibidos, 0, "ni siquiera llega al anillo");
    }

    #[test]
    fn una_credencial_no_llega_al_anillo_ni_con_autorizacion() {
        // El camino esta en el tipo: el anillo solo acepta `Limpio`, y `Limpio`
        // no se construye mas que pasando por el redactor.
        let mut c = Capturador::nuevo(Redactor::nuevo(), 1024 * 1024);
        let a = Autorizacion::del_veredicto(&veredicto(Resultado::Malicioso)).unwrap();
        let mut f = Flujo::nuevo(entidad::maquina("m1"), Donde::default());
        f.decidir(Decision::autorizada(&a));

        let p = b"POST /login HTTP/1.1\r\nHost: x\r\n\r\nuser=ana&password=muysecreta";
        c.capturar(&mut f, 1, p, p.len());
        let dentro = c.vaciar();
        assert_eq!(dentro.len(), 1);
        let texto = String::from_utf8_lossy(&dentro[0].datos);
        assert!(!texto.contains("muysecreta"), "{texto}");
        assert!(texto.contains("user=ana"), "{texto}");
        assert!(f.tapados() > 0);
    }

    #[test]
    fn la_perdida_del_anillo_llega_hasta_la_frase_del_informe() {
        let mut c = Capturador::nuevo(Redactor::nuevo(), 4096);
        let a = Autorizacion::del_veredicto(&veredicto(Resultado::EnDisputa)).unwrap();
        let mut f = Flujo::nuevo(entidad::maquina("m1"), Donde::default());
        f.decidir(Decision::autorizada(&a));
        for i in 0..1000u64 {
            c.capturar(&mut f, i, &vec![b'x'; 1400], 1400);
        }
        assert!(
            c.contadores().cuadran_en_la_entrada(),
            "{:?}",
            c.contadores()
        );
        assert!(c.contadores().perdidos() > 0);
        assert!(c.frase().contains("SE PERDIERON"), "{}", c.frase());
    }

    #[test]
    fn el_ahorro_no_se_desborda_ni_divide_entre_cero() {
        assert_eq!(ahorro(0, 0), 0);
        assert_eq!(ahorro(0, 100), 100);
        assert_eq!(ahorro(100, 100), 0);
        assert_eq!(ahorro(u64::MAX, 1), 0);
    }

    /// El 100 por ciento significa «ni un byte», y no se llega a el redondeando.
    ///
    /// Es la prueba de una cifra que se publica: guardar tres megabytes de
    /// seiscientos es el 99 por ciento de ahorro, no el 100. Con division entera
    /// hacia abajo salia 100 —«no se guardo nada»— y la prueba anterior lo daba
    /// por bueno. Aqui se fija el borde por los dos lados: con un solo byte
    /// guardado el resultado baja de 100, y solo con cero llega.
    #[test]
    fn el_redondeo_del_ahorro_nunca_favorece_a_la_afirmacion() {
        // El caso de la medida de esta fase: 3 MB de 600 MB.
        assert_eq!(ahorro(3_000_000, 600_000_000), 99);

        // Un unico byte guardado ya impide decir «ninguno», por grande que sea
        // el denominador.
        assert_eq!(ahorro(1, u64::MAX), 99);
        assert_eq!(ahorro(1, 1_000_000), 99);

        // Y el 100 se reserva para lo que de verdad significa.
        assert_eq!(ahorro(0, u64::MAX), 100);

        // Por el otro lado, lo mismo: guardar casi todo no se redondea a «se
        // ahorro algo».
        assert_eq!(ahorro(999_999, 1_000_000), 0);

        // Monotona: guardar mas nunca puede dar mas ahorro.
        let mut anterior = 100;
        for guardados in [0, 1, 10, 1_000, 250_000, 500_000, 999_999, 1_000_000] {
            let a = ahorro(guardados, 1_000_000);
            assert!(
                a <= anterior,
                "ahorro({guardados}) = {a} subio de {anterior}"
            );
            anterior = a;
        }
    }

    #[test]
    fn la_caducidad_se_expone_para_que_el_almacen_purgue_por_particion() {
        assert_eq!(
            caducidad_de(Politica::Completo),
            Caducidad::de_politica(Politica::Completo)
        );
        assert!(caducidad_de(Politica::Completo) > caducidad_de(Politica::Cabeceras));
    }
}
