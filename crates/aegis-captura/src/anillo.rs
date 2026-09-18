//! El anillo de captura: escritura secuencial y perdida **contada**.
//!
//! # La unica propiedad que importa de un capturador
//!
//! No es la velocidad: es que **sepa lo que perdio**. Un capturador que va rapido
//! y suelta paquetes en silencio produce capturas incompletas que parecen
//! completas, y un analista reconstruye un incidente sobre un hueco sin saber que
//! hay un hueco. Eso es peor que no capturar.
//!
//! De ahi las **dos** invariantes de este modulo, que las pruebas comprueban
//! paquete a paquete:
//!
//! ```text
//! (entrada)  recibidos == escritos + descartados + rechazados
//! (salida)   escritos  == drenados + desalojados + los que siguen dentro
//! ```
//!
//! Son dos y no una, y la primera version de este fichero tenia una sola — la
//! prueba de carga la tumbo enseguida: un paquete que entra en el anillo y luego
//! se desaloja para hacer sitio estaba contado en `escritos` **y** en la cifra de
//! perdidas, asi que la suma no cuadraba nunca con el anillo lleno. No era un
//! fallo del anillo: era un modelo de contabilidad que mezclaba dos cosas
//! distintas.
//!
//! **Perderse, se pierden las tres**: lo que no cupo, lo que era imposible y lo
//! que se desalojo. Ver [`Contadores::perdidos`]. Lo que no puede pasar es que un
//! paquete no aparezca en ninguna de las cuentas.
//!
//! # Por que un anillo y no una cola que crece
//!
//! Porque el atacante elige el caudal. Una cola que crece con la carga es una
//! forma elegante de que quien genere trafico decida cuanta memoria reserva el
//! agente, y de que el agente muera cuando el atacante quiera. El anillo tiene su
//! tamano fijado al arrancar y lo que no cabe **se cuenta y se tira**, que es una
//! decision consciente y no un fallo.
//!
//! # Escritura secuencial
//!
//! Los paquetes se escriben uno detras de otro en un buffer contiguo, sin saltos
//! ni indices intermedios. No es una optimizacion prematura: un disco mecanico
//! rinde dos ordenes de magnitud mas en secuencial que en aleatorio, y a un disco
//! de estado solido le alarga la vida. El precio es que no se puede borrar del
//! medio, y por eso la purga es **por particion** y no por fila.

use crate::redaccion::Limpio;

/// La cabecera que precede a cada paquete dentro del anillo.
///
/// Doce bytes: ocho de marca de tiempo y cuatro de longitud. No lleva nada mas a
/// proposito — cada byte de cabecera es un byte menos de captura, y con cien mil
/// paquetes por segundo la diferencia se nota en un dia.
pub const CABECERA: usize = 12;

/// Lo que el anillo ha visto, ha escrito, ha desalojado y ha entregado.
///
/// # Por que seis contadores y no uno
///
/// Porque «se perdio algo» no sirve para decidir nada, y porque las tres formas
/// de perder un paquete se arreglan de tres maneras distintas:
///
/// - **descartados**: no cupo aunque se desalojara. Hay mas trafico del que el
///   drenaje acepta: el arreglo esta aguas abajo, no aqui.
/// - **rechazados**: era mayor que el anillo entero. El arreglo es la
///   configuracion, y ningun anillo mayor lo soluciona si el paquete tambien
///   crece.
/// - **desalojados**: entro y se fue para hacer sitio antes de que nadie lo
///   leyera. El arreglo es un anillo mayor o un drenaje mas rapido.
///
/// Mezclarlas en un numero manda al operador a mirar donde no es.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Contadores {
    /// Paquetes que entraron por la puerta.
    pub recibidos: u64,
    /// Paquetes que llegaron a estar dentro del anillo.
    pub escritos: u64,
    /// Paquetes que no cupieron ni desalojando.
    pub descartados: u64,
    /// Paquetes mayores que el anillo entero.
    pub rechazados: u64,
    /// Paquetes que estuvieron dentro y se fueron sin que nadie los leyera.
    pub desalojados: u64,
    /// Paquetes entregados a quien drena.
    pub drenados: u64,
    /// Bytes escritos, sin contar cabeceras.
    pub bytes: u64,
}

impl Contadores {
    /// **Invariante de entrada**: todo lo que llego entro, no cupo o era
    /// imposible.
    #[must_use]
    pub fn cuadran_en_la_entrada(&self) -> bool {
        self.recibidos == self.escritos + self.descartados + self.rechazados
    }

    /// **Invariante de salida**: todo lo que entro salio leido, salio desalojado
    /// o sigue dentro.
    ///
    /// `dentro` es cuantos hay ahora mismo en el anillo; lo sabe el anillo y se
    /// pasa aqui para que esta comprobacion se pueda hacer desde fuera, que es
    /// donde tiene valor.
    #[must_use]
    pub fn cuadran_en_la_salida(&self, dentro: u64) -> bool {
        self.escritos == self.drenados + self.desalojados + dentro
    }

    /// Cuantos paquetes se perdieron, por las tres vias.
    #[must_use]
    pub fn perdidos(&self) -> u64 {
        self.descartados + self.rechazados + self.desalojados
    }

    /// Que fraccion se perdio, en centesimas.
    #[must_use]
    pub fn fraccion_perdida(&self) -> u8 {
        if self.recibidos == 0 {
            return 0;
        }
        ((u128::from(self.perdidos()) * 100) / u128::from(self.recibidos)).min(100) as u8
    }

    /// Como se cuenta esto en un informe.
    #[must_use]
    pub fn frase(&self) -> String {
        if self.perdidos() == 0 {
            return format!(
                "{} paquetes capturados sin perder ninguno ({} bytes)",
                self.escritos, self.bytes
            );
        }
        format!(
            "{} paquetes vistos; SE PERDIERON {} ({}%): {} no cupieron, {} eran mayores que el \
             anillo entero y {} se desalojaron para hacer sitio antes de leerlos. Lo que no \
             aparezca en esta captura puede ser que no ocurriera o puede ser que estuviera en \
             esos",
            self.recibidos,
            self.perdidos(),
            self.fraccion_perdida(),
            self.descartados,
            self.rechazados,
            self.desalojados
        )
    }
}

/// Un paquete leido del anillo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paquete {
    /// Cuando llego, en nanosegundos desde la epoca.
    pub cuando_ns: u64,
    /// Los bytes, ya limpios.
    pub datos: Vec<u8>,
}

/// El anillo.
///
/// # Lo que NO tiene
///
/// No tiene forma de crecer. No hay `reservar`, no hay `redimensionar` y la
/// capacidad se fija al construirlo. Es lo que impide que quien genere trafico
/// decida cuanta memoria usa el agente.
#[derive(Debug)]
pub struct Anillo {
    datos: Vec<u8>,
    /// Donde se escribe el siguiente byte.
    cabeza: usize,
    /// Donde empieza el paquete mas antiguo sin leer.
    cola: usize,
    /// Cuantos bytes hay ocupados.
    ocupados: usize,
    /// Cuantos paquetes hay dentro ahora mismo.
    dentro: u64,
    /// Lo que ha pasado, contado.
    pub contadores: Contadores,
}

impl Anillo {
    /// Un anillo de `capacidad` bytes.
    ///
    /// La capacidad se redondea hacia arriba a un mínimo util: por debajo de la
    /// cabecera mas un paquete de red normal, el anillo no cabe ni un paquete y
    /// todo lo que llegue saldra como rechazado, que se lee como un fallo del
    /// producto y es una configuracion imposible.
    #[must_use]
    pub fn nuevo(capacidad: usize) -> Anillo {
        let capacidad = capacidad.max(CABECERA + 1500);
        Anillo {
            datos: vec![0u8; capacidad],
            cabeza: 0,
            cola: 0,
            ocupados: 0,
            dentro: 0,
            contadores: Contadores::default(),
        }
    }

    /// Cuantos bytes caben en total.
    #[must_use]
    pub fn capacidad(&self) -> usize {
        self.datos.len()
    }

    /// Cuantos bytes hay ocupados ahora.
    #[must_use]
    pub fn ocupados(&self) -> usize {
        self.ocupados
    }

    /// Si no queda nada por leer.
    #[must_use]
    pub fn vacio(&self) -> bool {
        self.ocupados == 0
    }

    /// Cuantos paquetes hay dentro ahora mismo.
    #[must_use]
    pub fn dentro(&self) -> u64 {
        self.dentro
    }

    /// Si las dos invariantes se cumplen.
    #[must_use]
    pub fn cuadran(&self) -> bool {
        self.contadores.cuadran_en_la_entrada() && self.contadores.cuadran_en_la_salida(self.dentro)
    }

    /// Escribe `n` bytes en el anillo, dando la vuelta si hace falta.
    fn escribir_crudo(&mut self, bytes: &[u8]) {
        let cap = self.datos.len();
        let hasta_el_final = cap - self.cabeza;
        if bytes.len() <= hasta_el_final {
            self.datos[self.cabeza..self.cabeza + bytes.len()].copy_from_slice(bytes);
        } else {
            self.datos[self.cabeza..].copy_from_slice(&bytes[..hasta_el_final]);
            self.datos[..bytes.len() - hasta_el_final].copy_from_slice(&bytes[hasta_el_final..]);
        }
        self.cabeza = (self.cabeza + bytes.len()) % cap;
        self.ocupados += bytes.len();
    }

    /// Lee `n` bytes desde la cola sin consumirlos.
    fn leer_crudo(&self, desde: usize, n: usize) -> Vec<u8> {
        let cap = self.datos.len();
        let mut v = Vec::with_capacity(n);
        let hasta_el_final = cap - desde;
        if n <= hasta_el_final {
            v.extend_from_slice(&self.datos[desde..desde + n]);
        } else {
            v.extend_from_slice(&self.datos[desde..]);
            v.extend_from_slice(&self.datos[..n - hasta_el_final]);
        }
        v
    }

    /// Suelta el paquete mas antiguo. Devuelve si habia alguno.
    fn soltar_el_mas_viejo(&mut self) -> bool {
        if self.ocupados < CABECERA {
            return false;
        }
        let cab = self.leer_crudo(self.cola, CABECERA);
        let largo = u32::from_le_bytes([cab[8], cab[9], cab[10], cab[11]]) as usize;
        let total = CABECERA + largo;
        if total > self.ocupados {
            // No deberia poder pasar: solo se escriben paquetes enteros. Si pasa,
            // el anillo esta corrupto y vaciarlo es preferible a leer basura como
            // si fueran paquetes.
            self.cola = self.cabeza;
            self.ocupados = 0;
            self.contadores.desalojados += self.dentro;
            self.dentro = 0;
            return false;
        }
        self.cola = (self.cola + total) % self.datos.len();
        self.ocupados -= total;
        self.dentro -= 1;
        self.contadores.desalojados += 1;
        true
    }

    /// Mete un paquete.
    ///
    /// Solo acepta [`Limpio`]: no hay camino de los bytes del cable al anillo que
    /// se salte la redaccion. Ver [`crate::redaccion`].
    ///
    /// Devuelve si se escribio. Cuando no cabe, **se suelta lo mas viejo y se
    /// cuenta**: la captura es una ventana deslizante sobre el pasado reciente, y
    /// lo reciente vale mas que lo antiguo cuando hay que elegir.
    pub fn meter(&mut self, cuando_ns: u64, limpio: &Limpio) -> bool {
        self.contadores.recibidos += 1;
        let datos = limpio.bytes();
        let total = CABECERA + datos.len();

        // Un paquete mayor que el anillo entero no cabe por mucho que se suelte:
        // se cuenta aparte porque es otro problema —uno se arregla con mas anillo
        // y el otro no—.
        if total > self.datos.len() {
            self.contadores.rechazados += 1;
            return false;
        }

        // Tope de vueltas: cada vuelta libera al menos un paquete, y el numero de
        // paquetes en el anillo esta acotado por su tamano entre la cabecera.
        let mut vueltas = 0usize;
        let tope_de_vueltas = self.datos.len() / CABECERA + 1;
        while self.datos.len() - self.ocupados < total {
            if !self.soltar_el_mas_viejo() {
                break;
            }
            vueltas += 1;
            if vueltas > tope_de_vueltas {
                break;
            }
        }
        if self.datos.len() - self.ocupados < total {
            self.contadores.descartados += 1;
            return false;
        }

        let mut cab = [0u8; CABECERA];
        cab[..8].copy_from_slice(&cuando_ns.to_le_bytes());
        cab[8..].copy_from_slice(&(datos.len() as u32).to_le_bytes());
        self.escribir_crudo(&cab);
        self.escribir_crudo(datos);
        self.dentro += 1;
        self.contadores.escritos += 1;
        self.contadores.bytes += datos.len() as u64;
        true
    }

    /// Saca el paquete mas antiguo.
    pub fn sacar(&mut self) -> Option<Paquete> {
        if self.ocupados < CABECERA {
            return None;
        }
        let cab = self.leer_crudo(self.cola, CABECERA);
        let cuando_ns = u64::from_le_bytes([
            cab[0], cab[1], cab[2], cab[3], cab[4], cab[5], cab[6], cab[7],
        ]);
        let largo = u32::from_le_bytes([cab[8], cab[9], cab[10], cab[11]]) as usize;
        if CABECERA + largo > self.ocupados {
            return None;
        }
        let datos = self.leer_crudo((self.cola + CABECERA) % self.datos.len(), largo);
        self.cola = (self.cola + CABECERA + largo) % self.datos.len();
        self.ocupados -= CABECERA + largo;
        self.dentro -= 1;
        self.contadores.drenados += 1;
        Some(Paquete { cuando_ns, datos })
    }

    /// Saca todo lo que haya, en orden de llegada.
    pub fn vaciar(&mut self) -> Vec<Paquete> {
        let mut v = Vec::new();
        while let Some(p) = self.sacar() {
            v.push(p);
        }
        v
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::redaccion::{Donde, Redactor};

    fn limpio(n: usize) -> Limpio {
        Redactor::nuevo().limpiar(&vec![b'x'; n], Donde::default())
    }

    /// LAS DOS invariantes del modulo, comprobadas paquete a paquete. Si alguna
    /// no cuadra, hay paquetes que desaparecieron sin que nadie los contara, que
    /// es el fallo que este modulo existe para no tener.
    #[test]
    fn las_dos_invariantes_se_cumplen_en_cada_paquete() {
        let mut a = Anillo::nuevo(64 * 1024);
        for i in 0..5000u64 {
            a.meter(i, &limpio((i as usize % 2000) + 1));
            assert!(
                a.contadores.cuadran_en_la_entrada(),
                "la entrada no cuadra en el paquete {i}: {:?}",
                a.contadores
            );
            assert!(
                a.contadores.cuadran_en_la_salida(a.dentro()),
                "la salida no cuadra en el paquete {i}: {:?} con {} dentro",
                a.contadores,
                a.dentro()
            );
            if i % 7 == 0 {
                a.sacar();
            }
        }
        assert_eq!(a.contadores.recibidos, 5000);
        assert!(a.cuadran(), "{:?}", a.contadores);
        // Y al vaciarlo tambien, que es cuando `dentro` vuelve a cero.
        a.vaciar();
        assert_eq!(a.dentro(), 0);
        assert!(a.cuadran(), "{:?}", a.contadores);
    }

    #[test]
    fn con_anillo_de_sobra_no_se_pierde_ni_uno() {
        // «Sin perdida bajo carga» no es una aspiracion: con el anillo bien
        // dimensionado y el drenaje al dia, la cifra es cero y se mide.
        let mut a = Anillo::nuevo(4 * 1024 * 1024);
        for i in 0..20_000u64 {
            assert!(a.meter(i, &limpio(100)));
            a.sacar();
        }
        assert_eq!(a.contadores.perdidos(), 0);
        assert_eq!(a.contadores.escritos, 20_000);
        assert_eq!(a.contadores.drenados, 20_000);
        assert!(
            a.contadores.frase().contains("sin perder ninguno"),
            "{}",
            a.contadores.frase()
        );
    }

    #[test]
    fn cuando_no_cabe_se_suelta_lo_mas_viejo_y_se_cuenta() {
        // La captura es una ventana sobre el pasado reciente, y lo reciente vale
        // mas que lo antiguo cuando hay que elegir. Lo que no se puede es
        // tirarlo en silencio.
        let mut a = Anillo::nuevo(CABECERA + 1500);
        for i in 0..100u64 {
            a.meter(i, &limpio(1000));
        }
        assert!(a.contadores.desalojados > 0);
        assert!(a.cuadran(), "{:?}", a.contadores);
        assert!(
            a.contadores.frase().contains("SE PERDIERON"),
            "{}",
            a.contadores.frase()
        );
        assert!(
            a.contadores.frase().contains("se desalojaron"),
            "la frase tiene que separar las tres formas de perder: {}",
            a.contadores.frase()
        );
        // Y lo que queda dentro es lo ULTIMO, no lo primero.
        let dentro = a.vaciar();
        assert!(!dentro.is_empty());
        assert!(dentro.last().unwrap().cuando_ns >= 90);
    }

    #[test]
    fn un_paquete_mayor_que_el_anillo_se_cuenta_aparte() {
        // Se arregla con otra configuracion, no con mas anillo del que hay:
        // mezclarlo con los soltados haria que el operador buscara donde no es.
        let mut a = Anillo::nuevo(CABECERA + 1500);
        assert!(!a.meter(1, &limpio(100_000)));
        assert_eq!(a.contadores.rechazados, 1);
        assert_eq!(a.contadores.descartados, 0);
        assert_eq!(a.contadores.desalojados, 0);
        assert!(a.cuadran());
    }

    #[test]
    fn el_anillo_no_crece_por_mucho_que_le_echen() {
        // Es lo que impide que quien genere trafico decida cuanta memoria usa el
        // agente.
        let mut a = Anillo::nuevo(32 * 1024);
        let antes = a.capacidad();
        for i in 0..50_000u64 {
            a.meter(i, &limpio(1400));
        }
        assert_eq!(a.capacidad(), antes);
        assert!(a.ocupados() <= antes);
    }

    #[test]
    fn los_paquetes_salen_en_el_orden_en_que_entraron() {
        let mut a = Anillo::nuevo(1024 * 1024);
        for i in 0..200u64 {
            a.meter(i * 1000, &limpio((i as usize % 50) + 1));
        }
        let salidos = a.vaciar();
        assert_eq!(salidos.len(), 200);
        for (i, p) in salidos.iter().enumerate() {
            assert_eq!(p.cuando_ns, i as u64 * 1000);
            assert_eq!(p.datos.len(), (i % 50) + 1);
        }
    }

    #[test]
    fn dar_la_vuelta_al_buffer_no_parte_ningun_paquete() {
        // El caso que rompe los anillos mal escritos: un paquete que empieza
        // cerca del final del buffer y acaba al principio. Se mete uno y se saca
        // uno, mil veces, con longitudes que no dividen la capacidad: asi la
        // cabeza pasa por todas las posiciones y ningun paquete se desaloja, que
        // es lo que permite comparar byte a byte lo que entro con lo que salio.
        let mut a = Anillo::nuevo(CABECERA * 4 + 300);
        for i in 0..1000u64 {
            let n = (i as usize % 61) + 1;
            assert!(a.meter(i, &limpio(n)), "no cupo el paquete {i}");
            let p = a.sacar().expect("lo que acaba de entrar tiene que salir");
            assert_eq!(p.cuando_ns, i);
            assert_eq!(p.datos.len(), n, "el paquete {i} salio partido");
            assert!(
                p.datos.iter().all(|&b| b == b'x'),
                "el paquete {i} salio con bytes de otro"
            );
        }
        assert_eq!(a.contadores.desalojados, 0);
        assert!(a.cuadran(), "{:?}", a.contadores);
    }

    /// Y el mismo caso con varios dentro a la vez: dos paquetes en vuelo mientras
    /// la cabeza da la vuelta es donde se cruzan los indices mal escritos.
    #[test]
    fn dar_la_vuelta_con_varios_dentro_conserva_el_orden_y_el_contenido() {
        let mut a = Anillo::nuevo(CABECERA * 8 + 400);
        let mut esperados: Vec<(u64, usize)> = Vec::new();
        for i in 0..500u64 {
            let n = (i as usize % 37) + 1;
            let antes = a.contadores.desalojados;
            if a.meter(i, &limpio(n)) {
                // Lo que se haya desalojado para hacerle sitio sale de la cola de
                // esperados: dejo de estar disponible y el contador lo dice.
                let fuera = (a.contadores.desalojados - antes) as usize;
                esperados.drain(..fuera.min(esperados.len()));
                esperados.push((i, n));
            }
            if i % 2 == 0 {
                if let Some(p) = a.sacar() {
                    let (cuando, largo) = esperados.remove(0);
                    assert_eq!(p.cuando_ns, cuando);
                    assert_eq!(p.datos.len(), largo, "un paquete salio partido");
                    assert!(p.datos.iter().all(|&b| b == b'x'));
                }
            }
        }
        for p in a.vaciar() {
            let (cuando, largo) = esperados.remove(0);
            assert_eq!(p.cuando_ns, cuando);
            assert_eq!(p.datos.len(), largo);
            assert!(p.datos.iter().all(|&b| b == b'x'));
        }
        assert!(a.cuadran(), "{:?}", a.contadores);
    }

    #[test]
    fn un_anillo_ridiculo_se_agranda_hasta_caber_un_paquete() {
        // Un anillo que no cabe ni un paquete saca todo como rechazado, que se
        // lee como un fallo del producto y es una configuracion imposible.
        let a = Anillo::nuevo(1);
        assert!(a.capacidad() >= CABECERA + 1500);
    }

    #[test]
    fn la_fraccion_perdida_no_se_desborda() {
        let mut c = Contadores {
            recibidos: u64::MAX,
            escritos: 0,
            descartados: u64::MAX,
            rechazados: 0,
            desalojados: 0,
            drenados: 0,
            bytes: 0,
        };
        assert_eq!(c.fraccion_perdida(), 100);
        assert!(c.cuadran_en_la_entrada());
        c.recibidos = 0;
        c.descartados = 0;
        assert_eq!(c.fraccion_perdida(), 0);
    }
}
