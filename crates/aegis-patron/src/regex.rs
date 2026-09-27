//! Motor de expresiones regulares sobre bytes, SIN RETROCESO.
//!
//! # La propiedad que se gana por construccion, no vigilando un limite
//!
//! YARA —y la mayoria de los motores— usan retroceso: ante `(a+)+b` y una entrada
//! sin `b`, exploran exponencialmente y se cuelgan. Es ReDoS, y viaja en corpus
//! publicos de reglas. Aqui el motor es una simulacion tipo Pike VM del NFA de
//! Thompson: mantiene TODOS los estados activos a la vez y avanza un byte cada
//! vez. Cada byte toca cada estado como mucho una vez, asi que el tiempo es
//! O(entrada x estados) SIEMPRE, sin importar la regex. No hay retroceso que
//! explote, y por eso no hay ReDoS — no porque se vigile, sino porque no existe la
//! via.
//!
//! # Determinismo
//!
//! El conjunto de coincidencias no depende del orden en que se activan los estados
//! ni del numero de hilos: la simulacion es una funcion pura de (programa,
//! entrada). Dos ejecuciones dan lo mismo.

/// Una instruccion del programa NFA compilado.
///
/// El NFA de Thompson se compila a un programa lineal de estas instrucciones; la
/// simulacion es un interprete de este programa que mantiene un conjunto de
/// contadores de programa activos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Insn {
    /// Consume un byte exacto y avanza.
    Byte(u8),
    /// Consume cualquier byte que caiga en la clase y avanza.
    ///
    /// La clase va en `Box` porque es un mapa de 256 bits: dejarla inline haria
    /// que cada instruccion del programa —la mayoria diminutas— ocupara lo que la
    /// mayor, malgastando memoria en programas grandes.
    Clase(Box<ClaseBytes>),
    /// Consume cualquier byte.
    Cualquiera,
    /// Bifurca a dos continuaciones (sin consumir): el estado se duplica.
    Bifurcar(usize, usize),
    /// Salta (sin consumir).
    Saltar(usize),
    /// Coincidencia: el estado ha aceptado.
    Aceptar,
}

/// Una clase de bytes: un conjunto representado por 256 bits, quiza negado ya
/// resuelto en el mapa. Es de tamano fijo, asi que no hay reserva por clase que un
/// atacante pueda inflar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaseBytes {
    mapa: [bool; 256],
}

impl ClaseBytes {
    /// Una clase vacia.
    #[must_use]
    pub fn vacia() -> ClaseBytes {
        ClaseBytes { mapa: [false; 256] }
    }

    /// Anade un rango inclusivo `[lo, hi]`.
    pub fn rango(&mut self, lo: u8, hi: u8) {
        let mut b = lo;
        loop {
            self.mapa[b as usize] = true;
            if b == hi {
                break;
            }
            b = b.wrapping_add(1);
        }
    }

    /// Anade un byte suelto.
    pub fn byte(&mut self, b: u8) {
        self.mapa[b as usize] = true;
    }

    /// Niega la clase (lo que no estaba, ahora esta).
    #[must_use]
    pub fn negada(mut self) -> ClaseBytes {
        for v in &mut self.mapa {
            *v = !*v;
        }
        self
    }

    /// Si un byte pertenece a la clase.
    #[must_use]
    pub fn contiene(&self, b: u8) -> bool {
        self.mapa[b as usize]
    }
}

/// Un programa NFA compilado, listo para simular.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Programa {
    insns: Vec<Insn>,
    /// Cota del numero de estados activos simultaneos, para acotar la memoria de
    /// la simulacion. Es tantos como instrucciones: cada PC aparece como mucho una
    /// vez en el conjunto activo.
    estados: usize,
}

impl Programa {
    /// Construye un programa a partir de sus instrucciones.
    #[must_use]
    pub fn nuevo(insns: Vec<Insn>) -> Programa {
        let estados = insns.len();
        Programa { insns, estados }
    }

    /// Cuantas instrucciones tiene (la cota de estados).
    #[must_use]
    pub fn estados(&self) -> usize {
        self.estados
    }

    /// Busca la primera coincidencia en `entrada` a partir de `desde`, devolviendo
    /// el desplazamiento de inicio si coincide en esa posicion.
    ///
    /// Es una simulacion tipo Pike VM: mantiene un conjunto de contadores de
    /// programa activos y avanza un byte cada vez. Sin retroceso.
    #[must_use]
    pub fn casa_en(&self, entrada: &[u8], desde: usize) -> bool {
        // `activos` es el conjunto de PCs vivos; `marca` evita duplicados en el
        // mismo paso (que es lo que hace la simulacion lineal en vez de
        // exponencial).
        let mut activos: Vec<usize> = Vec::with_capacity(self.estados);
        let mut marca_gen: Vec<u32> = vec![0; self.insns.len()];
        let mut gen = 1u32;

        self.anadir(&mut activos, &mut marca_gen, gen, 0);
        let mut pos = desde;
        loop {
            // Si algun estado activo es Aceptar, hay coincidencia.
            if activos
                .iter()
                .any(|&pc| matches!(self.insns[pc], Insn::Aceptar))
            {
                return true;
            }
            if pos >= entrada.len() {
                return false;
            }
            let b = entrada[pos];
            gen += 1;
            let mut siguientes: Vec<usize> = Vec::with_capacity(self.estados);
            for &pc in &activos {
                match &self.insns[pc] {
                    Insn::Byte(x) if *x == b => {
                        self.anadir(&mut siguientes, &mut marca_gen, gen, pc + 1);
                    }
                    Insn::Cualquiera => {
                        self.anadir(&mut siguientes, &mut marca_gen, gen, pc + 1);
                    }
                    Insn::Clase(c) if c.contiene(b) => {
                        self.anadir(&mut siguientes, &mut marca_gen, gen, pc + 1);
                    }
                    _ => {}
                }
            }
            activos = siguientes;
            pos += 1;
            if activos.is_empty() {
                return false;
            }
        }
    }

    /// Anade un PC al conjunto activo, siguiendo las bifurcaciones y saltos (que no
    /// consumen), sin duplicar en el mismo paso. Iterativo, para que una regex
    /// patologica no desborde la pila.
    fn anadir(&self, activos: &mut Vec<usize>, marca: &mut [u32], gen: u32, pc0: usize) {
        let mut pila = vec![pc0];
        while let Some(pc) = pila.pop() {
            if pc >= self.insns.len() || marca[pc] == gen {
                continue;
            }
            marca[pc] = gen;
            match &self.insns[pc] {
                Insn::Bifurcar(a, b) => {
                    pila.push(*b);
                    pila.push(*a);
                }
                Insn::Saltar(t) => pila.push(*t),
                _ => activos.push(pc),
            }
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Compila `abc` a mano: tres bytes y aceptar.
    fn abc() -> Programa {
        Programa::nuevo(vec![
            Insn::Byte(b'a'),
            Insn::Byte(b'b'),
            Insn::Byte(b'c'),
            Insn::Aceptar,
        ])
    }

    #[test]
    fn una_literal_casa_donde_esta() {
        let p = abc();
        assert!(p.casa_en(b"abc", 0));
        assert!(!p.casa_en(b"abd", 0));
        assert!(!p.casa_en(b"ab", 0), "truncada no casa");
    }

    #[test]
    fn una_clase_de_bytes_casa_su_conjunto() {
        // [0-9]
        let mut c = ClaseBytes::vacia();
        c.rango(b'0', b'9');
        let p = Programa::nuevo(vec![Insn::Clase(Box::new(c)), Insn::Aceptar]);
        assert!(p.casa_en(b"5", 0));
        assert!(!p.casa_en(b"x", 0));
    }

    #[test]
    fn una_clase_negada_casa_el_complemento() {
        let mut c = ClaseBytes::vacia();
        c.byte(b'a');
        let p = Programa::nuevo(vec![Insn::Clase(Box::new(c.negada())), Insn::Aceptar]);
        assert!(p.casa_en(b"b", 0));
        assert!(!p.casa_en(b"a", 0));
    }

    #[test]
    fn la_estrella_de_kleene_no_retrocede_ni_se_cuelga() {
        // a*  ->  L0: Bifurcar(L1, L3); L1: Byte('a'); L2: Saltar(L0); L3: Aceptar
        let p = Programa::nuevo(vec![
            Insn::Bifurcar(1, 3),
            Insn::Byte(b'a'),
            Insn::Saltar(0),
            Insn::Aceptar,
        ]);
        assert!(p.casa_en(b"", 0), "cero repeticiones casan");
        assert!(p.casa_en(b"aaaa", 0));
    }

    #[test]
    fn el_patron_patologico_de_redos_corre_en_tiempo_lineal() {
        // (a+)+ sobre una entrada larga de 'a' sin el byte final que exige el
        // resto: un motor con retroceso explota; este termina de inmediato porque
        // cada byte toca cada estado una vez. La prueba es que TERMINA.
        // (a+)+c  aproximado:
        // 0: Bifurcar(1,5)  ; entrar al grupo o salir
        // 1: Byte('a')
        // 2: Bifurcar(1,3)  ; a+
        // 3: Bifurcar(0,4)  ; (…)+  repetir grupo o
        // 4: Saltar(5)
        // 5: Byte('c')
        // 6: Aceptar
        let p = Programa::nuevo(vec![
            Insn::Bifurcar(1, 5),
            Insn::Byte(b'a'),
            Insn::Bifurcar(1, 3),
            Insn::Bifurcar(0, 4),
            Insn::Saltar(5),
            Insn::Byte(b'c'),
            Insn::Aceptar,
        ]);
        let entrada = vec![b'a'; 100_000]; // sin 'c' final
                                           // Si hubiera retroceso, esto no volveria en la vida. Con Pike VM, si.
        assert!(!p.casa_en(&entrada, 0));
    }

    #[test]
    fn la_simulacion_es_determinista() {
        let p = abc();
        assert_eq!(p.casa_en(b"abc", 0), p.casa_en(b"abc", 0));
    }
}
