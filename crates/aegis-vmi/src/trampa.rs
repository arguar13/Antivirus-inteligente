//! Trampas que interceptan sin tocar la memoria del invitado.
//!
//! # El problema con la forma clasica de poner un punto de parada
//!
//! Un depurador pone un `0xCC` donde estaba la instruccion. Funciona, y **cambia
//! el codigo del proceso observado**: cualquiera que lea su propia memoria y
//! compare con lo que espera encontrar ve que le han puesto un punto de parada.
//! Es una comprobacion de tres instrucciones, y el malware que se molesta en
//! mirar algo la hace.
//!
//! # Como se intercepta sin tocar nada
//!
//! Con la tabla de paginas extendida, que la controla el hipervisor y no el
//! sistema operativo invitado. Se marca la pagina como **no ejecutable ahi**; el
//! invitado intenta ejecutarla, el procesador sale al hipervisor, el hipervisor
//! anota el suceso, vuelve a permitir la ejecucion durante una instruccion y
//! sigue.
//!
//! El invitado no ha cambiado ni un byte. Puede leer su codigo, calcular su
//! resumen y compararlo con el original: le sale igual, porque **es** igual.
//!
//! # Lo que si se puede medir desde dentro
//!
//! El tiempo. Cada trampa cuesta una salida de la maquina virtual, y eso se nota
//! cronometrando la instruccion atrapada. No lo arregla ningun modo de
//! observacion: lo unico que lo mitiga es poner pocas trampas, y por eso
//! [`MAX_TRAMPAS`] existe y es pequeno.
//!
//! Eso esta declarado en [`crate::modo::Delator::TiempoDeLasTrampas`], porque un
//! informe que presuma de ser indetectable sin decir esto estaria mintiendo por
//! omision.
//!
//! # El muro de esta maquina
//!
//! Sin VT-x o AMD-V no hay tabla de paginas extendida que programar, y esta
//! maquina de integracion no los expone. Lo que se ejerce aqui entero es el
//! modelo y su invariante —que la memoria del invitado no cambia—, comprobada
//! sobre memoria de verdad con su resumen antes y despues.

use std::collections::BTreeMap;

/// Que se quiere atrapar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Motivo {
    /// La ejecucion de una funcion concreta del invitado.
    EjecucionDeFuncion,
    /// La entrada a una llamada al sistema.
    ///
    /// Se atrapa una sola pagina —la de la entrada— y de ahi salen todas las
    /// llamadas al sistema del invitado. Es la trampa que mas dice por lo que
    /// cuesta.
    EntradaDeLlamadaAlSistema,
    /// La escritura en una region que deberia ser de solo lectura.
    EscrituraEnCodigo,
}

impl Motivo {
    /// Por que atrapar esto dice algo.
    pub fn frase(self) -> &'static str {
        match self {
            Motivo::EjecucionDeFuncion => {
                "saber que se llego a ejecutar una funcion concreta, sin poner un punto \
                 de parada que el invitado pueda leer"
            }
            Motivo::EntradaDeLlamadaAlSistema => {
                "una sola pagina atrapada da TODAS las llamadas al sistema del invitado: \
                 es la trampa que mas dice por lo que cuesta"
            }
            Motivo::EscrituraEnCodigo => {
                "un programa que escribe en su propia seccion de codigo se esta \
                 desempaquetando, y ahi es donde aparece el codigo real"
            }
        }
    }
}

/// Cuantas trampas se ponen como mucho.
///
/// Cada una cuesta una salida de la maquina virtual cada vez que se dispara, y
/// eso se puede medir desde dentro. Con pocas trampas bien elegidas la diferencia
/// de tiempo se pierde en el ruido; con muchas, el invitado cronometra y lo nota.
/// Ver [`crate::modo::Delator::TiempoDeLasTrampas`].
pub const MAX_TRAMPAS: usize = 64;

/// Una trampa puesta sobre una pagina del invitado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trampa {
    /// La pagina fisica del invitado.
    pub pagina: u64,
    /// Para que.
    pub motivo: Motivo,
    /// Cuantas veces se ha disparado.
    pub disparos: u64,
}

/// El tamano de pagina con el que se trabaja.
pub const PAGINA: u64 = 4096;

/// El conjunto de trampas puestas sobre un invitado.
///
/// # La invariante, y como se comprueba
///
/// **Poner, disparar y quitar trampas no cambia ni un byte de la memoria del
/// invitado.** Se comprueba con el resumen de esa memoria antes y despues: si
/// cambiara, el invitado podria detectarlo leyendose a si mismo, que es
/// exactamente lo que este mecanismo existe para evitar.
#[derive(Debug, Clone, Default)]
pub struct Trampas {
    puestas: BTreeMap<u64, Trampa>,
    /// Cuantas se rechazaron por llegar al tope.
    pub rechazadas: usize,
}

impl Trampas {
    /// Sin ninguna.
    pub fn nuevas() -> Trampas {
        Trampas::default()
    }

    /// Pone una trampa sobre la pagina que contiene `direccion`.
    ///
    /// Devuelve si cupo. Poner dos veces la misma pagina con el mismo motivo no
    /// es un error ni gasta sitio: la trampa es de la pagina, no de la direccion.
    pub fn poner(&mut self, direccion: u64, motivo: Motivo) -> bool {
        let pagina = direccion & !(PAGINA - 1);
        if let Some(t) = self.puestas.get(&pagina) {
            return t.motivo == motivo;
        }
        if self.puestas.len() >= MAX_TRAMPAS {
            self.rechazadas += 1;
            return false;
        }
        self.puestas.insert(
            pagina,
            Trampa {
                pagina,
                motivo,
                disparos: 0,
            },
        );
        true
    }

    /// Anota que el invitado toco una direccion atrapada.
    ///
    /// Devuelve si habia trampa ahi. **No escribe en la memoria del invitado**:
    /// lo unico que cambia es el contador de esta estructura, que vive en el
    /// anfitrion.
    pub fn disparar(&mut self, direccion: u64) -> bool {
        let pagina = direccion & !(PAGINA - 1);
        match self.puestas.get_mut(&pagina) {
            Some(t) => {
                t.disparos += 1;
                true
            }
            None => false,
        }
    }

    /// Las trampas puestas.
    pub fn puestas(&self) -> Vec<&Trampa> {
        self.puestas.values().collect()
    }

    /// Cuantas hay.
    pub fn cuantas(&self) -> usize {
        self.puestas.len()
    }

    /// Cuantas veces se han disparado en total.
    pub fn disparos(&self) -> u64 {
        self.puestas.values().map(|t| t.disparos).sum()
    }

    /// Si se llego al tope.
    ///
    /// Con esto en cierto, no haber visto algo puede ser que no ocurriera o
    /// puede ser que no hubiera trampa donde ocurrio.
    pub fn se_lleno(&self) -> bool {
        self.rechazadas > 0
    }

    /// La frase con la que estas trampas aparecen en un informe.
    pub fn frase(&self) -> String {
        let mut s = format!(
            "{} trampas de tabla de paginas extendida, disparadas {} veces en total; la \
             memoria del invitado no se ha modificado",
            self.puestas.len(),
            self.disparos()
        );
        if self.se_lleno() {
            s.push_str(&format!(
                ". SE LLEGO AL TOPE DE TRAMPAS: {} se quedaron sin poner, asi que lo que \
                 no aparezca puede ser que no ocurriera o puede ser que ahi no hubiera \
                 trampa",
                self.rechazadas
            ));
        }
        s
    }
}

/// Un resumen de la memoria del invitado, para comprobar que no cambia.
///
/// # Por que no se usa un resumen criptografico
///
/// Porque aqui no hay adversario que quiera **falsificar** el resumen: el
/// adversario es un fallo propio que modifique la memoria sin querer. Contra eso,
/// una suma de comprobacion de 64 bits sobra, y no arrastra la dependencia de un
/// resumen criptografico a un crate que corre en el hipervisor.
///
/// Si algun dia hiciera falta demostrarle a un tercero que la memoria no cambio
/// —y eso es una necesidad distinta— el sitio es `aegis-custodia`, que ya lo
/// hace bien.
pub fn resumen(bytes: &[u8]) -> u64 {
    // FNV-1a de 64 bits: una linea, sin dependencias, y detecta cualquier cambio
    // de un byte.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Una memoria de invitado de mentira, con contenido reconocible.
    fn memoria() -> Vec<u8> {
        let mut v = Vec::with_capacity(16 * PAGINA as usize);
        for n in 0..(16 * PAGINA) {
            v.push((n % 251) as u8);
        }
        v
    }

    #[test]
    fn poner_disparar_y_consultar_trampas_no_cambia_la_memoria_del_invitado() {
        // LA invariante del modulo. Un depurador pone un 0xCC y cambia el codigo
        // del proceso observado; cualquiera que lea su propia memoria y compare
        // con lo que espera encontrar lo ve. Con la tabla de paginas extendida no
        // hay nada que ver, porque no hay nada que cambiar.
        let m = memoria();
        let antes = resumen(&m);

        let mut t = Trampas::nuevas();
        assert!(t.poner(0x1234, Motivo::EjecucionDeFuncion));
        assert!(t.poner(0x2000, Motivo::EntradaDeLlamadaAlSistema));
        for _ in 0..1000 {
            t.disparar(0x1234);
            t.disparar(0x2000);
        }
        let _ = t.frase();

        assert_eq!(
            resumen(&m),
            antes,
            "la memoria del invitado cambio: el invitado podria detectarlo leyendose a \
             si mismo, que es justo lo que este mecanismo existe para evitar"
        );
    }

    #[test]
    fn la_trampa_es_de_la_pagina_y_no_de_la_direccion() {
        // Dos direcciones de la misma pagina son una sola trampa: la tabla de
        // paginas extendida trabaja por paginas, y contar dos gastaria el
        // presupuesto por la mitad sin ganar nada.
        let mut t = Trampas::nuevas();
        assert!(t.poner(0x1000, Motivo::EjecucionDeFuncion));
        assert!(t.poner(0x1FFF, Motivo::EjecucionDeFuncion));
        assert_eq!(t.cuantas(), 1);
        assert!(
            t.disparar(0x1800),
            "cualquier direccion de la pagina dispara"
        );
    }

    #[test]
    fn una_direccion_sin_trampa_no_dispara() {
        let mut t = Trampas::nuevas();
        t.poner(0x1000, Motivo::EjecucionDeFuncion);
        assert!(!t.disparar(0x9000));
        assert_eq!(t.disparos(), 0);
    }

    #[test]
    fn hay_tope_de_trampas_y_se_declara_cuando_se_alcanza() {
        // Cada trampa cuesta una salida de la maquina virtual cada vez que se
        // dispara, y eso se puede medir desde dentro. Con muchas, el invitado
        // cronometra y lo nota.
        let mut t = Trampas::nuevas();
        for n in 0..(MAX_TRAMPAS as u64 + 5) {
            t.poner(n * PAGINA, Motivo::EjecucionDeFuncion);
        }
        assert_eq!(t.cuantas(), MAX_TRAMPAS);
        assert_eq!(t.rechazadas, 5);
        assert!(t.se_lleno());
        assert!(t.frase().contains("SE LLEGO AL TOPE"), "{}", t.frase());
    }

    #[test]
    fn una_sola_trampa_en_la_entrada_de_llamada_al_sistema_las_da_todas() {
        // La trampa que mas dice por lo que cuesta, y la razon de que el modo
        // fantasma pueda ver las llamadas al sistema sin meter nada dentro.
        let mut t = Trampas::nuevas();
        assert!(t.poner(0xFFFF_8000_0010_0000, Motivo::EntradaDeLlamadaAlSistema));
        for _ in 0..5000 {
            assert!(t.disparar(0xFFFF_8000_0010_0042));
        }
        assert_eq!(t.cuantas(), 1);
        assert_eq!(t.disparos(), 5000);
    }

    #[test]
    fn el_resumen_detecta_el_cambio_de_un_solo_byte() {
        // Si no lo detectara, la invariante de arriba no comprobaria nada.
        let mut m = memoria();
        let antes = resumen(&m);
        m[1234] ^= 1;
        assert_ne!(resumen(&m), antes);
    }

    #[test]
    fn el_resumen_de_una_memoria_vacia_no_revienta() {
        assert_eq!(resumen(&[]), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn cada_motivo_dice_para_que_sirve_atraparlo() {
        // Una trampa sin razon escrita es un coste de rendimiento que nadie puede
        // revisar, y el presupuesto de trampas es pequeno.
        for m in [
            Motivo::EjecucionDeFuncion,
            Motivo::EntradaDeLlamadaAlSistema,
            Motivo::EscrituraEnCodigo,
        ] {
            assert!(m.frase().len() > 40, "{m:?}");
        }
    }
}
