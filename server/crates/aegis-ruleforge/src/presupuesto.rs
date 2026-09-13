//! El presupuesto de compilacion: lo que un feed hostil NO puede hacer.
//!
//! # Quien elige el tamano de la entrada
//!
//! El contenido que entra aqui viene de feeds publicos: Emerging Threats, el
//! catalogo Sigma, las bases de ClamAV, colecciones de YARA de terceros. Son
//! utiles y son de otros. Si uno se compromete —o simplemente si alguien sube
//! una regla mal escrita— el fichero que llega a esta fabrica lo escribe alguien
//! que no somos nosotros.
//!
//! Y una fabrica de reglas sin topes es una via directa para tumbar el plano de
//! control: un fichero con diez millones de reglas, o una sola regla de
//! cuatrocientos megas, o una expresion regular que tarda horas en compilarse.
//! Ninguna de esas tres cosas es un ataque sofisticado; las tres son un fichero
//! de texto.
//!
//! # Por que los topes se DECLARAN y no se descubren
//!
//! Un tope implicito —el que salga de la memoria de la maquina— convierte un
//! fichero grande en una caida, y una caida del plano de control es una flota
//! entera sin consola. Un tope explicito convierte el mismo fichero en un
//! informe que dice «este feed trae mas reglas de las que acepto, y estas son
//! las que no entraron».
//!
//! La diferencia practica es quien se entera: en el primer caso, nadie hasta que
//! se cae; en el segundo, quien lee el informe, antes de distribuir nada.

/// Topes de una compilacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presupuesto {
    /// Reglas que se aceptan de un feed.
    ///
    /// Un catalogo real de Emerging Threats ronda las 40.000 reglas; cien mil da
    /// holgura de sobra y corta de raiz un fichero generado para agotar memoria.
    pub max_reglas: usize,
    /// Bytes que puede ocupar una sola regla.
    ///
    /// Una regla de red de verdad cabe en una linea larga. Sesenta y cuatro
    /// kilobytes es absurdamente generoso para una, y ridiculo para un ataque.
    pub max_bytes_regla: usize,
    /// Bytes que puede ocupar el fichero de entrada entero.
    pub max_bytes_entrada: usize,
    /// Complejidad maxima admitida en una expresion regular.
    ///
    /// Ver [`crate::regex_segura`]: no es el largo, es la estructura.
    pub max_complejidad_regex: u32,
    /// Patrones de contenido que se aceptan en una sola regla.
    ///
    /// Una regla con cientos de patrones no detecta mejor: cuesta mas por
    /// paquete, y ese coste lo paga el endpoint del cliente.
    pub max_patrones_por_regla: usize,
    /// Profundidad maxima de anidamiento en una condicion Sigma.
    pub max_anidamiento: usize,
}

/// Presupuesto por defecto, dimensionado contra catalogos reales.
pub const POR_DEFECTO: Presupuesto = Presupuesto {
    max_reglas: 100_000,
    max_bytes_regla: 64 * 1024,
    max_bytes_entrada: 256 * 1024 * 1024,
    max_complejidad_regex: 10_000,
    max_patrones_por_regla: 64,
    max_anidamiento: 16,
};

impl Default for Presupuesto {
    fn default() -> Presupuesto {
        POR_DEFECTO
    }
}

impl Presupuesto {
    /// Un presupuesto con todos los topes al minimo util.
    ///
    /// Existe para las pruebas: ejercer un tope con el valor de produccion
    /// obligaria a generar cien mil reglas en cada prueba, que es lento y hace
    /// que nadie quiera escribir la prueba. Un tope que no se ejerce es un tope
    /// que puede estar roto.
    #[must_use]
    pub fn estrecho() -> Presupuesto {
        Presupuesto {
            max_reglas: 4,
            max_bytes_regla: 256,
            max_bytes_entrada: 4096,
            max_complejidad_regex: 50,
            max_patrones_por_regla: 3,
            max_anidamiento: 3,
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Los topes por defecto tienen que ser HOLGADOS para el contenido real. Un
    /// tope que rechaza catalogos legitimos se desactiva el primer dia, y un
    /// tope desactivado no protege de nada.
    #[test]
    fn los_topes_por_defecto_dan_cabida_al_contenido_real() {
        let p = Presupuesto::default();
        // Emerging Threats ronda las 40.000 reglas.
        assert!(p.max_reglas >= 50_000, "max_reglas = {}", p.max_reglas);
        // Una regla de red de verdad cabe de sobra en una linea larga.
        assert!(p.max_bytes_regla >= 8 * 1024);
        // Las bases de ClamAV pasan de los 200 MB.
        assert!(p.max_bytes_entrada >= 200 * 1024 * 1024);
    }

    /// Y el estrecho tiene que ser de verdad estrecho, o las pruebas que lo usan
    /// no estarian ejerciendo ningun tope.
    #[test]
    fn el_presupuesto_estrecho_ejerce_los_topes_de_verdad() {
        let p = Presupuesto::estrecho();
        assert!(p.max_reglas < 10);
        assert!(p.max_bytes_regla < 1024);
        assert!(p.max_patrones_por_regla < 10);
    }
}
