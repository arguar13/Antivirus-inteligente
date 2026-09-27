//! El entorno sintetico: lo que la muestra "ve" del sistema, todo en memoria.
//!
//! # La ausencia es la frontera
//!
//! Qiling puede montar el sistema de ficheros del anfitrion: una muestra emulada
//! puede leer y escribir ficheros REALES. Aqui eso NO EXISTE. El entorno es un
//! sistema de ficheros, un registro y una red **en memoria**, con respuestas
//! DECLARADAS. No hay ninguna operacion en este tipo que abra un fichero real, un
//! socket real ni una clave de registro real —se verifica por lo que FALTA del
//! enumerado, no por una comprobacion que podria estar mal—.
//!
//! Lo que el malware "vea" es una decision escrita, no un descuido: si pregunta por
//! `/proc/self/status` o por `C:\Windows`, recibe lo que este entorno diga, y si
//! pregunta por algo no declarado, el emulador se PARA y lo dice, en vez de
//! devolver cero y dejar que el analisis siga sobre una mentira.

use std::collections::BTreeMap;

/// La respuesta declarada a una consulta del entorno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Respuesta {
    /// Unos bytes (el contenido de un fichero, una lectura de red).
    Bytes(Vec<u8>),
    /// Un valor entero (un descriptor, un codigo de retorno).
    Entero(i64),
    /// El recurso no existe (y eso es una respuesta, no un error del emulador).
    NoExiste,
}

/// El entorno sintetico. Todo lo que contiene esta en memoria; no hay nada que
/// conecte con el sistema real.
#[derive(Debug, Default)]
pub struct Entorno {
    /// Sistema de ficheros sintetico: ruta -> contenido.
    ficheros: BTreeMap<String, Vec<u8>>,
    /// Registro sintetico (Windows): clave -> valor.
    registro: BTreeMap<String, Vec<u8>>,
    /// Respuestas de red declaradas por destino.
    red: BTreeMap<String, Vec<u8>>,
    /// Lo que la muestra escribio: no va a ningun sitio real, se guarda para el
    /// informe (que intento escribir, y donde).
    escrituras: Vec<(String, Vec<u8>)>,
}

impl Entorno {
    /// Un entorno vacio.
    #[must_use]
    pub fn nuevo() -> Entorno {
        Entorno::default()
    }

    /// Declara el contenido de un fichero sintetico.
    pub fn declarar_fichero(&mut self, ruta: &str, contenido: &[u8]) {
        self.ficheros.insert(ruta.to_string(), contenido.to_vec());
    }

    /// Declara una clave de registro sintetica.
    pub fn declarar_registro(&mut self, clave: &str, valor: &[u8]) {
        self.registro.insert(clave.to_string(), valor.to_vec());
    }

    /// Declara la respuesta de red de un destino.
    pub fn declarar_red(&mut self, destino: &str, respuesta: &[u8]) {
        self.red.insert(destino.to_string(), respuesta.to_vec());
    }

    /// Abre/lee un fichero sintetico. Nunca toca el disco real.
    #[must_use]
    pub fn leer_fichero(&self, ruta: &str) -> Respuesta {
        self.ficheros
            .get(ruta)
            .map_or(Respuesta::NoExiste, |b| Respuesta::Bytes(b.clone()))
    }

    /// Lee una clave de registro sintetica.
    #[must_use]
    pub fn leer_registro(&self, clave: &str) -> Respuesta {
        self.registro
            .get(clave)
            .map_or(Respuesta::NoExiste, |b| Respuesta::Bytes(b.clone()))
    }

    /// "Envia" a un destino de red: devuelve la respuesta declarada. No abre ningun
    /// socket; anota el intento.
    #[must_use]
    pub fn red(&self, destino: &str) -> Respuesta {
        self.red
            .get(destino)
            .map_or(Respuesta::NoExiste, |b| Respuesta::Bytes(b.clone()))
    }

    /// Anota una escritura de la muestra. NO va a ningun sitio real: se guarda para
    /// el informe de comportamiento.
    pub fn anotar_escritura(&mut self, destino: &str, datos: &[u8]) {
        self.escrituras.push((destino.to_string(), datos.to_vec()));
    }

    /// Las escrituras que la muestra intento, para el informe.
    #[must_use]
    pub fn escrituras(&self) -> &[(String, Vec<u8>)] {
        &self.escrituras
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_fichero_no_declarado_no_existe_no_se_inventa() {
        let e = Entorno::nuevo();
        assert_eq!(e.leer_fichero("/etc/passwd"), Respuesta::NoExiste);
    }

    #[test]
    fn lo_declarado_es_lo_que_ve_la_muestra() {
        let mut e = Entorno::nuevo();
        e.declarar_fichero("/proc/self/status", b"TracerPid:\t0\n");
        assert_eq!(
            e.leer_fichero("/proc/self/status"),
            Respuesta::Bytes(b"TracerPid:\t0\n".to_vec())
        );
    }

    #[test]
    fn una_escritura_no_va_a_ningun_sitio_real_pero_se_anota() {
        let mut e = Entorno::nuevo();
        e.anotar_escritura("/tmp/dropper.sh", b"#!/bin/sh\n");
        assert_eq!(e.escrituras().len(), 1);
        assert_eq!(e.escrituras()[0].0, "/tmp/dropper.sh");
        // Y no existe ningun /tmp/dropper.sh real: solo se anoto el intento.
    }

    #[test]
    fn la_red_declarada_responde_y_lo_no_declarado_no_existe() {
        let mut e = Entorno::nuevo();
        e.declarar_red("1.2.3.4:80", b"HTTP/1.1 200 OK\r\n\r\n");
        assert!(matches!(e.red("1.2.3.4:80"), Respuesta::Bytes(_)));
        assert_eq!(e.red("8.8.8.8:53"), Respuesta::NoExiste);
    }
}
