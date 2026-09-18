//! La siembra: que token va en que senuelo, y como se sabe despues.
//!
//! # La pregunta que un tarro de miel normal no contesta
//!
//! Un senuelo cuenta visitas. Eso responde «¿me esta mirando alguien?», que es
//! util el primer dia y deja de serlo enseguida, porque en internet la respuesta
//! es siempre que si.
//!
//! La pregunta que de verdad importa en un incidente es otra: **¿por donde
//! entraron, y donde ha estado despues lo que se llevaron?** Y esa solo se
//! contesta si lo que el senuelo entrega es unico y esta atado al sitio del que
//! salio. Si el `.env` del senuelo web y el valor del senuelo de Redis llevan la
//! misma credencial, cuando esa credencial aparezca en un intento de acceso a la
//! nube tres semanas despues no se sabra cual de los dos se toco.
//!
//! Aqui cada siembra deriva su marcador de **(host, destino, numero)**, y el
//! destino incluye el servicio y el puerto. Dos senuelos distintos de la misma
//! maquina entregan credenciales distintas; la misma maquina en dos puertos, dos
//! credenciales distintas. Cuando una vuelve, el sitio esta dentro de ella.
//!
//! # Lo que esto NO hace
//!
//! No escribe nada en el disco ni siembra en la memoria de nadie: eso es de
//! `aegis-honeytoken` y de su feature `inyeccion`. Aqui se **acuna y se registra**,
//! y el texto resultante se lo queda el senuelo para servirlo cuando le pregunten.

use aegis_honeytoken::credformat::{render, Artefacto};
use aegis_honeytoken::destino::Destino;
use aegis_honeytoken::registry::Registro;
use aegis_honeytoken::token::{Acunador, Atribucion, Marcador};

/// Una siembra hecha: que se sembro, donde, y con que marcador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sembrado {
    /// A quien esta atado.
    pub atribucion: Atribucion,
    /// El marcador acunado.
    pub marcador: Marcador,
    /// Que forma tiene.
    pub artefacto: Artefacto,
    /// El texto que el senuelo entrega.
    pub texto: String,
}

/// Cuantas siembras se permiten en una plantacion.
///
/// Tiene techo por lo mismo que todo lo demas: una lista que crece sin limite es
/// una lista que alguien hace crecer. Mil tokens cubren de sobra una maquina con
/// los diecinueve senuelos y varios artefactos en cada uno.
pub const MAX_SIEMBRAS: usize = 1000;

/// La plantacion de una maquina: acuna, registra y reparte.
pub struct Plantacion {
    acunador: Acunador,
    host: String,
    registro: Registro,
    siembras: Vec<Sembrado>,
}

impl Plantacion {
    /// Una plantacion para `host` con el secreto de flota.
    #[must_use]
    pub fn nueva(secreto: [u8; 32], host: &str) -> Plantacion {
        Plantacion {
            acunador: Acunador::new(secreto),
            host: host.to_owned(),
            registro: Registro::new(),
            siembras: Vec::new(),
        }
    }

    /// Siembra un artefacto en un destino y devuelve lo que hay que servir.
    ///
    /// Devuelve `None` si la plantacion esta llena o si ese destino ya tenia una
    /// siembra: **un destino, un token**. Sembrar dos veces el mismo sitio con el
    /// mismo numero daria el mismo marcador y perderia la cuenta de cual es cual.
    pub fn sembrar(&mut self, destino: Destino, artefacto: Artefacto) -> Option<&Sembrado> {
        if self.siembras.len() >= MAX_SIEMBRAS {
            return None;
        }
        if self.registro.en_destino(&destino).is_some() {
            return None;
        }
        let atribucion = Atribucion {
            host: self.host.clone(),
            destino,
            token_id: self.siembras.len() as u32,
        };
        let marcador = self.acunador.acunar(&atribucion);
        let texto = render(artefacto, &marcador);
        self.registro.registrar(&marcador, atribucion.clone());
        self.siembras.push(Sembrado {
            atribucion,
            marcador,
            artefacto,
            texto,
        });
        self.siembras.last()
    }

    /// Siembra para un senuelo de red, que es el caso corriente.
    ///
    /// El destino queda atado al **servicio y al puerto**, asi que el mismo
    /// servicio en dos puertos distintos entrega credenciales distintas.
    pub fn sembrar_en_senuelo(
        &mut self,
        servicio: &str,
        puerto: u16,
        artefacto: Artefacto,
    ) -> Option<&Sembrado> {
        self.sembrar(
            Destino::Senuelo {
                servicio: servicio.to_owned(),
                puerto,
            },
            artefacto,
        )
    }

    /// El registro, para clasificar lo que vuelva.
    #[must_use]
    pub fn registro(&self) -> &Registro {
        &self.registro
    }

    /// Todo lo sembrado.
    #[must_use]
    pub fn siembras(&self) -> &[Sembrado] {
        &self.siembras
    }

    /// De donde salio un texto que ha reaparecido.
    ///
    /// Es **la** operacion de esta fase: alguien encuentra una credencial en un
    /// registro de acceso, en un volcado o en un aviso de un tercero, y esto dice
    /// de que senuelo salio. Si no salio de ninguno, devuelve `None` — y eso
    /// tambien es una respuesta, porque significa que la credencial es de verdad.
    #[must_use]
    pub fn de_donde_salio(&self, texto: &[u8]) -> Option<&Atribucion> {
        let hallazgos = self.registro.buscar_en(texto);
        let (marcador, _) = hallazgos.first()?;
        self.registro.atribucion(marcador)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn plantacion() -> Plantacion {
        Plantacion::nueva([0x7c; 32], "pasarela-01")
    }

    #[test]
    fn el_mismo_artefacto_en_dos_senuelos_da_dos_credenciales_distintas() {
        // **La propiedad de la fase.** Si esto fallara, una credencial que
        // reaparece no diria por que puerta salio.
        let mut p = plantacion();
        let a = p
            .sembrar_en_senuelo("http", 80, Artefacto::ClaveDeApi)
            .unwrap()
            .clone();
        let b = p
            .sembrar_en_senuelo("redis", 6379, Artefacto::ClaveDeApi)
            .unwrap()
            .clone();

        assert_ne!(a.texto, b.texto, "mismo texto: la procedencia se pierde");
        assert_ne!(a.marcador, b.marcador);
        assert_eq!(p.de_donde_salio(a.texto.as_bytes()), Some(&a.atribucion));
        assert_eq!(p.de_donde_salio(b.texto.as_bytes()), Some(&b.atribucion));
    }

    #[test]
    fn el_mismo_servicio_en_dos_puertos_tambien_se_distingue() {
        let mut p = plantacion();
        let a = p
            .sembrar_en_senuelo("http", 80, Artefacto::FicheroEnv)
            .unwrap()
            .clone();
        let b = p
            .sembrar_en_senuelo("http", 8080, Artefacto::FicheroEnv)
            .unwrap()
            .clone();
        assert_ne!(a.marcador, b.marcador);
        assert_eq!(
            p.de_donde_salio(b.texto.as_bytes())
                .map(|x| x.destino.clone()),
            Some(Destino::Senuelo {
                servicio: "http".to_owned(),
                puerto: 8080
            })
        );
    }

    #[test]
    fn todos_los_artefactos_llevan_su_marcador_y_se_pueden_rastrear() {
        let mut p = plantacion();
        let mut sembrados = Vec::new();
        for (i, art) in Artefacto::TODOS.iter().enumerate() {
            let s = p
                .sembrar(
                    Destino::Fichero {
                        ruta: format!("/srv/app/{i}.cfg"),
                    },
                    *art,
                )
                .expect("cabe")
                .clone();
            assert!(
                s.texto.contains(&s.marcador.hex()),
                "el artefacto {} no lleva el marcador",
                art.nombre()
            );
            sembrados.push(s);
        }
        // Y cada uno se rastrea hasta SU destino, no hasta otro.
        for s in &sembrados {
            assert_eq!(p.de_donde_salio(s.texto.as_bytes()), Some(&s.atribucion));
        }
    }

    #[test]
    fn un_destino_solo_se_siembra_una_vez() {
        let mut p = plantacion();
        assert!(p
            .sembrar_en_senuelo("ftp", 21, Artefacto::PgpassLinea)
            .is_some());
        assert!(
            p.sembrar_en_senuelo("ftp", 21, Artefacto::ShadowLinea)
                .is_none(),
            "dos tokens en el mismo sitio: no se sabria cual se toco"
        );
        assert_eq!(p.siembras().len(), 1);
    }

    #[test]
    fn la_plantacion_tiene_techo() {
        let mut p = plantacion();
        for i in 0..(MAX_SIEMBRAS + 10) {
            p.sembrar(
                Destino::Fichero {
                    ruta: format!("/t/{i}"),
                },
                Artefacto::PgpassLinea,
            );
        }
        assert_eq!(p.siembras().len(), MAX_SIEMBRAS);
    }

    #[test]
    fn una_credencial_de_verdad_no_se_atribuye_a_ningun_senuelo() {
        // El otro lado del cero falsos positivos: lo que no salio de aqui no se
        // dice que salio de aqui.
        let mut p = plantacion();
        p.sembrar_en_senuelo("ssh", 22, Artefacto::ClaveSshAutorizada);
        assert!(p
            .de_donde_salio(b"usuario=administrador clave=Verano2024")
            .is_none());
        // Y un marcador de otra flota tampoco.
        let otra = Plantacion::nueva([0x01; 32], "pasarela-01");
        let mut otra = otra;
        let ajeno = otra
            .sembrar_en_senuelo("ssh", 22, Artefacto::ClaveSshAutorizada)
            .unwrap()
            .clone();
        assert!(p.de_donde_salio(ajeno.texto.as_bytes()).is_none());
    }
}
