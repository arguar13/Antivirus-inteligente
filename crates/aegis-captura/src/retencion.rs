//! La politica de retencion, **expresada en el tipo**.
//!
//! # El problema que resuelve
//!
//! Guardar el trafico entero de una flota es caro y es una responsabilidad. Y
//! guardar solo metadatos deja al analista sin lo unico que de verdad cierra un
//! incidente: los bytes. La respuesta no es elegir uno de los dos, es **retener
//! por veredicto**: entero lo que el arbitro marco, y solo el sobre lo demas.
//!
//! Medido en la prueba de comparacion: un orden de magnitud menos de disco para
//! el mismo trafico, sin perder ni un byte de lo que importa.
//!
//! # Por que en el tipo y no en una bandera
//!
//! Porque una bandera se lee mal una vez y se guarda un terabyte de trafico
//! sanitario. Aqui el escritor de contenido completo pide una [`Autorizacion`],
//! y una `Autorizacion` **solo se puede construir desde un veredicto que la
//! justifique**. No hay `Autorizacion::nueva()`, no hay `Default`, y el campo es
//! privado: sin veredicto no hay cuerpo, y eso se verifica por lo que falta.
//!
//! # La caducidad tampoco es una bandera
//!
//! Cada trozo guardado lleva su [`Caducidad`] puesta en el momento de escribirlo,
//! derivada de su politica. El almacen purga **por particion**, no borrando filas
//! una a una: borrar fila a fila en un almacen de terabytes no acaba nunca y deja
//! el disco lleno mientras lo intenta.

use aegis_entidad::arbitro::{Resultado, Veredicto};
use aegis_entidad::escala::Severidad;

/// Cuanto se guarda de un flujo.
///
/// El orden de las variantes es el de menos a mas, y se usa: cuando dos motivos
/// piden politicas distintas para el mismo flujo, gana la mayor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Politica {
    /// Nada. Ni siquiera el sobre.
    ///
    /// Existe para el trafico que el cliente declara que no quiere retener en
    /// absoluto. Es una eleccion suya, y se respeta.
    Nada,
    /// Solo el sobre: quien, con quien, cuando, cuanto y que protocolo.
    ///
    /// Es la politica **por defecto**, y no es una concesion: el noventa y nueve
    /// por ciento del trafico de una red no se va a mirar nunca, y guardarlo
    /// entero es pagar por no decidir.
    SoloMetadatos,
    /// El sobre y los primeros bytes de cada sentido.
    ///
    /// Cubre el caso que mas aparece al investigar: ver el saludo, la peticion o
    /// la cabecera sin arrastrar la descarga entera.
    Cabeceras,
    /// Todo, byte a byte.
    ///
    /// Solo con [`Autorizacion`]. Es lo que permite reproducir el flujo y volver
    /// a arbitrarlo.
    Completo,
}

impl Politica {
    /// Nombre estable, que es el que aparece en la configuracion del cliente.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Politica::Nada => "nada",
            Politica::SoloMetadatos => "solo-metadatos",
            Politica::Cabeceras => "cabeceras",
            Politica::Completo => "completo",
        }
    }

    /// Cuantos bytes de cada sentido se guardan como maximo.
    ///
    /// `None` quiere decir «todos». El numero de `Cabeceras` no es redondo por
    /// gusto: ocho kilobytes cubren la cabecera de HTTP, el saludo de TLS con su
    /// certificado, y la negociacion de SMB2 con holgura.
    #[must_use]
    pub fn tope_por_sentido(self) -> Option<usize> {
        match self {
            Politica::Nada => Some(0),
            Politica::SoloMetadatos => Some(0),
            Politica::Cabeceras => Some(8 * 1024),
            Politica::Completo => None,
        }
    }

    /// Si esta politica guarda algun byte del contenido.
    #[must_use]
    pub fn guarda_contenido(self) -> bool {
        matches!(self, Politica::Cabeceras | Politica::Completo)
    }

    /// Todas, de menos a mas.
    #[must_use]
    pub fn todas() -> &'static [Politica] {
        &[
            Politica::Nada,
            Politica::SoloMetadatos,
            Politica::Cabeceras,
            Politica::Completo,
        ]
    }
}

/// Cuanto tiempo vive lo guardado, en dias.
///
/// Va **pegada a cada trozo** en el momento de escribirlo, y no en una tabla de
/// configuracion aparte: una politica que se pueda cambiar despues borraria
/// retroactivamente pruebas de un incidente abierto, o las conservaria mas de lo
/// que el cliente acepto. Lo que se escribio con catorce dias caduca a los
/// catorce, cambie luego la configuracion lo que cambie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Caducidad(u16);

impl Caducidad {
    /// Los dias.
    #[must_use]
    pub fn dias(self) -> u16 {
        self.0
    }

    /// Una caducidad de tantos dias, acotada a dos anos.
    ///
    /// El tope no es una preferencia: una retencion sin limite superior es un
    /// almacen que crece para siempre, y el dia que se llene se llenara entero.
    #[must_use]
    pub fn de_dias(d: u16) -> Caducidad {
        Caducidad(d.min(730))
    }

    /// La que corresponde a una politica.
    ///
    /// Lo que se guarda entero se guarda **mas tiempo** a proposito: es lo que un
    /// analista va a querer dentro de un mes, y es tambien lo poco que hay.
    #[must_use]
    pub fn de_politica(p: Politica) -> Caducidad {
        match p {
            Politica::Nada => Caducidad(0),
            Politica::SoloMetadatos => Caducidad(90),
            Politica::Cabeceras => Caducidad(30),
            Politica::Completo => Caducidad(180),
        }
    }
}

/// La prueba de que un veredicto justifica guardar el contenido entero.
///
/// # Lo que no tiene, y es lo importante
///
/// No tiene `nueva()`, no tiene `Default`, no tiene `From`. El unico camino es
/// [`Autorizacion::del_veredicto`], que devuelve `None` cuando el veredicto no la
/// justifica. Un capturador que pudiera fabricar su propia autorizacion tendria
/// la politica en una bandera otra vez, solo que mejor escondida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Autorizacion {
    /// La frase del veredicto que la justifica, para el informe de por que se
    /// guardo un flujo entero. Sin esto, dentro de seis meses nadie sabe por que
    /// hay un gigabyte de una maquina en el almacen.
    porque: String,
    resultado: Resultado,
    severidad: Severidad,
}

impl Autorizacion {
    /// La autorizacion que da un veredicto, si la da.
    ///
    /// # Que justifica guardar entero
    ///
    /// Lo que el arbitro marco como malicioso, y lo que dejo **en disputa**. Lo
    /// segundo no es generosidad: en disputa quiere decir que los motores no se
    /// pusieron de acuerdo y que lo va a mirar una persona, y esa persona va a
    /// necesitar los bytes. Es justo el caso en el que tirar el contenido sale
    /// mas caro.
    #[must_use]
    pub fn del_veredicto(v: &Veredicto) -> Option<Autorizacion> {
        match v.resultado {
            Resultado::Malicioso | Resultado::EnDisputa => Some(Autorizacion {
                porque: v.porque.clone(),
                resultado: v.resultado,
                severidad: v.severidad,
            }),
            _ => None,
        }
    }

    /// Por que se guardo.
    #[must_use]
    pub fn porque(&self) -> &str {
        &self.porque
    }

    /// A que resultado respondio.
    #[must_use]
    pub fn resultado(&self) -> Resultado {
        self.resultado
    }

    /// Con que severidad.
    #[must_use]
    pub fn severidad(&self) -> Severidad {
        self.severidad
    }
}

/// La decision de retencion para un flujo, con su porque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Que se guarda.
    pub politica: Politica,
    /// Cuanto vive.
    pub caducidad: Caducidad,
    /// Por que se decidio eso, en una frase que se pueda leer dentro de un ano.
    pub porque: String,
}

impl Decision {
    /// La decision por defecto: el sobre y nada mas.
    #[must_use]
    pub fn por_defecto() -> Decision {
        Decision {
            politica: Politica::SoloMetadatos,
            caducidad: Caducidad::de_politica(Politica::SoloMetadatos),
            porque: "sin veredicto que justifique guardar contenido: solo el sobre".to_owned(),
        }
    }

    /// La decision que corresponde a una autorizacion.
    #[must_use]
    pub fn autorizada(a: &Autorizacion) -> Decision {
        Decision {
            politica: Politica::Completo,
            caducidad: Caducidad::de_politica(Politica::Completo),
            porque: format!(
                "el arbitro lo dejo en {} con severidad {}: {}",
                a.resultado().nombre(),
                a.severidad().nombre(),
                a.porque()
            ),
        }
    }

    /// La decision de guardar solo las cabeceras, para el trafico que se vigila
    /// sin acusarlo.
    #[must_use]
    pub fn cabeceras(porque: &str) -> Decision {
        Decision {
            politica: Politica::Cabeceras,
            caducidad: Caducidad::de_politica(Politica::Cabeceras),
            porque: porque.to_owned(),
        }
    }

    /// La decision de no guardar nada, que la toma el cliente.
    #[must_use]
    pub fn nada(porque: &str) -> Decision {
        Decision {
            politica: Politica::Nada,
            caducidad: Caducidad(0),
            porque: porque.to_owned(),
        }
    }

    /// Cuando dos motivos piden politicas distintas, gana la mayor.
    ///
    /// Con una excepcion que **no** es simetrica: [`Politica::Nada`] la puso el
    /// cliente, y no la levanta un veredicto. Un producto que guardara el
    /// trafico que su cliente le dijo que no guardara estaria incumpliendo lo
    /// unico que no puede incumplir.
    #[must_use]
    pub fn combinar(a: Decision, b: Decision) -> Decision {
        if a.politica == Politica::Nada || b.politica == Politica::Nada {
            let cliente = if a.politica == Politica::Nada { a } else { b };
            return Decision {
                porque: format!(
                    "{} (lo pidio el cliente, y eso no lo levanta un veredicto)",
                    cliente.porque
                ),
                ..cliente
            };
        }
        if a.politica >= b.politica {
            a
        } else {
            b
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::arbitro::Senal;
    use aegis_entidad::entidad;
    use aegis_entidad::escala::Confianza;
    use aegis_entidad::escala::Plano;

    fn veredicto(r: Resultado) -> Veredicto {
        Veredicto {
            entidad: entidad::maquina("m1"),
            resultado: r,
            severidad: Severidad::Alta,
            confianza: Confianza::nueva(90),
            porque: "dos planos independientes lo sostienen".to_owned(),
            planos: vec![Plano::Estatico],
            senales: Vec::<Senal>::new(),
        }
    }

    /// LA propiedad del modulo: sin veredicto no hay cuerpo, y no por disciplina
    /// sino porque el tipo que autoriza no se puede construir de otra forma.
    #[test]
    fn sin_un_veredicto_que_lo_justifique_no_hay_autorizacion() {
        assert!(Autorizacion::del_veredicto(&veredicto(Resultado::Limpio)).is_none());
        assert!(Autorizacion::del_veredicto(&veredicto(Resultado::SinDatos)).is_none());
        assert!(Autorizacion::del_veredicto(&veredicto(Resultado::Malicioso)).is_some());
    }

    /// En disputa quiere decir que lo va a mirar una persona, y esa persona va a
    /// necesitar los bytes. Es justo el caso en el que tirarlos sale mas caro.
    #[test]
    fn lo_que_queda_en_disputa_se_guarda_entero() {
        let a = Autorizacion::del_veredicto(&veredicto(Resultado::EnDisputa))
            .expect("en disputa lo justifica");
        let d = Decision::autorizada(&a);
        assert_eq!(d.politica, Politica::Completo);
        assert!(
            d.porque.contains("en disputa") || d.porque.contains("disputa"),
            "{}",
            d.porque
        );
    }

    #[test]
    fn la_autorizacion_arrastra_el_porque_del_veredicto() {
        // Sin esto, dentro de seis meses nadie sabe por que hay un gigabyte de
        // una maquina en el almacen.
        let v = veredicto(Resultado::Malicioso);
        let a = Autorizacion::del_veredicto(&v).expect("malicioso lo justifica");
        assert_eq!(a.porque(), v.porque);
        let d = Decision::autorizada(&a);
        assert!(d.porque.contains("dos planos"), "{}", d.porque);
    }

    #[test]
    fn por_defecto_solo_se_guarda_el_sobre() {
        // El noventa y nueve por ciento del trafico no se va a mirar nunca, y
        // guardarlo entero es pagar por no decidir.
        let d = Decision::por_defecto();
        assert_eq!(d.politica, Politica::SoloMetadatos);
        assert!(!d.politica.guarda_contenido());
        assert_eq!(d.politica.tope_por_sentido(), Some(0));
    }

    #[test]
    fn de_dos_politicas_gana_la_mayor() {
        let menor = Decision::por_defecto();
        let mayor = Decision::cabeceras("se vigila el flujo");
        assert_eq!(
            Decision::combinar(menor.clone(), mayor.clone()).politica,
            Politica::Cabeceras
        );
        assert_eq!(
            Decision::combinar(mayor, menor).politica,
            Politica::Cabeceras
        );
    }

    /// La excepcion que NO es simetrica: lo que el cliente dijo que no se guarda,
    /// no lo levanta un veredicto.
    #[test]
    fn lo_que_el_cliente_prohibio_no_lo_levanta_un_veredicto() {
        let prohibido = Decision::nada("el cliente no retiene esta red");
        let a = Autorizacion::del_veredicto(&veredicto(Resultado::Malicioso)).unwrap();
        let autorizado = Decision::autorizada(&a);
        for (x, y) in [
            (prohibido.clone(), autorizado.clone()),
            (autorizado, prohibido.clone()),
        ] {
            let d = Decision::combinar(x, y);
            assert_eq!(d.politica, Politica::Nada);
            assert!(d.porque.contains("lo pidio el cliente"), "{}", d.porque);
        }
    }

    #[test]
    fn la_caducidad_esta_acotada_por_arriba() {
        // Una retencion sin limite superior es un almacen que crece para siempre,
        // y el dia que se llene se llenara entero.
        assert_eq!(Caducidad::de_dias(10_000).dias(), 730);
        assert_eq!(Caducidad::de_dias(7).dias(), 7);
        assert_eq!(Caducidad::de_politica(Politica::Nada).dias(), 0);
    }

    #[test]
    fn lo_que_se_guarda_entero_vive_mas_que_lo_demas() {
        // Es lo que un analista va a querer dentro de un mes, y es tambien lo
        // poco que hay.
        assert!(
            Caducidad::de_politica(Politica::Completo)
                > Caducidad::de_politica(Politica::Cabeceras)
        );
    }

    #[test]
    fn cada_politica_tiene_nombre_propio_y_tope_propio() {
        let mut vistos = Vec::new();
        for p in Politica::todas() {
            assert!(!vistos.contains(&p.nombre()), "repetido: {}", p.nombre());
            vistos.push(p.nombre());
        }
        assert_eq!(Politica::Completo.tope_por_sentido(), None);
        assert_eq!(Politica::SoloMetadatos.tope_por_sentido(), Some(0));
    }
}
