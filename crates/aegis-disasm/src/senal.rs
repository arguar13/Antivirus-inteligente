//! El puente al arbitro: como sale de aqui lo que se encontro.
//!
//! # Por que este modulo no decide nada
//!
//! Porque no puede. «Cifra con AES» es cierto de un gestor de copias de
//! seguridad y de un secuestrador de ficheros; «se resuelve las funciones sin
//! tabla de importaciones» es cierto de un empaquetador comercial y de un
//! implante. El desensamblador ve el codigo del fichero y nada mas: no sabe de
//! donde salio, quien lo firma, que hizo al ejecutarse ni si la maquina lleva
//! tres dias rara.
//!
//! Quien junta eso es el arbitro. Lo que sale de aqui es **una senal**, con su
//! confianza acotada al tope del motor estatico, su severidad y su frase de por
//! que. Ver [`crate::capacidad`].
//!
//! # Las dos cosas que este modulo no hace, y por que
//!
//! **No emite `Limpio` cuando el analisis se corto.** Con la cobertura
//! incompleta, no haber encontrado nada significa «no dio tiempo a mirar», y esa
//! es exactamente la confusion que este producto persigue desde la primera fase.
//! Sale [`Juicio::NoConcluyente`], que es la unica respuesta cierta.
//!
//! **No sube la confianza por acumulacion de capacidades.** Diez capacidades no
//! hacen un veredicto diez veces mas seguro: el analisis estatico tiene el mismo
//! limite con una que con diez —que no ha visto ejecutarse nada—, y ese limite
//! es lo que fija el tope del motor. Lo que sube con las capacidades es la
//! **severidad**, que es otra cosa: cuanto daño haria si fuera verdad.

use aegis_entidad::{Confianza, Eid, Juicio, Motor, Senal, Severidad};

use crate::capacidad::{Familia, Informe};

/// El tope de confianza del motor estatico, repetido aqui para poder probarlo.
///
/// La fuente de verdad es [`Motor::Estatico`]; esta constante existe para que la
/// prueba de este modulo falle si alguien cambia una de las dos sin la otra.
pub const TOPE: u8 = 80;

/// Convierte lo encontrado en una senal para el arbitro.
///
/// `cuando_ns` lo pone quien llama, porque este crate no lee el reloj: leerlo
/// haria que el mismo binario analizado dos veces produjera dos resultados
/// distintos, y eso rompe la reproducibilidad que el resto del producto exige
/// para poder comparar dos analisis.
pub fn senal_de(informe: &Informe, entidad: Eid, cuando_ns: u64) -> Senal {
    let severidad = severidad_de(informe);
    let (juicio, confianza) = juicio_de(informe);
    Senal::nueva(
        Motor::Estatico,
        entidad,
        juicio,
        severidad,
        confianza,
        informe.frase(),
        cuando_ns,
    )
}

/// Cuanto daño haria esto si fuera verdad.
///
/// La familia manda sobre el numero: un binario con una sola capacidad de
/// destruccion es peor que uno con cinco de reconocimiento, y una escala que
/// contara capacidades diria lo contrario.
fn severidad_de(informe: &Informe) -> Severidad {
    let mut peor = Severidad::Info;
    for c in informe.capacidades() {
        let s = match c.familia {
            // Irreversible: lo que destruye o cifra no se deshace esperando.
            Familia::Destruccion => Severidad::Critica,
            // Comprometen la maquina o la cuenta.
            Familia::Inyeccion | Familia::Credenciales => Severidad::Alta,
            // El cifrado es alto y no critico porque por si solo no destruye: lo
            // critico es cifrar Y borrar las copias, y eso ya lo recoge la
            // familia de destruccion.
            Familia::Cifrado | Familia::Persistencia => Severidad::Alta,
            Familia::Evasion | Familia::Comunicaciones => Severidad::Media,
            Familia::Reconocimiento => Severidad::Baja,
        };
        if s > peor {
            peor = s;
        }
    }
    peor
}

/// Que se puede decir, y con cuanta seguridad.
///
/// # La tabla, y su asimetria deliberada
///
/// Encontrar algo y no encontrar nada no son simetricos, y tratarlos como si lo
/// fueran es el error que produce los informes que dicen «limpio» de ficheros
/// que no se llegaron a mirar.
///
/// - Se encontro algo → el hecho esta ahi, y lo esta se completara el analisis o
///   no: una capacidad con su evidencia no deja de ser cierta porque despues se
///   acabara el tiempo.
/// - No se encontro nada **y el analisis termino** → se puede decir que se miro
///   y no habia, con la confianza que permite haber mirado solo el codigo.
/// - No se encontro nada **y el analisis se corto** → no se puede decir nada.
fn juicio_de(informe: &Informe) -> (Juicio, Confianza) {
    let n = informe.capacidades().len();
    if n == 0 {
        return if informe.la_ausencia_significa_algo() {
            // Se miro el codigo entero y no habia nada. Es un hecho, pero de
            // alcance corto: solo dice que el CODIGO no lo tiene, y un fichero
            // empaquetado no ensena su codigo hasta que se ejecuta.
            (Juicio::Limpio, Confianza::BAJA)
        } else {
            (Juicio::NoConcluyente, Confianza::NULA)
        };
    }
    // Hay capacidades. La confianza no crece con su numero —ver la cabecera del
    // modulo—, crece con si lo visto admite otra lectura.
    let concluyente = informe.capacidades().iter().any(|c| {
        matches!(
            c.familia,
            Familia::Inyeccion | Familia::Destruccion | Familia::Credenciales
        )
    });
    if concluyente {
        (Juicio::Sospechoso, Confianza::nueva(TOPE))
    } else {
        (Juicio::Sospechoso, Confianza::MEDIA)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::capacidad::{Capacidad, Evidencia};
    use crate::plazo::Cobertura;

    fn capacidad(f: Familia) -> Capacidad {
        Capacidad::nueva(
            "lo que sea",
            f,
            None,
            vec![Evidencia {
                donde: 0x1000,
                que: "una instruccion".to_owned(),
                porque: "por algo".to_owned(),
            }],
        )
        .unwrap()
    }

    /// La entidad de las pruebas: el CONTENIDO de un fichero, que es sobre lo
    /// que puede hablar un desensamblador. No la ubicacion —el mismo fichero en
    /// dos sitios es el mismo contenido— ni el proceso, que aqui no existe
    /// porque nada se ejecuta.
    fn entidad_de_prueba() -> Eid {
        aegis_entidad::entidad::contenido(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
    }

    fn entera() -> Cobertura {
        Cobertura {
            bytes_cubiertos: 10,
            bytes_totales: 10,
            ..Default::default()
        }
    }

    fn cortada() -> Cobertura {
        Cobertura {
            cortado_por_plazo: true,
            ..Default::default()
        }
    }

    #[test]
    fn el_tope_de_este_modulo_es_el_del_motor_estatico() {
        // Si alguien cambia uno de los dos sin el otro, esta senal saldria
        // acotada en silencio por `Senal::nueva` y nadie se enteraria de que el
        // motor se creia mas seguro de lo que puede estar.
        assert_eq!(TOPE, Motor::Estatico.tope_confianza().centesimas());
    }

    #[test]
    fn un_analisis_cortado_sin_hallazgos_no_dice_que_esta_limpio() {
        // La averia que este producto persigue desde la primera fase: «no se
        // comprobo» y «se comprobo y esta bien» producen el mismo hueco en un
        // panel mal hecho, y solo una es aceptable.
        let s = senal_de(&Informe::nuevo(vec![], cortada()), entidad_de_prueba(), 0);
        assert_eq!(s.juicio, Juicio::NoConcluyente);
        assert!(!s.aporta(), "una senal que no sabe nada no debe pesar");
        assert!(s.porque.contains("NO LLEGO HASTA EL FINAL"), "{}", s.porque);
    }

    #[test]
    fn un_analisis_entero_sin_hallazgos_si_dice_que_esta_limpio_pero_con_poca_confianza() {
        // Se miro el codigo entero y no habia nada. Es un hecho, pero solo dice
        // que el CODIGO no lo tiene: un fichero empaquetado no ensena el suyo.
        let s = senal_de(&Informe::nuevo(vec![], entera()), entidad_de_prueba(), 0);
        assert_eq!(s.juicio, Juicio::Limpio);
        assert_eq!(s.confianza, Confianza::BAJA);
    }

    #[test]
    fn diez_capacidades_no_dan_mas_confianza_que_una() {
        // El analisis estatico tiene el mismo limite con una que con diez: no ha
        // visto ejecutarse nada. Lo que sube es la severidad, no la confianza.
        let una = Informe::nuevo(vec![capacidad(Familia::Inyeccion)], entera());
        let muchas = Informe::nuevo(
            vec![
                capacidad(Familia::Inyeccion),
                capacidad(Familia::Evasion),
                capacidad(Familia::Comunicaciones),
                capacidad(Familia::Persistencia),
            ],
            entera(),
        );
        let a = senal_de(&una, entidad_de_prueba(), 0);
        let b = senal_de(&muchas, entidad_de_prueba(), 0);
        assert_eq!(a.confianza, b.confianza);
    }

    #[test]
    fn la_confianza_nunca_pasa_del_tope_del_motor_estatico() {
        // La invariante que sostiene el arbitro entero.
        for f in Familia::todas() {
            let s = senal_de(
                &Informe::nuevo(vec![capacidad(f)], entera()),
                entidad_de_prueba(),
                0,
            );
            assert!(
                s.confianza.centesimas() <= TOPE,
                "{f:?} salio con {}",
                s.confianza.centesimas()
            );
        }
    }

    #[test]
    fn la_severidad_la_manda_la_familia_y_no_el_numero() {
        // Un binario con una capacidad de destruccion es peor que uno con cinco
        // de reconocimiento, y una escala que contara capacidades diria lo
        // contrario.
        let destructor = Informe::nuevo(vec![capacidad(Familia::Destruccion)], entera());
        let curioso = Informe::nuevo(
            vec![
                capacidad(Familia::Reconocimiento),
                capacidad(Familia::Reconocimiento),
                capacidad(Familia::Reconocimiento),
                capacidad(Familia::Reconocimiento),
                capacidad(Familia::Reconocimiento),
            ],
            entera(),
        );
        assert!(
            senal_de(&destructor, entidad_de_prueba(), 0).severidad
                > senal_de(&curioso, entidad_de_prueba(), 0).severidad
        );
    }

    #[test]
    fn una_capacidad_encontrada_sigue_valiendo_aunque_el_analisis_se_cortara() {
        // Una capacidad con su evidencia no deja de ser cierta porque despues se
        // acabara el tiempo. La asimetria es deliberada: lo que se vio, se vio.
        let s = senal_de(
            &Informe::nuevo(vec![capacidad(Familia::Inyeccion)], cortada()),
            entidad_de_prueba(),
            0,
        );
        assert_eq!(s.juicio, Juicio::Sospechoso);
        assert!(s.aporta());
    }

    #[test]
    fn la_frase_de_la_senal_lleva_la_cobertura() {
        // Quien reciba la senal tiene que poder saber si la lista de capacidades
        // es «esto es lo que hay» o «esto es lo que dio tiempo a mirar».
        let s = senal_de(
            &Informe::nuevo(vec![capacidad(Familia::Evasion)], cortada()),
            entidad_de_prueba(),
            0,
        );
        assert!(s.porque.contains("SE CORTO"), "{}", s.porque);
    }

    #[test]
    fn el_desensamblador_no_emite_nunca_un_juicio_de_malicioso() {
        // Ver el codigo no basta para eso, y un motor que lo dijera obligaria al
        // arbitro a contradecirlo. Lo mas fuerte que puede decir es «sospechoso».
        for f in Familia::todas() {
            for c in [entera(), cortada()] {
                let s = senal_de(
                    &Informe::nuevo(vec![capacidad(f)], c),
                    entidad_de_prueba(),
                    0,
                );
                assert_ne!(s.juicio, Juicio::Malicioso, "{f:?}");
            }
        }
    }
}
