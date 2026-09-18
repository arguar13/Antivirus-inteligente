//! Reproducir un flujo guardado y volver a arbitrarlo.
//!
//! # La prueba de determinismo mas fuerte que existe
//!
//! Un motor de deteccion que dé un veredicto distinto al volver a ver los mismos
//! bytes no es un motor: es un generador de opiniones. Y no se puede comprobar
//! con pruebas unitarias, porque cada una fija su propia entrada — lo que hay que
//! comprobar es que la ENTRADA REAL, la que llego por el cable un martes,
//! reproduce el mismo resultado un jueves.
//!
//! Eso es lo que este modulo hace posible, y es el motivo de fondo por el que
//! merece la pena guardar el trafico: no para mirarlo, sino para poder
//! **contradecir al sistema con sus propios datos**.
//!
//! # La honestidad que esto obliga a tener
//!
//! Un flujo del que se tapo una credencial **no tiene por que** reproducir el
//! mismo veredicto: si la senal estaba en la galleta que se tapo, al reproducirlo
//! ya no esta. Eso no se esconde detras de una media — se declara en
//! [`Fidelidad`], y solo se exige igualdad exacta donde la fidelidad es exacta.
//!
//! Prometer determinismo sobre datos que uno mismo ha modificado seria la clase
//! de promesa que se cumple en la demostracion y falla en el incidente.

use aegis_disectores::disector::{Contexto, Registro};
use aegis_disectores::Cobertura;
use aegis_entidad::arbitro::{arbitrar, Juicio, Senal, Veredicto};
use aegis_entidad::entidad::Eid;
use aegis_entidad::escala::{Confianza, Motor, Severidad};
use aegis_wire::hecho::Hecho;

use crate::anillo::Paquete;

/// Con cuanta fidelidad se puede reproducir un flujo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fidelidad {
    /// Los bytes guardados son los del cable, sin tocar.
    ///
    /// **Es lo unico que autoriza a exigir el mismo veredicto.**
    Exacta,
    /// Se taparon bytes al guardar.
    ///
    /// El veredicto reproducido puede diferir del original, y decir cuanto se
    /// tapo es lo que permite juzgar si la diferencia se explica.
    ConTapados {
        /// Cuantos bytes se taparon.
        bytes: u64,
    },
    /// Se guardo menos de lo que hubo: la politica era de cabeceras, o el
    /// paquete venia recortado.
    Parcial {
        /// Cuantos bytes se guardaron.
        guardados: u64,
        /// Cuantos hubo en el cable.
        originales: u64,
    },
}

impl Fidelidad {
    /// Si de esta reproduccion se puede exigir el mismo veredicto.
    #[must_use]
    pub fn autoriza_exigir_igualdad(self) -> bool {
        self == Fidelidad::Exacta
    }

    /// Como se lee en un informe.
    #[must_use]
    pub fn frase(self) -> String {
        match self {
            Fidelidad::Exacta => {
                "los bytes guardados son los del cable, asi que este veredicto tiene que ser \
                 el mismo que el original"
                    .to_owned()
            }
            Fidelidad::ConTapados { bytes } => format!(
                "se taparon {bytes} bytes al guardar (credenciales o un ambito declarado), \
                 asi que este veredicto PUEDE diferir del original y la diferencia se explica \
                 por lo tapado"
            ),
            Fidelidad::Parcial {
                guardados,
                originales,
            } => format!(
                "se guardaron {guardados} de {originales} bytes, asi que este veredicto se \
                 calculo sobre menos de lo que hubo"
            ),
        }
    }
}

/// Un flujo guardado, listo para volver a pasar por los disectores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlujoGuardado {
    /// De quien es.
    pub entidad: Eid,
    /// Los paquetes, en el orden en que llegaron.
    pub paquetes: Vec<Paquete>,
    /// El contexto con el que se disecaron la primera vez.
    ///
    /// Va guardado y no se vuelve a deducir: deducirlo otra vez podria dar otro
    /// resultado, y entonces la reproduccion no estaria reproduciendo nada.
    pub contexto: Contexto,
    /// Cuantos bytes se taparon en total al guardar.
    pub bytes_tapados: u64,
    /// Cuantos bytes hubo en el cable, contando lo que no se guardo.
    pub bytes_originales: u64,
}

impl FlujoGuardado {
    /// Con cuanta fidelidad se puede reproducir.
    #[must_use]
    pub fn fidelidad(&self) -> Fidelidad {
        if self.bytes_tapados > 0 {
            return Fidelidad::ConTapados {
                bytes: self.bytes_tapados,
            };
        }
        let guardados: u64 = self.paquetes.iter().map(|p| p.datos.len() as u64).sum();
        if guardados < self.bytes_originales {
            return Fidelidad::Parcial {
                guardados,
                originales: self.bytes_originales,
            };
        }
        Fidelidad::Exacta
    }
}

/// El resultado de reproducir un flujo.
#[derive(Debug, Clone, PartialEq)]
pub struct Reproduccion {
    /// Los hechos que salieron.
    pub hechos: Vec<Hecho>,
    /// Con que cobertura.
    pub cobertura: Cobertura,
    /// El veredicto al que se llega.
    pub veredicto: Veredicto,
    /// Con cuanta fidelidad.
    pub fidelidad: Fidelidad,
}

impl Reproduccion {
    /// Como se cuenta en un informe.
    #[must_use]
    pub fn frase(&self) -> String {
        format!(
            "{} · {} · {}",
            self.veredicto.resumen(),
            self.cobertura.frase(),
            self.fidelidad.frase()
        )
    }
}

/// Convierte los hechos de un flujo en las senales que ve el arbitro.
///
/// # Por que esta funcion existe y no se hace en linea
///
/// Porque tiene que ser **la misma** en la observacion en vivo y en la
/// reproduccion. Dos funciones que traduzcan hechos a senales acabarian
/// traduciendo distinto, y entonces la reproduccion daria otro veredicto sin que
/// nada estuviera roto — que es el peor fallo posible en una herramienta cuyo
/// argumento es el determinismo.
#[must_use]
pub fn senales_de(
    entidad: &Eid,
    hechos: &[Hecho],
    cobertura: &Cobertura,
    cuando_ns: u64,
) -> Vec<Senal> {
    let mut salida = Vec::new();

    for h in hechos {
        let (juicio, severidad, confianza, porque) = match h {
            // Una orden que ESCRIBE en un dispositivo industrial es la unica que
            // mueve algo en el mundo fisico. Leer un registro es telemetria.
            Hecho::OrdenIndustrial {
                protocolo,
                funcion,
                escribe: true,
                unidad,
                detalle,
            } => (
                Juicio::Sospechoso,
                Severidad::Alta,
                Confianza::nueva(60),
                format!(
                    "una orden de {} que cambia el estado del dispositivo: {funcion} sobre {unidad} ({detalle})",
                    protocolo.nombre()
                ),
            ),
            Hecho::EjecucionRemota { via, orden, objetivo } => (
                Juicio::Sospechoso,
                Severidad::Media,
                Confianza::nueva(50),
                format!("ejecucion remota por {}: {orden} sobre {objetivo}", via.nombre()),
            ),
            Hecho::AccesoAMetadatosDeNube {
                proveedor,
                recurso,
                con_credencial: true,
            } => (
                Juicio::Sospechoso,
                Severidad::Alta,
                Confianza::nueva(55),
                format!("se pidio una credencial de instancia a {proveedor}: {recurso}"),
            ),
            Hecho::IndicioDeTunel {
                portador,
                tecnica,
                detalle,
            } => (
                Juicio::Sospechoso,
                Severidad::Media,
                Confianza::nueva(40),
                format!("indicio de tunel sobre {}: {tecnica} ({detalle})", portador.nombre()),
            ),
            Hecho::NoAnalizable { protocolo, motivo } => (
                // El tri-estado: no haber podido mirar NO es haber mirado.
                Juicio::NoConcluyente,
                Severidad::Info,
                Confianza::NULA,
                format!("no se pudo analizar {}: {motivo}", protocolo.nombre()),
            ),
            _ => continue,
        };
        salida.push(Senal::nueva(
            Motor::Wire,
            entidad.clone(),
            juicio,
            severidad,
            confianza,
            porque,
            cuando_ns,
        ));
    }

    // Y la cobertura entra como senal SIEMPRE, tambien cuando es completa: es la
    // que dice si el silencio de las demas significa algo. Sin ella, un flujo del
    // que no se entendio nada y uno que estaba limpio llegarian iguales al
    // arbitro.
    if !cobertura.completa() {
        salida.push(Senal::nueva(
            Motor::Wire,
            entidad.clone(),
            Juicio::NoConcluyente,
            Severidad::Info,
            Confianza::NULA,
            cobertura.frase(),
            cuando_ns,
        ));
    }

    salida
}

/// Reproduce un flujo guardado: lo vuelve a disecar y lo vuelve a arbitrar.
///
/// `ahora_ns` se pasa y no se lee del reloj, por la misma razon que en el
/// arbitro: una funcion que mire la hora no se puede reproducir.
#[must_use]
pub fn reproducir(flujo: &FlujoGuardado, registro: &mut Registro, ahora_ns: u64) -> Reproduccion {
    let mut hechos = Vec::new();
    let mut cobertura = Cobertura::nueva();
    for p in &flujo.paquetes {
        let s = registro.disecar(&p.datos, &flujo.contexto);
        hechos.extend(s.hechos);
        cobertura.sumar(&s.cobertura);
    }
    let senales = senales_de(&flujo.entidad, &hechos, &cobertura, ahora_ns);
    let veredicto = arbitrar(&flujo.entidad, &senales, ahora_ns);
    Reproduccion {
        hechos,
        cobertura,
        veredicto,
        fidelidad: flujo.fidelidad(),
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_disectores::catalogo::registro_completo;
    use aegis_entidad::entidad;

    fn flujo(datos: Vec<Vec<u8>>, ctx: Contexto) -> FlujoGuardado {
        let originales = datos.iter().map(|d| d.len() as u64).sum();
        FlujoGuardado {
            entidad: entidad::maquina("pasarela-1"),
            paquetes: datos
                .into_iter()
                .enumerate()
                .map(|(i, datos)| Paquete {
                    cuando_ns: i as u64 * 1_000_000,
                    datos,
                })
                .collect(),
            contexto: ctx,
            bytes_tapados: 0,
            bytes_originales: originales,
        }
    }

    /// LA prueba que justifica guardar el trafico: los mismos bytes dan el mismo
    /// veredicto, la vez que sea. Un motor que no cumpla esto no es un motor, es
    /// un generador de opiniones.
    #[test]
    fn los_mismos_bytes_dan_el_mismo_veredicto_siempre() {
        let f = flujo(
            vec![
                // Una orden de escritura a un PLC: es lo que mueve algo en el
                // mundo fisico, y tiene que salir igual las diez veces.
                vec![
                    0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x11, 0x05, 0x00, 0xAC, 0xFF, 0x00,
                ],
                vec![
                    0x00, 0x03, 0x00, 0x00, 0x00, 0x06, 0x11, 0x06, 0x00, 0x01, 0x00, 0x2A,
                ],
            ],
            Contexto::tcp_cliente(502),
        );
        assert_eq!(f.fidelidad(), Fidelidad::Exacta);

        let primera = reproducir(&f, &mut registro_completo(), 1_000);
        for vuelta in 0..10 {
            let otra = reproducir(&f, &mut registro_completo(), 1_000);
            assert_eq!(
                otra.veredicto, primera.veredicto,
                "la vuelta {vuelta} dio otro veredicto"
            );
            assert_eq!(otra.hechos, primera.hechos);
            assert_eq!(otra.cobertura, primera.cobertura);
        }
        assert!(primera.fidelidad.autoriza_exigir_igualdad());
        assert!(!primera.veredicto.porque.is_empty());
    }

    #[test]
    fn el_orden_de_los_paquetes_cambia_el_resultado_y_conservarlo_es_el_trabajo() {
        // Es por lo que el flujo guarda el orden de llegada y no un conjunto: un
        // almacen que reordenara los paquetes reproduciria otra conversacion.
        let a = flujo(
            vec![
                b"*2\r\n$3\r\nGET\r\n$5\r\nclave\r\n".to_vec(),
                b"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$1\r\n/\r\n".to_vec(),
            ],
            Contexto::tcp_cliente(6379),
        );
        let r = reproducir(&a, &mut registro_completo(), 1_000);
        assert_eq!(r.hechos.len(), 5, "{:?}", r.hechos);
        assert_eq!(a.paquetes[0].cuando_ns, 0);
        assert!(a.paquetes[1].cuando_ns > a.paquetes[0].cuando_ns);
    }

    /// La honestidad que la redaccion obliga a tener: prometer determinismo sobre
    /// datos que uno mismo ha modificado seria una promesa que se cumple en la
    /// demostracion y falla en el incidente.
    #[test]
    fn un_flujo_con_bytes_tapados_no_promete_el_mismo_veredicto() {
        let mut f = flujo(
            vec![b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic ****\r\n\r\n".to_vec()],
            Contexto::tcp_cliente(80),
        );
        f.bytes_tapados = 4;
        assert!(matches!(f.fidelidad(), Fidelidad::ConTapados { bytes: 4 }));
        assert!(!f.fidelidad().autoriza_exigir_igualdad());
        let r = reproducir(&f, &mut registro_completo(), 1_000);
        assert!(r.frase().contains("PUEDE diferir"), "{}", r.frase());
    }

    #[test]
    fn un_flujo_guardado_a_medias_dice_que_lo_esta() {
        let mut f = flujo(vec![vec![b'x'; 100]], Contexto::tcp_cliente(80));
        f.bytes_originales = 5000;
        match f.fidelidad() {
            Fidelidad::Parcial {
                guardados,
                originales,
            } => {
                assert_eq!(guardados, 100);
                assert_eq!(originales, 5000);
            }
            otra => panic!("{otra:?}"),
        }
        assert!(!f.fidelidad().autoriza_exigir_igualdad());
    }

    /// El tri-estado, otra vez y en este camino tambien: no haber podido mirar
    /// NO es haber mirado. Un flujo cuya cobertura no es completa llega al
    /// arbitro diciendolo.
    #[test]
    fn un_flujo_que_no_se_entendio_llega_al_arbitro_diciendolo() {
        let f = flujo(
            vec![b"esto no es ningun protocolo conocido".to_vec()],
            Contexto::tcp_cliente(31337),
        );
        let r = reproducir(&f, &mut registro_completo(), 1_000);
        assert!(!r.cobertura.completa());
        assert!(
            r.veredicto
                .senales
                .iter()
                .any(|s| s.juicio == Juicio::NoConcluyente),
            "{:?}",
            r.veredicto.senales
        );
    }

    #[test]
    fn una_orden_industrial_que_escribe_sale_como_sospechosa_y_una_lectura_no() {
        let escribe = flujo(
            vec![vec![
                0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x11, 0x05, 0x00, 0xAC, 0xFF, 0x00,
            ]],
            Contexto::tcp_cliente(502),
        );
        let lee = flujo(
            vec![vec![
                0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x6B, 0x00, 0x03,
            ]],
            Contexto::tcp_cliente(502),
        );
        let r1 = reproducir(&escribe, &mut registro_completo(), 1);
        let r2 = reproducir(&lee, &mut registro_completo(), 1);
        assert!(
            r1.veredicto
                .senales
                .iter()
                .any(|s| s.juicio == Juicio::Sospechoso),
            "escribir en un PLC tiene que aportar algo: {:?}",
            r1.veredicto.senales
        );
        assert!(
            !r2.veredicto
                .senales
                .iter()
                .any(|s| s.juicio == Juicio::Sospechoso),
            "leer un registro es telemetria y pasa miles de veces por minuto: {:?}",
            r2.veredicto.senales
        );
    }

    #[test]
    fn la_confianza_de_una_senal_de_red_no_pasa_de_su_tope() {
        // El motor de red tiene su tope como todos: un motor no puede declararse
        // mas seguro de lo que su plano le permite estar.
        let f = flujo(
            vec![vec![
                0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x11, 0x05, 0x00, 0xAC, 0xFF, 0x00,
            ]],
            Contexto::tcp_cliente(502),
        );
        let r = reproducir(&f, &mut registro_completo(), 1);
        for s in &r.veredicto.senales {
            assert!(s.confianza <= Motor::Wire.tope_confianza(), "{s:?}");
        }
    }

    #[test]
    fn cada_fidelidad_dice_algo_distinto() {
        let tres = [
            Fidelidad::Exacta,
            Fidelidad::ConTapados { bytes: 10 },
            Fidelidad::Parcial {
                guardados: 1,
                originales: 2,
            },
        ];
        let mut vistas = Vec::new();
        for f in tres {
            let frase = f.frase();
            assert!(frase.len() > 40, "{f:?}");
            assert!(!vistas.contains(&frase), "{f:?} repite");
            vistas.push(frase);
        }
        assert!(Fidelidad::Exacta.autoriza_exigir_igualdad());
    }
}
