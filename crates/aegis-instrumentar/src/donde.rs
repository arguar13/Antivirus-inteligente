//! Donde merece la pena mirar, decidido por lo que el analisis estatico NO pudo.
//!
//! # La idea, y por que es la unica que escala
//!
//! Instrumentar todo es inservible: una ejecucion con un punto por instruccion
//! tarda mil veces mas y produce una traza que nadie lee. Instrumentar «lo
//! importante» segun una lista fija tampoco, porque lo importante cambia con cada
//! muestra.
//!
//! Lo que si escala es **dejar que el analisis estatico diga donde se rindio**.
//! `aegis-disasm` ya cuenta exactamente eso: las transferencias de control que no
//! pudo resolver, las regiones a las que salta y no estan en el fichero, las
//! fronteras con el nucleo. Cada una de esas es una pregunta concreta que la
//! ejecucion responde sin esfuerzo, y **solo** esas.
//!
//! Es la razon de que la FASE 85 vaya antes que esta: un instrumentador que no
//! sabe donde se quedo ciego el analisis estatico tiene que adivinar.
//!
//! # Lo que NO se instrumenta, y por que
//!
//! Lo que el analisis estatico ya resolvio. Poner un punto en un `call 0x401000`
//! confirma lo que ya se sabia, gasta presupuesto y alarga la ejecucion. La
//! instrumentacion sirve para lo que no se sabe.

use aegis_disasm::instruccion::{Clase, Flujo};
use aegis_disasm::llamadas::Motivo;
use aegis_disasm::Analisis;

use crate::plan::Plan;
use crate::punto::{Punto, Que};

/// Construye un plan a partir de lo que el analisis estatico dejo sin responder.
///
/// El orden en que se anaden importa porque el plan tiene tope: lo primero que
/// entra es lo que mas dice, para que un recorte se lleve lo menos importante.
pub fn plan_desde(a: &Analisis) -> Plan {
    let mut plan = Plan::vacio();

    // 1. Las transferencias que el analisis de constantes no pudo resolver. Son
    //    literalmente las preguntas que el analisis estatico se hizo y no pudo
    //    contestar, y no hay nada mas barato de responder ejecutando.
    for sr in &a.llamadas.sin_resolver {
        let porque = match sr.motivo {
            Motivo::EnMemoria => {
                "el destino se lee de memoria y su contenido no esta en el codigo: \
                 estaticamente no hay forma de saberlo, y en ejecucion es un dato"
            }
            Motivo::RegistroDesconocido { .. } => {
                "el destino sale de un registro cuyo valor llega por mas de un camino \
                 o se calcula con datos que no estan en el codigo"
            }
        };
        if let Some(p) = Punto::nuevo(sr.desde, Que::DestinoDeLaTransferencia, porque) {
            plan.anadir(p);
        }
    }

    // 2. Los saltos a codigo que no esta en el fichero. Es lo que hace un
    //    desempaquetador al terminar, y el sitio exacto donde aparece el codigo
    //    que de verdad hay que analizar.
    for l in &a.llamadas.llamadas {
        if a.cfg.bloque_que_contiene(l.a).is_some() {
            continue;
        }
        if let Some(p) = Punto::nuevo(
            l.desde,
            Que::ContenidoEscrito,
            "el control se va a una direccion que no esta en el codigo del fichero: \
             ahi es donde aparece la carga que un empaquetador despliega, que es el \
             codigo real y el que hay que analizar",
        ) {
            plan.anadir(p);
        }
    }

    // 3. Las fronteras con el nucleo. Es lo que el programa PIDE al sistema, y
    //    lo unico que no se puede falsear desde dentro del programa.
    for i in a.cfg.instrucciones() {
        if i.flujo != Flujo::Frontera && i.clase != Clase::Syscall {
            continue;
        }
        if let Some(p) = Punto::nuevo(
            i.direccion,
            Que::Argumentos,
            "una llamada al sistema es lo que el programa le PIDE a la maquina, y es \
             lo unico que no puede falsear desde dentro de si mismo",
        ) {
            plan.anadir(p);
        }
    }

    // 4. Las entradas de funcion, al final y solo si sobra sitio. Saber por
    //    donde paso el programa es util y es lo menos especifico de todo lo
    //    anterior: si hay que recortar, se recorta esto.
    for f in a.llamadas.funciones() {
        if let Some(p) = Punto::nuevo(
            f.entrada,
            Que::Paso,
            "entrada de funcion: saber cual de las que hay se llego a ejecutar separa \
             el codigo que corre del que solo esta escrito",
        ) {
            plan.anadir(p);
        }
    }

    plan
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_disasm::instruccion::Arquitectura;
    use aegis_disasm::plazo::Plazo;
    use aegis_disasm::{analizar, Entrada};

    fn analisis(bytes: &[u8]) -> Analisis {
        let entradas = [0x1000u64];
        let e = Entrada::minima(bytes, 0x1000, Arquitectura::X86_64, &entradas);
        analizar(&e, &mut Plazo::determinista())
    }

    #[test]
    fn una_llamada_indirecta_sin_resolver_se_instrumenta() {
        // Es literalmente la pregunta que el analisis estatico se hizo y no pudo
        // contestar. `call [rip+0x2f10]` = FF 15 ...
        let a = analisis(&[0xFF, 0x15, 0x10, 0x2F, 0x00, 0x00, 0xC3]);
        let plan = plan_desde(&a);
        let p = plan
            .puntos()
            .into_iter()
            .find(|p| p.que == Que::DestinoDeLaTransferencia)
            .unwrap_or_else(|| panic!("{}", plan.frase()));
        assert_eq!(p.direccion, 0x1000);
        assert!(p.porque.contains("memoria"), "{}", p.porque);
    }

    #[test]
    fn una_llamada_que_el_analisis_ya_resolvio_no_se_instrumenta() {
        // Poner un punto ahi confirma lo que ya se sabia, gasta presupuesto y
        // alarga la ejecucion. La instrumentacion sirve para lo que NO se sabe.
        //
        //   0x1000 mov rax, 0x1010 ; call rax ; ret ; ... ; 0x1010 ret
        let mut bytes = vec![
            0x48, 0xC7, 0xC0, 0x10, 0x10, 0x00, 0x00, // mov rax, 0x1010
            0xFF, 0xD0, // call rax
            0xC3,
        ];
        bytes.resize(0x11, 0x90);
        bytes[0x10] = 0xC3;
        let a = analisis(&bytes);
        let plan = plan_desde(&a);
        assert!(
            !plan
                .puntos()
                .iter()
                .any(|p| p.direccion == 0x1007 && p.que == Que::DestinoDeLaTransferencia),
            "esa llamada ya estaba resuelta: {}",
            plan.frase()
        );
    }

    #[test]
    fn una_llamada_al_sistema_se_instrumenta_por_sus_argumentos() {
        // `syscall` = 0F 05. Es lo unico que el programa no puede falsear desde
        // dentro de si mismo.
        let a = analisis(&[0x0F, 0x05, 0xC3]);
        let plan = plan_desde(&a);
        assert!(
            plan.puntos().iter().any(|p| p.que == Que::Argumentos),
            "{}",
            plan.frase()
        );
    }

    #[test]
    fn un_salto_fuera_del_codigo_se_instrumenta_por_su_contenido() {
        // Es lo que hace un desempaquetador al terminar, y el sitio exacto donde
        // aparece el codigo que de verdad hay que analizar.
        //
        //   mov rax, 0x900000 ; jmp rax
        let a = analisis(&[
            0x48, 0xB8, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0,
        ]);
        let plan = plan_desde(&a);
        let p = plan
            .puntos()
            .into_iter()
            .find(|p| p.que == Que::ContenidoEscrito)
            .unwrap_or_else(|| panic!("{}", plan.frase()));
        assert!(p.porque.contains("empaquetador"), "{}", p.porque);
    }

    #[test]
    fn un_binario_que_el_analisis_entiende_entero_produce_un_plan_pequeno() {
        // La propiedad que hace utilizable esto: si el analisis estatico lo
        // resolvio todo, no hay casi nada que preguntarle a la ejecucion, y una
        // ejecucion con pocos puntos es una que se hace.
        let a = analisis(&[0x31, 0xC0, 0xC3]);
        let plan = plan_desde(&a);
        assert!(
            plan.cuantos() <= 1,
            "un xor y un ret no tienen nada sin resolver: {}",
            plan.frase()
        );
        assert!(!plan.se_recorto());
    }

    #[test]
    fn lo_mas_especifico_entra_antes_que_lo_mas_generico() {
        // El orden importa porque el plan tiene tope: si hay que recortar, lo
        // que se pierde tiene que ser lo que menos dice. Con muchas llamadas
        // indirectas, ninguna puede quedarse fuera por culpa de las entradas de
        // funcion.
        let mut bytes = Vec::new();
        for _ in 0..300 {
            bytes.extend_from_slice(&[0xFF, 0x15, 0x10, 0x2F, 0x00, 0x00]); // call [rip+..]
        }
        bytes.push(0xC3);
        let a = analisis(&bytes);
        let plan = plan_desde(&a);
        assert!(plan.se_recorto(), "{}", plan.frase());
        assert_eq!(
            plan.por_clase(Que::Paso),
            0,
            "las entradas de funcion son lo primero que se recorta: {}",
            plan.frase()
        );
        assert!(plan.por_clase(Que::DestinoDeLaTransferencia) > 0);
    }

    #[test]
    fn el_mismo_binario_produce_siempre_el_mismo_plan() {
        // Sin esto no se pueden comparar dos ejecuciones instrumentadas y saber
        // que lo que cambio fue el binario.
        let bytes = &[0xFF, 0x15, 0x10, 0x2F, 0x00, 0x00, 0x0F, 0x05, 0xC3];
        let a = plan_desde(&analisis(bytes));
        let b = plan_desde(&analisis(bytes));
        assert_eq!(a, b);
        assert_eq!(a.frase(), b.frase());
    }
}
