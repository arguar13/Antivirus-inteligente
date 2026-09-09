//! Prueba de la sonda de la PMU.
//!
//! No se afirma que la PMU exista —en un microVM no existe—. Se afirma que la
//! sonda responde con HONESTIDAD: si no hay PMU, lo dice con una causa, y jamas
//! entra en panico ni miente diciendo que la hay.

use aegis_syscallguard::pmu::{sondear_pmu, SoportePmu};

#[test]
fn la_sonda_de_pmu_es_honesta() {
    match sondear_pmu() {
        SoportePmu::Disponible => {
            // Si la maquina tiene PMU, se puede abrir y leer un contador.
            let c = aegis_syscallguard::pmu::ContadorHardware::instrucciones()
                .expect("si la sonda dice Disponible, abrir el contador no puede fallar");
            c.arrancar().expect("arrancar el contador");
            // Hacer algo de trabajo para que el contador avance.
            let mut s = 0u64;
            for i in 0..100_000u64 {
                s = s.wrapping_add(i);
            }
            std::hint::black_box(s);
            c.detener().ok();
            let _ = c.leer().expect("leer el contador");
        }
        SoportePmu::NoDisponible(motivo) => {
            // El caso de esta maquina. Lo importante: hay una causa, no un
            // silencio.
            assert!(!motivo.is_empty(), "una no-disponibilidad debe explicarse");
            eprintln!("PMU no disponible (esperado en microVM): {motivo}");
        }
    }
}
