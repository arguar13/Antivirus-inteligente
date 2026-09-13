//! Obligar el presupuesto desde fuera del proceso.
//!
//! Todo lo anterior lo decide el agente sobre si mismo, y un agente comprometido
//! —o sencillamente con un bug— decide lo que le da la gana. Lo que convierte el
//! presupuesto en un invariante es que lo imponga alguien que no sea el: el
//! kernel, via cgroup v2.
//!
//! El reparto en dos limites no es decorativo:
//!
//! - `MemoryHigh` es **blando**. Al cruzarlo el kernel no mata: reclama con
//!   agresividad y frena al proceso. Es exactamente lo que se quiere en el pico,
//!   porque el escaneo tiene que terminar aunque vaya mas lento.
//! - `MemoryMax` es **duro**. Al cruzarlo hay OOM dentro del cgroup, que mata al
//!   agente sin tocar al resto del host. Con `Restart=always` el resultado es un
//!   agente nuevo y sano en un segundo, y sin el seria una maquina de produccion
//!   caida por culpa de quien venia a protegerla.
//!
//! Y `MemorySwapMax=0` por dos motivos que apuntan al mismo sitio: un EDR
//! paginado a disco llega tarde a todo, y sus estructuras llevan claves y
//! fragmentos de memoria ajena que no deben acabar escritos en el disco de la
//! victima.

use crate::perfil::Presupuesto;
use crate::reparto::Componente;

/// Genera el fragmento `[Service]` que impone el presupuesto.
///
/// Se entrega como *drop-in* (`/etc/systemd/system/aegis-agent.service.d/`) y no
/// como unidad completa a proposito: el perfil de un host puede cambiar —se le
/// anade RAM, se decide apretarlo porque la tiene vendida a otra cosa— y el
/// despliegue tiene que poder reescribir solo esto sin tocar la unidad.
#[must_use]
pub fn dropin(presupuesto: &Presupuesto) -> String {
    let mut s = String::new();
    s.push_str("# Generado por aegis-presupuesto. No editar a mano.\n");
    s.push_str(&format!(
        "# Perfil {} sobre un host de {}.\n",
        presupuesto.perfil.nombre(),
        humano(presupuesto.memoria_host)
    ));
    if !presupuesto.es_viable() {
        s.push_str("# AVISO: host por debajo del minimo viable; el agente arranca degradado.\n");
    }
    s.push_str("\n[Service]\n");
    s.push_str("MemoryAccounting=yes\n");
    s.push_str(&format!(
        "# Blando: al cruzarlo el kernel reclama y frena, pero el escaneo termina.\nMemoryHigh={}\n",
        presupuesto.pico
    ));
    s.push_str(&format!(
        "# Duro: OOM dentro del cgroup. Mata al agente, nunca al host.\nMemoryMax={}\n",
        presupuesto.techo
    ));
    s.push_str("# Un EDR paginado llega tarde, y sus estructuras no deben tocar disco.\n");
    s.push_str("MemorySwapMax=0\n");
    s.push_str("# Frente a una presion de memoria ajena el agente no es la victima\n");
    s.push_str("# a sacrificar: su propia fuga ya la corta MemoryMax, que es local.\n");
    s.push_str("OOMScoreAdjust=-500\n");
    s.push_str("# El OOM del cgroup no es el final: es un reinicio de un segundo.\n");
    s.push_str("Restart=always\n");
    s.push_str("RestartSec=1\n");
    s.push_str(&format!(
        "Environment=AEGIS_PERFIL={}\n",
        presupuesto.perfil.nombre()
    ));
    s
}

/// Resumen legible del reparto, para el instalador y para `aegis-ctl`.
#[must_use]
pub fn resumen(presupuesto: &Presupuesto) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "host {} · perfil {} · techo {} ({},{} % del host)\n",
        humano(presupuesto.memoria_host),
        presupuesto.perfil.nombre(),
        humano(presupuesto.techo),
        presupuesto.peso_del_techo() / 100,
        presupuesto.peso_del_techo() % 100
    ));
    s.push_str(&format!(
        "  reposo {}   pico {}   techo {}\n",
        humano(presupuesto.reposo),
        humano(presupuesto.pico),
        humano(presupuesto.techo)
    ));
    for c in Componente::todos() {
        s.push_str(&format!(
            "  {:<8} {:>10}{}\n",
            c.nombre(),
            humano(presupuesto.cuota(c)),
            if c.es_fijo() { "  (fijo)" } else { "" }
        ));
    }
    if !presupuesto.es_viable() {
        s.push_str("  AVISO: por debajo del minimo viable; deteccion degradada\n");
    }
    s
}

/// Formatea bytes en la unidad que menos ruido mete al leerlos.
#[must_use]
pub fn humano(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{},{} GiB", bytes / GIB, (bytes % GIB) * 10 / GIB)
    } else if bytes >= MIB {
        format!("{} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    #[test]
    fn el_dropin_lleva_los_dos_limites_y_no_los_confunde() {
        let p = Presupuesto::para(16 * GIB);
        let texto = dropin(&p);
        assert!(texto.contains(&format!("MemoryHigh={}", p.pico)));
        assert!(texto.contains(&format!("MemoryMax={}", p.techo)));
        // El blando tiene que ser el pico y el duro el techo, no al reves: si se
        // intercambian, el kernel mata donde deberia frenar.
        let alto = texto.find("MemoryHigh=").unwrap();
        let maximo = texto.find("MemoryMax=").unwrap();
        assert!(alto < maximo);
        assert!(p.pico < p.techo);
    }

    #[test]
    fn el_dropin_impide_el_swap_y_reinicia() {
        let texto = dropin(&Presupuesto::para(16 * GIB));
        assert!(texto.contains("MemorySwapMax=0"));
        assert!(texto.contains("Restart=always"));
        assert!(texto.contains("MemoryAccounting=yes"));
        assert!(texto.contains("OOMScoreAdjust=-500"));
    }

    #[test]
    fn el_dropin_declara_un_host_no_viable() {
        let texto = dropin(&Presupuesto::para(64 * MIB));
        assert!(texto.contains("AVISO"), "{texto}");
        // Y el que si es viable no mete el aviso.
        assert!(!dropin(&Presupuesto::para(16 * GIB)).contains("AVISO"));
    }

    #[test]
    fn el_dropin_es_una_seccion_de_service_valida() {
        let texto = dropin(&Presupuesto::para(8 * GIB));
        assert!(texto.contains("\n[Service]\n"));
        for linea in texto.lines() {
            if linea.is_empty() || linea.starts_with('#') || linea == "[Service]" {
                continue;
            }
            assert!(linea.contains('='), "linea sin clave=valor: {linea:?}");
        }
    }

    #[test]
    fn el_resumen_nombra_todos_los_componentes() {
        let texto = resumen(&Presupuesto::para(16 * GIB));
        for c in Componente::todos() {
            assert!(
                texto.contains(c.nombre()),
                "falta {} en:\n{texto}",
                c.nombre()
            );
        }
        assert!(texto.contains("estacion"));
    }

    #[test]
    fn humano_no_miente_en_las_fronteras() {
        assert_eq!(humano(512), "512 B");
        assert_eq!(humano(1024), "1 KiB");
        assert_eq!(humano(48 * MIB), "48 MiB");
        assert_eq!(humano(1536 * MIB), "1,5 GiB");
        assert_eq!(humano(GIB), "1,0 GiB");
    }
}
