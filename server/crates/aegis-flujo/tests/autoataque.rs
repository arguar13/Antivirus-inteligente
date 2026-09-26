//! AUTOATAQUE: la automatizacion como arma.
//!
//! Un SOAR que puede aislar mil maquinas por un error de plantilla es un arma
//! apuntando al cliente. Aqui se construyen, contra una flota REAL de mil
//! maquinas en el esquema del plano de control, los flujos que un error —o
//! alguien con acceso al editor de flujos— escribiria para dejar a la
//! organizacion sin red, y se comprueba EN LA BASE DE DATOS que no pasa nada:
//!
//! 1. Aislar la flota entera en un paso, CON FIRMA: la firma dice que una
//!    persona lo aprobo, no que el radio sea razonable. Los frenos lo escalan.
//! 2. La misma intencion expandida por una plantilla en mil pasos de una
//!    maquina, cada uno firmado: el radio es el acumulado de la ejecucion, asi
//!    que se para en el 26, y los 25 anteriores se revierten.
//! 3. Bloquear `0.0.0.0/0` (la plantilla que puso una red donde iba una
//!    direccion): su radio son las maquinas de la flota que viven dentro, las
//!    mil. Se escala.
//! 4. Bloquear la subred del controlador de dominio: la red cabe en el radio,
//!    pero corta un activo protegido y el efecto no se puede separar de el.
//!
//! Y en los cuatro casos, que lo que se escala se escala: el informe lleva el
//! paso y el motivo que una persona tiene que ver.

mod comun;

use aegis_entidad::{entidad, Eid};
use aegis_flujo::catalogo::{Aislar, AislarGrupo, BloquearIndicador, Indicador, Tomar};
use aegis_flujo::firma::Firma;
use aegis_flujo::frenos::Motivo;
use aegis_flujo::pg::PuertosPg;
use aegis_flujo::tipos::{Maquina, Objetivo};
use aegis_flujo::{Estado, Flujo, Motor, ResultadoPaso, SinFirma};
use comun::{frenos, rt, Analista, Base};

const FLOTA: usize = 1000;

fn toda_la_flota() -> Vec<Objetivo<Maquina>> {
    (0..FLOTA)
        .map(|i| Objetivo::en(format!("srv-{i:04}")))
        .collect()
}

fn firmar_en_paralelo(
    ana: &Analista,
    flujo: &str,
    paso: &str,
    maquinas: &[Objetivo<Maquina>],
) -> Vec<Firma> {
    let hilos = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
    let trozo = maquinas.len().div_ceil(hilos).max(1);
    std::thread::scope(|s| {
        let tareas: Vec<_> = maquinas
            .chunks(trozo)
            .map(|c| {
                s.spawn(move || {
                    c.iter()
                        .map(|m| ana.aprueba(flujo, paso, std::slice::from_ref(m.eid())))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        tareas
            .into_iter()
            .flat_map(|t| t.join().expect("firmar"))
            .collect()
    })
}

async fn nada_cambio(b: &Base) {
    assert_eq!(
        b.contar("SELECT count(*) FROM agentes WHERE aislado").await,
        0,
        "maquinas aisladas"
    );
    assert_eq!(
        b.contar("SELECT count(*) FROM comandos").await,
        0,
        "ordenes encoladas"
    );
    assert_eq!(
        b.contar("SELECT count(*) FROM cuarentena").await,
        0,
        "redes bloqueadas"
    );
}

#[test]
fn autoataque_la_automatizacion_como_arma() {
    rt().block_on(async {
        let Some(b) = Base::abrir("autoataque").await else {
            return;
        };
        b.flota(FLOTA).await;
        // El controlador de dominio, protegido, en 10.20.1.254: dentro de la
        // primera /24 de la flota, junto a srv-0247..srv-0249 (.248 a .250).
        b.maquina("dc-01", "10.20.1.254").await;
        let dc = entidad::maquina("dc-01");
        let fr = frenos(FLOTA + 1, std::slice::from_ref(&dc));
        let ana = Analista::nuevo("ana");
        let p = b.puertos("autoataque");
        let motor = Motor::nuevo(&p, &fr);

        // 1. La flota entera en un paso, firmado.
        let flota = toda_la_flota();
        let ids: Vec<Eid> = flota.iter().map(|m| m.eid().clone()).collect();
        let (mut f, g) = Flujo::<PuertosPg, Vec<Objetivo<Maquina>>>::nuevo("aislar todo");
        f.paso(
            AislarGrupo,
            g,
            ana.aprueba("aislar todo", "aislar grupo", &ids),
        );
        let inf = motor.ejecutar(&f, flota.clone()).await;
        println!("1. aislar la flota en un paso, firmado: {:?}", inf.estado);
        assert!(
            matches!(
                inf.estado,
                Estado::Escalado {
                    paso: "aislar grupo",
                    motivo: Motivo::RadioDemasiadoGrande {
                        objetivos: FLOTA,
                        tope: 25
                    }
                }
            ),
            "{:?}",
            inf.estado
        );
        assert!(matches!(
            inf.registro[0].resultado,
            ResultadoPaso::Frenado(_)
        ));
        nada_cambio(&b).await;

        // 2. La plantilla expandida: mil pasos de radio uno, cada uno firmado.
        // Mil aprobaciones hibridas (Ed25519 + ML-DSA) son el coste de esta
        // prueba, no del motor: se firman en paralelo.
        let firmas = firmar_en_paralelo(&ana, "aislar una a una", "aislar", &flota);
        let (mut f, e) = Flujo::<PuertosPg, Vec<Objetivo<Maquina>>>::nuevo("aislar una a una");
        for (i, firma) in firmas.into_iter().enumerate() {
            let t = f.paso(
                Tomar::nueva(
                    &format!("maquina {i}"),
                    move |v: &Vec<Objetivo<Maquina>>| v[i].clone(),
                ),
                e,
                SinFirma,
            );
            f.paso(Aislar, t, firma);
        }
        let inf = motor.ejecutar(&f, flota.clone()).await;
        let revertidos = inf
            .registro
            .iter()
            .filter(|r| r.paso == "aislar" && r.resultado == ResultadoPaso::Revertido)
            .count();
        println!(
            "2. mil pasos de radio uno: {:?}; {revertidos} aislamientos hechos y revertidos",
            inf.estado
        );
        assert!(
            matches!(
                inf.estado,
                Estado::Escalado {
                    paso: "aislar",
                    motivo: Motivo::RadioDemasiadoGrande {
                        objetivos: 26,
                        tope: 25
                    }
                }
            ),
            "{:?}",
            inf.estado
        );
        assert_eq!(revertidos, 25);
        nada_cambio(&b).await;

        // 3. 0.0.0.0/0 donde iba una direccion.
        let (mut f, r) = Flujo::<PuertosPg, Indicador>::nuevo("bloquear C2");
        f.paso(BloquearIndicador, r, SinFirma);
        let inf = motor
            .ejecutar(&f, Indicador::nuevo("0.0.0.0/0").unwrap())
            .await;
        println!("3. bloquear 0.0.0.0/0: {:?}", inf.estado);
        assert!(
            matches!(
                inf.estado,
                Estado::Escalado {
                    motivo: Motivo::RadioDemasiadoGrande { objetivos, .. },
                    ..
                } if objetivos == FLOTA + 1
            ),
            "{:?}",
            inf.estado
        );
        nada_cambio(&b).await;

        // 4. La subred del controlador de dominio. La /24 entera son 251
        // maquinas —mas que el tope—; la /29 10.20.1.248 son cuatro (tres
        // servidores y el controlador): dentro del radio, pero toca un protegido.
        let inf = motor
            .ejecutar(&f, Indicador::nuevo("10.20.1.248/29").unwrap())
            .await;
        println!(
            "4. bloquear la red del controlador de dominio: {:?}",
            inf.estado
        );
        assert!(
            matches!(
                inf.estado,
                Estado::Escalado {
                    motivo: Motivo::ProtegidosEnElRadio { preservados: 1 },
                    ..
                }
            ),
            "{:?}",
            inf.estado
        );
        assert_eq!(inf.registro[0].preservados, std::slice::from_ref(&dc));
        assert_eq!(inf.registro[0].objetivos.len(), 4);
        nada_cambio(&b).await;

        // Y la contencion legitima sigue funcionando: una maquina, firmada.
        let (mut f, m) = Flujo::<PuertosPg, Objetivo<Maquina>>::nuevo("aislar una");
        let una = Objetivo::<Maquina>::en("srv-0042".to_string());
        f.paso(
            Aislar,
            m,
            ana.aprueba("aislar una", "aislar", &[una.eid().clone()]),
        );
        let inf = motor.ejecutar(&f, una).await;
        println!("control: aislar una maquina, firmado: {:?}", inf.estado);
        assert_eq!(inf.estado, Estado::Completado);
        assert_eq!(
            b.contar("SELECT count(*) FROM agentes WHERE aislado").await,
            1
        );
        b.cerrar().await;
    });
}
