//! El motor, contra un mundo en memoria que registra cada efecto y cada
//! reversion en orden.
//!
//! Las pruebas contra el estado REAL del plano de control estan en `pg.rs`;
//! estas fijan las propiedades del motor sin nada mas alrededor: el orden de la
//! reversion, el estado de antes, la idempotencia, los frenos por paso con radio
//! acumulado y la firma que cubre una ejecucion concreta.

use std::collections::BTreeSet;
use std::sync::Mutex;

use aegis_entidad::{entidad, Eid};
use aegis_flujo::firma::{huella, Firma, DOMINIO};
use aegis_flujo::frenos::{CincoFrenos, Motivo};
use aegis_flujo::paso::{ErrorPaso, Fut, Paso, Reversibilidad};
use aegis_flujo::tipos::{Maquina, Objetivo};
use aegis_flujo::{Estado, Flujo, Motor, ResultadoPaso, SinFirma};
use aegis_pqc::firma_hibrida::ClaveFirmaHibrida;
use aegis_predict::grafo::Evidencia;
use aegis_predict::ConfigContencion;

/// Un mundo: un conjunto de marcas y el diario de lo que se hizo.
#[derive(Default)]
struct Mundo {
    marcas: Mutex<BTreeSet<String>>,
    diario: Mutex<Vec<String>>,
    /// Pasos cuya reversion falla.
    no_revierten: Vec<&'static str>,
}

impl Mundo {
    fn marcas(&self) -> BTreeSet<String> {
        self.marcas.lock().unwrap().clone()
    }
    fn diario(&self) -> Vec<String> {
        self.diario.lock().unwrap().clone()
    }
}

/// Marca una maquina (como aislarla). Guarda si ya estaba marcada.
struct Marcar {
    nombre: &'static str,
    falla: bool,
}

fn marcar(nombre: &'static str) -> Marcar {
    Marcar {
        nombre,
        falla: false,
    }
}

impl Paso<Mundo> for Marcar {
    type Entrada = Objetivo<Maquina>;
    type Salida = Objetivo<Maquina>;
    type Deshacer = (String, bool);
    type Permiso = SinFirma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
    const TOCA_FLOTA: bool = true;

    fn nombre(&self) -> &'static str {
        self.nombre
    }
    fn objetivos<'a>(
        &'a self,
        m: &'a Objetivo<Maquina>,
        _: &'a Mundo,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        Box::pin(async move { Ok(vec![m.eid().clone()]) })
    }
    fn clave(&self, m: &Objetivo<Maquina>) -> String {
        m.eid().texto()
    }
    fn ejecutar<'a>(
        &'a self,
        m: &'a Objetivo<Maquina>,
        w: &'a Mundo,
    ) -> Fut<'a, Result<(Objetivo<Maquina>, (String, bool)), ErrorPaso>> {
        Box::pin(async move {
            if self.falla {
                return Err(ErrorPaso::Fallo(format!("{} fallo", self.nombre)));
            }
            let k = format!("{}:{}", self.nombre, m.loc());
            let ya = !w.marcas.lock().unwrap().insert(k.clone());
            w.diario.lock().unwrap().push(format!("+{k}"));
            Ok((m.clone(), (k, ya)))
        })
    }
    fn revertir<'a>(
        &'a self,
        (k, ya): (String, bool),
        w: &'a Mundo,
    ) -> Fut<'a, Result<(), ErrorPaso>> {
        Box::pin(async move {
            if w.no_revierten.contains(&self.nombre) {
                return Err(ErrorPaso::Fallo("el sistema remoto no responde".into()));
            }
            w.diario.lock().unwrap().push(format!("-{k}"));
            if !ya {
                w.marcas.lock().unwrap().remove(&k);
            }
            Ok(())
        })
    }
}

/// Un paso irreversible que exige firma.
struct Destruir;

impl Paso<Mundo> for Destruir {
    type Entrada = Objetivo<Maquina>;
    type Salida = Objetivo<Maquina>;
    type Deshacer = ();
    type Permiso = Firma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Irreversible;
    const TOCA_FLOTA: bool = true;

    fn nombre(&self) -> &'static str {
        "destruir"
    }
    fn objetivos<'a>(
        &'a self,
        m: &'a Objetivo<Maquina>,
        _: &'a Mundo,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        Box::pin(async move { Ok(vec![m.eid().clone()]) })
    }
    fn clave(&self, m: &Objetivo<Maquina>) -> String {
        m.eid().texto()
    }
    fn ejecutar<'a>(
        &'a self,
        m: &'a Objetivo<Maquina>,
        w: &'a Mundo,
    ) -> Fut<'a, Result<(Objetivo<Maquina>, ()), ErrorPaso>> {
        Box::pin(async move {
            w.diario.lock().unwrap().push(format!("x{}", m.loc()));
            Ok((m.clone(), ()))
        })
    }
    fn revertir<'a>(&'a self, (): (), _: &'a Mundo) -> Fut<'a, Result<(), ErrorPaso>> {
        Box::pin(async { Err(ErrorPaso::Fallo("no se puede".into())) })
    }
}

/// Marca un grupo en un solo paso.
struct MarcarGrupo;

impl Paso<Mundo> for MarcarGrupo {
    type Entrada = Vec<Objetivo<Maquina>>;
    type Salida = ();
    type Deshacer = Vec<String>;
    type Permiso = SinFirma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
    const TOCA_FLOTA: bool = true;

    fn nombre(&self) -> &'static str {
        "marcar grupo"
    }
    fn objetivos<'a>(
        &'a self,
        g: &'a Vec<Objetivo<Maquina>>,
        _: &'a Mundo,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        Box::pin(async move { Ok(g.iter().map(|m| m.eid().clone()).collect()) })
    }
    fn clave(&self, g: &Vec<Objetivo<Maquina>>) -> String {
        g.len().to_string()
    }
    fn ejecutar<'a>(
        &'a self,
        g: &'a Vec<Objetivo<Maquina>>,
        w: &'a Mundo,
    ) -> Fut<'a, Result<((), Vec<String>), ErrorPaso>> {
        Box::pin(async move {
            let ks: Vec<String> = g.iter().map(|m| format!("grupo:{}", m.loc())).collect();
            w.marcas.lock().unwrap().extend(ks.iter().cloned());
            Ok(((), ks))
        })
    }
    fn revertir<'a>(&'a self, ks: Vec<String>, w: &'a Mundo) -> Fut<'a, Result<(), ErrorPaso>> {
        Box::pin(async move {
            let mut m = w.marcas.lock().unwrap();
            for k in ks {
                m.remove(&k);
            }
            Ok(())
        })
    }
}

fn frenos(flota: usize) -> CincoFrenos {
    CincoFrenos {
        config: ConfigContencion::default(),
        flota,
        protegidos: [entidad::maquina("dc-01")].into_iter().collect(),
        evidencia: Evidencia {
            observaciones: 5,
            observadores: 3,
            antiguedad_seg: 2 * 86_400,
        },
        confianza: 0.9,
    }
}

fn maquina(cn: &str) -> Objetivo<Maquina> {
    Objetivo::en(cn.to_string())
}

fn ejecutar<E: Send + Sync + 'static>(
    w: &Mundo,
    f: &Flujo<Mundo, E>,
    e: E,
    flota: usize,
) -> aegis_flujo::Informe {
    let fr = frenos(flota);
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(Motor::nuevo(w, &fr).ejecutar(f, e))
}

#[test]
fn un_flujo_que_falla_a_medias_se_revierte_en_orden_inverso() {
    let w = Mundo::default();
    let (mut f, m) = Flujo::<Mundo, Objetivo<Maquina>>::nuevo("contencion");
    let a = f.paso(marcar("a"), m, SinFirma);
    let b = f.paso(marcar("b"), a, SinFirma);
    let c = f.paso(marcar("c"), b, SinFirma);
    f.paso(
        Marcar {
            nombre: "d",
            falla: true,
        },
        c,
        SinFirma,
    );
    let inf = ejecutar(&w, &f, maquina("srv-1"), 100);

    assert_eq!(
        inf.estado,
        Estado::Revertido {
            paso: "d",
            motivo: "d fallo".into()
        }
    );
    assert!(w.marcas().is_empty(), "no queda nada: {:?}", w.marcas());
    assert_eq!(
        w.diario(),
        ["+a:srv-1", "+b:srv-1", "+c:srv-1", "-c:srv-1", "-b:srv-1", "-a:srv-1"]
    );
    let r: Vec<_> = inf.registro.iter().map(|r| r.resultado.clone()).collect();
    assert_eq!(
        r,
        [
            ResultadoPaso::Revertido,
            ResultadoPaso::Revertido,
            ResultadoPaso::Revertido,
            ResultadoPaso::Fallido("d fallo".into())
        ]
    );
}

#[test]
fn revertir_vuelve_al_estado_de_antes_y_no_deshace_lo_ajeno() {
    let w = Mundo::default();
    // Otra persona ya habia marcado srv-1 con «a» antes del flujo.
    w.marcas.lock().unwrap().insert("a:srv-1".into());
    let (mut f, m) = Flujo::<Mundo, Objetivo<Maquina>>::nuevo("contencion");
    let a = f.paso(marcar("a"), m, SinFirma);
    let b = f.paso(marcar("b"), a, SinFirma);
    f.paso(
        Marcar {
            nombre: "c",
            falla: true,
        },
        b,
        SinFirma,
    );
    ejecutar(&w, &f, maquina("srv-1"), 100);
    assert_eq!(w.marcas(), ["a:srv-1".to_string()].into_iter().collect());
}

#[test]
fn el_mismo_paso_con_la_misma_clave_no_se_repite() {
    let w = Mundo::default();
    let (mut f, m) = Flujo::<Mundo, Objetivo<Maquina>>::nuevo("repetido");
    let a = f.paso(marcar("a"), m, SinFirma);
    let a2 = f.paso(marcar("a"), a, SinFirma);
    f.paso(marcar("b"), a2, SinFirma);
    let inf = ejecutar(&w, &f, maquina("srv-1"), 100);
    assert_eq!(inf.estado, Estado::Completado);
    assert_eq!(inf.registro[1].resultado, ResultadoPaso::Repetido);
    assert_eq!(w.diario(), ["+a:srv-1", "+b:srv-1"]);
}

#[test]
fn los_frenos_miran_cada_paso_y_el_primero_se_revierte() {
    let w = Mundo::default();
    let (mut f, m) = Flujo::<Mundo, Objetivo<Maquina>>::nuevo("mixto");
    f.paso(marcar("a"), m, SinFirma);
    // Un segundo flujo cuya entrada es un grupo de 30.
    let (mut g, grupo) = Flujo::<Mundo, Vec<Objetivo<Maquina>>>::nuevo("grupo");
    g.paso(MarcarGrupo, grupo, SinFirma);
    let treinta: Vec<_> = (0..30).map(|i| maquina(&format!("srv-{i}"))).collect();
    let inf = ejecutar(&w, &g, treinta, 1000);
    assert!(
        matches!(
            inf.estado,
            Estado::Escalado {
                paso: "marcar grupo",
                motivo: Motivo::RadioDemasiadoGrande { objetivos: 30, .. }
            }
        ),
        "{:?}",
        inf.estado
    );
    assert!(w.marcas().is_empty());
    // El de un solo objetivo pasa.
    assert_eq!(
        ejecutar(&w, &f, maquina("srv-1"), 1000).estado,
        Estado::Completado
    );
}

#[test]
fn mil_pasos_de_radio_uno_no_suman_un_radio_de_uno() {
    // La plantilla que expande «aislar» maquina a maquina: cada paso tiene radio
    // uno. El freno mira el acumulado y para en el 26.
    let w = Mundo::default();
    let (mut f, m) = Flujo::<Mundo, Objetivo<Maquina>>::nuevo("expandido");
    let mut n = m;
    const NOMBRES: [&str; 5] = ["p0", "p1", "p2", "p3", "p4"];
    // Cada paso es un paso distinto (otro nombre) sobre otra maquina: se
    // encadenan pasando por un paso que cambia de maquina.
    struct Siguiente(usize);
    impl Paso<Mundo> for Siguiente {
        type Entrada = Objetivo<Maquina>;
        type Salida = Objetivo<Maquina>;
        type Deshacer = ();
        type Permiso = SinFirma;
        const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
        const TOCA_FLOTA: bool = false;
        fn nombre(&self) -> &'static str {
            "siguiente"
        }
        fn objetivos<'a>(
            &'a self,
            _: &'a Objetivo<Maquina>,
            _: &'a Mundo,
        ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn clave(&self, _: &Objetivo<Maquina>) -> String {
            self.0.to_string()
        }
        fn ejecutar<'a>(
            &'a self,
            _: &'a Objetivo<Maquina>,
            _: &'a Mundo,
        ) -> Fut<'a, Result<(Objetivo<Maquina>, ()), ErrorPaso>> {
            let m = maquina(&format!("srv-{}", self.0));
            Box::pin(async move { Ok((m, ())) })
        }
        fn revertir<'a>(&'a self, (): (), _: &'a Mundo) -> Fut<'a, Result<(), ErrorPaso>> {
            Box::pin(async { Ok(()) })
        }
    }
    for i in 0..1000 {
        let s = f.paso(Siguiente(i), n, SinFirma);
        n = f.paso(marcar(NOMBRES[i % NOMBRES.len()]), s, SinFirma);
    }
    let inf = ejecutar(&w, &f, maquina("srv-x"), 1000);
    assert!(
        matches!(
            inf.estado,
            Estado::Escalado {
                motivo: Motivo::RadioDemasiadoGrande {
                    objetivos: 26,
                    tope: 25
                },
                ..
            }
        ),
        "{:?}",
        inf.estado
    );
    let hechos = w.diario().iter().filter(|d| d.starts_with('+')).count();
    let deshechos = w.diario().iter().filter(|d| d.starts_with('-')).count();
    assert_eq!((hechos, deshechos), (25, 25));
    assert!(w.marcas().is_empty());
}

#[test]
fn una_firma_para_otros_objetivos_no_ejecuta_nada() {
    let clave = ClaveFirmaHibrida::generar_aleatorio().unwrap();
    let m1 = maquina("srv-1");
    let m2 = maquina("srv-2");
    let h = huella("limpieza", "destruir", std::slice::from_ref(m1.eid()));
    let firma = clave.firmar(&h, DOMINIO).unwrap();
    let f1 = Firma::verificar(
        &clave.clave_verificacion(),
        "ana",
        "limpieza",
        "destruir",
        std::slice::from_ref(m1.eid()),
        &firma,
    )
    .unwrap();

    let w = Mundo::default();
    let (mut f, m) = Flujo::<Mundo, Objetivo<Maquina>>::nuevo("limpieza");
    let a = f.paso(marcar("a"), m, SinFirma);
    f.paso(Destruir, a, f1.clone());
    // Firmada para srv-1, ejecutada sobre srv-2: no se ejecuta, y lo anterior
    // se revierte.
    let inf = ejecutar(&w, &f, m2, 100);
    assert!(
        matches!(
            inf.estado,
            Estado::Revertido {
                paso: "destruir",
                ..
            }
        ),
        "{:?}",
        inf.estado
    );
    assert_eq!(inf.registro[1].resultado, ResultadoPaso::SinPermiso);
    assert!(!w.diario().iter().any(|d| d.starts_with('x')));
    assert!(w.marcas().is_empty());

    // Sobre srv-1 si, y queda quien lo aprobo.
    let w = Mundo::default();
    let inf = ejecutar(&w, &f, m1, 100);
    assert_eq!(inf.estado, Estado::Completado);
    assert_eq!(inf.registro[1].aprobado_por.as_deref(), Some("ana"));
}

#[test]
fn lo_irreversible_ya_hecho_no_se_finge_deshacer_se_escala() {
    let clave = ClaveFirmaHibrida::generar_aleatorio().unwrap();
    let m1 = maquina("srv-1");
    let h = huella("limpieza", "destruir", std::slice::from_ref(m1.eid()));
    let f1 = Firma::verificar(
        &clave.clave_verificacion(),
        "ana",
        "limpieza",
        "destruir",
        std::slice::from_ref(m1.eid()),
        &clave.firmar(&h, DOMINIO).unwrap(),
    )
    .unwrap();
    let w = Mundo::default();
    let (mut f, m) = Flujo::<Mundo, Objetivo<Maquina>>::nuevo("limpieza");
    let a = f.paso(marcar("a"), m, SinFirma);
    let d = f.paso(Destruir, a, f1);
    f.paso(
        Marcar {
            nombre: "c",
            falla: true,
        },
        d,
        SinFirma,
    );
    let inf = ejecutar(&w, &f, m1, 100);
    assert_eq!(
        inf.estado,
        Estado::RevertidoConFallos {
            paso: "c",
            motivo: "c fallo".into(),
            pendientes: vec!["destruir"]
        }
    );
    assert_eq!(inf.registro[1].resultado, ResultadoPaso::IrreversibleHecho);
    assert_eq!(inf.registro[0].resultado, ResultadoPaso::Revertido);
}

#[test]
fn una_reversion_que_falla_se_dice() {
    let w = Mundo {
        no_revierten: vec!["b"],
        ..Mundo::default()
    };
    let (mut f, m) = Flujo::<Mundo, Objetivo<Maquina>>::nuevo("contencion");
    let a = f.paso(marcar("a"), m, SinFirma);
    let b = f.paso(marcar("b"), a, SinFirma);
    f.paso(
        Marcar {
            nombre: "c",
            falla: true,
        },
        b,
        SinFirma,
    );
    let inf = ejecutar(&w, &f, maquina("srv-1"), 100);
    assert!(
        matches!(&inf.estado, Estado::RevertidoConFallos { pendientes, .. } if pendientes == &["b"]),
        "{:?}",
        inf.estado
    );
    // «a» si se revirtio; «b» sigue puesta y el informe lo dice.
    assert_eq!(w.marcas(), ["b:srv-1".to_string()].into_iter().collect());
    assert!(matches!(
        inf.registro[1].resultado,
        ResultadoPaso::ReversionFallida(_)
    ));
}

#[test]
fn un_grupo_que_incluye_un_protegido_se_detiene() {
    let w = Mundo::default();
    let (mut g, grupo) = Flujo::<Mundo, Vec<Objetivo<Maquina>>>::nuevo("grupo");
    g.paso(MarcarGrupo, grupo, SinFirma);
    let inf = ejecutar(&w, &g, vec![maquina("srv-1"), maquina("dc-01")], 100);
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
    assert_eq!(inf.registro[0].preservados, [entidad::maquina("dc-01")]);
    assert!(w.marcas().is_empty());
}
