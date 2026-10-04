//! Pruebas del canal de contenido de extremo a extremo: publicar, firmar con
//! una clave hibrida REAL, instalar y cargar en el almacen de un equipo.
//!
//! Lo que tiene que rechazarse, y se comprueba que se rechaza sin tocar el
//! estado: el paquete alterado, el de otra clave, el de otro dominio de firma,
//! el viejo (reposicion), el roto (en la puerta y, si alguien se la salta, en el
//! equipo), el que no es de su anillo y la escalera falsa.
//!
//! Las reglas de prueba son sinteticas: casan con marcadores inocuos
//! («AEGIS-CANAL-...»), no con nada que se parezca a una amenaza.

use std::path::{Path, PathBuf};

use aegis_contenido::anillo::{Peldano, CINCO_POR_CIENTO};
use aegis_contenido::paquete::MIN_MUESTRAS_IMPONER;
use aegis_contenido::publicar::{preparar, promover, revertir};
use aegis_contenido::{
    Ajustes, Almacen, Anillo, Borrador, ClaveFirmaHibrida, ClaveVerificacionHibrida, Coste,
    Destino, Entrada, ErrorCanal, FalloRegla, Firmable, Historial, Manifiesto, Medicion, Modo,
    Rebaja, Sellado, Tipo, Validadores, Verificacion, CTX_AJUSTES, CTX_CONTENIDO,
};

const CANAL: &str = "estable";
const EQUIPO: &str = "maq:equipo-de-prueba";

struct Lab(PathBuf);
impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-contenido-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        Lab(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn claves(s: u8) -> (ClaveFirmaHibrida, ClaveVerificacionHibrida) {
    let f = ClaveFirmaHibrida::desde_semillas(&[s; 32], &[s ^ 0x5a; 32]);
    let v = f.clave_verificacion();
    (f, v)
}

fn verificacion(v: &ClaveVerificacionHibrida, equipo: &str) -> Verificacion {
    Verificacion::nueva(v.clone(), CANAL, equipo, Validadores::por_defecto())
}

fn fuente_yara(id: &str, cadena: &str) -> Vec<u8> {
    format!(
        "rule {id}\n{{\n    meta:\n        description = \"regla sintetica del canal\"\n        \
         severity = \"low\"\n    strings:\n        {cadena}\n    condition:\n        $a\n}}\n"
    )
    .into_bytes()
}

fn regla(id: &str) -> Entrada {
    let marcador = format!("AEGIS-CANAL-{id}");
    Entrada {
        id: id.into(),
        tipo: Tipo::Yara,
        modo: Modo::Auditoria,
        activa: true,
        coste: Coste {
            pasos_por_byte: 4,
            micros_por_64k: 20_000,
        },
        medicion: Medicion::default(),
        fuente: fuente_yara(id, &format!("$a = \"{marcador}\" ascii")),
        dispara: vec![format!("antes {marcador} despues").into_bytes()],
        no_dispara: vec![b"texto corriente de un fichero cualquiera".to_vec()],
    }
}

fn destino(epoca: u64, anillo: Anillo) -> Destino {
    Destino {
        epoca,
        generado_ns: 0,
        anillo,
        escalera: Vec::new(),
        revierte_a: 0,
    }
}

fn canario() -> Anillo {
    Anillo::canario(&[EQUIPO, "maq:otro-canario"])
}

fn preparar_en(
    epoca: u64,
    anillo: Anillo,
    entradas: Vec<Entrada>,
    h: &Historial,
) -> Result<Firmable, ErrorCanal> {
    preparar(
        Borrador {
            canal: CANAL.into(),
            entradas,
        },
        destino(epoca, anillo),
        h,
        &Validadores::por_defecto(),
    )
}

/// Un paquete de canario firmado, en la epoca dada.
fn paquete(f: &ClaveFirmaHibrida, epoca: u64, entradas: Vec<Entrada>) -> Vec<u8> {
    preparar_en(epoca, canario(), entradas, &Historial::nuevo())
        .unwrap()
        .firmar(f)
        .unwrap()
}

/// Firma un manifiesto a mano, SALTANDOSE la puerta de publicacion.
fn firmar_a_mano(f: &ClaveFirmaHibrida, m: &Manifiesto, ctx: &[u8]) -> Vec<u8> {
    let cuerpo = m.a_bytes();
    let firma = f.firmar(&cuerpo, ctx).unwrap().a_bytes();
    Sellado { cuerpo, firma }.a_bytes()
}

fn ids(a: &Almacen, v: &Verificacion) -> Vec<String> {
    a.cargar(v)
        .unwrap()
        .reglas
        .into_iter()
        .map(|r| r.id)
        .collect()
}

#[test]
fn un_paquete_valido_se_instala_y_se_carga_en_auditoria() {
    let lab = Lab::nuevo("valido");
    let (f, pk) = claves(1);
    let v = verificacion(&pk, EQUIPO);
    let mut a = Almacen::abrir(lab.path()).unwrap();
    assert!(matches!(a.cargar(&v), Err(ErrorCanal::SinContenido)));

    let i = a
        .instalar(&paquete(&f, 1, vec![regla("R_Uno")]), &v)
        .unwrap();
    assert_eq!(i.epoca, 1);
    assert_eq!(i.anillo, "canario");

    // Otro proceso (el agente al arrancar) abre el mismo almacen y carga.
    let c = Almacen::abrir(lab.path()).unwrap().cargar(&v).unwrap();
    assert_eq!(c.epoca, 1);
    assert_eq!(c.reglas.len(), 1);
    assert_eq!(c.reglas[0].modo, Modo::Auditoria);
    assert_eq!(c.cuantas(Modo::Imponer), 0);
    assert!(!c.recuperado_de_anterior);
}

#[test]
fn un_paquete_alterado_se_rechaza_sin_tocar_el_estado() {
    let lab = Lab::nuevo("alterado");
    let (f, pk) = claves(2);
    let v = verificacion(&pk, EQUIPO);
    let mut a = Almacen::abrir(lab.path()).unwrap();
    a.instalar(&paquete(&f, 1, vec![regla("R_Uno")]), &v)
        .unwrap();

    let bueno = paquete(&f, 2, vec![regla("R_Dos")]);
    // Un bit del cuerpo (tras la longitud) y un bit de la firma.
    for i in [12, bueno.len() - 1] {
        let mut malo = bueno.clone();
        malo[i] ^= 0x01;
        assert!(
            matches!(a.instalar(&malo, &v), Err(ErrorCanal::Firma(_))),
            "byte {i}"
        );
    }
    assert_eq!(a.estado().epoca_vista, 1);
    assert_eq!(ids(&a, &v), vec!["R_Uno".to_string()]);
    // El bueno sigue entrando.
    a.instalar(&bueno, &v).unwrap();
}

#[test]
fn un_paquete_de_otra_clave_o_de_otro_dominio_se_rechaza() {
    let lab = Lab::nuevo("otra-clave");
    let (_, pk) = claves(3);
    let (f_ajena, _) = claves(4);
    let v = verificacion(&pk, EQUIPO);
    let mut a = Almacen::abrir(lab.path()).unwrap();
    let ajeno = paquete(&f_ajena, 1, vec![regla("R_Uno")]);
    assert!(matches!(a.instalar(&ajeno, &v), Err(ErrorCanal::Firma(_))));

    // Firma de la clave BUENA pero con el dominio de los ajustes.
    let (f, pk) = claves(5);
    let v = verificacion(&pk, EQUIPO);
    let firmable = preparar_en(1, canario(), vec![regla("R_Uno")], &Historial::nuevo()).unwrap();
    let otro_dominio = firmar_a_mano(&f, firmable.manifiesto(), CTX_AJUSTES);
    assert!(matches!(
        a.instalar(&otro_dominio, &v),
        Err(ErrorCanal::Firma(_))
    ));
    assert_eq!(a.estado().epoca_vista, 0);
}

#[test]
fn un_paquete_viejo_autentico_no_se_repone() {
    let lab = Lab::nuevo("viejo");
    let (f, pk) = claves(6);
    let v = verificacion(&pk, EQUIPO);
    let mut a = Almacen::abrir(lab.path()).unwrap();
    let e1 = paquete(&f, 1, vec![regla("R_Uno")]);
    let e2 = paquete(&f, 2, vec![regla("R_Dos")]);
    a.instalar(&e1, &v).unwrap();
    a.instalar(&e2, &v).unwrap();

    for viejo in [&e1, &e2] {
        match a.instalar(viejo, &v) {
            Err(ErrorCanal::Retroceso { vista, .. }) => assert_eq!(vista, 2),
            otro => panic!("se esperaba Retroceso: {otro:?}"),
        }
    }
    assert_eq!(ids(&a, &v), vec!["R_Dos".to_string()]);
}

#[test]
fn un_paquete_roto_no_pasa_la_puerta_y_se_dice_todo_lo_roto() {
    let mut no_compila = regla("R_NoCompila");
    no_compila.fuente = b"rule R_NoCompila { condition: ".to_vec();

    let mut no_dispara = regla("R_NoDispara");
    no_dispara.dispara = vec![b"aqui no esta el marcador".to_vec()];

    let mut salta = regla("R_Salta");
    salta.no_dispara = vec![b"AEGIS-CANAL-R_Salta en algo legitimo".to_vec()];

    // Un patron con salto: su cota por byte pasa de lo que declara (4).
    let mut cara = regla("R_Cara");
    cara.fuente = fuente_yara("R_Cara", "$a = { 41 45 47 [0-64] 49 53 }");
    cara.dispara = vec![b"AEG--------IS".to_vec()];

    let mut sigma = regla("R_Sigma");
    sigma.tipo = Tipo::Sigma;

    let buena = regla("R_Buena");

    let r = preparar_en(
        1,
        canario(),
        vec![no_compila, no_dispara, salta, cara, sigma, buena],
        &Historial::nuevo(),
    );
    let roturas = match r {
        Err(ErrorCanal::Roto(v)) => v,
        otro => panic!("se esperaba Roto: {otro:?}"),
    };
    let fallo = |id: &str| {
        roturas
            .iter()
            .find(|x| x.id == id)
            .map(|x| x.fallo.clone())
            .unwrap_or_else(|| panic!("{id} no aparece como roto"))
    };
    assert!(matches!(fallo("R_NoCompila"), FalloRegla::NoCompila(_)));
    assert!(matches!(
        fallo("R_NoDispara"),
        FalloRegla::NoDispara { muestra: 0 }
    ));
    assert!(matches!(
        fallo("R_Salta"),
        FalloRegla::DisparaEnBenigno { muestra: 0 }
    ));
    assert!(matches!(fallo("R_Cara"), FalloRegla::ExcedePasos { .. }));
    assert!(matches!(
        fallo("R_Sigma"),
        FalloRegla::SinValidador(Tipo::Sigma)
    ));
    assert_eq!(roturas.len(), 5, "la buena no es una rotura");
}

#[test]
fn un_paquete_roto_firmado_saltandose_la_puerta_no_se_carga_en_el_equipo() {
    let lab = Lab::nuevo("roto-firmado");
    let (f, pk) = claves(7);
    let v = verificacion(&pk, EQUIPO);
    let mut a = Almacen::abrir(lab.path()).unwrap();

    let mut rota = regla("R_Rota");
    rota.fuente = b"rule R_Rota { strings: $a = ".to_vec();
    let m = Manifiesto {
        canal: CANAL.into(),
        epoca: 1,
        generado_ns: 0,
        anillo: canario(),
        escalera: Vec::new(),
        revierte_a: 0,
        entradas: vec![rota],
    };
    let firmado = firmar_a_mano(&f, &m, CTX_CONTENIDO);
    assert!(matches!(a.instalar(&firmado, &v), Err(ErrorCanal::Roto(_))));
    assert_eq!(a.estado().epoca_vista, 0);
    assert!(!lab.path().join("activo.aegc").exists());
}

#[test]
fn el_anillo_lo_decide_el_servidor_y_lo_comprueba_el_equipo() {
    let lab = Lab::nuevo("anillo");
    let (f, pk) = claves(8);
    let mut a = Almacen::abrir(lab.path()).unwrap();
    let fuera = verificacion(&pk, "maq:no-es-canario");
    let dentro = verificacion(&pk, EQUIPO);

    let mut h = Historial::nuevo();
    let e1 = preparar_en(1, canario(), vec![regla("R_Uno")], &h).unwrap();
    h.registrar(&e1).unwrap();
    let e1b = e1.firmar(&f).unwrap();

    // Un equipo que no es canario lo ignora sin mover su epoca.
    assert!(matches!(
        a.instalar(&e1b, &fuera),
        Err(ErrorCanal::FueraDeAnillo { epoca: 1, .. })
    ));
    assert_eq!(a.estado().epoca_vista, 0);
    a.instalar(&e1b, &dentro).unwrap();

    // Directo a la flota, sin escalera: no se publica.
    assert!(matches!(
        preparar_en(2, Anillo::Flota, vec![regla("R_Uno")], &h),
        Err(ErrorCanal::Estructura(_))
    ));
    // Con fallos en el canario: no se promociona.
    let v = Validadores::por_defecto();
    let porcentaje = Anillo::Porcentaje {
        puntos: CINCO_POR_CIENTO,
        sal: [9; 32],
    };
    assert!(promover(&h, 1, (50, 1), porcentaje.clone(), 2, 0, &v).is_err());

    // Canario sano -> 5 % -> flota.
    let e2 = promover(&h, 1, (50, 0), porcentaje, 2, 0, &v).unwrap();
    h.registrar(&e2).unwrap();
    let e3 = promover(&h, 2, (500, 0), Anillo::Flota, 3, 0, &v).unwrap();
    h.registrar(&e3).unwrap();
    assert_eq!(e3.manifiesto().escalera.len(), 2);
    // El 5 % puede o no incluir a este equipo; la flota, si.
    let _ = a.instalar(&e2.firmar(&f).unwrap(), &dentro);
    a.instalar(&e3.firmar(&f).unwrap(), &dentro).unwrap();
    assert_eq!(a.estado().epoca_vista, 3);
}

#[test]
fn el_equipo_desmiente_una_escalera_que_no_vivio() {
    let lab = Lab::nuevo("escalera-falsa");
    let (f, pk) = claves(9);
    let v = verificacion(&pk, EQUIPO);
    let mut a = Almacen::abrir(lab.path()).unwrap();
    a.instalar(&paquete(&f, 1, vec![regla("R_Uno")]), &v)
        .unwrap();

    // Un plano de control equivocado afirma que OTRO contenido paso por el
    // canario de la epoca 1. Este equipo estuvo alli y sabe que no.
    let m = Manifiesto {
        canal: CANAL.into(),
        epoca: 3,
        generado_ns: 0,
        anillo: Anillo::Flota,
        escalera: vec![
            Peldano {
                orden: 0,
                epoca: 1,
                sanos: 50,
                fallos: 0,
            },
            Peldano {
                orden: 1,
                epoca: 2,
                sanos: 500,
                fallos: 0,
            },
        ],
        revierte_a: 0,
        entradas: vec![regla("R_Otra")],
    };
    let firmado = firmar_a_mano(&f, &m, CTX_CONTENIDO);
    assert!(matches!(
        a.instalar(&firmado, &v),
        Err(ErrorCanal::Escalera(_))
    ));
    assert_eq!(a.estado().epoca_vista, 1);
}

#[test]
fn imponer_exige_numeros() {
    let lab = Lab::nuevo("imponer");
    let (f, pk) = claves(10);
    let v = verificacion(&pk, EQUIPO);
    let mut sin = regla("R_Impone");
    sin.modo = Modo::Imponer;
    assert!(matches!(
        preparar_en(1, canario(), vec![sin.clone()], &Historial::nuevo()),
        Err(ErrorCanal::Estructura(_))
    ));
    let mut con = sin;
    con.medicion = Medicion {
        muestras_benignas: MIN_MUESTRAS_IMPONER,
        falsos_positivos: 0,
    };
    let mut a = Almacen::abrir(lab.path()).unwrap();
    a.instalar(&paquete(&f, 1, vec![con]), &v).unwrap();
    assert_eq!(a.cargar(&v).unwrap().cuantas(Modo::Imponer), 1);
}

fn ajustes_firmados(
    f: &ClaveFirmaHibrida,
    epoca: u64,
    rebajas: &[(&str, Rebaja)],
    ctx: &[u8],
) -> Vec<u8> {
    let a = Ajustes {
        canal: CANAL.into(),
        epoca,
        rebajas: rebajas
            .iter()
            .map(|(id, r)| ((*id).to_string(), *r))
            .collect(),
    };
    let cuerpo = a.a_bytes();
    let firma = f.firmar(&cuerpo, ctx).unwrap().a_bytes();
    Sellado { cuerpo, firma }.a_bytes()
}

#[test]
fn apagado_individual_y_bajada_a_auditoria_sin_republicar() {
    let lab = Lab::nuevo("ajustes");
    let (f, pk) = claves(11);
    let v = verificacion(&pk, EQUIPO);
    let mut a = Almacen::abrir(lab.path()).unwrap();
    let mut impone = regla("R_A");
    impone.modo = Modo::Imponer;
    impone.medicion = Medicion {
        muestras_benignas: MIN_MUESTRAS_IMPONER,
        falsos_positivos: 0,
    };
    a.instalar(
        &paquete(&f, 1, vec![impone, regla("R_B"), regla("R_C")]),
        &v,
    )
    .unwrap();

    let aj = ajustes_firmados(
        &f,
        1,
        &[("R_A", Rebaja::Auditoria), ("R_B", Rebaja::Apagar)],
        CTX_AJUSTES,
    );
    assert_eq!(a.aplicar_ajustes(&aj, &v).unwrap(), 1);
    let c = a.cargar(&v).unwrap();
    assert_eq!(c.apagadas, vec!["R_B".to_string()]);
    assert_eq!(c.cuantas(Modo::Imponer), 0);
    assert_eq!(c.cuantas(Modo::Auditoria), 2);

    // Reponer los mismos ajustes: retroceso. Firmados como paquete: firma mala.
    assert!(matches!(
        a.aplicar_ajustes(&aj, &v),
        Err(ErrorCanal::Retroceso { .. })
    ));
    let otro_dominio = ajustes_firmados(&f, 2, &[], CTX_CONTENIDO);
    assert!(matches!(
        a.aplicar_ajustes(&otro_dominio, &v),
        Err(ErrorCanal::Firma(_))
    ));

    // Quitar los ajustes del disco no vuelve a encender lo apagado: no carga.
    std::fs::remove_file(lab.path().join("ajustes.aegs")).unwrap();
    assert!(a.cargar(&v).is_err());
}

#[test]
fn rollback_local_en_un_comando_sin_bajar_la_epoca() {
    let lab = Lab::nuevo("rollback-local");
    let (f, pk) = claves(12);
    let v = verificacion(&pk, EQUIPO);
    let mut a = Almacen::abrir(lab.path()).unwrap();
    let e1 = paquete(&f, 1, vec![regla("R_Uno")]);
    a.instalar(&e1, &v).unwrap();
    a.instalar(&paquete(&f, 2, vec![regla("R_Dos")]), &v)
        .unwrap();

    let r = a.revertir(&v).unwrap();
    assert_eq!(r.epoca_restaurada, 1);
    assert_eq!(r.epoca_vista, 2);
    let c = a.cargar(&v).unwrap();
    assert_eq!(c.epoca, 1);
    assert_eq!(c.epoca_vista, 2);
    assert!(lab.path().join("descartado.aegc").exists());

    // La epoca vista no bajo: el paquete viejo que llegue por la red sigue fuera.
    assert!(matches!(
        a.instalar(&e1, &v),
        Err(ErrorCanal::Retroceso { .. })
    ));
    // Un solo nivel.
    assert!(matches!(a.revertir(&v), Err(ErrorCanal::SinAnterior)));
}

#[test]
fn rollback_de_la_flota_en_un_comando() {
    let lab = Lab::nuevo("rollback-flota");
    let (f, pk) = claves(13);
    let v = verificacion(&pk, EQUIPO);
    let val = Validadores::por_defecto();
    let mut a = Almacen::abrir(lab.path()).unwrap();
    let mut h = Historial::nuevo();
    let porcentaje = Anillo::Porcentaje {
        puntos: CINCO_POR_CIENTO,
        sal: [3; 32],
    };

    // Contenido A sube la escalera (epocas 1-3); despues B (epocas 4-6).
    let mut epoca = 0;
    for contenido in [vec![regla("R_A")], vec![regla("R_B")]] {
        epoca += 1;
        let c = preparar_en(epoca, canario(), contenido, &h).unwrap();
        h.registrar(&c).unwrap();
        let _ = a.instalar(&c.firmar(&f).unwrap(), &v);
        epoca += 1;
        let p = promover(&h, epoca - 1, (50, 0), porcentaje.clone(), epoca, 0, &val).unwrap();
        h.registrar(&p).unwrap();
        let _ = a.instalar(&p.firmar(&f).unwrap(), &v);
        epoca += 1;
        let fl = promover(&h, epoca - 1, (500, 0), Anillo::Flota, epoca, 0, &val).unwrap();
        h.registrar(&fl).unwrap();
        a.instalar(&fl.firmar(&f).unwrap(), &v).unwrap();
    }
    assert_eq!(ids(&a, &v), vec!["R_B".to_string()]);

    // Una llamada: vuelve A a toda la flota con epoca nueva.
    let r = revertir(&h, 7, 0, &val).unwrap();
    assert_eq!(r.manifiesto().revierte_a, 3);
    assert_eq!(r.manifiesto().anillo, Anillo::Flota);
    a.instalar(&r.firmar(&f).unwrap(), &v).unwrap();
    assert_eq!(ids(&a, &v), vec!["R_A".to_string()]);
    assert_eq!(a.estado().epoca_vista, 7);
}

#[test]
fn un_corte_a_mitad_de_instalacion_se_recupera_del_anterior() {
    let lab = Lab::nuevo("corte");
    let (f, pk) = claves(14);
    let v = verificacion(&pk, EQUIPO);
    let mut a = Almacen::abrir(lab.path()).unwrap();
    a.instalar(&paquete(&f, 1, vec![regla("R_Uno")]), &v)
        .unwrap();

    // Lo que deja un corte tras los renombrados y antes del estado.
    let activo = lab.path().join("activo.aegc");
    std::fs::rename(&activo, lab.path().join("anterior.aegc")).unwrap();
    std::fs::write(&activo, paquete(&f, 2, vec![regla("R_Dos")])).unwrap();

    let c = Almacen::abrir(lab.path()).unwrap().cargar(&v).unwrap();
    assert!(c.recuperado_de_anterior);
    assert_eq!(c.epoca, 1);
}

#[test]
fn un_paquete_de_otro_canal_no_se_instala() {
    let lab = Lab::nuevo("canal");
    let (f, pk) = claves(15);
    let v = Verificacion::nueva(pk, "pruebas", EQUIPO, Validadores::por_defecto());
    let mut a = Almacen::abrir(lab.path()).unwrap();
    assert!(matches!(
        a.instalar(&paquete(&f, 1, vec![regla("R_Uno")]), &v),
        Err(ErrorCanal::OtroCanal { .. })
    ));
}
