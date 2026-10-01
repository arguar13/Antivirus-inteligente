//! PUERTA H-04: el quorum cuenta identidades AUTENTICADAS, no nombres declarados.
//!
//! El fallo que esta puerta impide que vuelva: el quorum de K testigos contaba
//! valores distintos de `Observacion::origen`, un campo que rellena el emisor, y
//! la firma del sobre ni se miraba. Un solo equipo comprometido declaraba `e1`,
//! `e2` y `e3` y cerraba el quorum el solo.
//!
//! Aqui todo se hace con claves hibridas Ed25519 + ML-DSA-65 DE VERDAD, por la
//! misma razon que en `tests/circuito.rs`: los ataques interesantes —copiar una
//! credencial autentica de la red, reinyectar una observacion autentica fuera de
//! su ventana— solo se pueden construir con firmas buenas. Con firmas falsas la
//! prueba demostraria lo facil, no lo que importa.
//!
//! Cada prueba es un ataque concreto y falla si el ataque vuelve a funcionar.

use aegis_pqc::firma_hibrida::ClaveFirmaHibrida;
use aegis_swarm::credencial::{Credencial, CTX_CREDENCIAL, MAX_VIGENCIA_SEG};
use aegis_swarm::enjambre::{
    ConfigEnjambre, Enjambre, EstadoEnlace, MotivoDescarte, Salida, SALTOS_POR_DEFECTO,
    TASA_POR_DEFECTO,
};
use aegis_swarm::mensaje::{Sobre, TipoMensaje};
use aegis_swarm::observacion::{self, Observacion, CTX_OBSERVACION};
use aegis_swarm::orden::{Accion, Orden, CTX_ORDEN};
use aegis_sync::ioc::{Ioc, IocKind};
use aegis_update::signature::ClaveActualizacion;

/// Momento de referencia de las pruebas, en segundos Unix.
const T0: u64 = 1_000_000;

/// Ventana de corroboro de las pruebas.
const VENTANA: u64 = 3600;

/// Un plano de control: firma credenciales al matricular. Su clave privada no
/// esta en ningun agente.
struct Plano {
    clave: ClaveFirmaHibrida,
}

/// Un agente matriculado: su clave privada y la credencial que le dieron.
struct Par {
    clave: ClaveFirmaHibrida,
    credencial: Credencial,
}

impl Plano {
    fn nuevo(semilla: u8) -> Plano {
        Plano {
            clave: ClaveFirmaHibrida::desde_semillas(&[semilla; 32], &[semilla ^ 0xA5; 32]),
        }
    }

    fn clave_publica(&self) -> ClaveActualizacion {
        ClaveActualizacion::Hibrida(Box::new(self.clave.clave_verificacion()))
    }

    fn matricular_con_vigencia(&self, cn: &str, semilla: u8, desde: u64, hasta: u64) -> Par {
        let clave = ClaveFirmaHibrida::desde_semillas(&[semilla; 32], &[semilla ^ 0x5A; 32]);
        let mut credencial = Credencial {
            cn: cn.to_string(),
            clave_par: clave.clave_verificacion().a_bytes().to_vec(),
            valida_desde: desde,
            valida_hasta: hasta,
            firma_plano: Vec::new(),
        };
        credencial.firma_plano = self
            .clave
            .firmar(&credencial.bytes_firmados(), CTX_CREDENCIAL)
            .expect("el plano de control firma")
            .a_bytes();
        Par { clave, credencial }
    }

    fn matricular(&self, cn: &str, semilla: u8) -> Par {
        self.matricular_con_vigencia(cn, semilla, T0 - 86_400, T0 + 7 * 86_400)
    }
}

fn obs(origen: &str, valor: &str, vista_en: u64) -> Observacion {
    Observacion {
        origen: origen.to_string(),
        indicador: Ioc {
            kind: IocKind::FileSha256,
            value: valor.to_string(),
        },
        tecnica: "T1486".to_string(),
        confianza: 90,
        vista_en,
    }
}

impl Par {
    /// Firma `o` con la clave de este par y lo empaqueta con `credencial`, que
    /// normalmente es la suya y en los ataques no.
    fn sobre_con(&self, credencial: &Credencial, o: &Observacion) -> Vec<u8> {
        let firma = self
            .clave
            .firmar(&o.bytes_firmados(credencial), CTX_OBSERVACION)
            .expect("el par firma")
            .a_bytes();
        Sobre {
            tipo: TipoMensaje::Observacion,
            saltos: 3,
            cuerpo: observacion::empaquetar(credencial, o),
            firma,
        }
        .a_bytes()
    }

    /// Una observacion honesta: declara su propio CN.
    fn observa(&self, valor: &str, vista_en: u64) -> Vec<u8> {
        self.sobre_con(&self.credencial, &obs(&self.credencial.cn, valor, vista_en))
    }
}

fn agente(plano: &Plano) -> Enjambre {
    let mut e = Enjambre::nuevo(ConfigEnjambre {
        clave_plano_control: plano.clave_publica(),
        saltos: SALTOS_POR_DEFECTO,
        tasa: TASA_POR_DEFECTO,
        umbral_corroboro: 3,
        ventana_corroboro_seg: VENTANA,
    });
    e.declarar_enlace(EstadoEnlace::Aislado);
    e
}

fn corroboro(s: &[Salida]) -> Option<Vec<String>> {
    s.iter().find_map(|x| match x {
        Salida::Corroborado { testigos, .. } => Some(testigos.clone()),
        _ => None,
    })
}

fn descartado_por(s: &[Salida], m: MotivoDescarte) -> bool {
    matches!(s.first(), Some(Salida::Descartado(x)) if *x == m)
}

/// EL CONTROL POSITIVO: sin el, las puertas de abajo pasarian con un quorum que
/// no cierra nunca. Tres equipos matriculados distintos, cada uno entregado por
/// un vecino distinto, corroboran una vez.
#[test]
fn tres_equipos_matriculados_distintos_corroboran_sin_plano_de_control() {
    let plano = Plano::nuevo(42);
    let pares = [
        plano.matricular("wks-11", 11),
        plano.matricular("wks-24", 24),
        plano.matricular("wks-37", 37),
    ];
    let mut a = agente(&plano);

    let mut corroboros = Vec::new();
    for (i, par) in pares.iter().enumerate() {
        let vecino = format!("vecino-{i}");
        let s = a.recibir(&vecino, &par.observa("hash-malo", T0), T0);
        assert!(
            s.iter().any(|x| matches!(x, Salida::Reenviar(_))),
            "una observacion autentica se reenvia: {s:?}"
        );
        corroboros.extend(corroboro(&s));
    }
    assert_eq!(corroboros, vec![vec!["wks-11", "wks-24", "wks-37"]]);
}

/// PUERTA H-04, el ataque tal cual: un nodo con UNA credencial declara N
/// identidades. Cada una es una suplantacion con firma buena —el culpable queda
/// identificado— y el nodo no pasa de un testigo.
#[test]
fn puerta_h04_un_nodo_con_n_identidades_declaradas_no_alcanza_el_quorum() {
    let plano = Plano::nuevo(42);
    let comprometido = plano.matricular("wks-66", 66);
    let mut a = agente(&plano);

    let declaradas = ["wks-11", "wks-24", "wks-37", "wks-48", "wks-59"];
    for nombre in declaradas {
        let o = obs(nombre, "hash-malo", T0);
        let s = a.recibir(
            "vecino",
            &comprometido.sobre_con(&comprometido.credencial, &o),
            T0,
        );
        assert!(
            descartado_por(&s, MotivoDescarte::Suplantacion),
            "firmar como {nombre} con la credencial de wks-66 no puede contar: {s:?}"
        );
        assert!(
            !s.iter().any(|x| matches!(x, Salida::Reenviar(_))),
            "una suplantacion no se reenvia"
        );
    }
    let s = a.recibir("vecino", &comprometido.observa("hash-malo", T0), T0);
    assert_eq!(corroboro(&s), None, "un solo nodo cerro el quorum");
    assert_eq!(
        a.contadores().de(MotivoDescarte::Suplantacion),
        declaradas.len() as u64
    );
}

/// PUERTA H-04, la variante que no deja rastro de suplantacion: el atacante no
/// firma con su credencial, se ACUÑA las suyas. Credenciales para tres CN
/// distintos, bien formadas y firmadas... por una clave que no es la del plano
/// de control. No dan ni un testigo.
#[test]
fn puerta_h04_credenciales_que_no_firmo_el_plano_de_control_no_dan_testigos() {
    let plano = Plano::nuevo(42);
    let falso = Plano::nuevo(13);
    let mut a = agente(&plano);

    for (i, nombre) in ["wks-11", "wks-24", "wks-37"].iter().enumerate() {
        let sybil = falso.matricular(nombre, 100 + u8::try_from(i).expect("cabe"));
        let s = a.recibir("atacante", &sybil.observa("hash-malo", T0), T0);
        assert!(
            descartado_por(&s, MotivoDescarte::FirmaInvalida),
            "una credencial acuñada fuera del plano de control dio testigo: {s:?}"
        );
        assert_eq!(corroboro(&s), None);
    }
}

/// Las credenciales viajan en claro: cualquiera las copia de la red. Copiar la
/// de un equipo honesto y firmar con la clave propia no sirve, porque la firma
/// se verifica con la clave que nombra la credencial.
#[test]
fn una_credencial_ajena_copiada_de_la_red_no_sirve_sin_su_clave_privada() {
    let plano = Plano::nuevo(42);
    let honesto = plano.matricular("wks-11", 11);
    let comprometido = plano.matricular("wks-66", 66);
    let mut a = agente(&plano);

    let o = obs("wks-11", "hash-malo", T0);
    let s = a.recibir(
        "vecino",
        &comprometido.sobre_con(&honesto.credencial, &o),
        T0,
    );
    assert!(descartado_por(&s, MotivoDescarte::FirmaInvalida), "{s:?}");
}

/// PUERTA H-04, la reinyeccion: el atacante graba tres observaciones AUTENTICAS
/// de tres equipos distintos y las suelta mas tarde, fuera de su ventana. La
/// firma es buena y no importa: `vista_en` va firmado y ya no es «ahora». Y
/// rejuvenecerlo rompe la firma.
#[test]
fn puerta_h04_un_aviso_reenviado_fuera_de_su_ventana_no_cuenta() {
    let plano = Plano::nuevo(42);
    let grabadas: Vec<Vec<u8>> = [("wks-11", 11), ("wks-24", 24), ("wks-37", 37)]
        .iter()
        .map(|(cn, s)| plano.matricular(cn, *s).observa("hash-viejo", T0))
        .collect();

    // Un receptor que nunca las vio (recien arrancado: la deduplicacion no lo
    // salva), mas alla de la ventana.
    let tarde = T0 + VENTANA + 1;
    let mut a = agente(&plano);
    for g in &grabadas {
        let s = a.recibir("atacante", g, tarde);
        assert!(
            descartado_por(&s, MotivoDescarte::Caducado),
            "una observacion de fuera de la ventana conto: {s:?}"
        );
        assert!(!s.iter().any(|x| matches!(x, Salida::Reenviar(_))));
    }

    // Y no se puede rejuvenecer: cambiar `vista_en` rompe la firma del par.
    let mut sobre = Sobre::desde_bytes(&grabadas[0]).expect("valido");
    let (credencial, mut o) = observacion::desempaquetar(&sobre.cuerpo).expect("valido");
    o.vista_en = tarde;
    sobre.cuerpo = observacion::empaquetar(&credencial, &o);
    let s = a.recibir("atacante", &sobre.a_bytes(), tarde);
    assert!(descartado_por(&s, MotivoDescarte::FirmaInvalida), "{s:?}");
}

/// Dentro de la ventana, reinyectar la observacion autentica de un testigo que
/// ya conto no suma: es el mismo testigo.
#[test]
fn reinyectar_dentro_de_la_ventana_no_multiplica_a_un_testigo() {
    let plano = Plano::nuevo(42);
    let e1 = plano.matricular("wks-11", 11);
    let e2 = plano.matricular("wks-24", 24);
    let mut a = agente(&plano);

    // El mismo testigo, con tres observaciones autenticas distintas en el tiempo.
    for t in [T0, T0 + 10, T0 + 20] {
        let s = a.recibir("atacante", &e1.observa("hash-malo", t), t);
        assert_eq!(corroboro(&s), None);
    }
    let s = a.recibir("vecino", &e2.observa("hash-malo", T0 + 30), T0 + 30);
    assert_eq!(
        corroboro(&s),
        None,
        "dos testigos cerraron un quorum de tres"
    );
}

/// Una credencial caducada no da testigo, aunque su firma sea buena: es la
/// epoca de la identidad, y lo que acota el valor de una credencial robada.
#[test]
fn una_credencial_caducada_no_da_testigo() {
    let plano = Plano::nuevo(42);
    let viejo = plano.matricular_con_vigencia("wks-11", 11, T0 - 10 * 86_400, T0 - 1);
    let mut a = agente(&plano);
    let s = a.recibir("vecino", &viejo.observa("hash-malo", T0), T0);
    assert!(descartado_por(&s, MotivoDescarte::Caducado), "{s:?}");
}

/// Y una credencial «eterna» ni se considera, aunque la firme el plano de
/// control: una vigencia sin tope convertiria un equipo robado en un testigo
/// para siempre.
#[test]
fn una_credencial_de_vigencia_desmesurada_se_rechaza() {
    let plano = Plano::nuevo(42);
    let eterno = plano.matricular_con_vigencia("wks-11", 11, T0 - 1, T0 + MAX_VIGENCIA_SEG);
    let mut a = agente(&plano);
    let s = a.recibir("vecino", &eterno.observa("hash-malo", T0), T0);
    assert!(descartado_por(&s, MotivoDescarte::Malformado), "{s:?}");
}

/// INVARIANTE 10. La credencial da voz para aportar EVIDENCIA, no autoridad:
/// una orden firmada con la clave de un par no se aplica, y levantar un
/// aislamiento no viaja por el enjambre ni firmado por nadie.
#[test]
fn la_credencial_de_un_par_no_da_autoridad_para_ordenar() {
    let plano = Plano::nuevo(42);
    let par = plano.matricular("wks-11", 11);
    let mut a = agente(&plano);

    for (accion, motivo) in [
        (Accion::AislarRed, MotivoDescarte::FirmaInvalida),
        (Accion::LevantarAislamiento, MotivoDescarte::ClaseProhibida),
    ] {
        let o = Orden {
            accion,
            sujeto: "wks-24".to_string(),
            incidente: "inc-2026-0042".to_string(),
            epoca: 1,
            emitida_en: T0,
            caduca_en: T0 + 3600,
        };
        let firma = par
            .clave
            .firmar(&o.bytes_firmados(), CTX_ORDEN)
            .expect("firma")
            .a_bytes();
        let sobre = Sobre {
            tipo: TipoMensaje::Orden,
            saltos: 3,
            cuerpo: o.a_bytes(),
            firma,
        }
        .a_bytes();
        let s = a.recibir("vecino", &sobre, T0);
        assert!(descartado_por(&s, motivo), "{}: {s:?}", accion.nombre());
        assert!(!s.iter().any(|x| matches!(x, Salida::AplicarOrden(_))));
    }
}
