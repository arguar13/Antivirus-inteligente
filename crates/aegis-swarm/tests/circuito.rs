//! El circuito del enjambre con **criptografía de verdad**.
//!
//! Las pruebas unitarias del crate ejercen las cotas que no dependen de firmas
//! (tasa, deduplicación, saltos, memoria). Estas ejercen lo que sí depende, y lo
//! hacen con claves híbridas Ed25519 + ML-DSA-65 auténticas, firmando y
//! verificando de verdad. Hay una razón concreta para no simularlo: el ataque
//! central de esta fase —**reproducir una orden antigua y AUTÉNTICA durante el
//! corte**— no se puede demostrar con una firma falsa, porque la gracia del
//! ataque es justamente que la firma es buena.
//!
//! Vive en un crate de integración aparte porque necesita `aegis-pqc` como
//! dependencia de desarrollo, y el crate del enjambre no debe arrastrarla en
//! producción: quien firma es el plano de control, el agente sólo verifica.

use aegis_pqc::firma_hibrida::ClaveFirmaHibrida;
use aegis_swarm::artefacto::{trocear, ClaseArtefacto, Descriptor, CTX_ARTEFACTO};
use aegis_swarm::enjambre::{
    ConfigEnjambre, Enjambre, EstadoEnlace, MotivoDescarte, Salida, SALTOS_POR_DEFECTO,
    TASA_POR_DEFECTO,
};
use aegis_swarm::mensaje::{Sobre, TipoMensaje};
use aegis_swarm::orden::{Accion, Orden, CTX_ORDEN};
use aegis_update::signature::ClaveActualizacion;

/// El plano de control: la única entidad que puede firmar órdenes. Su clave
/// privada NO está en ningún agente, y por eso vive sólo dentro de la prueba.
struct PlanoDeControl {
    clave: ClaveFirmaHibrida,
}

impl PlanoDeControl {
    fn nuevo() -> PlanoDeControl {
        PlanoDeControl {
            clave: ClaveFirmaHibrida::desde_semillas(&[42u8; 32], &[99u8; 32]),
        }
    }

    /// Lo que se le reparte al agente: sólo la parte pública.
    fn clave_publica(&self) -> ClaveActualizacion {
        ClaveActualizacion::Hibrida(Box::new(self.clave.clave_verificacion()))
    }

    fn firmar(&self, bytes: &[u8], ctx: &[u8]) -> Vec<u8> {
        self.clave
            .firmar(bytes, ctx)
            .expect("el plano de control firma")
            .a_bytes()
            .to_vec()
    }

    fn sobre_de_orden(&self, o: &Orden, saltos: u8) -> Vec<u8> {
        let firma = self.firmar(&o.bytes_firmados(), CTX_ORDEN);
        Sobre {
            tipo: TipoMensaje::Orden,
            saltos,
            cuerpo: o.a_bytes(),
            firma,
        }
        .a_bytes()
    }
}

fn agente(pc: &PlanoDeControl) -> Enjambre {
    Enjambre::nuevo(ConfigEnjambre {
        clave_plano_control: pc.clave_publica(),
        saltos: SALTOS_POR_DEFECTO,
        tasa: TASA_POR_DEFECTO,
        umbral_corroboro: 3,
        ventana_corroboro_seg: 3600,
    })
}

fn orden(accion: Accion, sujeto: &str, epoca: u64, ahora: u64) -> Orden {
    Orden {
        accion,
        sujeto: sujeto.to_string(),
        incidente: "inc-2026-0042".to_string(),
        epoca,
        emitida_en: ahora,
        caduca_en: ahora + 3600,
    }
}

/// EL CASO QUE JUSTIFICA LA FASE: el plano de control emite una orden de
/// aislamiento, el enlace se cae, y la orden llega igual por el enjambre.
#[test]
fn una_orden_firmada_llega_por_el_enjambre_con_el_plano_de_control_caido() {
    let pc = PlanoDeControl::nuevo();
    let mut a = agente(&pc);
    a.declarar_enlace(EstadoEnlace::Aislado);

    let o = orden(Accion::AislarRed, "endpoint-17", 1, 1_000_000);
    let salidas = a.recibir("vecino", &pc.sobre_de_orden(&o, 3), 1_000_000);

    let aplicada = salidas
        .iter()
        .find_map(|s| match s {
            Salida::AplicarOrden(o) => Some(o.clone()),
            _ => None,
        })
        .expect("la orden firmada tiene que aplicarse aunque no haya consola");
    assert_eq!(*aplicada, o);

    // Y se reenvía, que es lo que hace que llegue al resto de la sede aislada.
    assert!(salidas.iter().any(|s| matches!(s, Salida::Reenviar(_))));
}

/// EL ATAQUE CENTRAL DE LA FASE. El atacante graba una orden legítima, provoca
/// el corte y la vuelve a soltar. **La firma es auténtica**: la criptografía no
/// puede distinguirla, y por eso hace falta la época monótona.
#[test]
fn reproducir_una_orden_antigua_y_autentica_no_cuela() {
    let pc = PlanoDeControl::nuevo();
    let mut a = agente(&pc);

    // El plano de control emitió dos órdenes sobre el mismo sujeto.
    let vieja = orden(Accion::AislarRed, "endpoint-17", 1, 1_000_000);
    let nueva = orden(Accion::AislarRed, "endpoint-17", 2, 1_000_100);
    let sobre_viejo = pc.sobre_de_orden(&vieja, 3);

    // Primero llega la nueva.
    let s = a.recibir("vecino", &pc.sobre_de_orden(&nueva, 3), 1_000_100);
    assert!(s.iter().any(|x| matches!(x, Salida::AplicarOrden(_))));

    // El atacante reproduce la vieja. Su firma VERIFICA: es auténtica.
    pc.clave
        .clave_verificacion()
        .verificar(
            &vieja.bytes_firmados(),
            CTX_ORDEN,
            &aegis_pqc::firma_hibrida::FirmaHibrida::desde_bytes(
                &pc.firmar(&vieja.bytes_firmados(), CTX_ORDEN),
            )
            .expect("firma bien formada"),
        )
        .then_some(())
        .expect("la firma de la orden vieja es autentica, ese es el problema");

    let s = a.recibir("atacante", &sobre_viejo, 1_000_200);
    assert!(
        matches!(
            s.first(),
            Some(Salida::Descartado(MotivoDescarte::Reproduccion))
        ),
        "una epoca ya superada es una reproduccion: {s:?}"
    );
}

/// La época es **por sujeto**: aislar al equipo 18 no puede quedar bloqueado
/// porque ya se aisló al 17 con una época mayor.
#[test]
fn la_epoca_de_un_sujeto_no_bloquea_a_otro() {
    let pc = PlanoDeControl::nuevo();
    let mut a = agente(&pc);

    let alta = orden(Accion::AislarRed, "endpoint-17", 50, 1_000_000);
    a.recibir("v", &pc.sobre_de_orden(&alta, 3), 1_000_000);

    let baja_otro = orden(Accion::AislarRed, "endpoint-18", 1, 1_000_000);
    let s = a.recibir("v", &pc.sobre_de_orden(&baja_otro, 3), 1_000_000);
    assert!(
        s.iter().any(|x| matches!(x, Salida::AplicarOrden(_))),
        "el otro sujeto tiene su propia cuenta de epocas: {s:?}"
    );
}

/// Una orden firmada por CUALQUIER OTRA clave no vale. Es el caso del atacante
/// que compromete un endpoint y fabrica sus propias órdenes.
#[test]
fn un_endpoint_comprometido_no_puede_fabricar_ordenes() {
    let pc = PlanoDeControl::nuevo();
    let atacante = PlanoDeControl {
        clave: ClaveFirmaHibrida::desde_semillas(&[1u8; 32], &[2u8; 32]),
    };
    let mut a = agente(&pc);

    let o = orden(Accion::AislarRed, "el-salto-del-soc", 1, 1_000_000);
    let s = a.recibir("comprometido", &atacante.sobre_de_orden(&o, 3), 1_000_000);
    assert!(
        matches!(
            s.first(),
            Some(Salida::Descartado(MotivoDescarte::FirmaInvalida))
        ),
        "sin la clave del plano de control no se manda: {s:?}"
    );
    assert!(!s.iter().any(|x| matches!(x, Salida::AplicarOrden(_))));
}

/// Alterar un solo byte del cuerpo invalida la firma. Cubre el caso del par
/// intermedio que reenvía y aprovecha para cambiar el sujeto de la orden.
#[test]
fn un_reenviador_no_puede_cambiar_el_sujeto_de_una_orden_en_transito() {
    let pc = PlanoDeControl::nuevo();
    let mut a = agente(&pc);

    let o = orden(Accion::AislarRed, "endpoint-17", 1, 1_000_000);
    let bytes = pc.sobre_de_orden(&o, 3);
    let mut sobre = Sobre::desde_bytes(&bytes).expect("valido");

    // El reenviador cambia el sujeto: quiere aislar otro equipo.
    let mut manipulada = o.clone();
    manipulada.sujeto = "el-salto-del-soc".to_string();
    sobre.cuerpo = manipulada.a_bytes();

    let s = a.recibir("reenviador", &sobre.a_bytes(), 1_000_000);
    assert!(
        matches!(
            s.first(),
            Some(Salida::Descartado(MotivoDescarte::FirmaInvalida))
        ),
        "cambiar el cuerpo rompe la firma: {s:?}"
    );
}

/// Los saltos van FUERA de lo firmado a propósito —cada reenvío los decrementa—,
/// así que tocarlos no invalida la firma. Esta prueba fija que eso es inocuo:
/// lo único que un atacante consigue subiéndolos es que se reenvíe más, y contra
/// eso están la deduplicación y el límite por par.
#[test]
fn tocar_los_saltos_no_invalida_la_firma_y_es_inocuo() {
    let pc = PlanoDeControl::nuevo();
    let mut a = agente(&pc);

    let o = orden(Accion::AislarRed, "endpoint-17", 1, 1_000_000);
    let mut sobre = Sobre::desde_bytes(&pc.sobre_de_orden(&o, 3)).expect("valido");
    sobre.saltos = 250;

    let s = a.recibir("v", &sobre.a_bytes(), 1_000_000);
    assert!(
        s.iter().any(|x| matches!(x, Salida::AplicarOrden(_))),
        "los saltos no entran en la firma"
    );

    // Pero el mismo mensaje no vuelve a procesarse: la deduplicación lo corta.
    let s = a.recibir("v", &sobre.a_bytes(), 1_000_000);
    assert!(matches!(
        s.first(),
        Some(Salida::Descartado(MotivoDescarte::Duplicado))
    ));
}

/// LA REGLA DE CLASE, con firma perfecta del plano de control: levantar el
/// aislamiento no viaja por el enjambre ni con la firma buena.
#[test]
fn levantar_el_aislamiento_no_viaja_ni_con_la_firma_del_plano_de_control() {
    let pc = PlanoDeControl::nuevo();
    let mut a = agente(&pc);

    for accion in [
        Accion::LevantarAislamiento,
        Accion::DesactivarRegla,
        Accion::DegradarProteccion,
    ] {
        let o = orden(accion, "endpoint-17", 1, 1_000_000);
        let s = a.recibir("v", &pc.sobre_de_orden(&o, 3), 1_000_000);
        assert!(
            matches!(
                s.first(),
                Some(Salida::Descartado(MotivoDescarte::ClaseProhibida))
            ),
            "{} no puede viajar por el enjambre: {s:?}",
            accion.nombre()
        );
    }
}

/// Una orden caducada no se aplica aunque su firma sea buena: acota la ventana
/// en la que una orden grabada sigue sirviendo de algo.
#[test]
fn una_orden_caducada_no_se_aplica() {
    let pc = PlanoDeControl::nuevo();
    let mut a = agente(&pc);

    let o = orden(Accion::AislarRed, "endpoint-17", 1, 1_000_000);
    let s = a.recibir("v", &pc.sobre_de_orden(&o, 3), 1_000_000 + 7200);
    assert!(
        matches!(
            s.first(),
            Some(Salida::Descartado(MotivoDescarte::Caducado))
        ),
        "{s:?}"
    );
}

/// Un paquete de reglas YARA firmado viaja entero por trozos y llega verificado.
#[test]
fn un_paquete_de_reglas_yara_firmado_llega_completo_y_verificado() {
    let pc = PlanoDeControl::nuevo();
    let mut a = agente(&pc);

    let reglas: Vec<u8> = (0..300)
        .flat_map(|i| {
            format!("rule aegis_{i} {{ strings: $a = \"c2-{i}\" condition: $a }}\n").into_bytes()
        })
        .collect();
    let d = Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "flota-v7", &reglas, 1024)
        .expect("descriptor");
    assert!(d.trozos() > 3, "el caso interesante tiene varios trozos");

    let sobre_desc = Sobre {
        tipo: TipoMensaje::DescriptorArtefacto,
        saltos: 3,
        cuerpo: d.a_bytes(),
        firma: pc.firmar(&d.bytes_firmados(), CTX_ARTEFACTO),
    }
    .a_bytes();

    let s = a.recibir("v", &sobre_desc, 1_000_000);
    let pedidos = s
        .iter()
        .find_map(|x| match x {
            Salida::PedirTrozos { indices, .. } => Some(indices.clone()),
            _ => None,
        })
        .expect("el descriptor firmado abre el reensamblado y pide los trozos");
    assert_eq!(pedidos.len(), d.trozos());

    let mut listo = None;
    for t in trocear(&d, &reglas) {
        let sobre = Sobre {
            tipo: TipoMensaje::TrozoArtefacto,
            saltos: 3,
            cuerpo: t.a_bytes(),
            firma: Vec::new(),
        }
        .a_bytes();
        for salida in a.recibir("v", &sobre, 1_000_000) {
            if let Salida::ArtefactoListo {
                descriptor,
                contenido,
            } = salida
            {
                listo = Some((descriptor, contenido));
            }
        }
    }
    let (descriptor, contenido) = listo.expect("el artefacto tiene que completarse");
    assert_eq!(contenido, reglas);
    assert_eq!(descriptor.nombre, "flota-v7");
    assert_eq!(
        a.reensamblados_en_curso(),
        0,
        "la ranura se libera al cerrar"
    );
}

/// Un descriptor SIN firma válida no abre ni una ranura de reensamblado: si la
/// abriera, cualquier par agotaría las ranuras gratis y el paquete de reglas de
/// verdad se quedaría sin sitio.
#[test]
fn un_descriptor_sin_firma_valida_no_abre_ranura() {
    let pc = PlanoDeControl::nuevo();
    let mut a = agente(&pc);

    let d = Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "falso", b"contenido", 4)
        .expect("descriptor");
    let sobre = Sobre {
        tipo: TipoMensaje::DescriptorArtefacto,
        saltos: 3,
        cuerpo: d.a_bytes(),
        firma: vec![0u8; 3373],
    }
    .a_bytes();

    let s = a.recibir("atacante", &sobre, 1_000_000);
    assert!(matches!(
        s.first(),
        Some(Salida::Descartado(MotivoDescarte::FirmaInvalida))
    ));
    assert_eq!(a.reensamblados_en_curso(), 0);
}

/// Un trozo envenenado de un artefacto firmado se rechaza, y el artefacto no se
/// da por bueno: el atacante no puede colar una regla YARA modificada.
#[test]
fn un_trozo_envenenado_no_contamina_un_artefacto_firmado() {
    let pc = PlanoDeControl::nuevo();
    let mut a = agente(&pc);

    let reglas = b"rule buena { condition: true }\nrule otra { condition: false }\n".to_vec();
    let d = Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "v1", &reglas, 16)
        .expect("descriptor");
    let sobre_desc = Sobre {
        tipo: TipoMensaje::DescriptorArtefacto,
        saltos: 3,
        cuerpo: d.a_bytes(),
        firma: pc.firmar(&d.bytes_firmados(), CTX_ARTEFACTO),
    }
    .a_bytes();
    a.recibir("v", &sobre_desc, 1_000_000);

    let mut trozos = trocear(&d, &reglas);
    trozos[1].datos[0] ^= 0xFF;

    let mut rechazados = 0;
    let mut completado = false;
    for t in &trozos {
        let sobre = Sobre {
            tipo: TipoMensaje::TrozoArtefacto,
            saltos: 3,
            cuerpo: t.a_bytes(),
            firma: Vec::new(),
        }
        .a_bytes();
        for salida in a.recibir("atacante", &sobre, 1_000_000) {
            match salida {
                Salida::Descartado(MotivoDescarte::TrozoInvalido) => rechazados += 1,
                Salida::ArtefactoListo { .. } => completado = true,
                _ => {}
            }
        }
    }
    assert_eq!(rechazados, 1, "solo el envenenado");
    assert!(
        !completado,
        "un artefacto con un trozo malo no se da por bueno"
    );
}
