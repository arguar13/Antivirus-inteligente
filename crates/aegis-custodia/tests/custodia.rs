//! La custodia de extremo a extremo, sobre evidencia real de esta maquina.
//!
//! Las pruebas unitarias de cada modulo comprueban su pieza. Estas comprueban lo
//! unico que le importa a quien tiene que defender la prueba: que un artefacto
//! de verdad, recogido de esta maquina, recorra el camino completo —recogida,
//! transferencia, archivo, acceso— y que cada forma conocida de manipularlo se
//! detecte.
//!
//! La evidencia no es inventada: son los bytes reales de `/proc/self/maps` y del
//! binario de esta propia prueba. Un artefacto de mentira comprueba la
//! aritmetica de la firma; uno real comprueba tambien que el camino funciona con
//! lo que de verdad se recoge, que es donde aparecen los tamanos raros, los
//! bytes no imprimibles y los ficheros que cambian mientras se leen.

use aegis_custodia::cadena::Claveros;
use aegis_custodia::{
    Ausencia, CadenaDeCustodia, Clase, ConjuntoDeFlota, CustodiaError, LimiteDeLaPrueba, Marca,
    Paso, Pieza, Procedencia, Sello, Veredicto,
};
use aegis_pqc::firma_hibrida::ClaveFirmaHibrida;
use aegis_prueba::{omitir, Requisito};

/// Evidencia real: el mapa de memoria de este mismo proceso.
fn evidencia_real() -> Vec<u8> {
    std::fs::read("/proc/self/maps").expect("/proc/self/maps siempre se puede leer")
}

fn clave() -> ClaveFirmaHibrida {
    ClaveFirmaHibrida::generar_aleatorio().expect("generar clave")
}

fn procedencia(endpoint: &str, agente: &str, clase: Clase) -> Procedencia {
    Procedencia {
        caso: "CASO-2026-0042".into(),
        endpoint: endpoint.into(),
        agente: agente.into(),
        version_agente: env!("CARGO_PKG_VERSION").into(),
        clase,
        motivo: "el motor conductual marco el proceso".into(),
        tecnicas: vec!["T1055".into(), "T1620".into()],
        recogido: Marca::ahora(),
    }
}

// ---------------------------------------------------------------------------
// El camino completo
// ---------------------------------------------------------------------------

#[test]
fn una_evidencia_real_recorre_las_cuatro_manos_y_sigue_probando_quien_la_toco() {
    let bytes = evidencia_real();
    assert!(
        bytes.len() > 200,
        "el mapa de memoria de un proceso vivo no es trivial: {} bytes",
        bytes.len()
    );

    let agente = clave();
    let plano = clave();
    let almacen = clave();
    let analista = clave();

    // 1. El endpoint recoge y sella en el momento.
    let sello = Sello::sellar(
        &bytes,
        procedencia("endpoint-7", "agente-7", Clase::Memoria),
        &agente,
    )
    .unwrap();
    let mut cadena = CadenaDeCustodia::anclada_en(&sello);
    cadena
        .anadir(
            Paso::Recogida,
            "agente-7",
            "regiones del proceso 4711, disparada por el motor conductual",
            &agente,
        )
        .unwrap();

    // 2. Viaja al plano de control.
    cadena
        .anadir(
            Paso::Transferencia,
            "plano-de-control",
            "por el canal mTLS de la flota",
            &plano,
        )
        .unwrap();

    // 3. Se archiva.
    cadena
        .anadir(
            Paso::Archivo,
            "almacen-de-evidencia",
            "cifrado en reposo, plazo de conservacion 7 anos",
            &almacen,
        )
        .unwrap();

    // 4. Un analista la abre.
    cadena
        .anadir(
            Paso::Acceso,
            "analista-3",
            "triaje inicial del caso CASO-2026-0042",
            &analista,
        )
        .unwrap();

    let registro = Claveros::nuevo()
        .con("agente-7", agente.clave_verificacion())
        .con("plano-de-control", plano.clave_verificacion())
        .con("almacen-de-evidencia", almacen.clave_verificacion())
        .con("analista-3", analista.clave_verificacion());

    let v = Veredicto::de(&bytes, &sello, &cadena, &registro);
    assert!(v.intacta, "motivo: {:?}", v.motivo);
    assert_eq!(v.recorrido.len(), 4, "las cuatro manos constan");
    assert_eq!(v.recorrido[0].paso, Paso::Recogida);
    assert_eq!(v.recorrido[3].actor, "analista-3");
    assert!(
        v.recorrido.iter().all(|p| p.cuando.is_some()),
        "cada paso lleva su hora"
    );
    assert!(v.saltos_de_reloj.is_empty(), "sin saltos de reloj");

    // Y aun asi, el veredicto dice lo que no prueba.
    assert!(
        !v.no_demuestra.is_empty(),
        "un veredicto intacto tambien tiene limites, y se listan"
    );
    assert!(v.no_demuestra.contains(&LimiteDeLaPrueba::ClaveNoEsPersona));
}

// ---------------------------------------------------------------------------
// Cada forma conocida de manipular la evidencia
// ---------------------------------------------------------------------------

/// Monta el caso base y devuelve todo lo necesario para manipularlo.
fn caso_base() -> (
    Vec<u8>,
    Sello,
    CadenaDeCustodia,
    Claveros,
    ClaveFirmaHibrida,
) {
    let bytes = evidencia_real();
    let agente = clave();
    let plano = clave();
    let sello = Sello::sellar(
        &bytes,
        procedencia("endpoint-7", "agente-7", Clase::Memoria),
        &agente,
    )
    .unwrap();
    let mut cadena = CadenaDeCustodia::anclada_en(&sello);
    cadena
        .anadir(Paso::Recogida, "agente-7", "recogida automatica", &agente)
        .unwrap();
    cadena
        .anadir(Paso::Transferencia, "plano-de-control", "mTLS", &plano)
        .unwrap();
    let registro = Claveros::nuevo()
        .con("agente-7", agente.clave_verificacion())
        .con("plano-de-control", plano.clave_verificacion());
    (bytes, sello, cadena, registro, agente)
}

#[test]
fn cambiar_un_byte_de_la_evidencia_real_se_detecta() {
    let (bytes, sello, cadena, registro, _) = caso_base();
    let mut alterada = bytes.clone();
    let i = alterada.len() / 2;
    alterada[i] ^= 0x01; // un solo bit
    let v = Veredicto::de(&alterada, &sello, &cadena, &registro);
    assert!(!v.intacta);
    assert!(matches!(v.motivo, Some(CustodiaError::OtrosBytes { .. })));
}

#[test]
fn recortar_el_final_de_la_evidencia_se_detecta_por_la_longitud() {
    let (bytes, sello, cadena, registro, _) = caso_base();
    let v = Veredicto::de(&bytes[..bytes.len() - 1], &sello, &cadena, &registro);
    assert!(!v.intacta);
    assert!(matches!(v.motivo, Some(CustodiaError::OtraLongitud { .. })));
}

#[test]
fn reetiquetar_la_evidencia_para_otro_caso_se_detecta() {
    let (bytes, mut sello, cadena, registro, _) = caso_base();
    sello.procedencia.caso = "CASO-2026-0001".into();
    let v = Veredicto::de(&bytes, &sello, &cadena, &registro);
    assert!(!v.intacta);
    assert!(matches!(
        v.motivo,
        Some(CustodiaError::FirmaQueNoCubre { .. })
    ));
}

#[test]
fn borrar_el_paso_intermedio_de_la_custodia_se_detecta() {
    let (bytes, sello, mut cadena, registro, _) = caso_base();
    cadena.eslabones.remove(0);
    let v = Veredicto::de(&bytes, &sello, &cadena, &registro);
    assert!(!v.intacta);
    assert!(matches!(v.motivo, Some(CustodiaError::CadenaRota { .. })));
}

#[test]
fn pegarle_a_la_evidencia_la_cadena_de_otra_se_detecta() {
    let (bytes, _sello, cadena, registro, _) = caso_base();
    // Otra evidencia distinta, con su propia cadena impecable.
    let (_, otro_sello, _, _, _) = caso_base();
    let v = Veredicto::de(&bytes, &otro_sello, &cadena, &registro);
    assert!(!v.intacta);
    // Falla ya al comprobar la firma del otro sello contra este agente, o al
    // comprobar el ancla: las dos respuestas son correctas y dicen lo mismo.
    assert!(v.motivo.is_some());
}

#[test]
fn una_evidencia_sin_ningun_paso_registrado_no_se_da_por_buena() {
    let bytes = evidencia_real();
    let agente = clave();
    let sello = Sello::sellar(
        &bytes,
        procedencia("endpoint-7", "agente-7", Clase::Memoria),
        &agente,
    )
    .unwrap();
    let cadena = CadenaDeCustodia::anclada_en(&sello);
    let registro = Claveros::nuevo().con("agente-7", agente.clave_verificacion());

    let v = Veredicto::de(&bytes, &sello, &cadena, &registro);
    assert!(
        !v.intacta,
        "un sello perfecto sin custodia no es evidencia custodiada"
    );
    assert!(matches!(v.motivo, Some(CustodiaError::CadenaVacia)));
}

// ---------------------------------------------------------------------------
// El formato canonico, congelado
// ---------------------------------------------------------------------------

#[test]
fn el_formato_canonico_no_puede_cambiar_sin_que_esto_falle() {
    // Este es el seguro de vida de toda la evidencia ya sellada. Si alguien
    // cambia el orden de un campo, el prefijo de longitud o la etiqueta de un
    // documento, la evidencia sellada con la version anterior deja de verificar
    // —para siempre, y sin aviso—. Aqui se congela con datos fijos, incluida la
    // marca de tiempo, para que ese cambio rompa la compilacion en vez de
    // romper un caso dentro de tres anos.
    //
    // Si esta prueba falla y el cambio es deliberado, la respuesta NO es
    // actualizar el numero: es publicar una version nueva del formato
    // (`/v2` en la etiqueta) y conservar la anterior para poder reverificar lo
    // ya sellado.
    let procedencia = Procedencia {
        caso: "CASO-FIJO".into(),
        endpoint: "endpoint-fijo".into(),
        agente: "agente-fijo".into(),
        version_agente: "0.0.0".into(),
        clase: Clase::Binario,
        motivo: "vector de prueba".into(),
        tecnicas: vec!["T0000".into()],
        recogido: Marca {
            pared: 1_700_000_000,
            arranque_ns: 123_456_789,
            arranque: 42,
        },
    };
    // Una clave fija haria la firma reproducible, pero la firma no es el
    // formato: lo que se congela es el MENSAJE que se firma, y se observa por el
    // resumen del sello sobre unos bytes fijos con una clave cualquiera.
    let k = clave();
    let sello = Sello::sellar(b"evidencia fija", procedencia, &k).unwrap();

    // El resumen del artefacto es SHA-256 puro: se puede cotejar con cualquier
    // herramienta de fuera, y aqui esta el valor que da `sha256sum`.
    assert_eq!(
        aegis_custodia::hex(&sello.evidencia),
        "2f261e241017c2d4b8f5ecb5de2c4b761c3c4ebf058d8db149ead83bd4265469",
        "printf 'evidencia fija' | sha256sum"
    );
    assert_eq!(sello.tamano, 14);

    // Y esto es lo que de verdad hay que congelar: el resumen de los BYTES
    // CANONICOS que la firma cubre. No hay herramienta externa con la que
    // cotejarlo —el formato es de este crate—, y por eso mismo esta prueba es
    // la unica defensa que tiene: cualquier cambio en el orden de los campos, en
    // los prefijos de longitud o en las etiquetas lo mueve.
    assert_eq!(
        aegis_custodia::hex(&sello.huella_de_lo_firmado()),
        "2f2a1c676cfb900f66e8e7449f32112126a17cd496ea71df9249f704209e3841",
        "el formato canonico del sello cambio: ver el comentario de arriba"
    );
}

// ---------------------------------------------------------------------------
// La flota
// ---------------------------------------------------------------------------

#[test]
fn una_recogida_de_flota_a_la_que_le_falta_un_endpoint_no_se_presenta_como_completa() {
    // El caso que da sentido a la fase. Cuatro endpoints contestan con evidencia
    // impecable y uno no contesta. El conjunto NO esta completo, y lo que falta
    // se nombra.
    let k = clave();
    let registro = Claveros::nuevo().con("agente-comun", k.clave_verificacion());
    let bytes = evidencia_real();
    let endpoints: Vec<String> = (1..=5).map(|i| format!("endpoint-{i}")).collect();

    let mut conjunto = ConjuntoDeFlota::ordenado("CASO-2026-0042", &endpoints);
    for e in endpoints.iter().take(4) {
        let sello = Sello::sellar(
            &bytes,
            procedencia(e, "agente-comun", Clase::ArbolDeProcesos),
            &k,
        )
        .unwrap();
        let mut cadena = CadenaDeCustodia::anclada_en(&sello);
        cadena
            .anadir(Paso::Recogida, "agente-comun", "orden de caso", &k)
            .unwrap();
        conjunto.con_pieza(Pieza {
            endpoint: e.clone(),
            sello,
            cadena,
        });
    }
    conjunto.con_ausencia(
        "endpoint-5",
        Ausencia::NoAlcanzable {
            visto_por_ultima_vez: Some(1_700_000_000),
        },
    );

    let dame = |_: &str| Some(bytes.clone());
    assert_eq!(
        conjunto.integras(&registro, &dame),
        4,
        "las cuatro que llegaron estan intactas"
    );
    assert!(
        !conjunto.esta_completo(&registro, &dame),
        "cuatro piezas perfectas de cinco endpoints no son la evidencia del caso"
    );
    let falta = conjunto.lo_que_falta();
    assert_eq!(falta.len(), 1);
    assert!(
        falta[0].contains("endpoint-5") && falta[0].contains("no alcanzable"),
        "lo que falta se nombra con su motivo: {falta:?}"
    );
}

#[test]
fn una_recogida_de_flota_entera_e_integra_si_esta_completa() {
    let k = clave();
    let registro = Claveros::nuevo().con("agente-comun", k.clave_verificacion());
    let bytes = evidencia_real();
    let endpoints: Vec<String> = (1..=3).map(|i| format!("endpoint-{i}")).collect();

    let mut conjunto = ConjuntoDeFlota::ordenado("CASO-2026-0042", &endpoints);
    for e in &endpoints {
        let sello = Sello::sellar(
            &bytes,
            procedencia(e, "agente-comun", Clase::ArbolDeProcesos),
            &k,
        )
        .unwrap();
        let mut cadena = CadenaDeCustodia::anclada_en(&sello);
        cadena
            .anadir(Paso::Recogida, "agente-comun", "orden de caso", &k)
            .unwrap();
        conjunto.con_pieza(Pieza {
            endpoint: e.clone(),
            sello,
            cadena,
        });
    }

    let dame = |_: &str| Some(bytes.clone());
    assert!(conjunto.esta_completo(&registro, &dame));
    assert!(conjunto.lo_que_falta().is_empty());
    assert!(conjunto.sin_contabilizar().is_empty());
}

#[test]
fn un_artefacto_grande_de_verdad_se_sella_y_se_verifica() {
    // El binario de esta prueba: unos cuantos megabytes de verdad, con bytes no
    // imprimibles. Comprueba que el camino no depende de que la evidencia sea
    // texto corto, que es como suelen escribirse las pruebas y como nunca es la
    // evidencia real.
    let Ok(ruta) = std::env::current_exe() else {
        omitir(
            "no se pudo localizar el binario de la prueba",
            Requisito::Entorno,
        );
        return;
    };
    let bytes = std::fs::read(&ruta).expect("leer el binario de la prueba");
    assert!(bytes.len() > 100_000, "{} bytes", bytes.len());

    let k = clave();
    let sello = Sello::sellar(
        &bytes,
        procedencia("endpoint-7", "agente-7", Clase::Binario),
        &k,
    )
    .unwrap();
    let mut cadena = CadenaDeCustodia::anclada_en(&sello);
    cadena
        .anadir(Paso::Recogida, "agente-7", "binario sospechoso", &k)
        .unwrap();
    let registro = Claveros::nuevo().con("agente-7", k.clave_verificacion());

    let v = Veredicto::de(&bytes, &sello, &cadena, &registro);
    assert!(v.intacta, "motivo: {:?}", v.motivo);
    assert_eq!(sello.tamano, bytes.len() as u64);
}
