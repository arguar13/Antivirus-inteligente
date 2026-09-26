//! Extremo a extremo: documentos con la forma real de CloudTrail, Azure
//! Activity y GCP Audit, por `aegis_pipeline::nube::analizar_lote`, y de ahi a
//! la postura.
//!
//! Los fixtures de `fixtures/` copian la forma que publican los tres
//! proveedores (campos, anidamiento, `{"items":[...]}` de EC2, `requestbody`
//! como texto JSON en Azure, `serviceData.policyDelta` y operaciones largas de
//! Compute en GCP). Lo que se prueba es que un hallazgo sale con el
//! identificador EXACTO del evento que lo sostiene, que la correccion lo
//! devuelve a `Cumple`, y que lo no observado dice `SinDatos`.

use aegis_entidad::entidad;
use aegis_ingest::esquema::{Evento, Valor};
use aegis_ingest::tiempo::desde_rfc3339;
use aegis_pipeline::nube::{analizar_lote, Contexto};
use aegis_postura::credenciales;
use aegis_postura::estado::eid_recurso;
use aegis_postura::modelo::{ALM_001, CLV_001, IAM_001, IAM_002, LOG_001, LOG_002, RED_001};
use aegis_postura::{Estado, Informe, Naturaleza, Proveedor, Resultado};

const AWS: &str = include_str!("../fixtures/aws.json");
const AWS_CORRECCION: &str = include_str!("../fixtures/aws_correccion.json");
const AZURE: &str = include_str!("../fixtures/azure.json");
const GCP: &str = include_str!("../fixtures/gcp.jsonl");

fn ahora() -> u64 {
    desde_rfc3339("2026-09-26T00:00:00Z").unwrap()
}

fn ctx(crudo: bool) -> Contexto {
    Contexto {
        inquilino: "cliente-1".into(),
        observado_ns: ahora(),
        conservar_crudo: crudo,
    }
}

fn lote(doc: &str, crudo: bool) -> Vec<Evento> {
    let v = analizar_lote(doc.as_bytes(), &ctx(crudo));
    assert!(!v.is_empty(), "el fixture no produjo eventos");
    v
}

fn todos(crudo: bool) -> Vec<Evento> {
    let mut v = lote(AWS, crudo);
    v.extend(lote(AZURE, crudo));
    v.extend(lote(GCP, crudo));
    v
}

/// El `Evento::id` del evento cuyo identificador de proveedor es `ancla`.
fn id_de(eventos: &[Evento], ancla: &str) -> String {
    eventos
        .iter()
        .find(|e| e.ancla == format!("nube:{ancla}"))
        .unwrap_or_else(|| panic!("no hay evento con ancla {ancla}"))
        .id
        .clone()
}

/// El id del evento de Azure con esa correlacion y ese resultado.
fn id_azure(eventos: &[Evento], correlacion: &str, resultado: &str) -> String {
    eventos
        .iter()
        .find(|e| {
            e.campos.get("nube.correlacion") == Some(&Valor::Texto(correlacion.into()))
                && e.campos.get("nube.resultado") == Some(&Valor::Texto(resultado.into()))
        })
        .unwrap()
        .id
        .clone()
}

fn resultado<'a>(inf: &'a Informe, comp: &str, contiene: &str) -> &'a Resultado {
    inf.resultados(comp)
        .into_iter()
        .find(|r| r.recurso.contains(contiene))
        .unwrap_or_else(|| {
            panic!(
                "no hay resultado de {comp} con {contiene:?}; hay: {:?}",
                inf.resultados(comp)
                    .iter()
                    .map(|r| &r.recurso)
                    .collect::<Vec<_>>()
            )
        })
}

fn cita(r: &Resultado, id: &str) -> bool {
    r.estado
        .evidencia()
        .is_some_and(|e| e.ids_de_evento().contains(&id))
}

fn es_sin_datos(e: Option<&Estado>) -> bool {
    matches!(e, Some(Estado::SinDatos(_)))
}

// --- AWS -----------------------------------------------------------------

#[test]
fn aws_cada_comprobacion_incumple_con_el_id_exacto_de_su_evento() {
    let ev = lote(AWS, true);
    let inf = Informe::evaluar(&ev, ahora());

    let admin = resultado(&inf, IAM_001, "user/ana <- AdministratorAccess");
    assert!(admin.estado.incumple(), "{:?}", admin.estado);
    assert!(cita(admin, &id_de(&ev, "aws-0002-attach-admin-ana")));
    assert_eq!(
        admin.entidad,
        entidad::cuenta("arn:aws:iam::123456789012:user/ana")
    );

    let publico = resultado(&inf, ALM_001, "datos-clientes");
    assert!(publico.estado.incumple());
    assert!(cita(
        publico,
        &id_de(&ev, "aws-0005-putbucketpolicy-publica")
    ));
    assert_eq!(
        publico.entidad,
        eid_recurso(Proveedor::Aws, "arn:aws:s3:::datos-clientes")
    );
    let acl = resultado(&inf, ALM_001, "logs-web");
    assert!(acl.estado.incumple());
    assert!(cita(acl, &id_de(&ev, "aws-0006-putbucketacl-allusers")));
    let sin_bloqueo = resultado(&inf, ALM_001, "copias");
    assert!(sin_bloqueo.estado.incumple());
    assert!(cita(
        sin_bloqueo,
        &id_de(&ev, "aws-0007-deletepublicaccessblock")
    ));

    let vieja = resultado(&inf, CLV_001, "AKIAIOSFODNN7CIDEPL");
    assert!(vieja.estado.incumple(), "{:?}", vieja.estado);
    assert!(cita(vieja, &id_de(&ev, "aws-0003-createaccesskey-ci")));
    let nueva = resultado(&inf, CLV_001, "AKIAIOSFODNN7BACKUP");
    assert!(
        nueva.estado.cumple(),
        "creada hace 16 dias: {:?}",
        nueva.estado
    );

    let trail = resultado(&inf, LOG_001, "trail/principal");
    assert!(trail.estado.incumple());
    assert!(cita(trail, &id_de(&ev, "aws-0011-stoplogging")));

    let ssh = resultado(&inf, RED_001, "puerto 22");
    assert!(ssh.estado.incumple());
    assert!(cita(ssh, &id_de(&ev, "aws-0008-authorize-ssh")));
    let rdp = resultado(&inf, RED_001, "puerto 3389");
    assert!(rdp.estado.incumple(), "::/0 tambien es Internet");

    for comp in [IAM_001, ALM_001, CLV_001, LOG_001, LOG_002, RED_001] {
        assert!(
            inf.estado(comp, Proveedor::Aws)
                .is_some_and(Estado::incumple),
            "{comp}: {:?}",
            inf.estado(comp, Proveedor::Aws)
        );
    }
}

#[test]
fn apagar_el_registro_y_crear_cuentas_es_compromiso_y_no_exposicion() {
    let ev = lote(AWS, true);
    let inf = Informe::evaluar(&ev, ahora());
    let c = resultado(&inf, LOG_002, "trail/principal");
    assert!(c.estado.incumple(), "{:?}", c.estado);
    assert_eq!(c.naturaleza(), Naturaleza::Compromiso);
    // La entidad es quien apago el registro, con su ARN: la misma cuenta que
    // veria ITDR.
    assert_eq!(
        c.entidad,
        entidad::cuenta("arn:aws:iam::123456789012:user/soporte")
    );
    for ancla in [
        "aws-0011-stoplogging",
        "aws-0012-createuser-tras-apagar",
        "aws-0013-createaccesskey-tras-apagar",
    ] {
        assert!(cita(c, &id_de(&ev, ancla)), "falta {ancla}");
    }
    assert!(inf.compromisos().iter().any(|r| r.comprobacion == LOG_002));
    assert!(inf.exposiciones().iter().all(|r| r.comprobacion != LOG_002));
    // La creacion de cuentas ANTES del apagado no cuenta.
    assert!(!cita(c, &id_de(&ev, "aws-0001-createuser-ana")));
}

#[test]
fn la_correccion_posterior_devuelve_cada_comprobacion_a_cumple() {
    let mut ev = lote(AWS, true);
    ev.extend(lote(AWS_CORRECCION, true));
    let inf = Informe::evaluar(&ev, ahora());

    let admin = resultado(&inf, IAM_001, "user/ana <- AdministratorAccess");
    assert!(admin.estado.cumple(), "{:?}", admin.estado);
    // La evidencia cuenta la historia entera: lo que se abrio y lo que lo
    // cerro.
    assert!(cita(admin, &id_de(&ev, "aws-0002-attach-admin-ana")));
    assert!(cita(admin, &id_de(&ev, "aws-0102-detach-admin-ana")));

    let cubo = resultado(&inf, ALM_001, "datos-clientes");
    assert!(cubo.estado.cumple(), "{:?}", cubo.estado);
    assert!(cita(cubo, &id_de(&ev, "aws-0103-putpublicaccessblock")));

    let ssh = resultado(&inf, RED_001, "puerto 22");
    assert!(ssh.estado.cumple(), "{:?}", ssh.estado);
    // Revocada por IDENTIFICADOR de regla: el emparejamiento sale de la
    // respuesta de AuthorizeSecurityGroupIngress, que solo esta en el crudo.
    let rdp = resultado(&inf, RED_001, "puerto 3389");
    assert!(rdp.estado.cumple(), "{:?}", rdp.estado);
    assert!(cita(rdp, &id_de(&ev, "aws-0105-revoke-rdp-por-id")));
    assert!(inf
        .estado(RED_001, Proveedor::Aws)
        .is_some_and(Estado::cumple));

    let trail = resultado(&inf, LOG_001, "trail/principal");
    assert!(trail.estado.cumple(), "{:?}", trail.estado);

    let clave = resultado(&inf, CLV_001, "AKIAIOSFODNN7CIDEPL");
    assert!(clave.estado.cumple(), "{:?}", clave.estado);

    // Volver a encender el registro no borra lo que paso mientras estuvo
    // apagado.
    assert!(resultado(&inf, LOG_002, "trail/principal")
        .estado
        .incumple());
}

#[test]
fn un_evento_fallido_no_cambia_el_estado() {
    let ev = lote(AWS, true);
    let inf = Informe::evaluar(&ev, ahora());
    // PutBucketPolicy publica sobre `finanzas` con AccessDenied: no hay cubo.
    assert!(inf
        .resultados(ALM_001)
        .iter()
        .all(|r| !r.recurso.contains("finanzas")));
    let aws = inf.cobertura.de(Proveedor::Aws).unwrap();
    assert_eq!(aws.contadores.no_aplicados, 1);

    // Y uno fallido DESPUES de uno bueno no lo deshace: una llamada rechazada
    // no configuro nada.
    let detach_denegado = r#"{"Records":[{"eventVersion":"1.09","eventSource":"iam.amazonaws.com",
        "eventName":"DetachUserPolicy","eventTime":"2026-09-22T00:00:00Z","awsRegion":"us-east-1",
        "errorCode":"AccessDenied","errorMessage":"no",
        "userIdentity":{"type":"IAMUser","accountId":"123456789012","userName":"x"},
        "requestParameters":{"userName":"ana","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"},
        "eventID":"aws-0200-detach-denegado"}]}"#;
    let mut ev2 = ev.clone();
    ev2.extend(lote(detach_denegado, true));
    let inf2 = Informe::evaluar(&ev2, ahora());
    assert!(resultado(&inf2, IAM_001, "user/ana").estado.incumple());
}

#[test]
fn un_duplicado_del_mismo_evento_no_duplica_evidencia_ni_cambia_nada() {
    let ev = lote(AWS, true);
    let una = Informe::evaluar(&ev, ahora());
    let mut dos = ev.clone();
    dos.extend(lote(AWS, true));
    let doble = Informe::evaluar(&dos, ahora());
    assert_eq!(una.comprobaciones, doble.comprobaciones);
    assert_eq!(
        doble
            .cobertura
            .de(Proveedor::Aws)
            .unwrap()
            .contadores
            .duplicados,
        ev.len()
    );
    for c in &doble.comprobaciones {
        for r in &c.resultados {
            if let Some(e) = r.estado.evidencia() {
                let mut ids = e.ids_de_evento();
                let n = ids.len();
                ids.sort_unstable();
                ids.dedup();
                assert_eq!(ids.len(), n, "evidencia repetida en {}", r.recurso);
            }
        }
    }
}

#[test]
fn el_orden_de_llegada_no_importa() {
    let mut ev = todos(true);
    ev.extend(lote(AWS_CORRECCION, true));
    let a = Informe::evaluar(&ev, ahora());
    ev.reverse();
    let b = Informe::evaluar(&ev, ahora());
    assert_eq!(a, b);
}

// --- EL MURO ---------------------------------------------------------------

#[test]
fn sin_eventos_nada_cumple_y_sin_eventos_de_un_proveedor_ese_proveedor_tampoco() {
    let vacio = Informe::evaluar(&[], ahora());
    for c in &vacio.comprobaciones {
        for (_, e) in &c.por_proveedor {
            assert!(matches!(e, Estado::SinDatos(_)));
        }
    }
    // Solo AWS: Azure y GCP no dicen nada, ni siquiera LOG-002.
    let inf = Informe::evaluar(&lote(AWS, true), ahora());
    for c in &inf.comprobaciones {
        for p in [Proveedor::Azure, Proveedor::Gcp] {
            if let Some(e) = c.estado(p) {
                assert!(
                    matches!(e, Estado::SinDatos(m) if m.contains("ningun evento")),
                    "{} {}: {e:?}",
                    c.definicion.id,
                    p.nombre()
                );
            }
        }
    }
    let az = inf.cobertura.de(Proveedor::Azure).unwrap();
    assert!(!az.tuvo_eventos());
    assert!(az.con_datos.is_empty());
}

#[test]
fn una_clave_en_uso_cuyo_alta_no_se_vio_es_sin_datos_y_lo_dice() {
    let inf = Informe::evaluar(&lote(AWS, true), ahora());
    let robada = resultado(&inf, CLV_001, "AKIAIOSFODNN7ROBADA");
    match &robada.estado {
        Estado::SinDatos(m) => assert!(m.contains("no se observo"), "{m}"),
        otro => panic!("{otro:?}"),
    }
    // Las claves de sesion (ASIA) no se rotan y no se listan.
    assert!(inf
        .resultados(CLV_001)
        .iter()
        .all(|r| !r.recurso.contains("ASIA")));
}

#[test]
fn quitar_una_concesion_no_observada_no_afirma_que_la_identidad_este_limpia() {
    // Un grupo de seguridad del que solo se ve un revoke: no se sabe que mas
    // tiene, y no sale nada que diga Cumple sobre el.
    let solo_revoke = r#"{"Records":[{"eventVersion":"1.09","eventSource":"ec2.amazonaws.com",
        "eventName":"RevokeSecurityGroupIngress","eventTime":"2026-09-22T00:00:00Z",
        "awsRegion":"eu-west-1","userIdentity":{"type":"IAMUser","accountId":"123456789012","userName":"admin"},
        "requestParameters":{"groupId":"sg-otro","ipPermissions":{"items":[{"ipProtocol":"tcp",
        "fromPort":22,"toPort":22,"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]}}]}},
        "eventID":"aws-0300-revoke-solo"}]}"#;
    let inf = Informe::evaluar(&lote(solo_revoke, true), ahora());
    assert!(es_sin_datos(inf.estado(RED_001, Proveedor::Aws)));
}

#[test]
fn apagar_el_registro_sin_que_llegue_nada_despues_deja_ciego_y_no_se_afirma_nada() {
    let solo_stop = r#"{"Records":[{"eventVersion":"1.09","eventSource":"cloudtrail.amazonaws.com",
        "eventName":"StopLogging","eventTime":"2026-09-25T00:00:00Z","awsRegion":"eu-west-1",
        "userIdentity":{"type":"IAMUser","accountId":"123456789012","userName":"x","arn":"arn:aws:iam::123456789012:user/x"},
        "requestParameters":{"name":"principal"},"eventID":"aws-0400-stop"}]}"#;
    let inf = Informe::evaluar(&lote(solo_stop, true), ahora());
    let c = resultado(&inf, LOG_002, "principal");
    match &c.estado {
        Estado::SinDatos(m) => assert!(m.contains("es el que se apago"), "{m}"),
        otro => panic!("{otro:?}"),
    }
    assert!(inf
        .cobertura
        .de(Proveedor::Aws)
        .unwrap()
        .ciego_desde_ns
        .is_some());
    assert!(inf.texto().contains("CIEGO"));
}

// --- Azure -----------------------------------------------------------------

#[test]
fn azure_owner_y_rdp_abierto_se_leen_del_start_y_aplican_con_el_success() {
    let ev = lote(AZURE, true);
    let inf = Informe::evaluar(&ev, ahora());
    let owner = resultado(&inf, IAM_001, "Owner a 9f8e7d6c");
    assert!(owner.estado.incumple(), "{:?}", owner.estado);
    assert_eq!(
        owner.entidad,
        entidad::cuenta("9f8e7d6c-5b4a-4321-8765-0fedcba98765")
    );
    // Cita los dos: el Start dice QUE se pidio; el Success, que se hizo.
    let corr = "c0a1b2c3-0001-4d5e-8f90-a1b2c3d4e5f6";
    assert!(cita(owner, &id_azure(&ev, corr, "Start")));
    assert!(cita(owner, &id_azure(&ev, corr, "Success")));

    // La asignacion de Contributor que acabo en Failure no concedio nada.
    assert!(inf
        .resultados(IAM_001)
        .iter()
        .all(|r| !r.recurso.contains("22222222")));

    let rdp = resultado(&inf, RED_001, "permitir-rdp");
    assert!(rdp.estado.incumple(), "{:?}", rdp.estado);
    let diag = resultado(&inf, LOG_001, "envio-a-siem");
    assert!(diag.estado.incumple());
    // Tras borrar la configuracion de diagnostico no llega nada mas: la
    // gestion de cuentas posterior no se puede afirmar ni negar.
    assert!(es_sin_datos(inf.estado(LOG_002, Proveedor::Azure)));
}

#[test]
fn azure_sin_crudo_no_tiene_cuerpo_y_lo_dice_en_vez_de_cumplir() {
    let inf = Informe::evaluar(&lote(AZURE, false), ahora());
    let owner = resultado(&inf, IAM_001, "roleassignments");
    match &owner.estado {
        Estado::SinDatos(m) => assert!(m.contains("crudo"), "{m}"),
        otro => panic!("{otro:?}"),
    }
    assert!(!inf
        .estado(RED_001, Proveedor::Azure)
        .is_some_and(Estado::cumple));
    assert!(
        inf.cobertura
            .de(Proveedor::Azure)
            .unwrap()
            .contadores
            .sin_detalle
            > 0
    );
}

// --- GCP -------------------------------------------------------------------

#[test]
fn gcp_owner_publico_cubo_clave_cortafuegos_y_sink() {
    let ev = lote(GCP, true);
    let inf = Informe::evaluar(&ev, ahora());

    let externo = resultado(&inf, IAM_001, "externo@gmail.com roles/owner");
    assert!(externo.estado.incumple());
    assert_eq!(externo.entidad, entidad::cuenta("externo@gmail.com"));
    assert!(cita(externo, &id_de(&ev, "gcp-0001-setiampolicy-owner")));

    let publico = resultado(&inf, IAM_002, "allUsers");
    assert!(publico.estado.incumple());
    assert_eq!(
        publico.entidad,
        eid_recurso(Proveedor::Gcp, "projects/prod-123")
    );

    let cubo = resultado(&inf, ALM_001, "fotos-publicas");
    assert!(cubo.estado.incumple());
    assert!(cita(cubo, &id_de(&ev, "gcp-0002-storage-allusers")));

    let clave = resultado(&inf, CLV_001, "5f1c2a9b8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b");
    assert!(clave.estado.incumple(), "{:?}", clave.estado);
    assert_eq!(
        clave.entidad,
        entidad::cuenta("deployer@prod-123.iam.gserviceaccount.com")
    );

    let fw = resultado(&inf, RED_001, "permitir-ssh");
    assert!(fw.estado.incumple(), "{:?}", fw.estado);
    assert!(cita(fw, &id_de(&ev, "gcp-0004-firewall-insert-first")));

    let sink = resultado(&inf, LOG_001, "siem-export");
    assert!(sink.estado.incumple());

    // La clave creada tras borrar el sink es la secuencia de quien sabe lo
    // que hace.
    let comp = resultado(&inf, LOG_002, "siem-export");
    assert!(comp.estado.incumple(), "{:?}", comp.estado);
    assert!(cita(comp, &id_de(&ev, "gcp-0008-createkey-tras-sink")));

    // SetIamPolicy denegada: el becario no es propietario.
    assert!(inf
        .resultados(IAM_001)
        .iter()
        .all(|r| !r.recurso.contains("becario")));
}

#[test]
fn gcp_una_politica_completa_posterior_retira_lo_que_ya_no_esta() {
    let mut ev = lote(GCP, true);
    let correccion = r#"{"insertId":"gcp-0100-setiampolicy-limpia","protoPayload":{"status":{},
        "authenticationInfo":{"principalEmail":"plataforma@corp.com"},
        "serviceName":"cloudresourcemanager.googleapis.com","methodName":"SetIamPolicy",
        "resourceName":"projects/prod-123",
        "serviceData":{"policyDelta":{"bindingDeltas":[{"action":"REMOVE","role":"roles/owner","member":"user:externo@gmail.com"},{"action":"REMOVE","role":"roles/viewer","member":"allUsers"}]}},
        "request":{"policy":{"bindings":[{"role":"roles/owner","members":["user:plataforma@corp.com"]}]}}},
        "timestamp":"2026-09-21T10:00:00Z"}"#;
    ev.extend(lote(correccion, true));
    let inf = Informe::evaluar(&ev, ahora());
    assert!(resultado(&inf, IAM_001, "externo@gmail.com")
        .estado
        .cumple());
    assert!(resultado(&inf, IAM_002, "allUsers").estado.cumple());
    // El propietario que sigue en la politica completa sigue saliendo.
    assert!(resultado(&inf, IAM_001, "plataforma@corp.com")
        .estado
        .incumple());
}

// --- Sin crudo: lo que el aplanado deja ver y lo que no ------------------------

#[test]
fn sin_crudo_aws_sigue_viendo_lo_que_esta_en_request_parameters() {
    let inf = Informe::evaluar(&lote(AWS, false), ahora());
    assert!(resultado(&inf, IAM_001, "user/ana").estado.incumple());
    assert!(resultado(&inf, ALM_001, "datos-clientes").estado.incumple());
    assert!(resultado(&inf, RED_001, "puerto 22").estado.incumple());
    assert!(resultado(&inf, LOG_001, "principal").estado.incumple());
    // El identificador de la clave esta en responseElements, que el aplanado
    // no conserva: la clave existe y su edad se sabe, su nombre no.
    let sin_id = resultado(&inf, CLV_001, "user/ci-deploy");
    assert!(sin_id.recurso.contains("sin-id:"), "{}", sin_id.recurso);
    assert!(sin_id.estado.incumple(), "{:?}", sin_id.estado);
}

#[test]
fn una_regla_abierta_detras_del_elemento_32_se_ve_con_crudo_y_sin_crudo_no_se_niega() {
    let mut rangos = String::new();
    for i in 0..40 {
        if i > 0 {
            rangos.push(',');
        }
        let cidr = if i == 35 {
            "0.0.0.0/0".to_string()
        } else {
            format!("10.0.{i}.0/24")
        };
        rangos.push_str(&format!(r#"{{"cidrIp":"{cidr}"}}"#));
    }
    let doc = format!(
        r#"{{"eventVersion":"1.09","eventSource":"ec2.amazonaws.com",
        "eventName":"AuthorizeSecurityGroupIngress","eventTime":"2026-09-22T00:00:00Z",
        "awsRegion":"eu-west-1","userIdentity":{{"type":"IAMUser","accountId":"123456789012","userName":"x"}},
        "requestParameters":{{"groupId":"sg-escondido","ipPermissions":{{"items":[{{"ipProtocol":"tcp",
        "fromPort":22,"toPort":22,"ipRanges":{{"items":[{rangos}]}}}}]}}}},
        "eventID":"aws-0500-escondido"}}"#
    );
    let con = Informe::evaluar(&lote(&doc, true), ahora());
    assert!(resultado(&con, RED_001, "sg-escondido").estado.incumple());
    let sin = Informe::evaluar(&lote(&doc, false), ahora());
    let r = resultado(&sin, RED_001, "sg-escondido");
    assert!(
        matches!(&r.estado, Estado::SinDatos(m) if m.contains("no se vieron enteras")),
        "el aplanado corta en 32: sin crudo NO puede salir Cumple; salio {:?}",
        r.estado
    );
}

// --- Informe de credenciales -------------------------------------------------

#[test]
fn el_informe_de_credenciales_tapa_el_muro_de_la_antiguedad_de_claves() {
    let csv = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::123456789012:root,2019-01-10T08:00:00+00:00,not_supported,2026-09-01T10:00:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
soporte,arn:aws:iam::123456789012:user/soporte,2021-03-02T09:00:00+00:00,false,N/A,N/A,N/A,false,true,2024-02-11T12:00:00+00:00,2026-09-20T02:06:00+00:00,us-east-1,iam,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
";
    let cred = credenciales::leer(csv.as_bytes(), ahora()).unwrap();
    // Sin eventos: la fuente es solo el informe, y AWS/CLV-001 tiene datos.
    let inf = Informe::evaluar_con_credenciales(&[], Some(&cred), ahora());
    let r = resultado(&inf, CLV_001, "user/soporte");
    assert!(r.estado.incumple(), "{:?}", r.estado);
    assert!(matches!(
        r.estado.evidencia().unwrap().referencias[0],
        aegis_postura::Referencia::InformeCredenciales { fila: 2, .. }
    ));
    assert!(inf
        .estado(CLV_001, Proveedor::Aws)
        .is_some_and(Estado::incumple));
    // El resto de comprobaciones de AWS sigue sin datos: el informe solo
    // habla de claves.
    assert!(es_sin_datos(inf.estado(IAM_001, Proveedor::Aws)));
}

// --- Entrada hostil ------------------------------------------------------------

#[test]
fn un_documento_de_politica_enorme_o_anidado_no_revienta_y_no_se_afirma() {
    let grande = format!(
        r#"{{\"Statement\":[{{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\",\"Sid\":\"{}\"}}]}}"#,
        "a".repeat(300 * 1024)
    );
    let mut hondo = String::new();
    for _ in 0..1000 {
        hondo.push('[');
    }
    for _ in 0..1000 {
        hondo.push(']');
    }
    let hondo = hondo.replace('"', "\\\"");
    for (n, doc) in [(1, grande), (2, hondo)] {
        let ev = format!(
            r#"{{"eventVersion":"1.09","eventSource":"iam.amazonaws.com","eventName":"PutUserPolicy",
            "eventTime":"2026-09-22T00:00:00Z","awsRegion":"us-east-1",
            "userIdentity":{{"type":"IAMUser","accountId":"123456789012","userName":"x"}},
            "requestParameters":{{"userName":"victima","policyName":"p{n}","policyDocument":"{doc}"}},
            "eventID":"aws-0600-hostil-{n}"}}"#
        );
        for crudo in [true, false] {
            let inf = Informe::evaluar(&lote(&ev, crudo), ahora());
            let r = resultado(&inf, IAM_001, &format!("en linea p{n}"));
            assert!(
                matches!(r.estado, Estado::SinDatos(_)),
                "documento hostil {n} (crudo={crudo}): {:?}",
                r.estado
            );
        }
    }
}

#[test]
fn un_crudo_de_un_mega_se_ignora_y_se_lee_del_aplanado() {
    let mut ev = lote(AWS, true);
    let i = ev
        .iter()
        .position(|e| e.ancla == "nube:aws-0005-putbucketpolicy-publica")
        .unwrap();
    // El crudo no entra en el identificador: se puede inflar sin romper el
    // sello, que es justo lo que haria un intermediario hostil.
    ev[i].crudo = Some(vec![b'{'; 1024 * 1024]);
    let inf = Informe::evaluar(&ev, ahora());
    assert!(resultado(&inf, ALM_001, "datos-clientes").estado.incumple());
}

#[test]
fn nombres_de_recurso_gigantes_salen_recortados() {
    let largo = "b".repeat(3000);
    let doc = format!(
        r#"{{"eventVersion":"1.09","eventSource":"s3.amazonaws.com","eventName":"DeletePublicAccessBlock",
        "eventTime":"2026-09-22T00:00:00Z","awsRegion":"eu-west-1",
        "userIdentity":{{"type":"IAMUser","accountId":"123456789012","userName":"x"}},
        "requestParameters":{{"bucketName":"{largo}"}},"eventID":"aws-0700-largo"}}"#
    );
    let inf = Informe::evaluar(&lote(&doc, true), ahora());
    for c in &inf.comprobaciones {
        for r in &c.resultados {
            assert!(r.recurso.len() <= aegis_postura::modelo::MAX_RECURSO + 32);
            if let Some(e) = r.estado.evidencia() {
                assert!(e.extracto.len() <= aegis_postura::modelo::MAX_EXTRACTO);
            }
        }
    }
}

#[test]
fn miles_de_concesiones_inventadas_estan_acotadas() {
    let mut recs = Vec::new();
    for i in 0..1200 {
        recs.push(format!(
            r#"{{"eventVersion":"1.09","eventSource":"iam.amazonaws.com","eventName":"AttachUserPolicy",
            "eventTime":"2026-09-22T00:00:00Z","awsRegion":"us-east-1",
            "userIdentity":{{"type":"IAMUser","accountId":"123456789012","userName":"x"}},
            "requestParameters":{{"userName":"u{i}","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}},
            "eventID":"aws-inventada-{i}"}}"#
        ));
    }
    let doc = format!(r#"{{"Records":[{}]}}"#, recs.join(","));
    let inf = Informe::evaluar(&lote(&doc, false), ahora());
    let c = inf.comprobacion(IAM_001).unwrap();
    assert_eq!(c.resultados.len(), 1200);
    let e = c.estado(Proveedor::Aws).unwrap().evidencia().unwrap();
    assert!(e.referencias.len() <= aegis_postura::modelo::MAX_REFERENCIAS);
    assert!(e.omitidas > 0, "lo que no cabe se cuenta");
}

// --- Todo junto ----------------------------------------------------------------

#[test]
fn los_tres_proveedores_juntos_y_la_cobertura_lo_cuenta() {
    let inf = Informe::evaluar(&todos(true), ahora());
    for p in [Proveedor::Aws, Proveedor::Azure, Proveedor::Gcp] {
        let c = inf.cobertura.de(p).unwrap();
        assert!(c.tuvo_eventos(), "{}", p.nombre());
        assert!(!c.con_datos.is_empty(), "{}", p.nombre());
    }
    // Azure: pendientes (los Start) y un fallo (la asignacion denegada).
    let az = &inf.cobertura.de(Proveedor::Azure).unwrap().contadores;
    assert!(az.pendientes >= 2);
    assert!(az.no_aplicados >= 1);
    let texto = inf.texto();
    for id in [
        IAM_001, IAM_002, ALM_001, CLV_001, LOG_001, LOG_002, RED_001,
    ] {
        assert!(texto.contains(id), "{id}");
    }
}

#[test]
fn la_evaluacion_es_determinista() {
    let ev = todos(true);
    let a = Informe::evaluar(&ev, ahora());
    for _ in 0..3 {
        assert_eq!(a, Informe::evaluar(&ev, ahora()));
    }
    assert_eq!(a.texto(), Informe::evaluar(&ev, ahora()).texto());
}
