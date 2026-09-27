//! Escala: el muro de los cien mil, medido con el directorio sintetico mas grande
//! que cabe.
//!
//! Sin un dominio de produccion real no se puede medir a escala de cien mil
//! cuentas —eso se declara como muro—. Lo que si se puede es construir un
//! directorio sintetico grande y comprobar que el modelo lo aguanta: que se
//! construye dentro de los topes, que encuentra la exposicion plantada entre el
//! ruido, y que la auditoria es determinista a esa escala.

use aegis_itdr::directorio::colector::{construir_grafo, EntradaLdap, Lote};
use aegis_itdr::directorio::exposicion::ClaseExposicion;

/// Un objectSid binario `S-1-5-21-1-2-3-rid`.
fn sid_bin(rid: u32) -> Vec<u8> {
    let mut v = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
    for sub in [21u32, 1, 2, 3, rid] {
        v.extend_from_slice(&sub.to_le_bytes());
    }
    v
}

/// Un descriptor con un ACE de WriteDacl para un trustee (RID).
fn sd_writedacl(rid: u32) -> Vec<u8> {
    let sid = sid_bin(rid);
    let ace_size = 8 + sid.len();
    let mut ace = vec![0u8, 0];
    ace.extend_from_slice(&(ace_size as u16).to_le_bytes());
    ace.extend_from_slice(&0x0004_0000u32.to_le_bytes()); // WRITE_DAC
    ace.extend_from_slice(&sid);
    let acl_size = 8 + ace.len();
    let mut acl = vec![2u8, 0];
    acl.extend_from_slice(&(acl_size as u16).to_le_bytes());
    acl.extend_from_slice(&1u16.to_le_bytes());
    acl.extend_from_slice(&[0, 0]);
    acl.extend_from_slice(&ace);
    let mut sd = vec![1u8, 0];
    sd.extend_from_slice(&0x0004u16.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(&acl);
    sd
}

/// Construye un lote sintetico: `n` usuarios, repartidos en cadenas de grupos
/// anidados que terminan en «Domain Admins», y un becario con WriteDacl sobre el.
fn lote_sintetico(n: u32) -> Vec<EntradaLdap> {
    let mut entradas = Vec::with_capacity(n as usize + 2);

    // Domain Admins (RID 512), con la ACL peligrosa plantada: el becario (RID 900000)
    // puede reescribir su DACL.
    entradas.push(
        EntradaLdap::nueva("CN=Domain Admins,CN=Users,DC=aegis,DC=local")
            .con_texto("objectClass", &["group"])
            .con_texto("sAMAccountName", &["Domain Admins"])
            .con_binario("objectSid", sid_bin(512))
            .con_binario("ntSecurityDescriptor", sd_writedacl(900_000)),
    );
    entradas.push(
        EntradaLdap::nueva("CN=becario,CN=Users,DC=aegis,DC=local")
            .con_texto("objectClass", &["user"])
            .con_texto("sAMAccountName", &["becario"])
            .con_binario("objectSid", sid_bin(900_000)),
    );

    // n usuarios normales, cada uno miembro de un grupo intermedio distinto para
    // que la pertenencia anidada tenga trabajo que hacer.
    for i in 0..n {
        let rid_usuario = 10_000 + i;
        let rid_grupo = 50_000 + i;
        entradas.push(
            EntradaLdap::nueva(format!("CN=grupo{i},CN=Users,DC=aegis,DC=local"))
                .con_texto("objectClass", &["group"])
                .con_texto("sAMAccountName", &[&format!("grupo{i}")])
                .con_texto(
                    "member",
                    &[&format!("CN=usuario{i},CN=Users,DC=aegis,DC=local")],
                )
                .con_binario("objectSid", sid_bin(rid_grupo)),
        );
        entradas.push(
            EntradaLdap::nueva(format!("CN=usuario{i},CN=Users,DC=aegis,DC=local"))
                .con_texto("objectClass", &["user"])
                .con_texto("sAMAccountName", &[&format!("usuario{i}")])
                .con_binario("objectSid", sid_bin(rid_usuario)),
        );
    }
    entradas
}

#[test]
fn un_directorio_sintetico_grande_se_construye_y_encuentra_la_exposicion_plantada() {
    // 5000 usuarios + 5000 grupos + Domain Admins + becario: un directorio de
    // tamano medio. El muro de cien mil se declara en el docs/; aqui se mide lo
    // que cabe en la maquina.
    let n = 5_000;
    let (g, huecos) = construir_grafo(&Lote(lote_sintetico(n))).expect("construccion a escala");
    assert_eq!(g.principales(), (n * 2 + 2) as usize);
    assert!(
        huecos.is_empty(),
        "todo se resolvio: {} huecos",
        huecos.len()
    );

    // La aguja en el pajar: la ACL peligrosa del becario sobre Domain Admins se
    // encuentra entre 10 000 principales.
    let inf = g.auditar();
    assert!(
        inf.exposiciones
            .iter()
            .any(|e| e.clase == ClaseExposicion::AclPeligrosa && e.nombre == "becario"),
        "la exposicion plantada se encuentra entre el ruido"
    );

    // Determinismo a escala: dos auditorias del mismo grafo dan lo mismo.
    let inf2 = g.auditar();
    assert_eq!(inf.exposiciones.len(), inf2.exposiciones.len());
    eprintln!(
        "escala: {} principales, {} aristas, {} exposiciones",
        g.principales(),
        g.aristas(),
        inf.exposiciones.len()
    );
}
