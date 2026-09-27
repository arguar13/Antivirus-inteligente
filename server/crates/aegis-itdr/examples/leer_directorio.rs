//! Captura EN VIVO del directorio por LDAP de solo lectura, y construccion del
//! grafo de exposicion.
//!
//! Es la frontera walled de la FASE 95 hecha ejecutable: se liga a un Active
//! Directory real (por ejemplo un Samba AD de pruebas en `127.0.0.1`), lee los
//! principales y sus relaciones en solo lectura, construye el grafo y lo audita.
//!
//! Solo se compila con la caracteristica `live-ldap`. La puerta de calidad lo
//! ejecuta cuando hay un directorio al que ligarse, y declara el muro cuando no.
//!
//! Uso:
//!   AEGIS_AD_URL=ldap://127.0.0.1:389 AEGIS_AD_BASE='DC=aegis,DC=local' \
//!   [AEGIS_AD_BIND='CN=Administrator,CN=Users,DC=aegis,DC=local' AEGIS_AD_PASS=...] \
//!   cargo run -p aegis-itdr --features live-ldap --example leer_directorio

#[cfg(feature = "live-ldap")]
fn main() -> std::process::ExitCode {
    use aegis_itdr::directorio::colector::{construir_grafo, LectorLdap};

    let url = std::env::var("AEGIS_AD_URL").unwrap_or_default();
    let base = std::env::var("AEGIS_AD_BASE").unwrap_or_default();
    if url.is_empty() || base.is_empty() {
        eprintln!("MURO: sin AEGIS_AD_URL / AEGIS_AD_BASE no hay directorio al que ligarse.");
        return std::process::ExitCode::from(2);
    }
    let credenciales = match (
        std::env::var("AEGIS_AD_BIND"),
        std::env::var("AEGIS_AD_PASS"),
    ) {
        (Ok(dn), Ok(clave)) if !dn.is_empty() => Some((dn, clave)),
        _ => None,
    };
    let lector = LectorLdap {
        url,
        base,
        credenciales,
    };
    match construir_grafo(&lector) {
        Ok((g, huecos)) => {
            let inf = g.auditar();
            println!(
                "OK: {} principales, {} aristas, {} exposiciones, {} huecos",
                g.principales(),
                g.aristas(),
                inf.exposiciones.len(),
                huecos.len()
            );
            for e in inf.exposiciones.iter().take(10) {
                println!(
                    "  [{}] {} — {}",
                    e.clase.identificador(),
                    e.nombre,
                    e.evidencia
                );
            }
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FALLO al leer el directorio: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "live-ldap"))]
fn main() {
    eprintln!("Este ejemplo necesita la caracteristica `live-ldap`.");
}
