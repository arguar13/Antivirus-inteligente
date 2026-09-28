//! El catalogo de cobertura de bibliotecas TLS (FASE 107).
//!
//! eCapture cubre un punado de bibliotecas por nombre y version. Aqui la cobertura
//! es una TABLA tipada: cada biblioteca dice como se engancha —por simbolo
//! exportado, compartiendo la API de OpenSSL, o requiriendo DERIVAR el offset por
//! analisis del binario (FASE 85 + 100) porque no expone un simbolo estable—. Lo
//! que no se puede enganchar aun se DECLARA, no se finge.

/// Una pila TLS que el cazador conoce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Biblioteca {
    /// OpenSSL 3.x (la rama viva mayoritaria).
    OpenSsl3,
    /// OpenSSL 1.1.x (todavia muy desplegada).
    OpenSsl11,
    /// BoringSSL (Chrome, Android, muchos servidores de Google).
    BoringSsl,
    /// LibreSSL (OpenBSD y derivados).
    LibreSsl,
    /// GnuTLS (`wget`, `apt`, glib-networking).
    GnuTls,
    /// NSS (Firefox y herramientas de Mozilla).
    Nss,
    /// wolfSSL (embebidos e IoT).
    WolfSsl,
    /// `crypto/tls` de Go, enlazado estaticamente.
    GoCryptoTls,
    /// rustls (Rust), enlazado estaticamente.
    Rustls,
    /// JSSE (el TLS de la JVM).
    Jsse,
    /// El TLS de .NET (`System.Net.Security`).
    DotNet,
    /// Node.js (usa su copia de OpenSSL/BoringSSL).
    NodeJs,
    /// Python (usa OpenSSL via el modulo `_ssl`).
    Python,
}

impl Biblioteca {
    /// Nombre legible.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Biblioteca::OpenSsl3 => "OpenSSL 3.x",
            Biblioteca::OpenSsl11 => "OpenSSL 1.1.x",
            Biblioteca::BoringSsl => "BoringSSL",
            Biblioteca::LibreSsl => "LibreSSL",
            Biblioteca::GnuTls => "GnuTLS",
            Biblioteca::Nss => "NSS",
            Biblioteca::WolfSsl => "wolfSSL",
            Biblioteca::GoCryptoTls => "Go crypto/tls",
            Biblioteca::Rustls => "rustls",
            Biblioteca::Jsse => "JSSE (Java)",
            Biblioteca::DotNet => ".NET",
            Biblioteca::NodeJs => "Node.js",
            Biblioteca::Python => "Python",
        }
    }
}

/// Como se engancha una biblioteca.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstrategiaEnganche {
    /// Exporta un simbolo con nombre estable: el caso facil.
    SimboloExportado {
        /// El simbolo de escritura (envio en claro).
        escritura: &'static str,
        /// El simbolo de lectura (recepcion en claro tras descifrar).
        lectura: &'static str,
    },
    /// Comparte la API de OpenSSL (`SSL_read`/`SSL_write`): un solo enganche vale
    /// para todas las que la heredan.
    ApiOpenSsl,
    /// No expone un simbolo estable (estatico, o el simbolo lo elige el compilador):
    /// hay que DERIVAR el offset analizando el binario. Si no se puede,
    /// `NoConcluyente` —nunca una lectura a ciegas—.
    RequiereDerivacion {
        /// Por que no basta un nombre de simbolo.
        nota: &'static str,
    },
}

/// La cobertura de una biblioteca: como se engancha y si esta cubierta hoy.
#[derive(Debug, Clone, Copy)]
pub struct Cobertura {
    /// La biblioteca.
    pub biblioteca: Biblioteca,
    /// Como se engancha.
    pub estrategia: EstrategiaEnganche,
    /// Si esta cubierta y verificada en la maquina de integracion HOY. Lo que no,
    /// se declara.
    pub cubierta_hoy: bool,
}

/// El catalogo completo de cobertura.
pub const COBERTURA: &[Cobertura] = &[
    Cobertura {
        biblioteca: Biblioteca::OpenSsl3,
        estrategia: EstrategiaEnganche::SimboloExportado {
            escritura: "SSL_write",
            lectura: "SSL_read",
        },
        cubierta_hoy: true,
    },
    Cobertura {
        biblioteca: Biblioteca::OpenSsl11,
        estrategia: EstrategiaEnganche::SimboloExportado {
            escritura: "SSL_write",
            lectura: "SSL_read",
        },
        cubierta_hoy: true,
    },
    // BoringSSL y LibreSSL heredan la API de OpenSSL: el mismo enganche vale.
    Cobertura {
        biblioteca: Biblioteca::BoringSsl,
        estrategia: EstrategiaEnganche::ApiOpenSsl,
        cubierta_hoy: true,
    },
    Cobertura {
        biblioteca: Biblioteca::LibreSsl,
        estrategia: EstrategiaEnganche::ApiOpenSsl,
        cubierta_hoy: true,
    },
    Cobertura {
        biblioteca: Biblioteca::GnuTls,
        estrategia: EstrategiaEnganche::SimboloExportado {
            escritura: "gnutls_record_send",
            lectura: "gnutls_record_recv",
        },
        cubierta_hoy: true,
    },
    Cobertura {
        biblioteca: Biblioteca::Nss,
        estrategia: EstrategiaEnganche::SimboloExportado {
            escritura: "PR_Write",
            lectura: "PR_Read",
        },
        cubierta_hoy: true,
    },
    Cobertura {
        biblioteca: Biblioteca::WolfSsl,
        estrategia: EstrategiaEnganche::SimboloExportado {
            escritura: "wolfSSL_write",
            lectura: "wolfSSL_read",
        },
        cubierta_hoy: true,
    },
    // Go: estatico, y el simbolo es `crypto/tls.(*Conn).Write`. Requiere derivar el
    // offset del binario: no hay libssl que enganchar.
    Cobertura {
        biblioteca: Biblioteca::GoCryptoTls,
        estrategia: EstrategiaEnganche::RequiereDerivacion {
            nota: "estatico; el simbolo es crypto/tls.(*Conn).Write, se deriva del binario",
        },
        cubierta_hoy: true,
    },
    // rustls: estatico y sin C ABI estable; se deriva por analisis.
    Cobertura {
        biblioteca: Biblioteca::Rustls,
        estrategia: EstrategiaEnganche::RequiereDerivacion {
            nota: "estatico, sin ABI de C estable: offset derivado por analisis del binario",
        },
        cubierta_hoy: false,
    },
    // Node, Python y .NET usan OpenSSL por debajo: el enganche de OpenSSL vale.
    Cobertura {
        biblioteca: Biblioteca::NodeJs,
        estrategia: EstrategiaEnganche::ApiOpenSsl,
        cubierta_hoy: true,
    },
    Cobertura {
        biblioteca: Biblioteca::Python,
        estrategia: EstrategiaEnganche::ApiOpenSsl,
        cubierta_hoy: true,
    },
    Cobertura {
        biblioteca: Biblioteca::DotNet,
        estrategia: EstrategiaEnganche::ApiOpenSsl,
        cubierta_hoy: false,
    },
    // JSSE: TLS en la JVM, sin simbolo nativo estable; requiere otra via (JVMTI),
    // declarada como incremento.
    Cobertura {
        biblioteca: Biblioteca::Jsse,
        estrategia: EstrategiaEnganche::RequiereDerivacion {
            nota: "TLS en la JVM: no hay simbolo nativo; via JVMTI, declarada",
        },
        cubierta_hoy: false,
    },
];

/// La cobertura de una biblioteca concreta.
#[must_use]
pub fn cobertura_de(b: Biblioteca) -> Option<Cobertura> {
    COBERTURA.iter().copied().find(|c| c.biblioteca == b)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn el_catalogo_cubre_al_menos_doce_bibliotecas_sin_repetir() {
        let unicas: BTreeSet<Biblioteca> = COBERTURA.iter().map(|c| c.biblioteca).collect();
        assert_eq!(
            unicas.len(),
            COBERTURA.len(),
            "no hay bibliotecas repetidas"
        );
        assert!(
            unicas.len() >= 12,
            "cobertura de doce o mas: {}",
            unicas.len()
        );
    }

    #[test]
    fn las_estaticas_requieren_derivacion_no_un_nombre_de_simbolo() {
        // Go y rustls no tienen libssl que enganchar: hay que derivar el offset.
        for b in [Biblioteca::GoCryptoTls, Biblioteca::Rustls] {
            let c = cobertura_de(b).unwrap();
            assert!(
                matches!(c.estrategia, EstrategiaEnganche::RequiereDerivacion { .. }),
                "{}: deberia requerir derivacion",
                b.nombre()
            );
        }
    }

    #[test]
    fn las_que_heredan_openssl_comparten_enganche() {
        for b in [
            Biblioteca::BoringSsl,
            Biblioteca::LibreSsl,
            Biblioteca::NodeJs,
            Biblioteca::Python,
        ] {
            let c = cobertura_de(b).unwrap();
            assert_eq!(
                c.estrategia,
                EstrategiaEnganche::ApiOpenSsl,
                "{}: hereda la API de OpenSSL",
                b.nombre()
            );
        }
    }

    #[test]
    fn lo_no_cubierto_hoy_se_declara_no_se_finge() {
        // rustls, .NET y JSSE se declaran como incrementos; no se marcan cubiertos.
        for b in [Biblioteca::Rustls, Biblioteca::DotNet, Biblioteca::Jsse] {
            assert!(!cobertura_de(b).unwrap().cubierta_hoy, "{}", b.nombre());
        }
    }
}
