//! # aegis-server — plano de control de AegisCore
//!
//! Recoge la telemetria de la flota, la persiste y ofrece la superficie de
//! administracion del panel.
//!
//! # Los tres transportes
//!
//! | Transporte | Quien lo usa | Formato |
//! |---|---|---|
//! | Nativo de flota (mTLS) | los agentes REALES de AegisCore | protobuf con enmarcado de gRPC sobre TLS mutuo crudo |
//! | gRPC estandar (HTTP/2) | integraciones de terceros, conectores de SIEM | gRPC canonico |
//! | REST (HTTP) | el panel web de administracion | JSON |
//!
//! Los tres desembocan en el MISMO nucleo de dominio ([`dominio::ServicioFlota`]),
//! asi que un endpoint recibe la misma decision entre por donde entre. Esta
//! separacion en biblioteca es lo que permite que las pruebas de integracion
//! levanten el servidor de verdad —con PostgreSQL, Redis y mTLS reales— en vez
//! de comprobar imitaciones.

#![forbid(unsafe_code)]

pub mod almacen;
pub mod api;
pub mod atestacion;
pub mod autodefensa;
pub mod autorizacion;
pub mod ca;
pub mod cache;
pub mod casos;
pub mod config;
pub mod correlador;
pub mod credenciales;
pub mod dominio;
pub mod error;
pub mod eventos;
pub mod firehose;
pub mod flota;
pub mod grpc;
pub mod heuristicas;
pub mod inquilino;
pub mod itdr;
pub mod notificador;
pub mod panel;
pub mod particiones;
pub mod pizarra;
pub mod pqc;
pub mod prediccion;
pub mod reglas;
pub mod remediacion;

/// Codigo generado por tonic a partir de `proto/aegis_fleet.proto`.
pub mod pb {
    #![allow(missing_docs)]
    tonic::include_proto!("aegis.fleet.v1");
}
