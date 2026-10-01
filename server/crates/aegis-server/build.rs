//! Genera el codigo de la superficie gRPC estandar a partir del `.proto`.
//!
//! Se genera el lado SERVIDOR —que es el papel del binario— y tambien el
//! CLIENTE, que no se usa en produccion pero permite que las pruebas llamen a
//! la superficie gRPC igual que lo haria una integracion de terceros. Probar un
//! transporte con su propio cliente canonico es la unica forma de saber que un
//! tercero podra hablar con el.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../../proto/aegis_fleet.proto";
    println!("cargo:rerun-if-changed={proto}");
    // `sqlx::migrate!` empotra server/migrations al compilar, pero un macro
    // procedimental no puede pedir a cargo que vigile un directorio: sin
    // esto, anadir una migracion sin tocar ningun .rs dejaba un binario (y
    // unas pruebas) con las migraciones de antes. Es lo que recomienda sqlx.
    println!("cargo:rerun-if-changed=../../migrations");
    // `sqlx::migrate!` empotra las migraciones al compilar: sin esto, una
    // migracion NUEVA no recompila el crate y el binario arranca sin ella.
    println!("cargo:rerun-if-changed=../../migrations");
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[proto], &["../../proto"])?;
    Ok(())
}
