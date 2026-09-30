//! El trabajador, solo, con los analizadores de PRUEBA: el ejecutable que las
//! pruebas de confinamiento real arrancan como hijo. En produccion el trabajador
//! es el propio agente con `--trabajador`, sin estos analizadores.

fn main() {
    aegis_trabajador::servidor::servir()
}
