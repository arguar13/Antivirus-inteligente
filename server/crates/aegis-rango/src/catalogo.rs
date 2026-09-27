//! El catalogo de tecnicas emulables: al menos una por cada tactica de ATT&CK
//! Enterprise, y todas las que las FASES 81-98 dicen detectar.
//!
//! # Que es cada tecnica aqui, dicho claro
//!
//! Una emulacion **benigna y reversible**: materializa un artefacto marcador en la
//! jaula del rango —el gesto minimo que la deteccion deberia ver— y sabe borrarlo.
//! No hay payload, ni codigo de ataque, ni accion fuera de la jaula: el valor de
//! esta fase esta en MEDIR si la deteccion se dispara, no en la tecnica. Cada una
//! declara el motor del producto que **deberia** verla, que es contra lo que el
//! rango contrasta el veredicto del arbitro.
//!
//! # Tacticas que un EDR no puede ver, dichas como tales
//!
//! Reconocimiento y desarrollo de recursos ocurren en la infraestructura del
//! adversario, no en el endpoint. Estan en el catalogo —para que el informe las
//! cuente— y saldran casi siempre como hueco: un EDR no las cubre, y decirlo es
//! mas honrado que omitirlas.

use aegis_entidad::{entidad, Eid, Motor};

use crate::rango::{ErrorRango, Plataforma, PruebaDeRango, Rango};
use crate::tecnica::{Tactica, Tecnica};

const TODAS: &[Plataforma] = &[Plataforma::Linux, Plataforma::Windows, Plataforma::Macos];
const SOLO_WINDOWS: &[Plataforma] = &[Plataforma::Windows];

/// Una tecnica emulada por un artefacto marcador en la jaula.
///
/// Toda la mecanica de ejecutar/revertir/comprobar es la misma —materializar y
/// borrar un fichero dentro del rango—, asi que se escribe una vez. Lo que cambia
/// entre tecnicas son sus datos: identificador, tactica, plataformas y el motor
/// que deberia detectarla.
pub struct TecnicaMarcador {
    id: &'static str,
    nombre: &'static str,
    tactica: Tactica,
    plataformas: &'static [Plataforma],
    deteccion_esperada: Motor,
}

impl TecnicaMarcador {
    /// Construye una tecnica del catalogo.
    #[must_use]
    pub const fn nueva(
        id: &'static str,
        nombre: &'static str,
        tactica: Tactica,
        plataformas: &'static [Plataforma],
        deteccion_esperada: Motor,
    ) -> TecnicaMarcador {
        TecnicaMarcador {
            id,
            nombre,
            tactica,
            plataformas,
            deteccion_esperada,
        }
    }
}

impl Tecnica for TecnicaMarcador {
    fn id(&self) -> &str {
        self.id
    }

    fn nombre(&self) -> &str {
        self.nombre
    }

    fn tactica(&self) -> Tactica {
        self.tactica
    }

    fn plataformas(&self) -> &[Plataforma] {
        self.plataformas
    }

    fn deteccion_esperada(&self) -> Motor {
        self.deteccion_esperada
    }

    fn entidad_afectada(&self, _rango: &Rango) -> Eid {
        // Una entidad estable y unica por tecnica, del modelo unico. Es la misma
        // por la que la fuente de señales y el arbitro se preguntan.
        entidad::contenido(&format!("rango-tecnica:{}", self.id))
    }

    fn ejecutar(&self, _prueba: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango> {
        // El gesto minimo: un marcador dentro de la jaula. La `PruebaDeRango` que
        // exige la firma es lo que garantiza que esto solo corre en un rango.
        std::fs::write(rango.ruta_marcador(self.id), self.id.as_bytes())?;
        Ok(())
    }

    fn revertir(&self, _prueba: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango> {
        let ruta = rango.ruta_marcador(self.id);
        match std::fs::remove_file(&ruta) {
            Ok(()) => Ok(()),
            // Que ya no este es exactamente lo que se buscaba.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ErrorRango::Es(e)),
        }
    }

    fn exito(&self, rango: &Rango) -> bool {
        rango.ruta_marcador(self.id).exists()
    }
}

/// El catalogo completo: al menos una tecnica por cada una de las catorce tacticas
/// de ATT&CK Enterprise, incluidas las catorce del motor conductual (FASE 19) y
/// las de identidad (FASE 58/95), red (FASE 89) e impacto.
///
/// El motor esperado de cada una es el plano del producto que deberia verla. Donde
/// hoy ese motor no entrega señal al arbitro, el rango lo marcara como hueco: eso
/// es exactamente lo que esta fase existe para medir.
#[must_use]
pub fn catalogo_completo() -> Vec<Box<dyn Tecnica>> {
    use Motor as M;
    use Tactica as T;

    let defs: &[TecnicaMarcador] = &[
        // ── Reconocimiento (TA0043): un EDR casi no lo ve ───────────────────────
        TecnicaMarcador::nueva("T1595", "escaneo activo", T::Reconocimiento, TODAS, M::Wire),
        // ── Desarrollo de recursos (TA0042): fuera del endpoint ─────────────────
        TecnicaMarcador::nueva(
            "T1587",
            "desarrollo de capacidades",
            T::DesarrolloDeRecursos,
            TODAS,
            M::Intel,
        ),
        // ── Acceso inicial (TA0001) ─────────────────────────────────────────────
        TecnicaMarcador::nueva(
            "T1190",
            "explotacion de servicio expuesto",
            T::AccesoInicial,
            TODAS,
            M::Ips,
        ),
        TecnicaMarcador::nueva("T1566", "phishing", T::AccesoInicial, TODAS, M::Wire),
        // ── Ejecucion (TA0002) ──────────────────────────────────────────────────
        TecnicaMarcador::nueva(
            "T1059",
            "interprete de comandos y scripts",
            T::Ejecucion,
            TODAS,
            M::Conductual,
        ),
        TecnicaMarcador::nueva(
            "T1203",
            "explotacion para ejecucion",
            T::Ejecucion,
            TODAS,
            M::Conductual,
        ),
        // ── Persistencia (TA0003) ───────────────────────────────────────────────
        TecnicaMarcador::nueva(
            "T1053",
            "tarea o trabajo programado",
            T::Persistencia,
            TODAS,
            M::Conductual,
        ),
        TecnicaMarcador::nueva(
            "T1547",
            "arranque o inicio de sesion automatico",
            T::Persistencia,
            TODAS,
            M::Conductual,
        ),
        // ── Escalada de privilegios (TA0004) ────────────────────────────────────
        TecnicaMarcador::nueva(
            "T1548",
            "abuso del control de elevacion",
            T::EscaladaDePrivilegios,
            TODAS,
            M::Conductual,
        ),
        TecnicaMarcador::nueva(
            "T1055",
            "inyeccion de codigo en proceso",
            T::EscaladaDePrivilegios,
            TODAS,
            M::MemHunter,
        ),
        // ── Evasion defensiva (TA0005) ──────────────────────────────────────────
        TecnicaMarcador::nueva(
            "T1027",
            "ficheros o informacion ofuscados",
            T::EvasionDefensiva,
            TODAS,
            M::Estatico,
        ),
        TecnicaMarcador::nueva(
            "T1070",
            "borrado de indicadores",
            T::EvasionDefensiva,
            TODAS,
            M::Conductual,
        ),
        TecnicaMarcador::nueva(
            "T1036",
            "enmascaramiento",
            T::EvasionDefensiva,
            TODAS,
            M::Conductual,
        ),
        TecnicaMarcador::nueva(
            "T1222",
            "modificacion de permisos de fichero",
            T::EvasionDefensiva,
            TODAS,
            M::Conductual,
        ),
        // ── Acceso a credenciales (TA0006) ──────────────────────────────────────
        TecnicaMarcador::nueva(
            "T1003",
            "volcado de credenciales del sistema",
            T::AccesoACredenciales,
            TODAS,
            M::MemHunter,
        ),
        TecnicaMarcador::nueva(
            "T1558",
            "kerberoasting / peticion de tickets de servicio",
            T::AccesoACredenciales,
            TODAS,
            M::Itdr,
        ),
        // ── Descubrimiento (TA0007) ─────────────────────────────────────────────
        TecnicaMarcador::nueva(
            "T1057",
            "descubrimiento de procesos",
            T::Descubrimiento,
            TODAS,
            M::Conductual,
        ),
        TecnicaMarcador::nueva(
            "T1087",
            "descubrimiento de cuentas",
            T::Descubrimiento,
            TODAS,
            M::Itdr,
        ),
        // ── Movimiento lateral (TA0008) ─────────────────────────────────────────
        TecnicaMarcador::nueva(
            "T1021",
            "servicios remotos",
            T::MovimientoLateral,
            TODAS,
            M::Itdr,
        ),
        // ── Recoleccion (TA0009) ────────────────────────────────────────────────
        TecnicaMarcador::nueva(
            "T1005",
            "datos del sistema local",
            T::Recoleccion,
            TODAS,
            M::Conductual,
        ),
        // ── Mando y control (TA0011) ────────────────────────────────────────────
        TecnicaMarcador::nueva(
            "T1071",
            "protocolo de capa de aplicacion",
            T::MandoYControl,
            TODAS,
            M::Wire,
        ),
        TecnicaMarcador::nueva(
            "T1105",
            "transferencia de herramienta al host",
            T::MandoYControl,
            TODAS,
            M::Wire,
        ),
        TecnicaMarcador::nueva(
            "T1573",
            "canal cifrado",
            T::MandoYControl,
            TODAS,
            M::L7Hunter,
        ),
        // ── Exfiltracion (TA0010) ───────────────────────────────────────────────
        TecnicaMarcador::nueva(
            "T1041",
            "exfiltracion por el canal de mando",
            T::Exfiltracion,
            TODAS,
            M::L7Hunter,
        ),
        TecnicaMarcador::nueva(
            "T1048",
            "exfiltracion por protocolo alternativo",
            T::Exfiltracion,
            TODAS,
            M::Wire,
        ),
        // ── Impacto (TA0040) ────────────────────────────────────────────────────
        TecnicaMarcador::nueva(
            "T1486",
            "cifrado de datos para impacto (ransomware)",
            T::Impacto,
            TODAS,
            M::Conductual,
        ),
        TecnicaMarcador::nueva(
            "T1490",
            "inhibicion de la recuperacion del sistema",
            T::Impacto,
            SOLO_WINDOWS,
            M::Conductual,
        ),
        TecnicaMarcador::nueva(
            "T1485",
            "destruccion de datos",
            T::Impacto,
            TODAS,
            M::Conductual,
        ),
    ];

    defs.iter()
        .map(|d| {
            Box::new(TecnicaMarcador::nueva(
                d.id,
                d.nombre,
                d.tactica,
                d.plataformas,
                d.deteccion_esperada,
            )) as Box<dyn Tecnica>
        })
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn hay_al_menos_una_tecnica_por_cada_tactica_de_attck() {
        let cat = catalogo_completo();
        let cubiertas: BTreeSet<&'static str> = cat.iter().map(|t| t.tactica().id()).collect();
        for tac in Tactica::todas() {
            assert!(
                cubiertas.contains(tac.id()),
                "la tactica «{}» ({}) no tiene ninguna tecnica en el catalogo",
                tac.nombre(),
                tac.id()
            );
        }
    }

    #[test]
    fn estan_las_catorce_tecnicas_del_motor_conductual() {
        // Las que la FASE 19 dice detectar: si el rango no las contiene, no puede
        // medir si de verdad se detectan.
        let cat = catalogo_completo();
        let ids: BTreeSet<String> = cat.iter().map(|t| t.id().to_string()).collect();
        for id in [
            "T1055", "T1059", "T1486", "T1105", "T1222", "T1036", "T1070", "T1071", "T1053",
            "T1027", "T1548", "T1203", "T1057", "T1021",
        ] {
            assert!(ids.contains(id), "falta la tecnica conductual {id}");
        }
    }

    #[test]
    fn los_identificadores_no_se_repiten_dentro_de_una_tactica() {
        // Un id repetido en la misma tactica desordenaria el informe estable.
        let cat = catalogo_completo();
        let mut pares: Vec<(String, String)> = cat
            .iter()
            .map(|t| (t.tactica().id().to_string(), t.id().to_string()))
            .collect();
        let antes = pares.len();
        pares.sort();
        pares.dedup();
        assert_eq!(antes, pares.len(), "hay un (tactica, id) repetido");
    }
}
