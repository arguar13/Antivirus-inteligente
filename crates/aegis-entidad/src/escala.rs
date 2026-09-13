//! Una sola escala de severidad y confianza, con la traduccion de cada motor
//! escrita.
//!
//! # El problema, medido
//!
//! En este arbol habia **once** enumerados distintos de veredicto o severidad, uno
//! por subsistema: tres valores en uno, cinco en otro, un `f32` en el de
//! aprendizaje, un `Verdict` con tres variantes en el triaje del agente. Ninguno
//! estaba mal por separado. Juntos hacen imposible la unica frase que un producto
//! tiene que poder decir:
//!
//! > «Esto es grave» — **y que signifique lo mismo mire quien lo mire.**
//!
//! # Las dos escalas, y por que son dos
//!
//! Se confunden constantemente y son ortogonales:
//!
//! - **Severidad** responde a *«si esto es verdad, cuanto daño hace»*.
//! - **Confianza** responde a *«cuanto creo que es verdad»*.
//!
//! Un cifrado masivo detectado con dudas es **severidad critica, confianza baja**.
//! Un PowerShell codificado detectado con certeza absoluta es **severidad media,
//! confianza alta**. Un solo numero no puede decir ninguna de las dos cosas, y el
//! que lo intenta acaba diciendo la media — que no es ninguna.
//!
//! # La traduccion se declara Y se comprueba
//!
//! Una tabla de traduccion que no se ejecuta se desvia: alguien añade un valor al
//! enumerado de su motor y la tabla se queda con los de ayer. Aqui cada motor
//! declara sus valores nativos y su traduccion, y hay una prueba que **recorre
//! todos** y exige que ninguno se quede sin traducir.

use core::fmt;

/// Cuanto daño hace, si es verdad.
///
/// Cinco valores, los mismos que ya usaba `aegis-case` y que se eligieron
/// entonces por la misma razon: es la escala que un analista lee sin traducir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severidad {
    /// No hace daño; se guarda porque puede hacer falta despues.
    Info,
    /// Molesta, no compromete.
    Baja,
    /// Compromete algo acotado.
    Media,
    /// Compromete una maquina o una cuenta.
    Alta,
    /// Compromete la organizacion, o es irreversible.
    ///
    /// Cifrado, destruccion, exfiltracion de volumen, control del directorio.
    Critica,
}

impl Severidad {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Severidad::Info => "info",
            Severidad::Baja => "baja",
            Severidad::Media => "media",
            Severidad::Alta => "alta",
            Severidad::Critica => "critica",
        }
    }

    /// Todos los valores.
    #[must_use]
    pub fn todas() -> &'static [Severidad] {
        &[
            Severidad::Info,
            Severidad::Baja,
            Severidad::Media,
            Severidad::Alta,
            Severidad::Critica,
        ]
    }
}

impl fmt::Display for Severidad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.nombre())
    }
}

/// Cuanto se cree que es verdad, en centesimas.
///
/// # Lo que este numero significa, dicho para que nadie lo use para otra cosa
///
/// Es **la probabilidad de que la afirmacion sea cierta**, no «lo fuerte que grito
/// el motor». La diferencia importa: una regla que casa con mucho texto no es mas
/// probable que una que casa con poco, y un modelo con una puntuacion de 0,99 no
/// esta al 99 % de acertar salvo que se haya calibrado, que casi nunca se hace.
///
/// Por eso la traduccion de cada motor la escribe **quien conoce su calibracion**,
/// y va en la tabla, no en el motor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Confianza(u8);

impl Confianza {
    /// No se sabe nada.
    pub const NULA: Confianza = Confianza(0);
    /// Indicio.
    pub const BAJA: Confianza = Confianza(30);
    /// Fundada.
    pub const MEDIA: Confianza = Confianza(60);
    /// Solida.
    pub const ALTA: Confianza = Confianza(85);
    /// Observado directamente.
    pub const CIERTA: Confianza = Confianza(99);

    /// Crea una confianza, acotada a cien.
    ///
    /// **No llega nunca a cien.** Cien es certeza absoluta, y un sistema de
    /// deteccion que se declara absolutamente seguro no deja sitio a la duda que
    /// el analista necesita para poder contradecirlo. Lo observado directamente
    /// llega a 99.
    #[must_use]
    pub fn nueva(centesimas: u8) -> Confianza {
        Confianza(centesimas.min(99))
    }

    /// El valor en centesimas.
    #[must_use]
    pub fn centesimas(self) -> u8 {
        self.0
    }

    /// Si aporta algo a una decision.
    ///
    /// Cero no es «probablemente no»: es «no se». Misma disciplina de tri-estado
    /// que el resto del producto.
    #[must_use]
    pub fn aporta(self) -> bool {
        self.0 > 0
    }

    /// Nombre del tramo, para el panel.
    #[must_use]
    pub fn tramo(self) -> &'static str {
        match self.0 {
            0 => "sin-datos",
            1..=44 => "indicio",
            45..=74 => "fundada",
            75..=94 => "solida",
            _ => "observada",
        }
    }
}

impl fmt::Display for Confianza {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} % ({})", self.0, self.tramo())
    }
}

/// En que plano observa un motor.
///
/// # Por que esto existe, y es la pieza que hace util al arbitro
///
/// «Dos motores coinciden» no vale como corroboracion si los dos miran **lo
/// mismo**. Un analisis estatico y un modelo entrenado sobre caracteristicas
/// estaticas comparten la entrada entera: si el fichero esta ofuscado de una forma
/// que los dos no reconocen, los dos fallan **a la vez y por lo mismo**. Contarlos
/// como dos opiniones independientes es contar una opinion dos veces.
///
/// Es exactamente la misma idea que en `aegis-share::procedencia`, donde dos
/// canales que se nutren del mismo no son dos fuentes. Aqui se aplica a los
/// motores propios: el arbitro corrobora contando **planos**, no motores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Plano {
    /// Lo que el fichero ES: cabeceras, firmas, reglas, entropia, modelos sobre
    /// caracteristicas estaticas.
    Estatico,
    /// Lo que el proceso HACE: llamadas al sistema, arbol de procesos, ficheros
    /// tocados.
    Conductual,
    /// Lo que viaja: flujos, protocolos, balizas, prevencion en linea.
    Red,
    /// Lo que hay en la memoria: inyecciones, regiones anonimas ejecutables,
    /// enganches.
    Memoria,
    /// Quien lo hace: autenticacion, tickets, permisos, directorio.
    Identidad,
    /// Lo que hay por debajo del sistema: firmware, arranque medido, hipervisor.
    Plataforma,
    /// Lo que dice alguien de fuera: reputacion, inteligencia compartida,
    /// corroboro del enjambre.
    ///
    /// Es un plano y no un motor mas **porque no observa nada**: repite. Y por eso
    /// nunca decide solo.
    Externo,
}

impl Plano {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Plano::Estatico => "estatico",
            Plano::Conductual => "conductual",
            Plano::Red => "red",
            Plano::Memoria => "memoria",
            Plano::Identidad => "identidad",
            Plano::Plataforma => "plataforma",
            Plano::Externo => "externo",
        }
    }

    /// Si este plano **vio** algo ocurrir, en vez de deducirlo de una forma.
    ///
    /// La diferencia decide el arbitro: quien vio el fichero cifrar ficheros sabe
    /// algo que quien mira sus cabeceras no puede saber, por bien que las mire.
    #[must_use]
    pub fn observa_ejecucion(self) -> bool {
        matches!(self, Plano::Conductual | Plano::Memoria | Plano::Red)
    }

    /// Todos los planos.
    #[must_use]
    pub fn todos() -> &'static [Plano] {
        &[
            Plano::Estatico,
            Plano::Conductual,
            Plano::Red,
            Plano::Memoria,
            Plano::Identidad,
            Plano::Plataforma,
            Plano::Externo,
        ]
    }
}

/// Un motor de deteccion del producto.
///
/// La lista es cerrada y la puerta de calidad la recorre: un motor nuevo que no
/// aparezca aqui no tiene traduccion declarada, y la prueba lo dice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Motor {
    /// Analisis estatico y reglas sobre el fichero.
    Estatico,
    /// Modelo en el endpoint.
    Aprendizaje,
    /// Analisis de comportamiento del proceso.
    Conductual,
    /// Deteccion de syscalls directas.
    SyscallGuard,
    /// Forense de memoria.
    MemHunter,
    /// Diseccion de protocolos.
    Wire,
    /// Prevencion en linea.
    Ips,
    /// Caza en trafico cifrado.
    L7Hunter,
    /// Deteccion de amenazas de identidad.
    Itdr,
    /// Auditoria de firmware.
    FirmwareAudit,
    /// Detonacion en microVM.
    Detonate,
    /// Inteligencia compartida.
    Intel,
    /// Corroboro del enjambre.
    Enjambre,
}

impl Motor {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Motor::Estatico => "estatico",
            Motor::Aprendizaje => "aprendizaje",
            Motor::Conductual => "conductual",
            Motor::SyscallGuard => "syscallguard",
            Motor::MemHunter => "memhunter",
            Motor::Wire => "wire",
            Motor::Ips => "ips",
            Motor::L7Hunter => "l7hunter",
            Motor::Itdr => "itdr",
            Motor::FirmwareAudit => "fwaudit",
            Motor::Detonate => "detonate",
            Motor::Intel => "intel",
            Motor::Enjambre => "enjambre",
        }
    }

    /// En que plano observa.
    ///
    /// # La fila que mas dice de esta tabla
    ///
    /// `Aprendizaje` es `Estatico`, no un plano propio. El modelo del endpoint se
    /// alimenta de caracteristicas estaticas: comparte la entrada entera con el
    /// analisis estatico, y si el fichero esta ofuscado de una forma que ninguno
    /// reconoce, **fallan los dos a la vez y por lo mismo**. Ponerlo en su propio
    /// plano convertiria «el estatico y el modelo coinciden» en corroboracion
    /// independiente, que es la falsa confirmacion mas facil de fabricar.
    #[must_use]
    pub fn plano(self) -> Plano {
        match self {
            Motor::Estatico | Motor::Aprendizaje => Plano::Estatico,
            Motor::Conductual | Motor::SyscallGuard | Motor::Detonate => Plano::Conductual,
            Motor::MemHunter => Plano::Memoria,
            Motor::Wire | Motor::Ips | Motor::L7Hunter => Plano::Red,
            Motor::Itdr => Plano::Identidad,
            Motor::FirmwareAudit => Plano::Plataforma,
            Motor::Intel | Motor::Enjambre => Plano::Externo,
        }
    }

    /// La confianza **maxima** que este motor puede aportar, y por que.
    ///
    /// No es un desprecio a nadie: es que un motor que no puede ver una cosa no
    /// puede estar seguro de ella, por bien que haga lo suyo.
    ///
    /// | Motor | Tope | Por que |
    /// |---|---|---|
    /// | `Detonate` | 99 | **Vio** la muestra ejecutarse y hacer lo que hizo |
    /// | `MemHunter` | 95 | Vio el codigo inyectado en la memoria del proceso |
    /// | `Conductual`, `SyscallGuard` | 90 | Vieron la accion; la intencion se deduce |
    /// | `Ips`, `Wire`, `L7Hunter` | 85 | Vieron el trafico; el contenido puede ir cifrado |
    /// | `Itdr`, `FirmwareAudit` | 85 | Vieron el hecho en su plano |
    /// | `Estatico` | 80 | Una firma acierta mucho y un empaquetador nuevo la esquiva |
    /// | `Aprendizaje` | 70 | Una puntuacion alta **no es** una probabilidad salvo que se haya calibrado |
    /// | `Intel`, `Enjambre` | 75 | Repiten lo que otro observo |
    #[must_use]
    pub fn tope_confianza(self) -> Confianza {
        Confianza(match self {
            Motor::Detonate => 99,
            Motor::MemHunter => 95,
            Motor::Conductual | Motor::SyscallGuard => 90,
            Motor::Ips | Motor::Wire | Motor::L7Hunter | Motor::Itdr | Motor::FirmwareAudit => 85,
            Motor::Estatico => 80,
            Motor::Intel | Motor::Enjambre => 75,
            Motor::Aprendizaje => 70,
        })
    }

    /// Todos los motores.
    #[must_use]
    pub fn todos() -> &'static [Motor] {
        &[
            Motor::Estatico,
            Motor::Aprendizaje,
            Motor::Conductual,
            Motor::SyscallGuard,
            Motor::MemHunter,
            Motor::Wire,
            Motor::Ips,
            Motor::L7Hunter,
            Motor::Itdr,
            Motor::FirmwareAudit,
            Motor::Detonate,
            Motor::Intel,
            Motor::Enjambre,
        ]
    }
}

/// Traduce una severidad de tres niveles a la escala unica.
///
/// La usan los motores que solo distinguen benigno / sospechoso / malicioso. La
/// traduccion **no es lineal a proposito**: «malicioso» de un motor de tres
/// niveles no es «critico», porque ese motor no puede distinguir un adware de un
/// borrador de discos. Sube a `Alta` y deja que el arbitro decida si llega a
/// `Critica` con lo que digan los demas.
#[must_use]
pub fn de_tres_niveles(benigno_sospechoso_malicioso: u8) -> Severidad {
    match benigno_sospechoso_malicioso {
        0 => Severidad::Info,
        1 => Severidad::Media,
        _ => Severidad::Alta,
    }
}

/// Traduce una puntuacion de modelo a confianza.
///
/// # Por que no es la puntuacion tal cual
///
/// Una puntuacion de 0,99 en un modelo sin calibrar **no significa 99 % de
/// probabilidad**: significa «muy arriba en la escala interna del modelo». Pasarla
/// directamente a confianza es afirmar una calibracion que no se ha hecho.
///
/// La conversion comprime hacia el tope del motor y deja la certeza para quien
/// puede tenerla: quien vio la cosa ocurrir.
#[must_use]
pub fn de_puntuacion(puntuacion_milesimas: u16) -> Confianza {
    let p = u32::from(puntuacion_milesimas.min(1000));
    let tope = u32::from(Motor::Aprendizaje.tope_confianza().centesimas());
    Confianza(u8::try_from(p * tope / 1000).unwrap_or(0))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn severidad_y_confianza_son_ejes_distintos() {
        // Un cifrado masivo detectado con dudas es severidad critica y confianza
        // baja. Un PowerShell codificado con certeza es severidad media y
        // confianza alta. Un solo numero no puede decir ninguna de las dos.
        let ransomware_dudoso = (Severidad::Critica, Confianza::BAJA);
        let powershell_seguro = (Severidad::Media, Confianza::ALTA);
        assert!(ransomware_dudoso.0 > powershell_seguro.0);
        assert!(ransomware_dudoso.1 < powershell_seguro.1);
    }

    #[test]
    fn la_confianza_no_llega_nunca_a_cien() {
        // Un sistema que se declara absolutamente seguro no deja sitio a la duda
        // que el analista necesita para poder contradecirlo.
        assert_eq!(Confianza::nueva(255).centesimas(), 99);
        assert_eq!(Confianza::nueva(100).centesimas(), 99);
        assert_eq!(Confianza::CIERTA.centesimas(), 99);
    }

    #[test]
    fn confianza_cero_es_no_se_y_no_probablemente_no() {
        assert!(!Confianza::NULA.aporta());
        assert_eq!(Confianza::NULA.tramo(), "sin-datos");
        assert!(Confianza::BAJA.aporta());
    }

    #[test]
    fn el_aprendizaje_comparte_plano_con_el_estatico() {
        // LA FILA QUE MAS DICE. El modelo se alimenta de caracteristicas
        // estaticas: comparte la entrada entera. Si el fichero esta ofuscado de
        // una forma que ninguno reconoce, fallan los dos a la vez y por lo mismo,
        // y contarlos como dos opiniones es contar una dos veces.
        assert_eq!(Motor::Aprendizaje.plano(), Motor::Estatico.plano());
    }

    #[test]
    fn la_detonacion_y_lo_conductual_comparten_plano() {
        // Los dos ven al proceso HACER cosas. La detonacion lo ve en un
        // laboratorio y lo conductual en la maquina del cliente, pero es la misma
        // clase de evidencia.
        assert_eq!(Motor::Detonate.plano(), Plano::Conductual);
        assert_eq!(Motor::Conductual.plano(), Plano::Conductual);
    }

    #[test]
    fn los_planos_que_observan_ejecucion_estan_declarados() {
        // Quien vio el fichero cifrar ficheros sabe algo que quien mira sus
        // cabeceras no puede saber, por bien que las mire.
        assert!(Plano::Conductual.observa_ejecucion());
        assert!(Plano::Memoria.observa_ejecucion());
        assert!(Plano::Red.observa_ejecucion());
        assert!(!Plano::Estatico.observa_ejecucion());
        assert!(!Plano::Externo.observa_ejecucion());
    }

    #[test]
    fn lo_externo_nunca_es_el_motor_mas_seguro() {
        // Repite lo que otro observo: no puede estar mas seguro que quien lo vio.
        for m in Motor::todos() {
            if m.plano() == Plano::Externo {
                assert!(
                    m.tope_confianza() < Motor::Detonate.tope_confianza(),
                    "«{}» se declara tan seguro como quien lo vio",
                    m.nombre()
                );
            }
        }
    }

    #[test]
    fn todos_los_motores_tienen_plano_y_tope_declarados() {
        // Una tabla de traduccion que no se ejecuta se desvia: alguien añade un
        // motor y la tabla se queda con los de ayer. Esto lo impide.
        assert_eq!(Motor::todos().len(), 13);
        let mut nombres: Vec<&str> = Motor::todos().iter().map(|m| m.nombre()).collect();
        nombres.sort_unstable();
        let antes = nombres.len();
        nombres.dedup();
        assert_eq!(antes, nombres.len(), "dos motores comparten nombre");

        for m in Motor::todos() {
            assert!(
                m.tope_confianza().aporta(),
                "«{}» no puede aportar nada: o tiene tope cero o falta en la tabla",
                m.nombre()
            );
            assert!(
                Plano::todos().contains(&m.plano()),
                "«{}» declara un plano que no esta en la lista",
                m.nombre()
            );
        }
    }

    #[test]
    fn cada_plano_tiene_al_menos_un_motor() {
        // Un plano sin motores es una casilla vacia en el arbitro: el criterio
        // cuenta planos, y uno que nunca se puede llenar sesga el recuento.
        for p in Plano::todos() {
            assert!(
                Motor::todos().iter().any(|m| m.plano() == *p),
                "el plano «{}» no tiene ningun motor",
                p.nombre()
            );
        }
    }

    #[test]
    fn tres_niveles_no_se_traduce_linealmente_a_critico() {
        // «Malicioso» de un motor de tres niveles no es «critico»: ese motor no
        // distingue un adware de un borrador de discos.
        assert_eq!(de_tres_niveles(0), Severidad::Info);
        assert_eq!(de_tres_niveles(1), Severidad::Media);
        assert_eq!(de_tres_niveles(2), Severidad::Alta);
        assert_ne!(de_tres_niveles(2), Severidad::Critica);
    }

    #[test]
    fn una_puntuacion_de_modelo_no_se_toma_por_una_probabilidad() {
        // Un 0,99 en un modelo sin calibrar significa «muy arriba en su escala
        // interna», no «99 % de probabilidad».
        let maxima = de_puntuacion(1000);
        assert_eq!(maxima, Motor::Aprendizaje.tope_confianza());
        assert!(maxima < Confianza::CIERTA);
        assert_eq!(de_puntuacion(0), Confianza::NULA);
        assert_eq!(de_puntuacion(u16::MAX), maxima, "se acota");
        // Y es monotona: mas puntuacion nunca da menos confianza.
        let mut anterior = 0;
        for p in (0..=1000).step_by(50) {
            let c = de_puntuacion(p).centesimas();
            assert!(c >= anterior);
            anterior = c;
        }
    }

    #[test]
    fn los_tramos_de_confianza_cubren_toda_la_escala() {
        // Un tramo sin nombre sale vacio en el panel justo cuando alguien mira.
        for c in 0..=99u8 {
            assert!(!Confianza::nueva(c).tramo().is_empty(), "sin tramo: {c}");
        }
    }

    #[test]
    fn la_severidad_se_ordena_y_se_nombra_entera() {
        assert!(Severidad::Info < Severidad::Critica);
        assert_eq!(Severidad::todas().len(), 5);
        for s in Severidad::todas() {
            assert!(!s.nombre().is_empty());
        }
    }
}
