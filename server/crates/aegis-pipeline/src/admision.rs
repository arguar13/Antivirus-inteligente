//! Cuotas por inquilino y contrapresion hacia los agentes.
//!
//! # La invariante: un cliente ruidoso no degrada a los demas
//!
//! En una plataforma multiinquilino esto no es una cuestion de rendimiento, es
//! de **aislamiento**. Si el volumen de un cliente puede retrasar la ingesta de
//! otro, entonces cualquiera que consiga hacer ruido en el inquilino A puede
//! cegar al inquilino B, y eso es un ataque con un solo paso.
//!
//! # Por que hay DOS cubos por inquilino y no uno
//!
//! Con un solo cubo de fichas, un cliente que emita millones de lineas de log de
//! aplicacion agota su cuota, y a partir de ahi **su propia telemetria de
//! seguridad tampoco entra**. El atacante que este dentro de ese cliente no
//! necesita hacer nada mas: genera ruido en una aplicacion cualquiera y sus
//! propias huellas dejan de subir.
//!
//! Por eso cada inquilino tiene un cubo **general** y una **reserva** que solo
//! pueden usar los eventos de prioridad de seguridad. Un diluvio de log de
//! aplicacion agota el general y no toca la reserva. Y un atacante que
//! inundara con eventos marcados como de seguridad choca con la reserva, que
//! tambien esta acotada: no hay forma de que una etiqueta sirva de llave.
//!
//! # Aritmetica entera, no coma flotante
//!
//! Un cubo de fichas con `f64` da resultados que dependen del orden de las
//! operaciones y del redondeo de cada maquina. En una decision que puede
//! descartar evidencia, dos nodos del plano de control decidiendo distinto sobre
//! el mismo evento es un fallo que nadie reproduce. Aqui las fichas son enteros
//! en milesimas.

use std::collections::BTreeMap;

use aegis_ingest::esquema::{Evento, Prioridad};

/// Milesimas de ficha por ficha.
const MILI: u64 = 1000;

/// Nanosegundos en un segundo.
const SEG_NS: u64 = 1_000_000_000;

/// Inquilinos maximos con cubo a la vez.
pub const MAX_INQUILINOS: usize = 4096;

/// Cuota de un inquilino.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cuota {
    /// Eventos por segundo sostenidos.
    pub eventos_por_segundo: u64,
    /// Rafaga: cuantos eventos puede meter de golpe tras un rato callado.
    ///
    /// Sin rafaga, un endpoint que acaba de reconectar con un lote de mil
    /// eventos se veria estrangulado justo cuando entrega lo que nadie vio. Con
    /// rafaga, entrega el lote y despues vuelve al ritmo sostenido.
    pub rafaga: u64,
    /// Parte de la rafaga reservada a la telemetria de seguridad.
    ///
    /// Ver el encabezado del modulo: es lo que impide que el ruido de una
    /// aplicacion apague las huellas del atacante que lo genera.
    pub reserva_seguridad: u64,
}

impl Default for Cuota {
    /// La cuota por defecto de un inquilino nuevo.
    ///
    /// Mil eventos por segundo sostenidos con rafaga de diez mil: da holgura a
    /// una flota mediana y sigue siendo un techo. Un cliente que necesite mas lo
    /// pide y se le configura; lo que no puede pasar es que no haya techo.
    fn default() -> Cuota {
        Cuota {
            eventos_por_segundo: 1000,
            rafaga: 10_000,
            reserva_seguridad: 2000,
        }
    }
}

/// Lo que se decidio sobre un evento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Entra.
    Admitido,
    /// El inquilino ha agotado su cuota.
    ///
    /// Lleva cuanto habria que esperar: sin ese numero, el agente reintenta a
    /// ciegas y el estrangulamiento se convierte en una tormenta de reintentos
    /// que cuesta mas que el trafico original.
    FueraDeCuota {
        /// Milisegundos hasta que vuelva a haber sitio.
        reintentar_en_ms: u64,
    },
    /// El plano de control entero va saturado.
    Saturado,
}

/// Lo que el plano de control le dice al agente sobre el ritmo.
///
/// Viaja en la respuesta del canal de control. Es la ultima pata de la
/// contrapresion de extremo a extremo: sin ella, el agente solo se entera de que
/// va rapido cuando le rechazan eventos, que es tarde.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Senal {
    /// Ritmo normal.
    Normal,
    /// Reduce el ritmo.
    Frena,
    /// Para de enviar y guarda en disco.
    Para,
}

/// Ocupacion, en centesimas, a partir de la cual se pide freno.
pub const MARCA_FRENA: u32 = 70;
/// Ocupacion, en centesimas, a partir de la cual se pide parar.
pub const MARCA_PARA: u32 = 90;
/// Ocupacion, en centesimas, por debajo de la cual se vuelve a ritmo normal.
///
/// Bien por debajo de [`MARCA_FRENA`]: con un solo umbral, una flota de cien mil
/// agentes oscilando alrededor de el arranca y frena a la vez —todos reciben la
/// misma senal en el mismo instante— y el resultado es un oscilador de escala
/// completa. La histeresis lo amortigua.
pub const MARCA_NORMAL: u32 = 40;

/// Contadores de la admision.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Contadores {
    /// Eventos admitidos.
    pub admitidos: u64,
    /// Eventos rechazados por cuota del inquilino.
    pub fuera_de_cuota: u64,
    /// Eventos rechazados por saturacion global.
    pub saturados: u64,
    /// Eventos de seguridad que entraron gracias a la reserva.
    ///
    /// Que esta cifra deje de ser cero significa que el ruido de ese cliente
    /// habria tapado su propia telemetria de seguridad.
    pub salvados_por_la_reserva: u64,
    /// Veces que se paso a pedir freno.
    pub frenadas: u64,
}

/// Cubo de fichas entero.
#[derive(Debug, Clone, Copy)]
struct Cubo {
    /// Fichas disponibles, en milesimas.
    fichas_mili: u64,
    /// Techo, en milesimas.
    tope_mili: u64,
    /// Relleno por segundo, en milesimas.
    ritmo_mili: u64,
    /// Ultima vez que se relleno.
    ultimo_ns: u64,
}

impl Cubo {
    fn nuevo(tope: u64, ritmo: u64, ahora_ns: u64) -> Cubo {
        Cubo {
            fichas_mili: tope.saturating_mul(MILI),
            tope_mili: tope.saturating_mul(MILI),
            ritmo_mili: ritmo.saturating_mul(MILI),
            ultimo_ns: ahora_ns,
        }
    }

    /// Rellena segun el tiempo transcurrido.
    ///
    /// El reloj que retrocede —un ajuste de NTP, una maquina virtual que se
    /// suspende— no rellena nada en vez de producir un desbordamiento: sin este
    /// cuidado, un salto hacia atras deja `ultimo_ns` en el futuro y el cubo no
    /// se rellena nunca mas.
    fn rellenar(&mut self, ahora_ns: u64) {
        if ahora_ns <= self.ultimo_ns {
            self.ultimo_ns = ahora_ns;
            return;
        }
        let transcurrido = ahora_ns - self.ultimo_ns;
        let ganadas = u128::from(transcurrido) * u128::from(self.ritmo_mili) / u128::from(SEG_NS);
        let ganadas = u64::try_from(ganadas).unwrap_or(u64::MAX);
        self.fichas_mili = self.fichas_mili.saturating_add(ganadas).min(self.tope_mili);
        self.ultimo_ns = ahora_ns;
    }

    fn tomar(&mut self, cuantas: u64) -> bool {
        let coste = cuantas.saturating_mul(MILI);
        if self.fichas_mili >= coste {
            self.fichas_mili -= coste;
            return true;
        }
        false
    }

    /// Milisegundos hasta tener `cuantas` fichas.
    fn espera_ms(&self, cuantas: u64) -> u64 {
        let coste = cuantas.saturating_mul(MILI);
        if self.fichas_mili >= coste || self.ritmo_mili == 0 {
            return 0;
        }
        let faltan = coste - self.fichas_mili;
        let ms = u128::from(faltan) * 1000 / u128::from(self.ritmo_mili);
        u64::try_from(ms).unwrap_or(u64::MAX).max(1)
    }
}

#[derive(Debug)]
struct Estado {
    cuota: Cuota,
    general: Cubo,
    reserva: Cubo,
}

/// La puerta de entrada del plano de control.
#[derive(Debug)]
pub struct Admision {
    por_defecto: Cuota,
    inquilinos: BTreeMap<String, Estado>,
    /// Ocupacion global publicada por el resto de la canalizacion, en centesimas.
    ocupacion: u32,
    senal: Senal,
    contadores: Contadores,
}

impl Default for Admision {
    fn default() -> Admision {
        Admision::nueva(Cuota::default())
    }
}

impl Admision {
    /// Crea la admision con una cuota por defecto.
    #[must_use]
    pub fn nueva(por_defecto: Cuota) -> Admision {
        Admision {
            por_defecto,
            inquilinos: BTreeMap::new(),
            ocupacion: 0,
            senal: Senal::Normal,
            contadores: Contadores::default(),
        }
    }

    /// Contadores acumulados.
    #[must_use]
    pub fn contadores(&self) -> Contadores {
        self.contadores
    }

    /// Senal de ritmo que hay que devolver a los agentes.
    #[must_use]
    pub fn senal(&self) -> Senal {
        self.senal
    }

    /// Configura la cuota de un inquilino.
    pub fn configurar(&mut self, inquilino: &str, cuota: Cuota, ahora_ns: u64) {
        let estado = Estado {
            cuota,
            general: Cubo::nuevo(cuota.rafaga, cuota.eventos_por_segundo, ahora_ns),
            reserva: Cubo::nuevo(
                cuota.reserva_seguridad,
                cuota.eventos_por_segundo / 4 + 1,
                ahora_ns,
            ),
        };
        self.inquilinos.insert(inquilino.to_string(), estado);
    }

    /// Cuota vigente de un inquilino.
    #[must_use]
    pub fn cuota(&self, inquilino: &str) -> Cuota {
        self.inquilinos
            .get(inquilino)
            .map_or(self.por_defecto, |e| e.cuota)
    }

    /// Publica la ocupacion global de la canalizacion, en centesimas.
    ///
    /// La calcula quien tiene los numeros —profundidad de las colas, memoria del
    /// reordenador, retraso de la base de datos— y se traduce aqui a la senal
    /// que viaja hasta el agente, con histeresis.
    pub fn publicar_ocupacion(&mut self, centesimas: u32) {
        self.ocupacion = centesimas.min(100);
        let nueva = match (self.senal, self.ocupacion) {
            (_, o) if o >= MARCA_PARA => Senal::Para,
            (Senal::Normal, o) if o >= MARCA_FRENA => Senal::Frena,
            (Senal::Normal, _) => Senal::Normal,
            (_, o) if o <= MARCA_NORMAL => Senal::Normal,
            (s, _) => s.min(Senal::Frena).max(Senal::Frena),
        };
        if nueva > self.senal {
            self.contadores.frenadas += 1;
        }
        self.senal = nueva;
    }

    /// Decide sobre un evento.
    pub fn admitir(&mut self, evento: &Evento, ahora_ns: u64) -> Decision {
        if self.ocupacion >= MARCA_PARA && evento.prioridad() != Prioridad::Seguridad {
            // Con el plano de control al borde, lo primero que deja de entrar es
            // lo que menos cuesta perder. La telemetria de seguridad sigue
            // pasando mientras haya cuota: es la razon de que el sistema exista.
            self.contadores.saturados += 1;
            return Decision::Saturado;
        }

        if !self.inquilinos.contains_key(&evento.inquilino) {
            if self.inquilinos.len() >= MAX_INQUILINOS {
                // Sin cubo no hay cuota, y sin cuota no hay aislamiento. Se
                // rechaza: aceptar sin limite es exactamente lo que la
                // invariante prohibe.
                self.contadores.fuera_de_cuota += 1;
                return Decision::FueraDeCuota {
                    reintentar_en_ms: 1000,
                };
            }
            let cuota = self.por_defecto;
            self.configurar(&evento.inquilino, cuota, ahora_ns);
        }

        let es_seguridad = evento.prioridad() == Prioridad::Seguridad;
        let Some(estado) = self.inquilinos.get_mut(&evento.inquilino) else {
            return Decision::FueraDeCuota {
                reintentar_en_ms: 1000,
            };
        };
        estado.general.rellenar(ahora_ns);
        estado.reserva.rellenar(ahora_ns);

        if estado.general.tomar(1) {
            self.contadores.admitidos += 1;
            return Decision::Admitido;
        }
        if es_seguridad && estado.reserva.tomar(1) {
            self.contadores.admitidos += 1;
            self.contadores.salvados_por_la_reserva += 1;
            return Decision::Admitido;
        }
        let espera = if es_seguridad {
            estado.general.espera_ms(1).min(estado.reserva.espera_ms(1))
        } else {
            estado.general.espera_ms(1)
        };
        self.contadores.fuera_de_cuota += 1;
        Decision::FueraDeCuota {
            reintentar_en_ms: espera,
        }
    }

    /// Filtra un lote, devolviendo lo admitido.
    pub fn filtrar(&mut self, lote: Vec<Evento>, ahora_ns: u64) -> Vec<Evento> {
        let mut salida = Vec::with_capacity(lote.len());
        for e in lote {
            if self.admitir(&e, ahora_ns) == Decision::Admitido {
                salida.push(e);
            }
        }
        salida
    }

    /// Olvida el estado de un inquilino que ya no existe.
    pub fn olvidar(&mut self, inquilino: &str) {
        self.inquilinos.remove(inquilino);
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::pruebas_comunes::{evento, evento_de_seguridad};

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn cuota_pequena() -> Cuota {
        Cuota {
            eventos_por_segundo: 10,
            rafaga: 20,
            reserva_seguridad: 5,
        }
    }

    #[test]
    fn un_inquilino_que_satura_su_cuota_no_afecta_a_otro() {
        // LA INVARIANTE DE LA FASE. Si el volumen de un cliente puede retrasar
        // la ingesta de otro, cualquiera que haga ruido en A ciega a B.
        let mut a = Admision::nueva(cuota_pequena());
        a.configurar("ruidoso", cuota_pequena(), AHORA);
        a.configurar("tranquilo", cuota_pequena(), AHORA);

        for _ in 0..1000 {
            let _ = a.admitir(&evento("ruidoso", "x", AHORA), AHORA);
        }
        assert!(a.contadores().fuera_de_cuota > 900);

        // Y el tranquilo entra sin enterarse.
        for i in 0..20 {
            assert_eq!(
                a.admitir(&evento("tranquilo", &format!("t{i}"), AHORA), AHORA),
                Decision::Admitido
            );
        }
    }

    #[test]
    fn el_ruido_de_una_aplicacion_no_apaga_las_huellas_del_atacante() {
        // EL CASO QUE LA RESERVA CIERRA. Con un solo cubo, el atacante genera
        // ruido en una aplicacion cualquiera y su propia telemetria de seguridad
        // deja de subir. No tiene que hacer nada mas.
        let mut a = Admision::nueva(cuota_pequena());
        a.configurar("victima", cuota_pequena(), AHORA);
        for i in 0..1000 {
            let _ = a.admitir(&evento("victima", &format!("ruido{i}"), AHORA), AHORA);
        }
        // El cubo general esta seco.
        assert!(matches!(
            a.admitir(&evento("victima", "mas-ruido", AHORA), AHORA),
            Decision::FueraDeCuota { .. }
        ));
        // Y la telemetria de seguridad sigue entrando.
        assert_eq!(
            a.admitir(&evento_de_seguridad("victima", "huella", AHORA), AHORA),
            Decision::Admitido
        );
        assert!(a.contadores().salvados_por_la_reserva > 0);
    }

    #[test]
    fn la_reserva_tambien_tiene_techo_para_que_la_etiqueta_no_sea_una_llave() {
        let mut a = Admision::nueva(cuota_pequena());
        a.configurar("cliente", cuota_pequena(), AHORA);
        let mut admitidos = 0;
        for i in 0..10_000 {
            if a.admitir(
                &evento_de_seguridad("cliente", &format!("s{i}"), AHORA),
                AHORA,
            ) == Decision::Admitido
            {
                admitidos += 1;
            }
        }
        assert!(
            admitidos <= 30,
            "entraron {admitidos}, la reserva no es un pase"
        );
    }

    #[test]
    fn la_rafaga_deja_entregar_el_lote_de_un_endpoint_que_reconecta() {
        // Sin rafaga, un endpoint que acaba de reconectar se veria estrangulado
        // justo cuando entrega lo que nadie vio.
        let mut a = Admision::nueva(cuota_pequena());
        a.configurar("c", cuota_pequena(), AHORA);
        let mut entraron = 0;
        for i in 0..20 {
            if a.admitir(&evento("c", &format!("e{i}"), AHORA), AHORA) == Decision::Admitido {
                entraron += 1;
            }
        }
        assert_eq!(entraron, 20, "la rafaga entera");
    }

    #[test]
    fn el_cubo_se_rellena_con_el_tiempo() {
        let mut a = Admision::nueva(cuota_pequena());
        a.configurar("c", cuota_pequena(), AHORA);
        for i in 0..20 {
            let _ = a.admitir(&evento("c", &format!("e{i}"), AHORA), AHORA);
        }
        assert!(matches!(
            a.admitir(&evento("c", "x", AHORA), AHORA),
            Decision::FueraDeCuota { .. }
        ));
        // Un segundo despues hay diez fichas mas.
        let mut entraron = 0;
        for i in 0..10 {
            if a.admitir(&evento("c", &format!("d{i}"), AHORA), AHORA + SEG) == Decision::Admitido {
                entraron += 1;
            }
        }
        assert_eq!(entraron, 10);
    }

    #[test]
    fn el_rechazo_dice_cuanto_esperar() {
        // Sin ese numero, el agente reintenta a ciegas y el estrangulamiento se
        // convierte en una tormenta de reintentos que cuesta mas que el trafico
        // original.
        let mut a = Admision::nueva(cuota_pequena());
        a.configurar("c", cuota_pequena(), AHORA);
        for i in 0..25 {
            let _ = a.admitir(&evento("c", &format!("e{i}"), AHORA), AHORA);
        }
        match a.admitir(&evento("c", "x", AHORA), AHORA) {
            Decision::FueraDeCuota { reintentar_en_ms } => {
                assert!(
                    reintentar_en_ms > 0 && reintentar_en_ms <= 1000,
                    "{reintentar_en_ms}"
                );
            }
            otro => panic!("{otro:?}"),
        }
    }

    #[test]
    fn un_reloj_que_retrocede_no_deja_el_cubo_seco_para_siempre() {
        // Un ajuste de NTP o una maquina virtual que se suspende. Sin el cuidado,
        // `ultimo_ns` se queda en el futuro y el cubo no se rellena nunca mas.
        let mut a = Admision::nueva(cuota_pequena());
        a.configurar("c", cuota_pequena(), AHORA);
        for i in 0..25 {
            let _ = a.admitir(&evento("c", &format!("e{i}"), AHORA), AHORA + 3600 * SEG);
        }
        // El reloj vuelve atras una hora.
        let _ = a.admitir(&evento("c", "y", AHORA), AHORA);
        // Y a partir de ahi sigue rellenando con normalidad.
        let mut entraron = 0;
        for i in 0..10 {
            if a.admitir(&evento("c", &format!("z{i}"), AHORA), AHORA + 5 * SEG)
                == Decision::Admitido
            {
                entraron += 1;
            }
        }
        assert!(entraron >= 10, "entraron {entraron}");
    }

    // --- La senal de contrapresion -------------------------------------------

    #[test]
    fn la_senal_tiene_histeresis() {
        // Con un solo umbral, una flota de cien mil agentes oscilando alrededor
        // arranca y frena a la vez: un oscilador de escala completa.
        let mut a = Admision::default();
        assert_eq!(a.senal(), Senal::Normal);
        a.publicar_ocupacion(75);
        assert_eq!(a.senal(), Senal::Frena);
        a.publicar_ocupacion(60);
        assert_eq!(a.senal(), Senal::Frena, "no vuelve a la primera");
        a.publicar_ocupacion(35);
        assert_eq!(a.senal(), Senal::Normal);
    }

    #[test]
    fn por_encima_de_la_marca_de_parar_se_pide_parar() {
        let mut a = Admision::default();
        a.publicar_ocupacion(95);
        assert_eq!(a.senal(), Senal::Para);
        a.publicar_ocupacion(80);
        assert_eq!(a.senal(), Senal::Frena);
    }

    #[test]
    fn con_el_plano_de_control_al_borde_la_seguridad_sigue_pasando() {
        // Es la razon de que el sistema exista.
        let mut a = Admision::default();
        a.publicar_ocupacion(95);
        assert_eq!(
            a.admitir(&evento("c", "app", AHORA), AHORA),
            Decision::Saturado
        );
        assert_eq!(
            a.admitir(&evento_de_seguridad("c", "grave", AHORA), AHORA),
            Decision::Admitido
        );
    }

    #[test]
    fn el_numero_de_inquilinos_esta_acotado_y_el_que_sobra_no_entra_sin_cuota() {
        // Aceptar sin limite es exactamente lo que la invariante prohibe.
        let mut a = Admision::default();
        for i in 0..MAX_INQUILINOS {
            let _ = a.admitir(&evento(&format!("c{i}"), "x", AHORA), AHORA);
        }
        assert!(matches!(
            a.admitir(&evento("el-que-sobra", "x", AHORA), AHORA),
            Decision::FueraDeCuota { .. }
        ));
    }

    #[test]
    fn la_decision_es_identica_en_dos_nodos_del_plano_de_control() {
        // Aritmetica entera: dos nodos decidiendo distinto sobre el mismo evento
        // es un fallo que nadie reproduce.
        let secuencia = || {
            let mut a = Admision::nueva(cuota_pequena());
            a.configurar("c", cuota_pequena(), AHORA);
            (0..100)
                .map(|i| {
                    a.admitir(
                        &evento("c", &format!("e{i}"), AHORA),
                        AHORA + u64::try_from(i).unwrap_or(0) * SEG / 7,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(secuencia(), secuencia());
    }

    #[test]
    fn filtrar_un_lote_deja_pasar_lo_que_cabe_en_la_cuota() {
        let mut a = Admision::nueva(cuota_pequena());
        a.configurar("c", cuota_pequena(), AHORA);
        let lote: Vec<Evento> = (0..100)
            .map(|i| evento("c", &format!("e{i}"), AHORA))
            .collect();
        let pasan = a.filtrar(lote, AHORA);
        assert_eq!(pasan.len(), 20, "la rafaga");
    }
}
