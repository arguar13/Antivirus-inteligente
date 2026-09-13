//! Clase de host y presupuesto que le corresponde.
//!
//! Un presupuesto fijo para todo el parque es siempre el equivocado en los dos
//! extremos: castiga al servidor de 512 GB, que tiene RAM de sobra y al que le
//! sale mas barato tener el corpus residente que ir al disco en cada escaneo, y
//! sigue siendo una fraccion notable de una pasarela de 1 GB. Lo que se fija no
//! es una cifra sino una **fraccion de la RAM del host, con suelo y con techo**:
//! la fraccion es lo que hace que escale, el suelo es lo que hace que el agente
//! siga siendo capaz de detectar algo en una maquina pequena, y el techo es lo
//! que impide que en un host enorme el agente crezca solo porque puede.

/// Clase de host, deducida de la RAM total.
///
/// No es cosmetica: cada clase cambia el reparto, el modo de degradacion y lo
/// que el agente mantiene residente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Perfil {
    /// Menos de 2 GiB: pasarelas, IoT industrial, VMs minimas.
    ///
    /// Aqui el agente es, inevitablemente, un porcentaje visible del host. Se
    /// declara en la documentacion en vez de disimularlo.
    Incrustado,
    /// De 2 GiB a 32 GiB: portatiles y escritorios corporativos.
    ///
    /// Es el caso comun y el que se compara contra la competencia.
    Estacion,
    /// Mas de 32 GiB: servidores, hipervisores, hosts de base de datos.
    ///
    /// El agente puede permitirse mas residencia, y le conviene: cada firma que
    /// no esta en RAM es una lectura de disco que compite con la carga real del
    /// host, que es justo lo que el administrador no perdona.
    Servidor,
}

/// Frontera entre [`Perfil::Incrustado`] y [`Perfil::Estacion`].
pub const FRONTERA_INCRUSTADO: u64 = 2 * 1024 * 1024 * 1024;
/// Frontera entre [`Perfil::Estacion`] y [`Perfil::Servidor`].
pub const FRONTERA_SERVIDOR: u64 = 32 * 1024 * 1024 * 1024;

impl Perfil {
    /// Deduce el perfil a partir de la RAM total del host, en bytes.
    #[must_use]
    pub fn de_memoria(memoria_host: u64) -> Self {
        if memoria_host < FRONTERA_INCRUSTADO {
            Perfil::Incrustado
        } else if memoria_host < FRONTERA_SERVIDOR {
            Perfil::Estacion
        } else {
            Perfil::Servidor
        }
    }

    /// Nombre estable para logs, metricas y ficheros de configuracion.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Perfil::Incrustado => "incrustado",
            Perfil::Estacion => "estacion",
            Perfil::Servidor => "servidor",
        }
    }

    /// Lee un perfil por su nombre estable.
    #[must_use]
    pub fn desde_nombre(nombre: &str) -> Option<Self> {
        match nombre {
            "incrustado" => Some(Perfil::Incrustado),
            "estacion" => Some(Perfil::Estacion),
            "servidor" => Some(Perfil::Servidor),
            _ => None,
        }
    }
}

// --- Fracciones y limites -----------------------------------------------------
//
// Las fracciones se expresan en diezmilesimas para no meter coma flotante en un
// calculo del que dependen decisiones de contencion: la aritmetica entera da el
// mismo resultado en todas las maquinas y no tiene sorpresas de redondeo.

/// Fraccion de la RAM del host que el agente puede ocupar en reposo (0,5 %).
pub const FRACCION_REPOSO: u64 = 50;
/// Fraccion de la RAM del host que el agente puede ocupar en pico (2 %).
pub const FRACCION_PICO: u64 = 200;
/// Fraccion de la RAM del host a partir de la cual el agente es un problema (3 %).
pub const FRACCION_TECHO: u64 = 300;
/// Denominador de las fracciones anteriores.
pub const BASE_FRACCION: u64 = 10_000;

/// Suelo del reposo: por debajo de esto el agente no cabe ni con lo fijo.
pub const SUELO_REPOSO: u64 = 48 * 1024 * 1024;
/// Suelo del pico.
pub const SUELO_PICO: u64 = 96 * 1024 * 1024;
/// Suelo del techo duro.
pub const SUELO_TECHO: u64 = 160 * 1024 * 1024;

/// Techo del reposo: mas residencia que esta deja de comprar deteccion.
pub const TOPE_REPOSO: u64 = 384 * 1024 * 1024;
/// Techo del pico.
pub const TOPE_PICO: u64 = 1024 * 1024 * 1024;
/// Techo absoluto: ningun host, por grande que sea, cede mas que esto.
pub const TOPE_TECHO: u64 = 1536 * 1024 * 1024;

/// Parte de la RAM del host que el agente no puede pasar ni para llegar al suelo.
///
/// Los suelos existen para que el agente siga siendo capaz de detectar algo en
/// una maquina pequena, pero un suelo aplicado a ciegas se come el host: 48 MiB
/// en una maquina de 64 MiB no es un agente conservador, es una caida. Cuando el
/// suelo y esta cota chocan gana la cota, y el presupuesto resultante se declara
/// **no viable** en vez de fingir que cabe.
pub const MAXIMO_DEL_HOST: u64 = 4;

/// Reposo por debajo del cual el agente no puede hacer su trabajo.
pub const MINIMO_VIABLE: u64 = SUELO_REPOSO;

fn fraccion(memoria_host: u64, numerador: u64, suelo: u64, tope: u64) -> u64 {
    // u128 porque un host de varios TB por 300 se sale de u64 con holgura
    // suficiente como para que no merezca la pena razonar si se sale o no.
    let bruto = (u128::from(memoria_host) * u128::from(numerador)) / u128::from(BASE_FRACCION);
    let bruto = u64::try_from(bruto).unwrap_or(u64::MAX);
    // El suelo levanta, el tope baja, y la cota del host manda sobre los dos.
    bruto.clamp(suelo, tope).min(memoria_host / MAXIMO_DEL_HOST)
}

/// Presupuesto de memoria del agente en un host concreto.
///
/// Tres regimenes, no uno. La distincion importa porque el numero que el
/// administrador ve en `top` el 99 % del tiempo es [`Presupuesto::reposo`],
/// mientras que el numero que decide si el agente puede hacer su trabajo es
/// [`Presupuesto::pico`], y el que protege al host del propio agente es
/// [`Presupuesto::techo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presupuesto {
    /// Clase de host del que sale este reparto.
    pub perfil: Perfil,
    /// RAM total del host, en bytes.
    pub memoria_host: u64,
    /// Vigilancia sin trabajo pesado: colector, correlacion, reglas residentes.
    pub reposo: u64,
    /// Escaneo completo, recarga de corpus, desempaquetado, triaje de volcado.
    ///
    /// Es transitorio por definicion: quedarse aqui es la senal de contencion.
    pub pico: u64,
    /// A partir de aqui el agente es un riesgo para el host que protege.
    ///
    /// El cgroup lo mata y el watchdog lo levanta. Un EDR que tumba al host es
    /// peor que un EDR ausente, porque el ausente al menos no causa la caida.
    pub techo: u64,
}

impl Presupuesto {
    /// Calcula el presupuesto que corresponde a un host con esa RAM total.
    #[must_use]
    pub fn para(memoria_host: u64) -> Self {
        let perfil = Perfil::de_memoria(memoria_host);
        let reposo = fraccion(memoria_host, FRACCION_REPOSO, SUELO_REPOSO, TOPE_REPOSO);
        let pico = fraccion(memoria_host, FRACCION_PICO, SUELO_PICO, TOPE_PICO);
        let techo = fraccion(memoria_host, FRACCION_TECHO, SUELO_TECHO, TOPE_TECHO);
        // Los topes de cada escalon son independientes, asi que en un host muy
        // grande el reposo podria alcanzar al pico. Se ordenan explicitamente
        // para que la invariante reposo <= pico <= techo no dependa de que los
        // numeros de arriba se elijan con cuidado.
        let pico = pico.max(reposo);
        let techo = techo.max(pico);
        Self {
            perfil,
            memoria_host,
            reposo,
            pico,
            techo,
        }
    }

    /// Presupuesto del host donde corre este proceso.
    ///
    /// Si `/proc/meminfo` no se puede leer se asume [`Perfil::Estacion`] en su
    /// extremo bajo: equivocarse hacia abajo aprieta al agente, equivocarse
    /// hacia arriba aprieta al host, y de los dos errores solo uno tira
    /// maquinas de produccion.
    #[must_use]
    pub fn del_host() -> Self {
        Self::para(crate::medida::memoria_total().unwrap_or(FRONTERA_INCRUSTADO))
    }

    /// Fuerza un perfil concreto conservando la RAM real del host.
    ///
    /// El administrador manda sobre la deteccion automatica: hay hosts de 64 GB
    /// donde el agente no debe pasar de un pelo porque la RAM ya esta vendida a
    /// una JVM, y hosts pequenos donde se quiere maxima deteccion a sabiendas.
    #[must_use]
    pub fn forzando(perfil: Perfil, memoria_host: u64) -> Self {
        // Se toma la RAM representativa del perfil pedido, acotada por la real:
        // pedir perfil de servidor en una maquina de 1 GB no crea memoria.
        let representativa = match perfil {
            Perfil::Incrustado => FRONTERA_INCRUSTADO - 1,
            Perfil::Estacion => FRONTERA_SERVIDOR - 1,
            Perfil::Servidor => u64::MAX / 2,
        };
        let efectiva = memoria_host.min(representativa);
        let mut p = Self::para(efectiva);
        p.perfil = perfil;
        p.memoria_host = memoria_host;
        p
    }

    /// Si este host puede sostener un agente que sirva para algo.
    ///
    /// Un `false` no es un fallo del calculo: es la respuesta correcta para una
    /// maquina donde desplegar el agente haria mas dano que el que evita. Quien
    /// lo consulta decide si arranca en modo minimo o si se niega a arrancar,
    /// pero lo hace sabiendolo en vez de descubrirlo con un OOM a las tres de la
    /// manana.
    #[must_use]
    pub fn es_viable(&self) -> bool {
        self.reposo >= MINIMO_VIABLE
    }

    /// Porcentaje de la RAM del host que ocupa el techo duro, en centesimas.
    ///
    /// Es el numero que hay que ensenar en la documentacion sin adornos: en una
    /// pasarela pequena el agente es un 15 % del host y disimularlo seria
    /// mentir al que decide si lo despliega.
    #[must_use]
    pub fn peso_del_techo(&self) -> u64 {
        if self.memoria_host == 0 {
            return 0;
        }
        (u128::from(self.techo) * 10_000 / u128::from(self.memoria_host)) as u64
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    #[test]
    fn perfil_por_fronteras() {
        assert_eq!(Perfil::de_memoria(512 * MIB), Perfil::Incrustado);
        assert_eq!(Perfil::de_memoria(2 * GIB - 1), Perfil::Incrustado);
        assert_eq!(Perfil::de_memoria(2 * GIB), Perfil::Estacion);
        assert_eq!(Perfil::de_memoria(32 * GIB - 1), Perfil::Estacion);
        assert_eq!(Perfil::de_memoria(32 * GIB), Perfil::Servidor);
    }

    #[test]
    fn pasarela_pequena_usa_los_suelos() {
        // 1 GiB al 0,5 % son 5 MiB: no cabe ni el nucleo. Manda el suelo.
        let p = Presupuesto::para(GIB);
        assert_eq!(p.reposo, SUELO_REPOSO);
        assert_eq!(p.pico, SUELO_PICO);
        assert_eq!(p.techo, SUELO_TECHO);
        assert_eq!(p.perfil, Perfil::Incrustado);
    }

    #[test]
    fn estacion_de_16_gib_escala_por_fraccion() {
        let p = Presupuesto::para(16 * GIB);
        assert_eq!(p.reposo, 16 * GIB * 50 / 10_000); // 81,9 MiB
        assert_eq!(p.pico, 16 * GIB * 200 / 10_000); // 327,7 MiB
        assert_eq!(p.techo, 16 * GIB * 300 / 10_000); // 491,5 MiB
        assert_eq!(p.perfil, Perfil::Estacion);
    }

    #[test]
    fn servidor_grande_usa_los_topes() {
        let p = Presupuesto::para(768 * GIB);
        assert_eq!(p.reposo, TOPE_REPOSO);
        assert_eq!(p.pico, TOPE_PICO);
        assert_eq!(p.techo, TOPE_TECHO);
        assert_eq!(p.perfil, Perfil::Servidor);
    }

    #[test]
    fn los_regimenes_estan_siempre_ordenados() {
        // Barrido por potencias y por valores intermedios: la invariante
        // reposo <= pico <= techo no puede depender de que alguien elija bien
        // los suelos y los topes al tocarlos.
        for exponente in 0..42u32 {
            for factor in [1u64, 3, 7] {
                let memoria = (1u64 << exponente).saturating_mul(factor);
                let p = Presupuesto::para(memoria);
                assert!(p.reposo <= p.pico, "{memoria}: reposo > pico");
                assert!(p.pico <= p.techo, "{memoria}: pico > techo");
            }
        }
    }

    #[test]
    fn host_enorme_no_desborda() {
        let p = Presupuesto::para(u64::MAX);
        assert_eq!(p.techo, TOPE_TECHO);
    }

    #[test]
    fn forzar_perfil_no_inventa_memoria() {
        // Pedir perfil de servidor en una maquina de 1 GiB no puede dar un
        // presupuesto de servidor: la RAM real acota.
        let p = Presupuesto::forzando(Perfil::Servidor, GIB);
        assert_eq!(p.perfil, Perfil::Servidor);
        assert_eq!(p.techo, SUELO_TECHO);
        assert_eq!(p.memoria_host, GIB);
    }

    #[test]
    fn forzar_perfil_bajo_aprieta_un_host_grande() {
        let grande = Presupuesto::para(64 * GIB);
        let apretado = Presupuesto::forzando(Perfil::Incrustado, 64 * GIB);
        assert!(apretado.techo < grande.techo);
        assert_eq!(apretado.memoria_host, 64 * GIB);
    }

    #[test]
    fn el_peso_del_techo_se_declara() {
        // En una pasarela de 1 GiB el agente es un 15,6 % del host.
        assert_eq!(Presupuesto::para(GIB).peso_del_techo(), 1562);
        // En una estacion de 16 GiB es la fraccion del 3 %, menos la centesima
        // que se pierde al truncar la division entera del techo.
        assert_eq!(Presupuesto::para(16 * GIB).peso_del_techo(), 299);
        // En un host de 768 GiB es dos decimas de un uno por ciento.
        assert_eq!(Presupuesto::para(768 * GIB).peso_del_techo(), 19);
    }

    #[test]
    fn el_suelo_nunca_se_come_el_host() {
        // 64 MiB de RAM total: el suelo de 48 MiB seria el 75 % de la maquina.
        // Manda la cota del host, y el presupuesto se declara no viable.
        let p = Presupuesto::para(64 * MIB);
        assert_eq!(p.techo, 16 * MIB);
        assert!(!p.es_viable());
        // A partir de 192 MiB de host el suelo ya cabe en su cuarta parte.
        assert!(Presupuesto::para(192 * MIB).es_viable());
    }

    #[test]
    fn ningun_host_cede_mas_de_su_cuarta_parte() {
        for exponente in 0..42u32 {
            for factor in [1u64, 3, 7] {
                let memoria = (1u64 << exponente).saturating_mul(factor);
                let p = Presupuesto::para(memoria);
                assert!(
                    p.techo <= memoria / MAXIMO_DEL_HOST,
                    "{memoria}: techo {} pasa de la cuarta parte",
                    p.techo
                );
            }
        }
    }

    #[test]
    fn una_pasarela_de_1_gib_sigue_siendo_viable() {
        // La cota del host (256 MiB) no toca los suelos en el caso que importa.
        let p = Presupuesto::para(GIB);
        assert!(p.es_viable());
        assert_eq!(p.techo, SUELO_TECHO);
    }

    #[test]
    fn nombres_van_y_vuelven() {
        for p in [Perfil::Incrustado, Perfil::Estacion, Perfil::Servidor] {
            assert_eq!(Perfil::desde_nombre(p.nombre()), Some(p));
        }
        assert_eq!(Perfil::desde_nombre("mainframe"), None);
    }
}
