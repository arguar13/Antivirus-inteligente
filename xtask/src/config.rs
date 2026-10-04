//! Los ficheros editables de `tools/config/`, tal cual se escriben.
//!
//! Cada estructura es el espejo de un TOML. Los campos desconocidos se rechazan
//! (`deny_unknown_fields`): una errata en un fichero de configuracion tiene que
//! fallar en voz alta, no ignorarse y dejar una puerta sin comprobar.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::Resultado;

/// Lee y deserializa un TOML de `tools/config/`.
pub fn leer<T: for<'de> Deserialize<'de>>(raiz: &Path, nombre: &str) -> Resultado<T> {
    let ruta = raiz.join("tools/config").join(nombre);
    let texto = std::fs::read_to_string(&ruta)
        .map_err(|e| format!("no se pudo leer {}: {e}", ruta.display()))?;
    toml::from_str(&texto).map_err(|e| format!("{}: {e}", ruta.display()).into())
}

// ── instalables.toml ────────────────────────────────────────────────────────

/// `tools/config/instalables.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instalables {
    /// Los ejecutables que llegan a una maquina.
    pub instalable: Vec<Instalable>,
}

/// Un ejecutable instalable.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instalable {
    /// Nombre del ejecutable.
    pub binario: String,
    /// Crate que lo define.
    pub paquete: String,
    /// `agente`, `servidor` o `enjambre`.
    pub workspace: String,
    /// `endpoint` o `plano-de-control`.
    pub lado: String,
    /// Features del artefacto publicado.
    #[serde(default)]
    pub caracteristicas: Vec<String>,
    /// Features del binario hermetico, si se publica.
    pub hermetico: Option<Vec<String>>,
    /// Una linea para la documentacion.
    pub descripcion: String,
}

// ── capas.toml ──────────────────────────────────────────────────────────────

/// `tools/config/capas.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capas {
    /// Tipos, modelos y primitivas puras.
    pub nucleo: ListaCrates,
    /// Acceso al kernel, al hardware y a los recursos locales.
    pub plataforma: ListaCrates,
    /// Deteccion y analisis.
    pub motores: ListaCrates,
    /// Entrada/salida y ejecutables.
    pub es: ListaCrates,
    /// Herramientas de prueba, fuera de las capas.
    pub herramientas: ListaCrates,
    /// Dependencias que hoy suben de capa, con su plan.
    #[serde(default)]
    pub excepcion: Vec<Excepcion>,
}

/// Una lista de crates.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListaCrates {
    /// Nombres de paquete.
    pub crates: Vec<String>,
}

/// Una dependencia que viola las capas, conocida y con plan.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Excepcion {
    /// Crate que depende.
    pub desde: String,
    /// Crate del que depende.
    pub hacia: String,
    /// Por que ocurre.
    pub causa: String,
    /// Como se elimina.
    pub plan: String,
}

// ── nombres.toml ────────────────────────────────────────────────────────────

/// `tools/config/nombres.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nombres {
    /// Crates.
    pub crates: NombresCrates,
    /// Modulos.
    pub modulos: NombresModulos,
}

/// Plan de nombres de crates.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NombresCrates {
    /// Ya en espanol, o siglas.
    pub conformes: Vec<String>,
    /// Nombre actual -> nombre planificado.
    pub pendientes: BTreeMap<String, String>,
}

/// Plan de nombres de modulos.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NombresModulos {
    /// Nombres impuestos por Rust.
    pub convencion: Vec<String>,
    /// Palabras inglesas que delatan un nombre por traducir.
    pub lexico_ingles: Vec<String>,
    /// Modulos en ingles que ya existian (solo puede menguar).
    #[serde(default)]
    pub pendientes: Vec<String>,
}

// ── condiciones.toml ────────────────────────────────────────────────────────

/// `tools/config/condiciones.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condiciones {
    /// Crates que dependen de hardware o certificado.
    #[serde(default)]
    pub condicional: Vec<Condicional>,
}

/// Un crate condicional.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condicional {
    /// Nombre de paquete.
    #[serde(rename = "crate")]
    pub krate: String,
    /// Que hardware o certificado necesita.
    pub requisito: String,
    /// Donde se detecta en tiempo de ejecucion.
    pub deteccion: Evidencia,
    /// Que se degrada sin el.
    pub degradacion: String,
}

/// Un fichero del repositorio y un texto que tiene que contener.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidencia {
    /// Ruta relativa a la raiz del repositorio.
    pub fichero: String,
    /// Texto literal que tiene que aparecer.
    pub contiene: String,
}

impl Evidencia {
    /// Comprueba la evidencia contra el repositorio.
    pub fn comprobar(&self, raiz: &Path) -> Resultado<()> {
        let texto = std::fs::read_to_string(raiz.join(&self.fichero))
            .map_err(|e| format!("evidencia: no se puede leer {}: {e}", self.fichero))?;
        if texto.contains(&self.contiene) {
            Ok(())
        } else {
            Err(format!(
                "evidencia rota: {} ya no contiene «{}»",
                self.fichero, self.contiene
            )
            .into())
        }
    }
}

// ── documentacion.toml ──────────────────────────────────────────────────────

/// `tools/config/documentacion.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Documentacion {
    /// Tabla de presupuesto.
    pub presupuesto: Presupuesto,
    /// Diagrama C4.
    pub c4: C4,
}

/// Hosts de ejemplo de la tabla de presupuesto.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presupuesto {
    /// Un host por fila.
    pub host: Vec<HostEjemplo>,
}

/// Un host de ejemplo.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEjemplo {
    /// Clase de host.
    pub nombre: String,
    /// RAM total.
    pub ram_gib: u64,
}

/// Datos del diagrama C4.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct C4 {
    /// Sistemas externos.
    pub externo: Vec<Externo>,
    /// Relaciones, cada una con su evidencia.
    pub relacion: Vec<Relacion>,
}

/// Un sistema externo del diagrama.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Externo {
    /// Identificador en el diagrama.
    pub id: String,
    /// Nombre visible.
    pub nombre: String,
    /// Una linea de detalle.
    pub detalle: String,
}

/// Una flecha del diagrama.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relacion {
    /// Origen: un externo o un binario instalable.
    pub desde: String,
    /// Destino: un externo o un binario instalable.
    pub hacia: String,
    /// Texto de la flecha.
    pub etiqueta: String,
    /// Prueba de que la relacion existe en el codigo.
    pub evidencia: Evidencia,
}

// ── kernels.toml ────────────────────────────────────────────────────────────

/// `tools/config/kernels.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kernels {
    /// Parametros de las microVM.
    pub vm: ParametrosVm,
    /// Distribuciones y kernels.
    pub imagen: Vec<Imagen>,
    /// Objetos eBPF que tienen que pasar el verificador en cada kernel.
    pub bpf: Vec<ObjetoBpf>,
    /// Pruebas de extremo a extremo que se ejecutan dentro de cada microVM.
    pub prueba: Vec<PruebaE2e>,
}

/// Recursos y plazos de las microVM.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParametrosVm {
    /// Memoria de cada microVM.
    pub memoria_mib: u32,
    /// CPU virtuales con KVM.
    pub cpus: u32,
    /// CPU virtuales con emulacion completa: QEMU traduce cada vCPU en su
    /// propio hilo del anfitrion (MTTCG), asi que aqui si acortan el arranque.
    pub cpus_emulado: u32,
    /// Plazo con KVM.
    pub plazo_kvm_s: u64,
    /// Plazo con emulacion completa (otra arquitectura).
    pub plazo_emulado_s: u64,
}

/// Una imagen de la matriz.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Imagen {
    /// Identificador corto.
    pub id: String,
    /// Nombre de la distribucion.
    pub distro: String,
    /// `x86_64` o `aarch64`.
    pub arquitectura: String,
    /// Familia de kernel esperada (`5.10`, `6.1`...).
    pub kernel: String,
    /// URL directa de la imagen, o...
    pub url: Option<String>,
    /// ...indice HTML donde buscarla por patron.
    pub indice: Option<String>,
    /// Prefijo del nombre de fichero a buscar en el indice.
    pub patron: Option<String>,
    /// Fichero de sumas publicado por la distribucion.
    pub sumas: String,
    /// `sha256` o `sha512`.
    pub algoritmo: String,
    /// `bios` (por defecto) o `uefi`.
    #[serde(default = "bios")]
    pub firmware: String,
    /// Aclaracion honesta (sustitutos, limitaciones).
    #[serde(default)]
    pub nota: String,
}

fn bios() -> String {
    "bios".into()
}

/// Un objeto eBPF que tiene que pasar el verificador.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjetoBpf {
    /// Nombre sin extension (`aegis_probes`).
    pub objeto: String,
    /// kfuncs que exige; si el kernel no las tiene es `no-aplica`, no fallo.
    #[serde(default)]
    pub requiere_kfunc: Vec<String>,
    /// Version de kernel (`6.7`) desde la que `no-aplica` deja de valer y el
    /// objeto TIENE que pasar. Sin ella, un cambio que pierde kernels que si
    /// tienen las kfunc —otro tipo de programa, por ejemplo— se leeria como
    /// una capacidad ausente y no como el defecto que es.
    #[serde(default)]
    pub obligatorio_desde: Option<String>,
}

/// Una prueba de extremo a extremo.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PruebaE2e {
    /// Identificador.
    pub id: String,
    /// Que demuestra, en una linea.
    pub descripcion: String,
    /// `instalable`: se ejecuta un binario publicado dentro de la microVM.
    /// `cargo-test`: una prueba de integracion compilada estatica.
    pub tipo: String,
    /// Para `instalable`: el binario.
    pub binario: Option<String>,
    /// Para `instalable`: otros instalables que la prueba necesita junto al
    /// binario (el watchdog que lo vigila, por ejemplo). Viajan a la microVM y
    /// la matriz de capacidades les acredita lo que ejercen.
    #[serde(default)]
    pub acompanantes: Vec<String>,
    /// Para `instalable`: la prueba necesita los paquetes .deb y .rpm de la
    /// arquitectura (`tools/empaquetar.sh --matriz`), que viajan en `paquetes/`.
    #[serde(default)]
    pub paquetes: bool,
    /// Para `cargo-test`: el paquete.
    pub paquete: Option<String>,
    /// Para `cargo-test`: el destino de prueba (`tests/<nombre>.rs`).
    pub prueba: Option<String>,
    /// Para `cargo-test`: features.
    #[serde(default)]
    pub caracteristicas: Vec<String>,
}

// ── auditoria.toml ──────────────────────────────────────────────────────────

/// `tools/config/auditoria.toml`: lo que el paquete para auditoria externa no
/// puede sacar del codigo, cada cosa con su evidencia.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auditoria {
    /// Objetivos para los que se resuelve el SBOM.
    pub sbom: ConfigSbom,
    /// Bibliotecas de sistema que entran en el binario sin pasar por cargo.
    #[serde(default)]
    pub sistema: Vec<ComponenteSistema>,
    /// Codigo C que un crate lleva dentro.
    #[serde(default)]
    pub vendorizado: Vec<Vendorizado>,
    /// Prosa del paquete.
    pub textos: TextosAuditoria,
    /// Superficies del alcance del pentest.
    pub superficie: Vec<Superficie>,
    /// Requisitos SLSA y garantias complementarias.
    pub slsa: Vec<RequisitoSlsa>,
}

/// `[sbom]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSbom {
    /// Triple de los binarios hermeticos (el de `tools/ci/hermetico.sh`).
    pub objetivo_hermetico: String,
    /// Triple de los instalables sin version hermetica.
    pub objetivo_nativo: String,
}

/// Una biblioteca de sistema enlazada en el binario.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponenteSistema {
    /// Nombre.
    pub nombre: String,
    /// Expresion SPDX, declarada por el proyecto de origen.
    pub licencia: String,
    /// `todos` o `hermetico`.
    pub aplica: String,
    /// De donde sale la version en el build: `rustc` (MANIFIESTO.txt) o
    /// `dpkg:<paquete>` (medida en el constructor).
    pub version_de: String,
    /// Una linea.
    pub descripcion: String,
}

/// Codigo C que un crate compila desde sus fuentes incluidas.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vendorizado {
    /// Crate que lo lleva dentro.
    #[serde(rename = "crate")]
    pub krate: String,
    /// Nombre del componente C.
    pub nombre: String,
    /// Expresion SPDX, declarada por el proyecto de origen.
    pub licencia: String,
    /// Solo si el instalable se construye con esta feature.
    #[serde(default)]
    pub exige_caracteristica: Option<String>,
    /// Prueba en el repositorio de que se compila incluido.
    #[serde(default)]
    pub evidencia: Option<Evidencia>,
    /// Aclaracion.
    pub nota: String,
}

/// `[textos]`: prosa, sin cifras escritas a mano.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextosAuditoria {
    /// Primer parrafo del indice.
    pub introduccion: String,
    /// Por que las sumas no se versionan y donde estan.
    pub procedencia: String,
    /// Limites conocidos del SBOM.
    pub limitaciones_sbom: Vec<String>,
    /// Primer parrafo del alcance.
    pub alcance_introduccion: String,
    /// Reglas de enfrentamiento.
    pub reglas: Vec<String>,
    /// Fuera de alcance, en general.
    pub fuera_de_alcance: Vec<String>,
    /// Ventanas y contacto.
    pub ventanas_y_contacto: String,
    /// Criterios de cierre.
    pub criterios_de_cierre: Vec<String>,
    /// Donde corre el constructor.
    pub constructor: String,
}

/// Una superficie de ataque del alcance del pentest.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Superficie {
    /// Identificador (ancla del documento).
    pub id: String,
    /// Nombre visible.
    pub nombre: String,
    /// Que es y que busca el atacante.
    pub descripcion: String,
    /// Crates que la implementan.
    pub crates: Vec<String>,
    /// Prefijos de los objetivos de fuzzing que la cubren (`fuzz/Cargo.toml` y
    /// `server/fuzz/Cargo.toml`).
    #[serde(default)]
    pub fuzz: Vec<String>,
    /// Como se sacan del codigo sus puntos de entrada.
    pub extractor: Vec<Extractor>,
    /// Ataques minimos propuestos.
    pub ataques: Vec<String>,
    /// Fuera de alcance en esta superficie.
    #[serde(default)]
    pub fuera: Vec<String>,
}

/// Un extractor de puntos de entrada.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Extractor {
    /// `variantes`, `constantes`, `rutas`, `rpc` o `funciones`.
    pub tipo: String,
    /// Fichero, relativo a la raiz.
    pub fichero: String,
    /// Titulo de la tabla.
    pub titulo: String,
    /// `variantes`: nombre del enum.
    #[serde(default)]
    pub nombre: Option<String>,
    /// `variantes`: se omite la variante con un atributo que contenga esto.
    #[serde(default)]
    pub omitir_atributo: Option<String>,
    /// `variantes`: cada variante exige el objetivo de fuzzing
    /// `<prefijo><variante en minusculas>`.
    #[serde(default)]
    pub fuzz_prefijo: Option<String>,
    /// `constantes`: nombres.
    #[serde(default)]
    pub nombres: Vec<String>,
    /// `rutas`: llamadas que declaran una ruta (`.ruta(`, `.route(`).
    #[serde(default)]
    pub marcas: Vec<String>,
    /// `rutas`: constante del mismo fichero con los pares (metodo, patron)
    /// que se sirven SIN sesion (`RUTAS_PUBLICAS`).
    #[serde(default)]
    pub publicas: Option<String>,
    /// `rutas`: fichero con la tabla RBAC (`const REGLAS`), de la que sale el
    /// permiso y el alcance de cada metodo y ruta.
    #[serde(default)]
    pub reglas: Option<String>,
}

/// Un requisito SLSA (nivel 1 a 3) o una garantia complementaria (nivel 0).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequisitoSlsa {
    /// 1, 2 o 3; 0 = complementaria.
    pub nivel: u8,
    /// Que se exige.
    pub requisito: String,
    /// `cumple`, `parcial` o `no`.
    pub estado: String,
    /// Pruebas en el repositorio. Obligatorias si cumple.
    #[serde(default)]
    pub evidencia: Vec<Evidencia>,
    /// Un fichero cuya existencia contradice un «no» o un «parcial».
    #[serde(default)]
    pub desmiente: Option<String>,
    /// Explicacion.
    pub detalle: String,
}
