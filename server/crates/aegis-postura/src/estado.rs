//! El estado de la nube, reconstruido plegando eventos.
//!
//! # No hay instantanea: hay una historia
//!
//! El plano de control ingiere eventos, no configuraciones. Nadie le ha dado a
//! este producto credenciales para preguntar a AWS «¿que politica tiene este
//! cubo?». Lo que tiene es la lista de llamadas que alguien hizo: «a las 10:14
//! `admin` puso esta politica», «a las 10:20 la quito». El estado se obtiene
//! **plegando** esa lista en orden de ocurrencia, como se reconstruye una base
//! de datos desde su diario.
//!
//! Tres reglas hacen que el pliegue sea correcto:
//!
//! 1. **Orden de ocurrencia, no de llegada.** `PutBucketPolicy` publica y luego
//!    `DeleteBucketPolicy` es un cubo cerrado; al reves, uno abierto. Los
//!    conectores entregan desordenado, asi que se ordena por
//!    [`Evento::ocurrio_ns`] y, a igualdad, por [`Evento::id`] —arbitrario pero
//!    determinista: la misma entrada da siempre el mismo estado—.
//! 2. **Idempotencia.** La entrega es al-menos-una-vez por contrato; un evento
//!    repetido (mismo [`Evento::id`]) se pliega una vez y se cuenta como
//!    duplicado.
//! 3. **Una llamada que fallo no configuro nada.** `errorCode` en CloudTrail,
//!    `status.code` en GCP, `Failure` en Azure: el estado no cambia. Se cuenta,
//!    porque un `AccessDenied` sobre `PutBucketPolicy` es interesante para la
//!    deteccion, pero no para la postura.
//!
//! # EL MURO
//!
//! **Lo que no se vio en la ventana no se sabe.** Un cubo que se hizo publico
//! hace un año, antes de que el cliente conectara CloudTrail, no aparece en
//! ningun evento de la ventana y este modulo no lo ve. Por eso:
//!
//! - Una comprobacion sin eventos que la toquen dice `SinDatos`, **nunca**
//!   `Cumple`.
//! - De lo que se configura por **deltas** (concesiones de IAM, entradas de un
//!   grupo de seguridad) solo se afirma sobre la concesion o la entrada
//!   observada: «esta concesion de `AdministratorAccess` se retiro», no «esta
//!   identidad no es administradora» —lo concedido antes de la ventana no se ve—.
//! - De lo que se escribe **entero** (una regla de NSG, una regla de
//!   cortafuegos de GCP, el estado de un trail, la politica de un cubo) si se
//!   afirma el estado completo, porque el evento lo trae completo.
//! - La antiguedad de una clave solo se afirma si se vio su creacion. Una clave
//!   que se ve EN USO sin haber visto su alta es exactamente el caso que el
//!   muro produce, y sale como `SinDatos` con ese motivo.
//! - Y el muro tiene un caso cruel que se declara: **apagar el registro apaga
//!   la fuente de esta postura**. Tras un `StopLogging` del unico trail, lo
//!   siguiente no llega. Solo se ve lo que otra fuente sigue registrando.

use std::collections::{BTreeMap, BTreeSet};

use aegis_entidad::{entidad, Eid};
use aegis_ingest::esquema::{recortar, Clase as ClaseEvento, ConfianzaReloj, Evento};
use serde_json::Value;

use crate::entrada::{
    arn_iam, booleano, campo, ci, entero, lista_con_tope, ruta, texto, Desenlace, Detalle, Llamada,
};
use crate::modelo::{
    Estado, Evidencia, Proveedor, Referencia, Resultado, ALM_001, CLV_001, IAM_001, IAM_002,
    LOG_001, LOG_002, MAX_RECURSO, RED_001,
};
use crate::politica::{self, Lectura};

/// Eventos maximos que se pliegan de una vez.
///
/// Lo que excede se cuenta en [`EstadoNube::descartados`] y el informe deja de
/// afirmar `Cumple` en todas las comprobaciones: un estado reconstruido sin los
/// ultimos eventos puede haberse perdido justo la correccion o justo el
/// cambio.
pub const MAX_EVENTOS: usize = 1_000_000;

/// Piezas maximas del estado (concesiones, cubos, claves, reglas, registros).
///
/// Cada una la crea un evento que escribe un atacante; sin tope, un millon de
/// `AttachUserPolicy` inventadas serian un millon de entradas. Al llegar al
/// tope se deja de anadir y se marca [`EstadoNube::desbordado`].
pub const MAX_PIEZAS: usize = 200_000;

/// Cuerpos de Azure pendientes de su evento final.
pub const MAX_PENDIENTES: usize = 10_000;

/// Tras apagar el registro, cuanto tiempo se buscan acciones de gestion de
/// cuentas: veinticuatro horas.
///
/// Es la ventana en la que «apagar y crear» es una secuencia y no dos hechos
/// sueltos. Si el registro se vuelve a encender antes, la ventana se cierra
/// alli.
pub const VENTANA_COMPROMISO_NS: u64 = 24 * 3600 * 1_000_000_000;

/// Dias tras los que una clave de acceso debe haberse rotado (CIS AWS 1.14,
/// CIS GCP 1.7).
pub const DIAS_ROTACION: u64 = 90;

/// Un dia en nanosegundos.
pub const DIA_NS: u64 = 24 * 3600 * 1_000_000_000;

/// Puertos de administracion: SSH, RDP, PostgreSQL, MySQL, Redis,
/// Elasticsearch, MongoDB.
pub const PUERTOS_ADMIN: [i64; 7] = [22, 3389, 5432, 3306, 6379, 9200, 27017];

/// Roles de Azure que se cuentan como administrador: Owner, Contributor y User
/// Access Administrator (que puede concederse Owner a si mismo).
pub const ROLES_AZURE_ADMIN: [(&str, &str); 3] = [
    ("8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "Owner"),
    ("b24988ac-6180-42a0-ab88-20f7382dd24c", "Contributor"),
    (
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
        "User Access Administrator",
    ),
];

/// Roles basicos de GCP que se cuentan como administrador.
pub const ROLES_GCP_ADMIN: [&str; 2] = ["roles/owner", "roles/editor"];

/// Miembros de GCP que son «cualquiera».
pub const MIEMBROS_PUBLICOS: [&str; 2] = ["allUsers", "allAuthenticatedUsers"];

/// Como esta una pieza del estado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Situacion {
    Mala(Evidencia),
    Buena(Evidencia),
    Incierta(String, Evidencia),
}

impl Situacion {
    fn en_estado(&self) -> Estado {
        match self {
            Situacion::Mala(e) => Estado::Incumple(e.clone()),
            Situacion::Buena(e) => Estado::Cumple(e.clone()),
            Situacion::Incierta(m, e) => {
                let refs: Vec<String> = e.referencias.iter().map(Referencia::texto).collect();
                if refs.is_empty() {
                    Estado::SinDatos(m.clone())
                } else {
                    Estado::SinDatos(format!("{m} [{}]", refs.join(", ")))
                }
            }
        }
    }

    fn es_mala(&self) -> bool {
        matches!(self, Situacion::Mala(_))
    }
}

#[derive(Debug, Clone)]
struct Pieza {
    proveedor: Proveedor,
    recurso: String,
    entidad: Eid,
    situacion: Situacion,
}

/// Lo que se conto de un proveedor al plegar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Contadores {
    /// Eventos distintos plegados.
    pub eventos: usize,
    /// Eventos repetidos (mismo identificador) que no se plegaron otra vez.
    pub duplicados: usize,
    /// Llamadas que fallaron o no se sabe como acabaron: no cambiaron nada.
    pub no_aplicados: usize,
    /// Azure: operaciones empezadas cuyo final quedo pendiente.
    pub pendientes: usize,
    /// Llamadas relevantes para alguna comprobacion sin detalle que leer.
    pub sin_detalle: usize,
    /// Primer instante de la ventana observada.
    pub desde_ns: Option<u64>,
    /// Ultimo instante de la ventana observada.
    pub hasta_ns: Option<u64>,
}

#[derive(Debug, Clone)]
struct Apagado {
    referencia: Referencia,
    ns: u64,
    proveedor: Proveedor,
    cuenta: String,
    actor: String,
    recurso: String,
    hasta_ns: Option<u64>,
}

#[derive(Debug, Clone)]
struct Gestion {
    referencia: Referencia,
    ns: u64,
    proveedor: Proveedor,
    cuenta: String,
    accion: String,
}

#[derive(Debug, Clone, Default)]
enum Faceta {
    #[default]
    Desconocida,
    Publica(Evidencia),
    NoPublica(Evidencia),
    Ilegible(String, Evidencia),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bloqueo {
    bloquear_acls: bool,
    ignorar_acls: bool,
    bloquear_politica: bool,
    restringir: bool,
}

impl Bloqueo {
    const NINGUNO: Bloqueo = Bloqueo {
        bloquear_acls: false,
        ignorar_acls: false,
        bloquear_politica: false,
        restringir: false,
    };

    fn completo(self) -> bool {
        self.bloquear_acls && self.ignorar_acls && self.bloquear_politica && self.restringir
    }

    fn nulo(self) -> bool {
        self == Bloqueo::NINGUNO
    }
}

#[derive(Debug, Clone, Default)]
enum FacetaBloqueo {
    #[default]
    Desconocido,
    Conocido(Bloqueo, Evidencia),
    Ilegible(String, Evidencia),
}

#[derive(Debug, Clone, Default)]
struct Cubo {
    politica: Faceta,
    acl: Faceta,
    bloqueo: FacetaBloqueo,
    borrado: Option<Evidencia>,
}

#[derive(Debug, Clone)]
enum Selectores {
    Bien,
    Deficientes(String),
    Ilegibles(String),
}

#[derive(Debug, Clone, Default)]
struct Trail {
    registrando: Option<(bool, Evidencia)>,
    borrado: Option<Evidencia>,
    selectores: Option<(Selectores, Evidencia)>,
}

#[derive(Debug, Clone, Default)]
struct ReglaGcp {
    fuentes: Option<Vec<String>>,
    permitidos: Option<Vec<(String, Vec<String>)>>,
    entrada: Option<bool>,
    deshabilitada: Option<bool>,
    borrada: bool,
    error: Option<String>,
    evidencia: Evidencia,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EstadoClave {
    Activa,
    Inactiva,
    Borrada,
}

#[derive(Debug, Clone)]
struct Clave {
    proveedor: Proveedor,
    dueno: String,
    creada: Option<(u64, ConfianzaReloj)>,
    estado: EstadoClave,
    identificada: bool,
    incierta: Option<String>,
    evidencia: Evidencia,
}

/// El estado de la nube reconstruido de una ventana de eventos.
#[derive(Debug, Clone, Default)]
pub struct EstadoNube {
    piezas: BTreeMap<(&'static str, String), Pieza>,
    cubos: BTreeMap<String, Cubo>,
    trails: BTreeMap<String, Trail>,
    reglas_gcp: BTreeMap<String, ReglaGcp>,
    claves: BTreeMap<String, Clave>,
    politicas_aws: BTreeMap<String, bool>,
    adjuntos_aws: BTreeMap<String, BTreeSet<String>>,
    reglas_sg: BTreeMap<String, String>,
    con_id_sg: BTreeSet<String>,
    operaciones_gcp: BTreeMap<String, String>,
    pendientes_azure: BTreeMap<String, (Value, Referencia)>,
    tocada: Option<(&'static str, String)>,
    apagados: Vec<Apagado>,
    gestiones: Vec<Gestion>,
    actividad: BTreeMap<Proveedor, Vec<(u64, String)>>,
    /// Lo contado por proveedor.
    pub contadores: BTreeMap<Proveedor, Contadores>,
    /// Eventos que no se plegaron por exceder [`MAX_EVENTOS`].
    pub descartados: usize,
    /// Si se llego a [`MAX_PIEZAS`] y se dejo de anadir.
    pub desbordado: bool,
}

impl EstadoNube {
    /// Reconstruye el estado de una ventana de eventos.
    ///
    /// Los eventos pueden venir en cualquier orden y con duplicados: se
    /// desduplican por [`Evento::id`] y se ordenan por ocurrencia antes de
    /// plegar. Los que no son de nube se ignoran.
    #[must_use]
    pub fn reconstruir(eventos: &[Evento]) -> EstadoNube {
        let mut estado = EstadoNube::default();
        let mut vistos: BTreeSet<&str> = BTreeSet::new();
        let mut orden: Vec<&Evento> = Vec::new();
        for ev in eventos {
            let Some(l) = Llamada::de(ev) else {
                continue;
            };
            if !vistos.insert(ev.id.as_str()) {
                estado.contadores.entry(l.proveedor).or_default().duplicados += 1;
                continue;
            }
            orden.push(ev);
        }
        orden.sort_by(|a, b| (a.ocurrio_ns, &a.id).cmp(&(b.ocurrio_ns, &b.id)));
        if orden.len() > MAX_EVENTOS {
            estado.descartados = orden.len() - MAX_EVENTOS;
            orden.truncate(MAX_EVENTOS);
        }
        for ev in orden {
            if let Some(l) = Llamada::de(ev) {
                estado.plegar(&l);
            }
        }
        estado
    }

    /// Cuantas piezas hay, de todas las clases.
    fn total(&self) -> usize {
        self.piezas.len()
            + self.cubos.len()
            + self.trails.len()
            + self.reglas_gcp.len()
            + self.claves.len()
    }

    fn cabe(&mut self) -> bool {
        if self.total() >= MAX_PIEZAS {
            self.desbordado = true;
            return false;
        }
        true
    }

    fn plegar(&mut self, l: &Llamada<'_>) {
        let ns = l.evento.ocurrio_ns;
        let c = self.contadores.entry(l.proveedor).or_default();
        c.eventos += 1;
        c.desde_ns = Some(c.desde_ns.map_or(ns, |d| d.min(ns)));
        c.hasta_ns = Some(c.hasta_ns.map_or(ns, |h| h.max(ns)));
        self.actividad
            .entry(l.proveedor)
            .or_default()
            .push((ns, cuenta_efectiva(l)));

        match l.desenlace() {
            Desenlace::NoAplicada => {
                self.contadores.entry(l.proveedor).or_default().no_aplicados += 1;
                // Una operacion larga de Compute que acaba en error: su primer
                // evento ya se aplico (llevaba la peticion y aun no habia
                // fallado). No se deshace a ciegas; se deja de afirmar.
                if let Some((op, _)) = l.operacion() {
                    if let Some(recurso) = self.operaciones_gcp.get(&op).cloned() {
                        if let Some(r) = self.reglas_gcp.get_mut(&recurso) {
                            r.error = Some(format!(
                                "la operacion {} termino en error despues de aceptarse",
                                recortar(&op, 64)
                            ));
                            r.evidencia.anadir(l.referencia());
                        }
                    }
                }
                return;
            }
            Desenlace::Pendiente => {
                self.contadores.entry(l.proveedor).or_default().pendientes += 1;
                let corr = l.correlacion();
                if !corr.is_empty() && self.pendientes_azure.len() < MAX_PENDIENTES {
                    if let Some(p) = l.peticion() {
                        self.pendientes_azure
                            .insert(corr, (p.into_owned(), l.referencia()));
                    }
                }
                return;
            }
            Desenlace::Aplicada => {}
        }

        if es_gestion_de_cuentas(l) {
            self.gestiones.push(Gestion {
                referencia: l.referencia(),
                ns,
                proveedor: l.proveedor,
                cuenta: cuenta_efectiva(l),
                accion: recortar(&l.accion, 128),
            });
        }
        match l.proveedor {
            Proveedor::Aws => self.aws(l),
            Proveedor::Azure => self.azure(l),
            Proveedor::Gcp => self.gcp(l),
        }
    }

    fn sin_detalle(&mut self, p: Proveedor) {
        self.contadores.entry(p).or_default().sin_detalle += 1;
    }

    /// Pone una pieza. Si ya existia y la nueva es buena, conserva la
    /// evidencia de lo que se corrigio: el analista ve que se abrio y que se
    /// cerro, no solo lo segundo.
    fn poner(
        &mut self,
        comprobacion: &'static str,
        clave: &str,
        proveedor: Proveedor,
        recurso: &str,
        entidad: Eid,
        situacion: Situacion,
    ) {
        let k = (comprobacion, recortar(clave, 2 * MAX_RECURSO));
        let situacion = match (self.piezas.get(&k).map(|p| &p.situacion), situacion) {
            (Some(Situacion::Mala(vieja)), Situacion::Buena(nueva)) => {
                let mut e = vieja.clone();
                e.unir(&nueva);
                e.con_extracto(&nueva.extracto);
                Situacion::Buena(e)
            }
            (_, s) => s,
        };
        if !self.piezas.contains_key(&k) && !self.cabe() {
            return;
        }
        self.tocada = Some(k.clone());
        self.piezas.insert(
            k,
            Pieza {
                proveedor,
                recurso: recortar(recurso, MAX_RECURSO),
                entidad,
                situacion,
            },
        );
    }

    fn existe(&self, comprobacion: &'static str, clave: &str) -> bool {
        self.piezas
            .contains_key(&(comprobacion, recortar(clave, 2 * MAX_RECURSO)))
    }

    /// Marca como buenas todas las piezas de una comprobacion cuya clave
    /// empieza por `prefijo` (un grupo borrado, una identidad borrada).
    fn cerrar_prefijo(&mut self, comprobacion: &'static str, prefijo: &str, ev: &Evidencia) {
        let claves: Vec<String> = self
            .piezas
            .range((comprobacion, prefijo.to_string())..)
            .take_while(|((c, k), _)| *c == comprobacion && k.starts_with(prefijo))
            .map(|((_, k), _)| k.clone())
            .collect();
        for k in claves {
            if let Some(p) = self.piezas.get(&(comprobacion, k.clone())).cloned() {
                self.poner(
                    comprobacion,
                    &k,
                    p.proveedor,
                    &p.recurso,
                    p.entidad,
                    Situacion::Buena(ev.clone()),
                );
            }
        }
    }

    fn apagar(&mut self, l: &Llamada<'_>, recurso: &str) {
        if self.apagados.len() >= MAX_PIEZAS {
            self.desbordado = true;
            return;
        }
        self.apagados.push(Apagado {
            referencia: l.referencia(),
            ns: l.evento.ocurrio_ns,
            proveedor: l.proveedor,
            cuenta: cuenta_efectiva(l),
            actor: l.actor(),
            recurso: recortar(recurso, MAX_RECURSO),
            hasta_ns: None,
        });
    }

    fn encender(&mut self, proveedor: Proveedor, recurso: &str, ns: u64) {
        for a in &mut self.apagados {
            if a.proveedor == proveedor && a.recurso == recurso && a.hasta_ns.is_none() {
                a.hasta_ns = Some(ns);
            }
        }
    }

    // --- AWS ---------------------------------------------------------------

    fn aws(&mut self, l: &Llamada<'_>) {
        let clave_uso = campo(l.evento, "nube.clave_acceso");
        // Solo las claves de larga duracion (AKIA). Las ASIA son de sesion,
        // caducan solas y no se rotan.
        if clave_uso.starts_with("AKIA") {
            self.clave_en_uso(l, &clave_uso);
        }
        match l.accion.as_str() {
            "AttachUserPolicy" | "AttachRolePolicy" | "AttachGroupPolicy" => {
                self.aws_adjunto(l, true);
            }
            "DetachUserPolicy" | "DetachRolePolicy" | "DetachGroupPolicy" => {
                self.aws_adjunto(l, false);
            }
            "PutUserPolicy" | "PutRolePolicy" | "PutGroupPolicy" => self.aws_en_linea(l, true),
            "DeleteUserPolicy" | "DeleteRolePolicy" | "DeleteGroupPolicy" => {
                self.aws_en_linea(l, false);
            }
            "CreatePolicy" | "CreatePolicyVersion" => self.aws_politica_gestionada(l),
            "DeleteUser" | "DeleteRole" | "DeleteGroup" => self.aws_borrar_identidad(l),
            "CreateAccessKey" | "DeleteAccessKey" | "UpdateAccessKey" => self.aws_clave(l),
            "PutBucketPolicy"
            | "DeleteBucketPolicy"
            | "PutBucketAcl"
            | "PutBucketPublicAccessBlock"
            | "DeletePublicAccessBlock"
            | "DeleteBucket" => self.aws_cubo(l),
            "AuthorizeSecurityGroupIngress" => self.aws_sg_autorizar(l),
            "RevokeSecurityGroupIngress" => self.aws_sg_revocar(l),
            "ModifySecurityGroupRules" => self.aws_sg_modificar(l),
            "DeleteSecurityGroup" => self.aws_sg_borrar(l),
            "StopLogging" | "StartLogging" | "DeleteTrail" | "CreateTrail"
            | "PutEventSelectors" => {
                self.aws_trail(l);
            }
            _ => {}
        }
    }

    fn aws_adjunto(&mut self, l: &Llamada<'_>, adjuntar: bool) {
        let Some(p) = l.peticion() else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let (Some((tipo, nombre)), Some(arn_pol)) =
            (principal_aws(&p), ci(&p, "policyArn").and_then(texto))
        else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let principal = arn_iam(&l.cuenta, tipo, &nombre);
        let clave = format!("{principal}|gestionada:{arn_pol}");
        let recurso = format!("{tipo}/{nombre} <- {}", nombre_politica(&arn_pol));
        let entidad = entidad::cuenta(&principal);
        let gestionada_por_aws = arn_pol.contains(":iam::aws:policy/");
        let admin = if es_administrator_access(&arn_pol) {
            Some(true)
        } else if gestionada_por_aws {
            Some(false)
        } else {
            self.politicas_aws.get(&arn_pol).copied()
        };
        if adjuntar {
            if !gestionada_por_aws {
                let s = self.adjuntos_aws.entry(arn_pol.clone()).or_default();
                if s.len() < 10_000 {
                    s.insert(principal.clone());
                }
            }
            let ev = Evidencia::nueva(
                l.referencia(),
                &format!(
                    "{} adjunto {} a {principal} (por {})",
                    l.accion,
                    nombre_politica(&arn_pol),
                    l.actor()
                ),
            );
            match admin {
                Some(true) => {
                    self.poner(
                        IAM_001,
                        &clave,
                        l.proveedor,
                        &recurso,
                        entidad,
                        Situacion::Mala(ev),
                    );
                }
                Some(false) => {}
                // EL MURO en IAM: una politica del cliente cuyo contenido no se
                // vio en la ventana puede ser cualquier cosa, incluida `*:*`.
                None => self.poner(
                    IAM_001,
                    &clave,
                    l.proveedor,
                    &recurso,
                    entidad,
                    Situacion::Incierta(
                        format!(
                            "se adjunto la politica del cliente {arn_pol}, cuyo contenido no se \
                             observo en la ventana"
                        ),
                        ev,
                    ),
                ),
            }
        } else {
            if let Some(s) = self.adjuntos_aws.get_mut(&arn_pol) {
                s.remove(&principal);
            }
            if admin == Some(true) || self.existe(IAM_001, &clave) {
                let ev = Evidencia::nueva(
                    l.referencia(),
                    &format!(
                        "{} retiro {} de {principal}",
                        l.accion,
                        nombre_politica(&arn_pol)
                    ),
                );
                self.poner(
                    IAM_001,
                    &clave,
                    l.proveedor,
                    &recurso,
                    entidad,
                    Situacion::Buena(ev),
                );
            }
        }
    }

    fn aws_en_linea(&mut self, l: &Llamada<'_>, poner: bool) {
        let Some(p) = l.peticion() else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let (Some((tipo, nombre)), Some(pol)) =
            (principal_aws(&p), ci(&p, "policyName").and_then(texto))
        else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let principal = arn_iam(&l.cuenta, tipo, &nombre);
        let clave = format!("{principal}|en-linea:{pol}");
        let recurso = format!("{tipo}/{nombre} <- en linea {pol}");
        let entidad = entidad::cuenta(&principal);
        if !poner {
            if self.existe(IAM_001, &clave) {
                let ev = Evidencia::nueva(
                    l.referencia(),
                    &format!(
                        "{} borro la politica en linea {pol} de {principal}",
                        l.accion
                    ),
                );
                self.poner(
                    IAM_001,
                    &clave,
                    l.proveedor,
                    &recurso,
                    entidad,
                    Situacion::Buena(ev),
                );
            }
            return;
        }
        let lectura = ci(&p, "policyDocument").map_or_else(
            || Lectura::Ilegible("la llamada no trae policyDocument".into()),
            politica::concede_todo,
        );
        let base = format!(
            "{} puso la politica en linea {pol} en {principal}",
            l.accion
        );
        match lectura {
            Lectura::Si(d) => {
                let ev = Evidencia::nueva(l.referencia(), &format!("{base}: {d}"));
                self.poner(
                    IAM_001,
                    &clave,
                    l.proveedor,
                    &recurso,
                    entidad,
                    Situacion::Mala(ev),
                );
            }
            Lectura::No(_) => {
                if self.existe(IAM_001, &clave) {
                    let ev =
                        Evidencia::nueva(l.referencia(), &format!("{base}, y ya no concede todo"));
                    self.poner(
                        IAM_001,
                        &clave,
                        l.proveedor,
                        &recurso,
                        entidad,
                        Situacion::Buena(ev),
                    );
                }
            }
            Lectura::Ilegible(m) => {
                self.sin_detalle(l.proveedor);
                let motivo = if l.detalle == Detalle::Crudo {
                    format!("{base}, pero el documento no se pudo leer: {m}")
                } else {
                    format!(
                        "{base}, pero el documento no se pudo leer ({m}); sin el crudo del \
                         evento llega recortado a 4096 bytes"
                    )
                };
                let ev = Evidencia::nueva(l.referencia(), &base);
                self.poner(
                    IAM_001,
                    &clave,
                    l.proveedor,
                    &recurso,
                    entidad,
                    Situacion::Incierta(motivo, ev),
                );
            }
        }
    }

    fn aws_politica_gestionada(&mut self, l: &Llamada<'_>) {
        let Some(p) = l.peticion() else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let arn = if l.accion == "CreatePolicy" {
            let de_respuesta = l
                .respuesta()
                .and_then(|r| ruta(&r, &["policy", "arn"]).and_then(texto));
            let construido = ci(&p, "policyName").and_then(texto).map(|n| {
                let camino = ci(&p, "path").and_then(texto).unwrap_or_else(|| "/".into());
                let cuenta = if l.cuenta.is_empty() {
                    "desconocida"
                } else {
                    &l.cuenta
                };
                format!("arn:aws:iam::{cuenta}:policy{camino}{n}")
            });
            de_respuesta.or(construido)
        } else {
            // Una version que no pasa a ser la predeterminada no cambia lo que
            // la politica concede.
            if !ci(&p, "setAsDefault").and_then(booleano).unwrap_or(false) {
                return;
            }
            ci(&p, "policyArn").and_then(texto)
        };
        let Some(arn) = arn else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let lectura = ci(&p, "policyDocument").map_or_else(
            || Lectura::Ilegible("sin documento".into()),
            politica::concede_todo,
        );
        let admin = match &lectura {
            Lectura::Si(_) => Some(true),
            Lectura::No(_) => Some(false),
            Lectura::Ilegible(_) => None,
        };
        if self.politicas_aws.len() < MAX_PIEZAS {
            match admin {
                Some(a) => {
                    self.politicas_aws.insert(arn.clone(), a);
                }
                None => {
                    self.politicas_aws.remove(&arn);
                }
            }
        }
        // Una politica que pasa a conceder todo DESPUES de adjuntarse convierte
        // en administradoras a las identidades que ya la tenian.
        if admin == Some(true) {
            let principales: Vec<String> = self
                .adjuntos_aws
                .get(&arn)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            for principal in principales {
                let clave = format!("{principal}|gestionada:{arn}");
                let ev = Evidencia::nueva(
                    l.referencia(),
                    &format!(
                        "{} hizo que {} conceda todo, y ya estaba adjunta a {principal}",
                        l.accion,
                        nombre_politica(&arn)
                    ),
                );
                let recurso = format!("{principal} <- {}", nombre_politica(&arn));
                self.poner(
                    IAM_001,
                    &clave,
                    l.proveedor,
                    &recurso,
                    entidad::cuenta(&principal),
                    Situacion::Mala(ev),
                );
            }
        }
    }

    fn aws_borrar_identidad(&mut self, l: &Llamada<'_>) {
        let Some(p) = l.peticion() else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let Some((tipo, nombre)) = principal_aws(&p) else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let principal = arn_iam(&l.cuenta, tipo, &nombre);
        let ev = Evidencia::nueva(
            l.referencia(),
            &format!("{} borro la identidad {principal}", l.accion),
        );
        self.cerrar_prefijo(IAM_001, &format!("{principal}|"), &ev);
    }

    fn aws_clave(&mut self, l: &Llamada<'_>) {
        let p = l.peticion();
        let dueno = p
            .as_deref()
            .and_then(|p| ci(p, "userName").and_then(texto))
            .map_or_else(|| l.actor(), |n| arn_iam(&l.cuenta, "user", &n));
        match l.accion.as_str() {
            "CreateAccessKey" => {
                let id = l
                    .respuesta()
                    .and_then(|r| ruta(&r, &["accessKey", "accessKeyId"]).and_then(texto));
                self.alta_de_clave(l, id, dueno);
            }
            "DeleteAccessKey" => {
                let id = p
                    .as_deref()
                    .and_then(|p| ci(p, "accessKeyId").and_then(texto));
                self.baja_de_clave(l, id, dueno, EstadoClave::Borrada);
            }
            _ => {
                let p = p.as_deref();
                let id = p.and_then(|p| ci(p, "accessKeyId").and_then(texto));
                let estado = match p.and_then(|p| ci(p, "status").and_then(texto)).as_deref() {
                    Some("Inactive") => EstadoClave::Inactiva,
                    Some("Active") => EstadoClave::Activa,
                    _ => {
                        self.sin_detalle(l.proveedor);
                        return;
                    }
                };
                self.baja_de_clave(l, id, dueno, estado);
            }
        }
    }

    /// El alta de una clave. Sin identificador (no hay crudo con la
    /// respuesta), se guarda con uno sintetico: se sabe que existe y cuando se
    /// creo, no cual es.
    fn alta_de_clave(&mut self, l: &Llamada<'_>, id: Option<String>, dueno: String) {
        let (id, identificada) = match id {
            Some(i) => (i, true),
            None => {
                self.sin_detalle(l.proveedor);
                (format!("sin-id:{}", recortar(&l.evento.id, 16)), false)
            }
        };
        if !self.claves.contains_key(&id) && !self.cabe() {
            return;
        }
        let ev = Evidencia::nueva(
            l.referencia(),
            &format!("{} creo la clave {id} de {dueno}", l.accion),
        );
        self.claves.insert(
            id,
            Clave {
                proveedor: l.proveedor,
                dueno,
                creada: Some((l.evento.ocurrio_ns, l.evento.reloj)),
                estado: EstadoClave::Activa,
                identificada,
                incierta: None,
                evidencia: ev,
            },
        );
    }

    fn baja_de_clave(
        &mut self,
        l: &Llamada<'_>,
        id: Option<String>,
        dueno: String,
        estado: EstadoClave,
    ) {
        let Some(id) = id else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let que = match estado {
            EstadoClave::Borrada => "borro",
            EstadoClave::Inactiva => "desactivo",
            EstadoClave::Activa => "reactivo",
        };
        if let Some(c) = self.claves.get_mut(&id) {
            c.estado = estado;
            c.evidencia.anadir(l.referencia());
            c.evidencia
                .con_extracto(&format!("{} {que} la clave {id} de {}", l.accion, c.dueno));
            return;
        }
        // Una clave de este dueño cuyo alta se vio sin identificador puede ser
        // esta. No se puede saber: esas dejan de afirmarse.
        let referencia = l.referencia();
        let mut ambiguas = 0;
        for c in self.claves.values_mut() {
            if !c.identificada && c.dueno == dueno && c.estado == EstadoClave::Activa {
                c.incierta = Some(format!(
                    "se {que} la clave {id} de {dueno} y no se puede emparejar con esta (su alta \
                     se vio sin el crudo que trae el identificador)"
                ));
                c.evidencia.anadir(referencia.clone());
                ambiguas += 1;
            }
        }
        if ambiguas > 0 || !self.cabe() {
            return;
        }
        self.claves.insert(
            id.clone(),
            Clave {
                proveedor: l.proveedor,
                dueno: dueno.clone(),
                creada: None,
                estado,
                identificada: true,
                incierta: None,
                evidencia: Evidencia::nueva(
                    referencia,
                    &format!("{} {que} la clave {id} de {dueno}", l.accion),
                ),
            },
        );
    }

    fn clave_en_uso(&mut self, l: &Llamada<'_>, id: &str) {
        if self.claves.contains_key(id) || !self.cabe() {
            return;
        }
        let dueno = l.actor();
        self.claves.insert(
            id.to_string(),
            Clave {
                proveedor: l.proveedor,
                dueno: dueno.clone(),
                creada: None,
                estado: EstadoClave::Activa,
                identificada: true,
                incierta: None,
                evidencia: Evidencia::nueva(
                    l.referencia(),
                    &format!("la clave {id} de {dueno} se uso en {}", l.accion),
                ),
            },
        );
    }

    fn aws_cubo(&mut self, l: &Llamada<'_>) {
        let Some(p) = l.peticion() else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let Some(nombre) = ci(&p, "bucketName").and_then(texto) else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let nombre = recortar(&nombre, MAX_RECURSO);
        if !self.cubos.contains_key(&nombre) && !self.cabe() {
            return;
        }
        let r = l.referencia();
        let completo = l.detalle.completo();
        let accion = l.accion.clone();
        let actor = l.actor();
        let cubo = self.cubos.entry(nombre.clone()).or_default();
        if accion != "DeleteBucket" {
            cubo.borrado = None;
        }
        match accion.as_str() {
            "PutBucketPolicy" => {
                let lectura = ci(&p, "bucketPolicy").map_or_else(
                    || Lectura::Ilegible("la llamada no trae bucketPolicy".into()),
                    politica::es_publica,
                );
                cubo.politica = match lectura {
                    Lectura::Si(d) => Faceta::Publica(Evidencia::nueva(
                        r,
                        &format!("PutBucketPolicy de {actor} en {nombre}: {d}"),
                    )),
                    Lectura::No(nota) if completo => Faceta::NoPublica(Evidencia::nueva(
                        r,
                        &format!(
                            "PutBucketPolicy en {nombre} sin Principal * incondicional{}",
                            nota.map(|n| format!(" ({n})")).unwrap_or_default()
                        ),
                    )),
                    Lectura::No(_) => Faceta::Ilegible(
                        "la politica llego recortada por el aplanado; sin crudo no se afirma que \
                         no sea publica"
                            .into(),
                        Evidencia::nueva(r, "PutBucketPolicy"),
                    ),
                    Lectura::Ilegible(m) => {
                        Faceta::Ilegible(m, Evidencia::nueva(r, "PutBucketPolicy"))
                    }
                };
            }
            "DeleteBucketPolicy" => {
                cubo.politica = Faceta::NoPublica(Evidencia::nueva(
                    r,
                    &format!("DeleteBucketPolicy quito la politica de {nombre}"),
                ));
            }
            "PutBucketAcl" => cubo.acl = faceta_acl(&p, r, &nombre, &actor, completo),
            "PutBucketPublicAccessBlock" => {
                cubo.bloqueo = match ci(&p, "PublicAccessBlockConfiguration") {
                    Some(cfg) => {
                        // En la API de S3 un indicador omitido es `false`.
                        let f = |k: &str| ci(cfg, k).and_then(booleano).unwrap_or(false);
                        let b = Bloqueo {
                            bloquear_acls: f("BlockPublicAcls"),
                            ignorar_acls: f("IgnorePublicAcls"),
                            bloquear_politica: f("BlockPublicPolicy"),
                            restringir: f("RestrictPublicBuckets"),
                        };
                        FacetaBloqueo::Conocido(
                            b,
                            Evidencia::nueva(
                                r,
                                &format!(
                                    "PutBucketPublicAccessBlock en {nombre}: BlockPublicAcls={} \
                                     IgnorePublicAcls={} BlockPublicPolicy={} \
                                     RestrictPublicBuckets={}",
                                    b.bloquear_acls,
                                    b.ignorar_acls,
                                    b.bloquear_politica,
                                    b.restringir
                                ),
                            ),
                        )
                    }
                    None => FacetaBloqueo::Ilegible(
                        "la llamada no trae PublicAccessBlockConfiguration".into(),
                        Evidencia::nueva(r, "PutBucketPublicAccessBlock"),
                    ),
                };
            }
            "DeletePublicAccessBlock" => {
                cubo.bloqueo = FacetaBloqueo::Conocido(
                    Bloqueo::NINGUNO,
                    Evidencia::nueva(
                        r,
                        &format!(
                            "DeletePublicAccessBlock de {actor} retiro el bloqueo de acceso \
                             publico de {nombre}"
                        ),
                    ),
                );
            }
            _ => {
                cubo.borrado = Some(Evidencia::nueva(r, &format!("DeleteBucket borro {nombre}")));
            }
        }
    }

    fn sg(l: &Llamada<'_>, p: &Value) -> Option<String> {
        let g = ci(p, "groupId").and_then(texto).or_else(|| {
            ci(p, "groupName")
                .and_then(texto)
                .map(|n| format!("nombre:{n}"))
        })?;
        Some(format!(
            "arn:aws:ec2:{}:{}:security-group/{}",
            l.region,
            l.cuenta,
            recortar(&g, 256)
        ))
    }

    fn aws_sg_autorizar(&mut self, l: &Llamada<'_>) {
        let Some(p) = l.peticion() else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let Some(sg) = Self::sg(l, &p) else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let (entradas, cortada) = entradas_abiertas(&p);
        let actor = l.actor();
        let mut alguna = false;
        for (proto, desde, hasta, cidr) in &entradas {
            alguna = true;
            let clave = clave_entrada(&sg, proto, *desde, *hasta, cidr);
            let ev = Evidencia::nueva(
                l.referencia(),
                &format!(
                    "AuthorizeSecurityGroupIngress de {actor}: {} {} desde {cidr}",
                    nombre_proto(proto),
                    rango_puertos(*desde, *hasta)
                ),
            );
            self.poner(
                RED_001,
                &clave,
                l.proveedor,
                &format!(
                    "{sg} {} {}",
                    nombre_proto(proto),
                    rango_puertos(*desde, *hasta)
                ),
                eid_recurso(l.proveedor, &sg),
                Situacion::Mala(ev),
            );
        }
        // Los identificadores de regla solo vienen en la respuesta (crudo):
        // son los que usa un `RevokeSecurityGroupIngress` moderno.
        if let Some(r) = l.respuesta() {
            if let Some(items) = ci(&r, "securityGroupRuleSet") {
                for it in lista_con_tope(items).0 {
                    let Some(id) = ci(it, "securityGroupRuleId").and_then(texto) else {
                        continue;
                    };
                    let proto = ci(it, "ipProtocol").and_then(texto).unwrap_or_default();
                    let desde = ci(it, "fromPort").and_then(entero).unwrap_or(-1);
                    let hasta = ci(it, "toPort").and_then(entero).unwrap_or(-1);
                    let cidr = ci(it, "cidrIpv4")
                        .or_else(|| ci(it, "cidrIpv6"))
                        .and_then(texto)
                        .unwrap_or_default();
                    let clave = clave_entrada(&sg, &proto, desde, hasta, &cidr);
                    if self.existe(RED_001, &clave) && self.reglas_sg.len() < MAX_PIEZAS {
                        self.reglas_sg.insert(id, clave.clone());
                        self.con_id_sg.insert(clave);
                    }
                }
            }
        }
        if !alguna && (cortada || !l.detalle.completo()) {
            self.sin_detalle(l.proveedor);
            let ev = Evidencia::nueva(l.referencia(), "AuthorizeSecurityGroupIngress");
            self.poner(
                RED_001,
                &format!("{sg}|recortada:{}", recortar(&l.evento.id, 16)),
                l.proveedor,
                &sg,
                eid_recurso(l.proveedor, &sg),
                Situacion::Incierta(
                    "se autorizo entrada con listas que no se vieron enteras (aplanado recortado \
                     o mas de MAX_ELEMENTOS): no se afirma que no abra nada"
                        .into(),
                    ev,
                ),
            );
        }
    }

    fn aws_sg_revocar(&mut self, l: &Llamada<'_>) {
        let Some(p) = l.peticion() else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let Some(sg) = Self::sg(l, &p) else {
            self.sin_detalle(l.proveedor);
            return;
        };
        for (proto, desde, hasta, cidr) in entradas_abiertas(&p).0 {
            let clave = clave_entrada(&sg, &proto, desde, hasta, &cidr);
            if self.existe(RED_001, &clave) {
                let ev = Evidencia::nueva(
                    l.referencia(),
                    &format!(
                        "RevokeSecurityGroupIngress quito {} {} desde {cidr}",
                        nombre_proto(&proto),
                        rango_puertos(desde, hasta)
                    ),
                );
                self.poner(
                    RED_001,
                    &clave,
                    l.proveedor,
                    &format!(
                        "{sg} {} {}",
                        nombre_proto(&proto),
                        rango_puertos(desde, hasta)
                    ),
                    eid_recurso(l.proveedor, &sg),
                    Situacion::Buena(ev),
                );
            }
        }
        let Some(ids) = ci(&p, "securityGroupRuleIds") else {
            return;
        };
        for id in lista_con_tope(ids).0 {
            let id = ci(id, "securityGroupRuleId")
                .and_then(texto)
                .or_else(|| texto(id));
            let Some(id) = id else {
                continue;
            };
            if let Some(clave) = self.reglas_sg.get(&id).cloned() {
                if let Some(pz) = self.piezas.get(&(RED_001, clave.clone())).cloned() {
                    let ev = Evidencia::nueva(
                        l.referencia(),
                        &format!("RevokeSecurityGroupIngress quito la regla {id}"),
                    );
                    self.poner(
                        RED_001,
                        &clave,
                        pz.proveedor,
                        &pz.recurso,
                        pz.entidad,
                        Situacion::Buena(ev),
                    );
                }
                continue;
            }
            // Una regla revocada por identificador que no se sabe emparejar:
            // si hay entradas abiertas de este grupo cuyo identificador no se
            // conoce, pudo ser cualquiera de ellas.
            let prefijo = format!("{sg}|");
            let sospechosas: Vec<(String, Pieza)> = self
                .piezas
                .range((RED_001, prefijo.clone())..)
                .take_while(|((c, k), _)| *c == RED_001 && k.starts_with(&prefijo))
                .filter(|((_, k), p)| p.situacion.es_mala() && !self.con_id_sg.contains(k))
                .map(|((_, k), p)| (k.clone(), p.clone()))
                .collect();
            for (k, pz) in sospechosas {
                let mut ev = match &pz.situacion {
                    Situacion::Mala(e) => e.clone(),
                    _ => Evidencia::default(),
                };
                ev.anadir(l.referencia());
                self.poner(
                    RED_001,
                    &k,
                    pz.proveedor,
                    &pz.recurso,
                    pz.entidad,
                    Situacion::Incierta(
                        format!(
                            "se revoco la regla {id} por identificador y no se puede emparejar \
                             con esta entrada (su alta se vio sin el crudo que trae el \
                             identificador)"
                        ),
                        ev,
                    ),
                );
            }
        }
    }

    fn aws_sg_modificar(&mut self, l: &Llamada<'_>) {
        let Some(p) = l.peticion() else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let Some(sg) = Self::sg(l, &p) else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let ev = Evidencia::nueva(l.referencia(), "ModifySecurityGroupRules");
        self.poner(
            RED_001,
            &format!("{sg}|modificada:{}", recortar(&l.evento.id, 16)),
            l.proveedor,
            &sg,
            eid_recurso(l.proveedor, &sg),
            Situacion::Incierta(
                "ModifySecurityGroupRules reescribe reglas por identificador y no se modela: \
                 el grupo deja de afirmarse"
                    .into(),
                ev,
            ),
        );
    }

    fn aws_sg_borrar(&mut self, l: &Llamada<'_>) {
        let Some(p) = l.peticion() else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let Some(sg) = Self::sg(l, &p) else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let ev = Evidencia::nueva(l.referencia(), &format!("DeleteSecurityGroup borro {sg}"));
        self.cerrar_prefijo(RED_001, &format!("{sg}|"), &ev);
    }

    fn aws_trail(&mut self, l: &Llamada<'_>) {
        let Some(p) = l.peticion() else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let clave_nombre = if l.accion == "PutEventSelectors" {
            "trailName"
        } else {
            "name"
        };
        let Some(nombre) = ci(&p, clave_nombre).and_then(texto) else {
            self.sin_detalle(l.proveedor);
            return;
        };
        let recurso = recurso_trail(l, &nombre);
        if !self.trails.contains_key(&recurso) && !self.cabe() {
            return;
        }
        let r = l.referencia();
        let actor = l.actor();
        let ns = l.evento.ocurrio_ns;
        let mut apaga = false;
        {
            let t = self.trails.entry(recurso.clone()).or_default();
            match l.accion.as_str() {
                "StopLogging" => {
                    t.registrando = Some((
                        false,
                        Evidencia::nueva(r, &format!("StopLogging de {actor} detuvo {recurso}")),
                    ));
                    apaga = true;
                }
                "StartLogging" => {
                    t.registrando = Some((
                        true,
                        Evidencia::nueva(r, &format!("StartLogging encendio {recurso}")),
                    ));
                }
                "DeleteTrail" => {
                    t.borrado = Some(Evidencia::nueva(
                        r,
                        &format!("DeleteTrail de {actor} borro {recurso}"),
                    ));
                    apaga = true;
                }
                "CreateTrail" => {
                    // Un trail recien creado NO registra hasta `StartLogging`:
                    // es la semantica de la API, no una suposicion.
                    t.borrado = None;
                    t.selectores = None;
                    t.registrando = Some((
                        false,
                        Evidencia::nueva(
                            r,
                            &format!("CreateTrail creo {recurso}; no registra hasta StartLogging"),
                        ),
                    ));
                }
                _ => {
                    let s = selectores(&p);
                    apaga = matches!(s, Selectores::Deficientes(_));
                    let extracto = match &s {
                        Selectores::Bien => {
                            format!("PutEventSelectors en {recurso} registra eventos de gestion")
                        }
                        Selectores::Deficientes(m) | Selectores::Ilegibles(m) => {
                            format!("PutEventSelectors de {actor} en {recurso}: {m}")
                        }
                    };
                    t.selectores = Some((s, Evidencia::nueva(r, &extracto)));
                }
            }
        }
        if apaga {
            self.apagar(l, &recurso);
        } else if matches!(self.veredicto_trail(&recurso), Some(Situacion::Buena(_))) {
            self.encender(l.proveedor, &recurso, ns);
        }
    }

    fn veredicto_trail(&self, recurso: &str) -> Option<Situacion> {
        let t = self.trails.get(recurso)?;
        if let Some(e) = &t.borrado {
            return Some(Situacion::Mala(e.clone()));
        }
        if let Some((false, e)) = &t.registrando {
            return Some(Situacion::Mala(e.clone()));
        }
        if let Some((Selectores::Deficientes(_), e)) = &t.selectores {
            return Some(Situacion::Mala(e.clone()));
        }
        match (&t.registrando, &t.selectores) {
            (Some((true, _)), Some((Selectores::Ilegibles(m), e))) => {
                Some(Situacion::Incierta(m.clone(), e.clone()))
            }
            (Some((true, e)), sel) => {
                let mut ev = e.clone();
                if let Some((_, es)) = sel {
                    ev.unir(es);
                }
                Some(Situacion::Buena(ev))
            }
            (_, Some((_, e))) => Some(Situacion::Incierta(
                "solo se vieron los selectores de eventos; no si el trail registra".into(),
                e.clone(),
            )),
            _ => None,
        }
    }

    // --- Azure -------------------------------------------------------------

    fn azure(&mut self, l: &Llamada<'_>) {
        // El cuerpo esta en el evento `Start`, que se guardo como pendiente; el
        // de exito solo a veces lo repite.
        let (pendiente, inicio) = match self.pendientes_azure.remove(&l.correlacion()) {
            Some((c, r)) => (Some(c), Some(r)),
            None => (None, None),
        };
        let cuerpo: Option<Value> = l.peticion().map(|c| c.into_owned()).or(pendiente);
        self.tocada = None;
        let op = l.accion.to_ascii_uppercase();
        let recurso = recortar(&l.recurso.to_ascii_lowercase(), MAX_RECURSO);
        if op.contains("MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/") {
            self.azure_asignacion(l, &op, &recurso, cuerpo.as_ref());
        } else if op.contains("MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/") {
            self.azure_diagnostico(l, &op, &recurso, cuerpo.as_ref());
        } else if op.contains("MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/") {
            self.azure_regla(l, &op, &recurso, cuerpo.as_ref());
        }
        // La evidencia cita tambien el `Start`: es el registro que dice QUE se
        // pidio, y sin el el analista veria un «Success» sin contenido.
        if let (Some(r), Some(k)) = (inicio, self.tocada.take()) {
            if let Some(p) = self.piezas.get_mut(&k) {
                let e = match &mut p.situacion {
                    Situacion::Mala(e) | Situacion::Buena(e) | Situacion::Incierta(_, e) => e,
                };
                if !e.referencias.contains(&r) {
                    e.referencias.insert(0, r);
                    e.referencias.truncate(crate::modelo::MAX_REFERENCIAS);
                }
            }
        }
    }

    fn azure_asignacion(
        &mut self,
        l: &Llamada<'_>,
        op: &str,
        recurso: &str,
        cuerpo: Option<&Value>,
    ) {
        if op.ends_with("/DELETE") {
            if let Some(pz) = self.piezas.get(&(IAM_001, recurso.to_string())).cloned() {
                let ev = Evidencia::nueva(
                    l.referencia(),
                    &format!("roleAssignments/delete borro la asignacion {recurso}"),
                );
                self.poner(
                    IAM_001,
                    recurso,
                    pz.proveedor,
                    &pz.recurso,
                    pz.entidad,
                    Situacion::Buena(ev),
                );
            }
            return;
        }
        if !op.ends_with("/WRITE") {
            return;
        }
        let respuesta = l.respuesta();
        let props = cuerpo
            .and_then(|c| ci(c, "properties"))
            .or_else(|| respuesta.as_deref().and_then(|r| ci(r, "properties")));
        let rol = props.and_then(|p| ci(p, "roleDefinitionId").and_then(texto));
        let principal = props.and_then(|p| ci(p, "principalId").and_then(texto));
        let (Some(rol), Some(principal)) = (rol, principal) else {
            self.sin_detalle(l.proveedor);
            let ev = Evidencia::nueva(l.referencia(), "roleAssignments/write");
            self.poner(
                IAM_001,
                recurso,
                l.proveedor,
                recurso,
                eid_recurso(l.proveedor, recurso),
                Situacion::Incierta(
                    "asignacion de rol sin cuerpo legible (hace falta el crudo del evento): no \
                     se sabe que rol concede"
                        .into(),
                    ev,
                ),
            );
            return;
        };
        let guid = rol.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
        let ambito = props
            .and_then(|p| ci(p, "scope").and_then(texto))
            .unwrap_or_default();
        let nombre_rol = ROLES_AZURE_ADMIN
            .iter()
            .find(|(g, _)| *g == guid)
            .map(|(_, n)| *n);
        let desc = format!(
            "{} a {principal} en {}",
            nombre_rol.unwrap_or("rol no administrador"),
            if ambito.is_empty() { recurso } else { &ambito }
        );
        match nombre_rol {
            Some(n) => {
                let ev = Evidencia::nueva(
                    l.referencia(),
                    &format!(
                        "roleAssignments/write de {} concedio {n} ({guid}) a {principal}",
                        l.usuario
                    ),
                );
                self.poner(
                    IAM_001,
                    recurso,
                    l.proveedor,
                    &desc,
                    entidad::cuenta(&principal),
                    Situacion::Mala(ev),
                );
            }
            None => {
                if self.existe(IAM_001, recurso) {
                    let ev = Evidencia::nueva(
                        l.referencia(),
                        &format!(
                            "la asignacion {recurso} se reescribio con un rol no administrador"
                        ),
                    );
                    self.poner(
                        IAM_001,
                        recurso,
                        l.proveedor,
                        &desc,
                        entidad::cuenta(&principal),
                        Situacion::Buena(ev),
                    );
                }
            }
        }
    }

    fn azure_diagnostico(
        &mut self,
        l: &Llamada<'_>,
        op: &str,
        recurso: &str,
        cuerpo: Option<&Value>,
    ) {
        let eid = eid_recurso(l.proveedor, recurso);
        if op.ends_with("/DELETE") {
            let ev = Evidencia::nueva(
                l.referencia(),
                &format!("diagnosticSettings/delete de {} borro {recurso}", l.usuario),
            );
            self.poner(
                LOG_001,
                recurso,
                l.proveedor,
                recurso,
                eid,
                Situacion::Mala(ev),
            );
            self.apagar(l, recurso);
            return;
        }
        if !op.ends_with("/WRITE") {
            return;
        }
        let Some(c) = cuerpo else {
            self.sin_detalle(l.proveedor);
            let ev = Evidencia::nueva(l.referencia(), "diagnosticSettings/write");
            self.poner(
                LOG_001,
                recurso,
                l.proveedor,
                recurso,
                eid,
                Situacion::Incierta(
                    "configuracion de diagnostico escrita sin cuerpo legible: no se sabe que \
                     categorias registra"
                        .into(),
                    ev,
                ),
            );
            return;
        };
        let logs = ruta(c, &["properties", "logs"]).map(lista_con_tope);
        let alguna = logs.as_ref().is_some_and(|(l, _)| {
            l.iter()
                .any(|x| ci(x, "enabled").and_then(booleano).unwrap_or(false))
        });
        if alguna {
            let ev = Evidencia::nueva(
                l.referencia(),
                &format!("diagnosticSettings/write deja registrando {recurso}"),
            );
            self.poner(
                LOG_001,
                recurso,
                l.proveedor,
                recurso,
                eid,
                Situacion::Buena(ev),
            );
            self.encender(l.proveedor, recurso, l.evento.ocurrio_ns);
        } else {
            let ev = Evidencia::nueva(
                l.referencia(),
                &format!(
                    "diagnosticSettings/write de {} deja {recurso} sin ninguna categoria activa",
                    l.usuario
                ),
            );
            self.poner(
                LOG_001,
                recurso,
                l.proveedor,
                recurso,
                eid,
                Situacion::Mala(ev),
            );
            self.apagar(l, recurso);
        }
    }

    fn azure_regla(&mut self, l: &Llamada<'_>, op: &str, recurso: &str, cuerpo: Option<&Value>) {
        let eid = eid_recurso(l.proveedor, recurso);
        if op.ends_with("/DELETE") {
            if self.existe(RED_001, recurso) {
                let ev = Evidencia::nueva(
                    l.referencia(),
                    &format!("securityRules/delete borro {recurso}"),
                );
                self.poner(
                    RED_001,
                    recurso,
                    l.proveedor,
                    recurso,
                    eid,
                    Situacion::Buena(ev),
                );
            }
            return;
        }
        if !op.ends_with("/WRITE") {
            return;
        }
        let Some(props) = cuerpo.and_then(|c| ci(c, "properties")) else {
            self.sin_detalle(l.proveedor);
            let ev = Evidencia::nueva(l.referencia(), "securityRules/write");
            self.poner(
                RED_001,
                recurso,
                l.proveedor,
                recurso,
                eid,
                Situacion::Incierta(
                    "regla de NSG escrita sin cuerpo legible (hace falta el crudo del evento)"
                        .into(),
                    ev,
                ),
            );
            return;
        };
        let t = |k: &str| ci(props, k).and_then(texto).unwrap_or_default();
        let permite = t("access").eq_ignore_ascii_case("allow");
        let entrada = t("direction").eq_ignore_ascii_case("inbound");
        let mut origenes = vec![t("sourceAddressPrefix")];
        let (mas, c1) =
            ci(props, "sourceAddressPrefixes").map_or((Vec::new(), false), lista_con_tope);
        origenes.extend(mas.into_iter().filter_map(texto));
        let publico = origenes
            .iter()
            .find(|o| es_origen_publico_azure(o))
            .cloned();
        let proto = t("protocol").to_ascii_lowercase();
        let proto_ok = matches!(proto.as_str(), "*" | "tcp" | "udp");
        let mut puertos = vec![t("destinationPortRange")];
        let (mas, c2) =
            ci(props, "destinationPortRanges").map_or((Vec::new(), false), lista_con_tope);
        puertos.extend(mas.into_iter().filter_map(texto));
        let puerto = puertos.iter().find(|p| cubre_admin(p)).cloned();
        let abierta = permite && entrada && proto_ok && publico.is_some() && puerto.is_some();
        if abierta {
            let ev = Evidencia::nueva(
                l.referencia(),
                &format!(
                    "securityRules/write de {} permite {} {} desde {}",
                    l.usuario,
                    proto,
                    puerto.unwrap_or_default(),
                    publico.unwrap_or_default()
                ),
            );
            self.poner(
                RED_001,
                recurso,
                l.proveedor,
                recurso,
                eid,
                Situacion::Mala(ev),
            );
        } else if c1 || c2 {
            let ev = Evidencia::nueva(l.referencia(), "securityRules/write");
            self.poner(
                RED_001,
                recurso,
                l.proveedor,
                recurso,
                eid,
                Situacion::Incierta("la regla tiene listas que no se vieron enteras".into(), ev),
            );
        } else {
            let ev = Evidencia::nueva(
                l.referencia(),
                &format!("securityRules/write deja {recurso} sin abrir administracion a Internet"),
            );
            self.poner(
                RED_001,
                recurso,
                l.proveedor,
                recurso,
                eid,
                Situacion::Buena(ev),
            );
        }
    }

    // --- GCP ---------------------------------------------------------------

    fn gcp(&mut self, l: &Llamada<'_>) {
        let m = l.accion.as_str();
        let bajo = m.to_ascii_lowercase();
        if bajo.contains("storage.setiampermissions")
            || bajo.contains("buckets.setiampolicy")
            || (bajo.ends_with("setiampolicy") && l.recurso.contains("/buckets/"))
        {
            self.gcp_iam(l, true);
        } else if bajo.ends_with("setiampolicy") {
            self.gcp_iam(l, false);
        } else if bajo.contains("createserviceaccountkey")
            || bajo.contains("serviceaccounts.keys.create")
        {
            self.gcp_clave_alta(l);
        } else if bajo.contains("deleteserviceaccountkey")
            || bajo.contains("serviceaccounts.keys.delete")
        {
            self.gcp_clave_baja(l, EstadoClave::Borrada);
        } else if bajo.contains("disableserviceaccountkey") {
            self.gcp_clave_baja(l, EstadoClave::Inactiva);
        } else if bajo.contains("enableserviceaccountkey") {
            self.gcp_clave_baja(l, EstadoClave::Activa);
        } else if bajo.contains("compute.firewalls.") {
            self.gcp_cortafuegos(l, &bajo);
        } else if bajo.contains("deletesink") || bajo.contains("logging.sinks.delete") {
            self.gcp_sink(l, true);
        } else if bajo.contains("createsink")
            || bajo.contains("updatesink")
            || bajo.contains("logging.sinks.create")
            || bajo.contains("logging.sinks.update")
        {
            self.gcp_sink(l, false);
        }
    }

    fn gcp_iam(&mut self, l: &Llamada<'_>, cubo: bool) {
        let recurso = recortar(&l.recurso, MAX_RECURSO);
        let prefijo = format!("{recurso}|");
        let deltas: Vec<(bool, String, String)> = l
            .delta_de_politica()
            .and_then(|d| ci(d, "bindingDeltas"))
            .map(|b| {
                lista_con_tope(b)
                    .0
                    .into_iter()
                    .filter_map(|x| {
                        let accion = ci(x, "action").and_then(texto)?;
                        let rol = ci(x, "role").and_then(texto)?;
                        let miembro = ci(x, "member").and_then(texto)?;
                        Some((accion.eq_ignore_ascii_case("ADD"), rol, miembro))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let completa: Option<Vec<(String, String)>> = l.peticion().and_then(|p| {
            let b = ruta(&p, &["policy", "bindings"])?;
            let mut v = Vec::new();
            for x in lista_con_tope(b).0 {
                let Some(rol) = ci(x, "role").and_then(texto) else {
                    continue;
                };
                for m in ci(x, "members")
                    .map(|m| lista_con_tope(m).0)
                    .unwrap_or_default()
                {
                    if let Some(m) = texto(m) {
                        v.push((rol.clone(), m));
                    }
                }
            }
            Some(v)
        });
        let actor = l.usuario.clone();
        if deltas.is_empty() && completa.is_none() {
            self.sin_detalle(l.proveedor);
            let (comp, desc) = if cubo {
                (ALM_001, "politica IAM de un cubo")
            } else {
                (IAM_001, "politica IAM")
            };
            let ev = Evidencia::nueva(l.referencia(), &l.accion);
            self.poner(
                comp,
                &format!("{prefijo}sin-detalle"),
                l.proveedor,
                &recurso,
                eid_recurso(l.proveedor, &recurso),
                Situacion::Incierta(
                    format!(
                        "se cambio la {desc} sin detalle legible (hace falta el crudo del evento)"
                    ),
                    ev,
                ),
            );
            return;
        }
        // Una politica completa observada dice lo que hay: lo que no esta en
        // ella se retiro, y la incertidumbre anterior se resuelve.
        if let Some(pares) = &completa {
            let ev = Evidencia::nueva(
                l.referencia(),
                &format!("{} fijo la politica completa de {recurso}", l.accion),
            );
            for comp in [IAM_001, IAM_002, ALM_001] {
                let claves: Vec<String> = self
                    .piezas
                    .range((comp, prefijo.clone())..)
                    .take_while(|((c, k), _)| *c == comp && k.starts_with(&prefijo))
                    .map(|((_, k), _)| k.clone())
                    .collect();
                for k in claves {
                    let sigue = pares.iter().any(|(r, m)| k == format!("{prefijo}{r}|{m}"));
                    if !sigue {
                        if let Some(pz) = self.piezas.get(&(comp, k.clone())).cloned() {
                            self.poner(
                                comp,
                                &k,
                                pz.proveedor,
                                &pz.recurso,
                                pz.entidad,
                                Situacion::Buena(ev.clone()),
                            );
                        }
                    }
                }
            }
        }
        // Con la politica completa delante, TODO lo que contiene es estado
        // observado —tambien lo que ya estaba antes de la ventana—; los deltas
        // solo dicen lo que cambio. Sin ella, se trabaja con los deltas.
        let cambios: Vec<(bool, String, String)> = match completa {
            Some(pares) => pares.into_iter().map(|(r, m)| (true, r, m)).collect(),
            None => deltas,
        };
        for (anade, rol, miembro) in cambios {
            let clave = format!("{prefijo}{rol}|{miembro}");
            let publico = MIEMBROS_PUBLICOS.contains(&miembro.as_str());
            let admin = ROLES_GCP_ADMIN.contains(&rol.as_str());
            let mut destinos: Vec<(&'static str, Eid, String)> = Vec::new();
            if cubo {
                if publico {
                    destinos.push((
                        ALM_001,
                        eid_recurso(l.proveedor, &recurso),
                        format!("{recurso} {rol} a {miembro}"),
                    ));
                }
            } else {
                if admin {
                    destinos.push((
                        IAM_001,
                        entidad::cuenta(miembro_gcp(&miembro)),
                        format!("{miembro} {rol} en {recurso}"),
                    ));
                }
                if publico {
                    destinos.push((
                        IAM_002,
                        eid_recurso(l.proveedor, &recurso),
                        format!("{recurso} {rol} a {miembro}"),
                    ));
                }
            }
            for (comp, eid, desc) in destinos {
                if anade {
                    let ev = Evidencia::nueva(
                        l.referencia(),
                        &format!(
                            "{} de {actor} anadio {rol} a {miembro} en {recurso}",
                            l.accion
                        ),
                    );
                    self.poner(comp, &clave, l.proveedor, &desc, eid, Situacion::Mala(ev));
                } else if self.existe(comp, &clave) {
                    let ev = Evidencia::nueva(
                        l.referencia(),
                        &format!("{} retiro {rol} de {miembro} en {recurso}", l.accion),
                    );
                    self.poner(comp, &clave, l.proveedor, &desc, eid, Situacion::Buena(ev));
                }
            }
        }
    }

    fn gcp_clave_alta(&mut self, l: &Llamada<'_>) {
        let nombre = l
            .respuesta()
            .and_then(|r| ci(&r, "name").and_then(texto))
            .unwrap_or_default();
        let id = nombre
            .rsplit_once("/keys/")
            .map(|(_, k)| k.to_string())
            .filter(|k| !k.is_empty());
        let dueno = cuenta_de_servicio(&nombre)
            .or_else(|| {
                l.peticion()
                    .and_then(|p| ci(&p, "name").and_then(texto))
                    .and_then(|n| cuenta_de_servicio(&n))
            })
            .or_else(|| cuenta_de_servicio(&l.recurso))
            .unwrap_or_else(|| l.recurso.clone());
        self.alta_de_clave(l, id, dueno);
    }

    fn gcp_clave_baja(&mut self, l: &Llamada<'_>, estado: EstadoClave) {
        let nombre = l
            .peticion()
            .and_then(|p| ci(&p, "name").and_then(texto))
            .unwrap_or_else(|| l.recurso.clone());
        let id = nombre
            .rsplit_once("/keys/")
            .map(|(_, k)| k.to_string())
            .filter(|k| !k.is_empty());
        let dueno = cuenta_de_servicio(&nombre).unwrap_or_default();
        self.baja_de_clave(l, id, dueno, estado);
    }

    fn gcp_cortafuegos(&mut self, l: &Llamada<'_>, metodo: &str) {
        let recurso = recortar(&l.recurso, MAX_RECURSO);
        if recurso.is_empty() {
            self.sin_detalle(l.proveedor);
            return;
        }
        if !self.reglas_gcp.contains_key(&recurso) && !self.cabe() {
            return;
        }
        if let Some((op, _)) = l.operacion() {
            if self.operaciones_gcp.len() < MAX_PIEZAS {
                self.operaciones_gcp.insert(op, recurso.clone());
            }
        }
        let peticion = l.peticion().map(|p| p.into_owned());
        let r = self.reglas_gcp.entry(recurso).or_default();
        r.evidencia.anadir(l.referencia());
        if metodo.contains("firewalls.delete") {
            r.borrada = true;
            return;
        }
        let Some(p) = peticion else {
            // Compute cierra cada operacion con un segundo evento SIN
            // peticion; ese no cambia nada.
            return;
        };
        let reemplaza = metodo.contains("firewalls.insert") || metodo.contains("firewalls.update");
        let fuentes = ci(&p, "sourceRanges").map(|v| {
            lista_con_tope(v)
                .0
                .into_iter()
                .filter_map(texto)
                .collect::<Vec<_>>()
        });
        let permitidos = ci(&p, "alloweds").or_else(|| ci(&p, "allowed")).map(|v| {
            lista_con_tope(v)
                .0
                .into_iter()
                .map(|a| {
                    let proto = ci(a, "IPProtocol")
                        .and_then(texto)
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    let puertos = ci(a, "ports")
                        .map(|p| lista_con_tope(p).0.into_iter().filter_map(texto).collect())
                        .unwrap_or_default();
                    (proto, puertos)
                })
                .collect::<Vec<_>>()
        });
        let direccion = ci(&p, "direction").and_then(texto);
        let deshabilitada = ci(&p, "disabled").and_then(booleano);
        r.borrada = false;
        r.error = None;
        if reemplaza {
            // Sin origen declarado, GCP aplica 0.0.0.0/0 a una regla de
            // entrada: esa es la semantica documentada, no una suposicion.
            let sin_origen = fuentes.is_none()
                && ci(&p, "sourceTags").is_none()
                && ci(&p, "sourceServiceAccounts").is_none();
            r.fuentes = if sin_origen {
                Some(vec!["0.0.0.0/0".into()])
            } else {
                Some(fuentes.unwrap_or_default())
            };
            r.permitidos = Some(permitidos.unwrap_or_default());
            r.entrada = Some(direccion.is_none_or(|d| d.eq_ignore_ascii_case("INGRESS")));
            r.deshabilitada = Some(deshabilitada.unwrap_or(false));
        } else {
            if fuentes.is_some() {
                r.fuentes = fuentes;
            }
            if permitidos.is_some() {
                r.permitidos = permitidos;
            }
            if let Some(d) = direccion {
                r.entrada = Some(d.eq_ignore_ascii_case("INGRESS"));
            }
            if deshabilitada.is_some() {
                r.deshabilitada = deshabilitada;
            }
        }
        let ext = format!("{} por {}", l.accion, l.usuario);
        r.evidencia.con_extracto(&ext);
    }

    fn gcp_sink(&mut self, l: &Llamada<'_>, borrar: bool) {
        let p = l.peticion();
        let recurso = p
            .as_deref()
            .and_then(|p| ci(p, "sinkName").and_then(texto))
            .or_else(|| l.recurso.contains("/sinks/").then(|| l.recurso.clone()))
            .or_else(|| {
                p.as_deref()
                    .and_then(|p| ruta(p, &["sink", "name"]).and_then(texto))
                    .map(|n| format!("{}/sinks/{n}", l.recurso))
            })
            .unwrap_or_else(|| l.recurso.clone());
        let recurso = recortar(&recurso, MAX_RECURSO);
        let eid = eid_recurso(l.proveedor, &recurso);
        if borrar {
            let ev = Evidencia::nueva(
                l.referencia(),
                &format!("{} de {} borro el sink {recurso}", l.accion, l.usuario),
            );
            self.poner(
                LOG_001,
                &recurso,
                l.proveedor,
                &recurso,
                eid,
                Situacion::Mala(ev),
            );
            self.apagar(l, &recurso);
            return;
        }
        let deshabilitado = p
            .as_deref()
            .and_then(|p| ruta(p, &["sink", "disabled"]).and_then(booleano));
        match deshabilitado {
            Some(true) => {
                let ev = Evidencia::nueva(
                    l.referencia(),
                    &format!(
                        "{} de {} deshabilito el sink {recurso}",
                        l.accion, l.usuario
                    ),
                );
                self.poner(
                    LOG_001,
                    &recurso,
                    l.proveedor,
                    &recurso,
                    eid,
                    Situacion::Mala(ev),
                );
                self.apagar(l, &recurso);
            }
            _ if p.is_some() => {
                let ev = Evidencia::nueva(
                    l.referencia(),
                    &format!("{} deja exportando el sink {recurso}", l.accion),
                );
                self.poner(
                    LOG_001,
                    &recurso,
                    l.proveedor,
                    &recurso,
                    eid,
                    Situacion::Buena(ev),
                );
                self.encender(l.proveedor, &recurso, l.evento.ocurrio_ns);
            }
            _ => {
                self.sin_detalle(l.proveedor);
                let ev = Evidencia::nueva(l.referencia(), &l.accion);
                self.poner(
                    LOG_001,
                    &recurso,
                    l.proveedor,
                    &recurso,
                    eid,
                    Situacion::Incierta(
                        "sink creado o cambiado sin cuerpo legible (hace falta el crudo)".into(),
                        ev,
                    ),
                );
            }
        }
    }

    // --- Resultados --------------------------------------------------------

    /// Los veredictos por entidad, en orden estable (comprobacion, recurso).
    #[must_use]
    pub fn resultados(&self, ahora_ns: u64) -> Vec<Resultado> {
        let mut v: Vec<Resultado> = self
            .piezas
            .iter()
            .map(|((c, _), p)| Resultado {
                comprobacion: c,
                proveedor: p.proveedor,
                recurso: p.recurso.clone(),
                entidad: p.entidad.clone(),
                estado: p.situacion.en_estado(),
            })
            .collect();
        for (nombre, cubo) in &self.cubos {
            let arn = format!("arn:aws:s3:::{nombre}");
            v.push(Resultado {
                comprobacion: ALM_001,
                proveedor: Proveedor::Aws,
                recurso: arn.clone(),
                entidad: eid_recurso(Proveedor::Aws, &arn),
                estado: veredicto_cubo(cubo).en_estado(),
            });
        }
        for recurso in self.trails.keys() {
            if let Some(s) = self.veredicto_trail(recurso) {
                v.push(Resultado {
                    comprobacion: LOG_001,
                    proveedor: Proveedor::Aws,
                    recurso: recurso.clone(),
                    entidad: eid_recurso(Proveedor::Aws, recurso),
                    estado: s.en_estado(),
                });
            }
        }
        for (recurso, r) in &self.reglas_gcp {
            v.push(Resultado {
                comprobacion: RED_001,
                proveedor: Proveedor::Gcp,
                recurso: recurso.clone(),
                entidad: eid_recurso(Proveedor::Gcp, recurso),
                estado: veredicto_regla_gcp(recurso, r).en_estado(),
            });
        }
        for (id, c) in &self.claves {
            v.push(Resultado {
                comprobacion: CLV_001,
                proveedor: c.proveedor,
                recurso: recortar(&format!("clave {id} de {}", c.dueno), MAX_RECURSO),
                entidad: entidad::cuenta(&c.dueno),
                estado: veredicto_clave(id, c, ahora_ns).en_estado(),
            });
        }
        v.extend(self.compromisos());
        v.sort_by(|a, b| {
            (a.comprobacion, a.proveedor, &a.recurso).cmp(&(
                b.comprobacion,
                b.proveedor,
                &b.recurso,
            ))
        });
        v
    }

    /// Los apagados del registro seguidos de gestion de cuentas.
    fn compromisos(&self) -> Vec<Resultado> {
        let mut v = Vec::new();
        for a in &self.apagados {
            // Mismo instante que el apagado cuenta: dos llamadas en el mismo
            // segundo son la secuencia, no una coincidencia.
            let gestiones: Vec<&Gestion> = self
                .gestiones
                .iter()
                .filter(|g| {
                    g.proveedor == a.proveedor
                        && cuentas_compatibles(&g.cuenta, &a.cuenta)
                        && (g.ns == a.ns || Self::dentro(a, g.ns))
                        && g.referencia != a.referencia
                })
                .collect();
            let recurso = format!("{} apagado por {}", a.recurso, a.actor);
            let situacion = if gestiones.is_empty() {
                let visibles = self.visibles_tras(a);
                let ev = Evidencia::nueva(a.referencia.clone(), &recurso);
                if visibles > 0 {
                    let mut ev = ev;
                    ev.con_extracto(&format!(
                        "tras apagar {} se siguieron viendo {visibles} eventos (otra fuente sigue \
                         registrando) y ninguno fue gestion de cuentas",
                        a.recurso
                    ));
                    Situacion::Buena(ev)
                } else {
                    Situacion::Incierta(
                        format!(
                            "tras apagar {} no llego ningun evento: el registro que diria si hubo \
                             gestion de cuentas es el que se apago",
                            a.recurso
                        ),
                        ev,
                    )
                }
            } else {
                let acciones: Vec<&str> = gestiones.iter().map(|g| g.accion.as_str()).collect();
                let mut ev = Evidencia::nueva(
                    a.referencia.clone(),
                    &format!(
                        "{} apago {} y despues, con el registro apagado, hubo {} accion(es) de \
                         gestion de cuentas: {}",
                        a.actor,
                        a.recurso,
                        gestiones.len(),
                        acciones.join(", ")
                    ),
                );
                for g in gestiones {
                    ev.anadir(g.referencia.clone());
                }
                Situacion::Mala(ev)
            };
            v.push(Resultado {
                comprobacion: LOG_002,
                proveedor: a.proveedor,
                recurso: recortar(&recurso, MAX_RECURSO),
                entidad: entidad::cuenta(&a.actor),
                estado: situacion.en_estado(),
            });
        }
        v
    }

    /// Desde cuando esta ciego un proveedor: el primer apagado del registro que
    /// no se volvio a encender y tras el que no llego ningun evento.
    ///
    /// Si despues del apagado siguen llegando eventos, otra fuente (un trail
    /// de organizacion, otra region) sigue registrando y no hay ceguera que
    /// declarar.
    #[must_use]
    pub fn ciego_desde(&self, p: Proveedor) -> Option<u64> {
        self.apagados
            .iter()
            .filter(|a| a.proveedor == p && a.hasta_ns.is_none() && self.visibles_tras(a) == 0)
            .map(|a| a.ns)
            .min()
    }

    /// Fin de la ventana de un apagado: el reencendido o
    /// [`VENTANA_COMPROMISO_NS`], lo que llegue antes.
    fn fin(a: &Apagado) -> u64 {
        a.hasta_ns
            .unwrap_or(u64::MAX)
            .min(a.ns.saturating_add(VENTANA_COMPROMISO_NS))
    }

    /// Si un instante cae dentro de la ventana de un apagado. Con reencendido
    /// la ventana es abierta por arriba: el propio evento que vuelve a
    /// encender no demuestra que se viera nada mientras estuvo apagado.
    fn dentro(a: &Apagado, ns: u64) -> bool {
        let fin = Self::fin(a);
        if a.hasta_ns.is_some() {
            ns > a.ns && ns < fin
        } else {
            ns > a.ns && ns <= fin
        }
    }

    /// Eventos del mismo proveedor y cuenta vistos durante la ventana de un
    /// apagado.
    fn visibles_tras(&self, a: &Apagado) -> usize {
        let fin = Self::fin(a);
        self.actividad.get(&a.proveedor).map_or(0, |act| {
            let desde = act.partition_point(|(ns, _)| *ns <= a.ns);
            act[desde..]
                .iter()
                .take_while(|(ns, _)| *ns <= fin)
                .filter(|(ns, c)| Self::dentro(a, *ns) && cuentas_compatibles(c, &a.cuenta))
                .count()
        })
    }
}

fn veredicto_cubo(c: &Cubo) -> Situacion {
    if let Some(e) = &c.borrado {
        return Situacion::Buena(e.clone());
    }
    let (restringe, ignora, bloqueo_ev) = match &c.bloqueo {
        FacetaBloqueo::Conocido(b, e) => (b.restringir, b.ignorar_acls, Some((b, e))),
        _ => (false, false, None),
    };
    let mut malas = Evidencia::default();
    let mut motivos = Vec::new();
    if let Faceta::Publica(e) = &c.politica {
        if !restringe {
            malas.unir(e);
            motivos.push(e.extracto.clone());
        }
    }
    if let Faceta::Publica(e) = &c.acl {
        if !ignora {
            malas.unir(e);
            motivos.push(e.extracto.clone());
        }
    }
    if let Some((b, e)) = bloqueo_ev {
        if b.nulo() {
            malas.unir(e);
            motivos.push(e.extracto.clone());
        }
    }
    if !motivos.is_empty() {
        malas.con_extracto(&motivos.join("; "));
        return Situacion::Mala(malas);
    }
    if let Some((b, e)) = bloqueo_ev {
        if b.completo() {
            let mut ev = e.clone();
            let nota = if matches!(c.politica, Faceta::Publica(_))
                || matches!(c.acl, Faceta::Publica(_))
            {
                " (hay una politica o ACL publica, neutralizada por el bloqueo)"
            } else {
                ""
            };
            ev.con_extracto(&format!(
                "bloqueo de acceso publico completo en el cubo{nota}"
            ));
            return Situacion::Buena(ev);
        }
    }
    let mut ilegibles = Vec::new();
    let mut ev = Evidencia::default();
    for f in [&c.politica, &c.acl] {
        if let Faceta::Ilegible(m, e) = f {
            ilegibles.push(m.clone());
            ev.unir(e);
        }
    }
    if let FacetaBloqueo::Ilegible(m, e) = &c.bloqueo {
        ilegibles.push(m.clone());
        ev.unir(e);
    }
    if !ilegibles.is_empty() {
        return Situacion::Incierta(ilegibles.join("; "), ev);
    }
    let conocida = |f: &Faceta| matches!(f, Faceta::NoPublica(_) | Faceta::Publica(_));
    if conocida(&c.politica) && conocida(&c.acl) {
        let mut ev = Evidencia::default();
        for f in [&c.politica, &c.acl] {
            if let Faceta::NoPublica(e) | Faceta::Publica(e) = f {
                ev.unir(e);
            }
        }
        ev.con_extracto("politica y ACL observadas, ninguna publica");
        return Situacion::Buena(ev);
    }
    let mut falta = Vec::new();
    let mut ev = Evidencia::default();
    for (nombre, f) in [("la politica", &c.politica), ("la ACL", &c.acl)] {
        match f {
            Faceta::Desconocida => falta.push(nombre),
            Faceta::NoPublica(e) | Faceta::Publica(e) | Faceta::Ilegible(_, e) => ev.unir(e),
        }
    }
    if let FacetaBloqueo::Conocido(_, e) = &c.bloqueo {
        ev.unir(e);
    }
    Situacion::Incierta(
        format!(
            "no se observo {} del cubo ni un bloqueo de acceso publico completo",
            falta.join(" ni ")
        ),
        ev,
    )
}

/// La ACL de un `PutBucketAcl`: predefinida (`x-amz-acl`) o explicita
/// (`AccessControlPolicy.AccessControlList.Grant[].Grantee.URI`).
fn faceta_acl(p: &Value, r: Referencia, nombre: &str, actor: &str, completo: bool) -> Faceta {
    const PREDEFINIDAS: [&str; 3] = ["public-read", "public-read-write", "authenticated-read"];
    let predefinidas: Vec<String> = ci(p, "x-amz-acl")
        .map(|v| lista_con_tope(v).0.into_iter().filter_map(texto).collect())
        .unwrap_or_default();
    if let Some(c) = predefinidas
        .iter()
        .find(|c| PREDEFINIDAS.contains(&c.as_str()))
    {
        return Faceta::Publica(Evidencia::nueva(
            r,
            &format!("PutBucketAcl de {actor} puso la ACL predefinida {c} en {nombre}"),
        ));
    }
    let concesiones = ruta(p, &["AccessControlPolicy", "AccessControlList", "Grant"]);
    let mut cortada = false;
    if let Some(g) = concesiones {
        let (l, c) = lista_con_tope(g);
        cortada = c;
        for gr in l {
            let uri = ruta(gr, &["Grantee", "URI"])
                .and_then(texto)
                .unwrap_or_default();
            if uri.ends_with("/global/AllUsers") || uri.ends_with("/global/AuthenticatedUsers") {
                let permiso = ci(gr, "Permission").and_then(texto).unwrap_or_default();
                let grupo = uri.rsplit('/').next().unwrap_or_default();
                return Faceta::Publica(Evidencia::nueva(
                    r,
                    &format!("PutBucketAcl de {actor} concede {permiso} a {grupo} en {nombre}"),
                ));
            }
        }
    }
    let vista = !predefinidas.is_empty() || ci(p, "AccessControlPolicy").is_some();
    match (vista, completo && !cortada) {
        (true, true) => Faceta::NoPublica(Evidencia::nueva(
            r,
            &format!("PutBucketAcl en {nombre} sin concesiones a AllUsers ni AuthenticatedUsers"),
        )),
        (true, false) => Faceta::Ilegible(
            "la ACL no se vio entera (aplanado recortado o demasiadas concesiones)".into(),
            Evidencia::nueva(r, "PutBucketAcl"),
        ),
        (false, _) => Faceta::Ilegible(
            "PutBucketAcl sin ACL legible".into(),
            Evidencia::nueva(r, "PutBucketAcl"),
        ),
    }
}

fn veredicto_regla_gcp(recurso: &str, r: &ReglaGcp) -> Situacion {
    if r.borrada {
        let mut ev = r.evidencia.clone();
        ev.con_extracto(&format!("la regla {recurso} se borro"));
        return Situacion::Buena(ev);
    }
    if let Some(m) = &r.error {
        return Situacion::Incierta(m.clone(), r.evidencia.clone());
    }
    let (Some(fuentes), Some(permitidos)) = (&r.fuentes, &r.permitidos) else {
        return Situacion::Incierta(
            "no se observo la definicion completa de la regla (origen y puertos)".into(),
            r.evidencia.clone(),
        );
    };
    let entrada = r.entrada.unwrap_or(true);
    let activa = !r.deshabilitada.unwrap_or(false);
    let publica = fuentes.iter().find(|f| *f == "0.0.0.0/0" || *f == "::/0");
    let puerto = permitidos.iter().find_map(|(proto, puertos)| {
        let proto_ok = matches!(proto.as_str(), "all" | "tcp" | "udp" | "6" | "17");
        if !proto_ok {
            return None;
        }
        if proto == "all" || puertos.is_empty() {
            return Some(format!("{proto} todos los puertos"));
        }
        puertos
            .iter()
            .find(|p| cubre_admin(p))
            .map(|p| format!("{proto}:{p}"))
    });
    let mut ev = r.evidencia.clone();
    match (entrada && activa, publica, puerto) {
        (true, Some(f), Some(p)) => {
            let ext = format!("{}: permite {p} desde {f}", ev.extracto);
            ev.con_extracto(&ext);
            Situacion::Mala(ev)
        }
        _ => {
            let ext = format!("{}: no abre administracion a Internet", ev.extracto);
            ev.con_extracto(&ext);
            Situacion::Buena(ev)
        }
    }
}

fn veredicto_clave(id: &str, c: &Clave, ahora_ns: u64) -> Situacion {
    let mut ev = c.evidencia.clone();
    match c.estado {
        EstadoClave::Borrada => return Situacion::Buena(ev),
        EstadoClave::Inactiva => return Situacion::Buena(ev),
        EstadoClave::Activa => {}
    }
    if let Some(m) = &c.incierta {
        return Situacion::Incierta(m.clone(), ev);
    }
    let Some((ns, reloj)) = c.creada else {
        return Situacion::Incierta(
            format!(
                "la clave {id} de {} esta activa y su creacion no se observo en la ventana: su \
                 antiguedad no se puede afirmar",
                c.dueno
            ),
            ev,
        );
    };
    let edad = ahora_ns.saturating_sub(ns);
    let dias = edad / DIA_NS;
    let limite = DIAS_ROTACION * DIA_NS;
    if reloj == ConfianzaReloj::DeLlegada {
        // La hora es la de llegada, no la del proveedor: la creacion fue ANTES.
        // Si ya asi pasa del limite, pasa seguro; si no, no se sabe.
        if edad > limite {
            ev.con_extracto(&format!(
                "la clave {id} de {} tiene al menos {dias} dias y sigue activa",
                c.dueno
            ));
            return Situacion::Mala(ev);
        }
        return Situacion::Incierta(
            "la hora del alta es la de llegada del evento, no la del proveedor".into(),
            ev,
        );
    }
    if edad > limite {
        ev.con_extracto(&format!(
            "la clave {id} de {} se creo hace {dias} dias (mas de {DIAS_ROTACION}) y sigue activa",
            c.dueno
        ));
        Situacion::Mala(ev)
    } else {
        ev.con_extracto(&format!(
            "la clave {id} de {} se creo hace {dias} dias",
            c.dueno
        ));
        Situacion::Buena(ev)
    }
}

// --- Auxiliares -------------------------------------------------------------

/// La entidad de un recurso de nube.
///
/// # Por que `Ubicacion` y un espacio con forma de maquina
///
/// El modelo unico no tiene una clase «recurso de nube», y esta fase no la
/// añade: hay pruebas que fijan las clases. Lo mas honrado de lo que existe es
/// [`Clase::Ubicacion`](aegis_entidad::Clase::Ubicacion): un sitio donde vive
/// algo, sea cual sea lo que contenga — que es exactamente lo que es un cubo, un
/// grupo de seguridad o un trail. Una ubicacion se deriva de una maquina y una
/// ruta; aqui la «maquina» es el espacio de nombres del proveedor
/// (`nube:aws`, `nube:azure`, `nube:gcp`) y la ruta el identificador global del
/// recurso (ARN, `resourceId`, `resourceName`). El prefijo `nube:` no puede
/// coincidir con una matricula de la flota, y los tres identificadores ya son
/// unicos en su proveedor, asi que dos observadores llegan al mismo `Eid` sin
/// hablar.
///
/// Lo que se pierde se dice: `ubicacion` normaliza a minusculas. Los nombres de
/// cubo y los identificadores de Azure ya lo son (o no distinguen); un trail
/// llamado `Principal` y otro `principal` en la misma cuenta y region caerian
/// en la misma entidad.
#[must_use]
pub fn eid_recurso(p: Proveedor, recurso: &str) -> Eid {
    entidad::ubicacion(&entidad::maquina(&format!("nube:{}", p.nombre())), recurso)
}

fn cuenta_efectiva(l: &Llamada<'_>) -> String {
    match l.proveedor {
        Proveedor::Aws => l.cuenta.clone(),
        Proveedor::Azure => segmento_tras(&l.recurso.to_ascii_lowercase(), "/subscriptions/"),
        Proveedor::Gcp => {
            let p = segmento_tras(&l.recurso, "projects/");
            if p == "_" || p == "-" {
                String::new()
            } else {
                p
            }
        }
    }
}

fn segmento_tras(s: &str, marca: &str) -> String {
    s.find(marca)
        .map(|i| {
            s[i + marca.len()..]
                .split('/')
                .next()
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default()
}

fn cuentas_compatibles(a: &str, b: &str) -> bool {
    a.is_empty() || b.is_empty() || a == b
}

/// Si la llamada es gestion de cuentas: lo que el catalogo de `aegis-pipeline`
/// clasifica asi, mas los nombres REALES de GCP que ese catalogo no reconoce
/// (`google.iam.admin.v1.CreateServiceAccountKey` no contiene
/// `serviceAccounts.keys.create`).
fn es_gestion_de_cuentas(l: &Llamada<'_>) -> bool {
    if l.evento.clase == ClaseEvento::GestionDeCuentas {
        return true;
    }
    let a = l.accion.to_ascii_lowercase();
    [
        "createserviceaccountkey",
        "createserviceaccount",
        "setiampolicy",
        "createuser",
        "createaccesskey",
        "createloginprofile",
        "updateloginprofile",
        "addusertogroup",
        "updateassumerolepolicy",
        "roleassignments/write",
        "roledefinitions/write",
    ]
    .iter()
    .any(|x| a.ends_with(x))
}

fn principal_aws(p: &Value) -> Option<(&'static str, String)> {
    for (k, t) in [
        ("userName", "user"),
        ("roleName", "role"),
        ("groupName", "group"),
    ] {
        if let Some(n) = ci(p, k).and_then(texto).filter(|n| !n.is_empty()) {
            return Some((t, recortar(&n, 128)));
        }
    }
    None
}

fn es_administrator_access(arn: &str) -> bool {
    // Tambien en las particiones aws-cn y aws-us-gov.
    arn.starts_with("arn:aws") && arn.ends_with(":iam::aws:policy/AdministratorAccess")
}

fn nombre_politica(arn: &str) -> String {
    recortar(arn.rsplit('/').next().unwrap_or(arn), 128)
}

fn miembro_gcp(m: &str) -> &str {
    for p in ["user:", "serviceAccount:", "group:", "domain:"] {
        if let Some(r) = m.strip_prefix(p) {
            return r;
        }
    }
    m
}

fn cuenta_de_servicio(nombre: &str) -> Option<String> {
    let (_, resto) = nombre.split_once("serviceAccounts/")?;
    let sa = resto.split('/').next()?;
    (!sa.is_empty()).then(|| sa.to_string())
}

fn recurso_trail(l: &Llamada<'_>, nombre: &str) -> String {
    if let Some(resto) = nombre.strip_prefix("arn:") {
        // arn:aws:cloudtrail:REGION:CUENTA:trail/NOMBRE
        let partes: Vec<&str> = resto.splitn(5, ':').collect();
        if partes.len() == 5 {
            return recortar(nombre, MAX_RECURSO);
        }
    }
    recortar(
        &format!(
            "arn:aws:cloudtrail:{}:{}:trail/{nombre}",
            l.region, l.cuenta
        ),
        MAX_RECURSO,
    )
}

fn selectores(p: &Value) -> Selectores {
    if let Some(s) = ci(p, "eventSelectors") {
        let (l, cortada) = lista_con_tope(s);
        if l.is_empty() {
            return Selectores::Deficientes("deja el trail sin selectores de eventos".into());
        }
        let gestion: Vec<&Value> = l
            .into_iter()
            .filter(|x| {
                // Omitido, IncludeManagementEvents vale `true` en la API.
                ci(x, "includeManagementEvents")
                    .and_then(booleano)
                    .unwrap_or(true)
            })
            .collect();
        if gestion.is_empty() {
            return if cortada {
                Selectores::Ilegibles("mas selectores de los que se recorren".into())
            } else {
                Selectores::Deficientes(
                    "deja el trail sin eventos de gestion (includeManagementEvents=false)".into(),
                )
            };
        }
        let escritura = gestion.iter().any(|x| {
            ci(x, "readWriteType")
                .and_then(texto)
                .is_none_or(|t| !t.eq_ignore_ascii_case("ReadOnly"))
        });
        if !escritura {
            return Selectores::Deficientes(
                "deja el trail registrando solo lecturas: las escrituras de gestion no se \
                 registran"
                    .into(),
            );
        }
        return Selectores::Bien;
    }
    if let Some(a) = ci(p, "advancedEventSelectors") {
        let (l, cortada) = lista_con_tope(a);
        let gestion = l.into_iter().any(|sel| {
            ci(sel, "fieldSelectors")
                .map(|f| lista_con_tope(f).0)
                .unwrap_or_default()
                .into_iter()
                .any(|f| {
                    ci(f, "field")
                        .and_then(texto)
                        .is_some_and(|x| x == "eventCategory")
                        && ci(f, "equals")
                            .map(|e| lista_con_tope(e).0)
                            .unwrap_or_default()
                            .into_iter()
                            .filter_map(texto)
                            .any(|x| x == "Management")
                })
        });
        return match (gestion, cortada) {
            (true, _) => Selectores::Bien,
            (false, true) => Selectores::Ilegibles("mas selectores de los que se recorren".into()),
            (false, false) => Selectores::Deficientes(
                "los selectores avanzados no incluyen eventCategory=Management".into(),
            ),
        };
    }
    Selectores::Ilegibles("PutEventSelectors sin selectores legibles".into())
}

/// Las entradas de `ipPermissions` que abren un puerto de administracion a
/// Internet: (protocolo, desde, hasta, cidr). Y si alguna lista se corto.
fn entradas_abiertas(p: &Value) -> (Vec<(String, i64, i64, String)>, bool) {
    let mut v = Vec::new();
    let Some(perms) = ci(p, "ipPermissions") else {
        return (v, false);
    };
    let (perms, mut cortada) = lista_con_tope(perms);
    for perm in perms {
        let proto = ci(perm, "ipProtocol").and_then(texto).unwrap_or_default();
        let desde = ci(perm, "fromPort").and_then(entero).unwrap_or(-1);
        let hasta = ci(perm, "toPort").and_then(entero).unwrap_or(-1);
        if !abre_admin(&proto, desde, hasta) {
            continue;
        }
        for (lista_k, cidr_k) in [("ipRanges", "cidrIp"), ("ipv6Ranges", "cidrIpv6")] {
            let Some(rangos) = ci(perm, lista_k) else {
                continue;
            };
            let (rangos, c) = lista_con_tope(rangos);
            cortada |= c;
            for r in rangos {
                if let Some(cidr) = ci(r, cidr_k).and_then(texto) {
                    if cidr == "0.0.0.0/0" || cidr == "::/0" {
                        v.push((proto.clone(), desde, hasta, cidr));
                    }
                }
            }
        }
    }
    (v, cortada)
}

fn abre_admin(proto: &str, desde: i64, hasta: i64) -> bool {
    match proto.to_ascii_lowercase().as_str() {
        "-1" | "all" => true,
        "tcp" | "udp" | "6" | "17" => {
            if desde < 0 || hasta < 0 {
                return true;
            }
            PUERTOS_ADMIN.iter().any(|p| (desde..=hasta).contains(p))
        }
        _ => false,
    }
}

fn clave_entrada(sg: &str, proto: &str, desde: i64, hasta: i64, cidr: &str) -> String {
    let proto = match proto.to_ascii_lowercase().as_str() {
        "6" => "tcp".to_string(),
        "17" => "udp".to_string(),
        "all" => "-1".to_string(),
        otro => otro.to_string(),
    };
    format!("{sg}|{proto}|{desde}-{hasta}|{cidr}")
}

fn nombre_proto(p: &str) -> String {
    if p == "-1" {
        "todos los protocolos".into()
    } else {
        recortar(p, 16)
    }
}

fn rango_puertos(desde: i64, hasta: i64) -> String {
    if desde < 0 || hasta < 0 || (desde == 0 && hasta == 65535) {
        "todos los puertos".into()
    } else if desde == hasta {
        format!("puerto {desde}")
    } else {
        format!("puertos {desde}-{hasta}")
    }
}

/// Si una especificacion de puertos (`*`, `22`, `20-30`) cubre alguno de
/// administracion.
fn cubre_admin(spec: &str) -> bool {
    let s = spec.trim();
    if s == "*" {
        return true;
    }
    if let Some((a, b)) = s.split_once('-') {
        if let (Ok(a), Ok(b)) = (a.trim().parse::<i64>(), b.trim().parse::<i64>()) {
            return PUERTOS_ADMIN.iter().any(|p| (a..=b).contains(p));
        }
        return false;
    }
    s.parse::<i64>().is_ok_and(|p| PUERTOS_ADMIN.contains(&p))
}

fn es_origen_publico_azure(o: &str) -> bool {
    ["*", "internet", "any", "0.0.0.0/0", "0.0.0.0", "::/0"]
        .iter()
        .any(|x| o.trim().eq_ignore_ascii_case(x))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn los_puertos_de_administracion_se_reconocen_en_rangos() {
        assert!(cubre_admin("22"));
        assert!(cubre_admin("*"));
        assert!(cubre_admin("3000-4000"));
        assert!(!cubre_admin("443"));
        assert!(!cubre_admin("8000-9000"));
        assert!(!cubre_admin("x-y"));
        assert!(abre_admin("-1", -1, -1));
        assert!(abre_admin("tcp", 0, 65535));
        assert!(!abre_admin("tcp", 443, 443));
        assert!(!abre_admin("icmp", -1, -1));
    }

    #[test]
    fn la_cuenta_efectiva_sale_del_recurso_en_azure_y_gcp() {
        assert_eq!(
            segmento_tras("/subscriptions/s1/resourcegroups/rg", "/subscriptions/"),
            "s1"
        );
        assert_eq!(segmento_tras("projects/p1/sinks/x", "projects/"), "p1");
    }

    #[test]
    fn un_miembro_de_gcp_se_reduce_a_su_correo() {
        assert_eq!(miembro_gcp("user:ana@corp.com"), "ana@corp.com");
        assert_eq!(miembro_gcp("allUsers"), "allUsers");
    }

    #[test]
    fn administrator_access_en_todas_las_particiones() {
        assert!(es_administrator_access(
            "arn:aws:iam::aws:policy/AdministratorAccess"
        ));
        assert!(es_administrator_access(
            "arn:aws-us-gov:iam::aws:policy/AdministratorAccess"
        ));
        assert!(!es_administrator_access(
            "arn:aws:iam::123:policy/AdministratorAccess"
        ));
    }
}
