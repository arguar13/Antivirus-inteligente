//! El catalogo de pasos listos: aislar, matar, cuarentena, revocar tickets,
//! deshabilitar cuenta, bloquear indicador, abrir caso, enriquecer y notificar.
//!
//! # Que declara cada uno
//!
//! | paso                  | entrada              | reversion                                   | firma | frenos |
//! |-----------------------|----------------------|---------------------------------------------|-------|--------|
//! | `aislar`              | `Objetivo<Maquina>`  | liberar, si no estaba ya aislada            | si    | si     |
//! | `aislar grupo`        | `Vec<Objetivo<Maquina>>` | liberar las que no estaban ya aisladas  | si    | si     |
//! | `matar`               | `Objetivo<Proceso>`  | IRREVERSIBLE: un proceso no revive          | si    | si     |
//! | `cuarentena`          | `Objetivo<Fichero>`  | restaurar el fichero                        | no    | si     |
//! | `revocar tickets`     | `Objetivo<Cuenta>`   | IRREVERSIBLE: un ticket revocado no vuelve  | si    | si     |
//! | `deshabilitar cuenta` | `Objetivo<Cuenta>`   | rehabilitar, si no estaba ya deshabilitada  | si    | si     |
//! | `bloquear indicador`  | [`Indicador`]        | el estado de ANTES del bloqueo              | no    | si     |
//! | `abrir caso`          | lo que sea           | cerrar el caso como «no concluyente»        | no    | no     |
//! | `enriquecer`          | `Objetivo<Contenido>`| nada: solo lee, y solo dentro               | no    | no     |
//! | `notificar`           | lo que sea           | anularla o, si ya salio, rectificarla       | no    | no     |
//! | `tomar`               | lo que sea           | nada: no tiene efecto, ramifica el grafo    | no    | no     |
//!
//! La columna «firma» no es una opcion: es el tipo del permiso del paso, y un
//! flujo que intenta meter un paso firmado sin [`Firma`] no compila.
//!
//! # Revertir es volver al estado de antes, no «hacer lo contrario»
//!
//! Cada paso guarda en su `Deshacer` como estaba lo que toca ANTES de tocarlo.
//! Una maquina que ya estaba aislada antes del flujo sigue aislada despues de
//! revertirlo; una red que ya estaba bloqueada por otra orden no se desbloquea;
//! una cuenta que un administrador ya habia deshabilitado no se rehabilita.
//! «Hacer lo contrario» desharia trabajo que el flujo no hizo.
//!
//! # Idempotencia
//!
//! Cada efecto tiene un identificador DERIVADO de la ejecucion, el paso y su
//! clave ([`Puertos::id_efecto`]). Reintentar la misma ejecucion produce los
//! mismos identificadores, y la base de datos rechaza el duplicado: la orden de
//! matar un proceso se encola una vez aunque el flujo se reintente diez.

use std::marker::PhantomData;

use aegis_case::Severidad;
use aegis_entidad::Eid;
use sha2::{Digest, Sha256};

use crate::firma::Firma;
use crate::paso::{ErrorPaso, Fut, Paso, Reversibilidad, SinFirma};
use crate::tipos::{
    Contenido, Cuenta, Fichero, LocFichero, LocProceso, Maquina, Objetivo, Proceso, Tipo,
};

/// Un indicador de red que bloquear en toda la flota: una direccion o una red.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Indicador {
    red: ipnet::IpNet,
}

impl Indicador {
    /// Una direccion (`10.0.0.5`) o una red (`10.0.0.0/24`).
    ///
    /// # Errors
    ///
    /// [`ErrorPaso::Entrada`] si no es ninguna de las dos.
    pub fn nuevo(texto: &str) -> Result<Indicador, ErrorPaso> {
        let t = texto.trim();
        let red = t
            .parse::<ipnet::IpNet>()
            .or_else(|_| t.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
            .map_err(|_| ErrorPaso::Entrada(format!("«{t}» no es una direccion ni una red")))?;
        // Normalizada: 10.0.0.7/24 es la red 10.0.0.0/24. Sin esto, dos
        // bloqueos de la misma red escritos distinto serian dos filas.
        Ok(Indicador { red: red.trunc() })
    }

    /// La red.
    #[must_use]
    pub fn red(&self) -> ipnet::IpNet {
        self.red
    }
}

/// Lo que implica una entrada: con que entidades se abre un caso o de que
/// habla una notificacion.
pub trait Implicados: Clone + Send + Sync + 'static {
    /// Las entidades.
    fn implicados(&self) -> Vec<Eid>;
    /// Una linea legible.
    fn describir(&self) -> String;
}

impl<T: Tipo> Implicados for Objetivo<T> {
    fn implicados(&self) -> Vec<Eid> {
        vec![self.eid().clone()]
    }
    fn describir(&self) -> String {
        format!("{} {:?}", T::NOMBRE, self.loc())
    }
}

impl Implicados for Indicador {
    fn implicados(&self) -> Vec<Eid> {
        Vec::new()
    }
    fn describir(&self) -> String {
        format!("indicador de red {}", self.red)
    }
}

/// Como estaba un aislamiento antes de aislar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrevioAislamiento {
    /// Matricula de la maquina.
    pub cn: String,
    /// Si ya estaba aislada: entonces no se toco nada y no hay nada que deshacer.
    pub ya_estaba: bool,
    /// La orden encolada, si se encolo.
    pub orden: Option<uuid::Uuid>,
}

/// Una orden encolada a un agente, para poder deshacerla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdenAgente {
    /// Matricula de la maquina.
    pub cn: String,
    /// La orden.
    pub orden: uuid::Uuid,
}

/// Como estaba una cuenta antes de deshabilitarla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrevioCuenta {
    /// La cuenta.
    pub cuenta: String,
    /// Si ya estaba deshabilitada.
    pub ya_estaba: bool,
}

/// Como estaba un bloqueo antes de bloquear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrevioBloqueo {
    /// No habia fila: el bloqueo es del flujo y al revertir se levanta.
    Nuevo(ipnet::IpNet),
    /// Ya estaba vigente por otra orden: no se toco.
    YaVigente(ipnet::IpNet),
    /// Habia una fila levantada: al revertir vuelve a quedar levantada, como
    /// estaba, con quien y cuando la levanto.
    Levantado {
        /// La red.
        red: ipnet::IpNet,
        /// La fila de antes, entera.
        fila: FilaBloqueo,
    },
}

/// Una fila de la cuarentena de red, tal cual.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilaBloqueo {
    /// Endpoint por cuya causa se ordeno.
    pub cn_origen: Option<String>,
    /// Motivo.
    pub motivo: String,
    /// Quien.
    pub ordenada_por: String,
    /// Cuando, en microsegundos Unix.
    pub ordenada_us: i64,
    /// Caducidad, en microsegundos Unix.
    pub expira_us: Option<i64>,
    /// Cuando se levanto, en microsegundos Unix.
    pub levantada_us: Option<i64>,
    /// Quien la levanto.
    pub levantada_por: Option<String>,
}

/// Un caso abierto por un flujo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasoAbierto {
    /// Su identificador.
    pub id: String,
    /// Si ya existia (el flujo se reintento): entonces al revertir no se cierra
    /// dos veces.
    pub ya_existia: bool,
}

/// Lo que se sabe DENTRO de un contenido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enriquecimiento {
    /// El SHA-256.
    pub sha256: String,
    /// Maquinas con alertas sobre este contenido.
    pub maquinas: Vec<String>,
    /// Alertas sobre este contenido.
    pub alertas: i64,
    /// Objetos de inteligencia que lo mencionan.
    pub inteligencia: Vec<String>,
}

/// Una notificacion enviada por un flujo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notificacion {
    /// Su identificador.
    pub id: uuid::Uuid,
    /// Si ya existia (reintento).
    pub ya_existia: bool,
}

/// Los puertos con los que actua el catalogo: el estado real de la flota.
///
/// Cada metodo es idempotente contra ese estado; ver [`crate::pg`] para la
/// implementacion sobre el esquema del plano de control.
pub trait Puertos: Send + Sync + 'static {
    /// Quien ordena: queda en cada fila que toca el flujo.
    fn actor(&self) -> &str;

    /// La ejecucion en curso: reintentarla es volver a pasar la misma.
    fn ejecucion(&self) -> &str;

    /// El identificador de un efecto: el mismo para la misma ejecucion, paso y
    /// clave, y distinto para cualquier otra.
    fn id_efecto(&self, paso: &str, clave: &str) -> uuid::Uuid {
        let mut h = Sha256::new();
        for p in [self.ejecucion(), paso, clave] {
            h.update(p.as_bytes());
            h.update([0x1f]);
        }
        let d: [u8; 32] = h.finalize().into();
        let mut b = [0u8; 16];
        b.copy_from_slice(&d[..16]);
        // Un UUID de version 8 (a medida, RFC 9562): derivado, no aleatorio.
        uuid::Builder::from_custom_bytes(b).into_uuid()
    }

    /// Aisla una maquina.
    fn aislar<'a>(
        &'a self,
        cn: &'a str,
        orden: uuid::Uuid,
    ) -> Fut<'a, Result<PrevioAislamiento, ErrorPaso>>;
    /// Deshace un aislamiento.
    fn deshacer_aislamiento(&self, previo: PrevioAislamiento) -> Fut<'_, Result<(), ErrorPaso>>;
    /// Ordena matar un proceso.
    fn matar<'a>(
        &'a self,
        p: &'a LocProceso,
        orden: uuid::Uuid,
    ) -> Fut<'a, Result<OrdenAgente, ErrorPaso>>;
    /// Ordena poner un fichero en cuarentena.
    fn cuarentena<'a>(
        &'a self,
        f: &'a LocFichero,
        orden: uuid::Uuid,
    ) -> Fut<'a, Result<OrdenAgente, ErrorPaso>>;
    /// Deshace una cuarentena de fichero.
    fn restaurar<'a>(&'a self, f: &'a LocFichero, o: OrdenAgente)
        -> Fut<'a, Result<(), ErrorPaso>>;
    /// Ordena revocar los tickets de una cuenta.
    fn revocar_tickets<'a>(
        &'a self,
        cuenta: &'a str,
        orden: uuid::Uuid,
    ) -> Fut<'a, Result<uuid::Uuid, ErrorPaso>>;
    /// Deshabilita una cuenta.
    fn deshabilitar<'a>(
        &'a self,
        cuenta: &'a str,
        orden: uuid::Uuid,
    ) -> Fut<'a, Result<PrevioCuenta, ErrorPaso>>;
    /// Deshace una deshabilitacion.
    fn rehabilitar(&self, previo: PrevioCuenta) -> Fut<'_, Result<(), ErrorPaso>>;
    /// Las maquinas de la flota cuya direccion cae dentro de una red.
    fn maquinas_en(&self, red: ipnet::IpNet) -> Fut<'_, Result<Vec<String>, ErrorPaso>>;
    /// Bloquea una red en toda la flota.
    fn bloquear(&self, red: ipnet::IpNet) -> Fut<'_, Result<PrevioBloqueo, ErrorPaso>>;
    /// Deshace un bloqueo, volviendo al estado de antes.
    fn restaurar_bloqueo(&self, previo: PrevioBloqueo) -> Fut<'_, Result<(), ErrorPaso>>;
    /// Abre un caso.
    fn abrir_caso<'a>(
        &'a self,
        id: &'a str,
        titulo: &'a str,
        severidad: &'a str,
        detalle: &'a str,
        implicados: &'a [Eid],
    ) -> Fut<'a, Result<CasoAbierto, ErrorPaso>>;
    /// Cierra un caso abierto por un flujo revertido.
    fn cerrar_caso_revertido(&self, caso: CasoAbierto) -> Fut<'_, Result<(), ErrorPaso>>;
    /// Lo que se sabe dentro de un contenido.
    fn enriquecer<'a>(&'a self, sha256: &'a str) -> Fut<'a, Result<Enriquecimiento, ErrorPaso>>;
    /// Encola una notificacion.
    fn notificar<'a>(
        &'a self,
        id: uuid::Uuid,
        destino: &'a str,
        texto: &'a str,
    ) -> Fut<'a, Result<Notificacion, ErrorPaso>>;
    /// Anula una notificacion o, si ya salio, envia la rectificacion.
    fn anular_notificacion(&self, n: Notificacion) -> Fut<'_, Result<(), ErrorPaso>>;
}

fn uno(e: &Eid) -> Fut<'_, Result<Vec<Eid>, ErrorPaso>> {
    let v = vec![e.clone()];
    Box::pin(async move { Ok(v) })
}

fn nada() -> Fut<'static, Result<(), ErrorPaso>> {
    Box::pin(async { Ok(()) })
}

/// Aisla una maquina de la red, salvo el canal con el plano de control.
#[derive(Debug, Clone, Copy, Default)]
pub struct Aislar;

impl<C: Puertos> Paso<C> for Aislar {
    type Entrada = Objetivo<Maquina>;
    type Salida = Objetivo<Maquina>;
    type Deshacer = PrevioAislamiento;
    type Permiso = Firma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
    const TOCA_FLOTA: bool = true;

    fn nombre(&self) -> &'static str {
        "aislar"
    }
    fn objetivos<'a>(
        &'a self,
        m: &'a Objetivo<Maquina>,
        _: &'a C,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        uno(m.eid())
    }
    fn clave(&self, m: &Objetivo<Maquina>) -> String {
        m.eid().texto()
    }
    fn ejecutar<'a>(
        &'a self,
        m: &'a Objetivo<Maquina>,
        ctx: &'a C,
    ) -> Fut<'a, Result<(Objetivo<Maquina>, PrevioAislamiento), ErrorPaso>> {
        Box::pin(async move {
            let orden = ctx.id_efecto("aislar", &m.eid().texto());
            let previo = ctx.aislar(m.loc(), orden).await?;
            Ok((m.clone(), previo))
        })
    }
    fn revertir<'a>(
        &'a self,
        previo: PrevioAislamiento,
        ctx: &'a C,
    ) -> Fut<'a, Result<(), ErrorPaso>> {
        ctx.deshacer_aislamiento(previo)
    }
}

/// Un `Hasher` que alimenta un SHA-256: la huella de una entrada con `Hash`
/// sin las colisiones de un resumen de 64 bits.
struct HuellaSha(Sha256);

impl std::hash::Hasher for HuellaSha {
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    fn finish(&self) -> u64 {
        // No lo usa `Tomar` (usa el SHA-256 entero), pero si alguien lo pide,
        // recibe un resumen coherente y no un panico.
        let d: [u8; 32] = self.0.clone().finalize().into();
        u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
    }
}

/// Toma una parte de la entrada: la maquina de un incidente, su cuenta, su red.
///
/// No tiene efecto —no toca nada, y revertirlo no hace nada—; existe para que el
/// grafo se pueda ramificar con tipos: de un `Incidente` salen un
/// `Objetivo<Maquina>` hacia «aislar» y un `Objetivo<Cuenta>` hacia
/// «deshabilitar cuenta», y el compilador comprueba las dos ramas.
pub struct Tomar<E, S> {
    etiqueta: String,
    f: std::sync::Arc<dyn Fn(&E) -> S + Send + Sync>,
}

impl<E, S> Tomar<E, S> {
    /// Toma con `f`. La etiqueta distingue dos tomas del mismo flujo (y es su
    /// clave de idempotencia).
    pub fn nueva(etiqueta: &str, f: impl Fn(&E) -> S + Send + Sync + 'static) -> Tomar<E, S> {
        Tomar {
            etiqueta: etiqueta.to_string(),
            f: std::sync::Arc::new(f),
        }
    }
}

impl<E, S> std::fmt::Debug for Tomar<E, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tomar")
            .field("etiqueta", &self.etiqueta)
            .finish()
    }
}

impl<C, E, S> Paso<C> for Tomar<E, S>
where
    C: Send + Sync + 'static,
    E: Clone + std::hash::Hash + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
{
    type Entrada = E;
    type Salida = S;
    type Deshacer = ();
    type Permiso = SinFirma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
    const TOCA_FLOTA: bool = false;

    fn nombre(&self) -> &'static str {
        "tomar"
    }
    fn objetivos<'a>(&'a self, _: &'a E, _: &'a C) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    /// La etiqueta y la huella de la entrada: dos tomas con la misma etiqueta
    /// sobre entradas distintas son dos tomas distintas, y el motor no toma la
    /// salida de una por la de la otra.
    fn clave(&self, e: &E) -> String {
        let mut h = HuellaSha(Sha256::new());
        std::hash::Hash::hash(e, &mut h);
        let d: [u8; 32] = h.0.finalize().into();
        let hex: String = d[..16].iter().map(|b| format!("{b:02x}")).collect();
        format!("{}|{hex}", self.etiqueta)
    }
    fn ejecutar<'a>(&'a self, e: &'a E, _: &'a C) -> Fut<'a, Result<(S, ()), ErrorPaso>> {
        let s = (self.f)(e);
        Box::pin(async move { Ok((s, ())) })
    }
    /// Sin efecto: nada que deshacer.
    fn revertir<'a>(&'a self, (): (), _: &'a C) -> Fut<'a, Result<(), ErrorPaso>> {
        nada()
    }
}

/// Aisla un grupo de maquinas en un solo paso: un equipo, una subred, «todas
/// las que tienen este binario».
///
/// Es la forma natural de escribir una contencion amplia, y por eso la que un
/// error de plantilla convierte en «aislar la flota entera». Su radio es el
/// grupo entero y los frenos lo miran entero, aunque venga firmado: una firma
/// dice que una persona lo aprobo, no que el radio sea razonable.
#[derive(Debug, Clone, Copy, Default)]
pub struct AislarGrupo;

impl<C: Puertos> Paso<C> for AislarGrupo {
    type Entrada = Vec<Objetivo<Maquina>>;
    type Salida = Vec<Objetivo<Maquina>>;
    type Deshacer = Vec<PrevioAislamiento>;
    type Permiso = Firma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
    const TOCA_FLOTA: bool = true;

    fn nombre(&self) -> &'static str {
        "aislar grupo"
    }
    fn objetivos<'a>(
        &'a self,
        g: &'a Vec<Objetivo<Maquina>>,
        _: &'a C,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        let v: Vec<Eid> = g.iter().map(|m| m.eid().clone()).collect();
        Box::pin(async move { Ok(v) })
    }
    fn clave(&self, g: &Vec<Objetivo<Maquina>>) -> String {
        let mut v: Vec<String> = g.iter().map(|m| m.eid().texto()).collect();
        v.sort();
        v.dedup();
        v.join(",")
    }
    fn ejecutar<'a>(
        &'a self,
        g: &'a Vec<Objetivo<Maquina>>,
        ctx: &'a C,
    ) -> Fut<'a, Result<(Vec<Objetivo<Maquina>>, Vec<PrevioAislamiento>), ErrorPaso>> {
        Box::pin(async move {
            let mut previos = Vec::with_capacity(g.len());
            for m in g {
                let orden = ctx.id_efecto("aislar", &m.eid().texto());
                match ctx.aislar(m.loc(), orden).await {
                    Ok(p) => previos.push(p),
                    Err(e) => {
                        // A medias dentro del propio paso: se deshace lo que
                        // este paso hizo antes de fallar, porque el motor solo
                        // revierte pasos COMPLETADOS.
                        // Si eso tambien falla, el error lo dice: una maquina
                        // aislada que nadie sabe que lo esta es peor que el
                        // fallo original.
                        let mut sueltas = Vec::new();
                        for p in previos.into_iter().rev() {
                            let cn = p.cn.clone();
                            if let Err(d) = ctx.deshacer_aislamiento(p).await {
                                sueltas.push(format!("{cn}: {d}"));
                            }
                        }
                        if sueltas.is_empty() {
                            return Err(e);
                        }
                        return Err(ErrorPaso::Fallo(format!(
                            "{e}; y quedaron aisladas sin poder liberarlas: {}",
                            sueltas.join("; ")
                        )));
                    }
                }
            }
            Ok((g.clone(), previos))
        })
    }
    fn revertir<'a>(
        &'a self,
        previos: Vec<PrevioAislamiento>,
        ctx: &'a C,
    ) -> Fut<'a, Result<(), ErrorPaso>> {
        Box::pin(async move {
            let mut fallos = Vec::new();
            for p in previos.into_iter().rev() {
                let cn = p.cn.clone();
                if let Err(e) = ctx.deshacer_aislamiento(p).await {
                    fallos.push(format!("{cn}: {e}"));
                }
            }
            if fallos.is_empty() {
                Ok(())
            } else {
                Err(ErrorPaso::Fallo(format!(
                    "no se pudieron liberar: {}",
                    fallos.join("; ")
                )))
            }
        })
    }
}

/// Mata un proceso concreto (maquina, arranque, pid e instante de arranque:
/// nunca «el pid 4242», que puede ser ya otro proceso).
#[derive(Debug, Clone, Copy, Default)]
pub struct Matar;

impl<C: Puertos> Paso<C> for Matar {
    type Entrada = Objetivo<Proceso>;
    type Salida = Objetivo<Proceso>;
    type Deshacer = OrdenAgente;
    type Permiso = Firma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Irreversible;
    const TOCA_FLOTA: bool = true;

    fn nombre(&self) -> &'static str {
        "matar"
    }
    fn objetivos<'a>(
        &'a self,
        p: &'a Objetivo<Proceso>,
        _: &'a C,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        uno(p.eid())
    }
    fn clave(&self, p: &Objetivo<Proceso>) -> String {
        p.eid().texto()
    }
    fn ejecutar<'a>(
        &'a self,
        p: &'a Objetivo<Proceso>,
        ctx: &'a C,
    ) -> Fut<'a, Result<(Objetivo<Proceso>, OrdenAgente), ErrorPaso>> {
        Box::pin(async move {
            let orden = ctx.id_efecto("matar", &p.eid().texto());
            Ok((p.clone(), ctx.matar(p.loc(), orden).await?))
        })
    }
    /// No hay nada que hacer: el motor no llama a esto para un paso
    /// irreversible, y si lo llamara, no fingiria resucitar un proceso.
    fn revertir<'a>(&'a self, _: OrdenAgente, _: &'a C) -> Fut<'a, Result<(), ErrorPaso>> {
        Box::pin(async {
            Err(ErrorPaso::Fallo(
                "un proceso matado no se puede revivir".into(),
            ))
        })
    }
}

/// Pone un fichero en cuarentena en su maquina.
#[derive(Debug, Clone, Copy, Default)]
pub struct Cuarentena;

impl<C: Puertos> Paso<C> for Cuarentena {
    type Entrada = Objetivo<Fichero>;
    type Salida = Objetivo<Fichero>;
    type Deshacer = (LocFichero, OrdenAgente);
    type Permiso = SinFirma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
    const TOCA_FLOTA: bool = true;

    fn nombre(&self) -> &'static str {
        "cuarentena"
    }
    fn objetivos<'a>(
        &'a self,
        f: &'a Objetivo<Fichero>,
        _: &'a C,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        uno(f.eid())
    }
    fn clave(&self, f: &Objetivo<Fichero>) -> String {
        f.eid().texto()
    }
    fn ejecutar<'a>(
        &'a self,
        f: &'a Objetivo<Fichero>,
        ctx: &'a C,
    ) -> Fut<'a, Result<(Objetivo<Fichero>, (LocFichero, OrdenAgente)), ErrorPaso>> {
        Box::pin(async move {
            let orden = ctx.id_efecto("cuarentena", &f.eid().texto());
            let o = ctx.cuarentena(f.loc(), orden).await?;
            Ok((f.clone(), (f.loc().clone(), o)))
        })
    }
    fn revertir<'a>(
        &'a self,
        (f, o): (LocFichero, OrdenAgente),
        ctx: &'a C,
    ) -> Fut<'a, Result<(), ErrorPaso>> {
        Box::pin(async move { ctx.restaurar(&f, o).await })
    }
}

/// Revoca los tickets Kerberos de una cuenta.
#[derive(Debug, Clone, Copy, Default)]
pub struct RevocarTickets;

impl<C: Puertos> Paso<C> for RevocarTickets {
    type Entrada = Objetivo<Cuenta>;
    type Salida = Objetivo<Cuenta>;
    type Deshacer = uuid::Uuid;
    type Permiso = Firma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Irreversible;
    const TOCA_FLOTA: bool = true;

    fn nombre(&self) -> &'static str {
        "revocar tickets"
    }
    fn objetivos<'a>(
        &'a self,
        c: &'a Objetivo<Cuenta>,
        _: &'a C,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        uno(c.eid())
    }
    fn clave(&self, c: &Objetivo<Cuenta>) -> String {
        c.eid().texto()
    }
    fn ejecutar<'a>(
        &'a self,
        c: &'a Objetivo<Cuenta>,
        ctx: &'a C,
    ) -> Fut<'a, Result<(Objetivo<Cuenta>, uuid::Uuid), ErrorPaso>> {
        Box::pin(async move {
            let orden = ctx.id_efecto("revocar tickets", &c.eid().texto());
            Ok((c.clone(), ctx.revocar_tickets(c.loc(), orden).await?))
        })
    }
    /// Un ticket revocado no vuelve: la cuenta tendra que pedir otro. Lo que
    /// se puede hacer despues es rehabilitar la cuenta, y eso es otro paso.
    fn revertir<'a>(&'a self, _: uuid::Uuid, _: &'a C) -> Fut<'a, Result<(), ErrorPaso>> {
        Box::pin(async {
            Err(ErrorPaso::Fallo(
                "unos tickets revocados no se pueden restituir".into(),
            ))
        })
    }
}

/// Deshabilita una cuenta en el directorio.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeshabilitarCuenta;

impl<C: Puertos> Paso<C> for DeshabilitarCuenta {
    type Entrada = Objetivo<Cuenta>;
    type Salida = Objetivo<Cuenta>;
    type Deshacer = PrevioCuenta;
    type Permiso = Firma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
    const TOCA_FLOTA: bool = true;

    fn nombre(&self) -> &'static str {
        "deshabilitar cuenta"
    }
    fn objetivos<'a>(
        &'a self,
        c: &'a Objetivo<Cuenta>,
        _: &'a C,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        uno(c.eid())
    }
    fn clave(&self, c: &Objetivo<Cuenta>) -> String {
        c.eid().texto()
    }
    fn ejecutar<'a>(
        &'a self,
        c: &'a Objetivo<Cuenta>,
        ctx: &'a C,
    ) -> Fut<'a, Result<(Objetivo<Cuenta>, PrevioCuenta), ErrorPaso>> {
        Box::pin(async move {
            let orden = ctx.id_efecto("deshabilitar cuenta", &c.eid().texto());
            Ok((c.clone(), ctx.deshabilitar(c.loc(), orden).await?))
        })
    }
    fn revertir<'a>(&'a self, previo: PrevioCuenta, ctx: &'a C) -> Fut<'a, Result<(), ErrorPaso>> {
        ctx.rehabilitar(previo)
    }
}

/// Bloquea una direccion o una red en toda la flota (cuarentena de enjambre,
/// FASE 44).
///
/// Sus objetivos son las MAQUINAS DE LA FLOTA que quedan dentro: bloquear una
/// red corta a todas ellas. Es el radio real que miran los frenos, y el que
/// para el error de plantilla que escribe `0.0.0.0/0` donde iba una direccion.
#[derive(Debug, Clone, Copy, Default)]
pub struct BloquearIndicador;

impl<C: Puertos> Paso<C> for BloquearIndicador {
    type Entrada = Indicador;
    type Salida = Indicador;
    type Deshacer = PrevioBloqueo;
    type Permiso = SinFirma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
    const TOCA_FLOTA: bool = true;

    fn nombre(&self) -> &'static str {
        "bloquear indicador"
    }
    fn objetivos<'a>(
        &'a self,
        i: &'a Indicador,
        ctx: &'a C,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        Box::pin(async move {
            Ok(ctx
                .maquinas_en(i.red)
                .await?
                .iter()
                .map(|cn| aegis_entidad::entidad::maquina(cn))
                .collect())
        })
    }
    fn clave(&self, i: &Indicador) -> String {
        i.red.to_string()
    }
    fn ejecutar<'a>(
        &'a self,
        i: &'a Indicador,
        ctx: &'a C,
    ) -> Fut<'a, Result<(Indicador, PrevioBloqueo), ErrorPaso>> {
        Box::pin(async move { Ok((i.clone(), ctx.bloquear(i.red).await?)) })
    }
    fn revertir<'a>(&'a self, previo: PrevioBloqueo, ctx: &'a C) -> Fut<'a, Result<(), ErrorPaso>> {
        ctx.restaurar_bloqueo(previo)
    }
}

/// Abre un caso con lo que implica la entrada.
#[derive(Debug, Clone)]
pub struct AbrirCaso<E> {
    /// Titulo.
    pub titulo: String,
    /// Severidad.
    pub severidad: Severidad,
    _e: PhantomData<fn(E)>,
}

impl<E> AbrirCaso<E> {
    /// Un paso que abre un caso.
    #[must_use]
    pub fn nuevo(titulo: &str, severidad: Severidad) -> AbrirCaso<E> {
        AbrirCaso {
            titulo: titulo.to_string(),
            severidad,
            _e: PhantomData,
        }
    }
}

impl<C: Puertos, E: Implicados> Paso<C> for AbrirCaso<E> {
    type Entrada = E;
    type Salida = CasoAbierto;
    type Deshacer = CasoAbierto;
    type Permiso = SinFirma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
    const TOCA_FLOTA: bool = false;

    fn nombre(&self) -> &'static str {
        "abrir caso"
    }
    fn objetivos<'a>(&'a self, e: &'a E, _: &'a C) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        let v = e.implicados();
        Box::pin(async move { Ok(v) })
    }
    fn clave(&self, e: &E) -> String {
        format!("{}|{}", self.titulo, e.describir())
    }
    fn ejecutar<'a>(
        &'a self,
        e: &'a E,
        ctx: &'a C,
    ) -> Fut<'a, Result<(CasoAbierto, CasoAbierto), ErrorPaso>> {
        Box::pin(async move {
            let id = format!(
                "flujo-{}",
                ctx.id_efecto("abrir caso", &Paso::<C>::clave(self, e))
                    .simple()
            );
            let caso = ctx
                .abrir_caso(
                    &id,
                    &self.titulo,
                    self.severidad.nombre(),
                    &e.describir(),
                    &e.implicados(),
                )
                .await?;
            Ok((caso.clone(), caso))
        })
    }
    fn revertir<'a>(&'a self, caso: CasoAbierto, ctx: &'a C) -> Fut<'a, Result<(), ErrorPaso>> {
        if caso.ya_existia {
            return nada();
        }
        ctx.cerrar_caso_revertido(caso)
    }
}

/// Lo que se sabe de un contenido DENTRO de la instancia: que maquinas lo han
/// visto y que inteligencia lo menciona. No pregunta fuera —no revela nada—.
#[derive(Debug, Clone, Copy, Default)]
pub struct Enriquecer;

impl<C: Puertos> Paso<C> for Enriquecer {
    type Entrada = Objetivo<Contenido>;
    type Salida = Enriquecimiento;
    type Deshacer = ();
    type Permiso = SinFirma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
    const TOCA_FLOTA: bool = false;

    fn nombre(&self) -> &'static str {
        "enriquecer"
    }
    fn objetivos<'a>(
        &'a self,
        c: &'a Objetivo<Contenido>,
        _: &'a C,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        uno(c.eid())
    }
    fn clave(&self, c: &Objetivo<Contenido>) -> String {
        c.eid().texto()
    }
    fn ejecutar<'a>(
        &'a self,
        c: &'a Objetivo<Contenido>,
        ctx: &'a C,
    ) -> Fut<'a, Result<(Enriquecimiento, ()), ErrorPaso>> {
        Box::pin(async move { Ok((ctx.enriquecer(c.loc()).await?, ())) })
    }
    /// Solo lee: no hay nada que deshacer.
    fn revertir<'a>(&'a self, (): (), _: &'a C) -> Fut<'a, Result<(), ErrorPaso>> {
        nada()
    }
}

/// Notifica a un destino (un equipo, una guardia) lo que implica la entrada, y
/// la deja pasar.
///
/// Su reversion es una COMPENSACION y se dice: si la notificacion aun no ha
/// salido, se anula; si ya salio, lo que se puede hacer es mandar otra que la
/// rectifique. Un mensaje leido no se «des-lee».
#[derive(Debug, Clone)]
pub struct Notificar<E> {
    /// A quien.
    pub destino: String,
    _e: PhantomData<fn(E)>,
}

impl<E> Notificar<E> {
    /// Un paso que notifica a `destino`.
    #[must_use]
    pub fn a(destino: &str) -> Notificar<E> {
        Notificar {
            destino: destino.to_string(),
            _e: PhantomData,
        }
    }
}

impl<C: Puertos, E: Implicados> Paso<C> for Notificar<E> {
    type Entrada = E;
    type Salida = E;
    type Deshacer = Notificacion;
    type Permiso = SinFirma;
    const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
    const TOCA_FLOTA: bool = false;

    fn nombre(&self) -> &'static str {
        "notificar"
    }
    fn objetivos<'a>(&'a self, e: &'a E, _: &'a C) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>> {
        let v = e.implicados();
        Box::pin(async move { Ok(v) })
    }
    fn clave(&self, e: &E) -> String {
        format!("{}|{}", self.destino, e.describir())
    }
    fn ejecutar<'a>(
        &'a self,
        e: &'a E,
        ctx: &'a C,
    ) -> Fut<'a, Result<(E, Notificacion), ErrorPaso>> {
        Box::pin(async move {
            let id = ctx.id_efecto("notificar", &Paso::<C>::clave(self, e));
            let texto = format!("respuesta automatica: {}", e.describir());
            Ok((e.clone(), ctx.notificar(id, &self.destino, &texto).await?))
        })
    }
    fn revertir<'a>(&'a self, n: Notificacion, ctx: &'a C) -> Fut<'a, Result<(), ErrorPaso>> {
        if n.ya_existia {
            return nada();
        }
        ctx.anular_notificacion(n)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_indicador_se_normaliza() {
        assert_eq!(
            Indicador::nuevo("10.0.0.7/24").unwrap().red().to_string(),
            "10.0.0.0/24"
        );
        assert_eq!(
            Indicador::nuevo(" 10.0.0.5 ").unwrap().red().to_string(),
            "10.0.0.5/32"
        );
        assert_eq!(
            Indicador::nuevo("::1").unwrap().red().to_string(),
            "::1/128"
        );
        assert!(Indicador::nuevo("10.0.0.300").is_err());
        assert!(Indicador::nuevo("rm -rf /").is_err());
    }
}
