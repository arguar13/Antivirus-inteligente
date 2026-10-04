//! El canal de contenido firmado, visto desde el agente (FASE 4.5 del MP-16).
//!
//! El agente solo carga contenido (reglas, modelos) desde un paquete que verifica
//! con la clave hibrida del canal, con epoca monotona y dentro de su anillo; todo
//! eso lo impone `aegis-contenido`. Aqui estan las ordenes de operador y el
//! informe al arrancar:
//!
//! ```text
//!   aegis-agent --contenido estado
//!   aegis-agent --contenido instalar PAQUETE.aegc
//!   aegis-agent --contenido ajustes AJUSTES.aegs
//!   aegis-agent --contenido revertir          (rollback local en un comando)
//!   opciones: --dir DIR --clave CLAVE.pub --canal CANAL
//! ```
//!
//! # Lo que aun NO hace
//!
//! Ningun motor consume todavia estas reglas: el motor de patrones no corre aun
//! en el trabajador confinado ni hay motor Sigma en el agente. Lo dice al
//! arrancar en vez de callarlo. La identidad con la que se decide el anillo es
//! la de la maquina ([`crate::motores::Identidad`]), que hoy sale de
//! `/etc/machine-id`: dos clones de una imagen caen en el mismo anillo hasta que
//! la identidad sea la de la matriculacion.

use std::path::PathBuf;
use std::process::ExitCode;

use aegis_contenido::{
    Almacen, ClaveVerificacionHibrida, ContenidoActivo, Modo, Validadores, Verificacion,
};

/// Directorio del almacen de contenido.
pub const DIR_POR_DEFECTO: &str = "/var/lib/aegiscore/contenido";
/// Clave publica hibrida del canal (bytes crudos de `ClaveVerificacionHibrida`).
pub const CLAVE_POR_DEFECTO: &str = "/etc/aegiscore/contenido.pub";
/// Canal que sigue el agente.
pub const CANAL_POR_DEFECTO: &str = "estable";

/// Donde esta cada cosa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Directorio del almacen.
    pub dir: PathBuf,
    /// Fichero de la clave publica.
    pub clave: PathBuf,
    /// Canal.
    pub canal: String,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            dir: DIR_POR_DEFECTO.into(),
            clave: CLAVE_POR_DEFECTO.into(),
            canal: CANAL_POR_DEFECTO.into(),
        }
    }
}

/// Una orden de operador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Orden {
    /// Que hay cargado.
    Estado,
    /// Instalar un paquete sellado.
    Instalar(PathBuf),
    /// Aplicar unos ajustes sellados.
    Ajustes(PathBuf),
    /// Volver al paquete anterior.
    Revertir,
}

/// Interpreta lo que va detras de `--contenido`, y rechaza lo que no conoce.
///
/// # Errores
/// El motivo, para la linea de ordenes.
pub fn interpretar(args: &[String]) -> Result<(Orden, Config), String> {
    let mut cfg = Config::default();
    let mut orden = None;
    let mut i = 0;
    while i < args.len() {
        let valor = |i: usize| {
            args.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{} necesita un valor", args[i]))
        };
        let nueva = match args[i].as_str() {
            "--dir" => {
                cfg.dir = valor(i)?.into();
                i += 2;
                None
            }
            "--clave" => {
                cfg.clave = valor(i)?.into();
                i += 2;
                None
            }
            "--canal" => {
                cfg.canal = valor(i)?;
                i += 2;
                None
            }
            "estado" => {
                i += 1;
                Some(Orden::Estado)
            }
            "revertir" => {
                i += 1;
                Some(Orden::Revertir)
            }
            "instalar" => {
                let f = valor(i)?;
                i += 2;
                Some(Orden::Instalar(f.into()))
            }
            "ajustes" => {
                let f = valor(i)?;
                i += 2;
                Some(Orden::Ajustes(f.into()))
            }
            otra => return Err(format!("argumento desconocido tras --contenido: {otra}")),
        };
        if let Some(o) = nueva {
            if orden.is_some() {
                return Err("una sola orden por invocacion".into());
            }
            orden = Some(o);
        }
    }
    let orden = orden.ok_or_else(|| {
        "falta la orden: estado, instalar FICHERO, ajustes FICHERO o revertir".to_string()
    })?;
    Ok((orden, cfg))
}

/// La verificacion de este equipo: clave, canal, identidad y validadores.
///
/// # Errores
/// Si la clave no se puede leer o no es una clave hibrida valida.
pub fn verificacion(cfg: &Config, id_equipo: &str) -> Result<Verificacion, String> {
    let bytes = std::fs::read(&cfg.clave).map_err(|e| {
        format!(
            "no se pudo leer la clave del canal {}: {e}",
            cfg.clave.display()
        )
    })?;
    let clave = ClaveVerificacionHibrida::desde_bytes(&bytes)
        .map_err(|e| format!("clave del canal {} invalida: {e}", cfg.clave.display()))?;
    Ok(Verificacion::nueva(
        clave,
        cfg.canal.clone(),
        id_equipo,
        Validadores::por_defecto(),
    ))
}

/// Una linea con lo cargado.
#[must_use]
pub fn resumen(c: &ContenidoActivo) -> String {
    format!(
        "contenido canal={} epoca={} epoca_vista={} anillo={} imponer={} auditoria={} \
         apagadas={} ajustes={}{}",
        c.canal,
        c.epoca,
        c.epoca_vista,
        c.anillo,
        c.cuantas(Modo::Imponer),
        c.cuantas(Modo::Auditoria),
        c.apagadas.len(),
        c.epoca_ajustes,
        if c.recuperado_de_anterior {
            " (recuperado del anterior tras una instalacion cortada)"
        } else {
            ""
        }
    )
}

/// Ejecuta una orden y devuelve lo que hay que decir.
///
/// # Errores
/// El motivo, en texto.
pub fn ejecutar_orden(orden: &Orden, cfg: &Config, id_equipo: &str) -> Result<String, String> {
    let v = verificacion(cfg, id_equipo)?;
    let mut almacen = Almacen::abrir(&cfg.dir).map_err(|e| e.to_string())?;
    match orden {
        Orden::Estado => almacen
            .cargar(&v)
            .map(|c| resumen(&c))
            .map_err(|e| format!("sin contenido utilizable: {e}")),
        Orden::Instalar(f) => {
            let b = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
            let i = almacen.instalar(&b, &v).map_err(|e| e.to_string())?;
            Ok(format!(
                "instalado: epoca {} del anillo {} con {} regla(s)",
                i.epoca, i.anillo, i.reglas
            ))
        }
        Orden::Ajustes(f) => {
            let b = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
            let e = almacen.aplicar_ajustes(&b, &v).map_err(|e| e.to_string())?;
            Ok(format!("ajustes aplicados: epoca {e}"))
        }
        Orden::Revertir => {
            let r = almacen.revertir(&v).map_err(|e| e.to_string())?;
            Ok(format!(
                "revertido a la epoca {} (la epoca vista sigue en {}: lo anterior que llegue \
                 por la red se sigue rechazando)",
                r.epoca_restaurada, r.epoca_vista
            ))
        }
    }
}

fn id_del_equipo() -> String {
    crate::motores::Identidad::del_host().maquina.texto()
}

/// `aegis-agent --contenido ...`: codigo 0 si fue bien, 1 si la orden fallo y
/// 2 si la linea de ordenes no se entiende.
pub fn orden(args: &[String]) -> ExitCode {
    let (o, cfg) = match interpretar(args) {
        Ok(x) => x,
        Err(m) => {
            eprintln!("aegis-agent: {m}");
            return ExitCode::from(2);
        }
    };
    match ejecutar_orden(&o, &cfg, &id_del_equipo()) {
        Ok(linea) => {
            println!("{linea}");
            ExitCode::SUCCESS
        }
        Err(m) => {
            eprintln!("aegis-agent: contenido: {m}");
            ExitCode::from(1)
        }
    }
}

/// Al arrancar: dice que contenido hay y si verifica, o por que no. Nunca
/// impide arrancar: sin contenido del canal, el agente protege con lo que
/// lleva en el binario, y lo declara.
pub fn informar_al_arrancar() {
    let cfg = Config::default();
    if !cfg.clave.exists() {
        eprintln!(
            "aegis-agent: DEGRADADO contenido: no hay clave del canal en {}; solo se usan las \
             reglas del binario",
            cfg.clave.display()
        );
        return;
    }
    let cargado = verificacion(&cfg, &id_del_equipo()).and_then(|v| {
        Almacen::abrir(&cfg.dir)
            .and_then(|a| a.cargar(&v))
            .map_err(|e| e.to_string())
    });
    match cargado {
        Ok(c) => eprintln!(
            "aegis-agent: {} (verificado; ningun motor lo consume aun)",
            resumen(&c)
        ),
        Err(m) => eprintln!("aegis-agent: DEGRADADO contenido: {m}"),
    }
}
