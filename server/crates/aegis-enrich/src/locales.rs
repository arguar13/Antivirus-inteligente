//! Los analizadores que no salen de la organizacion.
//!
//! # Por que existen, y no son un relleno
//!
//! Son los que hacen que el modo sin salida sea **degradado y no apagado**. Un
//! producto cuyo enriquecimiento entero depende de terceros no sirve en una red
//! aislada, y las redes aisladas son justo las de los clientes que mas lo
//! necesitan: industria, defensa, sanidad.
//!
//! Y hay una segunda razon, menos evidente: lo que la organizacion **ya sabe**
//! —sus listas, sus excepciones, lo que decidio la semana pasada— es mejor
//! informacion que cualquier reputacion externa, porque es sobre su propia red.
//! Consultar fuera antes de mirar dentro es el orden equivocado.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::analizador::{Analizador, Encargo, Ficha};
use crate::dictamen::{Clase, Dictamen, Juicio};
use crate::exposicion::Exposicion;
use crate::observable::{Observable, Tipo};
use crate::salida::Salida;

/// Lo que la organizacion ya decidio sobre un observable.
///
/// Es la fuente mas autorizada que hay para su propia red, y por eso su clase es
/// [`Clase::Propia`]: no repite lo que alguien dijo, **es** la decision.
#[derive(Debug, Default)]
pub struct Listas {
    ficha: Option<Ficha>,
    bloqueados: BTreeSet<String>,
    permitidos: BTreeSet<String>,
    motivos: std::collections::BTreeMap<String, String>,
}

impl Listas {
    /// Unas listas vacias.
    #[must_use]
    pub fn nuevas(nombre: &str) -> Listas {
        Listas {
            ficha: Some(Ficha {
                nombre: nombre.to_string(),
                clase: Clase::Propia,
                // Acepta todo: las listas de una organizacion cubren rutas y
                // cuentas igual que resumenes, y son precisamente los observables
                // que NO pueden salir — asi que si no los mirara nadie aqui, no los
                // miraria nadie en absoluto.
                acepta: Tipo::todos().to_vec(),
                exposicion: Exposicion::ninguna(),
                cuota: None,
                plazo: Duration::from_millis(50),
            }),
            ..Listas::default()
        }
    }

    /// Marca algo como malo, con el motivo por el que se decidio.
    ///
    /// El motivo es obligatorio: una lista de bloqueo sin motivos es una lista que
    /// nadie se atreve a limpiar, porque nadie sabe por que esta cada linea. A los
    /// dos años bloquea cosas que ya no hacen falta y nadie lo toca.
    pub fn bloquear(&mut self, o: &Observable, motivo: impl Into<String>) {
        let k = clave(o);
        self.permitidos.remove(&k);
        self.motivos.insert(k.clone(), motivo.into());
        self.bloqueados.insert(k);
    }

    /// Marca algo como conocido y legitimo, con su motivo.
    pub fn permitir(&mut self, o: &Observable, motivo: impl Into<String>) {
        let k = clave(o);
        self.bloqueados.remove(&k);
        self.motivos.insert(k.clone(), motivo.into());
        self.permitidos.insert(k);
    }

    /// Cuantas entradas hay.
    #[must_use]
    pub fn cuantas(&self) -> (usize, usize) {
        (self.bloqueados.len(), self.permitidos.len())
    }
}

fn clave(o: &Observable) -> String {
    format!("{}:{}", o.tipo().nombre(), o.valor().to_ascii_lowercase())
}

impl Analizador for Listas {
    fn ficha(&self) -> &Ficha {
        self.ficha.as_ref().expect("las listas se crean con ficha")
    }

    fn mirar(&self, e: &Encargo, _s: Option<&dyn Salida>) -> Result<Dictamen, String> {
        let k = clave(&e.observable);
        let (juicio, confianza, porque) = if self.bloqueados.contains(&k) {
            (
                Juicio::Malicioso,
                100,
                self.motivos
                    .get(&k)
                    .cloned()
                    .unwrap_or_else(|| "esta en la lista de bloqueo de la organizacion".into()),
            )
        } else if self.permitidos.contains(&k) {
            (
                Juicio::Limpio,
                100,
                self.motivos
                    .get(&k)
                    .cloned()
                    .unwrap_or_else(|| "esta en la lista de permitidos de la organizacion".into()),
            )
        } else {
            // No estar en las listas NO es estar limpio. Es la misma disciplina de
            // tri-estado del resto del producto, y aqui es donde mas tienta
            // saltarsela: una lista de permitidos invita a leer «no bloqueado»
            // como «bueno».
            return Ok(Dictamen::desconocido(
                &self.ficha().nombre,
                Clase::Propia,
                e.observable.clone(),
                e.ahora_ns,
            ));
        };
        Ok(Dictamen {
            fuente: self.ficha().nombre.clone(),
            clase: Clase::Propia,
            observable: e.observable.clone(),
            juicio,
            confianza,
            observado_ns: e.ahora_ns,
            porque,
            etiquetas: vec![],
        })
    }
}

/// Heuristica de dominio generado por algoritmo.
///
/// # Lo que este analizador NO puede decir, y por que
///
/// **Nunca devuelve [`Juicio::Malicioso`].** Como mucho `Sospechoso`.
///
/// No es prudencia: es que la heuristica no puede distinguir un dominio de un
/// algoritmo de generacion de un nombre de una red de distribucion de contenidos
/// —`d3kx7p2q9.cloudfront.net`—, de un identificador de despliegue, o de una marca
/// corta en un alfabeto que no es el latino. Todos se parecen. Un analizador que
/// pudiera decir «malicioso» sobre esa base acabaria bloqueando el dominio de un
/// proveedor legitimo, y el dia que eso pase el cliente apaga el producto entero.
///
/// Lo que si hace bien es **ordenar una cola**: entre diez mil dominios vistos hoy,
/// dice cuales merecen que alguien los mire primero. Eso es util y es honesto.
#[derive(Debug)]
pub struct Dga {
    ficha: Ficha,
}

/// Entropia por caracter a partir de la cual una etiqueta llama la atencion.
///
/// 3,4 bits. El ingles escrito ronda 2,2-2,5 bits por letra; una cadena aleatoria
/// de veintiseis letras llega a 4,7. El umbral esta deliberadamente alto: la
/// heuristica ordena una cola, no acusa a nadie.
pub const UMBRAL_ENTROPIA_MILI: u32 = 3400;

/// Longitud minima para juzgar una etiqueta.
///
/// Por debajo de esto la entropia no significa nada: `bbc` y `x7q` tienen
/// practicamente la misma, y una marca corta no puede salir sospechosa por serlo.
pub const MINIMO_ETIQUETA: usize = 8;

impl Dga {
    /// Crea el analizador.
    #[must_use]
    pub fn nuevo(nombre: &str) -> Dga {
        Dga {
            ficha: Ficha {
                nombre: nombre.to_string(),
                clase: Clase::Heuristica,
                acepta: vec![Tipo::Dominio, Tipo::Anfitrion],
                exposicion: Exposicion::ninguna(),
                cuota: None,
                plazo: Duration::from_millis(50),
            },
        }
    }
}

impl Analizador for Dga {
    fn ficha(&self) -> &Ficha {
        &self.ficha
    }

    fn mirar(&self, e: &Encargo, _s: Option<&dyn Salida>) -> Result<Dictamen, String> {
        let valor = e.observable.valor().trim().trim_end_matches('.');
        let desconocido = || {
            Ok(Dictamen::desconocido(
                &self.ficha.nombre,
                Clase::Heuristica,
                e.observable.clone(),
                e.ahora_ns,
            ))
        };

        // Se mira CADA etiqueta anterior al sufijo publico y se queda la peor, no
        // solo la registrable. Mirar solo la registrable perderia el tunel de DNS
        // —`a7f3b2c1d9e8.datos.ejemplo.com`, donde lo generado es el subdominio de
        // un dominio legitimo— que es justo el caso que nadie mas señala.
        let mut peor: Option<(String, Vec<String>)> = None;
        for etiqueta in etiquetas_candidatas(valor) {
            if etiqueta.len() < MINIMO_ETIQUETA {
                continue;
            }
            let indicios = indicios_de(&etiqueta);
            if indicios.is_empty() {
                continue;
            }
            if peor.as_ref().is_none_or(|(_, i)| indicios.len() > i.len()) {
                peor = Some((etiqueta, indicios));
            }
        }
        let Some((etiqueta, indicios)) = peor else {
            return desconocido();
        };

        // La confianza sube con el numero de indicios, y se queda muy por debajo
        // de la de una fuente que VIO algo. Es una probabilidad a priori sobre la
        // forma del nombre, no informacion sobre este caso.
        let confianza = match indicios.len() {
            1 => 25,
            2 => 40,
            _ => 55,
        };
        Ok(Dictamen {
            fuente: self.ficha.nombre.clone(),
            clase: Clase::Heuristica,
            observable: e.observable.clone(),
            // Nunca `Malicioso`: ver el encabezado del tipo.
            juicio: Juicio::Sospechoso,
            confianza,
            observado_ns: e.ahora_ns,
            porque: format!(
                "«{etiqueta}» tiene forma de nombre generado ({}). Es una heuristica sobre la \
                 FORMA, no informacion sobre este dominio: sirve para ordenar la cola, no para \
                 bloquear",
                indicios.join("; ")
            ),
            etiquetas: vec!["posible-dga".into()],
        })
    }
}

/// Los indicios de que una etiqueta esta generada, si los hay.
fn indicios_de(etiqueta: &str) -> Vec<String> {
    let mut indicios = Vec::new();
    let entropia = entropia_mili(etiqueta);
    if entropia >= UMBRAL_ENTROPIA_MILI {
        indicios.push(format!(
            "entropia {},{} bits por caracter (el texto normal ronda 2,3)",
            entropia / 1000,
            (entropia % 1000) / 100
        ));
    }
    let consonantes = racha_consonantes(etiqueta);
    if consonantes >= 5 {
        indicios.push(format!("{consonantes} consonantes seguidas"));
    }
    let digitos = proporcion_digitos_mili(etiqueta);
    if digitos >= 400 {
        indicios.push(format!("{} % de digitos", digitos / 10));
    }
    indicios
}

/// Las etiquetas que eligio quien monto el nombre, sin el sufijo publico.
///
/// Para `a7f3.datos.ejemplo.co.uk` son `["a7f3", "datos", "ejemplo"]`.
///
/// # Por que todas y no solo la registrable
///
/// Un algoritmo de generacion registra `xqzvbnmk.com`, asi que la etiqueta
/// registrable basta para ese caso. Pero un **tunel de DNS** usa un dominio
/// legitimo y mete los datos en el subdominio —`a7f3b2c1d9e8.datos.ejemplo.com`—,
/// y ahi la registrable (`ejemplo`) es perfectamente normal. Mirar solo esa
/// perderia justo el caso que casi nadie señala.
///
/// # El muro
///
/// La lista de sufijos compuestos **no** es la lista publica completa —eso es un
/// fichero de miles de lineas que hay que mantener al dia—. Con un sufijo raro se
/// incluye una etiqueta de mas, y una etiqueta de mas a lo sumo añade un candidato
/// que casi nunca dispara: el fallo es señalar de mas, nunca de menos, y de mas es
/// el lado seguro para una heuristica que solo ordena una cola.
fn etiquetas_candidatas(nombre: &str) -> Vec<String> {
    let n = nombre.to_ascii_lowercase();
    let partes: Vec<&str> = n.split('.').filter(|p| !p.is_empty()).collect();
    if partes.len() < 2 {
        return Vec::new();
    }
    const COMPUESTOS: &[&str] = &[
        "co.uk", "com.au", "co.jp", "com.br", "com.mx", "co.nz", "com.ar", "com.tr", "co.za",
        "com.cn", "org.uk", "gov.uk", "ac.uk", "net.au", "org.au",
    ];
    let dos_ultimas = format!("{}.{}", partes[partes.len() - 2], partes[partes.len() - 1]);
    let sufijo = if COMPUESTOS.contains(&dos_ultimas.as_str()) {
        2
    } else {
        1
    };
    if partes.len() <= sufijo {
        return Vec::new();
    }
    partes[..partes.len() - sufijo]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// Entropia de Shannon en milesimas de bit por caracter.
///
/// Entera y no en coma flotante: dos maquinas distintas tienen que producir el
/// mismo numero, o el mismo dominio sale sospechoso en un nodo y no en otro, y el
/// informe deja de ser reproducible.
fn entropia_mili(s: &str) -> u32 {
    let bytes: Vec<u8> = s.bytes().collect();
    if bytes.is_empty() {
        return 0;
    }
    let n = bytes.len() as u64;
    let mut cuentas = [0u32; 256];
    for b in &bytes {
        cuentas[*b as usize] += 1;
    }
    // H = -Σ p·log2(p) = log2(n) - (1/n)·Σ c·log2(c)
    let mut suma_mili: u64 = 0;
    for c in cuentas.iter().filter(|c| **c > 0) {
        suma_mili += u64::from(*c) * u64::from(log2_mili(u64::from(*c)));
    }
    let total_mili = u64::from(log2_mili(n));
    let resta = suma_mili / n;
    u32::try_from(total_mili.saturating_sub(resta)).unwrap_or(0)
}

/// log2 en milesimas, con aritmetica entera.
fn log2_mili(x: u64) -> u32 {
    if x == 0 {
        return 0;
    }
    let entero = 63 - x.leading_zeros();
    // Parte fraccionaria por division binaria: diez iteraciones dan tres decimales
    // de sobra y el resultado es identico en cualquier maquina.
    let mut resto = x as u128;
    let mut escala = 1u128 << entero;
    let mut frac_mili = 0u32;
    let mut paso = 500u32;
    for _ in 0..10 {
        resto = resto * resto / escala;
        escala <<= 0;
        if resto >= (escala << 1) {
            resto /= 2;
            frac_mili += paso;
        }
        // Renormaliza para no desbordar.
        while resto >= (escala << 1) {
            resto /= 2;
        }
        paso /= 2;
        if paso == 0 {
            break;
        }
    }
    entero * 1000 + frac_mili
}

/// La racha mas larga de consonantes seguidas.
fn racha_consonantes(s: &str) -> usize {
    const VOCALES: &[char] = &['a', 'e', 'i', 'o', 'u', 'y'];
    let mut mejor = 0;
    let mut actual = 0;
    for c in s.chars() {
        if c.is_ascii_alphabetic() && !VOCALES.contains(&c) {
            actual += 1;
            mejor = mejor.max(actual);
        } else {
            actual = 0;
        }
    }
    mejor
}

/// Proporcion de digitos en milesimas.
fn proporcion_digitos_mili(s: &str) -> u32 {
    if s.is_empty() {
        return 0;
    }
    let d = s.chars().filter(char::is_ascii_digit).count();
    u32::try_from(d * 1000 / s.chars().count()).unwrap_or(0)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn encargo(o: Observable) -> Encargo {
        Encargo {
            observable: o,
            ahora_ns: AHORA,
        }
    }

    #[test]
    fn las_listas_cubren_lo_que_nunca_puede_salir() {
        // Rutas y cuentas son precisamente los observables que NO salen: si no los
        // mirara nadie aqui, no los miraria nadie en absoluto.
        let l = Listas::nuevas("listas");
        for t in Tipo::todos() {
            assert!(l.ficha().acepta.contains(t), "{t:?} sin cubrir");
        }
        assert!(!l.ficha().necesita_salida());
    }

    #[test]
    fn lo_que_no_esta_en_las_listas_es_desconocido_y_no_limpio() {
        // Una lista de permitidos invita a leer «no bloqueado» como «bueno», y esa
        // es exactamente la lectura que deja pasar lo que nadie ha visto todavia.
        let l = Listas::nuevas("listas");
        let d = l
            .mirar(&encargo(Observable::Hash("abc".into())), None)
            .expect("no falla");
        assert_eq!(d.juicio, Juicio::Desconocido);
        assert_eq!(d.confianza, 0);
    }

    #[test]
    fn lo_bloqueado_sale_con_su_motivo_y_maxima_confianza() {
        let mut l = Listas::nuevas("listas");
        let o = Observable::Dominio("malo.example".into());
        l.bloquear(
            &o,
            "lo decidio el equipo el 3 de marzo tras el incidente 412",
        );
        let d = l.mirar(&encargo(o), None).expect("no falla");
        assert_eq!(d.juicio, Juicio::Malicioso);
        assert_eq!(d.confianza, 100);
        assert_eq!(d.clase, Clase::Propia);
        assert!(d.porque.contains("incidente 412"));
    }

    #[test]
    fn permitir_algo_bloqueado_lo_saca_de_la_otra_lista() {
        // Estar en las dos listas es un estado imposible que produce el veredicto
        // que salga primero en el codigo, que es la peor clase de fallo.
        let mut l = Listas::nuevas("listas");
        let o = Observable::Ip("8.8.8.8".into());
        l.bloquear(&o, "a");
        l.permitir(&o, "resolutor publico, autorizado");
        assert_eq!(l.cuantas(), (0, 1));
        let d = l.mirar(&encargo(o), None).expect("no falla");
        assert_eq!(d.juicio, Juicio::Limpio);
    }

    #[test]
    fn las_listas_no_distinguen_mayusculas() {
        let mut l = Listas::nuevas("listas");
        l.bloquear(&Observable::Dominio("Malo.Example".into()), "x");
        let d = l
            .mirar(&encargo(Observable::Dominio("MALO.EXAMPLE".into())), None)
            .expect("no falla");
        assert_eq!(d.juicio, Juicio::Malicioso);
    }

    #[test]
    fn el_dga_nunca_dice_malicioso() {
        // La propiedad que impide que un dominio de una red de distribucion de
        // contenidos acabe bloqueado por parecerse a uno generado.
        let a = Dga::nuevo("dga");
        for n in [
            "xqzvbnmkptr.example",
            "a1b2c3d4e5f6g7.example",
            "kjhgfdsazxcvbn.example",
        ] {
            let d = a
                .mirar(&encargo(Observable::Dominio(n.into())), None)
                .expect("no falla");
            assert_ne!(d.juicio, Juicio::Malicioso, "{n} salio malicioso");
            assert!(d.confianza <= 55, "{n} salio con demasiada confianza");
        }
    }

    #[test]
    fn el_dga_señala_lo_que_tiene_forma_de_generado() {
        let a = Dga::nuevo("dga");
        let d = a
            .mirar(
                &encargo(Observable::Dominio("xqzvbnmkptr.example".into())),
                None,
            )
            .expect("no falla");
        assert_eq!(d.juicio, Juicio::Sospechoso);
        assert!(d.etiquetas.contains(&"posible-dga".to_string()));
        // Y dice que es una heuristica sobre la forma, no informacion sobre el
        // dominio: sin esa frase, el analista lo lee como un hallazgo.
        assert!(d.porque.contains("heuristica sobre la FORMA"));
    }

    #[test]
    fn el_dga_deja_en_paz_los_dominios_normales() {
        let a = Dga::nuevo("dga");
        for n in [
            "google.com",
            "micorreo.es",
            "documentacion.example.org",
            "servicios.empresa.co.uk",
        ] {
            let d = a
                .mirar(&encargo(Observable::Dominio(n.into())), None)
                .expect("no falla");
            assert_eq!(d.juicio, Juicio::Desconocido, "{n} salio señalado");
        }
    }

    #[test]
    fn una_marca_corta_no_puede_salir_sospechosa_por_serlo() {
        // `bbc` y `x7q` tienen practicamente la misma entropia: por debajo del
        // minimo, la medida no significa nada.
        let a = Dga::nuevo("dga");
        for n in ["bbc.co.uk", "x7q.example", "ovh.net"] {
            let d = a
                .mirar(&encargo(Observable::Dominio(n.into())), None)
                .expect("no falla");
            assert_eq!(d.juicio, Juicio::Desconocido, "{n} salio señalado");
        }
    }

    #[test]
    fn las_candidatas_son_todo_menos_el_sufijo_publico() {
        assert_eq!(
            etiquetas_candidatas("a7f3.datos.ejemplo.co.uk"),
            vec!["a7f3", "datos", "ejemplo"]
        );
        assert_eq!(
            etiquetas_candidatas("xqzvbnmk.example.com"),
            vec!["xqzvbnmk", "example"]
        );
        assert_eq!(etiquetas_candidatas("ejemplo.com"), vec!["ejemplo"]);
        assert!(etiquetas_candidatas("solo").is_empty());
        assert!(etiquetas_candidatas("co.uk").is_empty());
    }

    #[test]
    fn el_dga_ve_el_tunel_de_dns_en_un_dominio_legitimo() {
        // El caso que se pierde mirando solo la etiqueta registrable: el dominio
        // es normal y lo generado es el subdominio. Es exactamente la forma de un
        // tunel de DNS o de una exfiltracion por consultas.
        let a = Dga::nuevo("dga");
        let d = a
            .mirar(
                &encargo(Observable::Dominio(
                    "a7f3b2c1d9e8f4a6.datos.ejemplo.com".into(),
                )),
                None,
            )
            .expect("no falla");
        assert_eq!(d.juicio, Juicio::Sospechoso);
        assert!(
            d.porque.contains("a7f3b2c1d9e8f4a6"),
            "señala la etiqueta equivocada: {}",
            d.porque
        );
    }

    #[test]
    fn la_entropia_es_entera_y_reproducible() {
        // Dos maquinas tienen que dar el mismo numero, o el mismo dominio sale
        // sospechoso en un nodo y no en otro.
        assert_eq!(
            entropia_mili("aaaaaaaa"),
            0,
            "un solo simbolo no tiene entropia"
        );
        let e = entropia_mili("abcdefgh");
        assert_eq!(e, 3000, "ocho simbolos distintos son exactamente 3 bits");
        // Y el resultado no cambia entre llamadas.
        assert_eq!(entropia_mili("xqzvbnmk"), entropia_mili("xqzvbnmk"));
    }

    #[test]
    fn log2_entero_acierta_en_las_potencias_de_dos() {
        for (x, esperado) in [(1u64, 0u32), (2, 1000), (4, 2000), (8, 3000), (1024, 10000)] {
            assert_eq!(log2_mili(x), esperado, "log2({x})");
        }
    }

    #[test]
    fn las_rachas_y_los_digitos_se_cuentan_bien() {
        assert_eq!(racha_consonantes("xqzvbnmk"), 8);
        assert_eq!(racha_consonantes("casa"), 1);
        // a-BSTR-a: cuatro seguidas.
        assert_eq!(racha_consonantes("abstracto"), 4);
        assert_eq!(proporcion_digitos_mili("a1b2"), 500);
        assert_eq!(proporcion_digitos_mili("abcd"), 0);
        assert_eq!(proporcion_digitos_mili(""), 0);
    }

    #[test]
    fn las_fichas_de_los_locales_son_coherentes() {
        assert!(Listas::nuevas("listas").ficha().coherente().is_ok());
        assert!(Dga::nuevo("dga").ficha().coherente().is_ok());
    }
}
