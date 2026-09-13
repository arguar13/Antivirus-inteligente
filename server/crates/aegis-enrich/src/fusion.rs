//! Cinco fuentes dicen cosas distintas. Que se hace.
//!
//! # Por que no una media
//!
//! Es la tentacion evidente: ponderar y promediar. Y produce el peor resultado
//! posible, por tres motivos distintos que se suman:
//!
//! 1. **Una media esconde el desacuerdo.** Dos fuentes seguras y contrarias
//!    —«malicioso al 95 %» y «limpio al 95 %»— promedian a un valor intermedio que
//!    se lee como evidencia debil, cuando lo que hay es evidencia **fuerte y en
//!    conflicto**. Son dos situaciones opuestas y el numero las hace iguales.
//! 2. **Una media convierte el desconocimiento en voto.** Cuatro fuentes que no
//!    saben nada arrastran el promedio hacia abajo y el resultado se lee como
//!    «probablemente limpio». No lo es: sigue sin saberse.
//! 3. **Una media trata a todas las fuentes como comparables.** Nuestra propia
//!    detonacion vio el fichero cifrar ficheros. Un canal comunitario repite algo
//!    que alguien envio. Meterlos en la misma suma es perder la unica informacion
//!    que de verdad ordena el problema.
//!
//! # El criterio, en cuatro reglas que se aplican en orden
//!
//! Se aplican **en orden** y la primera que decide, decide. Eso hace que el
//! resultado sea explicable en una frase, que es el requisito de verdad: un
//! veredicto que el analista no puede reconstruir es un veredicto que no usa.
//!
//! | # | Regla | Por que |
//! |---|---|---|
//! | 1 | Una observacion **propia** decide, y ninguna otra clase la contradice | Vimos la cosa; los demas repiten lo que alguien dijo |
//! | 2 | Si no hay nada que aporte, el resultado es **`SinDatos`** | Cuatro «no se» no son «probablemente limpio» |
//! | 3 | Si dentro de la clase mas autorizada que aporta hay desacuerdo, **`EnDisputa`** | El desacuerdo ES el hallazgo, y hay que verlo |
//! | 4 | Si no, decide esa clase, con la confianza de su mejor dictamen | El que mas sabe, manda |
//!
//! # La antiguedad no pondera: descarta
//!
//! Un dictamen viejo no es un dictamen debil, es un dictamen **sobre otra cosa**.
//! Un dominio que era malicioso hace dos años puede llevar dieciocho meses siendo
//! el blog de alguien. Ponderarlo por la mitad lo mete igual en la decision; lo
//! correcto es sacarlo y **decir que se saco**, que es lo que hace
//! [`Fusion::caducados`].
//!
//! # Determinista, y la prueba lo comprueba
//!
//! El mismo conjunto de dictamenes produce siempre el mismo veredicto,
//! independientemente del orden en que lleguen. Sin eso, dos ejecuciones sobre el
//! mismo incidente dan resultados distintos y el informe no vale.

use std::collections::BTreeMap;

use crate::dictamen::{Dictamen, Juicio};

/// Un segundo, en nanosegundos.
const SEG: u64 = 1_000_000_000;
/// Un dia, en nanosegundos.
const DIA: u64 = 24 * 3600 * SEG;

/// Cuanto vale el dictamen de una fuente sobre cada tipo de cosa.
///
/// No son numeros de gusto: cada uno sale de **cuanto tarda el mundo real en
/// cambiar** para ese observable.
///
/// | Observable | Caduca a | Por que |
/// |---|---|---|
/// | Resumen de fichero | 180 dias | El fichero no cambia; lo que cambia es lo que se sabe de el, y despacio |
/// | Dominio | 30 dias | Se registran, se abandonan, se incautan y se revenden en semanas |
/// | IP | 2 dias | Direccionamiento dinamico y nubes: la misma IP es de otro en horas |
/// | URL | 7 dias | La pagina cambia sin que cambie el dominio |
/// | Lo demas | 30 dias | Valor conservador |
///
/// La IP es la que mas importa acertar: tratar una IP con la caducidad de un
/// resumen significa bloquear a quien ocupa hoy una direccion por lo que hizo
/// quien la ocupaba la semana pasada.
#[must_use]
pub fn caducidad_ns(tipo: crate::observable::Tipo) -> u64 {
    use crate::observable::Tipo;
    match tipo {
        Tipo::Hash => 180 * DIA,
        Tipo::Dominio => 30 * DIA,
        Tipo::Ip => 2 * DIA,
        Tipo::Url => 7 * DIA,
        _ => 30 * DIA,
    }
}

/// El resultado de fusionar varios dictamenes.
///
/// Tiene **cinco** valores y no tres, y los dos de mas son los que hacen que sirva:
/// `SinDatos` y `EnDisputa` son situaciones reales y frecuentes que un enumerado
/// de tres obliga a disfrazar de otra cosa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Veredicto {
    /// Es malicioso.
    Malicioso,
    /// Hay indicios.
    Sospechoso,
    /// Es legitimo, y alguien lo sabe positivamente.
    Limpio,
    /// **Las fuentes se contradicen.**
    ///
    /// No es un punto medio: es que hay informacion fuerte en las dos direcciones
    /// y hace falta una persona. Esconderlo tras un numero intermedio es lo que
    /// hace que nadie mire el caso que mas lo necesita.
    EnDisputa,
    /// **Nadie sabe nada.**
    ///
    /// Distinto de limpio, y la diferencia importa: un fichero que ninguna fuente
    /// conoce es lo que parece un fichero recien compilado por un atacante.
    SinDatos,
}

impl Veredicto {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Veredicto::Malicioso => "malicioso",
            Veredicto::Sospechoso => "sospechoso",
            Veredicto::Limpio => "limpio",
            Veredicto::EnDisputa => "en-disputa",
            Veredicto::SinDatos => "sin-datos",
        }
    }

    /// Si esto exige que una persona lo mire.
    #[must_use]
    pub fn exige_persona(self) -> bool {
        self == Veredicto::EnDisputa
    }
}

/// El resultado completo, con su explicacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fusion {
    /// A que se llego.
    pub veredicto: Veredicto,
    /// Con que confianza, en centesimas. Cero si `SinDatos`.
    pub confianza: u8,
    /// La regla que decidio, en una frase.
    ///
    /// Es la parte que hace utilizable el resultado: un veredicto que el analista
    /// no puede reconstruir es un veredicto que no usa.
    pub porque: String,
    /// Que dijo cada fuente, ordenado y completo.
    ///
    /// **Va siempre**, tambien cuando todas coinciden: el informe dice quien dijo
    /// que, y eso es lo que permite discutir el resultado en vez de acatarlo.
    pub dictamenes: Vec<Dictamen>,
    /// Los que se descartaron por viejos, con su antiguedad en dias.
    ///
    /// Se enseñan aparte en vez de tirarlos en silencio: «no habia datos» y «los
    /// datos que habia eran de hace dos años» son cosas distintas.
    pub caducados: Vec<(String, u64)>,
    /// Etiquetas de las fuentes que aportaron, sin repetir.
    pub etiquetas: Vec<String>,
}

/// Fusiona los dictamenes de todas las fuentes.
///
/// `ahora_ns` decide que esta caducado. Se pasa como argumento y no se lee del
/// reloj para que la fusion sea una **funcion pura**: es lo que permite probar
/// veinte combinaciones de fuentes en microsegundos y tener el criterio en la
/// puerta de calidad.
#[must_use]
pub fn fusionar(dictamenes: &[Dictamen], ahora_ns: u64) -> Fusion {
    // 0 · Se apartan los viejos. Un dictamen viejo no es un dictamen debil, es un
    //     dictamen sobre otra cosa.
    let mut vivos: Vec<&Dictamen> = Vec::new();
    let mut caducados: Vec<(String, u64)> = Vec::new();
    for d in dictamenes {
        let edad = d.antiguedad_ns(ahora_ns);
        if edad > caducidad_ns(d.observable.tipo()) {
            caducados.push((d.fuente.clone(), edad / DIA));
        } else {
            vivos.push(d);
        }
    }
    caducados.sort();

    let mut todos: Vec<Dictamen> = dictamenes.to_vec();
    // Orden estable y total: la fusion tiene que dar lo mismo llegue como llegue.
    todos.sort_by(|a, b| {
        a.clase
            .cmp(&b.clase)
            .then(a.fuente.cmp(&b.fuente))
            .then(a.juicio.cmp(&b.juicio))
    });

    let etiquetas = {
        let mut e: Vec<String> = vivos
            .iter()
            .filter(|d| d.juicio.aporta())
            .flat_map(|d| d.etiquetas.iter().cloned())
            .collect();
        e.sort();
        e.dedup();
        e
    };

    // 1 · Una observacion PROPIA decide. Vimos la cosa; los demas repiten.
    let propios: Vec<&&Dictamen> = vivos
        .iter()
        .filter(|d| d.clase.observacion_directa() && d.juicio.aporta())
        .collect();
    if !propios.is_empty() {
        let juicios: Vec<Juicio> = {
            let mut j: Vec<Juicio> = propios.iter().map(|d| d.juicio).collect();
            j.sort_unstable();
            j.dedup();
            j
        };
        if juicios.len() > 1 {
            return Fusion {
                veredicto: Veredicto::EnDisputa,
                confianza: mejor_confianza(&propios),
                porque: format!(
                    "dos observaciones propias se contradicen ({}); es el unico caso en el que \
                     nuestras propias herramientas discrepan, y decidirlo por mayoria esconderia \
                     un fallo en una de ellas",
                    nombres_de_juicios(&juicios)
                ),
                dictamenes: todos,
                caducados,
                etiquetas,
            };
        }
        let juicio = juicios[0];
        let contrarios = vivos
            .iter()
            .filter(|d| !d.clase.observacion_directa() && d.juicio.aporta() && d.juicio != juicio)
            .count();
        return Fusion {
            veredicto: de_juicio(juicio),
            confianza: mejor_confianza(&propios),
            porque: if contrarios > 0 {
                format!(
                    "lo decide una observacion propia ({}): vimos la cosa, y las {contrarios} \
                     fuentes que dicen otra cosa repiten lo que alguien les conto",
                    juicio.nombre()
                )
            } else {
                format!(
                    "lo decide una observacion propia ({}), sin nadie que la contradiga",
                    juicio.nombre()
                )
            },
            dictamenes: todos,
            caducados,
            etiquetas,
        };
    }

    // 2 · Si nada aporta, SIN DATOS. Cuatro «no se» no son «probablemente limpio».
    let aportan: Vec<&&Dictamen> = vivos.iter().filter(|d| d.juicio.aporta()).collect();
    if aportan.is_empty() {
        let porque = if caducados.is_empty() {
            format!(
                "ninguna de las {} fuentes consultadas sabe nada de esto — que NO es lo mismo que \
                 que este limpio: un fichero que nadie conoce es lo que parece un fichero recien \
                 compilado",
                dictamenes.len()
            )
        } else {
            format!(
                "ninguna fuente viva sabe nada, y {} dictamen(es) se descartaron por viejos: «no \
                 habia datos» y «los datos eran de hace meses» son cosas distintas",
                caducados.len()
            )
        };
        return Fusion {
            veredicto: Veredicto::SinDatos,
            confianza: 0,
            porque,
            dictamenes: todos,
            caducados,
            etiquetas,
        };
    }

    // 3 · Dentro de la clase mas autorizada que aporta: si hay desacuerdo, DISPUTA.
    let clase = aportan
        .iter()
        .map(|d| d.clase)
        .min()
        .expect("no esta vacio");
    let mandan: Vec<&&Dictamen> = aportan
        .iter()
        .filter(|d| d.clase == clase)
        .copied()
        .collect();
    let juicios: Vec<Juicio> = {
        let mut j: Vec<Juicio> = mandan.iter().map(|d| d.juicio).collect();
        j.sort_unstable();
        j.dedup();
        j
    };

    if juicios.len() > 1 {
        // El desacuerdo ES el hallazgo. Promediarlo produciria un numero
        // intermedio que se lee como evidencia debil, y lo que hay es evidencia
        // fuerte en las dos direcciones.
        let mut por_juicio: BTreeMap<&'static str, Vec<&str>> = BTreeMap::new();
        for d in &mandan {
            por_juicio
                .entry(d.juicio.nombre())
                .or_default()
                .push(&d.fuente);
        }
        let detalle: Vec<String> = por_juicio
            .iter()
            .map(|(j, f)| format!("{j}: {}", f.join(", ")))
            .collect();
        return Fusion {
            veredicto: Veredicto::EnDisputa,
            confianza: mejor_confianza(&mandan),
            porque: format!(
                "las fuentes de clase «{}» se contradicen ({}); no se promedia porque un valor \
                 intermedio se leeria como evidencia debil y lo que hay es evidencia fuerte en \
                 las dos direcciones",
                clase.nombre(),
                detalle.join(" | ")
            ),
            dictamenes: todos,
            caducados,
            etiquetas,
        };
    }

    // 4 · Decide esa clase.
    let juicio = juicios[0];
    let debajo = aportan.iter().filter(|d| d.clase != clase).count();
    Fusion {
        veredicto: de_juicio(juicio),
        confianza: mejor_confianza(&mandan),
        porque: format!(
            "lo deciden las {} fuente(s) de clase «{}», que es la mas autorizada que sabe algo, y \
             coinciden en «{}»{}",
            mandan.len(),
            clase.nombre(),
            juicio.nombre(),
            if debajo > 0 {
                format!("; hay {debajo} fuente(s) de clase inferior que no la contradicen ni la confirman por si solas")
            } else {
                String::new()
            }
        ),
        dictamenes: todos,
        caducados,
        etiquetas,
    }
}

/// La mayor confianza del grupo que decidio.
///
/// La mayor y no la media: el grupo coincide en el juicio, asi que lo que interesa
/// es lo seguro que esta el que mas lo esta. Promediar con uno que apenas se moja
/// rebajaria un juicio firme por compañia.
fn mejor_confianza(grupo: &[&&Dictamen]) -> u8 {
    grupo.iter().map(|d| d.confianza).max().unwrap_or(0)
}

fn nombres_de_juicios(j: &[Juicio]) -> String {
    j.iter()
        .map(|x| x.nombre())
        .collect::<Vec<_>>()
        .join(" vs ")
}

fn de_juicio(j: Juicio) -> Veredicto {
    match j {
        Juicio::Malicioso => Veredicto::Malicioso,
        Juicio::Sospechoso => Veredicto::Sospechoso,
        Juicio::Limpio => Veredicto::Limpio,
        Juicio::Desconocido => Veredicto::SinDatos,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::dictamen::Clase;
    use crate::observable::{Observable, Tipo};

    const AHORA: u64 = 1_700_000_000 * SEG;

    fn d(fuente: &str, clase: Clase, juicio: Juicio, confianza: u8, hace_dias: u64) -> Dictamen {
        Dictamen {
            fuente: fuente.into(),
            clase,
            observable: Observable::Hash("abc".into()),
            juicio,
            confianza,
            observado_ns: AHORA - hace_dias * DIA,
            porque: "porque si".into(),
            etiquetas: vec![],
        }
    }

    #[test]
    fn cuatro_desconocidos_no_son_limpio() {
        // La regla que mas veces se incumple en los productos reales. Cuatro «no
        // se» promediados dan un numero bajo que se lee como «probablemente
        // limpio», y lo que hay es que nadie sabe nada.
        let ds = vec![
            d("a", Clase::Reputacion, Juicio::Desconocido, 0, 1),
            d("b", Clase::Reputacion, Juicio::Desconocido, 0, 1),
            d("c", Clase::Comunitaria, Juicio::Desconocido, 0, 1),
            d("e", Clase::Heuristica, Juicio::Desconocido, 0, 1),
        ];
        let f = fusionar(&ds, AHORA);
        assert_eq!(f.veredicto, Veredicto::SinDatos);
        assert_eq!(f.confianza, 0);
        assert!(f.porque.contains("NO es lo mismo"));
    }

    #[test]
    fn dos_fuentes_seguras_y_contrarias_no_se_promedian() {
        // Promediarlas daria «medio sospechoso», que se lee como evidencia debil.
        // Lo que hay es evidencia fuerte en las dos direcciones, y eso exige una
        // persona.
        let ds = vec![
            d("a", Clase::Reputacion, Juicio::Malicioso, 95, 1),
            d("b", Clase::Reputacion, Juicio::Limpio, 95, 1),
        ];
        let f = fusionar(&ds, AHORA);
        assert_eq!(f.veredicto, Veredicto::EnDisputa);
        assert!(f.veredicto.exige_persona());
        assert!(f.porque.contains("a") && f.porque.contains("b"));
    }

    #[test]
    fn nuestra_propia_observacion_gana_a_tres_reputaciones() {
        // Vimos el fichero cifrar ficheros. Tres servicios que no tienen la
        // muestra dicen que no la conocen o que parece limpia. No nos callan.
        let ds = vec![
            d("detonacion", Clase::Propia, Juicio::Malicioso, 99, 0),
            d("a", Clase::Reputacion, Juicio::Limpio, 90, 1),
            d("b", Clase::Reputacion, Juicio::Limpio, 90, 1),
            d("c", Clase::Comunitaria, Juicio::Limpio, 70, 1),
        ];
        let f = fusionar(&ds, AHORA);
        assert_eq!(f.veredicto, Veredicto::Malicioso);
        assert_eq!(f.confianza, 99);
        assert!(f.porque.contains("observacion propia"));
        assert!(
            f.porque.contains("3 fuentes"),
            "dice cuantas discrepan: {}",
            f.porque
        );
    }

    #[test]
    fn dos_observaciones_propias_contrarias_son_disputa_y_no_mayoria() {
        // Es el unico caso en el que nuestras propias herramientas discrepan.
        // Decidirlo por mayoria esconderia un fallo en una de ellas.
        let ds = vec![
            d("detonacion", Clase::Propia, Juicio::Malicioso, 99, 0),
            d("yara", Clase::Propia, Juicio::Limpio, 80, 0),
        ];
        let f = fusionar(&ds, AHORA);
        assert_eq!(f.veredicto, Veredicto::EnDisputa);
        assert!(f.porque.contains("propias se contradicen"));
    }

    #[test]
    fn una_clase_inferior_no_contradice_a_la_superior() {
        let ds = vec![
            d("a", Clase::Reputacion, Juicio::Limpio, 80, 1),
            d("com", Clase::Comunitaria, Juicio::Malicioso, 99, 1),
        ];
        let f = fusionar(&ds, AHORA);
        // La comunitaria es util y a menudo la primera en ver una campana; tambien
        // la primera en envenenarse. No tumba a una reputacion con nombre.
        assert_eq!(f.veredicto, Veredicto::Limpio);
        assert!(f.porque.contains("clase inferior"));
    }

    #[test]
    fn un_dictamen_viejo_se_descarta_y_se_dice() {
        // Un dominio que era malicioso hace dos años puede llevar dieciocho meses
        // siendo el blog de alguien. No se pondera por la mitad: se saca, y se
        // dice que se saco.
        let mut viejo = d("a", Clase::Reputacion, Juicio::Malicioso, 99, 400);
        viejo.observable = Observable::Dominio("ejemplo.com".into());
        let f = fusionar(&[viejo], AHORA);
        assert_eq!(f.veredicto, Veredicto::SinDatos);
        assert_eq!(f.caducados.len(), 1);
        assert_eq!(f.caducados[0].0, "a");
        assert!(f.porque.contains("viejos"));
    }

    #[test]
    fn la_caducidad_de_una_ip_es_mucho_mas_corta_que_la_de_un_resumen() {
        // Es la que mas importa acertar: tratar una IP con la caducidad de un
        // resumen significa bloquear a quien ocupa hoy una direccion por lo que
        // hizo quien la ocupaba la semana pasada.
        assert!(caducidad_ns(Tipo::Ip) < caducidad_ns(Tipo::Url));
        assert!(caducidad_ns(Tipo::Url) < caducidad_ns(Tipo::Dominio));
        assert!(caducidad_ns(Tipo::Dominio) < caducidad_ns(Tipo::Hash));
        assert_eq!(caducidad_ns(Tipo::Ip), 2 * DIA);
    }

    #[test]
    fn la_fusion_no_depende_del_orden_de_llegada() {
        // Sin esto, dos ejecuciones sobre el mismo incidente dan resultados
        // distintos y el informe no vale.
        let a = d("a", Clase::Reputacion, Juicio::Malicioso, 90, 1);
        let b = d("b", Clase::Comunitaria, Juicio::Limpio, 70, 1);
        let c = d("c", Clase::Heuristica, Juicio::Sospechoso, 40, 1);

        let uno = fusionar(&[a.clone(), b.clone(), c.clone()], AHORA);
        let dos = fusionar(&[c.clone(), a.clone(), b.clone()], AHORA);
        let tres = fusionar(&[b, c, a], AHORA);
        assert_eq!(uno, dos);
        assert_eq!(dos, tres);
    }

    #[test]
    fn el_informe_lleva_siempre_lo_que_dijo_cada_fuente() {
        // Tambien cuando todas coinciden: es lo que permite discutir el resultado
        // en vez de acatarlo.
        let ds = vec![
            d("a", Clase::Reputacion, Juicio::Malicioso, 90, 1),
            d("b", Clase::Reputacion, Juicio::Malicioso, 85, 1),
        ];
        let f = fusionar(&ds, AHORA);
        assert_eq!(f.veredicto, Veredicto::Malicioso);
        assert_eq!(f.dictamenes.len(), 2);
        // La mayor y no la media: coinciden en el juicio, asi que interesa lo
        // seguro que esta el que mas lo esta.
        assert_eq!(f.confianza, 90);
    }

    #[test]
    fn las_etiquetas_se_juntan_sin_repetir_y_solo_de_quien_aporta() {
        let mut a = d("a", Clase::Reputacion, Juicio::Malicioso, 90, 1);
        a.etiquetas = vec!["lockbit".into(), "ransomware".into()];
        let mut b = d("b", Clase::Reputacion, Juicio::Malicioso, 85, 1);
        b.etiquetas = vec!["ransomware".into()];
        // Este no aporta, asi que sus etiquetas tampoco: una fuente que no sabe
        // nada no puede meter una familia de malware en el informe.
        let mut c = d("c", Clase::Comunitaria, Juicio::Desconocido, 0, 1);
        c.etiquetas = vec!["inventada".into()];

        let f = fusionar(&[a, b, c], AHORA);
        assert_eq!(
            f.etiquetas,
            vec!["lockbit".to_string(), "ransomware".to_string()]
        );
    }

    #[test]
    fn sin_ninguna_fuente_el_resultado_es_sin_datos_y_no_limpio() {
        let f = fusionar(&[], AHORA);
        assert_eq!(f.veredicto, Veredicto::SinDatos);
        assert_eq!(f.confianza, 0);
    }

    #[test]
    fn solo_la_disputa_exige_una_persona() {
        for v in [
            Veredicto::Malicioso,
            Veredicto::Sospechoso,
            Veredicto::Limpio,
            Veredicto::SinDatos,
        ] {
            assert!(!v.exige_persona());
        }
        assert!(Veredicto::EnDisputa.exige_persona());
    }
}
