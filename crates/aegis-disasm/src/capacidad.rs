//! Que es capaz de hacer un binario, y **la prueba de que lo es**.
//!
//! # La diferencia con una firma
//!
//! Una firma dice «esto es Emotet» y no dice por que. Cuando se equivoca —y se
//! equivoca— no hay forma de saberlo sin repetir el analisis a mano. Una
//! capacidad dice «esto inyecta codigo en otro proceso» **y ensena las
//! instrucciones concretas que lo hacen**. Quien la lea puede comprobarla, y
//! quien la escriba no puede esconder que la regla era floja.
//!
//! Por eso aqui no hay ninguna funcion que devuelva una lista de nombres. Todo
//! lo que sale lleva su [`Evidencia`] pegada, y no hay forma de construir una
//! [`Capacidad`] sin ella: no es una convencion, es el tipo.
//!
//! # Por que las reglas son datos y no codigo
//!
//! Una regla escrita en Rust hay que compilarla, y una regla que hay que
//! compilar no la escribe quien analiza malware, la escribe quien mantiene el
//! desensamblador. Eso pone un cuello de botella justo donde el trabajo tiene
//! que ir rapido: entre ver una tecnica nueva y reconocerla.
//!
//! Las reglas de [`crate::reglas`] son estructuras de datos. El motor que las
//! evalua esta aqui y no sabe nada de lo que significan.
//!
//! # Lo que una capacidad NO es
//!
//! No es un veredicto. «Cifra con AES» es cierto de un gestor de copias de
//! seguridad y de un secuestrador de ficheros. Lo que sale de aqui son hechos
//! con su evidencia y su tecnica de ATT&CK; quien decide es el arbitro, con
//! esto y con todo lo demas. Ver [`crate::senal`].

use std::collections::BTreeMap;

use crate::plazo::Cobertura;

/// Que necesita una capacidad para ser cierta.
///
/// Es lo que separa una regla que dice algo de una que dispara con cualquier
/// cosa: no basta con que aparezca una instruccion, tienen que aparecer **todas
/// las piezas de la tecnica**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exigencia {
    /// Hacen falta todas las senales de la regla.
    ///
    /// Es lo normal, y es lo que hace que una regla signifique algo: «reserva
    /// memoria ejecutable» sola no es nada, y «reserva memoria ejecutable Y
    /// escribe en ella Y crea un hilo que empieza ahi» es una inyeccion.
    Todas,
    /// Basta una, porque una sola ya es concluyente.
    ///
    /// Se reserva para las senales que no tienen lectura benigna: una
    /// instruccion `aesenc` significa que hay cifrado AES y no significa ninguna
    /// otra cosa.
    Alguna,
    /// Hacen falta al menos tantas.
    ///
    /// Para tecnicas que se pueden hacer de varias formas parecidas, donde
    /// exigir todas seria no reconocer ninguna y exigir una seria reconocerlas
    /// todas.
    AlMenos(usize),
}

/// Donde tienen que verse las senales de una regla para que cuenten juntas.
///
/// # El defecto que este tipo existe para impedir
///
/// Sin esto, el motor busca cada senal en el binario entero y las junta aunque
/// esten en sitios que no tienen nada que ver. Medido sobre `/bin/ls`: la regla
/// de RC4 —que pide una constante 256, una instruccion de cadena y una logica—
/// disparaba con un `cmp rax, 0x100` en 0x604a, un `rep movsq` en 0x87da y un
/// `xor eax, eax` en 0x4dd5. Tres instrucciones en tres sitios distintos de un
/// binario de cien kilobytes, sin ninguna relacion entre ellas.
///
/// Eso no es una regla floja, es una regla que **afirma una relacion que no ha
/// comprobado**. Y lo peor es que su evidencia parece buena: tres direcciones
/// concretas, cada una con su instruccion. Quien la lea por encima la da por
/// buena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ambito {
    /// Las senales son propiedades del binario y no tienen por que estar juntas.
    ///
    /// Es lo correcto para lo que se lee de la tabla de importaciones: que un
    /// binario importe `VirtualAllocEx` y `CreateRemoteThread` significa lo
    /// mismo esten las dos llamadas en la misma funcion o en dos distintas,
    /// porque lo que se afirma es que el binario tiene las dos capacidades.
    Global,
    /// Todas las senales tienen que verse **juntas**: en la misma funcion y
    /// dentro de una ventana de direcciones.
    ///
    /// Es lo correcto para lo que se lee del codigo. Un algoritmo esta en un
    /// sitio: si sus piezas aparecen repartidas por el binario, lo que hay no es
    /// ese algoritmo, son varias coincidencias.
    ///
    /// # Por que la funcion sola no basta
    ///
    /// Porque «funcion» es lo que el analisis consigue delimitar, y en un
    /// binario sin tabla de simbolos completa delimita poco: en `/bin/ls`, donde
    /// muchas funciones internas no tienen simbolo ni se llaman directamente, la
    /// mayor de las funciones reconstruidas abarca 75 KB de un `.text` de 100.
    /// Con «funciones» de ese tamano, exigir la misma funcion no exige casi
    /// nada.
    ///
    /// La ventana es la segunda condicion, y sale de una observacion simple: un
    /// algoritmo cabe en unos pocos kilobytes de codigo. Ver
    /// [`VENTANA_DE_ALGORITMO`].
    MismaFuncion,
}

/// A que distancia como mucho pueden estar las piezas de un mismo algoritmo.
///
/// Cuatro kilobytes de codigo son varios cientos de instrucciones: cabe de sobra
/// cualquier rutina de cifrado, de compresion o de resolucion de importaciones.
/// Lo que no cabe es una funcion de un binario y otra de otro sitio del mismo
/// fichero, que es lo que se quiere impedir.
pub const VENTANA_DE_ALGORITMO: u64 = 4096;

/// Lo que se vio para afirmar una capacidad.
///
/// Una sola pieza: donde estaba, que era y por que cuenta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidencia {
    /// En que direccion.
    pub donde: u64,
    /// Que se vio, en el lenguaje del binario: el texto de la instruccion, el
    /// nombre de la funcion importada, la constante.
    pub que: String,
    /// Por que eso cuenta para esta capacidad.
    ///
    /// Va escrito en la regla y no se genera: una explicacion generada a partir
    /// del nombre de la regla no explica nada, solo lo repite.
    pub porque: String,
}

/// Una capacidad encontrada, con todo lo que la sostiene.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capacidad {
    /// Como se llama, en lenguaje de persona.
    pub nombre: &'static str,
    /// De que familia es.
    pub familia: Familia,
    /// La tecnica de ATT&CK, cuando la hay.
    ///
    /// Es `Option` porque no todo lo que un binario hace tiene identificador en
    /// ATT&CK, y poner uno aproximado es peor que no poner ninguno: quien
    /// agregue por tecnica contara como lo mismo cosas que no lo son.
    pub attack: Option<&'static str>,
    /// Lo que se vio. **Nunca esta vacio**: lo garantiza el constructor.
    evidencias: Vec<Evidencia>,
}

impl Capacidad {
    /// Construye una capacidad. Devuelve `None` si no hay evidencia.
    ///
    /// Es el unico camino para crear una, y por eso una [`Capacidad`] sin
    /// evidencia **no se puede representar**. No es una comprobacion que alguien
    /// pueda olvidarse de hacer: es que el valor no existe.
    pub fn nueva(
        nombre: &'static str,
        familia: Familia,
        attack: Option<&'static str>,
        evidencias: Vec<Evidencia>,
    ) -> Option<Capacidad> {
        if evidencias.is_empty() {
            return None;
        }
        Some(Capacidad {
            nombre,
            familia,
            attack,
            evidencias,
        })
    }

    /// Lo que se vio.
    pub fn evidencias(&self) -> &[Evidencia] {
        &self.evidencias
    }

    /// La frase con la que esta capacidad aparece en un informe.
    pub fn frase(&self) -> String {
        let mut s = format!("{} ({})", self.nombre, self.familia.nombre());
        if let Some(t) = self.attack {
            s.push_str(&format!(" [{t}]"));
        }
        s.push_str(". Se vio: ");
        let piezas: Vec<String> = self
            .evidencias
            .iter()
            .map(|e| format!("en {:#x}, {} — {}", e.donde, e.que, e.porque))
            .collect();
        s.push_str(&piezas.join("; "));
        s
    }
}

/// Las familias de capacidades que este motor reconoce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Familia {
    /// Meter codigo propio en otro proceso.
    Inyeccion,
    /// Quedarse tras el reinicio.
    Persistencia,
    /// Estorbar al analisis o a las defensas.
    Evasion,
    /// Cifrar.
    Cifrado,
    /// Hablar con fuera.
    Comunicaciones,
    /// Sacar credenciales.
    Credenciales,
    /// Destruir.
    Destruccion,
    /// Averiguar donde esta.
    Reconocimiento,
}

impl Familia {
    /// Nombre legible.
    pub fn nombre(&self) -> &'static str {
        match self {
            Familia::Inyeccion => "inyeccion de codigo",
            Familia::Persistencia => "persistencia",
            Familia::Evasion => "evasion",
            Familia::Cifrado => "cifrado",
            Familia::Comunicaciones => "comunicaciones",
            Familia::Credenciales => "robo de credenciales",
            Familia::Destruccion => "destruccion",
            Familia::Reconocimiento => "reconocimiento",
        }
    }

    /// Todas, para recorrerlas.
    pub fn todas() -> [Familia; 8] {
        [
            Familia::Inyeccion,
            Familia::Persistencia,
            Familia::Evasion,
            Familia::Cifrado,
            Familia::Comunicaciones,
            Familia::Credenciales,
            Familia::Destruccion,
            Familia::Reconocimiento,
        ]
    }
}

/// Lo que el motor encontro, con lo que llego a mirar.
///
/// Las dos cosas van juntas **en el mismo tipo** y no en dos valores que alguien
/// pueda separar por el camino. Una lista de capacidades sin su cobertura es una
/// afirmacion sobre el binario entero que solo es cierta si el analisis termino,
/// y quien la reciba no tiene forma de saber si lo hizo.
#[derive(Debug, Clone, Default)]
pub struct Informe {
    capacidades: Vec<Capacidad>,
    /// Hasta donde llego el analisis.
    pub cobertura: Cobertura,
}

impl Informe {
    /// Construye un informe.
    pub fn nuevo(capacidades: Vec<Capacidad>, cobertura: Cobertura) -> Informe {
        let mut c = capacidades;
        c.sort_by_key(|x| (x.familia, x.nombre));
        c.dedup_by_key(|x| (x.familia, x.nombre));
        Informe {
            capacidades: c,
            cobertura,
        }
    }

    /// Las capacidades encontradas.
    pub fn capacidades(&self) -> &[Capacidad] {
        &self.capacidades
    }

    /// Cuantas por familia.
    pub fn por_familia(&self) -> BTreeMap<Familia, usize> {
        let mut m = BTreeMap::new();
        for c in &self.capacidades {
            *m.entry(c.familia).or_insert(0) += 1;
        }
        m
    }

    /// Las tecnicas de ATT&CK vistas, sin repetir.
    pub fn tecnicas(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.capacidades.iter().filter_map(|c| c.attack).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Si de este informe se puede concluir que el binario **no** hace algo.
    ///
    /// Solo cuando el analisis llego hasta el final. Con la cobertura cortada,
    /// una lista vacia significa «no dio tiempo a mirar», que es otra frase, y
    /// confundirlas es como un informe acaba diciendo que un fichero es limpio
    /// porque el analizador se quedo sin tiempo.
    pub fn la_ausencia_significa_algo(&self) -> bool {
        self.cobertura.completa()
    }

    /// La frase con la que este informe aparece en un registro.
    pub fn frase(&self) -> String {
        let mut s = if self.capacidades.is_empty() {
            if self.la_ausencia_significa_algo() {
                "no se encontro ninguna capacidad, y el analisis llego hasta el final".to_owned()
            } else {
                "no se encontro ninguna capacidad, PERO EL ANALISIS NO LLEGO HASTA EL FINAL: \
                 eso no significa que no las haya"
                    .to_owned()
            }
        } else {
            let nombres: Vec<&str> = self.capacidades.iter().map(|c| c.nombre).collect();
            format!(
                "{} capacidades: {}",
                self.capacidades.len(),
                nombres.join(", ")
            )
        };
        s.push_str(". ");
        s.push_str(&self.cobertura.frase());
        s
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn evidencia() -> Evidencia {
        Evidencia {
            donde: 0x1000,
            que: "aesenc xmm0, xmm1".to_owned(),
            porque: "es la instruccion AES del procesador".to_owned(),
        }
    }

    #[test]
    fn una_capacidad_sin_evidencia_no_se_puede_construir() {
        // La propiedad central del modulo, y la razon de que el campo sea
        // privado: no es que se compruebe que hay evidencia, es que una
        // capacidad sin ella **no existe como valor**.
        assert!(Capacidad::nueva("lo que sea", Familia::Cifrado, None, vec![]).is_none());
        assert!(Capacidad::nueva("cifra", Familia::Cifrado, None, vec![evidencia()]).is_some());
    }

    #[test]
    fn la_frase_de_una_capacidad_lleva_la_evidencia_dentro() {
        // Si la frase no la llevara, quien lea el informe tendria que fiarse, y
        // fiarse es justo lo que este modulo existe para no tener que hacer.
        let c = Capacidad::nueva(
            "cifra con AES",
            Familia::Cifrado,
            Some("T1486"),
            vec![evidencia()],
        )
        .unwrap();
        let f = c.frase();
        assert!(f.contains("0x1000"), "{f}");
        assert!(f.contains("aesenc"), "{f}");
        assert!(f.contains("instruccion AES"), "{f}");
        assert!(f.contains("T1486"), "{f}");
    }

    #[test]
    fn una_lista_vacia_solo_significa_algo_si_el_analisis_termino() {
        // La invariante que impide que un informe diga que un fichero esta
        // limpio porque al analizador se le acabo el tiempo.
        let entero = Informe::nuevo(
            vec![],
            Cobertura {
                bytes_cubiertos: 10,
                bytes_totales: 10,
                ..Default::default()
            },
        );
        assert!(entero.la_ausencia_significa_algo());
        assert!(
            entero.frase().contains("llego hasta el final"),
            "{}",
            entero.frase()
        );

        let cortado = Informe::nuevo(
            vec![],
            Cobertura {
                cortado_por_plazo: true,
                ..Default::default()
            },
        );
        assert!(!cortado.la_ausencia_significa_algo());
        assert!(
            cortado.frase().contains("NO LLEGO HASTA EL FINAL"),
            "{}",
            cortado.frase()
        );
    }

    #[test]
    fn la_misma_capacidad_no_sale_dos_veces() {
        // Un binario que inyecta en diez sitios inyecta, no inyecta diez veces.
        // Repetirla haria que un informe pareciera diez veces peor por hacer lo
        // mismo mas veces.
        let c =
            || Capacidad::nueva("inyecta", Familia::Inyeccion, None, vec![evidencia()]).unwrap();
        let i = Informe::nuevo(vec![c(), c(), c()], Cobertura::default());
        assert_eq!(i.capacidades().len(), 1);
    }

    #[test]
    fn las_tecnicas_salen_sin_repetir_y_ordenadas() {
        let a =
            Capacidad::nueva("a", Familia::Inyeccion, Some("T1055"), vec![evidencia()]).unwrap();
        let b = Capacidad::nueva("b", Familia::Evasion, Some("T1055"), vec![evidencia()]).unwrap();
        let c = Capacidad::nueva("c", Familia::Cifrado, Some("T1027"), vec![evidencia()]).unwrap();
        let i = Informe::nuevo(vec![a, b, c], Cobertura::default());
        assert_eq!(i.tecnicas(), vec!["T1027", "T1055"]);
    }

    #[test]
    fn una_capacidad_sin_tecnica_de_attack_no_se_inventa_una() {
        // Poner una tecnica aproximada es peor que no poner ninguna: quien
        // agregue por tecnica contara como lo mismo cosas que no lo son.
        let c = Capacidad::nueva("algo raro", Familia::Evasion, None, vec![evidencia()]).unwrap();
        assert_eq!(c.attack, None);
        assert!(!c.frase().contains('['), "{}", c.frase());
    }
}
