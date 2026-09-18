//! La evidencia de un caso cuando el caso abarca una flota.
//!
//! # El fallo que este modulo existe para impedir
//!
//! Se ordena una recogida en cien endpoints. Contestan noventa y siete. El
//! informe dice «recogida completada» y lista noventa y siete artefactos
//! intactos, cada uno con su sello perfecto y su cadena entera.
//!
//! Todo lo que ese informe afirma es cierto, y la conclusion que induce es
//! falsa. Los tres que faltan son, en un incidente real, el sitio mas probable
//! donde esta lo que se busca: una maquina apagada porque el atacante la apago,
//! una que no contesta porque esta comprometida, una que el agente no alcanzo.
//! Un conjunto que presenta noventa y siete piezas integras como la evidencia
//! del caso convierte la ausencia mas informativa del incidente en silencio.
//!
//! Es la misma regla que el resto del producto aplica a lo que no puede leer:
//! **lo que falta se declara; no se descuenta del total**.
//!
//! # Como se impide
//!
//! La cuenta tiene que cuadrar, y se comprueba que cuadre. Cada endpoint al que
//! se le ordeno la recogida acaba **o** con su pieza **o** con una ausencia que
//! dice por que. Un endpoint que no este en ninguna de las dos listas es un
//! fallo de contabilidad, no un endpoint limpio, y
//! [`ConjuntoDeFlota::sin_contabilizar`] lo saca.
//!
//! Y [`ConjuntoDeFlota::esta_completo`] exige las dos cosas: que no falte nadie
//! y que cada pieza presente haya verificado. Una pieza rota cuenta como pieza
//! ausente a efectos de lo que el conjunto autoriza a concluir.

use std::collections::BTreeSet;

use crate::cadena::{CadenaDeCustodia, RegistroDeClaves};
use crate::sello::Sello;
use crate::verificar::Veredicto;

/// Por que un endpoint no aporto su pieza.
///
/// Cada variante es una historia distinta para quien investiga, y por eso no hay
/// una sola «no contesto»: que una maquina rechace la orden por politica y que
/// no se la pueda alcanzar significan cosas muy diferentes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ausencia {
    /// Se le ordeno y nunca contesto.
    SinRespuesta,
    /// No se pudo alcanzar: apagado, sin red, fuera del horario de conexion.
    NoAlcanzable {
        /// Lo ultimo que se supo de el, en segundos desde la epoca.
        visto_por_ultima_vez: Option<u64>,
    },
    /// Contesto rechazando la orden.
    Rechazada {
        /// Que regla la rechazo.
        motivo: String,
    },
    /// Contesto, pero no con todo lo que se le pidio.
    Parcial {
        /// Que falto.
        motivo: String,
    },
    /// Contesto y su pieza no supero la verificacion.
    ///
    /// Se separa de las demas a proposito: aqui SI hay bytes, y son
    /// sospechosos. Es la ausencia que mas hay que mirar.
    PiezaRota {
        /// Que fallo al verificarla.
        motivo: String,
    },
}

impl Ausencia {
    /// La frase con la que aparece en el informe.
    pub fn frase(&self) -> String {
        match self {
            Ausencia::SinRespuesta => "se le ordeno y no contesto".into(),
            Ausencia::NoAlcanzable {
                visto_por_ultima_vez: Some(t),
            } => format!("no alcanzable; visto por ultima vez en {t}"),
            Ausencia::NoAlcanzable {
                visto_por_ultima_vez: None,
            } => "no alcanzable; no consta cuando se le vio por ultima vez".into(),
            Ausencia::Rechazada { motivo } => format!("rechazo la orden: {motivo}"),
            Ausencia::Parcial { motivo } => format!("contesto incompleto: {motivo}"),
            Ausencia::PiezaRota { motivo } => {
                format!("contesto y su pieza no verifica: {motivo}")
            }
        }
    }
}

/// La evidencia que aporto un endpoint.
#[derive(Debug, Clone)]
pub struct Pieza {
    /// De que endpoint viene.
    pub endpoint: String,
    /// Su sello.
    pub sello: Sello,
    /// Su cadena de custodia.
    pub cadena: CadenaDeCustodia,
}

/// La evidencia de un caso a lo largo de una flota.
#[derive(Debug, Clone)]
pub struct ConjuntoDeFlota {
    /// Caso al que pertenece.
    pub caso: String,
    /// Endpoints a los que se ordeno la recogida.
    pub ordenados: Vec<String>,
    /// Las piezas que llegaron.
    pub piezas: Vec<Pieza>,
    /// Los que no aportaron, con su motivo.
    pub ausencias: Vec<(String, Ausencia)>,
}

impl ConjuntoDeFlota {
    /// Abre un conjunto para un caso y una lista de endpoints.
    pub fn ordenado(caso: &str, endpoints: &[String]) -> ConjuntoDeFlota {
        ConjuntoDeFlota {
            caso: caso.to_owned(),
            ordenados: endpoints.to_vec(),
            piezas: Vec::new(),
            ausencias: Vec::new(),
        }
    }

    /// Anota la pieza que aporto un endpoint.
    pub fn con_pieza(&mut self, pieza: Pieza) -> &mut Self {
        self.piezas.push(pieza);
        self
    }

    /// Anota que un endpoint no aporto, y por que.
    pub fn con_ausencia(&mut self, endpoint: &str, ausencia: Ausencia) -> &mut Self {
        self.ausencias.push((endpoint.to_owned(), ausencia));
        self
    }

    /// Endpoints a los que se ordeno y de los que no consta **nada**.
    ///
    /// Ni pieza ni ausencia declarada. Es un fallo de contabilidad del propio
    /// sistema de recogida, y se saca aparte porque es el unico caso en el que
    /// el informe no sabe siquiera que le falta: los demas al menos estan
    /// contados.
    pub fn sin_contabilizar(&self) -> Vec<String> {
        let con_pieza: BTreeSet<&str> = self.piezas.iter().map(|p| p.endpoint.as_str()).collect();
        let con_ausencia: BTreeSet<&str> = self.ausencias.iter().map(|(e, _)| e.as_str()).collect();
        self.ordenados
            .iter()
            .filter(|e| !con_pieza.contains(e.as_str()) && !con_ausencia.contains(e.as_str()))
            .cloned()
            .collect()
    }

    /// Verifica todas las piezas y devuelve el veredicto de cada una.
    ///
    /// `bytes_de` entrega los bytes del artefacto de un endpoint. Devuelve
    /// `None` cuando el almacen no los tiene, que es un caso real —el indice del
    /// caso sobrevive al artefacto— y se cuenta como pieza rota y no como pieza
    /// buena.
    pub fn verificar<'a>(
        &'a self,
        registro: &dyn RegistroDeClaves,
        bytes_de: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> Vec<(&'a str, Veredicto)> {
        self.piezas
            .iter()
            .map(|p| {
                let bytes = bytes_de(&p.endpoint).unwrap_or_default();
                (
                    p.endpoint.as_str(),
                    Veredicto::de(&bytes, &p.sello, &p.cadena, registro),
                )
            })
            .collect()
    }

    /// Cuantos endpoints aportaron una pieza que verifica.
    pub fn integras(
        &self,
        registro: &dyn RegistroDeClaves,
        bytes_de: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> usize {
        self.verificar(registro, bytes_de)
            .iter()
            .filter(|(_, v)| v.intacta)
            .count()
    }

    /// Si de este conjunto se puede concluir algo sobre la flota entera.
    ///
    /// Exige las cuatro cosas, porque con tres no basta:
    ///
    /// - Que se le haya ordenado a alguien. Con la lista vacia las otras tres
    ///   condiciones se cumplen **por vacuidad**, y un conjunto que no pregunto
    ///   a nadie diria estar completo: es la misma mentira en su forma mas pura.
    /// - Que ningun endpoint se haya quedado sin contabilizar.
    /// - Que ninguno tenga una ausencia declarada.
    /// - Que **todas** las piezas verifiquen.
    ///
    /// Un conjunto de noventa y siete piezas perfectas de cien endpoints NO es
    /// completo, y esta funcion es la que se niega a decir que lo sea.
    pub fn esta_completo(
        &self,
        registro: &dyn RegistroDeClaves,
        bytes_de: &dyn Fn(&str) -> Option<Vec<u8>>,
    ) -> bool {
        !self.ordenados.is_empty()
            && self.sin_contabilizar().is_empty()
            && self.ausencias.is_empty()
            && self.piezas.len() == self.ordenados.len()
            && self.integras(registro, bytes_de) == self.ordenados.len()
    }

    /// Las frases de lo que falta, para el informe.
    ///
    /// Lista tambien los no contabilizados, con su propia frase: no aparecen en
    /// `ausencias` justamente porque nadie los conto, y dejarlos fuera del
    /// resumen repetiria el fallo que este modulo evita.
    pub fn lo_que_falta(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .ausencias
            .iter()
            .map(|(e, a)| format!("{e}: {}", a.frase()))
            .collect();
        for e in self.sin_contabilizar() {
            v.push(format!(
                "{e}: no consta ni pieza ni motivo; la recogida no lo conto"
            ));
        }
        v
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::cadena::{Claveros, Paso};
    use crate::reloj::Marca;
    use crate::sello::{Clase, Procedencia};
    use aegis_pqc::firma_hibrida::ClaveFirmaHibrida;

    fn pieza_de(endpoint: &str, clave: &ClaveFirmaHibrida, bytes: &[u8]) -> Pieza {
        let sello = Sello::sellar(
            bytes,
            Procedencia {
                caso: "CASO-1".into(),
                endpoint: endpoint.into(),
                agente: "agente-comun".into(),
                version_agente: "1.0.0".into(),
                clase: Clase::ArbolDeProcesos,
                motivo: "caceria de la flota".into(),
                tecnicas: vec![],
                recogido: Marca::ahora(),
            },
            clave,
        )
        .unwrap();
        let mut cadena = CadenaDeCustodia::anclada_en(&sello);
        cadena
            .anadir(Paso::Recogida, "agente-comun", "orden de caso", clave)
            .unwrap();
        Pieza {
            endpoint: endpoint.into(),
            sello,
            cadena,
        }
    }

    fn tres_endpoints() -> (Vec<String>, ClaveFirmaHibrida, Claveros) {
        let k = ClaveFirmaHibrida::generar_aleatorio().unwrap();
        let registro = Claveros::nuevo().con("agente-comun", k.clave_verificacion());
        let eps: Vec<String> = vec!["e1".into(), "e2".into(), "e3".into()];
        (eps, k, registro)
    }

    #[test]
    fn un_conjunto_con_todos_los_endpoints_y_todo_integro_esta_completo() {
        let (eps, k, registro) = tres_endpoints();
        let mut c = ConjuntoDeFlota::ordenado("CASO-1", &eps);
        for e in &eps {
            c.con_pieza(pieza_de(e, &k, b"arbol"));
        }
        let bytes = |_: &str| Some(b"arbol".to_vec());
        assert!(c.esta_completo(&registro, &bytes));
        assert!(c.lo_que_falta().is_empty());
    }

    #[test]
    fn faltando_un_endpoint_el_conjunto_no_esta_completo_aunque_el_resto_sea_perfecto() {
        // El fallo que este modulo existe para impedir, en pequeno: dos piezas
        // impecables de tres endpoints no son la evidencia del caso.
        let (eps, k, registro) = tres_endpoints();
        let mut c = ConjuntoDeFlota::ordenado("CASO-1", &eps);
        c.con_pieza(pieza_de("e1", &k, b"arbol"));
        c.con_pieza(pieza_de("e2", &k, b"arbol"));
        c.con_ausencia(
            "e3",
            Ausencia::NoAlcanzable {
                visto_por_ultima_vez: Some(1_700_000_000),
            },
        );
        let bytes = |_: &str| Some(b"arbol".to_vec());

        assert_eq!(
            c.integras(&registro, &bytes),
            2,
            "las dos que hay, intactas"
        );
        assert!(
            !c.esta_completo(&registro, &bytes),
            "dos piezas perfectas de tres endpoints no autorizan a concluir \
             nada sobre la flota"
        );
        assert_eq!(c.lo_que_falta().len(), 1);
        assert!(c.lo_que_falta()[0].contains("e3"));
    }

    #[test]
    fn un_endpoint_del_que_no_consta_nada_sale_en_su_propia_lista() {
        // La ausencia peor: ni pieza ni motivo. El informe no sabe siquiera que
        // le falta, asi que la cuenta tiene que cuadrar por construccion.
        let (eps, k, registro) = tres_endpoints();
        let mut c = ConjuntoDeFlota::ordenado("CASO-1", &eps);
        c.con_pieza(pieza_de("e1", &k, b"arbol"));
        c.con_pieza(pieza_de("e2", &k, b"arbol"));
        // e3 no se anota de ninguna forma.
        let bytes = |_: &str| Some(b"arbol".to_vec());

        assert_eq!(c.sin_contabilizar(), vec!["e3".to_string()]);
        assert!(!c.esta_completo(&registro, &bytes));
        assert!(
            c.lo_que_falta().iter().any(|f| f.contains("no lo conto")),
            "un endpoint sin contabilizar tiene que salir en el resumen: {:?}",
            c.lo_que_falta()
        );
    }

    #[test]
    fn una_pieza_que_no_verifica_no_cuenta_como_pieza() {
        let (eps, k, registro) = tres_endpoints();
        let mut c = ConjuntoDeFlota::ordenado("CASO-1", &eps);
        for e in &eps {
            c.con_pieza(pieza_de(e, &k, b"arbol"));
        }
        // El almacen devuelve otros bytes para e2: alguien los cambio.
        let bytes = |e: &str| {
            if e == "e2" {
                Some(b"arbol alterado".to_vec())
            } else {
                Some(b"arbol".to_vec())
            }
        };
        assert_eq!(c.integras(&registro, &bytes), 2);
        assert!(
            !c.esta_completo(&registro, &bytes),
            "una pieza rota deja el conjunto incompleto igual que una ausente"
        );
    }

    #[test]
    fn un_artefacto_que_el_almacen_ya_no_tiene_no_se_da_por_bueno() {
        // El indice del caso sobrevive al artefacto, y entonces el sello y la
        // cadena estan perfectos y los bytes no estan. No es una pieza buena.
        let (eps, k, registro) = tres_endpoints();
        let mut c = ConjuntoDeFlota::ordenado("CASO-1", &eps);
        for e in &eps {
            c.con_pieza(pieza_de(e, &k, b"arbol"));
        }
        let bytes = |e: &str| {
            if e == "e3" {
                None
            } else {
                Some(b"arbol".to_vec())
            }
        };
        assert_eq!(c.integras(&registro, &bytes), 2);
        assert!(!c.esta_completo(&registro, &bytes));
    }

    #[test]
    fn cada_clase_de_ausencia_cuenta_una_historia_distinta() {
        // Que no contesten y que se nieguen no significan lo mismo para quien
        // investiga, y el informe no puede fundirlas en «no disponible».
        let casos = [
            Ausencia::SinRespuesta,
            Ausencia::NoAlcanzable {
                visto_por_ultima_vez: None,
            },
            Ausencia::Rechazada {
                motivo: "la politica del sitio prohibe volcar memoria".into(),
            },
            Ausencia::Parcial {
                motivo: "sin la region 3, el proceso murio a mitad".into(),
            },
            Ausencia::PiezaRota {
                motivo: "la firma no cubre estos bytes".into(),
            },
        ];
        let frases: BTreeSet<String> = casos.iter().map(|a| a.frase()).collect();
        assert_eq!(frases.len(), casos.len(), "ninguna frase se repite");
    }

    #[test]
    fn el_veredicto_de_cada_pieza_llega_con_su_endpoint() {
        let (eps, k, registro) = tres_endpoints();
        let mut c = ConjuntoDeFlota::ordenado("CASO-1", &eps);
        for e in &eps {
            c.con_pieza(pieza_de(e, &k, b"arbol"));
        }
        let bytes = |_: &str| Some(b"arbol".to_vec());
        let v = c.verificar(&registro, &bytes);
        assert_eq!(v.len(), 3);
        assert!(v.iter().all(|(_, ver)| ver.intacta));
        assert_eq!(v[0].0, "e1");
    }

    #[test]
    fn un_conjunto_sin_ordenar_a_nadie_no_esta_completo_por_vacio() {
        // El caso degenerado: cero ordenados y cero piezas cumpliria las tres
        // condiciones por vacuidad. Un conjunto que no ordeno nada no ha
        // recogido la flota, y decir que esta completo seria la misma mentira
        // en su forma mas pura.
        let (_, _, registro) = tres_endpoints();
        let c = ConjuntoDeFlota::ordenado("CASO-1", &[]);
        let bytes = |_: &str| None;
        assert!(
            !c.esta_completo(&registro, &bytes),
            "no haberle preguntado a nadie no es haber recogido la flota"
        );
    }
}
