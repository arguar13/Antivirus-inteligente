//! Los dos modos de detonar, y por que el informe TIENE que decir cual se uso.
//!
//! # La diferencia, y por que no es un detalle de implementacion
//!
//! Detonar una muestra necesita observarla. Hay dos formas:
//!
//! - **Con agente dentro.** Un programa propio corre en el invitado, ve las
//!   llamadas al sistema desde dentro y las cuenta. Ve mucho, ve con contexto, y
//!   **existe**: es un proceso mas, con su nombre, su fichero y su memoria. Una
//!   muestra que lo busque lo encuentra.
//! - **Fantasma, desde el hipervisor.** No hay nada dentro del invitado. Se
//!   observa desde fuera, con trampas de la tabla de paginas extendida y
//!   leyendo la memoria fisica. Ve menos —no hay contexto de proceso servido en
//!   bandeja— y **no hay nada que encontrar**.
//!
//! # Por que esto cambia lo que significa un informe
//!
//! Una muestra que detecta el agente invitado no hace nada, y el informe dice
//! «sin hallazgos». Esa frase es cierta y es inutil: no distingue «esta muestra
//! no hace nada» de «esta muestra no hizo nada MIENTRAS LA MIRABAMOS ASI».
//!
//! Con el modo declarado, las dos se separan. Y hay una consecuencia que suena
//! rara y es la correcta: **una muestra que produce hallazgos en modo fantasma y
//! nada con agente no es una muestra inofensiva, es una muestra que detecta
//! agentes** — y eso es, por si solo, un hallazgo de primera.
//!
//! # Lo que este modulo NO hace
//!
//! No arranca un hipervisor. Sin VT-x o AMD-V no hay trampas de tabla de paginas
//! extendida que poner, y esta maquina de integracion no los expone. Lo que si se
//! ejerce entero es el modelo: que ve cada modo, que delata cada modo, y como
//! cambia la cobertura declarada del informe. Ver
//! [`Modo::tecnicas_que_no_contrarresta`].

/// Como se observa a la muestra mientras detona.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Modo {
    /// Con un agente dentro del invitado.
    ///
    /// Ve mas y con mas contexto. Y existe dentro, asi que se puede encontrar.
    ConAgente,
    /// Desde el hipervisor, sin meter nada dentro.
    ///
    /// Ve menos y no hay nada que encontrar.
    Fantasma,
}

impl Modo {
    /// Los dos, para recorrerlos.
    pub fn todos() -> [Modo; 2] {
        [Modo::ConAgente, Modo::Fantasma]
    }

    /// Nombre estable para el informe.
    pub fn nombre(self) -> &'static str {
        match self {
            Modo::ConAgente => "con-agente",
            Modo::Fantasma => "fantasma",
        }
    }

    /// Lee un modo de su nombre estable.
    ///
    /// Existe para que un informe pueda guardar el modo como TEXTO en vez de
    /// como un numero de variante. El nombre no cambia entre versiones; el orden
    /// de las variantes si puede, y un informe archivado que se lea con otra
    /// version diria que se detono de la otra forma — que es exactamente la
    /// confusion que declarar el modo existe para evitar.
    pub fn de_nombre(s: &str) -> Option<Modo> {
        Modo::todos().into_iter().find(|m| m.nombre() == s)
    }

    /// Si hay algo dentro del invitado que la muestra pueda encontrar.
    ///
    /// Es la propiedad que define el modo, y la unica que de verdad importa: todo
    /// lo demas —que vea mas o menos contexto— es una diferencia de grado.
    pub fn deja_rastro_dentro(self) -> bool {
        matches!(self, Modo::ConAgente)
    }

    /// Las tecnicas de deteccion de analisis que este modo **no** contrarresta.
    ///
    /// # Por que esta lista es la razon de ser del modulo
    ///
    /// Cada una de estas es una forma concreta en que una muestra puede darse
    /// cuenta de que la miran, **con este modo concreto**. Un informe que no las
    /// declare esta diciendo «no encontramos nada» sin decir «y esto es lo que la
    /// muestra pudo mirar para decidir no hacer nada».
    pub fn tecnicas_que_no_contrarresta(self) -> &'static [Delator] {
        match self {
            // El agente es un proceso: tiene nombre, fichero, memoria y conexion
            // con el anfitrion. Cada una de esas cosas se puede buscar.
            Modo::ConAgente => &[
                Delator::ProcesoDelAgente,
                Delator::FicheroDelAgente,
                Delator::CanalConElAnfitrion,
                Delator::LlamadasDelAgente,
            ],
            // Sin nada dentro, esos cuatro desaparecen. Lo que queda son los que
            // vienen de estar virtualizado, que ningun modo de observacion
            // arregla porque no dependen de como se observa.
            Modo::Fantasma => &[Delator::TiempoDeLasTrampas],
        }
    }

    /// Lo que este modo puede observar, y lo que no.
    pub fn frase(self) -> &'static str {
        match self {
            Modo::ConAgente => {
                "con un agente dentro del invitado: ve las llamadas al sistema con su \
                 contexto de proceso, y ESE AGENTE EXISTE DENTRO — una muestra que lo \
                 busque lo encuentra, y si lo encuentra no hara nada"
            }
            Modo::Fantasma => {
                "desde el hipervisor, sin meter nada dentro del invitado: ve menos \
                 contexto, y no hay nada dentro que la muestra pueda encontrar"
            }
        }
    }
}

/// Algo que delata que se esta observando, en un modo concreto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Delator {
    /// El proceso del agente aparece en la lista de procesos del invitado.
    ProcesoDelAgente,
    /// El fichero del agente esta en el disco del invitado.
    FicheroDelAgente,
    /// Hay un canal abierto entre el invitado y el anfitrion.
    CanalConElAnfitrion,
    /// Las llamadas al sistema que hace el propio agente.
    LlamadasDelAgente,
    /// Las trampas del hipervisor cuestan tiempo, y ese tiempo se puede medir.
    TiempoDeLasTrampas,
}

impl Delator {
    /// Como se detecta, y por que el modo correspondiente no lo evita.
    pub fn frase(self) -> &'static str {
        match self {
            Delator::ProcesoDelAgente => {
                "el agente es un proceso del invitado: sale en cualquier lista de \
                 procesos, y quitarlo de la lista exigiria que el agente fuera un \
                 rootkit"
            }
            Delator::FicheroDelAgente => {
                "el binario del agente esta en el disco del invitado y se puede buscar \
                 por nombre, por tamano o por contenido"
            }
            Delator::CanalConElAnfitrion => {
                "el agente habla con el anfitrion, y ese canal —un puerto serie virtual, \
                 un socket— es visible desde dentro"
            }
            Delator::LlamadasDelAgente => {
                "el propio agente hace llamadas al sistema, y una muestra que cuente las \
                 llamadas del sistema entero ve las suyas mezcladas con las demas"
            }
            Delator::TiempoDeLasTrampas => {
                "cada trampa del hipervisor cuesta una salida de la maquina virtual, y \
                 eso se nota midiendo el tiempo de la instruccion atrapada. Es el precio \
                 de observar sin meter nada dentro, y no lo arregla ningun modo: lo \
                 unico que lo mitiga es poner pocas trampas"
            }
        }
    }
}

/// Lo que un modo consiguio observar, con su declaracion.
///
/// # Por que el modo va DENTRO del resultado
///
/// Porque «sin hallazgos» significa cosas distintas segun el modo, y separarlos
/// en dos valores permite que uno viaje sin el otro. Cuando eso pasa —y pasa, en
/// cuanto alguien serializa solo la lista— el informe queda diciendo una cosa
/// cierta y engañosa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observacion {
    /// Con que modo se observo.
    pub modo: Modo,
    /// Cuantos sucesos se vieron.
    pub sucesos: usize,
    /// Si la muestra llego a ejecutarse.
    pub arranco: bool,
}

impl Observacion {
    /// Si de esta observacion se puede concluir que la muestra no hace nada.
    ///
    /// **Nunca en modo con agente sin sucesos.** Con el agente dentro, cero
    /// sucesos es indistinguible de «la muestra encontro el agente y se marcho»,
    /// y las dos lecturas llevan a decisiones opuestas.
    pub fn la_ausencia_significa_algo(&self) -> bool {
        if !self.arranco {
            return false;
        }
        match self.modo {
            Modo::ConAgente => self.sucesos > 0,
            Modo::Fantasma => true,
        }
    }

    /// La frase con la que esta observacion aparece en un informe.
    pub fn frase(&self) -> String {
        let mut s = format!(
            "detonada en modo {} ({}); {} sucesos observados",
            self.modo.nombre(),
            self.modo.frase(),
            self.sucesos
        );
        if !self.arranco {
            s.push_str(". LA MUESTRA NO LLEGO A EJECUTARSE, asi que no se observo nada de ella");
            return s;
        }
        if !self.la_ausencia_significa_algo() {
            s.push_str(
                ". NO SE VIO NADA, Y CON AGENTE DENTRO ESO NO SIGNIFICA QUE NO HAGA \
                 NADA: es indistinguible de que la muestra encontrara el agente y se \
                 marchara",
            );
        }
        let sin_cubrir = self.modo.tecnicas_que_no_contrarresta();
        if !sin_cubrir.is_empty() {
            s.push_str(&format!(
                ". Este modo NO contrarresta {} formas de detectar el analisis: {}",
                sin_cubrir.len(),
                sin_cubrir
                    .iter()
                    .map(|d| d.frase())
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        s
    }
}

/// Lo que dicen las dos detonaciones de la misma muestra, juntas.
///
/// # El hallazgo que solo aparece comparando
///
/// Una muestra que hace cosas en modo fantasma y nada con agente **no es una
/// muestra inofensiva**: es una muestra que detecta agentes de analisis, y eso es
/// por si solo un hallazgo de primera. No hay forma de verlo con una sola
/// detonacion, y por eso este tipo existe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparacion {
    /// Lo que se vio con agente.
    pub con_agente: Observacion,
    /// Lo que se vio sin el.
    pub fantasma: Observacion,
}

impl Comparacion {
    /// Si la muestra se comporta distinto cuando hay un agente dentro.
    pub fn detecta_el_agente(&self) -> bool {
        self.con_agente.arranco
            && self.fantasma.arranco
            && self.con_agente.sucesos == 0
            && self.fantasma.sucesos > 0
    }

    /// La frase con la que esta comparacion aparece en un informe.
    pub fn frase(&self) -> String {
        if self.detecta_el_agente() {
            return format!(
                "ESTA MUESTRA DETECTA AGENTES DE ANALISIS: no hizo nada con el agente \
                 dentro y {} cosas sin el. Eso no es una muestra inofensiva, es una que \
                 sabe cuando la miran — y saberlo es, por si solo, un hallazgo",
                self.fantasma.sucesos
            );
        }
        format!(
            "con agente: {} sucesos; fantasma: {} sucesos",
            self.con_agente.sucesos, self.fantasma.sucesos
        )
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn obs(modo: Modo, sucesos: usize) -> Observacion {
        Observacion {
            modo,
            sucesos,
            arranco: true,
        }
    }

    #[test]
    fn el_nombre_de_un_modo_va_y_vuelve() {
        // Un informe archivado que se lea con otra version tiene que decir el
        // mismo modo. Por el numero de variante no se puede garantizar; por el
        // nombre si.
        for m in Modo::todos() {
            assert_eq!(Modo::de_nombre(m.nombre()), Some(m));
        }
        assert_eq!(Modo::de_nombre("lo-que-sea"), None);
    }

    #[test]
    fn el_modo_fantasma_no_deja_rastro_dentro_y_el_otro_si() {
        // Es la propiedad que define los dos modos; todo lo demas es grado.
        assert!(Modo::ConAgente.deja_rastro_dentro());
        assert!(!Modo::Fantasma.deja_rastro_dentro());
    }

    #[test]
    fn con_agente_hay_cuatro_delatores_y_sin_el_queda_uno() {
        // El agente es un proceso: tiene nombre, fichero, canal y llamadas. Sin
        // nada dentro, esas cuatro desaparecen y queda el precio de las trampas,
        // que no lo arregla ningun modo.
        assert_eq!(Modo::ConAgente.tecnicas_que_no_contrarresta().len(), 4);
        assert_eq!(Modo::Fantasma.tecnicas_que_no_contrarresta().len(), 1);
        assert!(Modo::Fantasma
            .tecnicas_que_no_contrarresta()
            .contains(&Delator::TiempoDeLasTrampas));
    }

    #[test]
    fn el_catalogo_de_delatores_cambia_con_el_modo_y_no_al_reves() {
        // La propiedad que hace util declarar el modo: si los dos modos tuvieran
        // el mismo catalogo, declararlo no diria nada.
        let a = Modo::ConAgente.tecnicas_que_no_contrarresta().to_vec();
        let f = Modo::Fantasma.tecnicas_que_no_contrarresta().to_vec();
        assert_ne!(a, f);
        for d in &a {
            assert!(
                !f.contains(d),
                "{d:?} tendria que desaparecer en modo fantasma"
            );
        }
    }

    #[test]
    fn cero_sucesos_con_agente_dentro_no_significa_que_la_muestra_no_haga_nada() {
        // La averia que esta fase existe para cerrar: es indistinguible de que la
        // muestra encontrara el agente y se marchara, y las dos lecturas llevan a
        // decisiones opuestas.
        let o = obs(Modo::ConAgente, 0);
        assert!(!o.la_ausencia_significa_algo());
        assert!(
            o.frase().contains("NO SIGNIFICA QUE NO HAGA NADA"),
            "{}",
            o.frase()
        );
    }

    #[test]
    fn cero_sucesos_en_modo_fantasma_si_significa_algo() {
        // Sin nada dentro que encontrar, no haber hecho nada es no haber hecho
        // nada. Es exactamente lo que el modo fantasma compra.
        let o = obs(Modo::Fantasma, 0);
        assert!(o.la_ausencia_significa_algo());
        assert!(!o.frase().contains("NO SIGNIFICA"), "{}", o.frase());
    }

    #[test]
    fn una_muestra_que_no_arranco_no_dice_nada_en_ningun_modo() {
        for m in Modo::todos() {
            let o = Observacion {
                modo: m,
                sucesos: 0,
                arranco: false,
            };
            assert!(!o.la_ausencia_significa_algo(), "{m:?}");
            assert!(o.frase().contains("NO LLEGO A EJECUTARSE"), "{}", o.frase());
        }
    }

    #[test]
    fn la_muestra_que_no_hace_nada_con_agente_y_si_sin_el_queda_senalada() {
        // El hallazgo que solo aparece comparando, y que ninguna detonacion suelta
        // puede producir.
        let c = Comparacion {
            con_agente: obs(Modo::ConAgente, 0),
            fantasma: obs(Modo::Fantasma, 47),
        };
        assert!(c.detecta_el_agente());
        assert!(c.frase().contains("DETECTA AGENTES"), "{}", c.frase());
        assert!(c.frase().contains("47"), "{}", c.frase());
    }

    #[test]
    fn una_muestra_que_no_hace_nada_en_ninguno_de_los_dos_no_se_acusa_de_nada() {
        // El caso negativo: si no hace nada en ninguno, no hay evidencia de que
        // detecte agentes, y decir que la hay seria inventarla.
        let c = Comparacion {
            con_agente: obs(Modo::ConAgente, 0),
            fantasma: obs(Modo::Fantasma, 0),
        };
        assert!(!c.detecta_el_agente());
        assert!(!c.frase().contains("DETECTA AGENTES"), "{}", c.frase());
    }

    #[test]
    fn una_muestra_que_hace_lo_mismo_en_los_dos_modos_tampoco() {
        let c = Comparacion {
            con_agente: obs(Modo::ConAgente, 30),
            fantasma: obs(Modo::Fantasma, 31),
        };
        assert!(!c.detecta_el_agente());
    }

    #[test]
    fn la_frase_de_cada_modo_dice_lo_que_ese_modo_no_cubre() {
        // Un informe que no lo declare esta diciendo «no encontramos nada» sin
        // decir «y esto es lo que la muestra pudo mirar para decidir no hacer
        // nada».
        let a = obs(Modo::ConAgente, 5).frase();
        assert!(a.contains("NO contrarresta 4"), "{a}");
        assert!(a.contains("lista de procesos"), "{a}");
        let f = obs(Modo::Fantasma, 5).frase();
        assert!(f.contains("NO contrarresta 1"), "{f}");
        assert!(f.contains("salida de la maquina virtual"), "{f}");
    }
}
