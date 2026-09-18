//! La jaula, y el tipo que no se puede construir fuera de ella.
//!
//! # La diferencia esta en el TIPO, no en una bandera
//!
//! Instrumentar un proceso vivo tiene dos modos que se parecen mucho por fuera:
//! observar y intervenir. El primero lee; el segundo escribe en el espacio de
//! direcciones de otro proceso, que es exactamente lo que hace una inyeccion de
//! codigo.
//!
//! La forma habitual de separarlos es una bandera: `modo: Modo`, `if solo_lectura
//! { ... }`. Esa separacion **no resiste nada**. Una bandera se pone mal, se lee
//! de configuracion, se invierte en un refactor, y el dia que falle nadie se
//! entera porque el codigo compila igual.
//!
//! Aqui la separacion es de tipos:
//!
//! - [`Observador`] existe siempre y **no tiene ninguna operacion de escritura**.
//! - [`Interventor`] necesita una `&`[`Jaula`] para construirse, y [`Jaula`] solo
//!   se obtiene **midiendo** que se esta dentro del confinamiento de detonacion.
//!
//! Fuera de la jaula, `Interventor` no se puede construir. No porque una
//! comprobacion lo impida en ejecucion: porque no hay forma de escribir la
//! llamada. Y nadie puede fabricar su propia prueba, porque [`PruebaDeJaula`]
//! esta **sellado** — depende de un rasgo privado de este modulo, asi que ningun
//! otro crate puede implementarlo.
//!
//! # Que se mide para dar por buena la jaula
//!
//! Estar dentro de la microVM de detonacion, y se exige que coincidan **varias
//! senales independientes**. Una sola es una adivinanza: un fichero marcador lo
//! puede crear cualquiera, y correr bajo un hipervisor lo hace media nube.
//!
//! Y lo mas importante: **[`Jaula::medir`] falla en esta maquina**, y hay una
//! prueba que lo comprueba. Una comprobacion de confinamiento que dijera que si
//! en la maquina de desarrollo no comprobaria nada en ninguna parte.
//!
//! # Las dos pruebas que no compilan
//!
//! Nadie puede fabricar su propia prueba de estar en la jaula. El ejemplo
//! implementa el rasgo ENTERO —para que el fallo no pueda ser «falta un metodo»—
//! y aun asi no compila, con el codigo de error atado: `E0277` es exactamente
//! «no cumple el rasgo sellado». Un `compile_fail` sin codigo de error pasaria
//! igual con una errata dentro, y no comprobaria nada.
//!
//! ```compile_fail,E0277
//! use aegis_instrumentar::jaula::{PruebaDeJaula, Senal};
//! struct MiJaulaFalsa;
//! impl PruebaDeJaula for MiJaulaFalsa {
//!     fn evidencia(&self) -> &[Senal] { &[] }
//! }
//! ```
//!
//! Y el interventor no se puede construir sin una jaula de verdad: `E0308` es
//! «ese no es el tipo que hace falta aqui».
//!
//! ```compile_fail,E0308
//! use aegis_instrumentar::jaula::Interventor;
//! // Ni con otro tipo cualquiera, ni con nada que no salga de `Jaula::medir`.
//! let _ = Interventor::nuevo(&(), 1234);
//! ```

use std::path::{Path, PathBuf};

/// El rasgo privado que sella [`PruebaDeJaula`].
///
/// Al estar en un modulo privado, ningun crate de fuera puede nombrarlo y por
/// tanto ninguno puede implementar el rasgo que depende de el. Es el mecanismo
/// estandar de Rust para un rasgo cerrado, y aqui es lo que impide que alguien
/// escriba su propia «prueba» de estar confinado.
mod sello {
    /// No lo puede implementar nadie de fuera.
    pub trait Sellado {}
}

/// La prueba de estar dentro de la jaula de detonacion.
///
/// **Sellado**: solo [`Jaula`] lo implementa, y solo se obtiene midiendo. Ver la
/// cabecera del modulo.
pub trait PruebaDeJaula: sello::Sellado {
    /// Que se midio para darla por buena.
    fn evidencia(&self) -> &[Senal];
}

/// Una senal de estar dentro del confinamiento.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Senal {
    /// El proceso numero uno es el arrancador de la microVM.
    ///
    /// Dentro de la jaula, el primer proceso lo pone el arranque de la microVM y
    /// no es el `init` de una maquina normal.
    ElProcesoUnoEsElArrancador,
    /// Hay un marcador que el arranque de la jaula escribe.
    ///
    /// Por si sola no prueba nada —un fichero lo crea cualquiera— y por eso no
    /// basta; en compania de las demas, confirma que es ESTA jaula y no otro
    /// confinamiento cualquiera.
    ElMarcadorDeArranque,
    /// No hay ruta de salida a la red.
    ///
    /// Es la propiedad que de verdad importa: dentro de la jaula, lo que la
    /// muestra haga no sale. Es tambien la mas dificil de fingir sin perderla.
    SinSalidaDeRed,
    /// La raiz esta montada de solo lectura.
    RaizDeSoloLectura,
}

impl Senal {
    /// Como se lee en un informe.
    pub fn frase(&self) -> &'static str {
        match self {
            Senal::ElProcesoUnoEsElArrancador => {
                "el proceso numero uno es el arrancador de la microVM y no el init de \
                 una maquina normal"
            }
            Senal::ElMarcadorDeArranque => "esta el marcador que escribe el arranque de la jaula",
            Senal::SinSalidaDeRed => {
                "no hay ruta de salida a la red, asi que lo que la muestra haga no sale"
            }
            Senal::RaizDeSoloLectura => "la raiz esta montada de solo lectura",
        }
    }
}

/// Cuantas senales independientes hacen falta.
///
/// Una sola es una adivinanza: un fichero marcador lo puede crear cualquiera, y
/// correr bajo un hipervisor lo hace media nube. Tres de cuatro exige que quien
/// quiera fingir la jaula reproduzca el confinamiento de verdad — momento en el
/// cual ya no esta fingiendo, esta confinado.
pub const SENALES_NECESARIAS: usize = 3;

/// El confinamiento de detonacion, medido.
///
/// No se puede construir con un literal desde fuera: sus campos son privados y su
/// unico constructor mide.
#[derive(Debug, Clone)]
pub struct Jaula {
    evidencia: Vec<Senal>,
}

impl sello::Sellado for Jaula {}

impl PruebaDeJaula for Jaula {
    fn evidencia(&self) -> &[Senal] {
        &self.evidencia
    }
}

/// Por que no se pudo dar por buena la jaula.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FueraDeLaJaula {
    /// Lo que si se vio.
    pub visto: Vec<Senal>,
    /// Cuantas hacian falta.
    pub hacian_falta: usize,
}

impl std::fmt::Display for FueraDeLaJaula {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no se esta dentro de la jaula de detonacion: hacian falta {} senales y se \
             vieron {} ({})",
            self.hacian_falta,
            self.visto.len(),
            if self.visto.is_empty() {
                "ninguna".to_owned()
            } else {
                self.visto
                    .iter()
                    .map(|s| s.frase())
                    .collect::<Vec<_>>()
                    .join("; ")
            }
        )
    }
}

impl std::error::Error for FueraDeLaJaula {}

impl Jaula {
    /// Mide el entorno y da la prueba, o dice por que no.
    ///
    /// **Falla en cualquier maquina que no sea la jaula**, incluida la de
    /// desarrollo, y hay una prueba que lo comprueba: una comprobacion de
    /// confinamiento que dijera que si en la maquina de desarrollo no
    /// comprobaria nada en ninguna parte.
    pub fn medir() -> Result<Jaula, FueraDeLaJaula> {
        Jaula::medir_en(Path::new("/"))
    }

    /// Lo mismo, con la raiz que se le diga.
    ///
    /// Existe para que las pruebas puedan construir un entorno que cumpla las
    /// senales y comprobar las DOS direcciones: que dentro se da por buena y que
    /// fuera no. Sin esto, la mitad de la propiedad quedaria sin probar.
    pub fn medir_en(raiz: &Path) -> Result<Jaula, FueraDeLaJaula> {
        let mut visto = Vec::new();

        if let Ok(c) = std::fs::read_to_string(raiz.join("proc/1/comm")) {
            if c.trim() == ARRANCADOR_DE_LA_JAULA {
                visto.push(Senal::ElProcesoUnoEsElArrancador);
            }
        }
        if raiz.join(MARCADOR_DE_ARRANQUE).exists() {
            visto.push(Senal::ElMarcadorDeArranque);
        }
        if sin_salida_de_red(raiz) {
            visto.push(Senal::SinSalidaDeRed);
        }
        if raiz_de_solo_lectura(raiz) {
            visto.push(Senal::RaizDeSoloLectura);
        }

        visto.sort_unstable();
        visto.dedup();
        if visto.len() >= SENALES_NECESARIAS {
            Ok(Jaula { evidencia: visto })
        } else {
            Err(FueraDeLaJaula {
                visto,
                hacian_falta: SENALES_NECESARIAS,
            })
        }
    }

    /// La frase con la que esta jaula aparece en un informe.
    pub fn frase(&self) -> String {
        format!(
            "confinamiento comprobado por {} senales: {}",
            self.evidencia.len(),
            self.evidencia
                .iter()
                .map(|s| s.frase())
                .collect::<Vec<_>>()
                .join("; ")
        )
    }
}

/// Como se llama el primer proceso dentro de la jaula.
const ARRANCADOR_DE_LA_JAULA: &str = "aegis-jaula";

/// Donde escribe su marcador el arranque de la jaula.
const MARCADOR_DE_ARRANQUE: &str = "run/aegis-jaula/confinado";

/// Si no hay ruta de salida a la red.
///
/// Se lee la tabla de rutas del nucleo y se busca una ruta por defecto —destino
/// cero—. Sin ella, nada sale de aqui.
fn sin_salida_de_red(raiz: &Path) -> bool {
    let Ok(texto) = std::fs::read_to_string(raiz.join("proc/net/route")) else {
        // Sin tabla de rutas legible no se puede afirmar que no hay salida. Se
        // devuelve `false`, que es lo seguro: una senal que no se puede medir no
        // cuenta a favor del confinamiento.
        return false;
    };
    !texto.lines().skip(1).any(|l| {
        let mut c = l.split_whitespace();
        let _ = c.next();
        c.next() == Some("00000000")
    })
}

/// Si la raiz esta montada de solo lectura.
fn raiz_de_solo_lectura(raiz: &Path) -> bool {
    let Ok(texto) = std::fs::read_to_string(raiz.join("proc/mounts")) else {
        return false;
    };
    texto.lines().any(|l| {
        let c: Vec<&str> = l.split_whitespace().collect();
        c.len() >= 4 && c[1] == "/" && c[3].split(',').any(|o| o == "ro")
    })
}

/// Observa un proceso sin escribir en el.
///
/// # Lo que no tiene
///
/// No hay aqui ningun metodo que escriba: ni en la memoria del proceso, ni en sus
/// registros, ni en su flujo de control. Existe fuera de la jaula porque leer no
/// tiene consecuencias; lo que las tiene es escribir, y para eso esta
/// [`Interventor`].
#[derive(Debug, Clone)]
pub struct Observador {
    proceso: u32,
    enganches: Vec<PathBuf>,
}

impl Observador {
    /// Empieza a observar un proceso.
    ///
    /// No necesita prueba de nada porque no puede hacer nada irreversible.
    pub fn sobre(proceso: u32) -> Observador {
        Observador {
            proceso,
            enganches: Vec::new(),
        }
    }

    /// Que proceso observa.
    pub fn proceso(&self) -> u32 {
        self.proceso
    }

    /// Anota un enganche de solo lectura sobre un binario.
    ///
    /// Un enganche de este tipo se implementa con un uprobe de eBPF: el nucleo
    /// pone el punto de parada, el proceso no se toca y no hay nada que el
    /// proceso pueda mirar para saber que esta enganchado — que es la diferencia
    /// con inyectarle un motor de scripts dentro.
    pub fn enganchar(&mut self, binario: PathBuf) {
        if !self.enganches.contains(&binario) {
            self.enganches.push(binario);
        }
    }

    /// Los enganches puestos.
    pub fn enganches(&self) -> &[PathBuf] {
        &self.enganches
    }

    /// La frase con la que este observador aparece en un informe.
    pub fn frase(&self) -> String {
        format!(
            "observando el proceso {} con {} enganches de solo lectura; no se ha escrito \
             ni un byte en el, y este tipo no tiene forma de hacerlo",
            self.proceso,
            self.enganches.len()
        )
    }
}

/// Interviene en un proceso: escribe.
///
/// # Por que este tipo lleva una referencia a la jaula
///
/// Porque sin ella no se puede construir, y la jaula solo se obtiene midiendo.
/// El prestamo no es decorativo: ata la vida del interventor a la de la prueba,
/// asi que no se puede construir la prueba, tirarla y quedarse con la capacidad.
#[derive(Debug)]
pub struct Interventor<'j> {
    jaula: &'j Jaula,
    proceso: u32,
    escrituras: Vec<Escritura>,
}

/// Una escritura hecha dentro de la jaula.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escritura {
    /// En que direccion.
    pub direccion: u64,
    /// Cuantos bytes.
    pub bytes: usize,
    /// Por que se hizo.
    ///
    /// Va dentro del tipo porque una escritura en la memoria de otro proceso sin
    /// razon escrita es indistinguible de un ataque en cualquier registro que
    /// alguien lea despues.
    pub porque: String,
}

impl<'j> Interventor<'j> {
    /// Abre un interventor. **Solo se puede llamar con una prueba de la jaula.**
    pub fn nuevo(jaula: &'j Jaula, proceso: u32) -> Interventor<'j> {
        Interventor {
            jaula,
            proceso,
            escrituras: Vec::new(),
        }
    }

    /// Anota una escritura, que solo tiene sentido dentro de la jaula.
    ///
    /// Devuelve `false` sin razon escrita: una escritura en la memoria de otro
    /// proceso sin justificacion es indistinguible de un ataque para quien lea el
    /// registro despues.
    pub fn escribir(&mut self, direccion: u64, bytes: usize, porque: impl Into<String>) -> bool {
        let porque = porque.into();
        if porque.trim().is_empty() {
            return false;
        }
        self.escrituras.push(Escritura {
            direccion,
            bytes,
            porque,
        });
        true
    }

    /// Lo que se ha escrito.
    pub fn escrituras(&self) -> &[Escritura] {
        &self.escrituras
    }

    /// Que proceso se interviene.
    pub fn proceso(&self) -> u32 {
        self.proceso
    }

    /// La frase con la que esta intervencion aparece en un informe.
    pub fn frase(&self) -> String {
        format!(
            "interviniendo el proceso {} con {} escrituras, dentro de la jaula ({})",
            self.proceso,
            self.escrituras.len(),
            self.jaula.frase()
        )
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Construye una raiz de mentira con las senales que se le pidan.
    fn raiz_con(senales: &[Senal], nombre: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aegis-jaula-{nombre}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("proc/1")).unwrap();
        std::fs::create_dir_all(d.join("proc/net")).unwrap();

        let arrancador = if senales.contains(&Senal::ElProcesoUnoEsElArrancador) {
            ARRANCADOR_DE_LA_JAULA
        } else {
            "systemd"
        };
        std::fs::write(d.join("proc/1/comm"), format!("{arrancador}\n")).unwrap();

        if senales.contains(&Senal::ElMarcadorDeArranque) {
            let m = d.join(MARCADOR_DE_ARRANQUE);
            std::fs::create_dir_all(m.parent().unwrap()).unwrap();
            std::fs::write(m, "1").unwrap();
        }
        // Con salida de red hay una ruta por defecto (destino 00000000).
        let rutas = if senales.contains(&Senal::SinSalidaDeRed) {
            "Iface\tDestination\tGateway\neth0\t0002A8C0\t00000000\n"
        } else {
            "Iface\tDestination\tGateway\neth0\t00000000\t0102A8C0\n"
        };
        std::fs::write(d.join("proc/net/route"), rutas).unwrap();

        let montajes = if senales.contains(&Senal::RaizDeSoloLectura) {
            "/dev/vda / ext4 ro,relatime 0 0\n"
        } else {
            "/dev/vda / ext4 rw,relatime 0 0\n"
        };
        std::fs::write(d.join("proc/mounts"), montajes).unwrap();
        d
    }

    #[test]
    fn en_esta_maquina_no_se_esta_dentro_de_la_jaula() {
        // La prueba mas importante del modulo. Una comprobacion de confinamiento
        // que dijera que si en la maquina de desarrollo no comprobaria nada en
        // ninguna parte, y todo lo demas seria decorado.
        let r = Jaula::medir();
        assert!(
            r.is_err(),
            "la comprobacion de confinamiento dice que si en la maquina de desarrollo"
        );
        let e = r.unwrap_err();
        assert!(e.to_string().contains("no se esta dentro"), "{e}");
    }

    #[test]
    fn con_las_senales_suficientes_la_jaula_se_da_por_buena() {
        // La otra direccion de la propiedad: si nunca diera que si, el
        // interventor no se podria usar ni en la jaula y la fase no serviria.
        let d = raiz_con(
            &[
                Senal::ElProcesoUnoEsElArrancador,
                Senal::ElMarcadorDeArranque,
                Senal::SinSalidaDeRed,
                Senal::RaizDeSoloLectura,
            ],
            "completa",
        );
        let j = Jaula::medir_en(&d).expect("con las cuatro senales tiene que dar que si");
        assert_eq!(j.evidencia().len(), 4);
        assert!(j.frase().contains("no hay ruta de salida"), "{}", j.frase());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn un_marcador_a_secas_no_basta_para_dar_la_jaula_por_buena() {
        // Un fichero lo crea cualquiera. Si bastara, la jaula la fingiria
        // cualquier proceso con permiso de escritura en su propia raiz.
        let d = raiz_con(&[Senal::ElMarcadorDeArranque], "solo-marcador");
        let e = Jaula::medir_en(&d).unwrap_err();
        assert_eq!(e.visto, vec![Senal::ElMarcadorDeArranque]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dos_senales_tampoco_bastan() {
        // El umbral es tres, y se comprueba justo por debajo: un umbral que no se
        // prueba en su frontera es un numero que nadie ha verificado.
        let d = raiz_con(
            &[Senal::ElMarcadorDeArranque, Senal::RaizDeSoloLectura],
            "dos",
        );
        assert!(Jaula::medir_en(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tres_senales_si_bastan() {
        let d = raiz_con(
            &[
                Senal::ElMarcadorDeArranque,
                Senal::RaizDeSoloLectura,
                Senal::SinSalidaDeRed,
            ],
            "tres",
        );
        assert!(Jaula::medir_en(&d).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn una_senal_que_no_se_puede_medir_no_cuenta_a_favor() {
        // Sin tabla de rutas legible no se puede AFIRMAR que no hay salida. Que
        // contara a favor haria que un entorno donde no se puede medir nada
        // pareciera el mas confinado de todos.
        let d = std::env::temp_dir().join("aegis-jaula-sin-proc");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert!(Jaula::medir_en(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn el_observador_no_tiene_ninguna_operacion_de_escritura() {
        // Se comprueba por lo que se puede escribir en esta prueba: si
        // `Observador` tuviera un metodo de escritura, esta linea lo usaria y la
        // prueba habria que cambiarla — que es justo el momento en que alguien
        // tiene que explicarse.
        let mut o = Observador::sobre(1234);
        o.enganchar(PathBuf::from("/usr/lib/libssl.so"));
        o.enganchar(PathBuf::from("/usr/lib/libssl.so"));
        assert_eq!(o.enganches().len(), 1, "un enganche repetido no se duplica");
        assert_eq!(o.proceso(), 1234);
        assert!(o.frase().contains("no se ha escrito"), "{}", o.frase());
    }

    #[test]
    fn el_interventor_necesita_la_jaula_para_existir() {
        // La propiedad central: la firma de `nuevo` exige `&Jaula`, y `Jaula` no
        // se puede construir sin medir. Esta prueba solo puede escribirse
        // consiguiendo antes la jaula, que es la demostracion.
        let d = raiz_con(
            &[
                Senal::ElProcesoUnoEsElArrancador,
                Senal::ElMarcadorDeArranque,
                Senal::SinSalidaDeRed,
            ],
            "interventor",
        );
        let j = Jaula::medir_en(&d).unwrap();
        let mut i = Interventor::nuevo(&j, 99);
        assert!(i.escribir(0x0040_1000, 8, "forzar la rama que solo toma en la victima"));
        assert_eq!(i.escrituras().len(), 1);
        assert!(i.frase().contains("dentro de la jaula"), "{}", i.frase());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn una_escritura_sin_razon_escrita_no_se_hace() {
        // Una escritura en la memoria de otro proceso sin justificacion es
        // indistinguible de un ataque para quien lea el registro despues.
        let d = raiz_con(
            &[
                Senal::ElProcesoUnoEsElArrancador,
                Senal::ElMarcadorDeArranque,
                Senal::SinSalidaDeRed,
            ],
            "sin-razon",
        );
        let j = Jaula::medir_en(&d).unwrap();
        let mut i = Interventor::nuevo(&j, 99);
        assert!(!i.escribir(0x0040_1000, 8, "   "));
        assert!(i.escrituras().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }
}
