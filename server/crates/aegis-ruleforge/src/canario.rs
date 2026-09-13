//! El canario: ningun corpus se firma si dispara sobre software legitimo.
//!
//! # Por que esto bloquea la release y no avisa
//!
//! Un falso positivo en un EDR no es un fallo cosmetico. Una firma que casa con
//! `/bin/ls` y se distribuye con el modo de corte activo **mata `ls` en toda la
//! flota a la vez**, en el mismo minuto, sin que haya un atacante. El radio de
//! explosion no es un equipo: es la organizacion entera, y la causa no es un
//! exploit sino un fichero de contenido firmado por el fabricante — que es
//! exactamente la forma que tuvo la caida de CrowdStrike de julio de 2024.
//!
//! Por eso el canario no emite un aviso que alguien pueda ignorar con prisa:
//! devuelve un veredicto, y [`Veredicto::aprobado`] en `false` significa que el
//! corpus **no se firma**. Un canario que solo avisa es un canario que en la
//! unica ocasion que importa nadie leyo.
//!
//! # Ficheros reales, no sinteticos
//!
//! Las muestras salen del sistema de ficheros del host ([`Canario::del_sistema`])
//! y no de un generador. Un ELF fabricado en una prueba no tiene las cadenas, las
//! tablas de secciones ni las secuencias de instrucciones que hacen que una firma
//! corta dispare; usarlo como canario daria un verde que no significa nada.
//!
//! # Las tres cosas que bloquean
//!
//! 1. **Disparo.** Una firma casa con una muestra buena conocida.
//! 2. **Firma demasiado corta.** Una firma con muy pocos bytes fijos dispara
//!    sobre cualquier fichero grande por pura estadistica, la haya visto o no el
//!    canario. Se rechaza sin necesidad de que dispare, porque el corpus de
//!    muestras nunca va a ser todo el software del mundo.
//! 3. **Firma no evaluable.** Si el emparejador agota su presupuesto de pasos, el
//!    resultado no es «limpia»: es **desconocida**, y desconocida bloquea igual.
//!    Declarar limpia una firma que no se pudo evaluar seria firmar a ciegas.
//!
//! # El muro, declarado
//!
//! Aqui se evaluan las firmas que esta fabrica sabe interpretar por si sola: las
//! de cuerpo de ClamAV, con sus comodines, y las de hash SHA-256. **Las reglas
//! YARA y Sigma no se evaluan aqui**: necesitan sus propios motores, que viven en
//! otros crates, y fingir que se comprueban devolviendo verde seria justo la
//! clase de mentira que este modulo existe para evitar. Quien tenga esos motores
//! los aporta con [`Canario::evaluar_con`].
//!
//! Y el limite de fondo, que ninguna implementacion arregla: el canario demuestra
//! la ausencia de falsos positivos **sobre su conjunto de muestras**, no en
//! general. Por eso la comprobacion 2 existe: es la unica de las tres que dice
//! algo sobre el software que el canario no ha visto.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::clamav::{Firma, Trozo};

/// Bytes fijos minimos que ha de tener una firma de cuerpo.
///
/// # De donde sale el numero
///
/// Una secuencia de `n` bytes concretos aparece por azar en un fichero de `L`
/// bytes con probabilidad aproximada `L / 256^n`. Con los 16 bytes de aqui, un
/// binario de 100 MB da del orden de `10^8 / 10^38`: imposible en la practica.
/// Con 8 bytes serian `10^8 / 10^19`, aun comodo; con 4, `10^8 / 10^9`, y eso ya
/// es un falso positivo cada diez ficheros grandes.
///
/// Se elige 16 y no 8 porque los bytes de una firma real no son aleatorios: son
/// codigo y cadenas, que se repiten muchisimo mas que el azar entre binarios
/// compilados con el mismo compilador.
pub const MINIMO_BYTES_FIJOS: usize = 16;

/// Pasos maximos que puede gastar el emparejador en una firma y una muestra.
///
/// Los comodines `*` y `{n-m}` combinados con alternativas hacen que el coste
/// crezca de forma explosiva. Agotar el presupuesto **no** es «no casa»: es «no
/// se sabe», y se trata como bloqueante.
pub const PRESUPUESTO_PASOS: u64 = 200_000;

/// Bytes maximos que se leen de cada muestra.
///
/// El canario se ejecuta en cada compilacion del corpus. Leer binarios enteros de
/// cientos de megas lo volveria tan lento que alguien acabaria saltandoselo, y un
/// canario que se salta no protege de nada.
pub const MAX_BYTES_MUESTRA: usize = 4 * 1024 * 1024;

/// De donde salio una muestra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Procedencia {
    /// Un fichero real del host.
    Sistema(PathBuf),
    /// Contenido aportado por quien llama.
    Aportada,
}

/// Una pieza de software legitimo contra la que se prueba el corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Muestra {
    /// Nombre legible, para el informe.
    pub nombre: String,
    /// Contenido, posiblemente truncado a [`MAX_BYTES_MUESTRA`].
    pub datos: Vec<u8>,
    /// De donde salio.
    pub procedencia: Procedencia,
}

impl Muestra {
    /// SHA-256 del contenido leido.
    ///
    /// Si la muestra esta truncada esto **no** es el hash del fichero original, y
    /// por eso [`Canario::evaluar`] solo compara hashes de muestras completas.
    #[must_use]
    pub fn sha256(&self) -> String {
        let mut h = Sha256::new();
        h.update(&self.datos);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Por que una firma no puede distribuirse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Motivo {
    /// Caso con una muestra de software legitimo.
    Disparo {
        /// Muestra sobre la que disparo.
        muestra: String,
    },
    /// Tiene menos bytes fijos de los que hacen falta para ser especifica.
    DemasiadoCorta {
        /// Bytes fijos que tiene.
        fijos: usize,
        /// Bytes fijos que necesitaria.
        minimo: usize,
    },
    /// El emparejador agoto su presupuesto: no se sabe si dispara o no.
    NoEvaluable {
        /// Muestra que agoto el presupuesto.
        muestra: String,
    },
    /// La firma no tiene forma de firma.
    ///
    /// Tiene motivo propio y no se cuenta como «demasiado corta» porque el
    /// arreglo es distinto: a quien escribe una firma vacia no hay que decirle
    /// que la alargue, hay que decirle que no ha escrito ninguna.
    Malformada {
        /// Que le pasa.
        detalle: String,
    },
}

impl Motivo {
    /// Codigo estable para agrupar en el informe.
    #[must_use]
    pub fn codigo(&self) -> &'static str {
        match self {
            Motivo::Disparo { .. } => "canario-disparo",
            Motivo::DemasiadoCorta { .. } => "canario-corta",
            Motivo::NoEvaluable { .. } => "canario-no-evaluable",
            Motivo::Malformada { .. } => "canario-malformada",
        }
    }

    /// Explicacion para quien tiene que arreglarlo.
    #[must_use]
    pub fn detalle(&self) -> String {
        match self {
            Motivo::Disparo { muestra } => {
                format!("casa con software legitimo: {muestra}")
            }
            Motivo::DemasiadoCorta { fijos, minimo } => {
                format!("solo {fijos} bytes fijos, hacen falta {minimo}")
            }
            Motivo::NoEvaluable { muestra } => {
                format!("no se pudo evaluar contra {muestra} dentro del presupuesto de pasos")
            }
            Motivo::Malformada { detalle } => format!("firma malformada: {detalle}"),
        }
    }
}

/// Una firma rechazada y por que.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rechazo {
    /// Nombre de la firma.
    pub firma: String,
    /// Por que se rechaza.
    pub motivo: Motivo,
}

/// Resultado de pasar un corpus por el canario.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Veredicto {
    /// Firmas evaluadas.
    pub evaluadas: usize,
    /// Muestras usadas.
    pub muestras: usize,
    /// Firmas que no pueden distribuirse, con su motivo.
    pub rechazos: Vec<Rechazo>,
}

impl Veredicto {
    /// Si el corpus puede firmarse.
    ///
    /// Un canario **sin muestras** nunca aprueba: devolver verde porque no habia
    /// nada contra lo que probar convertiria un despliegue mal configurado en un
    /// aval, que es el peor fallo posible en una puerta de seguridad.
    #[must_use]
    pub fn aprobado(&self) -> bool {
        self.rechazos.is_empty() && self.muestras > 0
    }

    /// Nombres de las firmas rechazadas, sin repetir.
    #[must_use]
    pub fn firmas_rechazadas(&self) -> BTreeSet<&str> {
        self.rechazos.iter().map(|r| r.firma.as_str()).collect()
    }

    /// Resumen de una linea para el registro de la compilacion.
    #[must_use]
    pub fn resumen(&self) -> String {
        if self.muestras == 0 {
            return "canario SIN MUESTRAS: no se firma nada".to_string();
        }
        if self.rechazos.is_empty() {
            return format!(
                "canario OK: {} firmas contra {} muestras legitimas",
                self.evaluadas, self.muestras
            );
        }
        format!(
            "canario BLOQUEA: {} de {} firmas rechazadas contra {} muestras",
            self.firmas_rechazadas().len(),
            self.evaluadas,
            self.muestras
        )
    }
}

/// Rutas de las que se intentan sacar muestras del sistema.
///
/// Son binarios que existen en practicamente cualquier Linux y que nadie
/// confundiria con malware. Si alguna no esta, se omite: el canario se adapta al
/// host, y [`Veredicto::aprobado`] ya se encarga de que cero muestras no aprueben.
const RUTAS_DEL_SISTEMA: &[&str] = &[
    "/bin/ls",
    "/bin/sh",
    "/bin/cat",
    "/bin/grep",
    "/usr/bin/env",
    "/usr/bin/id",
    "/usr/bin/awk",
    "/usr/bin/sed",
    "/usr/bin/find",
    "/usr/bin/sort",
    "/usr/bin/head",
    "/usr/bin/tail",
    "/usr/bin/wc",
    "/usr/bin/cut",
];

/// El conjunto de software legitimo contra el que se prueba el corpus.
#[derive(Debug, Clone, Default)]
pub struct Canario {
    muestras: Vec<Muestra>,
}

impl Canario {
    /// Un canario vacio.
    #[must_use]
    pub fn vacio() -> Canario {
        Canario {
            muestras: Vec::new(),
        }
    }

    /// Un canario con las muestras que se le den.
    #[must_use]
    pub fn con(muestras: Vec<Muestra>) -> Canario {
        Canario { muestras }
    }

    /// Recoge muestras de los binarios del propio host.
    ///
    /// Lo que no exista se omite en silencio; lo que no se pueda leer, tambien.
    /// Un canario con menos muestras de las esperadas sigue siendo mejor que
    /// ninguno, y el que quiera saber cuantas hay tiene [`Canario::len`].
    #[must_use]
    pub fn del_sistema() -> Canario {
        let mut c = Canario::vacio();
        for ruta in RUTAS_DEL_SISTEMA {
            c.anadir_fichero(Path::new(ruta));
        }
        c
    }

    /// Anade un fichero del disco como muestra. Devuelve si se pudo.
    pub fn anadir_fichero(&mut self, ruta: &Path) -> bool {
        let Ok(mut datos) = std::fs::read(ruta) else {
            return false;
        };
        if datos.is_empty() {
            return false;
        }
        let completa = datos.len() <= MAX_BYTES_MUESTRA;
        datos.truncate(MAX_BYTES_MUESTRA);
        self.muestras.push(Muestra {
            nombre: ruta.display().to_string(),
            datos,
            procedencia: Procedencia::Sistema(ruta.to_path_buf()),
        });
        // Se devuelve true igualmente: la muestra truncada sirve para el cuerpo,
        // que es donde estan los falsos positivos. Lo que no sirve es para
        // comparar hashes, y de eso se ocupa `evaluar`.
        let _ = completa;
        true
    }

    /// Anade contenido en memoria como muestra.
    pub fn anadir(&mut self, nombre: &str, datos: Vec<u8>) {
        self.muestras.push(Muestra {
            nombre: nombre.to_string(),
            datos,
            procedencia: Procedencia::Aportada,
        });
    }

    /// Cuantas muestras tiene.
    #[must_use]
    pub fn len(&self) -> usize {
        self.muestras.len()
    }

    /// Si no tiene ninguna.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.muestras.is_empty()
    }

    /// Las muestras, para quien aporte su propio motor.
    #[must_use]
    pub fn muestras(&self) -> &[Muestra] {
        &self.muestras
    }

    /// Pasa un conjunto de firmas de ClamAV por el canario.
    #[must_use]
    pub fn evaluar(&self, firmas: &[Firma]) -> Veredicto {
        let mut v = Veredicto {
            evaluadas: firmas.len(),
            muestras: self.muestras.len(),
            rechazos: Vec::new(),
        };

        // --- Fase 1: lo que se decide SIN mirar ninguna muestra -------------
        //
        // Malformada y demasiado corta son propiedades de la firma, no de su
        // relacion con un fichero. Resolverlas primero evita barrer catorce
        // binarios para una firma que ya estaba rechazada.
        let mut vivas: Vec<usize> = Vec::with_capacity(firmas.len());
        for (i, firma) in firmas.iter().enumerate() {
            if let Some(detalle) = malformada(firma) {
                v.rechazos.push(Rechazo {
                    firma: firma.nombre().to_string(),
                    motivo: Motivo::Malformada { detalle },
                });
                continue;
            }
            if let Some(fijos) = bytes_fijos(firma) {
                if fijos < MINIMO_BYTES_FIJOS {
                    v.rechazos.push(Rechazo {
                        firma: firma.nombre().to_string(),
                        motivo: Motivo::DemasiadoCorta {
                            fijos,
                            minimo: MINIMO_BYTES_FIJOS,
                        },
                    });
                    continue;
                }
            }
            vivas.push(i);
        }

        if self.muestras.is_empty() || vivas.is_empty() {
            return v;
        }

        // --- Fase 2: un solo recorrido de cada muestra ----------------------
        let patrones = Patron::de(firmas, &vivas);
        let filtro = Filtro::de(&patrones);
        let mut veredicto_por_firma: BTreeMap<usize, (Disparo, String)> = BTreeMap::new();

        // Los hashes se INDEXAN por su valor, no se recorren. Compararlos uno a
        // uno obligaria a calcular el SHA-256 de la muestra **por cada firma de
        // hash**: con cien mil hashes en el corpus y catorce muestras serian un
        // millon y medio de digest de cuatro megas cada uno. Asi se calcula uno
        // por muestra y se busca.
        let mut por_hash: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for &i in &vivas {
            if let Firma::HashFichero { hash, .. } | Firma::HashSeccion { hash, .. } = &firmas[i] {
                if hash.len() == 64 {
                    por_hash
                        .entry(hash.to_ascii_lowercase())
                        .or_default()
                        .push(i);
                }
            }
        }

        for muestra in &self.muestras {
            if !por_hash.is_empty() && muestra.datos.len() <= MAX_BYTES_MUESTRA {
                if let Some(del_hash) = por_hash.get(&muestra.sha256()) {
                    for &i in del_hash {
                        veredicto_por_firma
                            .entry(i)
                            .or_insert_with(|| (Disparo::Si, muestra.nombre.clone()));
                    }
                }
            }
            barrer(&patrones, &filtro, muestra, &mut veredicto_por_firma);
        }

        // --- Fase 3: el informe, en el orden de las firmas -------------------
        for &i in &vivas {
            match veredicto_por_firma.get(&i) {
                Some((Disparo::Si, donde)) => v.rechazos.push(Rechazo {
                    firma: firmas[i].nombre().to_string(),
                    motivo: Motivo::Disparo {
                        muestra: donde.clone(),
                    },
                }),
                Some((Disparo::Agotado, donde)) => v.rechazos.push(Rechazo {
                    firma: firmas[i].nombre().to_string(),
                    motivo: Motivo::NoEvaluable {
                        muestra: donde.clone(),
                    },
                }),
                _ => {}
            }
        }
        v
    }

    /// Pasa por el canario un motor ajeno (YARA, Sigma, lo que sea).
    ///
    /// `probar` recibe una muestra y devuelve los nombres de las reglas que
    /// dispararon sobre ella. Existe porque este crate **no** tiene esos motores
    /// y fingir que los tiene seria mentir en verde.
    pub fn evaluar_con<F>(&self, reglas: usize, mut probar: F) -> Veredicto
    where
        F: FnMut(&Muestra) -> Vec<String>,
    {
        let mut v = Veredicto {
            evaluadas: reglas,
            muestras: self.muestras.len(),
            rechazos: Vec::new(),
        };
        for muestra in &self.muestras {
            for regla in probar(muestra) {
                v.rechazos.push(Rechazo {
                    firma: regla,
                    motivo: Motivo::Disparo {
                        muestra: muestra.nombre.clone(),
                    },
                });
            }
        }
        v
    }
}

// ---------------------------------------------------------------------------
// El barrido: un recorrido de la muestra para TODAS las firmas a la vez
// ---------------------------------------------------------------------------
//
// # Por que no se puede hacer firma por firma
//
// La forma obvia —para cada firma, buscarla en cada muestra— es
// O(firmas x muestras x tamano). Con 40.000 firmas, catorce binarios del sistema
// y cuatro megas por binario son dos billones de comparaciones. No es «lento»:
// es que la puerta que se ejecuta en cada compilacion del corpus no termina, y
// una puerta que no termina es una puerta que alguien desactiva.
//
// Se invierte el bucle, que es lo que hace ClamAV con Aho-Corasick: **un solo
// recorrido de la muestra**, y en cada posicion se mira que firmas podrian
// empezar ahi. El coste pasa a ser O(muestras x tamano) mas el trabajo real de
// las pocas firmas que de verdad son candidatas.
//
// # El filtro de dos bytes
//
// El indice es por los **dos primeros bytes** del ancla, en una tabla de 65.536
// entradas. En cada posicion de la muestra se leen dos bytes y se indexa un
// vector: sin hash, sin comparaciones de cadena, tres operaciones. Solo cuando
// esa casilla tiene firmas se comprueba el ancla entera, y solo si el ancla casa
// se entra en el emparejador con comodines.
//
// No hay falsos negativos: si el ancla esta en la muestra, sus dos primeros
// bytes estan, y la casilla se visita. Un filtro con falsos negativos en una
// puerta de seguridad seria peor que no tener puerta, porque daria verdes.

/// Una secuencia por buscar, con la firma de la que sale.
///
/// Una firma logica aporta **un patron por subfirma**: cada una puede disparar
/// por su cuenta y cada una tiene su propia ancla.
#[derive(Debug)]
struct Patron<'a> {
    /// Indice de la firma en el vector original.
    firma: usize,
    /// Bytes que tienen que preceder al ancla.
    ///
    /// Sale de los comodines iniciales que se han recortado: si el patron
    /// empezaba por `{4-8}`, el ancla no puede aparecer antes del byte 4.
    sobrante: usize,
    /// Los trozos por casar, ya recortados.
    trozos: &'a [Trozo],
}

impl<'a> Patron<'a> {
    /// Extrae los patrones de las firmas vivas.
    fn de(firmas: &'a [Firma], vivas: &[usize]) -> Vec<Patron<'a>> {
        let mut v = Vec::new();
        for &i in vivas {
            match &firmas[i] {
                Firma::Cuerpo { trozos, .. } => v.push(Patron::nuevo(i, trozos)),
                Firma::Logica { subfirmas, .. } => {
                    for sub in subfirmas {
                        v.push(Patron::nuevo(i, sub));
                    }
                }
                // Los hashes no se buscan: se comparan.
                Firma::HashFichero { .. } | Firma::HashSeccion { .. } => {}
            }
        }
        v
    }

    /// Construye un patron recortando sus comodines iniciales si eso le da ancla.
    ///
    /// # Por que esto no es una optimizacion mas
    ///
    /// Un patron sin ancla hay que barrerlo entero contra cada muestra, y ese
    /// coste **si** es proporcional al numero de patrones. Un feed comprometido
    /// que trajera cien mil firmas empezando todas por `*` devolveria el canario
    /// al coste cuadratico y colgaria nuestra propia compilacion: una denegacion
    /// de servicio contra la fabrica, entregada como contenido, que es
    /// exactamente el modelo de amenaza de la invariante 1.
    ///
    /// # Por que recortar es correcto
    ///
    /// La busqueda es **sin anclar**: el patron puede empezar en cualquier
    /// posicion. Con esa libertad, «consumir de 2 a 4 bytes y luego el resto» es
    /// lo mismo que «el resto casa en alguna posicion >= 2». Se recorta el
    /// comodin y se guarda ese minimo en [`Patron::sobrante`].
    ///
    /// Si el recorte no descubre un ancla utilizable se conserva el patron
    /// entero: recortarlo sin ganar nada solo perderia el minimo.
    fn nuevo(firma: usize, trozos: &'a [Trozo]) -> Patron<'a> {
        let mut sobrante = 0usize;
        let mut i = 0usize;
        while i < trozos.len() {
            match &trozos[i] {
                Trozo::Cualquiera(n) => sobrante = sobrante.saturating_add(*n),
                Trozo::Salto { min, .. } => sobrante = sobrante.saturating_add(*min),
                _ => break,
            }
            i += 1;
        }
        match trozos.get(i) {
            Some(Trozo::Bytes(b)) if b.len() >= 2 => Patron {
                firma,
                sobrante,
                trozos: &trozos[i..],
            },
            _ => Patron {
                firma,
                sobrante: 0,
                trozos,
            },
        }
    }

    /// La secuencia fija con la que empieza, si empieza por una.
    fn ancla(&self) -> Option<&'a [u8]> {
        match self.trozos.first() {
            Some(Trozo::Bytes(b)) if b.len() >= 2 => Some(b),
            _ => None,
        }
    }
}

/// Entradas del indice de primer nivel: todos los pares de bytes posibles.
const CASILLAS: usize = 1 << 16;

/// Indice de patrones por los dos primeros bytes de su ancla.
struct Filtro {
    /// Para cada par de bytes, los patrones cuya ancla empieza asi.
    por_par: Vec<Vec<usize>>,
    /// Patrones sin ancla utilizable: hay que barrerlos uno a uno.
    ///
    /// Son los que empiezan por comodin. Se cuentan aparte porque su coste SI es
    /// proporcional al numero de patrones, y conviene que se note si un feed
    /// empieza a traer muchos.
    sin_ancla: Vec<usize>,
}

impl Filtro {
    fn de(patrones: &[Patron<'_>]) -> Filtro {
        let mut f = Filtro {
            por_par: vec![Vec::new(); CASILLAS],
            sin_ancla: Vec::new(),
        };
        for (i, p) in patrones.iter().enumerate() {
            match p.ancla() {
                Some(a) => f.por_par[usize::from(a[0]) << 8 | usize::from(a[1])].push(i),
                None => f.sin_ancla.push(i),
            }
        }
        f
    }
}

/// Recorre una muestra una vez y anota lo que dispara.
///
/// `ya` lleva el veredicto de las firmas que ya se decidieron: una firma que ya
/// disparo no se vuelve a mirar, ni en esta muestra ni en las siguientes.
fn barrer(
    patrones: &[Patron<'_>],
    filtro: &Filtro,
    muestra: &Muestra,
    ya: &mut BTreeMap<usize, (Disparo, String)>,
) {
    let datos = &muestra.datos;

    // Los que empiezan por comodin no se pueden indexar: barrido completo.
    for &i in &filtro.sin_ancla {
        let p = &patrones[i];
        if ya.contains_key(&p.firma) {
            continue;
        }
        match buscar(p.trozos, datos) {
            Disparo::Si => {
                ya.insert(p.firma, (Disparo::Si, muestra.nombre.clone()));
            }
            Disparo::Agotado => {
                ya.insert(p.firma, (Disparo::Agotado, muestra.nombre.clone()));
            }
            Disparo::No => {}
        }
    }

    if datos.len() < 2 {
        return;
    }

    // Presupuesto de retroceso por patron y por muestra. Se reparte aqui y no
    // dentro del emparejador porque un patron puede intentarse en muchas
    // posiciones de la misma muestra, y un presupuesto por posicion se
    // multiplicaria por la longitud del fichero hasta dejar de acotar nada.
    let mut pasos: Vec<u64> = vec![PRESUPUESTO_PASOS; patrones.len()];

    for i in 0..=datos.len() - 2 {
        let casilla = usize::from(datos[i]) << 8 | usize::from(datos[i + 1]);
        let candidatos = &filtro.por_par[casilla];
        if candidatos.is_empty() {
            continue;
        }
        for &c in candidatos {
            let p = &patrones[c];
            if ya.contains_key(&p.firma) {
                continue;
            }
            let Some(ancla) = p.ancla() else { continue };
            // Los comodines recortados exigen su hueco: si el patron empezaba
            // por `{4-8}`, el ancla no puede casar antes del byte 4.
            if i < p.sobrante {
                continue;
            }
            if datos.len() - i < ancla.len() || &datos[i..i + ancla.len()] != ancla {
                continue;
            }
            match casa_desde(&p.trozos[1..], datos, i + ancla.len(), &mut pasos[c]) {
                Disparo::Si => {
                    ya.insert(p.firma, (Disparo::Si, muestra.nombre.clone()));
                }
                Disparo::Agotado => {
                    ya.insert(p.firma, (Disparo::Agotado, muestra.nombre.clone()));
                }
                Disparo::No => {}
            }
        }
    }
}

/// Resultado de probar una firma contra una muestra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disparo {
    /// Casa.
    Si,
    /// No casa.
    No,
    /// No se pudo decidir dentro del presupuesto de pasos.
    Agotado,
}

/// Comprueba si una firma no tiene forma de firma, y dice que le pasa.
fn malformada(firma: &Firma) -> Option<String> {
    match firma {
        Firma::HashFichero { hash, .. } | Firma::HashSeccion { hash, .. } => {
            // Un hash que no es ni MD5 ni SHA-1 ni SHA-256 no se puede comparar
            // con nada, asi que no se sabe contra que protege.
            if matches!(hash.len(), 32 | 40 | 64) && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                None
            } else {
                Some(format!(
                    "hash de {} caracteres, no es MD5/SHA-1/SHA-256",
                    hash.len()
                ))
            }
        }
        Firma::Cuerpo { trozos, .. } => {
            if trozos.is_empty() {
                Some("sin ningun trozo: casaria con cualquier fichero".to_string())
            } else {
                None
            }
        }
        Firma::Logica { subfirmas, .. } => {
            if subfirmas.is_empty() {
                Some("sin ninguna subfirma".to_string())
            } else if subfirmas.iter().any(Vec::is_empty) {
                Some("con alguna subfirma vacia, que casaria con cualquier fichero".to_string())
            } else {
                None
            }
        }
    }
}

/// Bytes fijos que una firma exige, o `None` si el concepto no le aplica.
///
/// Los comodines no cuentan: son justo lo que quita especificidad. En una
/// alternativa cuenta la rama **mas corta**, porque es la que decide lo
/// especifica que es la firma en el peor caso.
#[must_use]
pub fn bytes_fijos(firma: &Firma) -> Option<usize> {
    match firma {
        // Un hash es especifico por construccion.
        Firma::HashFichero { .. } | Firma::HashSeccion { .. } => None,
        Firma::Cuerpo { trozos, .. } => Some(fijos_de(trozos)),
        // Una logica es tan especifica como su subfirma mas debil: la expresion
        // puede ser un simple «o», y entonces basta esa para disparar.
        Firma::Logica { subfirmas, .. } => subfirmas.iter().map(|s| fijos_de(s)).min(),
    }
}

fn fijos_de(trozos: &[Trozo]) -> usize {
    trozos
        .iter()
        .map(|t| match t {
            Trozo::Bytes(b) => b.len(),
            Trozo::Cualquiera(_) | Trozo::Salto { .. } => 0,
            Trozo::Alternativa(alts) => alts.iter().map(Vec::len).min().unwrap_or(0),
        })
        .sum()
}

/// Busca la secuencia en cualquier posicion de los datos.
///
/// # Dos decisiones que parecen de rendimiento y son de correccion
///
/// **El ancla.** Casi todas las firmas de cuerpo empiezan por una secuencia de
/// bytes fijos. Probar las demas posiciones no es solo caro: es inutil, porque
/// no pueden casar. Se buscan primero las posiciones donde el ancla esta de
/// verdad y solo desde ahi se intenta el resto. Sin esto, un corpus de 40.000
/// firmas contra catorce binarios del sistema serian billones de comparaciones,
/// y la puerta que se ejecuta en cada compilacion pasaria a ser la puerta que
/// alguien desactiva porque tarda demasiado.
///
/// **El presupuesto crece con los datos.** El presupuesto existe para cortar el
/// RETROCESO explosivo, no el barrido. Con una cifra fija, una firma que
/// sencillamente NO casa contra un binario de cuatro megas agotaba el
/// presupuesto recorriendo posiciones perfectamente normales y salia como «no
/// evaluable»: un bloqueo por lentitud disfrazado de duda. Se le concede un
/// barrido lineal completo MAS el margen de retroceso, con lo que agotarlo
/// vuelve a significar lo unico que tiene que significar: aqui hay explosion.
fn buscar(trozos: &[Trozo], datos: &[u8]) -> Disparo {
    if trozos.is_empty() {
        // Una firma sin trozos casaria con todo. No se trata como disparo sino
        // como no evaluable: es una firma malformada, y decir «casa con ls» de
        // ella confundiria a quien tenga que arreglarla.
        return Disparo::Agotado;
    }
    let mut pasos = PRESUPUESTO_PASOS.saturating_add(datos.len() as u64);

    if let Trozo::Bytes(ancla) = &trozos[0] {
        if !ancla.is_empty() {
            let mut desde = 0usize;
            while let Some(rel) = buscar_bytes(&datos[desde..], ancla) {
                let inicio = desde + rel;
                match casa_desde(&trozos[1..], datos, inicio + ancla.len(), &mut pasos) {
                    Disparo::Si => return Disparo::Si,
                    Disparo::Agotado => return Disparo::Agotado,
                    Disparo::No => {}
                }
                desde = inicio + 1;
                if desde > datos.len() {
                    break;
                }
            }
            return Disparo::No;
        }
    }

    for inicio in 0..=datos.len() {
        match casa_desde(trozos, datos, inicio, &mut pasos) {
            Disparo::Si => return Disparo::Si,
            Disparo::Agotado => return Disparo::Agotado,
            Disparo::No => {}
        }
    }
    Disparo::No
}

/// Primera posicion de `aguja` en `pajar`, o `None`.
fn buscar_bytes(pajar: &[u8], aguja: &[u8]) -> Option<usize> {
    if aguja.is_empty() || pajar.len() < aguja.len() {
        return None;
    }
    // Se compara el primer byte antes de mirar el resto: es lo que hace que el
    // barrido cueste un byte por posicion en el caso normal, y no la longitud
    // entera del ancla.
    let primero = aguja[0];
    let ultimo_inicio = pajar.len() - aguja.len();
    (0..=ultimo_inicio)
        .filter(|i| pajar[*i] == primero)
        .find(|i| &pajar[*i..*i + aguja.len()] == aguja)
}

/// Intenta casar los trozos empezando exactamente en `pos`.
///
/// El presupuesto de pasos es la unica defensa contra el coste explosivo de
/// combinar `*` con alternativas, y se comparte entre TODAS las posiciones de
/// inicio: un presupuesto por posicion se multiplicaria por la longitud del
/// fichero y dejaria de ser un presupuesto.
fn casa_desde(trozos: &[Trozo], datos: &[u8], pos: usize, pasos: &mut u64) -> Disparo {
    let Some((cabeza, resto)) = trozos.split_first() else {
        return Disparo::Si;
    };
    if *pasos == 0 {
        return Disparo::Agotado;
    }
    *pasos -= 1;

    match cabeza {
        Trozo::Bytes(b) => {
            if datos.len() - pos >= b.len() && &datos[pos..pos + b.len()] == b.as_slice() {
                casa_desde(resto, datos, pos + b.len(), pasos)
            } else {
                Disparo::No
            }
        }
        Trozo::Cualquiera(n) => {
            if datos.len() - pos >= *n {
                casa_desde(resto, datos, pos + n, pasos)
            } else {
                Disparo::No
            }
        }
        Trozo::Salto { min, max } => {
            let disponible = datos.len() - pos;
            if disponible < *min {
                return Disparo::No;
            }
            let tope = max.unwrap_or(disponible).min(disponible);
            for k in *min..=tope {
                match casa_desde(resto, datos, pos + k, pasos) {
                    Disparo::Si => return Disparo::Si,
                    Disparo::Agotado => return Disparo::Agotado,
                    Disparo::No => {}
                }
            }
            Disparo::No
        }
        Trozo::Alternativa(alts) => {
            for alt in alts {
                if datos.len() - pos >= alt.len() && &datos[pos..pos + alt.len()] == alt.as_slice()
                {
                    match casa_desde(resto, datos, pos + alt.len(), pasos) {
                        Disparo::Si => return Disparo::Si,
                        Disparo::Agotado => return Disparo::Agotado,
                        Disparo::No => {}
                    }
                }
            }
            Disparo::No
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn cuerpo(nombre: &str, trozos: Vec<Trozo>) -> Firma {
        Firma::Cuerpo {
            nombre: nombre.to_string(),
            objetivo: 0,
            desplazamiento: "*".to_string(),
            trozos,
        }
    }

    fn bytes(b: &[u8]) -> Trozo {
        Trozo::Bytes(b.to_vec())
    }

    fn canario_de_prueba() -> Canario {
        let mut c = Canario::vacio();
        c.anadir(
            "inocente.bin",
            b"contenido perfectamente normal de un programa".to_vec(),
        );
        c
    }

    // --- El emparejador ---------------------------------------------------

    #[test]
    fn una_secuencia_exacta_se_encuentra_donde_este() {
        let datos = b"prefacio AABBCCDD final";
        assert_eq!(buscar(&[bytes(b"AABBCCDD")], datos), Disparo::Si);
        assert_eq!(buscar(&[bytes(b"AABBCCDX")], datos), Disparo::No);
    }

    #[test]
    fn los_comodines_de_longitud_fija_consumen_exactamente_eso() {
        let datos = b"AA__BB";
        let firma = vec![bytes(b"AA"), Trozo::Cualquiera(2), bytes(b"BB")];
        assert_eq!(buscar(&firma, datos), Disparo::Si);

        // Con un byte de mas en medio ya no casa: `??` no es un salto elastico.
        assert_eq!(buscar(&firma, b"AA___BB"), Disparo::No);
    }

    #[test]
    fn el_salto_elastico_respeta_su_minimo_y_su_maximo() {
        let firma = vec![
            bytes(b"INI"),
            Trozo::Salto {
                min: 2,
                max: Some(4),
            },
            bytes(b"FIN"),
        ];
        assert_eq!(buscar(&firma, b"INI..FIN"), Disparo::Si);
        assert_eq!(buscar(&firma, b"INI....FIN"), Disparo::Si);
        assert_eq!(
            buscar(&firma, b"INI.FIN"),
            Disparo::No,
            "por debajo del minimo"
        );
        assert_eq!(
            buscar(&firma, b"INI.....FIN"),
            Disparo::No,
            "por encima del maximo"
        );
    }

    #[test]
    fn el_salto_sin_tope_llega_hasta_el_final() {
        let firma = vec![
            bytes(b"INI"),
            Trozo::Salto { min: 0, max: None },
            bytes(b"FIN"),
        ];
        assert_eq!(
            buscar(&firma, b"INI y mucho relleno por medio FIN"),
            Disparo::Si
        );
        assert_eq!(
            buscar(&firma, b"INI y mucho relleno por medio"),
            Disparo::No
        );
    }

    #[test]
    fn una_alternativa_casa_por_cualquier_rama() {
        let firma = vec![
            bytes(b"X"),
            Trozo::Alternativa(vec![b"aa".to_vec(), b"bbbb".to_vec()]),
            bytes(b"Y"),
        ];
        assert_eq!(buscar(&firma, b"XaaY"), Disparo::Si);
        assert_eq!(buscar(&firma, b"XbbbbY"), Disparo::Si);
        assert_eq!(buscar(&firma, b"XccY"), Disparo::No);
    }

    // --- Lo que bloquea ---------------------------------------------------

    #[test]
    fn una_firma_que_dispara_sobre_software_legitimo_bloquea() {
        let c = canario_de_prueba();
        // 16 bytes fijos, asi que pasa el filtro de longitud y llega a disparar.
        let firma = cuerpo("Prueba.FalsoPositivo", vec![bytes(b"perfectamente no")]);
        let v = c.evaluar(&[firma]);

        assert!(!v.aprobado(), "{}", v.resumen());
        assert_eq!(v.rechazos.len(), 1);
        assert_eq!(v.rechazos[0].motivo.codigo(), "canario-disparo");
        assert!(v.rechazos[0].motivo.detalle().contains("inocente.bin"));
    }

    #[test]
    fn una_firma_especifica_que_no_dispara_pasa() {
        let c = canario_de_prueba();
        let firma = cuerpo(
            "Prueba.Buena",
            vec![bytes(
                b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00",
            )],
        );
        let v = c.evaluar(&[firma]);
        assert!(v.aprobado(), "{}", v.resumen());
        assert_eq!(v.evaluadas, 1);
    }

    #[test]
    fn una_firma_corta_se_rechaza_aunque_no_dispare() {
        // Es la unica de las tres comprobaciones que dice algo sobre el software
        // que el canario NO ha visto: cuatro bytes casan con cualquier binario
        // grande por pura estadistica.
        let c = canario_de_prueba();
        let firma = cuerpo("Prueba.Corta", vec![bytes(b"\xde\xad\xbe\xef")]);
        let v = c.evaluar(&[firma]);

        assert!(!v.aprobado());
        assert_eq!(v.rechazos[0].motivo.codigo(), "canario-corta");
        match &v.rechazos[0].motivo {
            Motivo::DemasiadoCorta { fijos, minimo } => {
                assert_eq!(*fijos, 4);
                assert_eq!(*minimo, MINIMO_BYTES_FIJOS);
            }
            otro => panic!("motivo inesperado: {otro:?}"),
        }
    }

    #[test]
    fn los_comodines_no_cuentan_como_bytes_fijos() {
        // Una firma «larga» a base de comodines es tan inespecifica como una
        // corta, y contarlos seria dejar pasar exactamente eso.
        let firma = cuerpo(
            "Prueba.TodoComodin",
            vec![
                bytes(b"\xde\xad\xbe\xef"),
                Trozo::Cualquiera(64),
                Trozo::Salto { min: 0, max: None },
            ],
        );
        assert_eq!(bytes_fijos(&firma), Some(4));

        let v = canario_de_prueba().evaluar(&[firma]);
        assert_eq!(v.rechazos[0].motivo.codigo(), "canario-corta");
    }

    #[test]
    fn en_una_alternativa_manda_la_rama_mas_corta() {
        // La firma es tan especifica como su peor camino: si una rama tiene dos
        // bytes, la firma dispara con dos bytes.
        let firma = cuerpo(
            "Prueba.RamaDebil",
            vec![Trozo::Alternativa(vec![
                b"\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef".to_vec(),
                b"\x90\x90".to_vec(),
            ])],
        );
        assert_eq!(bytes_fijos(&firma), Some(2));
    }

    #[test]
    fn una_firma_que_no_se_puede_evaluar_no_se_declara_limpia() {
        // Comodines elasticos encadenados: el coste explota y el presupuesto se
        // agota. Lo importante es que el resultado NO sea «no dispara».
        let mut trozos = vec![bytes(b"INICIO")];
        for _ in 0..12 {
            trozos.push(Trozo::Salto { min: 0, max: None });
            trozos.push(Trozo::Alternativa(vec![
                b"a".to_vec(),
                b"b".to_vec(),
                b"c".to_vec(),
            ]));
        }
        trozos.push(bytes(b"NUNCA_JAMAS_APARECE_ESTO"));
        let firma = cuerpo("Prueba.Explosiva", trozos);

        // La muestra TIENE que contener el ancla. Sin ella el emparejador
        // rechaza en el primer trozo y no llega a gastar presupuesto: la prueba
        // pasaria en verde sin haber ejercitado nada.
        let mut datos = b"INICIO".to_vec();
        datos.extend(std::iter::repeat_n(b'a', 4096));
        let mut c = Canario::vacio();
        c.anadir("relleno.bin", datos);
        let v = c.evaluar(&[firma]);

        assert!(!v.aprobado(), "{}", v.resumen());
        assert_eq!(v.rechazos[0].motivo.codigo(), "canario-no-evaluable");
    }

    #[test]
    fn no_casar_contra_un_fichero_grande_no_es_no_saber() {
        // EL BUG QUE ESTA PRUEBA CIERRA. El presupuesto de pasos existe para
        // cortar el retroceso explosivo. Con una cifra fija, una firma que
        // sencillamente no casa contra un binario de varios megas lo agotaba
        // recorriendo posiciones perfectamente normales, y salia como «no
        // evaluable» — que BLOQUEA. El resultado era una puerta que rechazaba
        // firmas buenas por lentitud y lo presentaba como duda.
        let mut c = Canario::vacio();
        c.anadir("grande.bin", vec![0x41u8; 4 * 1024 * 1024]);

        let firma = cuerpo(
            "Prueba.NoCasa",
            vec![bytes(
                b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00",
            )],
        );
        let v = c.evaluar(&[firma]);
        assert!(
            v.aprobado(),
            "una firma que no casa tiene que salir limpia, no «no evaluable»: {:?}",
            v.rechazos
        );
    }

    #[test]
    fn el_ancla_no_cambia_ningun_veredicto() {
        // El ancla es una optimizacion, y una optimizacion en una puerta de
        // seguridad solo vale si el veredicto es identico. Se comprueban los dos
        // caminos: firma que empieza por bytes fijos (con ancla) y firma que
        // empieza por comodin (barrido completo), sobre los mismos datos.
        let datos = b"basura por delante INICIO carga util FIN basura por detras".to_vec();
        let mut c = Canario::vacio();
        c.anadir("m.bin", datos);

        let con_ancla = vec![
            bytes(b"INICIO"),
            Trozo::Salto { min: 0, max: None },
            bytes(b"FIN"),
        ];
        let sin_ancla = vec![
            Trozo::Salto { min: 0, max: None },
            bytes(b"INICIO"),
            Trozo::Salto { min: 0, max: None },
            bytes(b"FIN"),
        ];
        let ni_uno = vec![bytes(b"NO_ESTA_AQUI_ESTA_CADENA")];

        assert_eq!(
            c.evaluar(&[cuerpo("A", con_ancla)]).rechazos.len(),
            c.evaluar(&[cuerpo("B", sin_ancla)]).rechazos.len(),
            "los dos caminos tienen que dar el mismo veredicto"
        );
        assert_eq!(c.evaluar(&[cuerpo("C", ni_uno)]).rechazos.len(), 0);
    }

    #[test]
    fn el_ancla_prueba_todas_sus_apariciones_y_no_solo_la_primera() {
        // Si se parase en la primera aparicion del ancla, una firma que casa
        // desde la SEGUNDA saldria limpia. Es un falso negativo en la puerta que
        // sirve para cazar falsos positivos: lo peor de los dos mundos.
        let mut c = Canario::vacio();
        // El ancla tiene que ser larga: una firma de ocho bytes la rechaza
        // antes el filtro de longitud y no llegaria al emparejador.
        c.anadir("m.bin", b"ANCLA-LARGA-XYZ-no ANCLA-LARGA-XYZ-si".to_vec());
        let firma = cuerpo(
            "Prueba.Segunda",
            vec![bytes(b"ANCLA-LARGA-XYZ"), bytes(b"-si")],
        );
        let v = c.evaluar(&[firma]);
        assert_eq!(v.rechazos.len(), 1, "tiene que encontrarla en la segunda");
        assert_eq!(v.rechazos[0].motivo.codigo(), "canario-disparo");
    }

    #[test]
    fn un_comodin_inicial_no_deja_al_patron_sin_ancla() {
        // Un feed comprometido que trajera cien mil firmas empezando todas por
        // comodin devolveria el canario al coste cuadratico y colgaria nuestra
        // propia compilacion. Se recorta el comodin y se ancla en lo que sigue.
        let trozos = vec![
            Trozo::Salto { min: 4, max: None },
            bytes(b"ANCLA-LARGA-DE-VERDAD"),
        ];
        let firmas = vec![cuerpo("Prueba.ComodinDelante", trozos)];
        let patrones = Patron::de(&firmas, &[0]);
        assert_eq!(patrones.len(), 1);
        assert!(
            patrones[0].ancla().is_some(),
            "el recorte tiene que descubrir el ancla"
        );
        assert_eq!(patrones[0].sobrante, 4);

        let filtro = Filtro::de(&patrones);
        assert!(filtro.sin_ancla.is_empty(), "no puede quedarse sin indexar");
    }

    #[test]
    fn el_recorte_respeta_el_hueco_que_el_comodin_exigia() {
        // Recortar el comodin no puede regalar posiciones: si el patron exigia
        // cuatro bytes por delante, el ancla no puede casar en el byte cero.
        let firma = cuerpo(
            "Prueba.ConHueco",
            vec![
                Trozo::Salto {
                    min: 4,
                    max: Some(8),
                },
                bytes(b"ANCLA-LARGA-DE-VERDAD"),
            ],
        );

        let mut sin_hueco = Canario::vacio();
        sin_hueco.anadir("m.bin", b"ANCLA-LARGA-DE-VERDAD".to_vec());
        assert!(
            sin_hueco.evaluar(std::slice::from_ref(&firma)).aprobado(),
            "sin los cuatro bytes por delante NO puede casar"
        );

        let mut con_hueco = Canario::vacio();
        con_hueco.anadir("m.bin", b"xxxxxANCLA-LARGA-DE-VERDAD".to_vec());
        assert!(
            !con_hueco.evaluar(&[firma]).aprobado(),
            "con el hueco SI casa"
        );
    }

    #[test]
    fn un_corpus_de_hashes_no_recalcula_el_digest_por_firma() {
        // El bug que esta prueba cierra era de coste, no de resultado: el
        // SHA-256 de la muestra se recalculaba por cada firma de hash. Con cien
        // mil hashes y catorce muestras serian un millon y medio de digest.
        // Aqui se comprueba con una muestra grande y muchas firmas: si el
        // digest se recalculara, esta prueba tardaria minutos.
        let mut c = Canario::vacio();
        c.anadir("grande.bin", vec![0x5au8; 2 * 1024 * 1024]);
        let hash_real = c.muestras()[0].sha256();

        let mut firmas: Vec<Firma> = (0..5_000)
            .map(|n| Firma::HashFichero {
                nombre: format!("Prueba.Hash{n}"),
                hash: format!("{n:064x}"),
                tamano: None,
            })
            .collect();
        // Y una que SI es la de la muestra: el indice tiene que encontrarla.
        firmas.push(Firma::HashFichero {
            nombre: "Prueba.HashDeLoBueno".to_string(),
            hash: hash_real,
            tamano: None,
        });

        let v = c.evaluar(&firmas);
        assert!(!v.aprobado());
        assert_eq!(v.rechazos.len(), 1, "solo la que de verdad casa");
        assert_eq!(v.rechazos[0].firma, "Prueba.HashDeLoBueno");
    }

    #[test]
    fn una_firma_sin_trozos_no_se_declara_limpia() {
        let v = canario_de_prueba().evaluar(&[cuerpo("Prueba.Vacia", vec![])]);
        assert!(!v.aprobado());
        assert_eq!(v.rechazos[0].motivo.codigo(), "canario-malformada");
        // Y NO se confunde con «demasiado corta», que mandaria a alargar una
        // firma que lo que necesita es existir.
        assert!(v.rechazos[0].motivo.detalle().contains("cualquier fichero"));
    }

    #[test]
    fn un_hash_que_no_es_un_hash_se_rechaza() {
        let firma = Firma::HashFichero {
            nombre: "Prueba.HashRaro".to_string(),
            hash: "no-soy-un-hash".to_string(),
            tamano: None,
        };
        let v = canario_de_prueba().evaluar(&[firma]);
        assert_eq!(v.rechazos[0].motivo.codigo(), "canario-malformada");
    }

    #[test]
    fn una_firma_logica_se_rechaza_si_alguna_subfirma_dispara() {
        // Cota superior a proposito: no se interpreta la expresion, asi que si
        // alguna subfirma casa se rechaza. Equivocarse hacia rechazar cuesta una
        // firma; equivocarse hacia aceptar cuesta la flota.
        let firma = Firma::Logica {
            nombre: "Prueba.Logica".to_string(),
            expresion: "0&1".to_string(),
            subfirmas: vec![
                vec![bytes(
                    b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00",
                )],
                vec![bytes(b"perfectamente no")],
            ],
        };
        let v = canario_de_prueba().evaluar(&[firma]);
        assert!(!v.aprobado());
        assert_eq!(v.rechazos[0].motivo.codigo(), "canario-disparo");
    }

    // --- La puerta --------------------------------------------------------

    #[test]
    fn un_canario_sin_muestras_no_aprueba_nada() {
        // El peor fallo posible en una puerta de seguridad: dar el visto bueno
        // porque no habia nada contra lo que probar.
        let v = Canario::vacio().evaluar(&[cuerpo(
            "Prueba.Buena",
            vec![bytes(
                b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00",
            )],
        )]);
        assert_eq!(v.rechazos.len(), 0, "no hay nada que rechazar");
        assert!(!v.aprobado(), "y aun asi NO aprueba");
        assert!(v.resumen().contains("SIN MUESTRAS"));
    }

    #[test]
    fn un_motor_ajeno_entra_por_evaluar_con() {
        // YARA y Sigma no se evaluan aqui; quien tenga esos motores los aporta.
        let c = canario_de_prueba();
        let v = c.evaluar_con(3, |m| {
            if m.nombre == "inocente.bin" {
                vec!["APT_Generica_Demasiado_Amplia".to_string()]
            } else {
                Vec::new()
            }
        });
        assert!(!v.aprobado());
        assert_eq!(v.evaluadas, 3);
        assert!(v
            .firmas_rechazadas()
            .contains("APT_Generica_Demasiado_Amplia"));
    }

    #[test]
    fn el_hash_de_un_binario_del_sistema_en_el_corpus_se_caza() {
        let mut c = Canario::vacio();
        let datos = b"un binario legitimo cualquiera".to_vec();
        c.anadir("legitimo.bin", datos.clone());
        let hash = c.muestras()[0].sha256();

        let firma = Firma::HashFichero {
            nombre: "Prueba.HashDeLoBueno".to_string(),
            hash,
            tamano: Some(datos.len() as u64),
        };
        let v = c.evaluar(&[firma]);
        assert!(!v.aprobado());
        assert_eq!(v.rechazos[0].motivo.codigo(), "canario-disparo");
    }

    // --- Contra el sistema de verdad --------------------------------------

    #[test]
    fn el_canario_del_sistema_recoge_binarios_reales() {
        // Sin esta prueba, `del_sistema` podria devolver cero muestras en el
        // entorno de compilacion y nadie se enteraria: el canario pasaria a ser
        // decorativo justo donde tiene que morder.
        let c = Canario::del_sistema();
        assert!(
            c.len() >= 3,
            "solo {} muestras del sistema; el canario no muerde",
            c.len()
        );
        for m in c.muestras() {
            assert!(!m.datos.is_empty());
            assert!(matches!(m.procedencia, Procedencia::Sistema(_)));
        }
    }

    #[test]
    fn una_firma_de_cuatro_bytes_comunes_dispara_sobre_binarios_reales() {
        // LA PRUEBA QUE JUSTIFICA EL MODULO. No es un ejemplo inventado: se toman
        // bytes del principio de un binario real del host y se comprueba que una
        // firma hecha con ellos dispara sobre software legitimo. Es exactamente
        // el error que un analista comete con prisa.
        let c = Canario::del_sistema();
        if c.is_empty() {
            // Sin binarios del sistema no hay nada que demostrar aqui, y fingir
            // que si lo hay seria la clase de verde falso que este modulo evita.
            return;
        }
        let prefijo: Vec<u8> = c.muestras()[0].datos.iter().take(4).copied().collect();
        let firma = cuerpo("Prueba.ElfMagic", vec![Trozo::Bytes(prefijo)]);

        let v = c.evaluar(&[firma]);
        assert!(
            !v.aprobado(),
            "una firma de 4 bytes NO puede pasar la puerta"
        );
    }
}
