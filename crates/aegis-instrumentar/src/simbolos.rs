//! Donde esta una funcion, por tres vias y en el orden que importa.
//!
//! # El problema
//!
//! Un enganche necesita una direccion. El nombre de la funcion no basta: hace
//! falta el desplazamiento dentro del binario, y ese dato no siempre esta.
//!
//! Las tres vias, de mas fiable a menos:
//!
//! 1. **La tabla de simbolos.** Si el binario la trae, dice exactamente donde
//!    empieza cada funcion. Es un hecho, no una deduccion.
//! 2. **La informacion de depuracion.** Cuando la hay, ademas de la direccion
//!    trae los tipos de los argumentos, que es lo que permite extraerlos con
//!    sentido en vez de volcar registros.
//! 3. **La firma de bytes.** Cuando no hay ni lo uno ni lo otro —que es el caso
//!    de casi todo lo que se distribuye sin simbolos— se busca el prologo
//!    conocido de la funcion. Es una deduccion y **se declara como tal**.
//!
//! # Por que el orden no es negociable
//!
//! Porque las tres pueden discrepar, y cuando lo hacen la que gana tiene que ser
//! la mas fiable, no la ultima que se probo. Una firma de bytes que coincida por
//! casualidad en un binario que ademas tiene simbolos produciria un enganche en
//! mitad de otra funcion: el proceso observado se cae, y la culpa parece del
//! proceso.
//!
//! # Lo que este modulo NO hace
//!
//! No lee DWARF. Es un formato grande y hacerlo a medias produce direcciones
//! plausibles y equivocadas; el sitio donde se hace bien es un crate propio con
//! su propia justificacion de dependencia. Aqui queda **declarado** como via
//! reconocida y no resuelta: [`Via::InformacionDeDepuracion`] existe en el
//! modelo, y [`resolver`] no la produce todavia. Es la diferencia entre un hueco
//! declarado y un hueco escondido.

use std::collections::BTreeMap;

/// Por que via se supo donde esta una funcion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Via {
    /// De la tabla de simbolos del binario. Es un hecho.
    TablaDeSimbolos,
    /// De la informacion de depuracion. Trae ademas los tipos.
    InformacionDeDepuracion,
    /// De reconocer el prologo de la funcion por sus bytes. Es una deduccion.
    FirmaDeBytes,
}

impl Via {
    /// Si lo que da esta via es un hecho o una deduccion.
    ///
    /// La distincion importa para el informe: un enganche puesto por deduccion
    /// puede estar en el sitio equivocado, y quien lea la traza tiene que poder
    /// saberlo.
    pub fn es_un_hecho(&self) -> bool {
        matches!(self, Via::TablaDeSimbolos | Via::InformacionDeDepuracion)
    }

    /// Como se lee en un informe.
    pub fn frase(&self) -> &'static str {
        match self {
            Via::TablaDeSimbolos => {
                "de la tabla de simbolos del binario, que dice exactamente donde empieza \
                 la funcion"
            }
            Via::InformacionDeDepuracion => {
                "de la informacion de depuracion, que ademas trae los tipos de los \
                 argumentos"
            }
            Via::FirmaDeBytes => {
                "de reconocer el prologo de la funcion por sus bytes, porque el binario \
                 no trae simbolos: es una DEDUCCION y puede estar equivocada"
            }
        }
    }
}

/// Donde esta una funcion, y como se supo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Simbolo {
    /// Como se llama.
    pub nombre: String,
    /// Su desplazamiento dentro del binario.
    pub desplazamiento: u64,
    /// Por que via se supo.
    pub via: Via,
}

impl Simbolo {
    /// La frase con la que este simbolo aparece en un informe.
    pub fn frase(&self) -> String {
        format!(
            "{} en {:#x}, {}",
            self.nombre,
            self.desplazamiento,
            self.via.frase()
        )
    }
}

/// Una firma de bytes que reconoce el principio de una funcion.
#[derive(Debug, Clone)]
pub struct Firma {
    /// A que funcion corresponde.
    pub nombre: &'static str,
    /// Los bytes que la reconocen.
    ///
    /// Un `None` es un comodin: la posicion puede valer lo que sea. Hace falta
    /// porque los prologos reales llevan desplazamientos que cambian entre
    /// compilaciones, y una firma sin comodines solo reconoce el binario exacto
    /// sobre el que se escribio.
    pub patron: &'static [Option<u8>],
    /// Por que estos bytes reconocen esa funcion y no otra.
    pub porque: &'static str,
}

impl Firma {
    /// Cuantos bytes concretos —no comodines— tiene la firma.
    ///
    /// Es la medida de lo especifica que es: una firma de tres bytes concretos
    /// coincide por casualidad cada dieciseis millones, que en un binario grande
    /// es varias veces.
    pub fn bytes_concretos(&self) -> usize {
        self.patron.iter().filter(|b| b.is_some()).count()
    }

    /// Busca la firma en unos bytes y devuelve donde empieza.
    ///
    /// Devuelve **la primera** coincidencia y solo si es **unica**: dos
    /// coincidencias significan que la firma no distingue, y elegir una de las
    /// dos seria poner el enganche a cara o cruz.
    pub fn buscar(&self, bytes: &[u8]) -> Option<u64> {
        if self.patron.is_empty() || bytes.len() < self.patron.len() {
            return None;
        }
        let mut encontrada = None;
        for i in 0..=(bytes.len() - self.patron.len()) {
            let coincide = self
                .patron
                .iter()
                .enumerate()
                .all(|(n, p)| p.is_none_or(|b| bytes[i + n] == b));
            if coincide {
                if encontrada.is_some() {
                    // Dos coincidencias: la firma no distingue.
                    return None;
                }
                encontrada = Some(i as u64);
            }
        }
        encontrada
    }
}

/// Cuantos bytes concretos necesita una firma para ser aceptable.
///
/// Con menos, la probabilidad de coincidir por casualidad en un binario de un
/// megabyte deja de ser despreciable, y un enganche en mitad de otra funcion tira
/// el proceso observado — con la culpa aparente en el proceso.
pub const MINIMO_DE_BYTES_CONCRETOS: usize = 6;

/// Resuelve donde estan unas funciones, por las vias disponibles y en orden.
///
/// `simbolos` es lo que el binario declara —lo lee quien sepa leer su formato, no
/// este modulo— y `firmas` es el catalogo para cuando no hay simbolos.
pub fn resolver(
    quienes: &[&str],
    simbolos: &BTreeMap<String, u64>,
    firmas: &[Firma],
    bytes: &[u8],
) -> Vec<Simbolo> {
    let mut v = Vec::new();
    for quien in quienes {
        // 1. La tabla de simbolos. Si esta, se acabo: es un hecho, y ninguna
        //    deduccion posterior puede mejorarlo ni debe contradecirlo.
        if let Some(d) = simbolos.get(*quien) {
            v.push(Simbolo {
                nombre: (*quien).to_owned(),
                desplazamiento: *d,
                via: Via::TablaDeSimbolos,
            });
            continue;
        }
        // 2. La informacion de depuracion iria aqui. Esta declarada y no
        //    resuelta: ver la cabecera del modulo.

        // 3. La firma de bytes, que es una deduccion y sale marcada como tal.
        let Some(f) = firmas
            .iter()
            .find(|f| f.nombre == *quien && f.bytes_concretos() >= MINIMO_DE_BYTES_CONCRETOS)
        else {
            continue;
        };
        if let Some(d) = f.buscar(bytes) {
            v.push(Simbolo {
                nombre: (*quien).to_owned(),
                desplazamiento: d,
                via: Via::FirmaDeBytes,
            });
        }
    }
    v.sort_by(|a, b| a.nombre.cmp(&b.nombre));
    v
}

/// El catalogo de funciones que merece la pena enganchar.
///
/// # Por que estas
///
/// Son los sitios donde el comportamiento de un programa se vuelve observable sin
/// ambiguedad: lo que cifra, lo que manda por la red, lo que abre y lo que lee de
/// donde estan las credenciales. Un catalogo mas largo no dice mas: dice lo mismo
/// mas despacio, y la ejecucion instrumentada tiene presupuesto.
pub static CATALOGO: &[(&str, &str)] = &[
    // Cifrado: donde el contenido deja de poder leerse.
    (
        "EVP_EncryptUpdate",
        "cifrado simetrico: por aqui pasa el contenido en claro",
    ),
    (
        "EVP_DecryptUpdate",
        "descifrado: por aqui sale el contenido en claro",
    ),
    (
        "SSL_write",
        "lo que se manda por el canal cifrado, antes de cifrarse",
    ),
    (
        "SSL_read",
        "lo que llega por el canal cifrado, ya descifrado",
    ),
    // Red: con quien habla.
    ("connect", "con que direccion se abre una conexion"),
    ("sendto", "a donde se manda un datagrama"),
    (
        "getaddrinfo",
        "que nombre se resuelve, que es lo unico que queda de un dominio generado",
    ),
    // Proceso: que ejecuta.
    ("execve", "que programa se ejecuta y con que argumentos"),
    (
        "fork",
        "cuando se duplica el proceso: es como una muestra se separa del proceso que \
         la analiza y sigue por su cuenta",
    ),
    ("ptrace", "quien intenta observar a quien"),
    // Fichero: que toca.
    (
        "open",
        "que ficheros se abren, que es la lista de lo que el programa necesita y la \
         de lo que va a tocar",
    ),
    (
        "openat",
        "que ficheros se abren, con su directorio de referencia",
    ),
    (
        "unlink",
        "que se borra: un borrador y un secuestrador de ficheros pasan los dos por \
         aqui, y el que pasa muchas veces seguidas no es ninguna otra cosa",
    ),
    (
        "rename",
        "que se mueve, que es como se cifra un fichero sin que lo parezca",
    ),
    // Credenciales: de donde se sacan.
    ("getpwnam", "que usuario se consulta"),
    (
        "crypt",
        "que contrasena se compara: por aqui pasa en claro antes de convertirse en \
         el resumen con el que se coteja",
    ),
];

#[cfg(test)]
mod pruebas {
    use super::*;

    /// El prologo de una funcion de x86-64, con su desplazamiento como comodin.
    ///
    /// `endbr64; push rbp; mov rbp,rsp; sub rsp, <imm32>` — los bytes fijos son
    /// el prologo y el inmediato cambia entre compilaciones.
    const PROLOGO: &[Option<u8>] = &[
        Some(0xF3),
        Some(0x0F),
        Some(0x1E),
        Some(0xFA),
        Some(0x55),
        Some(0x48),
        Some(0x89),
        Some(0xE5),
        Some(0x48),
        Some(0x81),
        Some(0xEC),
        None,
        None,
        None,
        None,
    ];

    fn firma() -> Firma {
        Firma {
            nombre: "objetivo",
            patron: PROLOGO,
            porque: "el prologo completo con su reserva de pila",
        }
    }

    #[test]
    fn la_tabla_de_simbolos_gana_a_la_firma_de_bytes() {
        // Las tres vias pueden discrepar, y cuando lo hacen tiene que ganar la
        // mas fiable y no la ultima que se probo. Una firma que coincida por
        // casualidad en un binario que ademas tiene simbolos pondria el enganche
        // en mitad de otra funcion: el proceso observado se cae y la culpa parece
        // del proceso.
        let mut tabla = BTreeMap::new();
        tabla.insert("objetivo".to_owned(), 0x4000u64);
        let mut bytes = vec![0x90u8; 64];
        for (n, b) in PROLOGO.iter().enumerate() {
            if let Some(v) = b {
                bytes[n] = *v;
            }
        }
        let r = resolver(&["objetivo"], &tabla, &[firma()], &bytes);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].desplazamiento, 0x4000, "gana la tabla, no la firma");
        assert_eq!(r[0].via, Via::TablaDeSimbolos);
        assert!(r[0].via.es_un_hecho());
    }

    #[test]
    fn sin_simbolos_se_deduce_por_la_firma_y_se_declara_como_deduccion() {
        // Es el caso de casi todo lo que se distribuye. Funciona, y quien lea la
        // traza tiene que poder saber que ese enganche puede estar mal puesto.
        let mut bytes = vec![0x90u8; 32];
        for (n, b) in PROLOGO.iter().enumerate() {
            if let Some(v) = b {
                bytes[16 + n] = *v;
            }
        }
        let r = resolver(&["objetivo"], &BTreeMap::new(), &[firma()], &bytes);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].desplazamiento, 16);
        assert_eq!(r[0].via, Via::FirmaDeBytes);
        assert!(!r[0].via.es_un_hecho());
        assert!(r[0].frase().contains("DEDUCCION"), "{}", r[0].frase());
    }

    #[test]
    fn una_firma_que_coincide_dos_veces_no_resuelve_nada() {
        // Dos coincidencias significan que la firma no distingue, y elegir una de
        // las dos seria poner el enganche a cara o cruz.
        let mut bytes = vec![0x90u8; 64];
        for sitio in [0usize, 32] {
            for (n, b) in PROLOGO.iter().enumerate() {
                if let Some(v) = b {
                    bytes[sitio + n] = *v;
                }
            }
        }
        assert_eq!(firma().buscar(&bytes), None);
        assert!(resolver(&["objetivo"], &BTreeMap::new(), &[firma()], &bytes).is_empty());
    }

    #[test]
    fn una_firma_demasiado_corta_se_rechaza() {
        // Tres bytes concretos coinciden por casualidad cada dieciseis millones,
        // que en un binario de un megabyte pasa varias veces.
        let corta = Firma {
            nombre: "objetivo",
            patron: &[Some(0x55), Some(0x48), Some(0x89)],
            porque: "demasiado poco",
        };
        assert!(corta.bytes_concretos() < MINIMO_DE_BYTES_CONCRETOS);
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5];
        assert!(resolver(&["objetivo"], &BTreeMap::new(), &[corta], &bytes).is_empty());
    }

    #[test]
    fn los_comodines_dejan_reconocer_el_mismo_prologo_con_otra_reserva_de_pila() {
        // Una firma sin comodines solo reconoce el binario exacto sobre el que se
        // escribio, y el desplazamiento del prologo cambia entre compilaciones.
        for reserva in [0x10u8, 0x80, 0xF0] {
            let mut bytes = vec![0u8; 20];
            for (n, b) in PROLOGO.iter().enumerate() {
                bytes[n] = b.unwrap_or(reserva);
            }
            assert_eq!(firma().buscar(&bytes), Some(0), "reserva {reserva:#x}");
        }
    }

    #[test]
    fn una_funcion_que_no_esta_por_ninguna_via_no_se_inventa() {
        let r = resolver(&["no_existe"], &BTreeMap::new(), &[firma()], &[0x90; 32]);
        assert!(r.is_empty());
    }

    #[test]
    fn el_catalogo_cubre_las_cinco_familias_y_cada_entrada_dice_para_que() {
        // Un catalogo sin explicacion es una lista de nombres que nadie puede
        // revisar, y revisarlo es lo que evita enganchar cosas que no dicen nada.
        assert!(CATALOGO.len() >= 15);
        for (nombre, porque) in CATALOGO {
            assert!(!nombre.is_empty());
            assert!(
                porque.len() > 15,
                "{nombre}: la explicacion es demasiado corta para decir algo"
            );
        }
        let hay = |n: &str| CATALOGO.iter().any(|(x, _)| *x == n);
        assert!(hay("SSL_write"), "cifrado");
        assert!(hay("connect"), "red");
        assert!(hay("execve"), "proceso");
        assert!(hay("openat"), "fichero");
        assert!(hay("getpwnam"), "credenciales");
    }

    #[test]
    fn buscar_en_bytes_mas_cortos_que_la_firma_no_revienta() {
        assert_eq!(firma().buscar(&[0xF3, 0x0F]), None);
        assert_eq!(firma().buscar(&[]), None);
    }
}
