//! Lo que **nunca** se guarda, decidido en un solo sitio.
//!
//! # Por que esto va primero y no al final
//!
//! Un capturador que guarda todo es una fuga esperando a ocurrir. La memoria de
//! un servidor web contiene la contrasena de cada usuario que entro en la ultima
//! hora; el trafico de una clinica contiene su historial. Retener eso «por si
//! acaso» convierte la herramienta de defensa en el sitio del que se roba.
//!
//! Y no vale con decidirlo en la ruta de escritura: con tres rutas de escritura,
//! una se olvidara. Aqui la decision esta **en el tipo**: el escritor no acepta
//! `&[u8]`, acepta [`Limpio`], y `Limpio` no se puede construir mas que pasando
//! por [`Redactor::limpiar`]. No hay camino de los bytes del cable al disco que
//! se salte esto, y eso se verifica por lo que falta.
//!
//! # Que se tapa
//!
//! Dos cosas, y la distincion importa:
//!
//! - **Credenciales en claro**, que se detectan por su forma: la cabecera
//!   `Authorization`, los campos de contrasena de un formulario, y los verbos de
//!   autenticacion de los protocolos de texto. Se tapan siempre, sin que el
//!   cliente tenga que declarar nada.
//! - **Los cuerpos de los ambitos que el cliente declara sensibles** —sanidad,
//!   banca, recursos humanos—. Eso no se puede adivinar por la forma: lo declara
//!   quien conoce su red, y aqui se respeta.
//!
//! # Por que se tapa en el sitio y con la misma longitud
//!
//! Porque el contenido se guarda como paquetes, y un paquete es un marco con
//! longitudes declaradas. Acortar el cuerpo dejaria una captura que ninguna
//! herramienta puede leer —ni la nuestra— y perderia justo la propiedad que hace
//! util guardar: poder volver a pasarla por los disectores.
//!
//! **Lo que si cambia es el veredicto.** Un flujo con bytes tapados no tiene por
//! que reproducir el mismo veredicto que el original: si la senal estaba en la
//! galleta que se tapo, al reproducirlo no esta. Eso no se esconde — se cuenta,
//! y la reproduccion declara su [`crate::reproduccion::Fidelidad`].

/// Con que se tapa. Se elige un caracter imprimible a proposito: un analista que
/// abra la captura en Wireshark tiene que ver que ahi habia algo y que se tapo,
/// no un hueco de ceros que parece un fallo de la captura.
pub const RELLENO: u8 = b'*';

/// Cuanto texto se mira de un paquete buscando credenciales.
///
/// Las credenciales viajan en la cabecera, no en el megabyte cuarenta y dos. Sin
/// tope, cada paquete costaria su tamano —que lo elige quien lo manda— por cada
/// patron buscado.
pub const VENTANA: usize = 16 * 1024;

/// Un ambito que el cliente declara de contenido sensible.
///
/// No se adivina por la forma del trafico: lo declara quien conoce su red. Un
/// producto que decidiera por su cuenta que el trafico de una clinica es
/// sensible estaria acertando por casualidad y fallando en el caso siguiente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbitoSensible {
    /// Como se llama, para que aparezca en el informe de por que no hay cuerpo.
    pub nombre: String,
    /// Anfitriones cuyo trafico no conserva cuerpo. Se compara en minusculas y
    /// por sufijo, de modo que `banco.es` cubra `api.banco.es`.
    pub anfitriones: Vec<String>,
    /// Puertos cuyo trafico no conserva cuerpo.
    pub puertos: Vec<u16>,
}

impl AmbitoSensible {
    /// Si este ambito cubre un anfitrion.
    #[must_use]
    pub fn cubre_anfitrion(&self, anfitrion: &str) -> bool {
        let bajo = anfitrion.to_ascii_lowercase();
        // Se quita el puerto si venia pegado, que es como viaja en HTTP.
        let sin_puerto = bajo.split(':').next().unwrap_or(&bajo);
        self.anfitriones.iter().any(|a| {
            let a = a.to_ascii_lowercase();
            sin_puerto == a || sin_puerto.ends_with(&format!(".{a}"))
        })
    }

    /// Si este ambito cubre un puerto.
    #[must_use]
    pub fn cubre_puerto(&self, puerto: u16) -> bool {
        self.puertos.contains(&puerto)
    }
}

/// Por que se tapo un trozo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Motivo {
    /// Una credencial reconocida por su forma.
    Credencial,
    /// El cuerpo de un ambito que el cliente declaro sensible.
    AmbitoDeclarado,
}

impl Motivo {
    /// Como se lee en un informe.
    #[must_use]
    pub fn frase(self) -> &'static str {
        match self {
            Motivo::Credencial => {
                "una credencial en claro, que no se guarda nunca aunque el flujo entero si"
            }
            Motivo::AmbitoDeclarado => {
                "el cuerpo de un ambito que el cliente declaro sensible, que no se guarda \
                 aunque las cabeceras si"
            }
        }
    }
}

/// Un trozo tapado, con su sitio y su motivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tapado {
    /// Donde empezaba, dentro del paquete.
    pub desde: usize,
    /// Cuantos bytes ocupaba.
    pub cuantos: usize,
    /// Por que.
    pub motivo: Motivo,
}

/// Bytes que **ya pasaron** por la redaccion.
///
/// Es el unico tipo que el escritor acepta, y su unico constructor es
/// [`Redactor::limpiar`]. No hay `From<&[u8]>`, no hay `new`, y el campo es
/// privado: no existe camino de los bytes del cable al disco que se salte la
/// redaccion. Se verifica por lo que **falta**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limpio {
    bytes: Vec<u8>,
    tapados: Vec<Tapado>,
}

impl Limpio {
    /// Los bytes, ya limpios.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Lo que se tapo, con su sitio y su motivo.
    #[must_use]
    pub fn tapados(&self) -> &[Tapado] {
        &self.tapados
    }

    /// Cuantos bytes se taparon en total.
    #[must_use]
    pub fn bytes_tapados(&self) -> usize {
        self.tapados.iter().map(|t| t.cuantos).sum()
    }

    /// Si no hubo que tapar nada.
    ///
    /// Es lo que autoriza a esperar que una reproduccion de este flujo de
    /// **exactamente** el mismo veredicto que la observacion original.
    #[must_use]
    pub fn intacto(&self) -> bool {
        self.tapados.is_empty()
    }
}

/// El contexto de un paquete, para decidir si cae en un ambito declarado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Donde {
    /// Puerto de destino.
    pub puerto_destino: u16,
    /// Puerto de origen.
    pub puerto_origen: u16,
}

/// Donde acaba el valor de un patron.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fin {
    /// Al final de la linea: es como acaban las cabeceras y los verbos.
    Linea,
    /// En el siguiente separador de formulario, o al final de la linea.
    Formulario,
}

/// Un patron de credencial.
struct Patron {
    /// El texto que lo delata. Va en minusculas para los que no distinguen caso.
    texto: &'static str,
    /// Donde acaba el valor que hay detras.
    fin: Fin,
    /// Si tiene que empezar linea.
    ///
    /// Los verbos de los protocolos de texto si: sin esto, un cuerpo que hable de
    /// contrasenas y contenga «PASS » se taparia entero y el analista no veria
    /// nada.
    empieza_linea: bool,
    /// Si se compara sin distinguir mayusculas.
    ///
    /// Las cabeceras HTTP si —la norma lo permite—; los verbos de FTP, POP3 y
    /// SMTP no, porque la norma los fija en mayusculas y aceptar minusculas
    /// convertiria cualquier texto en una credencial.
    ignora_caso: bool,
}

/// Todos los patrones, en una sola tabla **ordenada por sus dos primeros bytes**.
///
/// # Por que una tabla y no tres bucles
///
/// Porque con tres bucles el paquete se recorre una vez **por patron**, y eso se
/// midio: dieciocho pasadas sobre mil quinientos bytes dejaban la captura en dos
/// mil paquetes por segundo, que no es una velocidad de captura, es un embudo.
///
/// # Y por que ordenada
///
/// Porque el orden es lo que permite que en cada posicion del paquete se prueben
/// **solo** los patrones que empiezan por esos dos bytes, y no los dieciocho.
/// [`INDICE`] guarda, para cada pareja de bytes que empieza algo, donde empieza
/// su tramo en esta tabla y cuantos hay. El orden de las filas de aqui no es
/// cosmetico: si se rompe, [`indice_coherente`] deja de compilar la prueba que lo
/// comprueba.
static PATRONES: &[Patron] = &[
    Patron {
        texto: "access_token=",
        fin: Fin::Formulario,
        empieza_linea: false,
        ignora_caso: true,
    },
    Patron {
        texto: "APOP ",
        fin: Fin::Linea,
        empieza_linea: true,
        ignora_caso: false,
    },
    Patron {
        texto: "api_key=",
        fin: Fin::Formulario,
        empieza_linea: false,
        ignora_caso: true,
    },
    Patron {
        texto: "apikey=",
        fin: Fin::Formulario,
        empieza_linea: false,
        ignora_caso: true,
    },
    Patron {
        texto: "authorization:",
        fin: Fin::Linea,
        empieza_linea: false,
        ignora_caso: true,
    },
    Patron {
        texto: "AUTH PLAIN ",
        fin: Fin::Linea,
        empieza_linea: true,
        ignora_caso: false,
    },
    Patron {
        texto: "AUTH LOGIN ",
        fin: Fin::Linea,
        empieza_linea: true,
        ignora_caso: false,
    },
    Patron {
        texto: "client_secret=",
        fin: Fin::Formulario,
        empieza_linea: false,
        ignora_caso: true,
    },
    Patron {
        texto: "PASS ",
        fin: Fin::Linea,
        empieza_linea: true,
        ignora_caso: false,
    },
    Patron {
        texto: "password=",
        fin: Fin::Formulario,
        empieza_linea: false,
        ignora_caso: true,
    },
    Patron {
        texto: "passwd=",
        fin: Fin::Formulario,
        empieza_linea: false,
        ignora_caso: true,
    },
    Patron {
        texto: "proxy-authorization:",
        fin: Fin::Linea,
        empieza_linea: false,
        ignora_caso: true,
    },
    Patron {
        texto: "pwd=",
        fin: Fin::Formulario,
        empieza_linea: false,
        ignora_caso: true,
    },
    Patron {
        texto: "refresh_token=",
        fin: Fin::Formulario,
        empieza_linea: false,
        ignora_caso: true,
    },
    Patron {
        texto: "secret=",
        fin: Fin::Formulario,
        empieza_linea: false,
        ignora_caso: true,
    },
    Patron {
        texto: "www-authenticate:",
        fin: Fin::Linea,
        empieza_linea: false,
        ignora_caso: true,
    },
    Patron {
        texto: "x-api-key:",
        fin: Fin::Linea,
        empieza_linea: false,
        ignora_caso: true,
    },
    Patron {
        texto: "x-auth-token:",
        fin: Fin::Linea,
        empieza_linea: false,
        ignora_caso: true,
    },
];

/// Los **dos** primeros bytes que pueden empezar un patron, como mapa de bits.
///
/// # Por que dos y no uno, medido
///
/// La primera version filtraba por un byte. Con un paquete de mil quinientas
/// equis —que un atacante manda cuando quiere— la `x` de `x-api-key:` hacia que
/// TODAS las posiciones pasaran el filtro, y se probaban los dieciocho patrones
/// en cada una: trescientos ochenta microsegundos por paquete, que son dos mil
/// cuatrocientos paquetes por segundo. Un sensor al que se le puede multiplicar
/// el coste por veinte eligiendo el relleno del paquete es un sensor que el
/// atacante apaga generando trafico.
///
/// Con dos bytes, `xx` no empieza ningun patron y la posicion se descarta con una
/// consulta a un mapa de bits. Sesenta y cinco mil claves posibles caben en ocho
/// kilobytes de tabla estatica, que se calcula en compilacion.
static PAREJAS: [u64; 1024] = parejas();

/// Cuantas parejas distintas hay como maximo. Sobra con el doble de patrones.
const MAX_PAREJAS: usize = 64;

/// Para cada pareja de bytes que empieza algo: `(clave, donde empieza su tramo en
/// [`PATRONES`], cuantos hay)`. Ordenado por clave, como la tabla.
static INDICE: ([(u16, u8, u8); MAX_PAREJAS], usize) = indice();

const fn clave_de(b: &[u8]) -> u16 {
    let a = if b[0] >= b'A' && b[0] <= b'Z' {
        b[0] + 32
    } else {
        b[0]
    };
    let c = if b[1] >= b'A' && b[1] <= b'Z' {
        b[1] + 32
    } else {
        b[1]
    };
    ((a as u16) << 8) | (c as u16)
}

const fn parejas() -> [u64; 1024] {
    let mut t = [0u64; 1024];
    let mut i = 0;
    while i < PATRONES.len() {
        let clave = clave_de(PATRONES[i].texto.as_bytes()) as usize;
        t[clave / 64] |= 1u64 << (clave % 64);
        i += 1;
    }
    t
}

const fn indice() -> ([(u16, u8, u8); MAX_PAREJAS], usize) {
    let mut t = [(0u16, 0u8, 0u8); MAX_PAREJAS];
    let mut cuantas = 0usize;
    let mut i = 0usize;
    while i < PATRONES.len() {
        let clave = clave_de(PATRONES[i].texto.as_bytes());
        // La tabla esta ordenada por clave, asi que el tramo de esta clave es
        // contiguo: se cuenta hasta que cambie.
        let mut j = i;
        while j < PATRONES.len() && clave_de(PATRONES[j].texto.as_bytes()) == clave {
            j += 1;
        }
        t[cuantas] = (clave, i as u8, (j - i) as u8);
        cuantas += 1;
        i = j;
    }
    (t, cuantas)
}

/// Si estos dos bytes pueden empezar algun patron.
#[inline]
fn pareja_posible(a: u8, b: u8) -> bool {
    let clave = ((a as usize) << 8) | (b as usize);
    PAREJAS[clave / 64] & (1u64 << (clave % 64)) != 0
}

/// El tramo de [`PATRONES`] que empieza por estos dos bytes.
///
/// Es lo que convierte «probar los dieciocho patrones en cada posicion» en
/// «probar uno o dos». Se midio: sin esto, un paquete lleno de uves dobles —la
/// `ww` de `www-authenticate:`— costaba nueve veces lo que uno neutro.
#[inline]
fn tramo(a: u8, b: u8) -> &'static [Patron] {
    let clave = ((a as u16) << 8) | (b as u16);
    let (tabla, cuantas) = &INDICE;
    let mut k = 0usize;
    while k < *cuantas {
        if tabla[k].0 == clave {
            let desde = tabla[k].1 as usize;
            return &PATRONES[desde..desde + tabla[k].2 as usize];
        }
        k += 1;
    }
    &[]
}

/// Si el ULTIMO byte del patron tambien cuadra.
///
/// # Por que hace falta ademas de los dos primeros
///
/// Porque hay patrones cuyos dos primeros bytes se repiten: `www-authenticate:`
/// empieza por `ww`, y un paquete lleno de uves dobles pasaba el filtro en todas
/// las posiciones y se comparaba entero —diecisiete bytes— en cada una. Se midio:
/// seiscientos ochenta y siete milisegundos contra setenta y siete de un paquete
/// neutro.
///
/// Comprobar el ultimo byte antes de comparar el patron entero corta eso en una
/// sola operacion: en un paquete de uves dobles, el byte decimosexto es una uve
/// doble y no los dos puntos con los que acaba la cabecera.
///
/// **Lo que esto garantiza y lo que no**: el coste por posicion queda acotado por
/// una constante pequena, no por la longitud de los patrones. No es inmunidad —
/// una entrada construida a medida para un patron concreto sigue costando lo que
/// mide ese patron—, pero deja de poder multiplicarse eligiendo el relleno.
#[inline]
fn ultimo_cuadra(datos: &[u8], i: usize, marca: &[u8], ignora_caso: bool) -> bool {
    let Some(&esperado) = marca.last() else {
        return false;
    };
    let Some(&hay) = datos.get(i + marca.len() - 1) else {
        return false;
    };
    if ignora_caso {
        hay.eq_ignore_ascii_case(&esperado)
    } else {
        hay == esperado
    }
}

/// Decide que se tapa y lo tapa.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    ambitos: Vec<AmbitoSensible>,
}

impl Redactor {
    /// Un redactor sin ambitos declarados: solo tapa credenciales.
    #[must_use]
    pub fn nuevo() -> Redactor {
        Redactor::default()
    }

    /// Anade un ambito declarado por el cliente.
    pub fn con_ambito(mut self, a: AmbitoSensible) -> Redactor {
        self.ambitos.push(a);
        self
    }

    /// Los ambitos declarados.
    #[must_use]
    pub fn ambitos(&self) -> &[AmbitoSensible] {
        &self.ambitos
    }

    /// El ambito que cubre estos bytes, si alguno.
    fn ambito_que_cubre(&self, datos: &[u8], donde: Donde) -> Option<&AmbitoSensible> {
        if let Some(a) = self
            .ambitos
            .iter()
            .find(|a| a.cubre_puerto(donde.puerto_destino) || a.cubre_puerto(donde.puerto_origen))
        {
            return Some(a);
        }
        let anfitrion = cabecera(datos, "host")?;
        self.ambitos.iter().find(|a| a.cubre_anfitrion(&anfitrion))
    }

    /// Decide que hay que tapar, sin copiar nada.
    ///
    /// Esta separado de [`Redactor::limpiar`] porque son dos costes distintos y
    /// solo uno esta acotado: MIRAR el paquete cuesta lo mismo pasado el tamano
    /// de la [`VENTANA`], y COPIARLO para entregar el resultado es lineal por
    /// necesidad. Medirlos juntos hacia que la prueba de la ventana midiera el
    /// asignador de memoria.
    fn inspeccionar(&self, datos: &[u8], donde: Donde) -> Vec<Tapado> {
        let mut tapados: Vec<Tapado> = Vec::new();

        // 1. Las credenciales, siempre y sin que nadie las declare.
        for t in credenciales(datos) {
            tapados.push(t);
        }

        // 2. El cuerpo de un ambito declarado. Se tapa el CUERPO y no las
        //    cabeceras: el analista sigue viendo quien hablo con quien y con que
        //    metodo, que es lo que hace falta para investigar, sin ver el
        //    contenido, que es lo que no puede salir.
        if self.ambito_que_cubre(datos, donde).is_some() {
            match fin_de_cabecera(datos) {
                Some(inicio) => {
                    if inicio < datos.len() {
                        tapados.push(Tapado {
                            desde: inicio,
                            cuantos: datos.len() - inicio,
                            motivo: Motivo::AmbitoDeclarado,
                        });
                    }
                }
                // Sin cabecera reconocible no se puede separar el sobre del
                // contenido: se tapa entero, que es el lado seguro del error.
                None => tapados.push(Tapado {
                    desde: 0,
                    cuantos: datos.len(),
                    motivo: Motivo::AmbitoDeclarado,
                }),
            }
        }
        tapados
    }

    /// Tapa lo que no se puede guardar y devuelve los bytes limpios.
    ///
    /// **Este es el unico constructor de [`Limpio`].** Todo lo que se escribe
    /// pasa por aqui, por construccion y no por disciplina.
    #[must_use]
    pub fn limpiar(&self, datos: &[u8], donde: Donde) -> Limpio {
        let mut tapados = self.inspeccionar(datos, donde);
        let mut bytes = datos.to_vec();

        // Se aplica al final y con el MISMO numero de bytes: acortar dejaria una
        // captura que ninguna herramienta puede leer, ni la nuestra.
        for t in &tapados {
            let fin = t.desde.saturating_add(t.cuantos).min(bytes.len());
            for b in &mut bytes[t.desde.min(fin)..fin] {
                *b = RELLENO;
            }
        }
        tapados.sort_by_key(|t| (t.desde, t.cuantos));
        tapados.dedup();

        Limpio { bytes, tapados }
    }
}

/// Donde acaba la cabecera de estilo HTTP.
fn fin_de_cabecera(datos: &[u8]) -> Option<usize> {
    let tope = datos.len().min(VENTANA);
    datos[..tope]
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| {
            datos[..tope]
                .windows(2)
                .position(|v| v == b"\n\n")
                .map(|p| p + 2)
        })
}

/// El valor de una cabecera de estilo HTTP, buscada sin distinguir mayusculas.
///
/// Compara byte a byte sin pasar el paquete entero a minusculas: una copia de mil
/// quinientos bytes por cabecera buscada es una copia que no hace falta, y aqui se
/// llama en la ruta de cada paquete.
fn cabecera(datos: &[u8], nombre: &str) -> Option<String> {
    let tope = datos.len().min(VENTANA);
    let marca = format!("\n{}:", nombre.to_ascii_lowercase());
    let m = marca.as_bytes();
    let p = datos[..tope]
        .windows(m.len())
        .position(|v| v.eq_ignore_ascii_case(m))?;
    let desde = p + m.len();
    let fin = datos[desde..tope]
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .map_or(tope, |n| desde + n);
    Some(
        String::from_utf8_lossy(&datos[desde..fin])
            .trim()
            .to_owned(),
    )
}

/// Todos los trozos de credencial que hay en estos bytes, en **una sola pasada**.
///
/// El coste es lineal en el tamano del paquete y no depende del numero de
/// patrones: en cada posicion se mira un byte, y solo cuando ese byte puede
/// empezar un patron se prueban los que empiezan por el. Ver [`PRIMERAS`].
fn credenciales(datos: &[u8]) -> Vec<Tapado> {
    let tope = datos.len().min(VENTANA);
    let mut salida = Vec::new();
    let mut i = 0usize;

    // Tope de hallazgos: el numero de credenciales lo escribe el emisor, y un
    // paquete preparado con diez mil podria hacer crecer este vector sin fin.
    const MAX_HALLAZGOS: usize = 256;

    // No se hace copia del paquete en minusculas: seria mil quinientos bytes de
    // reserva y copia por paquete, y el caso normal ni siquiera los mira.
    while i + 1 < tope && salida.len() < MAX_HALLAZGOS {
        let a = datos[i].to_ascii_lowercase();
        let b = datos[i + 1].to_ascii_lowercase();
        if !pareja_posible(a, b) {
            i += 1;
            continue;
        }
        let empieza_linea = i == 0 || datos[i - 1] == b'\n';
        let mut avance = 1usize;
        // Solo los patrones que empiezan por esos dos bytes: uno o dos, no los
        // dieciocho.
        for p in tramo(a, b) {
            let marca = p.texto.as_bytes();
            if i + marca.len() > tope {
                continue;
            }
            if p.empieza_linea && !empieza_linea {
                continue;
            }
            // El ultimo byte antes que el patron entero: es lo que impide que un
            // relleno elegido a proposito haga comparar diecisiete bytes en cada
            // posicion del paquete.
            if !ultimo_cuadra(datos, i, marca, p.ignora_caso) {
                continue;
            }
            let casa = if p.ignora_caso {
                datos[i..i + marca.len()].eq_ignore_ascii_case(marca)
            } else {
                &datos[i..i + marca.len()] == marca
            };
            if !casa {
                continue;
            }
            let inicio_valor = i + marca.len();
            let fin = datos[inicio_valor..tope]
                .iter()
                .position(|&b| match p.fin {
                    Fin::Linea => b == b'\r' || b == b'\n',
                    Fin::Formulario => b == b'&' || b == b'\r' || b == b'\n' || b == b' ',
                })
                .map_or(tope, |n| inicio_valor + n);
            if fin > inicio_valor {
                salida.push(Tapado {
                    desde: inicio_valor,
                    cuantos: fin - inicio_valor,
                    motivo: Motivo::Credencial,
                });
            }
            // Se sigue DESPUES del valor tapado: dentro de una credencial no hay
            // otra, y volver a entrar ahi seria recorrerla otra vez por cada
            // patron.
            avance = (fin.max(inicio_valor) - i).max(1);
            break;
        }
        i += avance;
    }
    salida
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn texto(l: &Limpio) -> String {
        String::from_utf8_lossy(l.bytes()).into_owned()
    }

    #[test]
    fn una_credencial_basica_no_llega_al_disco() {
        let r = Redactor::nuevo();
        let p = b"GET /a HTTP/1.1\r\nHost: x\r\nAuthorization: Basic YWRtaW46c2VjcmV0bw==\r\n\r\n";
        let l = r.limpiar(p, Donde::default());
        assert!(
            !texto(&l).contains("YWRtaW46c2VjcmV0bw"),
            "la credencial sigue ahi: {}",
            texto(&l)
        );
        assert!(texto(&l).contains("Authorization:"), "{}", texto(&l));
        assert!(!l.intacto());
        assert_eq!(l.tapados()[0].motivo, Motivo::Credencial);
    }

    /// La longitud es sagrada: la captura se guarda como paquetes, y acortar uno
    /// deja un fichero que ninguna herramienta puede leer, ni la nuestra.
    #[test]
    fn tapar_no_cambia_la_longitud_de_ni_un_byte() {
        let r = Redactor::nuevo();
        let p = b"POST /login HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer abc.def.ghi\r\n\r\nuser=ana&password=muysecreta&x=1";
        let l = r.limpiar(p, Donde::default());
        assert_eq!(l.bytes().len(), p.len());
        assert!(!texto(&l).contains("muysecreta"), "{}", texto(&l));
        assert!(texto(&l).contains("user=ana"), "{}", texto(&l));
        assert!(texto(&l).contains("&x=1"), "{}", texto(&l));
    }

    #[test]
    fn la_contrasena_de_un_protocolo_de_texto_tampoco() {
        let r = Redactor::nuevo();
        for p in [
            &b"USER ana\r\nPASS lacontrasena\r\n"[..],
            &b"AUTH PLAIN AGFuYQBsYWNvbnRyYXNlbmE=\r\n"[..],
            &b"APOP ana c4c9334bac560ecc979e58001b3e22fb\r\n"[..],
        ] {
            let l = r.limpiar(p, Donde::default());
            assert!(!l.intacto(), "{}", String::from_utf8_lossy(p));
            assert_eq!(l.bytes().len(), p.len());
        }
    }

    #[test]
    fn la_palabra_pass_dentro_de_un_cuerpo_no_tapa_nada() {
        // Sin exigir que el verbo empiece linea, un cuerpo que hable de
        // contrasenas se taparia entero y el analista no veria nada.
        let r = Redactor::nuevo();
        let p = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nel articulo explica PASS y sus riesgos";
        let l = r.limpiar(p, Donde::default());
        assert!(l.intacto(), "{:?}", l.tapados());
    }

    #[test]
    fn un_ambito_declarado_pierde_el_cuerpo_y_conserva_el_sobre() {
        // El analista sigue viendo quien hablo con quien y con que metodo, que es
        // lo que hace falta para investigar; el contenido no sale.
        let r = Redactor::nuevo().con_ambito(AmbitoSensible {
            nombre: "historia clinica".to_owned(),
            anfitriones: vec!["clinica.es".to_owned()],
            puertos: vec![],
        });
        let p =
            b"POST /paciente HTTP/1.1\r\nHost: api.clinica.es\r\n\r\n{\"diagnostico\":\"privado\"}";
        let l = r.limpiar(p, Donde::default());
        let t = texto(&l);
        assert!(t.contains("POST /paciente"), "{t}");
        assert!(t.contains("api.clinica.es"), "{t}");
        assert!(!t.contains("diagnostico"), "{t}");
        assert_eq!(l.bytes().len(), p.len());
        assert!(l
            .tapados()
            .iter()
            .any(|x| x.motivo == Motivo::AmbitoDeclarado));
    }

    #[test]
    fn el_ambito_se_declara_por_sufijo_y_no_por_igualdad() {
        let a = AmbitoSensible {
            nombre: "banca".to_owned(),
            anfitriones: vec!["banco.es".to_owned()],
            puertos: vec![],
        };
        assert!(a.cubre_anfitrion("banco.es"));
        assert!(a.cubre_anfitrion("api.banco.es"));
        assert!(a.cubre_anfitrion("API.BANCO.ES:443"));
        // Y no cubre a quien solo se le parece, que es el fallo clasico de
        // comparar por «contiene».
        assert!(!a.cubre_anfitrion("notbanco.es"));
        assert!(!a.cubre_anfitrion("banco.es.malo.com"));
    }

    #[test]
    fn un_ambito_por_puerto_sin_cabecera_reconocible_se_tapa_entero() {
        // Es el lado seguro del error: sin cabecera no se puede separar el sobre
        // del contenido, y dejar pasar el contenido de un ambito declarado seria
        // justo lo que el ambito existe para impedir.
        let r = Redactor::nuevo().con_ambito(AmbitoSensible {
            nombre: "banca".to_owned(),
            anfitriones: vec![],
            puertos: vec![8443],
        });
        let p = b"\x00\x01binario sin cabeceras con un numero de tarjeta";
        let l = r.limpiar(
            p,
            Donde {
                puerto_destino: 8443,
                puerto_origen: 40000,
            },
        );
        assert!(l.bytes().iter().all(|&b| b == RELLENO));
        assert_eq!(l.bytes().len(), p.len());
    }

    #[test]
    fn el_trafico_corriente_sale_intacto() {
        // Si la redaccion tocara el trafico normal, la reproduccion dejaria de
        // ser determinista para todo el mundo y la propiedad se perderia.
        let r = Redactor::nuevo();
        let p = b"GET /index.html HTTP/1.1\r\nHost: ejemplo.es\r\nUser-Agent: curl/8\r\n\r\n";
        let l = r.limpiar(p, Donde::default());
        assert!(l.intacto(), "{:?}", l.tapados());
        assert_eq!(l.bytes(), p);
    }

    /// Cuantas veces cuesta MIRAR cada paquete de `otros` lo que cuesta mirar
    /// `base`, **sin el ruido de la maquina**.
    ///
    /// # Como se mide, y por que asi
    ///
    /// Un cociente entre dos tiempos solo vale si los dos se tomaron en las
    /// mismas condiciones, y en una maquina compartida las condiciones cambian de
    /// un momento a otro. Por eso cada paquete se mide INMEDIATAMENTE despues de
    /// un lote de `base`, y se calcula el cociente de ese par: dos lotes seguidos
    /// sufren la misma carga. Se repite y se toma la MEDIANA de los cocientes, que
    /// ignora las pasadas en las que otro proceso se cruzo.
    ///
    /// Las dos formas anteriores fallaron de verdad. Medir la base una vez al
    /// principio y los demas despues comparaba momentos distintos: con otro
    /// proceso compilando al lado, un relleno de «w» salia de 5 a 8 veces mas caro
    /// que el neutro sin serlo. Y el cociente de dos MINIMOS, aun intercalados,
    /// seguia comparando pasadas distintas: el coste real de ese relleno es 3,5
    /// veces el neutro —medido estable, 3,47 a 3,56—, y bajo carga salia 4,4.
    ///
    /// Se mide [`Redactor::inspeccionar`] y no [`Redactor::limpiar`]: la copia que
    /// hace `limpiar` es lineal por necesidad y no es lo que se quiere acotar.
    fn cocientes(r: &Redactor, base: &[u8], otros: &[&[u8]], cuantos: u32) -> Vec<f64> {
        const PASADAS: usize = 9;
        let lote = |p: &[u8]| {
            let t = std::time::Instant::now();
            for _ in 0..cuantos {
                std::hint::black_box(r.inspeccionar(p, Donde::default()));
            }
            t.elapsed().as_secs_f64()
        };
        let mut por_paquete: Vec<Vec<f64>> = vec![Vec::with_capacity(PASADAS); otros.len()];
        for _ in 0..PASADAS {
            for (v, p) in por_paquete.iter_mut().zip(otros) {
                let b = lote(base);
                let o = lote(p);
                v.push(o / b.max(1e-12));
            }
        }
        por_paquete
            .into_iter()
            .map(|mut v| {
                v.sort_by(f64::total_cmp);
                v[v.len() / 2]
            })
            .collect()
    }

    /// El relleno del paquete no puede multiplicar el coste de mirarlo.
    ///
    /// Se midio: con el filtro de un solo byte, mil quinientas equis —la `x` de
    /// `x-api-key:`— hacian que todas las posiciones pasaran el filtro y se
    /// probaran los dieciocho patrones en cada una. Trescientos ochenta
    /// microsegundos por paquete contra treinta y siete. Un sensor al que se le
    /// puede multiplicar el coste por veinte eligiendo el relleno es un sensor
    /// que el atacante apaga generando trafico.
    #[test]
    fn el_relleno_del_paquete_no_multiplica_el_coste_de_mirarlo() {
        let r = Redactor::nuevo();

        // Un paquete corriente, de relleno neutro, y el peor relleno posible: el
        // primer byte de cada patron, repetido.
        let neutro = vec![b'.'; 1500];
        let mut rellenos: Vec<u8> = PATRONES.iter().map(|p| p.texto.as_bytes()[0]).collect();
        rellenos.sort_unstable();
        rellenos.dedup();
        let hostiles: Vec<Vec<u8>> = rellenos.iter().map(|b| vec![*b; 1500]).collect();
        let refs: Vec<&[u8]> = hostiles.iter().map(Vec::as_slice).collect();
        let c = cocientes(&r, &neutro, &refs, 400);
        let (i_peor, peor) = c
            .iter()
            .copied()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .unwrap_or((0, 0.0));
        let cual = rellenos.get(i_peor).copied().unwrap_or(b'?');
        eprintln!(
            "relleno: el peor es «{}», a {peor:.2} veces el neutro",
            cual as char
        );

        // Cuatro veces sigue siendo margen —lo que esta prueba impide es el
        // factor VEINTE que habia—; el peor relleno real, el de las uves dobles,
        // esta en 3,5.
        assert!(
            peor <= 4.0,
            "un paquete lleno de «{}» cuesta {peor:.2} veces lo que uno neutro: el filtro \
             de entrada no esta filtrando",
            cual as char
        );
    }

    #[test]
    fn la_redaccion_no_cuesta_lo_que_diga_el_emisor() {
        // Las credenciales viajan en la cabecera, no en el megabyte cuarenta y
        // dos. Sin ventana, cada paquete costaria su tamano por cada patron.
        //
        // La propiedad es que el coste de MIRAR no crece con el tamano del
        // paquete una vez pasada la ventana, y eso es lo que se mide, en la misma
        // maquina y en el mismo momento.
        //
        // Antes se exigia un tiempo absoluto —menos de dos segundos—, que no
        // dice nada de la propiedad: en una maquina rapida pasa aunque la ventana
        // no funcione, y en una cargada falla aunque funcione perfectamente. Un
        // umbral en segundos mide la maquina; este mide el producto.
        let r = Redactor::nuevo();
        let cabecera = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";

        let mut grande = cabecera.to_vec();
        grande.extend(std::iter::repeat_n(b'A', 4 * 1024 * 1024));

        // LO QUE SE EXIGE, Y POR QUE NO ES UN COCIENTE SOBRE `limpiar`. Devuelve una
        // COPIA del paquete: no se puede entregar un paquete limpio de cuatro
        // megabytes sin escribir cuatro megabytes, y esa copia es lineal por
        // necesidad. Exigir un cociente sobre `limpiar` media sobre todo al
        // asignador de memoria —fallos de pagina frente a memoria reutilizada— y
        // al ancho de banda de la maquina: pasaba de ~20 a 28 en cuanto otro
        // proceso compilaba a la vez, y fallo asi en una tanda de CI. Restar una
        // copia medida aparte tampoco sirve: son dos cifras de cientos de
        // milisegundos con ruido propio, y el resto sale dominado por ese ruido.
        //
        // La propiedad de la ventana es otra y mas estricta: pasado su tamano,
        // MIRAR cuesta lo mismo. Se compara la inspeccion sola sobre un paquete del
        // tamano exacto de la ventana y sobre uno de cuatro megabytes: tienen que
        // costar practicamente igual.
        let mut en_ventana = cabecera.to_vec();
        en_ventana.extend(std::iter::repeat_n(b'A', VENTANA - cabecera.len()));
        let cociente = cocientes(&r, &en_ventana, &[&grande], 200)[0];
        eprintln!(
            "ventana: mirar {} B cuesta {cociente:.2} veces mirar {} B",
            grande.len(),
            en_ventana.len()
        );
        assert!(
            cociente <= 3.0,
            "MIRAR {} bytes cuesta {cociente:.2} veces lo que mirar {}: pasado el tamano de \
             la ventana el coste sigue creciendo, asi que la ventana no esta acotando nada",
            grande.len(),
            en_ventana.len()
        );

        // Y lo que sale tiene el tamano que entro, tapado o no.
        let l = r.limpiar(&grande, Donde::default());
        assert_eq!(l.bytes().len(), grande.len());
    }

    /// El orden de [`PATRONES`] no es cosmetico: [`INDICE`] da por hecho que el
    /// tramo de cada pareja de bytes es contiguo. Si alguien anade una fila en
    /// medio sin respetar el orden, la busqueda dejaria de encontrar patrones y
    /// las credenciales llegarian al disco **sin que ninguna otra prueba lo
    /// viera**, porque los casos de las demas siguen casando.
    #[test]
    fn indice_coherente() {
        // La tabla esta ordenada por su clave de dos bytes.
        let claves: Vec<u16> = PATRONES
            .iter()
            .map(|p| clave_de(p.texto.as_bytes()))
            .collect();
        let mut ordenadas = claves.clone();
        ordenadas.sort_unstable();
        assert_eq!(
            claves, ordenadas,
            "PATRONES tiene que estar ordenada por sus dos primeros bytes"
        );

        // Y el indice encuentra TODOS los patrones, cada uno en su tramo.
        for p in PATRONES {
            let b = p.texto.as_bytes();
            let t = tramo(b[0].to_ascii_lowercase(), b[1].to_ascii_lowercase());
            assert!(
                t.iter().any(|q| q.texto == p.texto),
                "«{}» no esta en su propio tramo",
                p.texto
            );
            assert!(pareja_posible(
                b[0].to_ascii_lowercase(),
                b[1].to_ascii_lowercase()
            ));
        }
        // Y no hay tramos para parejas que no empiezan nada.
        assert!(tramo(b'z', b'z').is_empty());
        assert!(!pareja_posible(b'z', b'z'));
        let (_, cuantas) = &INDICE;
        assert!(*cuantas <= MAX_PAREJAS);
        assert!(*cuantas > 0);
    }

    /// Y la comprobacion que de verdad importa: cada patron de la tabla encuentra
    /// su credencial. Sin esto, el indice podria estar perfectamente coherente y
    /// no encontrar nada.
    #[test]
    fn cada_patron_de_la_tabla_tapa_lo_suyo() {
        let r = Redactor::nuevo();
        for p in PATRONES {
            let cuerpo = match p.fin {
                Fin::Linea => format!("{}ELSECRETO\r\n", p.texto),
                Fin::Formulario => format!("{}ELSECRETO&otro=1", p.texto),
            };
            // Los que exigen empezar linea se prueban al principio del paquete.
            let l = r.limpiar(cuerpo.as_bytes(), Donde::default());
            assert!(
                !texto(&l).contains("ELSECRETO"),
                "«{}» no tapo su credencial: {}",
                p.texto,
                texto(&l)
            );
            assert_eq!(l.bytes().len(), cuerpo.len());
        }
    }

    #[test]
    fn cada_motivo_explica_algo_distinto() {
        assert_ne!(Motivo::Credencial.frase(), Motivo::AmbitoDeclarado.frase());
        for m in [Motivo::Credencial, Motivo::AmbitoDeclarado] {
            assert!(m.frase().len() > 40, "{m:?}");
        }
    }
}
