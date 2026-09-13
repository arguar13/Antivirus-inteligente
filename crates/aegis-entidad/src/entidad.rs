//! Un identificador estable para cada cosa del mundo, y las reglas de cuando dos
//! observaciones son la misma.
//!
//! # La pregunta que este modulo contesta
//!
//! No es «como llamamos a las cosas»: es **«cuando dos observaciones distintas
//! son la misma entidad, y cuando no»**. Y la segunda mitad es la que importa,
//! porque unir de mas es peor que no unir: atribuye a una cosa lo que hizo otra,
//! y lo hace en silencio.
//!
//! # Lo que NO vale como identidad, con lo que pasa si se usa
//!
//! | Entidad | Lo evidente | Por que no vale |
//! |---|---|---|
//! | Proceso | el PID | Los PID se **reciclan**, y en una maquina cargada en minutos. Un proceso nuevo que hereda un PID reciclado hereda **su historia** — y esa historia puede decir «esto es el ransomware» |
//! | Fichero | la ruta, o el resumen | Son **dos** entidades distintas: el contenido y la ubicacion. Un fichero modificado es contenido nuevo en la misma ubicacion |
//! | Flujo | la quintupla | Se reutiliza. Y vista desde los dos extremos tiene que dar **el mismo** identificador, o el linaje se parte justo donde cruza la red |
//! | Cuenta | el nombre de inicio de sesion | Cambia: la gente se casa, cambia de departamento, y el dominio se migra |
//! | Maquina | el nombre, o el `machine-id` | Una imagen maestra clonada produce cien maquinas con **los dos** iguales |
//! | Artefacto detonado | el resumen de la muestra | Dos detonaciones con configuracion distinta **no son el mismo resultado** |
//!
//! # Por que esto vive en el agente y no en el servidor
//!
//! Porque el identificador tiene que ser el mismo **en el sitio donde se observa**
//! y en el sitio donde se correlaciona. Si lo calculara el servidor, dos agentes
//! que ven la misma conexion la mandarian con identificadores distintos y el
//! servidor tendria que adivinar — que es exactamente el problema que esto viene a
//! quitar.
//!
//! Coste: una dependencia, `sha2`, que el agente **ya tenia** por `aegis-sync`. El
//! arbol de dependencias del endpoint no crece.

use core::fmt;

use sha2::{Digest, Sha256};

/// Longitud del identificador en caracteres hexadecimales.
///
/// Dieciseis bytes de un SHA-256. Con `2^128` valores posibles, la probabilidad
/// de colision en una flota de cien mil maquinas produciendo mil millones de
/// entidades al dia durante diez años sigue siendo despreciable — y un
/// identificador de sesenta y cuatro caracteres se lee mal en un panel, se copia
/// mal en un ticket y ocupa el doble en cada fila de la base.
pub const LARGO_ID: usize = 32;

/// Que clase de cosa es.
///
/// El prefijo va **en el identificador**, no solo en el tipo. Un `proc:a1b2…` se
/// distingue de un `file:a1b2…` en un registro de texto, en una consulta y en un
/// correo — y sin el, dos identificadores de clases distintas que empiecen igual
/// se confunden justo cuando alguien esta depurando a las tres de la mañana.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Clase {
    /// Un proceso concreto en una maquina concreta.
    Proceso,
    /// El CONTENIDO de un fichero, sea cual sea donde este.
    Contenido,
    /// Una UBICACION de fichero, sea cual sea lo que contenga.
    Ubicacion,
    /// Un flujo de red.
    Flujo,
    /// Una cuenta de usuario o de servicio.
    Cuenta,
    /// Una maquina de la flota.
    Maquina,
    /// El resultado de detonar una muestra con una configuracion.
    Artefacto,
    /// Una regla de deteccion.
    Regla,
}

impl Clase {
    /// El prefijo que lleva el identificador.
    #[must_use]
    pub fn prefijo(self) -> &'static str {
        match self {
            Clase::Proceso => "proc",
            Clase::Contenido => "cont",
            Clase::Ubicacion => "ubic",
            Clase::Flujo => "flujo",
            Clase::Cuenta => "cuenta",
            Clase::Maquina => "maq",
            Clase::Artefacto => "arte",
            Clase::Regla => "regla",
        }
    }

    /// Interpreta un prefijo.
    #[must_use]
    pub fn de_prefijo(s: &str) -> Option<Clase> {
        match s {
            "proc" => Some(Clase::Proceso),
            "cont" => Some(Clase::Contenido),
            "ubic" => Some(Clase::Ubicacion),
            "flujo" => Some(Clase::Flujo),
            "cuenta" => Some(Clase::Cuenta),
            "maq" => Some(Clase::Maquina),
            "arte" => Some(Clase::Artefacto),
            "regla" => Some(Clase::Regla),
            _ => None,
        }
    }

    /// Todas las clases, para recorrerlas sin olvidar ninguna.
    #[must_use]
    pub fn todas() -> &'static [Clase] {
        &[
            Clase::Proceso,
            Clase::Contenido,
            Clase::Ubicacion,
            Clase::Flujo,
            Clase::Cuenta,
            Clase::Maquina,
            Clase::Artefacto,
            Clase::Regla,
        ]
    }
}

/// El identificador de una entidad.
///
/// Estable, imprimible y **derivado**: dos observadores con los mismos hechos
/// producen el mismo identificador sin hablar entre ellos. Es la misma propiedad
/// que el reparto por sorteo de `aegis-scale`, y por la misma razon: coordinar
/// para ponerse de acuerdo en un nombre es coordinacion que se puede perder.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Eid {
    clase: Clase,
    digito: [u8; LARGO_ID / 2],
}

impl Eid {
    /// De que clase es.
    #[must_use]
    pub fn clase(&self) -> Clase {
        self.clase
    }

    /// El identificador como texto, con su prefijo.
    #[must_use]
    pub fn texto(&self) -> String {
        let mut s = String::with_capacity(LARGO_ID + 8);
        s.push_str(self.clase.prefijo());
        s.push(':');
        for b in &self.digito {
            s.push(hex(b >> 4));
            s.push(hex(b & 0x0f));
        }
        s
    }

    /// Lee un identificador escrito.
    ///
    /// Devuelve `None` si no tiene la forma. **No hay modo tolerante**: un
    /// identificador que no se entiende no se resuelve a uno cualquiera, porque
    /// resolverlo mal atribuye hechos a la entidad equivocada.
    #[must_use]
    pub fn de_texto(s: &str) -> Option<Eid> {
        let (p, resto) = s.split_once(':')?;
        let clase = Clase::de_prefijo(p)?;
        if resto.len() != LARGO_ID {
            return None;
        }
        let mut digito = [0u8; LARGO_ID / 2];
        for (i, par) in resto.as_bytes().chunks_exact(2).enumerate() {
            digito[i] = (desde_hex(par[0])? << 4) | desde_hex(par[1])?;
        }
        Some(Eid { clase, digito })
    }

    /// Deriva un identificador de una clase y unos campos.
    ///
    /// El separador entre campos es un byte que no puede aparecer dentro de
    /// ninguno (`0x1f`), y **la clase entra en el resumen**. Sin lo primero,
    /// `("ab", "c")` y `("a", "bc")` darian el mismo identificador; sin lo
    /// segundo, un contenido y una ubicacion con los mismos campos colisionarian
    /// en el digito y solo se distinguirian por el prefijo — que es un adorno si
    /// el digito ya choca.
    #[must_use]
    fn derivar(clase: Clase, campos: &[&[u8]]) -> Eid {
        let mut h = Sha256::new();
        h.update(clase.prefijo().as_bytes());
        for c in campos {
            h.update([0x1f]);
            h.update(c);
        }
        let d = h.finalize();
        let mut digito = [0u8; LARGO_ID / 2];
        digito.copy_from_slice(&d[..LARGO_ID / 2]);
        Eid { clase, digito }
    }
}

impl fmt::Display for Eid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.texto())
    }
}

impl fmt::Debug for Eid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Eid({})", self.texto())
    }
}

// ─── Las seis derivaciones, cada una con su regla escrita ─────────────────────

/// La identidad de una maquina de la flota.
///
/// # Por que la matriculacion y no el nombre ni el `machine-id`
///
/// El nombre se renombra. Y el `machine-id` **tampoco vale**: una imagen maestra
/// clonada produce cien maquinas con el mismo, y ese es el caso normal en
/// cualquier sitio con despliegue automatizado — no una rareza.
///
/// El identificador de matriculacion es lo unico que el plano de control emitio
/// **una sola vez para esa maquina**. Es el unico dato del que se sabe, por
/// construccion, que no se duplica al clonar.
#[must_use]
pub fn maquina(matricula: &str) -> Eid {
    Eid::derivar(Clase::Maquina, &[matricula.as_bytes()])
}

/// La identidad de un proceso.
///
/// # Por que hace falta el instante de arranque, y que pasa sin el
///
/// Los PID se reciclan. En una maquina cargada, en minutos. Sin el instante de
/// arranque, un proceso nuevo que hereda un PID reciclado **hereda tambien todo
/// lo que se sabia del anterior** — y lo que se sabia puede ser «esto es el
/// ransomware, contenlo».
///
/// Es una atribucion erronea, grave y silenciosa: no hay ningun error, el panel
/// enseña un proceso con su historia, y la historia es de otro.
///
/// # Y por que tambien el arranque de la MAQUINA
///
/// Porque el instante de arranque del proceso se mide desde el arranque del
/// sistema en varios sistemas operativos. Dos arranques distintos de la misma
/// maquina producen los mismos valores, y sin el `boot` colisionan igual.
#[must_use]
pub fn proceso(maquina: &Eid, boot: u64, pid: u32, arranque_ns: u64) -> Eid {
    Eid::derivar(
        Clase::Proceso,
        &[
            maquina.texto().as_bytes(),
            &boot.to_be_bytes(),
            &pid.to_be_bytes(),
            &arranque_ns.to_be_bytes(),
        ],
    )
}

/// La identidad del CONTENIDO de un fichero.
///
/// Es el resumen y nada mas: el mismo contenido en mil maquinas es **una**
/// entidad, y esa es justamente la que se comparte, se detona y se busca.
#[must_use]
pub fn contenido(sha256: &str) -> Eid {
    Eid::derivar(
        Clase::Contenido,
        &[sha256.trim().to_ascii_lowercase().as_bytes()],
    )
}

/// La identidad de una UBICACION de fichero.
///
/// # Por que es una entidad distinta del contenido
///
/// Son dos preguntas que no se contestan igual:
///
/// - «¿Que hizo este fichero?» pregunta por el **contenido**, y la respuesta es
///   la misma en las mil maquinas donde este.
/// - «¿Que pusimos en cuarentena?» pregunta por la **ubicacion**, y la respuesta
///   es una ruta en una maquina.
///
/// Un fichero modificado es **contenido nuevo en la misma ubicacion**, y una
/// copia es **el mismo contenido en otra ubicacion**. Con una sola entidad, las
/// dos frases anteriores no se pueden ni escribir.
///
/// La ruta se normaliza: minusculas y barras hacia delante. En Windows, `C:\X\y`
/// y `c:/x/Y` son el mismo fichero, y tratarlos como dos parte el linaje por la
/// mitad segun que subsistema lo escribiera.
#[must_use]
pub fn ubicacion(maquina: &Eid, ruta: &str) -> Eid {
    Eid::derivar(
        Clase::Ubicacion,
        &[maquina.texto().as_bytes(), normalizar_ruta(ruta).as_bytes()],
    )
}

/// La identidad de un flujo de red.
///
/// # La quintupla se ordena, y esa es la decision que importa
///
/// La misma conexion vista desde los dos extremos tiene que producir **el mismo
/// identificador**. Si no, el linaje de un ataque se parte en dos justo donde
/// cruza la red — que es donde mas falta hace que no se parta.
///
/// Se consigue ordenando los dos extremos: el menor primero. Como efecto
/// secundario, la identidad deja de depender de quien inicio la conexion, que a
/// menudo no se sabe cuando se observa a mitad.
///
/// # Y por que el primer instante forma parte de la identidad
///
/// Porque una quintupla se reutiliza: los puertos efimeros se reciclan, y en una
/// maquina que abre muchas conexiones, en segundos. Sin el instante, dos
/// conexiones consecutivas al mismo destino son **la misma entidad**, y lo que
/// hizo la segunda se le atribuye a la primera.
#[must_use]
pub fn flujo(maquina: &Eid, a: (&str, u16), b: (&str, u16), protocolo: u8, primer_ns: u64) -> Eid {
    let (x, y) = if (a.0, a.1) <= (b.0, b.1) {
        (a, b)
    } else {
        (b, a)
    };
    Eid::derivar(
        Clase::Flujo,
        &[
            maquina.texto().as_bytes(),
            x.0.as_bytes(),
            &x.1.to_be_bytes(),
            y.0.as_bytes(),
            &y.1.to_be_bytes(),
            &[protocolo],
            &primer_ns.to_be_bytes(),
        ],
    )
}

/// La identidad de una cuenta.
///
/// # Por que el identificador del directorio y no el nombre
///
/// `CORP\maria.lopez`, `maria.lopez@corp.local` y `María López` son la misma
/// persona, y **ninguno de los tres es estable**: la gente se casa, cambia de
/// departamento, y los dominios se migran. El identificador del directorio —el
/// SID en Windows, el UUID en un directorio moderno— no cambia con nada de eso.
///
/// Ademas es el unico que no se puede confundir entre dominios: dos dominios
/// distintos tienen su `maria.lopez`, y son dos personas.
#[must_use]
pub fn cuenta(identificador_directorio: &str) -> Eid {
    Eid::derivar(
        Clase::Cuenta,
        &[identificador_directorio
            .trim()
            .to_ascii_uppercase()
            .as_bytes()],
    )
}

/// La identidad del resultado de detonar una muestra.
///
/// # Por que la configuracion entra en la identidad
///
/// Dos detonaciones de la misma muestra con configuracion distinta **no son el
/// mismo resultado**. Una con la red apagada dice «no hizo nada»; la misma con
/// red simulada dice «cifro todo». Tratarlas como una sola entidad hace que la
/// primera tape a la segunda —o al reves, segun cual llegue despues— y el
/// veredicto dependa del orden.
#[must_use]
pub fn artefacto(sha256_muestra: &str, resumen_configuracion: &str) -> Eid {
    Eid::derivar(
        Clase::Artefacto,
        &[
            sha256_muestra.trim().to_ascii_lowercase().as_bytes(),
            resumen_configuracion.as_bytes(),
        ],
    )
}

/// La identidad de una regla de deteccion.
#[must_use]
pub fn regla(espacio: &str, nombre: &str) -> Eid {
    Eid::derivar(
        Clase::Regla,
        &[espacio.as_bytes(), nombre.trim().as_bytes()],
    )
}

/// Normaliza una ruta para que dos escrituras de la misma den lo mismo.
///
/// Minusculas y barras hacia delante. En Windows, `C:\X\y` y `c:/x/Y` son el
/// mismo fichero; tratarlos como dos parte el linaje segun que subsistema lo
/// escribiera, y esa es la clase de fallo que solo se ve cuando el incidente ya
/// esta cerrado.
#[must_use]
pub fn normalizar_ruta(ruta: &str) -> String {
    ruta.trim()
        .chars()
        .map(|c| {
            if c == '\\' {
                '/'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

fn hex(n: u8) -> char {
    char::from(if n < 10 { b'0' + n } else { b'a' + n - 10 })
}

fn desde_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn maq() -> Eid {
        maquina("matricula-4f2a")
    }

    #[test]
    fn dos_observadores_con_los_mismos_hechos_dan_el_mismo_identificador() {
        // Es la propiedad que permite correlacionar sin coordinar: dos agentes
        // que ven lo mismo lo nombran igual sin hablar entre ellos.
        let a = proceso(&maq(), 7, 4242, AHORA);
        let b = proceso(&maquina("matricula-4f2a"), 7, 4242, AHORA);
        assert_eq!(a, b);
        assert_eq!(a.texto(), b.texto());
    }

    #[test]
    fn un_pid_reciclado_no_hereda_la_historia_del_anterior() {
        // El fallo mas grave que este modulo impide, y es silencioso: no hay
        // error, el panel enseña un proceso con su historia, y la historia es de
        // otro — que puede decir «esto es el ransomware, contenlo».
        let viejo = proceso(&maq(), 7, 4242, AHORA);
        let nuevo = proceso(&maq(), 7, 4242, AHORA + 30 * SEG);
        assert_ne!(viejo, nuevo, "un PID reciclado dio la misma entidad");
    }

    #[test]
    fn dos_arranques_de_la_misma_maquina_no_colisionan() {
        // El instante de arranque del proceso se mide desde el arranque del
        // sistema en varios sistemas operativos: sin el `boot`, dos arranques
        // producen los mismos valores.
        assert_ne!(
            proceso(&maq(), 7, 4242, AHORA),
            proceso(&maq(), 8, 4242, AHORA)
        );
    }

    #[test]
    fn el_mismo_pid_en_dos_maquinas_son_dos_procesos() {
        assert_ne!(
            proceso(&maquina("m-a"), 1, 4242, AHORA),
            proceso(&maquina("m-b"), 1, 4242, AHORA)
        );
    }

    #[test]
    fn el_contenido_y_la_ubicacion_son_entidades_distintas() {
        // «¿Que hizo este fichero?» pregunta por el contenido; «¿que pusimos en
        // cuarentena?» pregunta por la ubicacion. Con una sola entidad, las dos
        // frases no se pueden ni escribir.
        let c = contenido("7f1e3c9b");
        let u = ubicacion(&maq(), "C:\\Windows\\Temp\\x.exe");
        assert_ne!(c.clase(), u.clase());
        assert_ne!(c, u);

        // El mismo contenido en mil maquinas es UNA entidad.
        assert_eq!(contenido("7f1e3c9b"), contenido("7F1E3C9B"));
        // Y la misma ruta en dos maquinas son DOS.
        assert_ne!(
            ubicacion(&maquina("m-a"), "/tmp/x"),
            ubicacion(&maquina("m-b"), "/tmp/x")
        );
    }

    #[test]
    fn un_fichero_modificado_es_contenido_nuevo_en_la_misma_ubicacion() {
        let sitio = ubicacion(&maq(), "/opt/app/bin");
        let antes = contenido("aaaa");
        let despues = contenido("bbbb");
        assert_eq!(sitio, ubicacion(&maq(), "/opt/app/bin"));
        assert_ne!(antes, despues);
    }

    #[test]
    fn la_ruta_se_normaliza_entre_windows_y_unix() {
        // Tratarlas como dos parte el linaje segun que subsistema lo escribiera, y
        // eso solo se ve cuando el incidente ya esta cerrado.
        assert_eq!(
            ubicacion(&maq(), "C:\\Windows\\Temp\\X.exe"),
            ubicacion(&maq(), "c:/windows/temp/x.exe")
        );
        assert_eq!(normalizar_ruta(" C:\\A\\B "), "c:/a/b");
    }

    #[test]
    fn el_mismo_flujo_visto_desde_los_dos_extremos_es_uno() {
        // Si no, el linaje de un ataque se parte en dos justo donde cruza la red,
        // que es donde mas falta hace que no se parta.
        let cliente = flujo(
            &maq(),
            ("10.0.0.5", 51234),
            ("93.184.216.34", 443),
            6,
            AHORA,
        );
        let servidor = flujo(
            &maq(),
            ("93.184.216.34", 443),
            ("10.0.0.5", 51234),
            6,
            AHORA,
        );
        assert_eq!(cliente, servidor);
    }

    #[test]
    fn un_puerto_efimero_reciclado_no_funde_dos_conexiones() {
        // Los puertos efimeros se reciclan en segundos en una maquina que abre
        // muchas conexiones; sin el instante, lo que hizo la segunda se le
        // atribuye a la primera.
        let uno = flujo(&maq(), ("10.0.0.5", 51234), ("1.2.3.4", 443), 6, AHORA);
        let dos = flujo(
            &maq(),
            ("10.0.0.5", 51234),
            ("1.2.3.4", 443),
            6,
            AHORA + SEG,
        );
        assert_ne!(uno, dos);
    }

    #[test]
    fn el_protocolo_distingue_dos_flujos_con_la_misma_tupla() {
        assert_ne!(
            flujo(&maq(), ("10.0.0.5", 53), ("8.8.8.8", 53), 6, AHORA),
            flujo(&maq(), ("10.0.0.5", 53), ("8.8.8.8", 53), 17, AHORA)
        );
    }

    #[test]
    fn la_cuenta_se_identifica_por_el_directorio_y_no_por_el_nombre() {
        // La gente se casa, cambia de departamento, y los dominios se migran. El
        // identificador del directorio no cambia con nada de eso.
        let sid = "S-1-5-21-1004336348-1177238915-682003330-512";
        assert_eq!(cuenta(sid), cuenta(&sid.to_ascii_lowercase()));
        // Y dos dominios distintos tienen su maria.lopez, que son dos personas.
        assert_ne!(cuenta("S-1-5-21-AAA-512"), cuenta("S-1-5-21-BBB-512"));
    }

    #[test]
    fn dos_detonaciones_con_configuracion_distinta_son_dos_artefactos() {
        // Una con la red apagada dice «no hizo nada»; la misma con red simulada
        // dice «cifro todo». Tratarlas como una hace que el veredicto dependa del
        // orden de llegada.
        assert_ne!(
            artefacto("7f1e", "red=ninguna"),
            artefacto("7f1e", "red=simulada")
        );
        assert_eq!(
            artefacto("7f1e", "red=simulada"),
            artefacto("7F1E", "red=simulada")
        );
    }

    #[test]
    fn el_separador_impide_que_dos_reparticiones_colisionen() {
        // Sin un separador que no pueda aparecer dentro de un campo, ("ab","c") y
        // ("a","bc") darian el mismo identificador.
        assert_ne!(regla("ab", "c"), regla("a", "bc"));
    }

    #[test]
    fn la_clase_entra_en_el_resumen_y_no_solo_en_el_prefijo() {
        // Si solo estuviera en el prefijo, dos clases con los mismos campos
        // colisionarian en el digito y el prefijo seria un adorno.
        let a = contenido("mismo-valor");
        let b = regla("", "mismo-valor");
        assert_ne!(a.texto()[5..], b.texto()[6..]);
    }

    #[test]
    fn la_ida_y_vuelta_del_texto_es_estable() {
        // El identificador viaja por registros, tickets y correos: si no volviera
        // a leerse igual, cada salto lo perderia.
        for e in [
            maq(),
            proceso(&maq(), 1, 2, 3),
            contenido("abc"),
            ubicacion(&maq(), "/x"),
            flujo(&maq(), ("a", 1), ("b", 2), 6, 3),
            cuenta("S-1-5"),
            artefacto("abc", "cfg"),
            regla("yara", "lockbit"),
        ] {
            let t = e.texto();
            assert_eq!(Eid::de_texto(&t), Some(e.clone()), "ida y vuelta de {t}");
            assert!(t.starts_with(e.clase().prefijo()));
            assert_eq!(t.len(), e.clase().prefijo().len() + 1 + LARGO_ID);
        }
    }

    #[test]
    fn un_identificador_mal_escrito_no_se_resuelve_a_uno_cualquiera() {
        // Resolverlo mal atribuye hechos a la entidad equivocada.
        for s in [
            "",
            "proc",
            "proc:",
            "proc:abc",
            "desconocido:00000000000000000000000000000000",
            "proc:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "proc:000000000000000000000000000000000",
        ] {
            assert!(Eid::de_texto(s).is_none(), "«{s}» no deberia leerse");
        }
    }

    #[test]
    fn cada_clase_tiene_su_prefijo_y_no_se_repiten() {
        let mut vistos: Vec<&str> = Clase::todas().iter().map(|c| c.prefijo()).collect();
        assert_eq!(vistos.len(), 8);
        vistos.sort_unstable();
        vistos.dedup();
        assert_eq!(vistos.len(), 8, "dos clases comparten prefijo");
        for c in Clase::todas() {
            assert_eq!(Clase::de_prefijo(c.prefijo()), Some(*c));
        }
    }

    #[test]
    fn el_identificador_se_lee_en_un_panel_sin_ocupar_media_pantalla() {
        // Sesenta y cuatro caracteres se leen mal, se copian mal en un ticket y
        // ocupan el doble en cada fila de la base. El mas largo de todos cabe en
        // cuarenta.
        for c in Clase::todas() {
            let largo = c.prefijo().len() + 1 + LARGO_ID;
            assert!(largo <= 40, "«{}» produce {largo} caracteres", c.prefijo());
        }
        assert_eq!(maq().texto().len(), "maq".len() + 1 + LARGO_ID);
    }
}
