//! Artefactos grandes por trozos: paquetes de reglas YARA y modelos.
//!
//! # Por que hace falta y por que la malla de la FASE 23 no servia
//!
//! Un mensaje de [`aegis_mesh`](../../aegis_mesh/index.html) cabe en un
//! datagrama de menos de 1200 bytes, y eso es su diseno, no su limitacion: un
//! indicador es un hash y cuatro campos. Un **paquete de reglas YARA** son
//! decenas o cientos de kilobytes. Repartirlo exige trocear, y trocear exige
//! reensamblar, que es una superficie de ataque clasica —la de los fragmentos IP
//! y sus dos decadas de CVE—. Por eso el reensamblado de aqui esta acotado por
//! todos lados.
//!
//! # La propiedad de la que depende todo: el tamano viene de lo FIRMADO
//!
//! El descriptor lo firma el plano de control y declara identificador de
//! contenido, tamano total, tamano de trozo y el hash de cada trozo. **El
//! receptor reserva memoria segun el descriptor, jamas segun lo que diga un
//! trozo.** Si el tamano lo pusiera un trozo, un par mandaria uno que dice
//! «desplazamiento 4 GiB» y el receptor reservaria 4 GiB: denegacion de servicio
//! con un mensaje de 50 bytes.
//!
//! # Cada trozo se comprueba al llegar, no al final
//!
//! El descriptor lleva el hash de cada trozo. Un trozo que no cuadra se descarta
//! en el acto y se vuelve a pedir. Verificar solo al final tendria dos defectos:
//! un unico trozo corrupto obligaria a repetir la transferencia entera, y —lo
//! serio— un par malicioso podria envenenar la reconstruccion gratis, porque
//! hasta el ultimo byte no se sabria que algo iba mal.
//!
//! Al final se comprueba **ademas** el hash del conjunto: los hashes de trozo
//! prueban que cada pieza es la que toca, y el del conjunto que estan todas y en
//! su sitio.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::error::ErrorEnjambre;
use crate::mensaje::{escribir_texto, escribir_u64, lector::Lector};

/// Contexto de firma de los descriptores de artefacto.
pub const CTX_ARTEFACTO: &[u8] = b"aegis-swarm/artefacto/v1";

/// Tamano de trozo por defecto: 16 KiB.
pub const TAM_TROZO: usize = 16 * 1024;

/// Tope de un artefacto: 8 MiB.
///
/// Un paquete de reglas YARA de una flota entera no llega; lo que si llegaria es
/// un «artefacto» inventado para agotar el disco y la memoria del endpoint.
pub const MAX_ARTEFACTO: usize = 8 * 1024 * 1024;

/// Tope de trozos, derivado del anterior.
pub const MAX_TROZOS: usize = MAX_ARTEFACTO / 1024;

/// Clase de artefacto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaseArtefacto {
    /// Paquete de reglas YARA.
    ReglasYara,
    /// Modelo de inferencia.
    Modelo,
}

impl ClaseArtefacto {
    /// Discriminante de red.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            ClaseArtefacto::ReglasYara => 1,
            ClaseArtefacto::Modelo => 2,
        }
    }

    /// Recupera la clase desde su discriminante.
    #[must_use]
    pub fn desde_tag(t: u8) -> Option<ClaseArtefacto> {
        match t {
            1 => Some(ClaseArtefacto::ReglasYara),
            2 => Some(ClaseArtefacto::Modelo),
            _ => None,
        }
    }
}

/// Descriptor firmado de un artefacto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// Que es.
    pub clase: ClaseArtefacto,
    /// Nombre legible, para el registro.
    pub nombre: String,
    /// SHA-256 del contenido completo: su identificador.
    pub id: [u8; 32],
    /// Tamano total en bytes.
    pub tamano: u64,
    /// Tamano de cada trozo menos el ultimo.
    pub tam_trozo: u32,
    /// SHA-256 de cada trozo, en orden.
    pub hashes: Vec<[u8; 32]>,
}

impl Descriptor {
    /// Construye el descriptor de un contenido.
    ///
    /// # Errores
    /// [`ErrorEnjambre::LimiteExcedido`] si el contenido pasa de
    /// [`MAX_ARTEFACTO`].
    pub fn de_contenido(
        clase: ClaseArtefacto,
        nombre: &str,
        contenido: &[u8],
        tam_trozo: usize,
    ) -> Result<Descriptor, ErrorEnjambre> {
        if contenido.len() > MAX_ARTEFACTO {
            return Err(ErrorEnjambre::LimiteExcedido {
                campo: "artefacto",
                valor: contenido.len(),
                tope: MAX_ARTEFACTO,
            });
        }
        let tam = tam_trozo.clamp(1, TAM_TROZO * 4);
        let hashes: Vec<[u8; 32]> = contenido
            .chunks(tam)
            .map(|c| Sha256::digest(c).into())
            .collect();
        Ok(Descriptor {
            clase,
            nombre: nombre.to_string(),
            id: Sha256::digest(contenido).into(),
            tamano: contenido.len() as u64,
            tam_trozo: u32::try_from(tam).unwrap_or(u32::MAX),
            hashes,
        })
    }

    /// Numero de trozos que declara.
    #[must_use]
    pub fn trozos(&self) -> usize {
        self.hashes.len()
    }

    /// Los bytes que cubre la firma del plano de control.
    #[must_use]
    pub fn bytes_firmados(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(CTX_ARTEFACTO);
        v.extend_from_slice(&self.a_bytes());
        v
    }

    /// Serializa el descriptor.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(self.clase.tag());
        escribir_texto(&mut v, &self.nombre);
        v.extend_from_slice(&self.id);
        escribir_u64(&mut v, self.tamano);
        v.extend_from_slice(&self.tam_trozo.to_le_bytes());
        v.extend_from_slice(&(self.hashes.len() as u32).to_le_bytes());
        for h in &self.hashes {
            v.extend_from_slice(h);
        }
        v
    }

    /// Analiza un descriptor.
    ///
    /// # Errores
    /// Truncamiento, clase desconocida, o un numero de trozos incoherente con el
    /// tamano declarado.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Descriptor, ErrorEnjambre> {
        let mut l = Lector::nuevo(bytes);
        let tag = l.u8("clase")?;
        let clase = ClaseArtefacto::desde_tag(tag).ok_or(ErrorEnjambre::TipoDesconocido(tag))?;
        let nombre = l.texto("nombre")?;
        let id = l.hash("id")?;
        let tamano = l.u64("tamano")?;
        let tam_trozo = l.u32("tam_trozo")?;
        let n = l.u32("num_trozos")? as usize;

        if tamano > MAX_ARTEFACTO as u64 {
            return Err(ErrorEnjambre::LimiteExcedido {
                campo: "tamano",
                valor: usize::try_from(tamano).unwrap_or(usize::MAX),
                tope: MAX_ARTEFACTO,
            });
        }
        if n > MAX_TROZOS {
            return Err(ErrorEnjambre::LimiteExcedido {
                campo: "num_trozos",
                valor: n,
                tope: MAX_TROZOS,
            });
        }
        // La cuenta de trozos se comprueba ANTES de reservar: sin esto, un
        // descriptor que dice tener un millon de trozos reserva 32 MB de hashes
        // aunque el buffer que lo trae tenga 50 bytes.
        if n.saturating_mul(32) > l.restante() {
            return Err(ErrorEnjambre::LongitudImposible {
                campo: "hashes",
                declarada: n.saturating_mul(32),
                disponible: l.restante(),
            });
        }
        let mut hashes = Vec::with_capacity(n);
        for _ in 0..n {
            hashes.push(l.hash("hash_trozo")?);
        }

        let d = Descriptor {
            clase,
            nombre,
            id,
            tamano,
            tam_trozo,
            hashes,
        };
        d.coherente()?;
        Ok(d)
    }

    /// Comprueba que tamano, tamano de trozo y numero de trozos cuadren.
    ///
    /// Un descriptor incoherente no es un error inofensivo: si el numero de
    /// trozos no se dedujera del tamano, un descriptor podria declarar mil
    /// trozos para un contenido de un byte y el receptor esperaria para siempre
    /// trozos que no existen, ocupando una ranura de reensamblado.
    ///
    /// # Errores
    /// [`ErrorEnjambre::TrozoIncoherente`] si no cuadran.
    pub fn coherente(&self) -> Result<(), ErrorEnjambre> {
        if self.tam_trozo == 0 {
            return Err(ErrorEnjambre::TrozoIncoherente("tamano de trozo cero"));
        }
        let esperados = self.tamano.div_ceil(u64::from(self.tam_trozo)) as usize;
        if esperados != self.hashes.len() {
            return Err(ErrorEnjambre::TrozoIncoherente(
                "el numero de trozos no se deduce del tamano",
            ));
        }
        if self.tamano == 0 && !self.hashes.is_empty() {
            return Err(ErrorEnjambre::TrozoIncoherente("tamano cero con trozos"));
        }
        Ok(())
    }
}

/// Un trozo en transito.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trozo {
    /// A que artefacto pertenece.
    pub id: [u8; 32],
    /// Indice, desde cero.
    pub indice: u32,
    /// Contenido.
    pub datos: Vec<u8>,
}

impl Trozo {
    /// Serializa el trozo.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(40 + self.datos.len());
        v.extend_from_slice(&self.id);
        v.extend_from_slice(&self.indice.to_le_bytes());
        v.extend_from_slice(&(self.datos.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.datos);
        v
    }

    /// Analiza un trozo.
    ///
    /// # Errores
    /// Truncamiento o longitud declarada que no cabe.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Trozo, ErrorEnjambre> {
        let mut l = Lector::nuevo(bytes);
        let id = l.hash("id")?;
        let indice = l.u32("indice")?;
        let n = l.u32("longitud")? as usize;
        if n > l.restante() {
            return Err(ErrorEnjambre::LongitudImposible {
                campo: "datos",
                declarada: n,
                disponible: l.restante(),
            });
        }
        let mut datos = vec![0u8; n];
        datos.copy_from_slice(&bytes[bytes.len() - l.restante()..][..n]);
        Ok(Trozo { id, indice, datos })
    }
}

/// Reensamblado acotado de un artefacto.
#[derive(Debug, Clone)]
pub struct Reensamblado {
    descriptor: Descriptor,
    piezas: BTreeMap<u32, Vec<u8>>,
}

impl Reensamblado {
    /// Empieza un reensamblado a partir de un descriptor **ya verificado**.
    ///
    /// # Errores
    /// [`ErrorEnjambre::TrozoIncoherente`] si el descriptor no cuadra consigo
    /// mismo.
    pub fn nuevo(descriptor: Descriptor) -> Result<Reensamblado, ErrorEnjambre> {
        descriptor.coherente()?;
        Ok(Reensamblado {
            descriptor,
            piezas: BTreeMap::new(),
        })
    }

    /// El descriptor que gobierna este reensamblado.
    #[must_use]
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    /// Trozos que faltan, para pedirlos.
    #[must_use]
    pub fn faltan(&self) -> Vec<u32> {
        (0..self.descriptor.trozos() as u32)
            .filter(|i| !self.piezas.contains_key(i))
            .collect()
    }

    /// Si ya estan todos.
    #[must_use]
    pub fn completo(&self) -> bool {
        self.piezas.len() == self.descriptor.trozos()
    }

    /// Incorpora un trozo, comprobandolo contra el descriptor firmado.
    ///
    /// # Errores
    /// [`ErrorEnjambre::TrozoIncoherente`] si el trozo no es de este artefacto,
    /// su indice no existe, su tamano no es el que toca o su hash no cuadra.
    pub fn incorporar(&mut self, t: &Trozo) -> Result<(), ErrorEnjambre> {
        if t.id != self.descriptor.id {
            return Err(ErrorEnjambre::TrozoIncoherente("es de otro artefacto"));
        }
        let i = t.indice as usize;
        let esperado = self
            .descriptor
            .hashes
            .get(i)
            .ok_or(ErrorEnjambre::TrozoIncoherente(
                "indice fuera del descriptor",
            ))?;

        // El tamano del trozo lo fija el DESCRIPTOR FIRMADO, no el trozo. Todos
        // miden `tam_trozo` menos el ultimo, que mide el resto.
        let tam = self.descriptor.tam_trozo as usize;
        let ultimo = self.descriptor.trozos().saturating_sub(1);
        let esperado_tam = if i == ultimo {
            let resto = (self.descriptor.tamano as usize) % tam;
            if resto == 0 {
                tam
            } else {
                resto
            }
        } else {
            tam
        };
        if t.datos.len() != esperado_tam {
            return Err(ErrorEnjambre::TrozoIncoherente(
                "el tamano no es el que el descriptor firmado declara",
            ));
        }

        let real: [u8; 32] = Sha256::digest(&t.datos).into();
        if &real != esperado {
            return Err(ErrorEnjambre::TrozoIncoherente(
                "el hash del trozo no es el del descriptor",
            ));
        }
        self.piezas.insert(t.indice, t.datos.clone());
        Ok(())
    }

    /// Cierra el reensamblado y devuelve el contenido.
    ///
    /// # Errores
    /// [`ErrorEnjambre::TrozoIncoherente`] si faltan trozos, o
    /// [`ErrorEnjambre::ContenidoNoCoincide`] si el conjunto no da el hash
    /// prometido.
    pub fn terminar(self) -> Result<Vec<u8>, ErrorEnjambre> {
        if !self.completo() {
            return Err(ErrorEnjambre::TrozoIncoherente("faltan trozos"));
        }
        let mut v = Vec::with_capacity(self.descriptor.tamano as usize);
        for i in 0..self.descriptor.trozos() as u32 {
            let p = self
                .piezas
                .get(&i)
                .ok_or(ErrorEnjambre::TrozoIncoherente("falta un trozo"))?;
            v.extend_from_slice(p);
        }
        // Los hashes de trozo prueban que cada pieza es la que toca; este prueba
        // que estan todas y en su sitio. Las dos cosas no son la misma.
        let real: [u8; 32] = Sha256::digest(&v).into();
        if real != self.descriptor.id {
            return Err(ErrorEnjambre::ContenidoNoCoincide);
        }
        Ok(v)
    }
}

/// Trocea un contenido segun su descriptor.
#[must_use]
pub fn trocear(d: &Descriptor, contenido: &[u8]) -> Vec<Trozo> {
    contenido
        .chunks(d.tam_trozo as usize)
        .enumerate()
        .map(|(i, c)| Trozo {
            id: d.id,
            indice: u32::try_from(i).unwrap_or(u32::MAX),
            datos: c.to_vec(),
        })
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn reglas() -> Vec<u8> {
        // Un paquete de reglas YARA plausible: varios miles de bytes.
        let mut v = Vec::new();
        for i in 0..200 {
            v.extend_from_slice(
                format!("rule aegis_{i} {{ strings: $a = \"malicioso{i}\" condition: $a }}\n")
                    .as_bytes(),
            );
        }
        v
    }

    #[test]
    fn un_paquete_de_reglas_viaja_por_trozos_y_vuelve_identico() {
        let contenido = reglas();
        let d = Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "flota-v7", &contenido, 1024)
            .expect("descriptor");
        assert!(d.trozos() > 1, "el caso interesante es con varios trozos");

        let mut r = Reensamblado::nuevo(d.clone()).expect("reensamblado");
        assert_eq!(r.faltan().len(), d.trozos());
        for t in trocear(&d, &contenido) {
            r.incorporar(&t).expect("trozo bueno");
        }
        assert!(r.completo());
        assert_eq!(r.terminar().expect("cierre"), contenido);
    }

    /// EL TROZO ENVENENADO: se rechaza AL LLEGAR, no al final.
    #[test]
    fn un_trozo_alterado_se_rechaza_en_el_acto_y_no_envenena_la_reconstruccion() {
        let contenido = reglas();
        let d = Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "f", &contenido, 1024)
            .expect("descriptor");
        let mut trozos = trocear(&d, &contenido);
        trozos[2].datos[0] ^= 0xFF;

        let mut r = Reensamblado::nuevo(d).expect("reensamblado");
        let mut rechazados = 0;
        for t in &trozos {
            if r.incorporar(t).is_err() {
                rechazados += 1;
            }
        }
        assert_eq!(rechazados, 1, "solo el envenenado");
        assert!(!r.completo(), "el envenenado no cuenta como recibido");
        assert_eq!(r.faltan(), vec![2], "y se sabe cual hay que volver a pedir");
    }

    /// EL ATAQUE DE MEMORIA: un trozo que miente sobre su tamano no puede hacer
    /// que el receptor reserve lo que el diga. El tamano lo pone el descriptor.
    #[test]
    fn un_trozo_con_un_tamano_que_el_descriptor_no_declara_se_rechaza() {
        let contenido = reglas();
        let d = Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "f", &contenido, 1024)
            .expect("descriptor");
        let mut r = Reensamblado::nuevo(d.clone()).expect("reensamblado");

        let gordo = Trozo {
            id: d.id,
            indice: 0,
            datos: vec![0u8; 1_000_000],
        };
        assert!(matches!(
            r.incorporar(&gordo),
            Err(ErrorEnjambre::TrozoIncoherente(_))
        ));
    }

    #[test]
    fn un_trozo_de_otro_artefacto_no_se_cuela() {
        let a = Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "a", b"aaaa", 2).expect("a");
        let b = Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "b", b"bbbb", 2).expect("b");
        let mut r = Reensamblado::nuevo(a).expect("reensamblado");
        let ajeno = trocear(&b, b"bbbb").remove(0);
        assert!(matches!(
            r.incorporar(&ajeno),
            Err(ErrorEnjambre::TrozoIncoherente(_))
        ));
    }

    #[test]
    fn un_indice_fuera_del_descriptor_se_rechaza() {
        let d = Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "a", b"aaaa", 2).expect("d");
        let mut r = Reensamblado::nuevo(d.clone()).expect("reensamblado");
        let fuera = Trozo {
            id: d.id,
            indice: 9999,
            datos: vec![0u8; 2],
        };
        assert!(matches!(
            r.incorporar(&fuera),
            Err(ErrorEnjambre::TrozoIncoherente(_))
        ));
    }

    /// Un descriptor que dice tener un millon de trozos no puede hacer que el
    /// receptor reserve 32 MB de hashes con un buffer de 50 bytes.
    #[test]
    fn un_descriptor_con_una_cuenta_de_trozos_absurda_no_reserva_memoria() {
        let mut v = Vec::new();
        v.push(ClaseArtefacto::ReglasYara.tag());
        escribir_texto(&mut v, "mentiroso");
        v.extend_from_slice(&[0u8; 32]);
        escribir_u64(&mut v, 1024);
        v.extend_from_slice(&16u32.to_le_bytes());
        v.extend_from_slice(&1_000_000u32.to_le_bytes());
        // Y nada mas: promete un millon de hashes y no trae ninguno.
        assert!(matches!(
            Descriptor::desde_bytes(&v),
            Err(ErrorEnjambre::LongitudImposible { .. } | ErrorEnjambre::LimiteExcedido { .. })
        ));
    }

    #[test]
    fn un_descriptor_incoherente_se_rechaza_en_vez_de_esperar_trozos_inexistentes() {
        let mut d =
            Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "a", b"aaaa", 2).expect("d");
        d.hashes.push([0u8; 32]);
        assert!(matches!(
            d.coherente(),
            Err(ErrorEnjambre::TrozoIncoherente(_))
        ));
        assert!(Reensamblado::nuevo(d).is_err());
    }

    #[test]
    fn un_artefacto_mas_grande_que_el_tope_no_se_acepta() {
        let enorme = vec![0u8; MAX_ARTEFACTO + 1];
        assert!(matches!(
            Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "x", &enorme, TAM_TROZO),
            Err(ErrorEnjambre::LimiteExcedido { .. })
        ));
    }

    #[test]
    fn el_descriptor_va_y_vuelve_sin_perder_nada() {
        let contenido = reglas();
        let d = Descriptor::de_contenido(ClaseArtefacto::Modelo, "modelo-v2", &contenido, 512)
            .expect("d");
        assert_eq!(Descriptor::desde_bytes(&d.a_bytes()).expect("vuelta"), d);
    }

    #[test]
    fn cualquier_prefijo_de_un_descriptor_o_un_trozo_se_rechaza_sin_panico() {
        let d =
            Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "a", b"abcdefgh", 3).expect("d");
        let bytes = d.a_bytes();
        for corte in 0..bytes.len() {
            assert!(
                Descriptor::desde_bytes(&bytes[..corte]).is_err(),
                "corte {corte}"
            );
        }
        let t = trocear(&d, b"abcdefgh").remove(0);
        let tb = t.a_bytes();
        for corte in 0..tb.len() {
            assert!(Trozo::desde_bytes(&tb[..corte]).is_err(), "corte {corte}");
        }
    }

    #[test]
    fn un_trozo_va_y_vuelve_sin_perder_nada() {
        let d =
            Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "a", b"abcdefgh", 3).expect("d");
        for t in trocear(&d, b"abcdefgh") {
            assert_eq!(Trozo::desde_bytes(&t.a_bytes()).expect("vuelta"), t);
        }
    }

    #[test]
    fn el_ultimo_trozo_puede_ser_mas_corto_y_se_admite_solo_el() {
        // 8 bytes en trozos de 3: 3 + 3 + 2.
        let d =
            Descriptor::de_contenido(ClaseArtefacto::ReglasYara, "a", b"abcdefgh", 3).expect("d");
        assert_eq!(d.trozos(), 3);
        let trozos = trocear(&d, b"abcdefgh");
        assert_eq!(trozos[2].datos.len(), 2);

        let mut r = Reensamblado::nuevo(d.clone()).expect("r");
        for t in &trozos {
            r.incorporar(t).expect("todos validos");
        }
        assert_eq!(r.terminar().expect("cierre"), b"abcdefgh");

        // Pero un trozo intermedio corto NO se admite.
        let mut r = Reensamblado::nuevo(d).expect("r");
        let mut corto = trozos[0].clone();
        corto.datos.truncate(2);
        assert!(r.incorporar(&corto).is_err());
    }
}
