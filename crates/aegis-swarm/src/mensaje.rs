//! Formato de red del enjambre y el lector acotado que lo analiza.
//!
//! # Todo lo que se lee viene de un par que puede estar comprometido
//!
//! La FASE 23 asumia una clave simetrica compartida por la red local, y aun asi
//! documentaba que un equipo comprometido puede emitir mensajes validos. Aqui
//! la asuncion es la misma y mas fuerte: **cada byte que entra lo escribio
//! alguien que puede ser el atacante**. Por eso no hay ni un `unwrap` sobre la
//! entrada, ni un indice calculado sin comprobar, ni una longitud que se crea
//! sin cotejar con lo que queda.
//!
//! El [`Lector`] existe para que eso no dependa de la disciplina de quien
//! escriba cada `desde_bytes`: pedir un campo que no cabe devuelve un error con
//! nombre, siempre, y no hay forma de saltarselo sin escribir otro lector.
//!
//! # Por que un formato explicito y no una biblioteca de serializacion
//!
//! Un formato de red de un producto de seguridad es una superficie de ataque que
//! hay que poder leer entera en una sentada. Ademas, los discriminantes y el
//! orden de los campos son un **contrato entre versiones del agente**: dos
//! agentes de versiones distintas tienen que interpretar el mismo byte igual, o
//! uno de los dos actuara sobre algo que no es lo que el otro dijo.

use crate::error::ErrorEnjambre;

/// Marca del protocolo: "AGSW" en little-endian.
pub const MARCA: u32 = 0x5753_4741;

/// Version del formato.
pub const VERSION: u8 = 1;

/// Tope de un texto (sujeto, incidente, valor de indicador).
///
/// Un indicador es un hash, un dominio o una IP; 512 bytes sobra para todos y
/// corta de raiz que un par haga crecer la memoria del receptor con un nombre.
pub const MAX_TEXTO: usize = 512;

/// Tope de un mensaje suelto del enjambre, sin contar artefactos por trozos.
pub const MAX_MENSAJE: usize = 64 * 1024;

/// Tipo de mensaje del enjambre.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TipoMensaje {
    /// Orden de contencion firmada por el plano de control.
    Orden,
    /// Observacion local de un par: evidencia, no mandato.
    Observacion,
    /// Descriptor de un artefacto grande (paquete de reglas YARA, modelo).
    DescriptorArtefacto,
    /// Un trozo de un artefacto.
    TrozoArtefacto,
    /// Peticion de los trozos que faltan.
    PeticionTrozos,
}

impl TipoMensaje {
    /// Discriminante de red.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            TipoMensaje::Orden => 1,
            TipoMensaje::Observacion => 2,
            TipoMensaje::DescriptorArtefacto => 3,
            TipoMensaje::TrozoArtefacto => 4,
            TipoMensaje::PeticionTrozos => 5,
        }
    }

    /// Recupera el tipo desde su discriminante.
    #[must_use]
    pub fn desde_tag(t: u8) -> Option<TipoMensaje> {
        match t {
            1 => Some(TipoMensaje::Orden),
            2 => Some(TipoMensaje::Observacion),
            3 => Some(TipoMensaje::DescriptorArtefacto),
            4 => Some(TipoMensaje::TrozoArtefacto),
            5 => Some(TipoMensaje::PeticionTrozos),
            _ => None,
        }
    }
}

/// Escribe un texto con su longitud por delante (u16 little-endian).
pub fn escribir_texto(v: &mut Vec<u8>, s: &str) {
    let n = u16::try_from(s.len()).unwrap_or(u16::MAX);
    v.extend_from_slice(&n.to_le_bytes());
    v.extend_from_slice(&s.as_bytes()[..n as usize]);
}

/// Escribe un `u64` little-endian.
pub fn escribir_u64(v: &mut Vec<u8>, n: u64) {
    v.extend_from_slice(&n.to_le_bytes());
}

/// Escribe un bloque de bytes con su longitud por delante (u32 little-endian).
pub fn escribir_bloque(v: &mut Vec<u8>, b: &[u8]) {
    let n = u32::try_from(b.len()).unwrap_or(u32::MAX);
    v.extend_from_slice(&n.to_le_bytes());
    v.extend_from_slice(&b[..n as usize]);
}

/// Sobre de un mensaje del enjambre.
///
/// La cabecera lleva los saltos restantes **fuera** de lo firmado, a proposito:
/// cada reenvio los decrementa, asi que incluirlos invalidaria la firma en el
/// primer salto. Que sean mutables no es un riesgo porque su unico efecto es
/// acortar la vida del mensaje: un atacante que los suba solo consigue que se
/// reenvie mas, y contra eso estan la deduplicacion y el limite por par.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sobre {
    /// Tipo del contenido.
    pub tipo: TipoMensaje,
    /// Saltos que le quedan.
    pub saltos: u8,
    /// Cuerpo del mensaje.
    pub cuerpo: Vec<u8>,
    /// Firma que lo autentica (del plano de control o del par, segun el tipo).
    pub firma: Vec<u8>,
}

impl Sobre {
    /// Serializa el sobre.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16 + self.cuerpo.len() + self.firma.len());
        v.extend_from_slice(&MARCA.to_le_bytes());
        v.push(VERSION);
        v.push(self.tipo.tag());
        v.push(self.saltos);
        escribir_bloque(&mut v, &self.cuerpo);
        escribir_bloque(&mut v, &self.firma);
        v
    }

    /// Analiza un sobre desde la red.
    ///
    /// # Errores
    /// Marca o version que no cuadran, tipo desconocido, truncamiento, o una
    /// longitud declarada que no cabe en lo que queda.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Sobre, ErrorEnjambre> {
        if bytes.len() > MAX_MENSAJE {
            return Err(ErrorEnjambre::LimiteExcedido {
                campo: "mensaje",
                valor: bytes.len(),
                tope: MAX_MENSAJE,
            });
        }
        let mut l = Lector::nuevo(bytes);
        if l.u32("marca")? != MARCA {
            return Err(ErrorEnjambre::MarcaInvalida);
        }
        let version = l.u8("version")?;
        if version != VERSION {
            return Err(ErrorEnjambre::VersionNoSoportada(version));
        }
        let tag = l.u8("tipo")?;
        let tipo = TipoMensaje::desde_tag(tag).ok_or(ErrorEnjambre::TipoDesconocido(tag))?;
        let saltos = l.u8("saltos")?;
        let cuerpo = l.bloque("cuerpo")?.to_vec();
        let firma = l.bloque("firma")?.to_vec();
        Ok(Sobre {
            tipo,
            saltos,
            cuerpo,
            firma,
        })
    }

    /// Identificador de contenido para deduplicar.
    ///
    /// Cubre tipo, cuerpo y firma, pero **no los saltos**: el mismo mensaje
    /// llegando por dos caminos distintos trae contadores distintos, y si los
    /// saltos entraran en el identificador la deduplicacion no reconoceria el
    /// duplicado y la inundacion no se cortaria nunca.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update([self.tipo.tag()]);
        h.update((self.cuerpo.len() as u64).to_le_bytes());
        h.update(&self.cuerpo);
        h.update(&self.firma);
        h.finalize().into()
    }
}

pub mod lector {
    //! Lector acotado: ningun campo se lee sin comprobar que cabe.

    use super::{ErrorEnjambre, MAX_TEXTO};

    /// Cursor sobre un buffer de red que nunca lee fuera de rango.
    pub struct Lector<'a> {
        datos: &'a [u8],
        pos: usize,
    }

    impl<'a> Lector<'a> {
        /// Nuevo lector sobre `datos`.
        #[must_use]
        pub fn nuevo(datos: &'a [u8]) -> Lector<'a> {
            Lector { datos, pos: 0 }
        }

        /// Bytes que quedan por leer.
        #[must_use]
        pub fn restante(&self) -> usize {
            self.datos.len().saturating_sub(self.pos)
        }

        fn tomar(&mut self, n: usize, campo: &'static str) -> Result<&'a [u8], ErrorEnjambre> {
            let fin = self
                .pos
                .checked_add(n)
                .ok_or(ErrorEnjambre::LongitudImposible {
                    campo,
                    declarada: n,
                    disponible: self.restante(),
                })?;
            if fin > self.datos.len() {
                return Err(ErrorEnjambre::Truncado {
                    campo,
                    esperados: n,
                    habia: self.restante(),
                });
            }
            let s = &self.datos[self.pos..fin];
            self.pos = fin;
            Ok(s)
        }

        /// Lee un byte.
        ///
        /// # Errores
        /// Si no queda ninguno.
        pub fn u8(&mut self, campo: &'static str) -> Result<u8, ErrorEnjambre> {
            Ok(self.tomar(1, campo)?[0])
        }

        /// Lee un `u16` little-endian.
        ///
        /// # Errores
        /// Si no quedan dos bytes.
        pub fn u16(&mut self, campo: &'static str) -> Result<u16, ErrorEnjambre> {
            let b = self.tomar(2, campo)?;
            Ok(u16::from_le_bytes([b[0], b[1]]))
        }

        /// Lee un `u32` little-endian.
        ///
        /// # Errores
        /// Si no quedan cuatro bytes.
        pub fn u32(&mut self, campo: &'static str) -> Result<u32, ErrorEnjambre> {
            let b = self.tomar(4, campo)?;
            Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        }

        /// Lee un `u64` little-endian.
        ///
        /// # Errores
        /// Si no quedan ocho bytes.
        pub fn u64(&mut self, campo: &'static str) -> Result<u64, ErrorEnjambre> {
            let b = self.tomar(8, campo)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(b);
            Ok(u64::from_le_bytes(a))
        }

        /// Lee 32 bytes (un hash).
        ///
        /// # Errores
        /// Si no quedan 32 bytes.
        pub fn hash(&mut self, campo: &'static str) -> Result<[u8; 32], ErrorEnjambre> {
            let b = self.tomar(32, campo)?;
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            Ok(a)
        }

        /// Lee un texto con longitud `u16` por delante.
        ///
        /// # Errores
        /// Si la longitud no cabe, pasa de [`MAX_TEXTO`] o el contenido no es
        /// UTF-8.
        pub fn texto(&mut self, campo: &'static str) -> Result<String, ErrorEnjambre> {
            let n = self.u16(campo)? as usize;
            if n > MAX_TEXTO {
                return Err(ErrorEnjambre::LimiteExcedido {
                    campo,
                    valor: n,
                    tope: MAX_TEXTO,
                });
            }
            if n > self.restante() {
                return Err(ErrorEnjambre::LongitudImposible {
                    campo,
                    declarada: n,
                    disponible: self.restante(),
                });
            }
            let b = self.tomar(n, campo)?;
            String::from_utf8(b.to_vec()).map_err(|_| ErrorEnjambre::NoEsUtf8(campo))
        }

        /// Lee un bloque con longitud `u32` por delante.
        ///
        /// # Errores
        /// Si la longitud declarada no cabe en lo que queda.
        pub fn bloque(&mut self, campo: &'static str) -> Result<&'a [u8], ErrorEnjambre> {
            let n = self.u32(campo)? as usize;
            if n > self.restante() {
                return Err(ErrorEnjambre::LongitudImposible {
                    campo,
                    declarada: n,
                    disponible: self.restante(),
                });
            }
            self.tomar(n, campo)
        }
    }
}

pub use lector::Lector;

#[cfg(test)]
mod pruebas {
    use super::*;

    fn sobre() -> Sobre {
        Sobre {
            tipo: TipoMensaje::Orden,
            saltos: 3,
            cuerpo: vec![1, 2, 3, 4],
            firma: vec![9; 64],
        }
    }

    #[test]
    fn un_sobre_va_y_vuelve_sin_perder_nada() {
        let s = sobre();
        assert_eq!(Sobre::desde_bytes(&s.a_bytes()).expect("ida y vuelta"), s);
    }

    /// El identificador NO puede incluir los saltos: el mismo mensaje por dos
    /// caminos llega con contadores distintos, y si eso cambiara el id la
    /// deduplicacion no reconoceria el duplicado y la inundacion no pararia.
    #[test]
    fn el_identificador_ignora_los_saltos_para_que_la_deduplicacion_funcione() {
        let a = sobre();
        let b = Sobre {
            saltos: 1,
            ..sobre()
        };
        assert_eq!(
            a.id(),
            b.id(),
            "el mismo mensaje por otro camino es el mismo"
        );

        let c = Sobre {
            cuerpo: vec![1, 2, 3, 5],
            ..sobre()
        };
        assert_ne!(a.id(), c.id(), "otro contenido es otro mensaje");
    }

    /// Sin la longitud del cuerpo dentro del hash, un cuerpo y una firma podrian
    /// reagruparse dando el mismo identificador.
    #[test]
    fn mover_el_limite_entre_cuerpo_y_firma_cambia_el_identificador() {
        let a = Sobre {
            cuerpo: vec![1, 2],
            firma: vec![3],
            ..sobre()
        };
        let b = Sobre {
            cuerpo: vec![1],
            firma: vec![2, 3],
            ..sobre()
        };
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn cualquier_prefijo_de_un_sobre_se_rechaza_sin_panico() {
        let bytes = sobre().a_bytes();
        for corte in 0..bytes.len() {
            assert!(
                Sobre::desde_bytes(&bytes[..corte]).is_err(),
                "un prefijo de {corte} bytes no es un sobre"
            );
        }
    }

    #[test]
    fn una_marca_o_una_version_ajenas_se_rechazan() {
        let mut bytes = sobre().a_bytes();
        bytes[0] ^= 0xFF;
        assert_eq!(
            Sobre::desde_bytes(&bytes),
            Err(ErrorEnjambre::MarcaInvalida)
        );

        let mut bytes = sobre().a_bytes();
        bytes[4] = 99;
        assert_eq!(
            Sobre::desde_bytes(&bytes),
            Err(ErrorEnjambre::VersionNoSoportada(99))
        );
    }

    #[test]
    fn una_longitud_de_bloque_mentirosa_no_lee_fuera_de_rango() {
        let mut bytes = sobre().a_bytes();
        // La longitud del cuerpo es un u32 en el desplazamiento 7.
        bytes[7] = 0xFF;
        bytes[8] = 0xFF;
        bytes[9] = 0xFF;
        bytes[10] = 0x7F;
        assert!(matches!(
            Sobre::desde_bytes(&bytes),
            Err(ErrorEnjambre::LongitudImposible { .. })
        ));
    }

    #[test]
    fn un_mensaje_mas_grande_que_el_tope_se_rechaza_antes_de_analizarlo() {
        let enorme = vec![0u8; MAX_MENSAJE + 1];
        assert!(matches!(
            Sobre::desde_bytes(&enorme),
            Err(ErrorEnjambre::LimiteExcedido { .. })
        ));
    }

    #[test]
    fn el_lector_nunca_lee_fuera_de_rango_con_entrada_arbitraria() {
        // Barrido determinista de entradas hostiles: ninguna puede provocar
        // panico, solo Ok o Err.
        let mut semilla = 0x1234_5678_9ABC_DEF0u64;
        for n in 0..4000usize {
            semilla = semilla
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let largo = (semilla as usize) % 128;
            let mut v = Vec::with_capacity(largo);
            let mut s = semilla;
            for _ in 0..largo {
                s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                v.push((s >> 33) as u8);
            }
            // La mitad con marca valida, para llegar mas adentro del analisis.
            if n % 2 == 0 && v.len() >= 4 {
                v[..4].copy_from_slice(&MARCA.to_le_bytes());
                if v.len() >= 5 {
                    v[4] = VERSION;
                }
            }
            let _ = Sobre::desde_bytes(&v);
        }
    }

    #[test]
    fn los_discriminantes_de_tipo_son_estables_y_no_se_solapan() {
        let todos = [
            TipoMensaje::Orden,
            TipoMensaje::Observacion,
            TipoMensaje::DescriptorArtefacto,
            TipoMensaje::TrozoArtefacto,
            TipoMensaje::PeticionTrozos,
        ];
        let mut vistos = Vec::new();
        for t in todos {
            assert!(!vistos.contains(&t.tag()));
            vistos.push(t.tag());
            assert_eq!(TipoMensaje::desde_tag(t.tag()), Some(t));
        }
    }

    #[test]
    fn un_texto_mas_largo_que_el_tope_se_rechaza() {
        let mut v = Vec::new();
        v.extend_from_slice(&(u16::try_from(MAX_TEXTO + 1).unwrap()).to_le_bytes());
        v.extend_from_slice(&vec![b'a'; MAX_TEXTO + 1]);
        let mut l = Lector::nuevo(&v);
        assert!(matches!(
            l.texto("prueba"),
            Err(ErrorEnjambre::LimiteExcedido { .. })
        ));
    }

    #[test]
    fn un_texto_que_no_es_utf8_se_rechaza_en_vez_de_colarse() {
        let mut v = Vec::new();
        v.extend_from_slice(&3u16.to_le_bytes());
        v.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        let mut l = Lector::nuevo(&v);
        assert_eq!(l.texto("prueba"), Err(ErrorEnjambre::NoEsUtf8("prueba")));
    }
}
