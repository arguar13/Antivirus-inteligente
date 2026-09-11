//! Decodificador de paquetes Intel Processor Trace (Intel SDM Vol 3, cap. 33).
//!
//! La CPU vuelca la traza como un flujo de paquetes muy comprimidos: por cada
//! salto CONDICIONAL manda un solo bit (tomado / no tomado, empaquetados de seis
//! en seis en un byte), y por cada salto INDIRECTO manda la direccion destino,
//! y aun esa comprimida contra la anterior. Reconstruir el flujo de ejecucion
//! exige decodificar esto exactamente; un bit mal leido descarrila el resto de
//! la traza.
//!
//! Se decodifica a mano, en Rust puro, contra la especificacion. Se prueba con
//! flujos binarios reales construidos byte a byte segun el SDM: sin un TPM, sin
//! un chip con Intel PT, la CORRECCION del decodificador se puede demostrar
//! igual, porque el formato es el formato.

/// Un paquete de la traza, ya decodificado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Paquete {
    /// Packet Stream Boundary: sincronizacion. Marca un punto de reenganche.
    Psb,
    /// Fin del preambulo que sigue a un PSB.
    PsbEnd,
    /// Relleno; se ignora.
    Pad,
    /// Overflow: la CPU perdio traza (el consumidor no vacio el anillo a
    /// tiempo). Un hueco honesto, no un salto que no ocurrio.
    Ovf,
    /// Taken/Not-Taken: resultados de saltos condicionales, en orden temporal.
    /// `true` = tomado.
    Tnt(Vec<bool>),
    /// Target IP de un salto INDIRECTO (ret, jmp/call indirecto). La pieza clave
    /// para ROP/JOP: cada gadget termina en uno de estos.
    Tip(u64),
    /// Inicio de generacion de traza en una direccion (entrar en la region
    /// trazada).
    TipPge(u64),
    /// Fin de generacion de traza (salir de la region trazada).
    TipPgd(u64),
    /// Flow Update: fija el IP sin que haya habido un salto (p.ej. tras una
    /// excepcion).
    Fup(u64),
    /// Cambio de modo de ejecucion (16/32/64 bits).
    Mode(u8),
    /// Core Bus Ratio (frecuencia); solo temporizacion.
    Cbr(u16),
    /// Marca de tiempo.
    Tsc(u64),
    /// Un opcode que este decodificador no modela; se salta un byte para no
    /// descarrilar del todo, pero se reporta.
    Desconocido(u8),
}

/// Un fallo al decodificar.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PaqueteError {
    /// El buffer se acabo a mitad de un paquete.
    #[error("traza truncada en la posicion {0}")]
    Truncado(usize),
}

/// Decodificador con estado: recuerda el ultimo IP para descomprimir los TIP.
#[derive(Debug, Default)]
pub struct Decodificador {
    ultimo_ip: u64,
}

impl Decodificador {
    /// Un decodificador nuevo.
    pub fn new() -> Decodificador {
        Decodificador { ultimo_ip: 0 }
    }

    /// Decodifica todos los paquetes de un buffer. Devuelve la lista o el primer
    /// error de truncamiento.
    pub fn decodificar_todo(&mut self, buf: &[u8]) -> Result<Vec<Paquete>, PaqueteError> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < buf.len() {
            let (p, n) = self.siguiente(&buf[pos..], pos)?;
            out.push(p);
            debug_assert!(n > 0, "un paquete de 0 bytes seria un bucle infinito");
            pos += n;
        }
        Ok(out)
    }

    /// Decodifica el siguiente paquete de `buf`. `pos_global` es solo para el
    /// mensaje de error. Devuelve el paquete y cuantos bytes consumio.
    pub fn siguiente(
        &mut self,
        buf: &[u8],
        pos_global: usize,
    ) -> Result<(Paquete, usize), PaqueteError> {
        let b0 = *buf.first().ok_or(PaqueteError::Truncado(pos_global))?;

        // PAD
        if b0 == 0x00 {
            return Ok((Paquete::Pad, 1));
        }

        // Opcodes de 2 bytes (escape 0x02)
        if b0 == 0x02 {
            let b1 = *buf.get(1).ok_or(PaqueteError::Truncado(pos_global))?;
            return self.opcode_02(buf, b1, pos_global);
        }

        // Paquetes con IP en los 5 bits bajos (TIP / TIP.PGE / TIP.PGD / FUP)
        match b0 & 0x1F {
            0x0D => return self.leer_ip(buf, b0, pos_global, Paquete::Tip),
            0x11 => return self.leer_ip(buf, b0, pos_global, Paquete::TipPge),
            0x01 => return self.leer_ip(buf, b0, pos_global, Paquete::TipPgd),
            0x1D => return self.leer_ip(buf, b0, pos_global, Paquete::Fup),
            _ => {}
        }

        // Opcodes de un byte con payload fijo
        match b0 {
            0x99 => {
                // MODE: 2 bytes
                let b1 = *buf.get(1).ok_or(PaqueteError::Truncado(pos_global))?;
                Ok((Paquete::Mode(b1), 2))
            }
            0x19 => {
                // TSC: opcode + 7 bytes
                if buf.len() < 8 {
                    return Err(PaqueteError::Truncado(pos_global));
                }
                let mut v = [0u8; 8];
                v[..7].copy_from_slice(&buf[1..8]);
                Ok((Paquete::Tsc(u64::from_le_bytes(v)), 8))
            }
            0x59 => {
                // MTC: 2 bytes; se modela como Desconocido de timing (no afecta
                // al flujo). Se consume para no descarrilar.
                Ok((Paquete::Desconocido(0x59), 2))
            }
            _ => {
                // Short TNT: bit 0 = 0 y no es ninguno de los anteriores.
                if b0 & 0x01 == 0 {
                    return Ok((decodificar_tnt_corto(b0), 1));
                }
                // CYC y otros de timing: se saltan un byte.
                Ok((Paquete::Desconocido(b0), 1))
            }
        }
    }

    fn opcode_02(
        &mut self,
        buf: &[u8],
        b1: u8,
        pos_global: usize,
    ) -> Result<(Paquete, usize), PaqueteError> {
        match b1 {
            0x82 => {
                // PSB: 16 bytes en total.
                if buf.len() < 16 {
                    return Err(PaqueteError::Truncado(pos_global));
                }
                Ok((Paquete::Psb, 16))
            }
            0x23 => Ok((Paquete::PsbEnd, 2)),
            0xF3 => Ok((Paquete::Ovf, 2)),
            0x03 => {
                // CBR: 0x02 0x03 + 2 bytes
                if buf.len() < 4 {
                    return Err(PaqueteError::Truncado(pos_global));
                }
                Ok((Paquete::Cbr(u16::from_le_bytes([buf[2], buf[3]])), 4))
            }
            0xA3 => {
                // Long TNT: 0x02 0xA3 + 6 bytes
                if buf.len() < 8 {
                    return Err(PaqueteError::Truncado(pos_global));
                }
                let mut v = [0u8; 8];
                v[..6].copy_from_slice(&buf[2..8]);
                let campo = u64::from_le_bytes(v);
                Ok((decodificar_tnt_largo(campo), 8))
            }
            otro => Ok((Paquete::Desconocido(otro), 2)),
        }
    }

    /// Lee un paquete con IP comprimido y actualiza `ultimo_ip`.
    fn leer_ip(
        &mut self,
        buf: &[u8],
        b0: u8,
        pos_global: usize,
        constructor: fn(u64) -> Paquete,
    ) -> Result<(Paquete, usize), PaqueteError> {
        let ipbytes = b0 >> 5;
        let (ip, consumido) = self.descomprimir_ip(buf, ipbytes, pos_global)?;
        self.ultimo_ip = ip;
        Ok((constructor(ip), consumido))
    }

    /// Descomprime el IP de un paquete IP contra el ultimo IP conocido. El campo
    /// `ipbytes` (3 bits altos del opcode) dice cuantos bytes vienen y como se
    /// combinan con el IP anterior.
    fn descomprimir_ip(
        &self,
        buf: &[u8],
        ipbytes: u8,
        pos_global: usize,
    ) -> Result<(u64, usize), PaqueteError> {
        let necesita = |n: usize| -> Result<(), PaqueteError> {
            if buf.len() < 1 + n {
                Err(PaqueteError::Truncado(pos_global))
            } else {
                Ok(())
            }
        };
        let le = |bytes: &[u8]| -> u64 {
            let mut v = [0u8; 8];
            v[..bytes.len()].copy_from_slice(bytes);
            u64::from_le_bytes(v)
        };
        match ipbytes {
            0b000 => Ok((self.ultimo_ip, 1)), // IP suprimido: se mantiene el anterior
            0b001 => {
                necesita(2)?;
                let bajo = le(&buf[1..3]);
                Ok(((self.ultimo_ip & !0xFFFF) | bajo, 3))
            }
            0b010 => {
                necesita(4)?;
                let bajo = le(&buf[1..5]);
                Ok(((self.ultimo_ip & !0xFFFF_FFFF) | bajo, 5))
            }
            0b011 => {
                necesita(6)?;
                // 48 bits con extension de signo desde el bit 47.
                let bajo = le(&buf[1..7]);
                let ip = if bajo & 0x8000_0000_0000 != 0 {
                    bajo | 0xFFFF_0000_0000_0000
                } else {
                    bajo
                };
                Ok((ip, 7))
            }
            0b100 => {
                necesita(6)?;
                let bajo = le(&buf[1..7]);
                Ok(((self.ultimo_ip & !0xFFFF_FFFF_FFFF) | bajo, 7))
            }
            0b110 => {
                necesita(8)?;
                Ok((le(&buf[1..9]), 9))
            }
            _ => Ok((self.ultimo_ip, 1)),
        }
    }
}

/// Decodifica un Short TNT (1 byte). El bit mas alto puesto es el "stop bit"; los
/// bits por debajo (menos el bit 0, que va a cero) son los resultados de los
/// saltos, del mas antiguo al mas reciente.
fn decodificar_tnt_corto(b: u8) -> Paquete {
    let stop = 7 - b.leading_zeros() as u8; // posicion del bit mas alto puesto
    let n = stop.saturating_sub(1); // numero de saltos
    let mut bits = Vec::with_capacity(n as usize);
    for i in 0..n {
        let pos = stop - 1 - i;
        bits.push((b >> pos) & 1 == 1);
    }
    Paquete::Tnt(bits)
}

/// Decodifica un Long TNT (campo de 48 bits). Mismo esquema de stop bit que el
/// corto, pero hasta 47 saltos.
fn decodificar_tnt_largo(campo: u64) -> Paquete {
    if campo == 0 {
        return Paquete::Tnt(Vec::new());
    }
    let stop = 63 - campo.leading_zeros(); // bit mas alto puesto (<48)
    let n = stop; // los bits [stop-1 .. 0]... el bit 0 aqui SI cuenta en el campo de 48
    let mut bits = Vec::with_capacity(n as usize);
    for i in 0..n {
        let pos = stop - 1 - i;
        bits.push((campo >> pos) & 1 == 1);
    }
    Paquete::Tnt(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tnt_corto_un_salto_tomado_y_no_tomado() {
        // n=1 tomado: (1<<2)|(1<<1) = 0b110
        assert_eq!(decodificar_tnt_corto(0b110), Paquete::Tnt(vec![true]));
        // n=1 no tomado: (1<<2)|(0<<1) = 0b100
        assert_eq!(decodificar_tnt_corto(0b100), Paquete::Tnt(vec![false]));
    }

    #[test]
    fn tnt_corto_conserva_el_orden_temporal() {
        // n=2, [tomado, no_tomado]: stop en bit 3, branch0 en bit2=1, branch1 en bit1=0
        assert_eq!(
            decodificar_tnt_corto(0b1100),
            Paquete::Tnt(vec![true, false])
        );
        // n=3, [no, si, si]: stop bit4, bits 3,2,1 = 0,1,1
        assert_eq!(
            decodificar_tnt_corto(0b1_0110),
            Paquete::Tnt(vec![false, true, true])
        );
    }

    #[test]
    fn tip_completo_y_luego_comprimido() {
        let mut d = Decodificador::new();
        // TIP con IP de 8 bytes (ipbytes=0b110): opcode = (0b110<<5)|0x0D = 0xCD
        let mut buf = vec![0xCD];
        buf.extend_from_slice(&0x0000_7fff_dead_beefu64.to_le_bytes());
        let (p, n) = d.siguiente(&buf, 0).unwrap();
        assert_eq!(p, Paquete::Tip(0x0000_7fff_dead_beef));
        assert_eq!(n, 9);

        // TIP comprimido a 2 bytes bajos (ipbytes=0b001): opcode=(0b001<<5)|0x0D=0x2D
        let buf2 = vec![0x2D, 0x11, 0x22];
        let (p2, n2) = d.siguiente(&buf2, 0).unwrap();
        // Los 16 bits bajos se reemplazan; el resto viene del ultimo IP.
        assert_eq!(p2, Paquete::Tip(0x0000_7fff_dead_2211));
        assert_eq!(n2, 3);
    }

    #[test]
    fn psb_psbend_y_pad() {
        let mut d = Decodificador::new();
        let mut buf = Vec::new();
        for _ in 0..8 {
            buf.extend_from_slice(&[0x02, 0x82]);
        } // PSB = 16 bytes
        buf.extend_from_slice(&[0x02, 0x23]); // PSBEND
        buf.push(0x00); // PAD
        let ps = d.decodificar_todo(&buf).unwrap();
        assert_eq!(ps, vec![Paquete::Psb, Paquete::PsbEnd, Paquete::Pad]);
    }

    #[test]
    fn una_traza_truncada_es_error_no_panico() {
        let mut d = Decodificador::new();
        // TIP que promete 8 bytes pero solo hay 3.
        let buf = vec![0xCD, 0x01, 0x02];
        assert!(d.decodificar_todo(&buf).is_err());
    }
}
