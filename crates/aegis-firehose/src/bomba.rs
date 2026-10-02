//! La bomba: mueve el diario hacia el destino sin perder nada.
//!
//! # El orden importa y es el unico que funciona
//!
//! ```text
//! leer del diario  ->  entregar  ->  esperar el acuse  ->  confirmar
//! ```
//!
//! Cada flecha se puede romper. Lo que hace que ninguna rotura pierda nada es
//! que **confirmar es lo ultimo**:
//!
//! - Si el proceso muere despues de leer, el registro sigue en disco.
//! - Si muere despues de entregar pero antes de confirmar, el registro sigue en
//!   disco y se reenvia. El destino lo vera dos veces.
//! - Si muere despues de confirmar, ya estaba entregado.
//!
//! Confirmar ANTES de entregar convertiria «al menos una vez» en «como mucho
//! una vez»: exactamente lo contrario de lo que hace falta en auditoria, y de
//! una forma que no se nota hasta que alguien busca la evidencia y no esta.
//!
//! # Destinos sin acuse: la retencion (FASE 6.4 del MP-16)
//!
//! Syslog sobre TCP no tiene acuse de aplicacion: `entregar` devuelve `Ok`
//! cuando los bytes salieron del socket, no cuando el colector los guardo. Si
//! el colector muere con datos sin leer en su bufer, esos registros se pierden
//! y aqui parecian entregados. El caos de la FASE 6.4 lo demuestra: un
//! `kill -9` al colector se llevaba el ultimo lote.
//!
//! Con [`Bomba::con_retencion`] un lote entregado NO se confirma enseguida: se
//! RETIENE ese tiempo y solo se confirma si, al vencer, el destino sigue vivo
//! ([`Destino::vivo`]). Si el destino murio entretanto —o falla un envio
//! posterior—, la bomba REBOBINA hasta el ultimo lote confirmado y reenvia todo
//! lo retenido. Son duplicados, contados en [`Bomba::reentregados`], y el SIEM
//! los desduplica por el identificador del registro; perdida, ninguna.
//!
//! Lo que la retencion NO cubre, dicho en vez de escondido: un colector que
//! sigue vivo mas alla de la retencion sin haber guardado lo que leyo y muere
//! despues. Esa ventana la cierra solo un destino con acuse (Kafka).
//!
//! # Que se le pide a quien integra
//!
//! Duplicados. Cada registro lleva su identificador de evento; el SIEM
//! desduplica por el. Se dice aqui, en la documentacion, y no se esconde: un
//! duplicado que el integrador no espera acaba contando dos veces un incidente
//! en un informe de cumplimiento.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::destino::Destino;
use crate::diario::{Diario, Posicion};
use crate::error::Resultado;
use crate::reintento::{Politica, Reintento};

/// Cuantos registros se llevan por lote.
///
/// Un lote grande amortiza los viajes de red; uno demasiado grande retiene
/// evidencia en disco mas tiempo del necesario y, cuando falla, obliga a
/// reenviarlo entero.
pub const LOTE_POR_DEFECTO: usize = 256;

/// Resultado de una vuelta de la bomba.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Vuelta {
    /// Registros entregados en esta vuelta. Sin retencion quedan ademas
    /// confirmados; con retencion se confirman al vencer (ver
    /// [`Bomba::entregados`]).
    pub entregados: usize,
    /// Si el destino fallo en esta vuelta (o murio con lotes retenidos).
    pub fallo: bool,
    /// Cuanto conviene esperar antes de reintentar.
    pub espera: Duration,
}

/// Un lote entregado y aun no confirmado.
#[derive(Debug, Clone, Copy)]
struct Retenido {
    /// Ultimo registro del lote: lo que se confirma.
    hasta: Posicion,
    /// Donde empieza el registro siguiente.
    siguiente: Posicion,
    /// Registros del lote.
    n: u64,
    /// Cuando se entrego.
    entregado: Instant,
}

/// Mueve registros del diario al destino.
pub struct Bomba<D: Destino> {
    destino: D,
    reintento: Reintento,
    lote: usize,
    /// Donde seguir leyendo. `None` = por el principio.
    ///
    /// Es la posicion del registro SIGUIENTE al ultimo entregado, no la del
    /// ultimo entregado: apuntar al entregado lo reenviaria en cada vuelta.
    reanudar: Option<Posicion>,
    /// Siguiente al ultimo CONFIRMADO: adonde se rebobina si el destino cae
    /// con lotes retenidos.
    confirmado: Option<Posicion>,
    /// Cuanto se retiene un lote antes de confirmarlo. Cero = sin retencion.
    retencion: Duration,
    retenidos: VecDeque<Retenido>,
    entregados: u64,
    reentregados: u64,
    fallos: u64,
}

impl<D: Destino> Bomba<D> {
    /// Crea la bomba con la politica de reintento dada, sin retencion.
    pub fn nueva(destino: D, politica: Politica) -> Bomba<D> {
        Bomba {
            destino,
            reintento: Reintento::nuevo(politica),
            lote: LOTE_POR_DEFECTO,
            reanudar: None,
            confirmado: None,
            retencion: Duration::ZERO,
            retenidos: VecDeque::new(),
            entregados: 0,
            reentregados: 0,
            fallos: 0,
        }
    }

    /// Cambia el tamano de lote.
    pub fn con_lote(mut self, lote: usize) -> Bomba<D> {
        self.lote = lote.max(1);
        self
    }

    /// Retiene cada lote entregado `retencion` antes de confirmarlo, y lo
    /// reenvia si el destino muere entretanto. Ver el comentario del modulo.
    ///
    /// Para destinos sin acuse de aplicacion (syslog). Con un destino que acusa
    /// (Kafka) sobra: dejarla a cero.
    pub fn con_retencion(mut self, retencion: Duration) -> Bomba<D> {
        self.retencion = retencion;
        self
    }

    /// Registros entregados Y confirmados desde que arranco.
    pub fn entregados(&self) -> u64 {
        self.entregados
    }

    /// Registros que se volvieron a enviar porque el destino murio con ellos
    /// retenidos. Son duplicados en el destino, nunca perdidas.
    pub fn reentregados(&self) -> u64 {
        self.reentregados
    }

    /// Registros entregados que esperan a que venza su retencion.
    pub fn retenidos(&self) -> u64 {
        self.retenidos.iter().map(|r| r.n).sum()
    }

    /// Fallos de entrega acumulados.
    pub fn fallos(&self) -> u64 {
        self.fallos
    }

    /// Una vuelta: madura lo retenido, lee, entrega, y solo entonces confirma.
    ///
    /// `enmarcar` traduce el registro del diario al formato del destino. Va
    /// aparte porque el diario guarda la carga tal cual la produjo el plano de
    /// control: el marcado de syslog o la clave de Kafka son cosa del destino,
    /// y meterlos en disco ataria la evidencia ya escrita al destino que
    /// estuviera configurado ese dia.
    pub fn vuelta(
        &mut self,
        diario: &mut Diario,
        enmarcar: &dyn Fn(&[u8]) -> Vec<u8>,
    ) -> Resultado<Vuelta> {
        if let Some(v) = self.madurar(diario)? {
            return Ok(v);
        }

        // El diario borra por segmentos ENTEROS, asi que tras confirmar puede
        // quedar en disco la cola del segmento activo. Se sigue por donde
        // termino el ultimo entregado, no por el principio del directorio.
        let pendientes = diario.leer_desde(self.reanudar, self.lote)?;
        if pendientes.is_empty() {
            return Ok(Vuelta::default());
        }

        let marcos: Vec<Vec<u8>> = pendientes.iter().map(|r| enmarcar(&r.carga)).collect();
        let refs: Vec<&[u8]> = marcos.iter().map(|m| m.as_slice()).collect();

        match self.destino.entregar(&refs) {
            Ok(()) => {
                self.reintento.exito();
                let ultimo = &pendientes[pendientes.len() - 1];
                let n = pendientes.len() as u64;
                self.reanudar = Some(ultimo.siguiente);
                if self.retencion.is_zero() {
                    // CONFIRMAR ES LO ULTIMO. Ver el comentario del modulo.
                    diario.confirmar_hasta(ultimo.posicion)?;
                    self.confirmado = Some(ultimo.siguiente);
                    self.entregados += n;
                } else {
                    self.retenidos.push_back(Retenido {
                        hasta: ultimo.posicion,
                        siguiente: ultimo.siguiente,
                        n,
                        entregado: Instant::now(),
                    });
                }
                Ok(Vuelta {
                    entregados: pendientes.len(),
                    fallo: false,
                    espera: Duration::ZERO,
                })
            }
            Err(_) => {
                // Nada se confirma. El lote entero —y todo lo retenido— se
                // reintentara: puede producir duplicados en el destino y esa es
                // la eleccion deliberada, porque la alternativa es perder
                // auditoria.
                Ok(self.caida())
            }
        }
    }

    /// Confirma los lotes cuya retencion vencio, si el destino sigue vivo. Si
    /// murio, rebobina y devuelve la vuelta fallida.
    fn madurar(&mut self, diario: &mut Diario) -> Resultado<Option<Vuelta>> {
        let vencido = self
            .retenidos
            .front()
            .is_some_and(|r| r.entregado.elapsed() >= self.retencion);
        if !vencido {
            return Ok(None);
        }
        if !self.destino.vivo() {
            return Ok(Some(self.caida()));
        }
        while let Some(r) = self.retenidos.front().copied() {
            if r.entregado.elapsed() < self.retencion {
                break;
            }
            diario.confirmar_hasta(r.hasta)?;
            self.confirmado = Some(r.siguiente);
            self.entregados += r.n;
            self.retenidos.pop_front();
        }
        Ok(None)
    }

    /// El destino fallo: se rebobina a lo confirmado, se cierra la conexion y
    /// se espera segun la politica.
    fn caida(&mut self) -> Vuelta {
        self.reentregados += self.retenidos();
        self.retenidos.clear();
        self.reanudar = self.confirmado;
        self.destino.reiniciar();
        self.fallos += 1;
        Vuelta {
            entregados: 0,
            fallo: true,
            espera: self.reintento.fallo(),
        }
    }

    /// Acceso al destino, para las metricas.
    pub fn destino(&self) -> &D {
        &self.destino
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::diario::Config;
    use std::sync::{Arc, Mutex};

    /// Destino en memoria que hace de colector SIEM.
    ///
    /// `escritos` es lo que salio del socket y el colector aun tiene. Las
    /// pruebas lo vacian y lo marcan muerto para imitar un `kill -9` con datos
    /// en su bufer: lo escrito y no confirmado se pierde con el.
    #[derive(Default)]
    struct Colector {
        escritos: Vec<Vec<u8>>,
        vivo: bool,
    }

    struct DestinoPrueba(Arc<Mutex<Colector>>);

    impl Destino for DestinoPrueba {
        fn nombre(&self) -> &str {
            "prueba"
        }
        fn entregar(&mut self, lote: &[&[u8]]) -> Resultado<()> {
            let mut c = self.0.lock().unwrap();
            // Como TCP: tras la muerte del par, la primera escritura «funciona».
            for m in lote {
                c.escritos.push(m.to_vec());
            }
            Ok(())
        }
        fn vivo(&mut self) -> bool {
            self.0.lock().unwrap().vivo
        }
    }

    fn diario(etiqueta: &str) -> (Diario, std::path::PathBuf) {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aegis-bomba-{etiqueta}-{n}"));
        let mut cfg = Config::nueva(&dir);
        cfg.registros_por_sincronizacion = 1;
        (Diario::abrir(cfg).unwrap(), dir)
    }

    fn identidad(b: &[u8]) -> Vec<u8> {
        b.to_vec()
    }

    #[test]
    fn sin_retencion_confirma_al_entregar_como_antes() {
        let (mut d, dir) = diario("sin");
        let c = Arc::new(Mutex::new(Colector {
            vivo: true,
            ..Colector::default()
        }));
        let mut b = Bomba::nueva(DestinoPrueba(c.clone()), Politica::default());
        d.admitir(b"uno").unwrap();
        let v = b.vuelta(&mut d, &identidad).unwrap();
        assert_eq!(v.entregados, 1);
        assert_eq!(b.entregados(), 1);
        assert_eq!(b.retenidos(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn un_colector_que_muere_con_lo_retenido_lo_recibe_otra_vez() {
        let (mut d, dir) = diario("muere");
        let c = Arc::new(Mutex::new(Colector {
            vivo: true,
            ..Colector::default()
        }));
        let mut b = Bomba::nueva(DestinoPrueba(c.clone()), Politica::default())
            .con_retencion(Duration::from_millis(30));
        for r in [&b"a"[..], b"b", b"c"] {
            d.admitir(r).unwrap();
        }
        assert_eq!(b.vuelta(&mut d, &identidad).unwrap().entregados, 3);
        assert_eq!(b.retenidos(), 3);
        // El colector muere sin haber guardado nada de lo escrito.
        {
            let mut g = c.lock().unwrap();
            g.escritos.clear();
            g.vivo = false;
        }
        std::thread::sleep(Duration::from_millis(40));
        let v = b.vuelta(&mut d, &identidad).unwrap();
        assert!(v.fallo, "la muerte con lotes retenidos es una caida");
        assert_eq!(b.reentregados(), 3);
        assert_eq!(b.entregados(), 0, "nada se confirmo");
        // Vuelve: lo retenido se reenvia entero.
        c.lock().unwrap().vivo = true;
        let v = b.vuelta(&mut d, &identidad).unwrap();
        assert_eq!(v.entregados, 3);
        let escritos = c.lock().unwrap().escritos.clone();
        assert_eq!(escritos, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        std::thread::sleep(Duration::from_millis(40));
        b.vuelta(&mut d, &identidad).unwrap();
        assert_eq!(
            b.entregados(),
            3,
            "confirmados al vencer con el colector vivo"
        );
        assert_eq!(b.retenidos(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn la_cuenta_cuadra_admitidos_igual_a_confirmados_mas_retenidos_mas_pendientes() {
        let (mut d, dir) = diario("cuenta");
        let c = Arc::new(Mutex::new(Colector {
            vivo: true,
            ..Colector::default()
        }));
        let mut b = Bomba::nueva(DestinoPrueba(c.clone()), Politica::default())
            .con_lote(2)
            .con_retencion(Duration::from_secs(3600));
        for i in 0..5u8 {
            d.admitir(&[i]).unwrap();
        }
        b.vuelta(&mut d, &identidad).unwrap();
        b.vuelta(&mut d, &identidad).unwrap();
        // 4 entregados y retenidos, 1 pendiente en el diario, 0 confirmados.
        assert_eq!(b.retenidos(), 4);
        assert_eq!(b.entregados(), 0);
        assert_eq!(d.contadores().admitidos, 5);
        let _ = std::fs::remove_dir_all(dir);
    }
}
