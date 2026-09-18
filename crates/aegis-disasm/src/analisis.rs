//! La entrada de una sola pieza: bytes de codigo dentro, capacidades fuera.
//!
//! # Por que existe esta capa
//!
//! Los modulos de este crate son piezas separadas a proposito —el grafo de flujo
//! lo consume el decompilador de la FASE 100, el de llamadas lo consume el motor
//! de reglas, las reglas son datos—, pero quien solo quiere analizar un fichero
//! no deberia tener que saber en que orden se encadenan ni cual es el plazo de
//! cual. Esta capa hace ese encadenado una vez y bien.
//!
//! # Lo que esta capa NO hace, y es lo mas importante de ella
//!
//! **No ejecuta nada.** Es la invariante 8 del encargo, y aqui se puede
//! comprobar de un vistazo: entra un `&[u8]`, sale una estructura de datos, y en
//! todo el camino no hay ni una llamada que transfiera control a esos bytes, ni
//! una que los escriba en disco, ni una que abra un proceso. No es que este
//! desactivado: es que no esta.
//!
//! **No lee el reloj ni el disco ni la red.** El mismo fichero analizado dos
//! veces da exactamente el mismo resultado, lo que permite comparar dos analisis
//! y saber que lo que cambio fue el fichero. La marca de tiempo de la senal la
//! pone quien llama.

use crate::capacidad::Informe;
use crate::cfg::{Cfg, LeeDatos, SinDatos};
use crate::importaciones::{Importaciones, Importadas, SinTabla};
use crate::instruccion::Arquitectura;
use crate::llamadas::GrafoDeLlamadas;
use crate::plazo::{Cobertura, Plazo};
use crate::reglas::{evaluar, Contexto};
use crate::{arm64, x86};

/// Lo que hay que saber del binario para analizarlo.
///
/// Todo lo que no sea el codigo en si es opcional, y su ausencia se nota en el
/// resultado en vez de fingirse: sin tabla de importaciones no se resuelven
/// nombres, y sin lector de datos no se resuelven tablas de saltos. Las dos
/// cosas salen en la cobertura.
pub struct Entrada<'a> {
    /// Los bytes del codigo. **No se ejecutan nunca.**
    pub codigo: &'a [u8],
    /// Donde se carga ese codigo.
    pub base: u64,
    /// De que arquitectura es.
    pub arquitectura: Arquitectura,
    /// Por donde empezar: el punto de entrada y los simbolos de funcion que se
    /// conozcan.
    pub entradas: &'a [u64],
    /// La tabla de importaciones del contenedor, si la hay.
    pub importadas: &'a dyn Importadas,
    /// Con que leer datos de la imagen, para las tablas de saltos.
    pub datos: &'a dyn LeeDatos,
}

impl<'a> Entrada<'a> {
    /// Una entrada con lo minimo: codigo, donde se carga y por donde empezar.
    pub fn minima(
        codigo: &'a [u8],
        base: u64,
        arquitectura: Arquitectura,
        entradas: &'a [u64],
    ) -> Entrada<'a> {
        Entrada {
            codigo,
            base,
            arquitectura,
            entradas,
            importadas: &SinTabla,
            datos: &SinDatos,
        }
    }
}

/// Todo lo que salio del analisis.
///
/// Se devuelven las piezas intermedias y no solo el informe porque **las
/// consumen otras fases**: el grafo de flujo lo necesita el decompilador de la
/// FASE 100 y el de llamadas lo necesita cualquier regla nueva. Volver a
/// construirlas mas tarde, sobre bytes que quiza ya no esten, es como se
/// introducen las discrepancias entre dos analisis del mismo fichero.
pub struct Analisis {
    /// El grafo de flujo.
    pub cfg: Cfg,
    /// El grafo de llamadas.
    pub llamadas: GrafoDeLlamadas,
    /// Como resuelve el binario las funciones del sistema.
    pub importaciones: Importaciones,
    /// Las capacidades encontradas, con su evidencia y su cobertura.
    pub informe: Informe,
}

/// Analiza un tramo de codigo dentro de un plazo.
///
/// El plazo lo pone quien llama porque el presupuesto no es el mismo analizando
/// un fichero que llega por correo que revisando un volcado en el servidor, y un
/// valor fijo aqui obligaria a uno de los dos casos a vivir con el plazo del
/// otro.
pub fn analizar(e: &Entrada, plazo: &mut Plazo) -> Analisis {
    let cfg = match e.arquitectura {
        Arquitectura::Arm64 => match arm64::Tramo::nuevo(e.codigo, e.base, e.arquitectura) {
            Ok(t) => Cfg::construir(&t, e.datos, e.entradas, plazo),
            Err(_) => Cfg::default(),
        },
        a => match x86::Tramo::nuevo(e.codigo, e.base, a) {
            Ok(t) => Cfg::construir(&t, e.datos, e.entradas, plazo),
            Err(_) => Cfg::default(),
        },
    };
    let llamadas = GrafoDeLlamadas::construir(&cfg);
    let importaciones = Importaciones::buscar(&cfg, e.importadas, e.arquitectura);

    let ctx = Contexto::nuevo(
        &cfg,
        &llamadas,
        &importaciones,
        e.codigo,
        e.base,
        e.arquitectura,
    );
    let capacidades = evaluar(&ctx);

    // La cobertura sale del grafo de flujo y se completa con lo que aporta el
    // grafo de llamadas. Van juntas dentro del informe y no como dos valores
    // sueltos: ver [`crate::capacidad::Informe`].
    let cobertura = Cobertura {
        bytes_totales: e.codigo.len() as u64,
        transferencias_indirectas: cfg.indirectos.len(),
        funciones: llamadas.cuantas_funciones().max(cfg.cobertura.funciones),
        cortado_por_plazo: cfg.cobertura.cortado_por_plazo || llamadas.cortado,
        ..cfg.cobertura.clone()
    };
    let informe = Informe::nuevo(capacidades, cobertura);

    Analisis {
        cfg,
        llamadas,
        importaciones,
        informe,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::capacidad::Familia;

    #[test]
    fn un_tramo_de_codigo_normal_no_produce_ninguna_capacidad() {
        // El caso negativo que hace que lo demas signifique algo. `xor eax,eax`
        // y `ret` no son nada, y un motor que encontrara algo aqui encontraria
        // algo en todas partes.
        let e = Entrada::minima(&[0x31, 0xC0, 0xC3], 0x1000, Arquitectura::X86_64, &[0x1000]);
        let a = analizar(&e, &mut Plazo::default());
        assert!(a.informe.capacidades().is_empty(), "{}", a.informe.frase());
        assert!(
            a.informe.la_ausencia_significa_algo(),
            "el analisis termino, asi que la lista vacia si dice algo"
        );
    }

    #[test]
    fn las_instrucciones_aes_del_procesador_producen_la_capacidad_con_su_evidencia() {
        // `aesenc xmm0, xmm1` = 66 0F 38 DC C1. Es la evidencia mas limpia que
        // existe: no tiene lectura alternativa.
        let bytes = &[0x66, 0x0F, 0x38, 0xDC, 0xC1, 0xC3];
        let e = Entrada::minima(bytes, 0x1000, Arquitectura::X86_64, &[0x1000]);
        let a = analizar(&e, &mut Plazo::default());
        let c = a
            .informe
            .capacidades()
            .iter()
            .find(|c| c.familia == Familia::Cifrado)
            .unwrap_or_else(|| panic!("no salio el cifrado: {}", a.informe.frase()));
        assert!(!c.evidencias().is_empty());
        assert_eq!(c.evidencias()[0].donde, 0x1000);
        assert!(
            c.evidencias()[0].que.contains("aes"),
            "la evidencia tiene que llevar la instruccion escrita: {}",
            c.evidencias()[0].que
        );
    }

    #[test]
    fn el_analisis_de_bytes_arbitrarios_termina_y_no_afirma_nada_que_no_pueda() {
        // Entrada hostil. No se comprueba que el resultado sea bueno —sobre
        // bytes al azar no lo puede ser— sino que termina y que toda capacidad
        // que salga trae evidencia dentro del codigo analizado.
        let mut x = 0x243F_6A88_85A3_08D3u64;
        for _ in 0..32 {
            let mut bytes = Vec::with_capacity(8192);
            for _ in 0..8192 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                bytes.push(x as u8);
            }
            let e = Entrada::minima(&bytes, 0x1000, Arquitectura::X86_64, &[0x1000]);
            let a = analizar(&e, &mut Plazo::default());
            for c in a.informe.capacidades() {
                assert!(!c.evidencias().is_empty(), "capacidad sin evidencia");
                for ev in c.evidencias() {
                    assert!(
                        ev.donde >= 0x1000 && ev.donde < 0x1000 + bytes.len() as u64,
                        "la evidencia de {} apunta fuera del codigo: {:#x}",
                        c.nombre,
                        ev.donde
                    );
                }
            }
        }
    }

    #[test]
    fn una_arquitectura_que_no_encaja_con_los_bytes_no_revienta() {
        // Pedir A64 sobre bytes que no estan alineados, o x86 sobre nada. El
        // resultado es un analisis vacio y honesto, no un panico ni una
        // afirmacion.
        let e = Entrada::minima(&[0x01, 0x02, 0x03], 0x1001, Arquitectura::Arm64, &[0x1001]);
        let a = analizar(&e, &mut Plazo::default());
        assert!(a.informe.capacidades().is_empty());
    }

    #[test]
    fn el_mismo_fichero_analizado_dos_veces_da_exactamente_lo_mismo() {
        // Sin esto no se puede comparar un analisis de hoy con uno de ayer y
        // saber que lo que cambio fue el fichero.
        let bytes = &[
            0x66, 0x0F, 0x38, 0xDC, 0xC1, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3,
        ];
        let e = Entrada::minima(bytes, 0x1000, Arquitectura::X86_64, &[0x1000]);
        let a = analizar(&e, &mut Plazo::default());
        let b = analizar(&e, &mut Plazo::default());
        assert_eq!(a.informe.frase(), b.informe.frase());
        assert_eq!(a.llamadas.frase(), b.llamadas.frase());
        assert_eq!(a.informe.capacidades().len(), b.informe.capacidades().len());
    }

    #[test]
    fn la_cobertura_cuenta_los_bytes_que_se_le_dieron() {
        let bytes = vec![0x90u8; 256];
        let e = Entrada::minima(&bytes, 0x1000, Arquitectura::X86_64, &[0x1000]);
        let a = analizar(&e, &mut Plazo::default());
        assert_eq!(a.informe.cobertura.bytes_totales, 256);
        assert_eq!(a.informe.cobertura.fraccion_cubierta(), Some(100));
    }

    #[test]
    fn un_plazo_agotado_sale_declarado_en_la_cobertura() {
        // Lo que separa «no hay nada» de «no dio tiempo a mirar».
        let bytes = vec![0x90u8; 200_000];
        let e = Entrada::minima(&bytes, 0x1000, Arquitectura::X86_64, &[0x1000]);
        let mut plazo = Plazo::nuevo(std::time::Duration::from_secs(3600), 100);
        let a = analizar(&e, &mut plazo);
        assert!(!a.informe.la_ausencia_significa_algo());
        assert!(
            a.informe.frase().contains("SE CORTO"),
            "{}",
            a.informe.frase()
        );
    }
}
