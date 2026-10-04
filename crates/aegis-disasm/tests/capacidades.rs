//! Cada regla del catalogo, probada por los dos lados.
//!
//! # Por que el caso negativo importa mas que el positivo
//!
//! Una regla que dispara con lo que tiene que disparar y **tambien con lo que
//! no** parece que funciona: en el binario de prueba sale lo que se esperaba. El
//! fallo aparece en produccion, donde la misma regla dispara con medio parque
//! informatico y lo que llega al analista es ruido.
//!
//! Por eso cada regla se prueba dos veces: con un binario que tiene sus senales
//! y con uno que no las tiene. La segunda es la que descubre la regla que
//! dispara sola.
//!
//! # Y por que se prueban TODAS
//!
//! La prueba recorre [`CATALOGO`] entero y exige las dos comprobaciones de cada
//! entrada. Anadir una regla sin probarla rompe la prueba: no es una convencion
//! que alguien pueda saltarse con prisa, es un fallo de compilacion de la suite.

use std::collections::BTreeSet;

use aegis_disasm::capacidad::Exigencia;
use aegis_disasm::cfg::{Cfg, SinDatos};
use aegis_disasm::importaciones::{Importaciones, Importadas};
use aegis_disasm::instruccion::Arquitectura;
use aegis_disasm::llamadas::GrafoDeLlamadas;
use aegis_disasm::plazo::Plazo;
use aegis_disasm::reglas::{evaluar_una, Contexto, Regla, Senal, CATALOGO};
use aegis_disasm::x86;

/// Una tabla de importaciones de mentira con los nombres que se le den.
///
/// Es de mentira en el nombre pero no en la forma: devuelve nombres en unas
/// direcciones y no en otras, igual que la de verdad.
struct Tabla(Vec<(u64, String)>);

impl Importadas for Tabla {
    fn nombre_en(&self, direccion: u64) -> Option<&str> {
        self.0
            .iter()
            .find(|(d, _)| *d == direccion)
            .map(|(_, n)| n.as_str())
    }
}

/// Un binario de mentira construido para tener ciertas senales.
///
/// # Como se construye, y por que asi
///
/// Las senales de importacion se meten en la tabla; las de instruccion, como
/// bytes de codigo maquina de verdad. No se simula el resultado del analisis: se
/// construye un binario y se analiza. Una prueba que inyectara directamente el
/// resultado comprobaria que el motor sabe leer su propia estructura, que no es
/// lo que hay que comprobar.
struct Muestra {
    codigo: Vec<u8>,
    tabla: Tabla,
}

impl Muestra {
    /// Un binario que no tiene ninguna senal de nada.
    ///
    /// `xor eax,eax` y `ret`: lo mas parecido a un programa vacio que se puede
    /// escribir. Es la base del caso negativo.
    fn vacia() -> Muestra {
        Muestra {
            codigo: vec![0x31, 0xC0, 0xC3],
            tabla: Tabla(Vec::new()),
        }
    }

    /// Un binario que tiene exactamente las senales que se le piden.
    ///
    /// Las senales que **terminan el flujo** se emiten al final. Un salto
    /// incondicional cierra el bloque basico, asi que todo lo que se escribiera
    /// detras quedaria fuera del grafo y no se veria — igual que en un binario
    /// de verdad, donde el salto a la carga descomprimida es lo ultimo que hace
    /// el desempaquetador. Emitirlas en medio daria un negativo falso que
    /// pareceria un fallo de la regla.
    fn con(senales: &[Senal]) -> Muestra {
        let mut m = Muestra {
            codigo: Vec::new(),
            tabla: Tabla(Vec::new()),
        };
        let (cortan, no_cortan): (Vec<&Senal>, Vec<&Senal>) = senales
            .iter()
            .partition(|s| matches!(s, Senal::SaltaFueraDelCodigo));
        for s in no_cortan.into_iter().chain(cortan) {
            m.anadir(s);
        }
        m.codigo.push(0xC3); // ret, para cerrar el bloque
        m
    }

    /// Anade a la muestra lo que hace falta para que una senal se vea.
    fn anadir(&mut self, s: &Senal) {
        match s {
            Senal::Importa(nombre) => {
                // Una llamada indirecta por memoria, con la entrada de la tabla
                // en la direccion a la que apunta. El desplazamiento se elige
                // para que cada nombre caiga en una direccion distinta.
                let n = self.tabla.0.len() as u32;
                let desplazamiento = 0x1000 + n * 8;
                let siguiente = BASE + self.codigo.len() as u64 + 6;
                self.codigo.push(0xFF);
                self.codigo.push(0x15);
                self.codigo.extend_from_slice(&desplazamiento.to_le_bytes());
                self.tabla
                    .0
                    .push((siguiente + desplazamiento as u64, (*nombre).to_owned()));
            }
            // `aesenc xmm0, xmm1`: la unica clase que una regla pide por si
            // misma, y la unica instruccion que la produce.
            Senal::Clase(aegis_disasm::instruccion::Clase::Cripto) => {
                self.codigo
                    .extend_from_slice(&[0x66, 0x0F, 0x38, 0xDC, 0xC1]);
            }
            // `movs byte [rdi], [rsi]`.
            Senal::Clase(aegis_disasm::instruccion::Clase::Cadena) => {
                self.codigo.push(0xA4);
            }
            // `xor eax, ebx`.
            Senal::Clase(aegis_disasm::instruccion::Clase::Logica) => {
                self.codigo.extend_from_slice(&[0x31, 0xD8]);
            }
            Senal::Clase(_) => {
                // Ninguna regla del catalogo pide otra clase. Si alguna la
                // pidiera, esta prueba tiene que enterarse en vez de construir
                // una muestra que no la tiene y dar el negativo por bueno.
                panic!("no se sabe construir una muestra con {s:?}");
            }
            // `mov rax, <constante>`: la forma mas directa de que una constante
            // aparezca en el codigo.
            Senal::Constante(v) => {
                self.codigo.extend_from_slice(&[0x48, 0xB8]);
                self.codigo.extend_from_slice(&v.to_le_bytes());
            }
            // `mov rax, gs:[desplazamiento]` o su version con fs.
            Senal::Segmento(seg, desplazamiento) => {
                let prefijo = match seg {
                    aegis_disasm::instruccion::Segmento::Gs => 0x65,
                    aegis_disasm::instruccion::Segmento::Fs => 0x64,
                };
                self.codigo
                    .extend_from_slice(&[prefijo, 0x48, 0x8B, 0x04, 0x25]);
                self.codigo
                    .extend_from_slice(&(*desplazamiento as u32).to_le_bytes());
            }
            Senal::Resuelve(f) => match f {
                // `mov rax, gs:[0x60]`.
                aegis_disasm::importaciones::Forma::PorEstructurasDelCargador => {
                    self.codigo
                        .extend_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0, 0, 0]);
                }
                // `ror edx, 13`.
                aegis_disasm::importaciones::Forma::PorHashDelNombre => {
                    self.codigo.extend_from_slice(&[0xC1, 0xCA, 0x0D]);
                }
                // Una llamada por la tabla, con un nombre cualquiera.
                aegis_disasm::importaciones::Forma::PorTabla => {
                    self.anadir(&Senal::Importa("AlgunaFuncion"));
                }
            },
            // `mov rax, 0x900000` y `jmp rax`: el control se va a una direccion
            // que no esta en el codigo del fichero.
            Senal::SaltaFueraDelCodigo => {
                self.codigo
                    .extend_from_slice(&[0x48, 0xB8, 0x00, 0x00, 0x90, 0, 0, 0, 0, 0]);
                self.codigo.extend_from_slice(&[0xFF, 0xE0]);
            }
            // `call rax`.
            Senal::LlamadaPorRegistro => {
                self.codigo.extend_from_slice(&[0xFF, 0xD0]);
            }
            // Un bucle de verdad, que escribe en memoria y se repite tantas
            // veces como diga la cota:
            //
            //   inicio: mov [rdi], al ; inc rax ; cmp rax, cota ; jne inicio
            //
            // Va en su propio bloque porque el salto hacia atras lo cierra, y
            // por eso se emite completo y no por piezas.
            Senal::BucleAcotadoA(cota) => {
                let inicio = self.codigo.len();
                self.codigo.extend_from_slice(&[0x88, 0x07]); // mov [rdi], al
                self.codigo.extend_from_slice(&[0x48, 0xFF, 0xC0]); // inc rax
                self.codigo.extend_from_slice(&[0x48, 0x3D]); // cmp rax, imm32
                self.codigo.extend_from_slice(&(*cota as u32).to_le_bytes());
                // `jne` con desplazamiento relativo al final de la propia
                // instruccion, que son dos bytes mas.
                let salto = -((self.codigo.len() + 2 - inicio) as i32);
                self.codigo.push(0x75);
                self.codigo.push(salto as i8 as u8);
            }
        }
    }
}

/// Donde se carga el codigo de las muestras.
const BASE: u64 = 0x1000;

/// Analiza una muestra y evalua una regla sobre ella.
fn dispara(r: &Regla, m: &Muestra) -> bool {
    let t = x86::Tramo::nuevo(&m.codigo, BASE, Arquitectura::X86_64).unwrap();
    let mut p = Plazo::determinista();
    let cfg = Cfg::construir(&t, &SinDatos, &[BASE], &mut p);
    let llamadas = GrafoDeLlamadas::construir(&cfg);
    let importaciones = Importaciones::buscar(&cfg, &m.tabla, Arquitectura::X86_64);
    let ctx = Contexto::nuevo(
        &cfg,
        &llamadas,
        &importaciones,
        &m.codigo,
        BASE,
        Arquitectura::X86_64,
    );
    evaluar_una(r, &ctx).is_some()
}

#[test]
fn toda_regla_dispara_con_lo_que_tiene_que_disparar() {
    // El caso positivo: se construye un binario con **todas** las senales de la
    // regla y se comprueba que la reconoce. Una regla que no dispare aqui es una
    // regla escrita mal, que en produccion no encontraria nunca nada y nadie se
    // enteraria.
    for r in CATALOGO {
        let m = Muestra::con(r.senales);
        assert!(
            dispara(r, &m),
            "«{}» no dispara con un binario que tiene TODAS sus senales",
            r.nombre
        );
    }
}

#[test]
fn ninguna_regla_dispara_con_un_binario_que_no_tiene_nada() {
    // El caso negativo, que es el que descubre la regla que dispara sola. Un
    // `xor eax,eax` y un `ret` no son nada, y una regla que encontrara algo aqui
    // encontraria algo en todos los ficheros de todas las maquinas.
    let m = Muestra::vacia();
    for r in CATALOGO {
        assert!(
            !dispara(r, &m),
            "«{}» dispara con un binario vacio: en produccion disparara con todo",
            r.nombre
        );
    }
}

#[test]
fn una_regla_de_varias_senales_no_dispara_con_una_sola() {
    // La propiedad que hace que el catalogo sea utilizable. `VirtualAlloc` lo
    // llama medio Windows; lo que significa algo son las tres juntas. Una regla
    // de tres senales que dispare con una es una regla de una senal con dos de
    // adorno.
    for r in CATALOGO {
        let minimo = match r.exigencia {
            Exigencia::Todas => r.senales.len(),
            Exigencia::AlMenos(n) => n,
            // Estas disparan con una a proposito, y esa decision esta revisada
            // una por una en las pruebas de `reglas`.
            Exigencia::Alguna => continue,
        };
        if minimo < 2 {
            continue;
        }
        // Con una senal menos de las que pide, no puede disparar.
        let cuantas = minimo - 1;
        let m = Muestra::con(&r.senales[..cuantas]);
        assert!(
            !dispara(r, &m),
            "«{}» pide {minimo} senales y dispara con {cuantas}",
            r.nombre
        );
    }
}

#[test]
fn toda_capacidad_encontrada_trae_evidencia_dentro_del_codigo_analizado() {
    // Una evidencia que apunte fuera del codigo es peor que no tenerla: da la
    // apariencia de comprobable sin serlo, y quien vaya a mirar esa direccion no
    // encontrara nada.
    for r in CATALOGO {
        let m = Muestra::con(r.senales);
        let t = x86::Tramo::nuevo(&m.codigo, BASE, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::determinista();
        let cfg = Cfg::construir(&t, &SinDatos, &[BASE], &mut p);
        let llamadas = GrafoDeLlamadas::construir(&cfg);
        let importaciones = Importaciones::buscar(&cfg, &m.tabla, Arquitectura::X86_64);
        let ctx = Contexto::nuevo(
            &cfg,
            &llamadas,
            &importaciones,
            &m.codigo,
            BASE,
            Arquitectura::X86_64,
        );
        let Some(c) = evaluar_una(r, &ctx) else {
            continue;
        };
        assert!(!c.evidencias().is_empty(), "{}", r.nombre);
        for e in c.evidencias() {
            assert!(
                e.donde >= BASE && e.donde < BASE + m.codigo.len() as u64,
                "«{}»: la evidencia apunta a {:#x}, fuera del codigo [{BASE:#x}, {:#x})",
                r.nombre,
                e.donde,
                BASE + m.codigo.len() as u64
            );
            assert!(
                !e.porque.is_empty(),
                "«{}»: hay una evidencia sin explicacion",
                r.nombre
            );
        }
    }
}

#[test]
fn las_reglas_no_se_tapan_unas_a_otras() {
    // Dos reglas que miren exactamente lo mismo son una regla y un duplicado: el
    // informe contaria dos capacidades donde hay un hecho, y quien lo lea
    // creeria que el binario hace dos cosas.
    let mut vistas: BTreeSet<Vec<String>> = BTreeSet::new();
    for r in CATALOGO {
        let mut clave: Vec<String> = r.senales.iter().map(|s| format!("{s:?}")).collect();
        clave.sort();
        clave.push(format!("{:?}", r.exigencia));
        assert!(
            vistas.insert(clave),
            "«{}» mira exactamente lo mismo que otra regla con la misma exigencia",
            r.nombre
        );
    }
}
