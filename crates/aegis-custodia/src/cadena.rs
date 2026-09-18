//! La cadena de custodia: quien toco la evidencia, cuando, y en que orden.
//!
//! # Que anade sobre el sello
//!
//! El sello prueba de donde salio la evidencia. No dice nada de lo que le paso
//! despues, y en un incidente le pasan cosas: viaja del endpoint al plano de
//! control, se archiva, se exporta a un tercero, un analista la abre. Cada uno
//! de esos pasos es una oportunidad de alterarla, y la pregunta que hay que
//! poder contestar no es solo «¿es autentica?» sino **«¿por cuantas manos paso y
//! consta lo que hizo cada una?»**.
//!
//! # Por que encadenada por resumen y no una lista firmada
//!
//! Una lista de pasos, cada uno con su firma, se puede podar: quitar el eslabon
//! incomodo deja una lista mas corta cuyos eslabones siguen verificando uno a
//! uno. Lo que hay que impedir no es alterar un eslabon —eso lo para la firma—
//! sino **quitarlo, insertarlo o reordenarlo**.
//!
//! Por eso cada eslabon lleva el resumen del anterior DENTRO de lo que firma.
//! Quitar uno deja al siguiente apuntando a algo que ya no esta; insertar uno
//! rompe el enganche del que venia detras; reordenarlos los rompe todos. La
//! cadena solo verifica entera y en su orden.
//!
//! El primer eslabon apunta a la identidad del sello, no a un cero. Asi la
//! cadena queda **anclada a la evidencia concreta**: una cadena legitima de otro
//! artefacto no se puede pegar a este.
//!
//! # Una cadena vacia no es una cadena intacta
//!
//! Son dos cosas distintas y el codigo las distingue: una cadena sin eslabones
//! no dice «nadie toco esto», dice «nadie anoto nada». Verificarla devuelve
//! [`CustodiaError::CadenaVacia`] y no un aprobado, porque la ausencia de
//! registro es justo lo que produce una custodia rota.

use std::collections::BTreeMap;

use aegis_pqc::firma_hibrida::{ClaveFirmaHibrida, ClaveVerificacionHibrida, FirmaHibrida};

use crate::canon::{hex, Codificador, Resumen};
use crate::error::CustodiaError;
use crate::reloj::Marca;
use crate::sello::Sello;

/// Contexto de firma de un eslabon.
pub const CTX_ESLABON: &[u8] = b"aegis-custodia/eslabon/v1";

/// Que se le hizo a la evidencia.
///
/// Los discriminantes son parte del formato canonico y **no se pueden cambiar**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Paso {
    /// Se recogio del endpoint. Es siempre el primero.
    Recogida = 1,
    /// Viajo del endpoint al plano de control.
    Transferencia = 2,
    /// Quedo archivada en el almacen de evidencia.
    Archivo = 3,
    /// Se entrego a un tercero: otro equipo, un proveedor, un juzgado.
    Entrega = 4,
    /// Alguien la abrio para analizarla.
    Acceso = 5,
    /// Se destruyo al cumplirse su plazo de conservacion.
    Destruccion = 6,
}

impl Paso {
    /// Nombre legible, para el informe.
    pub fn nombre(&self) -> &'static str {
        match self {
            Paso::Recogida => "recogida",
            Paso::Transferencia => "transferencia",
            Paso::Archivo => "archivo",
            Paso::Entrega => "entrega",
            Paso::Acceso => "acceso",
            Paso::Destruccion => "destruccion",
        }
    }
}

/// Un paso de la custodia, firmado por quien lo dio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eslabon {
    /// Que se hizo.
    pub paso: Paso,
    /// Quien lo hizo, tal y como lo conoce la PKI de la flota.
    pub actor: String,
    /// El detalle que hace falta para entenderlo: a donde viajo, por que se
    /// abrio, a quien se entrego.
    pub detalle: String,
    /// Cuando, por los dos relojes.
    pub cuando: Marca,
    /// Resumen del eslabon anterior; en el primero, la identidad del sello.
    pub previo: Resumen,
    /// Firma hibrida sobre la codificacion canonica de todo lo anterior.
    pub firma: Vec<u8>,
}

impl Eslabon {
    /// Los bytes canonicos que la firma cubre.
    fn mensaje(
        paso: Paso,
        actor: &str,
        detalle: &str,
        cuando: &Marca,
        previo: &Resumen,
    ) -> Vec<u8> {
        let mut c = Codificador::nuevo("aegis-custodia/eslabon/v1");
        c.u8(paso as u8).texto(actor).texto(detalle);
        cuando.codificar(&mut c);
        c.resumen_de(previo);
        c.fin()
    }

    /// Resumen de este eslabon, que es a lo que apunta el siguiente.
    ///
    /// Cubre la firma ademas del contenido: si solo cubriera el contenido, dos
    /// eslabones iguales firmados por actores distintos tendrian el mismo
    /// resumen y se podrian intercambiar sin romper la cadena.
    pub fn resumen(&self) -> Resumen {
        let mut c = Codificador::nuevo("aegis-custodia/resumen-de-eslabon/v1");
        c.bytes(&Eslabon::mensaje(
            self.paso,
            &self.actor,
            &self.detalle,
            &self.cuando,
            &self.previo,
        ))
        .bytes(&self.firma);
        c.resumen()
    }

    /// Comprueba que la firma de este eslabon es de `clave`.
    fn firma_valida(&self, clave: &ClaveVerificacionHibrida) -> Result<(), CustodiaError> {
        let Ok(firma) = FirmaHibrida::desde_bytes(&self.firma) else {
            return Err(CustodiaError::FirmaQueNoCubre {
                que: format!("el eslabon de {} (firma mal formada)", self.paso.nombre()),
            });
        };
        let mensaje = Eslabon::mensaje(
            self.paso,
            &self.actor,
            &self.detalle,
            &self.cuando,
            &self.previo,
        );
        if clave.verificar(&mensaje, CTX_ESLABON, &firma) {
            Ok(())
        } else {
            Err(CustodiaError::FirmaQueNoCubre {
                que: format!("el eslabon de {}", self.paso.nombre()),
            })
        }
    }
}

/// Las claves publicas de quienes pueden firmar custodia.
///
/// Es un rasgo y no un mapa concreto porque en produccion las claves salen de la
/// PKI de la flota, con su vigencia y sus revocaciones, y en las pruebas de un
/// mapa. Lo que no cambia es la regla: una identidad que no consta **no** se
/// aprueba por defecto.
pub trait RegistroDeClaves {
    /// Devuelve la clave de una identidad, si consta.
    fn clave_de(&self, identidad: &str) -> Option<&ClaveVerificacionHibrida>;
}

/// Registro sencillo sobre un mapa ordenado.
#[derive(Default, Clone)]
pub struct Claveros {
    claves: BTreeMap<String, ClaveVerificacionHibrida>,
}

impl Claveros {
    /// Registro vacio.
    pub fn nuevo() -> Claveros {
        Claveros::default()
    }

    /// Da de alta la clave de una identidad.
    pub fn con(mut self, identidad: &str, clave: ClaveVerificacionHibrida) -> Claveros {
        self.claves.insert(identidad.to_owned(), clave);
        self
    }
}

impl RegistroDeClaves for Claveros {
    fn clave_de(&self, identidad: &str) -> Option<&ClaveVerificacionHibrida> {
        self.claves.get(identidad)
    }
}

/// La custodia completa de un artefacto: su ancla y sus pasos, en orden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CadenaDeCustodia {
    /// Identidad del sello del que arranca.
    pub ancla: Resumen,
    /// Los pasos, en el orden en que ocurrieron.
    pub eslabones: Vec<Eslabon>,
}

impl CadenaDeCustodia {
    /// Abre una cadena anclada a un sello.
    ///
    /// Nace vacia y sin probar nada. El primer eslabon lo anade quien recogio la
    /// evidencia, con [`CadenaDeCustodia::anadir`].
    pub fn anclada_en(sello: &Sello) -> CadenaDeCustodia {
        CadenaDeCustodia {
            ancla: sello.identidad(),
            eslabones: Vec::new(),
        }
    }

    /// A que tiene que apuntar el proximo eslabon.
    fn punta(&self) -> Resumen {
        match self.eslabones.last() {
            Some(e) => e.resumen(),
            None => self.ancla,
        }
    }

    /// Anade un paso, firmado por quien lo da.
    pub fn anadir(
        &mut self,
        paso: Paso,
        actor: &str,
        detalle: &str,
        clave: &ClaveFirmaHibrida,
    ) -> Result<(), CustodiaError> {
        let cuando = Marca::ahora();
        let previo = self.punta();
        let mensaje = Eslabon::mensaje(paso, actor, detalle, &cuando, &previo);
        let firma = clave
            .firmar(&mensaje, CTX_ESLABON)
            .map_err(|e| CustodiaError::NoSePudoFirmar(format!("{e:?}")))?;
        self.eslabones.push(Eslabon {
            paso,
            actor: actor.to_owned(),
            detalle: detalle.to_owned(),
            cuando,
            previo,
            firma: firma.a_bytes(),
        });
        Ok(())
    }

    /// Comprueba la cadena entera contra el sello del que dice venir.
    ///
    /// Tres cosas, en este orden, porque fallar en la primera hace inutil mirar
    /// las siguientes:
    ///
    /// 1. Que no este vacia: sin un solo eslabon no consta ni la recogida.
    /// 2. Que ancle en ESTE sello y no en otro.
    /// 3. Que cada eslabon enganche con el anterior y lo firme quien dice.
    pub fn verificar(
        &self,
        sello: &Sello,
        registro: &dyn RegistroDeClaves,
    ) -> Result<(), CustodiaError> {
        if self.eslabones.is_empty() {
            return Err(CustodiaError::CadenaVacia);
        }
        let identidad = sello.identidad();
        if self.ancla != identidad {
            return Err(CustodiaError::CadenaSinAncla {
                declarado: hex(&self.ancla),
                real: hex(&identidad),
            });
        }
        let mut esperado = self.ancla;
        for (posicion, eslabon) in self.eslabones.iter().enumerate() {
            if eslabon.previo != esperado {
                return Err(CustodiaError::CadenaRota {
                    posicion,
                    declarado: hex(&eslabon.previo),
                    real: hex(&esperado),
                });
            }
            let Some(clave) = registro.clave_de(&eslabon.actor) else {
                return Err(CustodiaError::FirmanteDesconocido {
                    firmante: eslabon.actor.clone(),
                });
            };
            eslabon.firma_valida(clave)?;
            esperado = eslabon.resumen();
        }
        Ok(())
    }

    /// Pares de eslabones consecutivos cuyas marcas se contradicen.
    ///
    /// Una cadena puede estar criptograficamente intacta y aun asi contar una
    /// cronologia imposible, porque el reloj de pared de alguna de las maquinas
    /// se movio. Eso no invalida la evidencia —los bytes siguen siendo los
    /// sellados— pero si invalida el razonamiento temporal que se haga con ella,
    /// asi que se reporta aparte en vez de mezclarse con la verificacion.
    ///
    /// Devuelve la posicion del segundo eslabon de cada par incoherente.
    pub fn saltos_de_reloj(&self) -> Vec<usize> {
        let mut v = Vec::new();
        for i in 1..self.eslabones.len() {
            if self.eslabones[i]
                .cuando
                .incoherente_con(&self.eslabones[i - 1].cuando)
            {
                v.push(i);
            }
        }
        v
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::sello::{Clase, Procedencia};

    fn clave() -> ClaveFirmaHibrida {
        ClaveFirmaHibrida::generar_aleatorio().expect("generar clave")
    }

    fn sello_de(clave: &ClaveFirmaHibrida) -> Sello {
        Sello::sellar(
            b"volcado",
            Procedencia {
                caso: "CASO-1".into(),
                endpoint: "endpoint-7".into(),
                agente: "agente-7".into(),
                version_agente: "1.0.0".into(),
                clase: Clase::Memoria,
                motivo: "region anonima ejecutable".into(),
                tecnicas: vec!["T1055".into()],
                recogido: Marca::ahora(),
            },
            clave,
        )
        .unwrap()
    }

    /// Una cadena de tres pasos con tres actores, y su registro de claves.
    fn cadena_completa() -> (Sello, CadenaDeCustodia, Claveros) {
        let ka = clave();
        let kb = clave();
        let kc = clave();
        let sello = sello_de(&ka);
        let mut cadena = CadenaDeCustodia::anclada_en(&sello);
        cadena
            .anadir(Paso::Recogida, "agente-7", "disparada por el motor", &ka)
            .unwrap();
        cadena
            .anadir(Paso::Transferencia, "plano-de-control", "por mTLS", &kb)
            .unwrap();
        cadena
            .anadir(Paso::Acceso, "analista-3", "triaje del caso", &kc)
            .unwrap();
        let registro = Claveros::nuevo()
            .con("agente-7", ka.clave_verificacion())
            .con("plano-de-control", kb.clave_verificacion())
            .con("analista-3", kc.clave_verificacion());
        (sello, cadena, registro)
    }

    #[test]
    fn una_cadena_intacta_verifica() {
        let (sello, cadena, registro) = cadena_completa();
        cadena.verificar(&sello, &registro).unwrap();
    }

    #[test]
    fn quitar_un_eslabon_del_medio_rompe_la_cadena() {
        // El ataque que una lista de firmas sueltas NO para: podar el paso
        // incomodo deja una lista mas corta cuyas firmas siguen siendo validas
        // una a una.
        let (sello, mut cadena, registro) = cadena_completa();
        cadena.eslabones.remove(1);
        let err = cadena.verificar(&sello, &registro).unwrap_err();
        assert!(
            matches!(err, CustodiaError::CadenaRota { posicion: 1, .. }),
            "{err}"
        );
    }

    #[test]
    fn podar_la_cadena_por_el_final_no_lo_detecta_el_encadenado() {
        // La limitacion del metodo, escrita como prueba para que no se olvide y
        // para que si algun dia deja de ser cierta, esta prueba falle y alguien
        // lo mire.
        //
        // Quitar el ultimo eslabon no rompe ningun enganche: lo que queda es un
        // prefijo legitimo, y verifica. Ninguna cadena puede detectar esto por
        // si sola —no lleva dentro cuantos eslabones deberia tener, y si lo
        // llevara, quien pueda podar el ultimo puede podar tambien ese numero—.
        //
        // Lo que SI lo detecta esta fuera de la cadena: la contraparte que firmo
        // el eslabon podado conserva su copia. El plano de control no puede
        // podar lo que el analista tiene, ni el analista lo que tiene el plano
        // de control. Por eso la custodia es de DOS lados y por eso
        // `Veredicto::no_demuestra` lo dice en vez de dejar que quien lea el
        // informe suponga lo contrario.
        let (sello, mut cadena, registro) = cadena_completa();
        let podado = cadena.eslabones.pop().unwrap();
        assert_eq!(podado.paso, Paso::Acceso);
        assert!(
            cadena.verificar(&sello, &registro).is_ok(),
            "un prefijo de una cadena valida es una cadena valida: esto es la \
             limitacion del metodo, no un fallo de esta implementacion"
        );
    }

    #[test]
    fn reordenar_dos_eslabones_rompe_la_cadena() {
        let (sello, mut cadena, registro) = cadena_completa();
        cadena.eslabones.swap(0, 1);
        assert!(matches!(
            cadena.verificar(&sello, &registro).unwrap_err(),
            CustodiaError::CadenaRota { posicion: 0, .. }
        ));
    }

    #[test]
    fn insertar_un_eslabon_inventado_rompe_la_cadena() {
        let (sello, mut cadena, registro) = cadena_completa();
        let falso = cadena.eslabones[2].clone();
        cadena.eslabones.insert(1, falso);
        assert!(matches!(
            cadena.verificar(&sello, &registro).unwrap_err(),
            CustodiaError::CadenaRota { posicion: 1, .. }
        ));
    }

    #[test]
    fn alterar_el_detalle_de_un_eslabon_invalida_su_firma() {
        let (sello, mut cadena, registro) = cadena_completa();
        cadena.eslabones[2].detalle = "no lo abrio nadie".into();
        assert!(matches!(
            cadena.verificar(&sello, &registro).unwrap_err(),
            CustodiaError::FirmaQueNoCubre { .. }
        ));
    }

    #[test]
    fn cambiar_quien_dio_un_paso_no_cuela() {
        let (sello, mut cadena, registro) = cadena_completa();
        cadena.eslabones[2].actor = "analista-9".into();
        let err = cadena.verificar(&sello, &registro).unwrap_err();
        assert!(
            matches!(err, CustodiaError::FirmanteDesconocido { .. }),
            "{err}"
        );
    }

    #[test]
    fn un_actor_que_no_consta_no_se_aprueba_por_defecto() {
        let ka = clave();
        let sello = sello_de(&ka);
        let mut cadena = CadenaDeCustodia::anclada_en(&sello);
        cadena
            .anadir(Paso::Recogida, "desconocido", "", &ka)
            .unwrap();
        let err = cadena.verificar(&sello, &Claveros::nuevo()).unwrap_err();
        assert!(
            matches!(err, CustodiaError::FirmanteDesconocido { .. }),
            "sin clave no hay nada que comprobar, y eso no es un aprobado: {err}"
        );
    }

    #[test]
    fn una_cadena_vacia_no_es_una_cadena_intacta() {
        let ka = clave();
        let sello = sello_de(&ka);
        let cadena = CadenaDeCustodia::anclada_en(&sello);
        let err = cadena.verificar(&sello, &Claveros::nuevo()).unwrap_err();
        assert!(
            matches!(err, CustodiaError::CadenaVacia),
            "sin un solo eslabon no consta ni la recogida: {err}"
        );
    }

    #[test]
    fn una_cadena_legitima_de_otro_artefacto_no_se_pega_a_este() {
        // La cadena entera es autentica y sus firmas validas; lo que no es, es
        // de esta evidencia. El ancla lo dice.
        let (_, cadena, registro) = cadena_completa();
        let otra_clave = clave();
        let otro_sello = sello_de(&otra_clave);
        let err = cadena.verificar(&otro_sello, &registro).unwrap_err();
        assert!(matches!(err, CustodiaError::CadenaSinAncla { .. }), "{err}");
    }

    #[test]
    fn el_primer_eslabon_apunta_al_sello() {
        let ka = clave();
        let sello = sello_de(&ka);
        let mut cadena = CadenaDeCustodia::anclada_en(&sello);
        cadena.anadir(Paso::Recogida, "agente-7", "", &ka).unwrap();
        assert_eq!(cadena.eslabones[0].previo, sello.identidad());
    }

    #[test]
    fn un_salto_de_reloj_se_reporta_sin_invalidar_la_evidencia() {
        let (sello, mut cadena, registro) = cadena_completa();
        // Se fuerza la contradiccion en las marcas SIN tocar nada firmado: el
        // reloj de la maquina se movio, la evidencia sigue intacta.
        for (i, e) in cadena.eslabones.iter_mut().enumerate() {
            e.cuando.arranque = 42;
            e.cuando.arranque_ns = (i as u64 + 1) * 1_000;
        }
        cadena.eslabones[0].cuando.pared = 1_700_000_100;
        cadena.eslabones[1].cuando.pared = 1_700_000_000; // hacia atras
        cadena.eslabones[2].cuando.pared = 1_700_000_200;

        assert_eq!(
            cadena.saltos_de_reloj(),
            vec![1],
            "el segundo eslabon ocurre despues y dice una hora anterior"
        );
        // Y aun asi, lo que la verificacion mira no depende de eso: las marcas
        // alteradas rompen las firmas, que es lo correcto. Se comprueba que la
        // deteccion de saltos NO necesita que la cadena verifique, porque
        // justamente sirve para una cadena que si verifica en otra maquina.
        assert!(cadena.verificar(&sello, &registro).is_err());
    }

    #[test]
    fn una_cadena_coherente_no_declara_saltos_de_reloj() {
        let (_, cadena, _) = cadena_completa();
        assert!(cadena.saltos_de_reloj().is_empty());
    }
}
