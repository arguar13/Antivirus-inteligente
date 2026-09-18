//! **Donde** se sembro un token, que es lo que lo hace util al dispararse.
//!
//! # El fallo que este modulo existe para impedir
//!
//! Un honey-token que solo dice «te han robado una credencial» sirve de poco. La
//! pregunta que hay que contestar en un incidente es **por donde entraron**, y esa
//! solo se contesta si el token dice de que sitio salio: de este fichero, de la
//! memoria de este proceso, de esta fila de esta tabla, de esta clave de esta API.
//!
//! La forma de conseguirlo no es apuntarlo en una tabla aparte —una tabla se
//! desincroniza, se pierde con la maquina, y el atacante que borre registros se la
//! lleva por delante—. Es derivar el marcador **del destino mismo**: la credencial
//! sembrada en `/root/.pgpass` y la sembrada en la fila 7 de `clientes` son
//! literalmente credenciales distintas, porque su marcador se calcula sobre donde
//! van. Cuando una aparece, el sitio del que salio esta dentro de ella.
//!
//! # Por que la clase va primero en el computo
//!
//! Porque si no, dos destinos distintos podrian dar los mismos bytes y por tanto
//! el mismo marcador. Un fichero llamado `prod` y una base llamada `prod` no
//! pueden colisionar: la etiqueta de clase se mete ANTES del texto, asi que ni
//! siquiera son la misma entrada del computo. Es la misma razon por la que los
//! campos van separados por un byte nulo.

/// El sitio concreto donde se sembro un token.
///
/// Cada variante es una superficie por la que un atacante recolecta credenciales
/// despues de entrar. No son categorias de informe: son los sitios de los que sale
/// una credencial robada, y cada uno dice algo distinto de por donde entraron.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Destino {
    /// Un fichero del disco: `.pgpass`, `authorized_keys`, un `credentials.xml`.
    ///
    /// Que se toque significa que alguien esta leyendo el disco buscando
    /// credenciales, que es el paso siguiente a conseguir ejecucion.
    Fichero {
        /// La ruta completa.
        ruta: String,
    },
    /// La memoria de un proceso vivo: un agente SSH, un gestor de secretos.
    ///
    /// Que se toque significa que alguien esta leyendo memoria ajena, que exige
    /// privilegios y es mucho mas grave que leer un fichero.
    Memoria {
        /// El proceso donde se coloco.
        proceso: String,
    },
    /// Un nombre de DNS que no resuelve a nada util.
    ///
    /// Que se consulte significa que la credencial salio de la organizacion: el
    /// atacante la esta probando desde fuera, o una herramienta suya resolvio el
    /// nombre que venia en ella. Es la unica de las seis que puede dispararse
    /// **sin que el atacante toque la maquina**, y por eso vale su peso en oro.
    Dns {
        /// El nombre sembrado.
        nombre: String,
    },
    /// Una clave de API de un servicio, con la ruta a la que llamaria.
    Api {
        /// El servicio que la credencial dice ser.
        servicio: String,
        /// La ruta que se llamaria con ella.
        ruta: String,
    },
    /// Una fila de una tabla de una base de datos.
    ///
    /// Es la que delata el volcado: nadie consulta una fila concreta de una tabla
    /// de clientes por casualidad, pero un `SELECT *` se la lleva entera.
    Fila {
        /// La base.
        base: String,
        /// La tabla.
        tabla: String,
        /// La columna donde vive el marcador.
        columna: String,
        /// Que fila.
        fila: u64,
    },
    /// Dentro de un senuelo de red: lo que el senuelo le entrega al que entra.
    ///
    /// Un atacante que «gana» en el senuelo se lleva credenciales que solo existen
    /// ahi. Cuando las use en otro sitio, se sabra que entro por el senuelo — y lo
    /// que este NO puede saber es lo que el atacante hizo despues, que es lo que
    /// esto viene a contestar.
    Senuelo {
        /// Que servicio se estaba fingiendo.
        servicio: String,
        /// En que puerto.
        puerto: u16,
    },
}

impl Destino {
    /// La clase, estable y corta, para informes y para el computo del marcador.
    #[must_use]
    pub fn clase(&self) -> &'static str {
        match self {
            Destino::Fichero { .. } => "fichero",
            Destino::Memoria { .. } => "memoria",
            Destino::Dns { .. } => "dns",
            Destino::Api { .. } => "api",
            Destino::Fila { .. } => "fila",
            Destino::Senuelo { .. } => "senuelo",
        }
    }

    /// Como se nombra en una alerta, para que un analista sepa donde mirar.
    #[must_use]
    pub fn frase(&self) -> String {
        match self {
            Destino::Fichero { ruta } => format!("el fichero {ruta}"),
            Destino::Memoria { proceso } => format!("la memoria del proceso {proceso}"),
            Destino::Dns { nombre } => format!("el nombre de DNS {nombre}"),
            Destino::Api { servicio, ruta } => format!("la clave de API de {servicio} para {ruta}"),
            Destino::Fila {
                base,
                tabla,
                columna,
                fila,
            } => format!("la fila {fila} de {base}.{tabla}, columna {columna}"),
            Destino::Senuelo { servicio, puerto } => {
                format!("el senuelo de {servicio} del puerto {puerto}")
            }
        }
    }

    /// Si el disparo implica que la credencial salio de la organizacion.
    ///
    /// Solo el DNS lo implica por si solo: los demas se disparan con el atacante
    /// todavia dentro. La distincion cambia la respuesta —uno se contiene, el otro
    /// ya hay que notificarlo—, asi que se dice en el tipo y no en un comentario.
    #[must_use]
    pub fn implica_que_salio(&self) -> bool {
        matches!(self, Destino::Dns { .. })
    }

    /// Los bytes canonicos del destino, para el computo del marcador.
    ///
    /// La **clase va primero**: sin ella, un fichero llamado `prod` y una base
    /// llamada `prod` podrian dar los mismos bytes, y dos destinos distintos con
    /// el mismo marcador es exactamente perder la procedencia que este modulo
    /// existe para dar. Los campos van separados por un byte nulo por lo mismo:
    /// («a», «bc») y («ab», «c») no pueden ser la misma entrada.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(self.clase().as_bytes());
        v.push(0);
        let mut campo = |s: &str| {
            v.extend_from_slice(s.as_bytes());
            v.push(0);
        };
        match self {
            Destino::Fichero { ruta } => campo(ruta),
            Destino::Memoria { proceso } => campo(proceso),
            Destino::Dns { nombre } => campo(nombre),
            Destino::Api { servicio, ruta } => {
                campo(servicio);
                campo(ruta);
            }
            Destino::Fila {
                base,
                tabla,
                columna,
                fila,
            } => {
                campo(base);
                campo(tabla);
                campo(columna);
                v.extend_from_slice(&fila.to_be_bytes());
                v.push(0);
            }
            Destino::Senuelo { servicio, puerto } => {
                campo(servicio);
                v.extend_from_slice(&puerto.to_be_bytes());
                v.push(0);
            }
        }
        v
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn dos_clases_con_el_mismo_texto_no_colisionan() {
        // Es el fallo que la etiqueta de clase impide: si los bytes fueran solo el
        // texto, estos dos destinos serian el mismo y el marcador no diria de cual
        // de los dos salio la credencial.
        let f = Destino::Fichero {
            ruta: "prod".to_owned(),
        };
        let d = Destino::Dns {
            nombre: "prod".to_owned(),
        };
        assert_ne!(f.bytes(), d.bytes());
    }

    #[test]
    fn los_campos_no_se_pueden_recolocar_para_colisionar() {
        // («a», «bc») y («ab», «c») dan los mismos bytes si no hay separador.
        let a = Destino::Api {
            servicio: "a".to_owned(),
            ruta: "bc".to_owned(),
        };
        let b = Destino::Api {
            servicio: "ab".to_owned(),
            ruta: "c".to_owned(),
        };
        assert_ne!(a.bytes(), b.bytes());
    }

    #[test]
    fn dos_filas_distintas_de_la_misma_tabla_son_destinos_distintos() {
        let f = |n| Destino::Fila {
            base: "crm".to_owned(),
            tabla: "clientes".to_owned(),
            columna: "notas".to_owned(),
            fila: n,
        };
        assert_ne!(f(7).bytes(), f(8).bytes());
    }

    #[test]
    fn solo_el_dns_implica_que_la_credencial_salio() {
        assert!(Destino::Dns {
            nombre: "x".to_owned()
        }
        .implica_que_salio());
        for d in [
            Destino::Fichero {
                ruta: "x".to_owned(),
            },
            Destino::Memoria {
                proceso: "x".to_owned(),
            },
            Destino::Api {
                servicio: "x".to_owned(),
                ruta: "y".to_owned(),
            },
            Destino::Fila {
                base: "a".to_owned(),
                tabla: "b".to_owned(),
                columna: "c".to_owned(),
                fila: 1,
            },
            Destino::Senuelo {
                servicio: "ssh".to_owned(),
                puerto: 22,
            },
        ] {
            assert!(!d.implica_que_salio(), "{d:?}");
        }
    }

    #[test]
    fn la_frase_dice_donde_mirar() {
        let d = Destino::Fila {
            base: "crm".to_owned(),
            tabla: "clientes".to_owned(),
            columna: "notas".to_owned(),
            fila: 7,
        };
        assert_eq!(d.frase(), "la fila 7 de crm.clientes, columna notas");
    }
}
