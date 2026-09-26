//! Entrada y salida de conocimiento, por los caminos que ya existen.
//!
//! # Entrada
//!
//! Tres formas, todas validadas por `aegis_share::stix` con sus topes y sus
//! reglas —el marcado que no resuelve es RED, la propiedad sin prefijo `x_` se
//! rechaza, el identificador tiene que cuadrar con su tipo—:
//!
//! - un paquete suelto ([`importar`]);
//! - una coleccion grande y confiada, objeto a objeto, con el marcado que el
//!   operador DECLARA para lo que calla ([`importar_declarado`]);
//! - una coleccion TAXII, agotando sus paginas ([`sondear`]).
//!
//! # Salida: una, y es la de siempre
//!
//! [`exportar`] es la UNICA funcion de este crate que produce un documento para
//! fuera, y lo hace despues de que el [`Difusor`] haya juzgado cada objeto
//! contra su destino declarado. No hay un segundo camino: lo observado (la
//! telemetria de este despliegue) no esta entre los objetos del grafo y no
//! puede salir por aqui, y las hipotesis no son objetos. `tools/verificar-
//! conocimiento.sh` comprueba por estructura que el documento solo se construye
//! aqui.

use aegis_share::difusion::{Difusor, Reparto};
use aegis_share::procedencia::Aporte;
use aegis_share::stix::{Declaracion, Paquete, Rechazo};
use aegis_share::taxii::{Cliente, Servidor};

use crate::grafo::{Absorcion, Grafo};

/// Lo que dejo una importacion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Importacion {
    /// Objetos nuevos.
    pub nuevos: usize,
    /// Objetos actualizados a una version mas reciente.
    pub actualizados: usize,
    /// Objetos que ya estaban igual o mas nuevos (se anoto la fuente).
    pub anotados: usize,
    /// Objetos que no cupieron.
    pub rechazados_por_tope: usize,
}

impl Importacion {
    fn contar(&mut self, a: Absorcion) {
        match a {
            Absorcion::Nuevo => self.nuevos += 1,
            Absorcion::Actualizado => self.actualizados += 1,
            Absorcion::Anotado => self.anotados += 1,
            Absorcion::Lleno => self.rechazados_por_tope += 1,
        }
    }

    /// Total de objetos entregados por la fuente.
    #[must_use]
    pub fn total(&self) -> usize {
        self.nuevos + self.actualizados + self.anotados + self.rechazados_por_tope
    }
}

/// Importa un paquete. `aporte` es la fuente que lo entrega; su
/// `id_en_origen` se rellena con el de cada objeto.
///
/// # Errors
///
/// El [`Rechazo`] del paquete: si no valida, no entra nada.
pub fn importar(g: &mut Grafo, texto: &str, aporte: &Aporte) -> Result<Importacion, Rechazo> {
    let mut r = Importacion::default();
    Paquete::recorrer(texto, |o| {
        let mut a = aporte.clone();
        a.id_en_origen.clone_from(&o.id);
        r.contar(g.absorber(o, a));
    })?;
    Ok(r)
}

/// Importa una coleccion con el marcado que el operador declara para lo que
/// calla (ver `aegis_share::stix::Paquete::recorrer_declarado`).
///
/// # Errors
///
/// El [`Rechazo`] de la coleccion, o de una declaracion sin autor.
pub fn importar_declarado(
    g: &mut Grafo,
    texto: &str,
    aporte: &Aporte,
    declaracion: &Declaracion,
) -> Result<Importacion, Rechazo> {
    let mut r = Importacion::default();
    Paquete::recorrer_declarado(texto, declaracion, |o| {
        let mut a = aporte.clone();
        a.id_en_origen.clone_from(&o.id);
        r.contar(g.absorber(o, a));
    })?;
    Ok(r)
}

/// Sondea una coleccion TAXII y absorbe todo lo nuevo.
///
/// # Errors
///
/// Si el servidor rechaza la peticion.
pub fn sondear(
    g: &mut Grafo,
    cliente: &mut Cliente,
    servidor: &Servidor,
    coleccion: &str,
    aporte: &Aporte,
) -> Result<Importacion, String> {
    let mut r = Importacion::default();
    for o in cliente.sondear(servidor, coleccion, aegis_share::taxii::MAX_PAGINA)? {
        let mut a = aporte.clone();
        a.id_en_origen.clone_from(&o.id);
        r.contar(g.absorber(o, a));
    }
    Ok(r)
}

/// Lo que sale hacia un destino.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Salida {
    /// Que sale y que se queda, con su motivo.
    pub reparto: Reparto,
    /// El paquete STIX con SOLO lo que sale.
    pub documento: String,
}

/// Exporta el conocimiento hacia un destino declarado, pasando por el juez
/// unico de difusion.
///
/// # Errors
///
/// Si el destino no esta declarado en el difusor: no se exporta a ciegas.
pub fn exportar(
    g: &Grafo,
    difusor: &Difusor,
    destino: &str,
    id_paquete: &str,
) -> Result<Salida, String> {
    let todo = Paquete {
        id: id_paquete.to_string(),
        objetos: g.objetos().map(|o| (o.id.clone(), o.clone())).collect(),
    };
    let reparto = difusor.repartir(&todo, destino)?;
    let salen = Paquete {
        id: todo.id,
        objetos: todo
            .objetos
            .into_iter()
            .filter(|(id, _)| reparto.salen.binary_search(id).is_ok())
            .collect(),
    };
    Ok(Salida {
        documento: salen.a_json(),
        reparto,
    })
}
