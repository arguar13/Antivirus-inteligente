//! Fusion de alertas en casos: mil alertas de una campana son un caso.
//!
//! # El problema, con numeros
//!
//! Un ransomware cifrando un servidor de ficheros dispara la regla de cifrado
//! masivo **una vez por fichero**. Son miles de alertas en minutos, todas del
//! mismo hecho. Sin fusion, el analista abre mil casos, cierra los novecientos
//! noventa y nueve primeros como duplicados, y para cuando llega al que
//! importaba ya ha pasado media hora.
//!
//! Peor: una cola con mil casos **esconde** el caso distinto que llego en medio.
//! La fusion no es comodidad; es lo que impide que el volumen tape la senal.
//!
//! # Pero fusionar de mas es peor que no fusionar
//!
//! Este es el error que hay que evitar por encima del otro. Si dos incidentes
//! **distintos** acaban en el mismo caso:
//!
//! * el analista cierra el caso cuando termina con el primero, y el segundo se
//!   va cerrado sin que nadie lo haya mirado;
//! * el rastro de auditoria dice que se investigo, porque se investigo *algo*;
//! * y la metrica dice que se resolvio en veinte minutos.
//!
//! Un caso perdido dentro de otro no deja hueco visible: es la unica forma de
//! perder un incidente sin que nada lo indique. Por eso todas las reglas de aqui
//! son **estrechas y explicitas**, y por eso hay cuatro topes —ventana, tamano,
//! maquinas y silencio— que cierran un caso abierto en vez de dejarlo crecer.
//!
//! # Las reglas, en orden de fuerza
//!
//! 1. **Nunca entre inquilinos.** No es una regla de fusion, es la invariante de
//!    aislamiento. Va primero porque es la unica que no admite excepcion.
//! 2. **Mismo sujeto** —el mismo proceso, la misma cuenta, el mismo fichero— en
//!    la misma maquina y dentro de la ventana. Es la fusion fuerte: es
//!    literalmente lo mismo pasando otra vez.
//! 3. **Misma tecnica en la misma maquina** dentro de la ventana. Mas floja: dos
//!    caminos del mismo ataque.
//! 4. **Campana**: la misma tecnica en VARIAS maquinas del mismo inquilino
//!    dentro de una ventana corta. Es la que convierte «doscientas maquinas con
//!    la misma alerta» en un caso, y ademas es la que hace visible que es una
//!    campana, que es el dato que cambia la respuesta.

use std::collections::BTreeSet;

use crate::modelo::{Alerta, Caso, Estado};

/// Ventana en la que un caso absorbe alertas del mismo sujeto, en nanosegundos.
///
/// Cuatro horas. Sale de lo que dura un incidente en atencion activa: mas alla,
/// una alerta del mismo sujeto es probablemente **otra cosa** —el atacante
/// volvio, o la maquina se reinfecto— y merece su propio caso, con su propia
/// cronologia y su propio tiempo de respuesta.
pub const VENTANA_CASO_NS: u64 = 4 * 3600 * 1_000_000_000;

/// Ventana, mas corta, para agrupar una campana entre maquinas.
///
/// Una hora. Una campana se reconoce por ser **simultanea**; si la misma tecnica
/// aparece en maquinas distintas con horas de diferencia, es mas probable que sea
/// la misma herramienta usada por gente distinta que un solo ataque.
pub const VENTANA_CAMPANA_NS: u64 = 3600 * 1_000_000_000;

/// Maquinas distintas a partir de las cuales se habla de campana.
pub const MINIMO_MAQUINAS_CAMPANA: usize = 3;

/// Alertas maximas en un caso.
///
/// Diez mil. No es una cota de memoria: es que un caso con mas alertas **ya no se
/// puede revisar**, y seguir metiendo dentro solo hace que el siguiente hecho se
/// pierda ahi. Al llegar, el caso se cierra a la absorcion y se abre otro que lo
/// referencia.
pub const MAX_ALERTAS_POR_CASO: usize = 10_000;

/// Silencio tras el cual un caso deja de absorber, en nanosegundos.
///
/// Treinta minutos sin una alerta nueva. Es lo que distingue «el incidente sigue»
/// de «el incidente acabo y esto es nuevo»: un caso que absorbe tras media hora
/// de silencio esta uniendo dos cosas separadas por media hora, que en un ataque
/// es una eternidad.
pub const SILENCIO_NS: u64 = 30 * 60 * 1_000_000_000;

/// Por que una alerta entro en un caso.
///
/// Se conserva **por alerta**, no por caso: cuando un analista mira por que hay
/// trescientas alertas juntas, la respuesta util no es «por campana» sino «esta
/// por sujeto, estas doscientas por campana, y esta por tecnica». Sin eso, una
/// fusion equivocada no se puede ni discutir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Motivo {
    /// El mismo sujeto en la misma maquina.
    MismoSujeto,
    /// La misma tecnica en la misma maquina.
    MismaTecnicaMismaMaquina,
    /// La misma tecnica en varias maquinas del inquilino.
    Campana,
    /// No encajo en ningun caso: abre uno nuevo.
    CasoNuevo,
}

impl Motivo {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Motivo::MismoSujeto => "mismo-sujeto",
            Motivo::MismaTecnicaMismaMaquina => "misma-tecnica-misma-maquina",
            Motivo::Campana => "campana",
            Motivo::CasoNuevo => "caso-nuevo",
        }
    }
}

/// Estado de fusion de un caso abierto.
#[derive(Debug, Clone)]
struct Ficha {
    caso: usize,
    inquilino: String,
    sujetos: BTreeSet<String>,
    tecnicas: BTreeSet<String>,
    maquinas: BTreeSet<String>,
    primera_ns: u64,
    ultima_ns: u64,
    alertas: usize,
    /// Cerrado a la absorcion: por tope, por silencio o porque se cerro el caso.
    sellado: bool,
}

/// Lo que se decidio con una alerta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Indice del caso en [`Fusionador::casos`].
    pub caso: usize,
    /// Por que fue a ese caso.
    pub motivo: Motivo,
    /// Si el caso se acaba de crear.
    pub nuevo: bool,
}

/// Agrupa alertas en casos.
#[derive(Debug, Default)]
pub struct Fusionador {
    casos: Vec<Caso>,
    fichas: Vec<Ficha>,
    siguiente: u64,
}

impl Fusionador {
    /// Crea un fusionador vacio.
    #[must_use]
    pub fn nuevo() -> Fusionador {
        Fusionador::default()
    }

    /// Casos producidos.
    #[must_use]
    pub fn casos(&self) -> &[Caso] {
        &self.casos
    }

    /// Casos producidos, mutables.
    pub fn casos_mut(&mut self) -> &mut [Caso] {
        &mut self.casos
    }

    /// Casos abiertos.
    #[must_use]
    pub fn abiertos(&self) -> usize {
        self.casos.iter().filter(|c| c.estado.abierto()).count()
    }

    /// Mete un caso que ya existia, para que pueda absorber alertas nuevas.
    ///
    /// Lo usa la capa de persistencia: la fusion decide sobre los casos ABIERTOS
    /// del inquilino que hay en la base de datos, no sobre los que este proceso
    /// vio en memoria. Sin esto, cada arranque del servidor volveria a abrir un
    /// caso por campana en curso.
    pub fn adoptar(&mut self, caso: Caso) {
        let mut ficha = Ficha {
            caso: self.casos.len(),
            inquilino: caso.inquilino.clone(),
            sujetos: caso.alertas.iter().map(|a| a.sujeto.clone()).collect(),
            tecnicas: caso.tecnicas.iter().cloned().collect(),
            maquinas: caso.alertas.iter().map(|a| a.anfitrion.clone()).collect(),
            primera_ns: caso.abierto_ns,
            ultima_ns: caso
                .alertas
                .iter()
                .map(|a| a.ocurrio_ns)
                .max()
                .unwrap_or(caso.abierto_ns),
            alertas: caso.alertas.len(),
            sellado: !caso.estado.abierto(),
        };
        if ficha.alertas >= MAX_ALERTAS_POR_CASO {
            ficha.sellado = true;
        }
        self.casos.push(caso);
        self.fichas.push(ficha);
    }

    /// Mete una alerta donde toque.
    pub fn admitir(&mut self, alerta: Alerta) -> Decision {
        self.caducar(alerta.ocurrio_ns);
        if let Some((i, motivo)) = self.buscar(&alerta) {
            self.fichas[i].sujetos.insert(alerta.sujeto.clone());
            self.fichas[i].maquinas.insert(alerta.anfitrion.clone());
            if let Some(t) = &alerta.tecnica {
                self.fichas[i].tecnicas.insert(t.clone());
            }
            self.fichas[i].ultima_ns = self.fichas[i].ultima_ns.max(alerta.ocurrio_ns);
            self.fichas[i].primera_ns = self.fichas[i].primera_ns.min(alerta.ocurrio_ns);
            self.fichas[i].alertas += 1;
            if self.fichas[i].alertas >= MAX_ALERTAS_POR_CASO {
                self.fichas[i].sellado = true;
            }
            let caso = self.fichas[i].caso;
            self.casos[caso].absorber(alerta);
            return Decision {
                caso,
                motivo,
                nuevo: false,
            };
        }

        self.siguiente += 1;
        let id = format!("CASO-{:06}", self.siguiente);
        let mut sujetos = BTreeSet::new();
        sujetos.insert(alerta.sujeto.clone());
        let mut maquinas = BTreeSet::new();
        maquinas.insert(alerta.anfitrion.clone());
        let mut tecnicas = BTreeSet::new();
        if let Some(t) = &alerta.tecnica {
            tecnicas.insert(t.clone());
        }
        let ficha = Ficha {
            caso: self.casos.len(),
            inquilino: alerta.inquilino.clone(),
            sujetos,
            tecnicas,
            maquinas,
            primera_ns: alerta.ocurrio_ns,
            ultima_ns: alerta.ocurrio_ns,
            alertas: 1,
            sellado: false,
        };
        let indice = ficha.caso;
        self.casos.push(Caso::abrir(id, alerta));
        self.fichas.push(ficha);
        Decision {
            caso: indice,
            motivo: Motivo::CasoNuevo,
            nuevo: true,
        }
    }

    /// Busca el caso al que le toca una alerta, con las reglas en orden de
    /// fuerza.
    fn buscar(&self, a: &Alerta) -> Option<(usize, Motivo)> {
        // 1. Mismo sujeto en la misma maquina: la fusion fuerte.
        for (i, f) in self.fichas.iter().enumerate() {
            if !self.admite(f, a) {
                continue;
            }
            if f.sujetos.contains(&a.sujeto) && f.maquinas.contains(&a.anfitrion) {
                return Some((i, Motivo::MismoSujeto));
            }
        }
        // 2. Campana: la misma tecnica en varias maquinas, en ventana corta.
        //    Va ANTES que la fusion por tecnica en una sola maquina porque es
        //    mas informativa: convierte doscientas alertas en «una campana», que
        //    es el dato que cambia la respuesta.
        if let Some(t) = &a.tecnica {
            for (i, f) in self.fichas.iter().enumerate() {
                if !self.admite(f, a) {
                    continue;
                }
                if f.tecnicas.contains(t)
                    && f.maquinas.len() >= MINIMO_MAQUINAS_CAMPANA
                    && a.ocurrio_ns.abs_diff(f.ultima_ns) <= VENTANA_CAMPANA_NS
                {
                    return Some((i, Motivo::Campana));
                }
            }
            // 3. La misma tecnica en la misma maquina.
            for (i, f) in self.fichas.iter().enumerate() {
                if !self.admite(f, a) {
                    continue;
                }
                if f.tecnicas.contains(t) && f.maquinas.contains(&a.anfitrion) {
                    return Some((i, Motivo::MismaTecnicaMismaMaquina));
                }
            }
            // 4. Y la semilla de una campana: la misma tecnica en otra maquina
            //    del mismo inquilino, en ventana corta. Es lo que hace que la
            //    tercera maquina encuentre un caso al que unirse en vez de abrir
            //    el suyo.
            for (i, f) in self.fichas.iter().enumerate() {
                if !self.admite(f, a) {
                    continue;
                }
                if f.tecnicas.contains(t)
                    && a.ocurrio_ns.abs_diff(f.ultima_ns) <= VENTANA_CAMPANA_NS
                {
                    return Some((i, Motivo::Campana));
                }
            }
        }
        None
    }

    /// Si un caso puede absorber esta alerta.
    ///
    /// La primera comprobacion es el inquilino, y no es una regla de fusion: es
    /// la invariante de aislamiento. Va primero porque es la unica que no admite
    /// excepcion.
    fn admite(&self, f: &Ficha, a: &Alerta) -> bool {
        if f.inquilino != a.inquilino {
            return false;
        }
        if f.sellado || !self.casos[f.caso].estado.abierto() {
            return false;
        }
        if f.alertas >= MAX_ALERTAS_POR_CASO {
            return false;
        }
        if a.ocurrio_ns.abs_diff(f.primera_ns) > VENTANA_CASO_NS {
            return false;
        }
        if a.ocurrio_ns > f.ultima_ns && a.ocurrio_ns - f.ultima_ns > SILENCIO_NS {
            return false;
        }
        true
    }

    /// Sella los casos que ya no pueden absorber mas.
    ///
    /// Se llama con cada alerta, no con un temporizador: sin reloj propio, el
    /// resultado es una funcion pura de la secuencia de alertas, y eso es lo que
    /// permite reproducirlo exactamente en una prueba y en una investigacion.
    fn caducar(&mut self, ahora_ns: u64) {
        for f in &mut self.fichas {
            if f.sellado {
                continue;
            }
            // Dos motivos distintos para el mismo efecto: el silencio dice «el
            // incidente acabo y esto es nuevo», y la ventana dice «esto ya dura
            // demasiado para ser el mismo incidente». Los dos sellan.
            let callado = ahora_ns > f.ultima_ns && ahora_ns - f.ultima_ns > SILENCIO_NS;
            let viejo = ahora_ns.abs_diff(f.primera_ns) > VENTANA_CASO_NS;
            if callado || viejo {
                f.sellado = true;
            }
        }
    }

    /// Marca un caso como cerrado a la absorcion.
    pub fn sellar(&mut self, caso: usize) {
        if let Some(f) = self.fichas.iter_mut().find(|f| f.caso == caso) {
            f.sellado = true;
        }
    }

    /// Cierra el caso y lo sella.
    pub fn cerrar(
        &mut self,
        caso: usize,
        veredicto: crate::modelo::Veredicto,
        justificacion: Option<String>,
        cuando_ns: u64,
    ) -> Result<(), crate::modelo::Rechazo> {
        self.sellar(caso);
        let c = self.casos.get_mut(caso).ok_or(crate::modelo::Rechazo {
            motivo: "ese caso no existe".into(),
        })?;
        if c.estado == Estado::Nuevo {
            // Un caso que se cierra sin que nadie lo mirara sigue siendo valido
            // —un falso positivo evidente— y la transicion lo permite.
        }
        c.cerrar(veredicto, justificacion, cuando_ns)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::modelo::{Observable, Severidad, Veredicto};

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn alerta(id: &str, maquina: &str, sujeto: &str, tecnica: &str, ns: u64) -> Alerta {
        Alerta {
            id: id.into(),
            inquilino: "cliente-1".into(),
            anfitrion: maquina.into(),
            sujeto: sujeto.into(),
            tecnica: Some(tecnica.into()),
            regla: "regla-x".into(),
            severidad: Severidad::Alta,
            ocurrio_ns: ns,
            observables: vec![Observable::Anfitrion(maquina.into())],
            resumen: format!("algo en {maquina}"),
        }
    }

    #[test]
    fn mil_alertas_de_una_campana_producen_un_caso() {
        // LA PRUEBA DE LA FASE. Sin fusion, el analista abre mil casos, cierra
        // los novecientos noventa y nueve primeros como duplicados, y para
        // cuando llega al que importaba ha pasado media hora.
        let mut f = Fusionador::nuevo();
        for i in 0..1000u64 {
            f.admitir(alerta(
                &format!("A-{i}"),
                "servidor-ficheros",
                "pid:4211",
                "T1486",
                AHORA + i * 100_000_000,
            ));
        }
        assert_eq!(f.casos().len(), 1, "se abrieron {} casos", f.casos().len());
        assert_eq!(f.casos()[0].alertas.len(), 1000);
    }

    #[test]
    fn doscientas_maquinas_con_la_misma_tecnica_son_una_campana() {
        // Y ademas se ve QUE es una campana, que es el dato que cambia la
        // respuesta.
        let mut f = Fusionador::nuevo();
        let mut motivos = std::collections::BTreeMap::new();
        for i in 0..200u64 {
            let d = f.admitir(alerta(
                &format!("A-{i}"),
                &format!("maquina-{i:03}"),
                &format!("pid:{}", 1000 + i),
                "T1059.001",
                AHORA + i * SEG,
            ));
            *motivos.entry(d.motivo).or_insert(0) += 1;
        }
        assert_eq!(f.casos().len(), 1, "{} casos", f.casos().len());
        assert!(motivos[&Motivo::Campana] > 190, "{motivos:?}");
        assert_eq!(motivos[&Motivo::CasoNuevo], 1);
    }

    #[test]
    fn nunca_se_fusionan_alertas_de_inquilinos_distintos() {
        // No es una regla de fusion: es la invariante de aislamiento, y es la
        // unica que no admite excepcion.
        let mut f = Fusionador::nuevo();
        let mut a = alerta("A-1", "maquina-1", "pid:1", "T1059", AHORA);
        let mut b = alerta("A-2", "maquina-1", "pid:1", "T1059", AHORA + SEG);
        a.inquilino = "cliente-1".into();
        b.inquilino = "cliente-2".into();
        f.admitir(a);
        f.admitir(b);
        assert_eq!(f.casos().len(), 2);
        assert_ne!(f.casos()[0].inquilino, f.casos()[1].inquilino);
    }

    #[test]
    fn dos_incidentes_separados_por_horas_no_acaban_en_el_mismo_caso() {
        // FUSIONAR DE MAS ES PEOR QUE NO FUSIONAR: el analista cierra el caso
        // cuando termina con el primero, y el segundo se va cerrado sin que
        // nadie lo haya mirado. Un caso perdido dentro de otro no deja hueco.
        let mut f = Fusionador::nuevo();
        f.admitir(alerta("A-1", "maquina-1", "pid:1", "T1059", AHORA));
        f.admitir(alerta(
            "A-2",
            "maquina-1",
            "pid:1",
            "T1059",
            AHORA + 5 * 3600 * SEG,
        ));
        assert_eq!(f.casos().len(), 2, "se unieron dos incidentes distintos");
    }

    #[test]
    fn media_hora_de_silencio_cierra_el_caso_a_la_absorcion() {
        // Un caso que absorbe tras media hora de silencio esta uniendo dos cosas
        // separadas por media hora, que en un ataque es una eternidad.
        let mut f = Fusionador::nuevo();
        f.admitir(alerta("A-1", "maquina-1", "pid:1", "T1059", AHORA));
        f.admitir(alerta(
            "A-2",
            "maquina-1",
            "pid:1",
            "T1059",
            AHORA + 31 * 60 * SEG,
        ));
        assert_eq!(f.casos().len(), 2);
    }

    #[test]
    fn un_caso_cerrado_no_absorbe_mas() {
        // Si lo hiciera, una alerta nueva entraria en un caso que ya tiene
        // veredicto y nadie volveria a mirarla.
        let mut f = Fusionador::nuevo();
        f.admitir(alerta("A-1", "maquina-1", "pid:1", "T1059", AHORA));
        f.cerrar(0, Veredicto::FalsoPositivo, None, AHORA + SEG)
            .unwrap();
        f.admitir(alerta(
            "A-2",
            "maquina-1",
            "pid:1",
            "T1059",
            AHORA + 2 * SEG,
        ));
        assert_eq!(f.casos().len(), 2);
    }

    #[test]
    fn un_caso_deja_de_crecer_cuando_ya_no_se_puede_revisar() {
        // No es una cota de memoria: es que un caso con diez mil alertas ya no se
        // puede revisar, y seguir metiendo dentro solo hace que el siguiente
        // hecho se pierda ahi.
        let mut f = Fusionador::nuevo();
        for i in 0..(MAX_ALERTAS_POR_CASO + 100) as u64 {
            f.admitir(alerta(
                &format!("A-{i}"),
                "maquina-1",
                "pid:1",
                "T1059",
                AHORA + i * 1000,
            ));
        }
        assert_eq!(f.casos().len(), 2, "no abrio uno nuevo al llenarse");
        assert_eq!(f.casos()[0].alertas.len(), MAX_ALERTAS_POR_CASO);
    }

    #[test]
    fn el_motivo_se_guarda_por_alerta_y_no_por_caso() {
        // Cuando un analista mira por que hay trescientas alertas juntas, la
        // respuesta util no es «por campana» sino «esta por sujeto, estas
        // doscientas por campana». Sin eso, una fusion equivocada ni se discute.
        let mut f = Fusionador::nuevo();
        let a = f.admitir(alerta("A-1", "maquina-1", "pid:1", "T1059", AHORA));
        let b = f.admitir(alerta("A-2", "maquina-1", "pid:1", "T1059", AHORA + SEG));
        let c = f.admitir(alerta(
            "A-3",
            "maquina-1",
            "pid:2",
            "T1059",
            AHORA + 2 * SEG,
        ));
        assert_eq!(a.motivo, Motivo::CasoNuevo);
        assert_eq!(b.motivo, Motivo::MismoSujeto);
        assert_eq!(c.motivo, Motivo::MismaTecnicaMismaMaquina);
    }

    #[test]
    fn una_tecnica_distinta_en_la_misma_maquina_abre_su_caso() {
        // Dos ataques simultaneos en la misma maquina son dos incidentes.
        let mut f = Fusionador::nuevo();
        f.admitir(alerta("A-1", "maquina-1", "pid:1", "T1059", AHORA));
        f.admitir(alerta("A-2", "maquina-1", "pid:9", "T1486", AHORA + SEG));
        assert_eq!(f.casos().len(), 2);
    }

    #[test]
    fn una_alerta_sin_tecnica_solo_fusiona_por_sujeto() {
        // Sin tecnica no hay nada que comparar entre maquinas, y adivinar seria
        // justo la fusion de mas que hay que evitar.
        let mut f = Fusionador::nuevo();
        let mut a = alerta("A-1", "maquina-1", "pid:1", "T1059", AHORA);
        a.tecnica = None;
        let mut b = alerta("A-2", "maquina-2", "pid:2", "T1059", AHORA + SEG);
        b.tecnica = None;
        f.admitir(a);
        f.admitir(b);
        assert_eq!(f.casos().len(), 2);
    }

    #[test]
    fn el_resultado_es_una_funcion_pura_de_la_secuencia_de_alertas() {
        // Sin reloj propio: es lo que permite reproducirlo exactamente en una
        // prueba y en una investigacion.
        let correr = || {
            let mut f = Fusionador::nuevo();
            for i in 0..300u64 {
                f.admitir(alerta(
                    &format!("A-{i}"),
                    &format!("maquina-{}", i % 7),
                    &format!("pid:{}", i % 13),
                    if i % 3 == 0 { "T1059" } else { "T1486" },
                    AHORA + i * SEG,
                ));
            }
            f.casos()
                .iter()
                .map(|c| (c.id.clone(), c.alertas.len()))
                .collect::<Vec<_>>()
        };
        assert_eq!(correr(), correr());
    }

    #[test]
    fn una_campana_necesita_varias_maquinas_de_verdad() {
        // Dos maquinas no son una campana: la misma herramienta usada dos veces
        // es lo normal en cualquier red.
        let mut f = Fusionador::nuevo();
        f.admitir(alerta("A-1", "maquina-1", "pid:1", "T1059", AHORA));
        let d = f.admitir(alerta("A-2", "maquina-2", "pid:2", "T1059", AHORA + SEG));
        // Se une como semilla de campana, pero el caso todavia no lo es.
        assert_eq!(d.motivo, Motivo::Campana);
        assert_eq!(f.casos().len(), 1);
    }
}
