//! Registro de transparencia propio, de solo apendice, verificable SIN CONEXION.
//!
//! # Por que no vale depender de Sigstore
//!
//! Sigstore apoya su transparencia en un servicio publico: para comprobar que una
//! atestacion esta en el registro, hay que preguntarle a alguien. Una flota aislada
//! —una planta industrial, una red clasificada— no puede preguntar a nadie. Aqui el
//! registro es un arbol de Merkle de solo apendice que el propio agente lleva, y las
//! pruebas —de INCLUSION («esta atestacion esta en el registro») y de CONSISTENCIA
//! («el registro nuevo EXTIENDE al viejo, no lo reescribio»)— se verifican en local,
//! sin red.
//!
//! La consistencia es la que caza un registro BIFURCADO: si el operador reescribe
//! la historia —cambia una atestacion vieja para ocultar una actualizacion
//! maliciosa que ya aplico—, ninguna prueba reconstruye la raiz que el agente
//! recordaba, y se detecta.
//!
//! El arbol sigue el esquema de RFC 6962 (Certificate Transparency): separacion de
//! dominio entre hoja (`0x00`) y nodo (`0x01`), y el mismo algoritmo de prueba, con
//! BLAKE3 como funcion de hash.

/// El hash de un nodo del arbol.
pub type Hash = [u8; 32];

const PREFIJO_HOJA: u8 = 0x00;
const PREFIJO_NODO: u8 = 0x01;

/// Hash de una hoja: `H(0x00 || datos)`.
#[must_use]
pub fn hash_hoja(datos: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[PREFIJO_HOJA]);
    h.update(datos);
    *h.finalize().as_bytes()
}

/// Hash de un nodo interno: `H(0x01 || izq || der)`.
fn hash_nodo(izq: &Hash, der: &Hash) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[PREFIJO_NODO]);
    h.update(izq);
    h.update(der);
    *h.finalize().as_bytes()
}

/// La mayor potencia de dos ESTRICTAMENTE menor que `n` (para `n >= 2`).
fn potencia_dos_menor(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// El Merkle Tree Hash (MTH) de una lista de hojas ya hasheadas.
#[must_use]
pub fn raiz(hojas: &[Hash]) -> Hash {
    match hojas.len() {
        0 => *blake3::hash(b"").as_bytes(),
        1 => hojas[0],
        n => {
            let k = potencia_dos_menor(n);
            hash_nodo(&raiz(&hojas[..k]), &raiz(&hojas[k..]))
        }
    }
}

/// Genera la prueba de inclusion de la hoja `m` (0-indexada) en un arbol de
/// `hojas`. La prueba va de la hoja hacia la raiz.
#[must_use]
pub fn prueba_inclusion(hojas: &[Hash], m: usize) -> Vec<Hash> {
    let n = hojas.len();
    if n <= 1 || m >= n {
        return Vec::new();
    }
    let k = potencia_dos_menor(n);
    if m < k {
        let mut p = prueba_inclusion(&hojas[..k], m);
        p.push(raiz(&hojas[k..]));
        p
    } else {
        let mut p = prueba_inclusion(&hojas[k..], m - k);
        p.push(raiz(&hojas[..k]));
        p
    }
}

/// Reconstruye la raiz desde una hoja y su prueba de inclusion. `None` si la
/// prueba no encaja con `(m, n)`.
fn raiz_desde_inclusion(n: usize, m: usize, hoja: Hash, prueba: &[Hash]) -> Option<Hash> {
    if n == 1 {
        return if prueba.is_empty() { Some(hoja) } else { None };
    }
    let k = potencia_dos_menor(n);
    let (ultimo, resto) = prueba.split_last()?;
    if m < k {
        let izq = raiz_desde_inclusion(k, m, hoja, resto)?;
        Some(hash_nodo(&izq, ultimo))
    } else {
        let der = raiz_desde_inclusion(n - k, m - k, hoja, resto)?;
        Some(hash_nodo(ultimo, &der))
    }
}

/// Verifica una prueba de inclusion: que la hoja `m` de un arbol de tamano `n` con
/// raiz `raiz_esperada` esta, con la prueba dada.
#[must_use]
pub fn verificar_inclusion(
    hoja: Hash,
    m: usize,
    n: usize,
    prueba: &[Hash],
    raiz_esperada: Hash,
) -> bool {
    if m >= n {
        return false;
    }
    raiz_desde_inclusion(n, m, hoja, prueba) == Some(raiz_esperada)
}

/// La parte recursiva de la prueba de consistencia (RFC 6962 SUBPROOF).
fn subprueba(m: usize, d: &[Hash], b: bool) -> Vec<Hash> {
    let n = d.len();
    if m == n {
        if b {
            return Vec::new();
        }
        return vec![raiz(d)];
    }
    let k = potencia_dos_menor(n);
    if m <= k {
        let mut p = subprueba(m, &d[..k], b);
        p.push(raiz(&d[k..]));
        p
    } else {
        let mut p = subprueba(m - k, &d[k..], false);
        p.push(raiz(&d[..k]));
        p
    }
}

/// Genera la prueba de consistencia entre el arbol de tamano `m` y el actual (de
/// tamano `hojas.len()`). Prueba que el actual EXTIENDE al de tamano `m`.
#[must_use]
pub fn prueba_consistencia(hojas: &[Hash], m: usize) -> Vec<Hash> {
    let n = hojas.len();
    if m == 0 || m >= n {
        return Vec::new();
    }
    subprueba(m, hojas, true)
}

/// Verifica una prueba de consistencia: que un arbol de tamano `n` con raiz
/// `raiz_n` EXTIENDE a uno de tamano `m` con raiz `raiz_m`. Un registro bifurcado
/// —historia reescrita— no supera esta prueba.
#[must_use]
pub fn verificar_consistencia(
    m: usize,
    n: usize,
    raiz_m: Hash,
    raiz_n: Hash,
    prueba: &[Hash],
) -> bool {
    if m > n {
        return false;
    }
    if m == n {
        return prueba.is_empty() && raiz_m == raiz_n;
    }
    if m == 0 {
        // El arbol vacio es consistente con cualquiera; no hay nada que probar.
        return prueba.is_empty();
    }
    let mut nodo = m - 1;
    let mut ultimo = n - 1;
    while nodo & 1 == 1 {
        nodo >>= 1;
        ultimo >>= 1;
    }
    let mut it = prueba.iter();
    let (mut hviejo, mut hnuevo) = if nodo != 0 {
        let Some(semilla) = it.next() else {
            return false;
        };
        (*semilla, *semilla)
    } else {
        (raiz_m, raiz_m)
    };
    while nodo != 0 {
        if nodo & 1 == 1 {
            let Some(o) = it.next() else { return false };
            hviejo = hash_nodo(o, &hviejo);
            hnuevo = hash_nodo(o, &hnuevo);
        } else if nodo < ultimo {
            let Some(o) = it.next() else { return false };
            hnuevo = hash_nodo(&hnuevo, o);
        }
        nodo >>= 1;
        ultimo >>= 1;
    }
    while ultimo != 0 {
        let Some(o) = it.next() else { return false };
        hnuevo = hash_nodo(&hnuevo, o);
        ultimo >>= 1;
    }
    it.next().is_none() && hviejo == raiz_m && hnuevo == raiz_n
}

/// El registro de transparencia: de solo apendice, con todas sus hojas.
#[derive(Debug, Clone, Default)]
pub struct RegistroTransparencia {
    hojas: Vec<Hash>,
}

impl RegistroTransparencia {
    /// Un registro vacio.
    #[must_use]
    pub fn nuevo() -> RegistroTransparencia {
        RegistroTransparencia::default()
    }

    /// Anade una entrada (una atestacion serializada) y devuelve su indice.
    pub fn anadir(&mut self, datos: &[u8]) -> usize {
        let i = self.hojas.len();
        self.hojas.push(hash_hoja(datos));
        i
    }

    /// El tamano actual (numero de entradas).
    #[must_use]
    pub fn tam(&self) -> usize {
        self.hojas.len()
    }

    /// Si esta vacio.
    #[must_use]
    pub fn esta_vacio(&self) -> bool {
        self.hojas.is_empty()
    }

    /// La raiz actual del arbol.
    #[must_use]
    pub fn raiz(&self) -> Hash {
        raiz(&self.hojas)
    }

    /// La raiz de un prefijo de tamano `m` (la que el agente recordaba).
    #[must_use]
    pub fn raiz_de_prefijo(&self, m: usize) -> Hash {
        raiz(&self.hojas[..m.min(self.hojas.len())])
    }

    /// La prueba de inclusion de la entrada `m`.
    #[must_use]
    pub fn prueba_inclusion(&self, m: usize) -> Vec<Hash> {
        prueba_inclusion(&self.hojas, m)
    }

    /// La prueba de consistencia entre el tamano `m` y el actual.
    #[must_use]
    pub fn prueba_consistencia(&self, m: usize) -> Vec<Hash> {
        prueba_consistencia(&self.hojas, m)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn hojas_de(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| hash_hoja(format!("entrada-{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn la_inclusion_verifica_para_todo_tamano_y_toda_hoja() {
        for n in 1..=33 {
            let hojas = hojas_de(n);
            let r = raiz(&hojas);
            for m in 0..n {
                let p = prueba_inclusion(&hojas, m);
                assert!(
                    verificar_inclusion(hojas[m], m, n, &p, r),
                    "inclusion falla en n={n} m={m}"
                );
                // Una hoja falsa no verifica.
                assert!(!verificar_inclusion(hash_hoja(b"falsa"), m, n, &p, r));
            }
        }
    }

    #[test]
    fn la_consistencia_verifica_para_todo_par_de_tamanos() {
        // Cruce contra el recomputo por prefijo: si la prueba compacta y el
        // recomputo coinciden en todo (m,n), la prueba compacta es correcta.
        for n in 1..=33 {
            let hojas = hojas_de(n);
            let raiz_n = raiz(&hojas);
            for m in 1..=n {
                let raiz_m = raiz(&hojas[..m]);
                let p = prueba_consistencia(&hojas, m);
                assert!(
                    verificar_consistencia(m, n, raiz_m, raiz_n, &p),
                    "consistencia falla en m={m} n={n}"
                );
            }
        }
    }

    #[test]
    fn un_registro_bifurcado_no_supera_la_consistencia() {
        // El agente recordaba la raiz al tamano m=5. El operador reescribe la
        // historia (cambia la entrada 2) y presenta un arbol de n=8 con su nueva
        // raiz y una prueba. Como el prefijo m=5 ya no reconstruye la raiz que el
        // agente recordaba, la consistencia falla: el fork se detecta.
        let honesto = hojas_de(8);
        let raiz_m_recordada = raiz(&honesto[..5]);

        let mut forjado = honesto.clone();
        forjado[2] = hash_hoja(b"entrada-2-REESCRITA");
        let raiz_n_forjada = raiz(&forjado);
        let prueba = prueba_consistencia(&forjado, 5);

        assert!(
            !verificar_consistencia(5, 8, raiz_m_recordada, raiz_n_forjada, &prueba),
            "un registro que reescribio la historia NO puede ser consistente"
        );
    }

    #[test]
    fn el_registro_anade_y_produce_pruebas() {
        let mut reg = RegistroTransparencia::nuevo();
        let i0 = reg.anadir(b"atestacion-v1");
        let raiz_1 = reg.raiz();
        reg.anadir(b"atestacion-v2");
        reg.anadir(b"atestacion-v3");
        // Inclusion de la primera entrada en el arbol de 3.
        let p = reg.prueba_inclusion(i0);
        assert!(verificar_inclusion(
            hash_hoja(b"atestacion-v1"),
            i0,
            reg.tam(),
            &p,
            reg.raiz()
        ));
        // Consistencia entre el tamano 1 (raiz recordada) y el actual (3).
        let pc = reg.prueba_consistencia(1);
        assert!(verificar_consistencia(
            1,
            reg.tam(),
            raiz_1,
            reg.raiz(),
            &pc
        ));
    }
}
