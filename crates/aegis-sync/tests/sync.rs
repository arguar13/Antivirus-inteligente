//! Pruebas de la sincronizacion diferencial.
//!
//! La prueba que importa no es solo que la reconciliacion sea correcta, sino que
//! sea DIFERENCIAL: que el trafico crezca con lo que cambio, no con el tamano de
//! la base. Por eso se cuentan las peticiones de nodo y de cubo y se comprueba
//! que son una fraccion diminuta de la base cuando el cambio es pequeno.

use aegis_sync::ioc::{Ioc, IocKind};
use aegis_sync::merkle::{MerkleTree, CUBOS};
use aegis_sync::sync::{reconcile, CountingView, SyncDiff};

fn hash_ioc(n: u64) -> Ioc {
    Ioc::new(IocKind::FileSha256, format!("{n:064x}"))
}

fn base(n: u64) -> Vec<Ioc> {
    (0..n).map(hash_ioc).collect()
}

// ---------------------------------------------------------------------------
// Correccion
// ---------------------------------------------------------------------------

#[test]
fn dos_bases_identicas_estan_en_sincronia_con_un_solo_hash() {
    let local = MerkleTree::build(base(10_000));
    let remoto = MerkleTree::build(base(10_000));
    let vista = CountingView::new(&remoto);

    let diff = reconcile(&local, &vista);
    assert!(
        diff.is_empty(),
        "bases identicas no deberian requerir cambios"
    );
    // Solo se comparo la raiz: un unico hash.
    assert_eq!(vista.node_requests.get(), 1);
    assert_eq!(vista.bucket_requests.get(), 0);
    assert_eq!(vista.iocs_transferred.get(), 0);
}

#[test]
fn se_detectan_las_altas_y_las_bajas() {
    // Local tiene 0..1000; el servidor quito el 500 y anadio el 2000.
    let local = MerkleTree::build(base(1000));
    let mut remota: Vec<Ioc> = base(1000);
    remota.retain(|i| i != &hash_ioc(500));
    remota.push(hash_ioc(2000));
    let remoto = MerkleTree::build(remota);
    let vista = CountingView::new(&remoto);

    let diff = reconcile(&local, &vista);
    assert_eq!(
        diff.to_add,
        vec![hash_ioc(2000)],
        "el 2000 hay que anadirlo"
    );
    assert_eq!(
        diff.to_remove,
        vec![hash_ioc(500)],
        "el 500 hay que quitarlo"
    );
}

#[test]
fn una_base_vacia_recibe_todo_lo_del_servidor() {
    let local = MerkleTree::build(Vec::<Ioc>::new());
    let remoto = MerkleTree::build(base(50));
    let vista = CountingView::new(&remoto);
    let diff = reconcile(&local, &vista);
    assert_eq!(diff.to_add.len(), 50);
    assert!(diff.to_remove.is_empty());
}

#[test]
fn aplicar_la_diferencia_iguala_las_bases() {
    let local_iocs = base(500);
    let mut remota = base(500);
    remota.retain(|i| i != &hash_ioc(1) && i != &hash_ioc(2));
    remota.push(hash_ioc(9998));
    remota.push(hash_ioc(9999));

    let local = MerkleTree::build(local_iocs.clone());
    let remoto = MerkleTree::build(remota.clone());
    let diff = reconcile(&local, &CountingView::new(&remoto));

    // Se aplica la diferencia sobre la base local...
    let mut resultado: std::collections::BTreeSet<[u8; 32]> =
        local_iocs.iter().map(|i| i.id()).collect();
    for i in &diff.to_remove {
        resultado.remove(&i.id());
    }
    for i in &diff.to_add {
        resultado.insert(i.id());
    }
    // ...y tiene que quedar igual que la remota.
    let esperado: std::collections::BTreeSet<[u8; 32]> = remota.iter().map(|i| i.id()).collect();
    assert_eq!(
        resultado, esperado,
        "aplicar la diferencia no igualo las bases"
    );
}

// ---------------------------------------------------------------------------
// La propiedad diferencial: el trafico es proporcional al cambio
// ---------------------------------------------------------------------------

#[test]
fn un_cambio_pequeno_en_una_base_grande_transfiere_poco() {
    // Base grande: 100.000 indicadores.
    let n = 100_000u64;
    let local = MerkleTree::build(base(n));

    // El servidor solo anadio 3.
    let mut remota = base(n);
    remota.push(hash_ioc(n + 1));
    remota.push(hash_ioc(n + 2));
    remota.push(hash_ioc(n + 3));
    let remoto = MerkleTree::build(remota);

    let vista = CountingView::new(&remoto);
    let diff = reconcile(&local, &vista);

    assert_eq!(diff.to_add.len(), 3);
    assert!(diff.to_remove.is_empty());

    // El trafico: los cubos que difieren son como mucho 3 (uno por indicador
    // nuevo, quiza menos si caen juntos). Los indicadores transferidos son solo
    // los de esos cubos, no los 100.000.
    assert!(
        diff.differing_buckets <= 3,
        "solo deberian diferir los cubos de los 3 nuevos: {}",
        diff.differing_buckets
    );
    let base_media_por_cubo = n as usize / CUBOS;
    assert!(
        vista.iocs_transferred.get() < base_media_por_cubo * 6,
        "se transfirieron {} indicadores; deberian ser solo los de unos pocos \
         cubos (~{} por cubo), no la base entera de {}",
        vista.iocs_transferred.get(),
        base_media_por_cubo,
        n
    );
    // Y desde luego, muchisimo menos que transferir la base entera.
    assert!(
        vista.iocs_transferred.get() < n as usize / 10,
        "el trafico no es diferencial: {} de {}",
        vista.iocs_transferred.get(),
        n
    );
    // Los hashes de nodo consultados son del orden del arbol (log), no de la
    // base.
    assert!(
        vista.node_requests.get() < 4 * CUBOS,
        "demasiados hashes de nodo: {}",
        vista.node_requests.get()
    );
}

#[test]
fn el_arbol_es_estable_ante_inserciones() {
    // Insertar un indicador solo debe cambiar un cubo y su camino a la raiz, no
    // media base: por eso el reparto es por prefijo y no por posicion en una
    // lista ordenada.
    let a = MerkleTree::build(base(1000));
    let mut con_uno_mas = base(1000);
    con_uno_mas.push(hash_ioc(123_456));
    let b = MerkleTree::build(con_uno_mas);

    // Cuentan cuantas hojas difieren entre los dos arboles.
    let mut hojas_distintas = 0;
    for i in 0..CUBOS {
        if a.node(CUBOS + i) != b.node(CUBOS + i) {
            hojas_distintas += 1;
        }
    }
    assert_eq!(
        hojas_distintas, 1,
        "una insercion tiene que cambiar exactamente un cubo, cambio {hojas_distintas}"
    );
}

// ---------------------------------------------------------------------------
// Prioridad
// ---------------------------------------------------------------------------

#[test]
fn la_sincronizacion_corre_en_baja_prioridad() {
    use aegis_sync::priority;
    // Se ejecuta en un hilo de baja prioridad y se comprueba que termina y
    // devuelve su resultado. El nice efectivo depende del entorno, pero rebajar
    // la prioridad del hilo llamante nunca requiere privilegios.
    let h = priority::en_hilo_baja_prioridad(10, || {
        let local = MerkleTree::build(base(2000));
        let remoto = MerkleTree::build(base(2000));
        reconcile(&local, &CountingView::new(&remoto))
    });
    let diff: SyncDiff = h.join().unwrap();
    assert!(diff.is_empty());
}

#[test]
fn rebajar_la_prioridad_del_hilo_actual_no_falla() {
    // Subir el nice (rebajar prioridad) no requiere privilegios; tiene que
    // aplicarse.
    assert!(aegis_sync::priority::rebajar_prioridad(5));
}
