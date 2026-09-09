# Módulo 14 — Sincronización diferencial de threat intel

> Componente: `crates/aegis-sync` (Rust, árboles de Merkle).

El agente y el servidor tienen cada uno una base de **indicadores de compromiso**
(hashes maliciosos, dominios de C2, IPs, reglas revocadas). Ponerlas al día
descargando la lista entera es prohibitivo cuando son cientos de miles y solo
cambian unos pocos al día. La sincronización **diferencial** transfiere solo lo
que difiere.

---

## 14.1 El árbol de Merkle sobre cubos

Los indicadores se reparten en `2^8 = 256` **cubos** por los bits altos de su
identificador (`SHA-256(tipo ‖ valor)`). El hash de un cubo resume su contenido;
sobre esos hashes se construye un árbol de Merkle. **El hash de la raíz resume
toda la base**: si coincide con el del servidor, las bases son idénticas y no se
transfiere nada más que ese hash.

Si difieren, se desciende por el árbol comparando hashes de nodo, bajando solo a
los subárboles que difieren, hasta llegar a los cubos concretos que cambiaron.
Solo el contenido de **esos** cubos se transfiere.

### Por qué cubos por prefijo y no un árbol sobre la lista ordenada

Un árbol sobre la lista ordenada se desbarata al insertar: un indicador nuevo
desplaza a todos los siguientes y cambia media rama. Repartir por prefijo del id
**fija la posición** de cada indicador independientemente de los demás: una
inserción toca un único cubo y su camino a la raíz, nada más. La prueba
`el_arbol_es_estable_ante_inserciones` lo confirma: añadir un indicador cambia
exactamente un cubo.

---

## 14.2 El tráfico es proporcional al cambio, no a la base

Es la propiedad que justifica todo el módulo, y se prueba contándola. Sobre una
base de **100.000 indicadores** a la que el servidor añadió **3**:

- Se comparan hashes de nodo bajando por el árbol: del orden del árbol
  (logarítmico), no de la base.
- Difieren como mucho 3 cubos.
- Se transfiere el contenido de esos cubos —unos pocos cientos de indicadores—,
  no los 100.000.

Cuando las bases ya están sincronizadas, la reconciliación termina con **una sola
comparación de hash** (la raíz) y cero transferencia.

El servidor se modela como un rasgo (`MerkleView`) que da el hash de la raíz, el
hash de cualquier nodo y el contenido de un cubo. En las pruebas, una vista que
envuelve el árbol **cuenta** cada petición, para poder afirmar sobre el tráfico y
no solo sobre la corrección.

---

## 14.3 En segundo plano y a baja prioridad

La sincronización no es urgente —puede tardar segundos o minutos sin que pase
nada— pero no puede robarle CPU a la detección. Corre en un hilo con el `nice`
rebajado (`setpriority` sobre el hilo llamante en Linux), de modo que el
planificador se la quite en cuanto la detección la necesite. Rebajar la propia
prioridad nunca requiere privilegios, que es la dirección segura.
