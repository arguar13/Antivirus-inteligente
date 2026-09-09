# Módulo 22 — Recogida automática de incidentes y exportación STIX 2.1

> Componente: `crates/aegis-forensics` (módulos `collect`, `stix`, `store`).

Un incidente se investiga horas o días después. Para entonces el proceso ya
murió, sus sockets se cerraron, su memoria se liberó y puede que el binario se
haya borrado a sí mismo. **Lo que no se recogió en el momento no existe.** Por
eso la recogida la dispara la detección, no un analista.

---

## 22.1 Qué se recoge, y por qué eso

| Artefacto | Para qué sirve |
|---|---|
| **Árbol de procesos** | Sin el linaje un `curl` no dice nada; con él es la segunda etapa de una ejecución remota |
| **Sockets** | Con quién hablaba: es lo que permite pivotar a la infraestructura del atacante y buscarla en el resto de la flota |
| **Hashes SHA-256** | Identidad del ejecutable, que sobrevive a que lo renombren o lo borren |
| **Memoria** | Las regiones anónimas ejecutables, donde vive el código sin fichero detrás |

Nada de esto detiene al proceso. Un `ptrace`-stop es observable por el propio
proceso —que es como el malware descubre que lo están mirando— y además congela
algo que todavía puede resultar legítimo.

Los sockets se atribuyen leyendo `/proc/<pid>/fd`, donde cada uno aparece como
`socket:[<inodo>]`, y cruzando esos inodos con `/proc/net/*`, que es global y no
dice de quién es cada entrada. Las tablas de `/proc/net` se leen **una vez** y se
indexan: un árbol de cincuenta procesos las releería cincuenta veces, y cada una
son miles de líneas en una máquina con carga.

Las direcciones de `procfs` vienen en hexadecimal y en el orden de bytes del
**host**, mientras que el **puerto** viene en orden de red. Mezclar los dos
criterios da direcciones invertidas que no corresponden a nada; hay una prueba
con el formato exacto.

---

## 22.2 Todos los límites son explícitos, y los huecos se escriben

Una recogida sin cotas es una denegación de servicio contra el propio agente: un
árbol de mil procesos con diez mil sockets produciría un informe que no cabe en
el registro de auditoría y una pausa larguísima en mitad de un incidente. Los
límites están en `CollectConfig` (64 procesos, 8 de profundidad, 256 sockets, 64
regiones, 128 MB de hasheo).

Lo que se deja fuera **se anota en `gaps`**, y `gaps` viaja dentro del documento
STIX. Un informe forense que calla lo que le faltó induce a concluir que algo no
ocurrió cuando lo único cierto es que no se pudo mirar.

La recogida **nunca falla entera**: que un proceso desaparezca a mitad es la
condición normal en un incidente vivo, y abortar por ello dejaría sin evidencia
un incidente del que sí se pudo capturar casi todo. Que un binario ya no esté en
disco tampoco es un fallo: **es un dato**, y significa que la evidencia se
destruyó.

---

## 22.3 STIX 2.1, y por qué hay SHA-1 en un producto de seguridad

Un informe que sólo entiende AegisCore obliga al equipo a copiar los indicadores
a mano en su plataforma de inteligencia, su SIEM y su EDR de terceros. STIX 2.1
es el formato que todos ellos leen.

El bundle lleva objetos observables `file`, `process`, `network-traffic`,
`ipv4-addr`/`ipv6-addr`, un `observed-data` que los ata al momento en que se
vieron, y un `indicator` con patrón `[file:hashes.'SHA-256' = '…']` y referencias
externas a MITRE ATT&CK.

STIX exige que los observables lleven un **UUIDv5**, que está definido sobre
SHA-1. No es una elección: es lo que hace que dos herramientas distintas que
observen el mismo fichero produzcan el mismo identificador, que es la base de la
deduplicación entre plataformas. Ese SHA-1 **no protege nada** y no se usa jamás
para integridad —para eso el producto usa SHA-256 y BLAKE3—; se implementa en
cincuenta líneas auditables, verificadas contra los vectores del FIPS 180-1, en
vez de traer una dependencia para una función que sólo sirve para nombrar.

Los objetos de dominio llevan **UUIDv4** del generador del kernel, como manda la
especificación. Por eso el bundle no es reproducible byte a byte, y
`to_bundle_with` permite fijarlos para poder compararlo entero en las pruebas.

Un socket **a la escucha** no entra en el bundle: su destino es `0.0.0.0:0`, no
aporta un extremo con el que pivotar y ensuciaría la búsqueda por
infraestructura. Un `indicator` **sin hash** tampoco se emite: un indicador sin
patrón útil es ruido en la plataforma de quien lo reciba.

---

## 22.4 El JSON se escribe a mano, a propósito

Lo único difícil de emitir JSON es el escapado, y aquí el material de entrada es
hostil **por definición**: nombres de fichero y líneas de comandos que el
atacante elige. Un `"` sin escapar rompe el documento; peor, permite **inyectar
campos y falsificar el propio informe forense**. Hay una prueba que lo intenta
con `x", "type": "identity", "name": "suplantado` y comprueba que no cuela.

Una línea de comandos no tiene por qué ser UTF-8 —el kernel guarda los bytes que
le dieron—, así que se sustituye lo inválido: el dato aproximado es útil siempre
que el documento siga siendo válido.

Las marcas de tiempo son RFC 3339 en UTC con milisegundos, que es lo que STIX
exige. El resto del producto usa el reloj **monótono**, que es lo correcto para
medir intervalos pero no tiene fecha; la aritmética del calendario se hace a mano
(algoritmo de Howard Hinnant) y se verifica contra el 29 de febrero de 2024 y el
de 2000, que es donde falla una implementación descuidada.

---

## 22.5 Custodia: registro cifrado, no un fichero suelto

Un informe forense en un `.json` del disco es exactamente lo que el atacante
borra cuando descubre que lo han detectado, y contiene lo más sensible de la
máquina: rutas, líneas de comandos —que a veces llevan credenciales— y con quién
hablaba el proceso. Se guarda en [el registro de auditoría](09-auditoria.md), con
AES-256-GCM y el identificador de fila ligado al cifrado. Hay una prueba que
recorre los ficheros del disco y verifica que **el destino remoto no aparece en
claro**.

La gravedad es siempre la máxima: se recoge un informe porque algo ya se decidió
que era un incidente, y degradarla haría que una consulta por gravedad se lo
saltara.

Si el bundle pasa de 256 KB se guarda un **resumen** —identificador, disparador,
hashes, extremos remotos, técnicas— y el hecho de haberlo recortado queda escrito
en el propio evento, con otra clase (`forensics.incident.truncated`). Guardarlo
entero desplazaría del registro, por rotación, a los eventos anteriores, que son
justo el contexto del incidente; recortarlo en silencio se leería como un
incidente pequeño.

---

## 22.6 Cómo se prueba

Lo que se recoge se recoge de un proceso **de verdad** —el de la propia prueba y
los hijos que lanza—, con una conexión TCP real abierta para que haya socket que
encontrar, y el hash recogido se compara con el del ejecutable real.

Lo que se exporta se valida con un **analizador de JSON escrito en la propia
prueba**: comprobar el documento buscando subcadenas no detectaría justo el fallo
que importa, que es un escapado roto por un nombre de fichero hostil.

El **escenario 8** de la simulación de Red Team reproduce una técnica antiforense
real: el proceso se borra a sí mismo del disco nada más arrancar. La recogida
tiene que capturar el incidente igual y dejar constancia explícita de que la
evidencia se destruyó.
