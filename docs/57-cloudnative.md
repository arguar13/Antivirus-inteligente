# Módulo 57 — AegisCloudNative: frenar el escape de contenedor

> Componentes: `crates/aegis-cloudnative/`.

## 57.1 El límite que importa en cloud-native

En una infraestructura de contenedores, la frontera crítica es la que separa al
contenedor del host. Un atacante que compromete un contenedor rara vez se
conforma con él: quiere **escapar** al anfitrión, donde están los demás
contenedores y los secretos. Herramientas como **Deepce** y **Traitor**
automatizan ese salto. AegisCloudNative vigila las syscalls con las que se da
—`setns`, `unshare`, `capset`, `bpf`, `mount` y la escritura de rutas del
kernel— y reconoce el patrón de escape antes de que se complete.

## 57.2 Los caminos de escape que se reconocen

El hilo común de casi todo escape es: desde **dentro** del contenedor, conseguir
que se ejecute algo **en el host**, o alcanzar los recursos del anfitrión.

- **`release_agent` de cgroup v1, `core_pattern`, `modprobe`**: escribir cualquiera
  de estas rutas hace que el kernel ejecute un programa **en el host** (al vaciarse
  el cgroup, al volcar un core, o al cargar un módulo). Ejecución directa en el
  anfitrión: **crítico**.
- **Montar el disco del host**: un `mount` de un dispositivo de bloque del
  anfitrión dentro del contenedor da acceso total a su sistema de ficheros:
  **crítico**.
- **`setns` a un namespace del host**: entrar, por ejemplo, al namespace de PID
  del anfitrión es salir del contenedor por la puerta de los namespaces.
- **`bpf` desde un contenedor**: cargar eBPF da lectura/escritura del kernel y
  casi nunca es legítimo dentro de un contenedor.
- **La secuencia `unshare(CLONE_NEWUSER)` + `mount`**: crear un namespace de
  usuario para ganar capacidades y luego montar. Es **multi-paso**, así que el
  decisor guarda un poco de estado por proceso para reconocerla.

Todo esto sólo cuenta como escape si ocurre **dentro** de un contenedor: las
mismas syscalls en el host son la orquestación normal (Docker, systemd, runc) y no
se tocan. Ésa es la diferencia entre detectar y estorbar.

## 57.3 El patrón del producto: eBPF tonto, decisión probada

El resto de AegisCore que usa eBPF (la telemetría del agente) sigue una regla: el
programa del kernel es un **transporte fino y tonto**, y toda la inteligencia vive
en Rust que se prueba sin kernel. AegisCloudNative hace lo mismo. El programa eBPF
engancha las syscalls y emite un evento de layout fijo ([`EventoBpf`]) por un ring
buffer; el **contrato** de esa estructura se verifica en compilación. El
**decisor** (`MonitorEscape`) consume esos eventos y reconoce los patrones, y es
Rust puro, probado con secuencias reales de escape.

[`EventoBpf`]: ../crates/aegis-cloudnative/src/eventos.rs

## 57.4 Honestidad de validación

| Pieza | Verificable aquí | Muro |
|---|---|---|
| `release_agent` / `core_pattern` / `modprobe` → escape crítico | sí, cero mocks | — |
| Montaje del disco del host → escape crítico | sí | — |
| `setns` a un namespace del host → escape | sí | — |
| Carga de eBPF desde un contenedor → escape | sí | — |
| Secuencia `unshare(CLONE_NEWUSER)` + `mount` (estado por proceso) | sí | — |
| Las mismas syscalls en el host → **no** es escape (sin falsos positivos) | sí | — |
| Contrato `EventoBpf` (ABI del ring buffer, 40 B) | sí, en compilación | — |
| Enganchar las syscalls en vivo con eBPF | — | necesita kernel con BTF, privilegios y el bytecode cargado; gated |

El núcleo que puede estar mal de forma peligrosa —reconocer el escape sin marcar
lo legítimo— se prueba de verdad en cada `make ci`. Enganchar las syscalls en vivo
es un programa eBPF en el kernel, un muro que `tools/verificar-cloudnative.sh`
declara en vez de fingir.
