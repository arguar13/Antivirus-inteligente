# Módulo 43 — Cerrando los dos huecos del CI: Kafka real y cross-compile del driver

> Componentes: `tools/kafka-broker.sh`, `tools/verificar-kafka.sh`,
> `tools/cross-windows.sh`, `tools/ci-local.sh`.

Al terminar la FASE 47 quedaban dos verificaciones escritas pero **no
ejecutadas**, y así se declaraba en cada `make ci`:

1. La entrega del firehose contra un corredor de Kafka **real** (FASE 46).
2. La compilación del driver de Windows (FASE 47).

Un hueco documentado sigue siendo un hueco. Esta fase los cierra hasta donde las
leyes físicas de un contenedor de integración en Linux permiten —y declara con
exactitud dónde está el muro que no se puede cruzar sin mentir—.

---

## 43.1 Kafka: un corredor de verdad, sin Docker y sin mocks

### Por qué no fue testcontainers

La forma "de libro" de cerrar el hueco es un contenedor Docker vía
testcontainers. Este contenedor de integración **no tiene demonio de Docker**
(`docker info` falla; no hay podman). Con testcontainers el hueco seguiría
abierto con otro nombre: la verificación no correría.

Lo que sí hay es una **JVM** y salida hacia `archive.apache.org`. Kafka en modo
KRaft (sin ZooKeeper) es un único proceso Java. Se puede levantar aquí mismo.

### Qué hace `tools/kafka-broker.sh`

Descarga —una vez, cacheada— la release oficial de Apache Kafka, formatea el
almacenamiento KRaft con un `cluster-id` nuevo, arranca un corredor de un solo
nodo en un puerto libre elegido por el kernel, y **espera a que responda de
verdad** (le pide la lista de temas hasta que contesta, no se conforma con que
el puerto esté abierto). `up` es idempotente; `down` mata el proceso por su pid
y, como respaldo, por la ruta única de su configuración —porque
`kafka-server-start.sh` engendra un `java` hijo cuyo pid no es el que se
captura—.

### Qué prueba, que las otras pruebas no pueden

`crates/aegis-firehose/tests/kafka.rs` comprueba, contra la librdkafka real, la
propiedad cuya rotura sería catastrófica: **que un destino inalcanzable nunca
devuelve éxito** (un éxito falso hace que la bomba borre evidencia que no llegó).
Lo que eso no puede comprobar sin un corredor es lo que pasa cuando el corredor
**sí** está: que el registro llega, que llega **una sola vez** por lote
confirmado, y que el orden dentro de una partición se conserva —que es lo que
mantiene una línea de tiempo forense como una línea de tiempo—. La verificación
de extremo a extremo (`kafka_extremo.rs`) corre ahora contra el corredor real:
**100 registros entregados y acusados, orden conservado, sin duplicados, diario
vacío**.

### Robustez de la puerta de calidad

Si no hay Java o no hay salida a la red, `verificar-kafka.sh` **omite con aviso**
(sale con 0) en vez de volver frágil la puerta obligatoria. La diferencia entre
"probado contra un corredor real" y "no se pudo levantar aquí" se ve en el CI, no
se esconde en un comentario. En un runner con Docker, `AEGIS_KAFKA=host:puerto`
apunta a cualquier corredor y las pruebas son las mismas.

---

## 43.2 El driver de Windows, compilado desde Linux

### Lo que sí se compila aquí, sobre código real

`clang` compila de forma cruzada a `x86_64-pc-windows-msvc`. `tools/cross-windows.sh`:

1. Compila la **política portable** (`aegis_politica.c`) a un objeto Windows x64
   **real** y comprueba que la máquina es `IMAGE_FILE_MACHINE_AMD64` y que
   exporta sus símbolos. Es el mismo fichero que decide qué acceso se recorta y
   qué evento es inyección: la parte que puede estar mal de forma peligrosa.
2. Demuestra la **cadena de enlace** `clang → lld-link` produciendo un `.sys` PE
   válido de subsistema NATIVE que **contiene el código real de la política**,
   enlazado con un `DriverEntry` mínimo. Prueba que la cadena cruzada entera
   —compilar y enlazar a formato driver— funciona sobre código real del
   proyecto, sin Windows y sin el WDK.

### El muro, declarado

El driver de **producción** completo (`obcallbacks.c`, `driver.c`) incluye
`<ntddk.h>` y `<fltKernel.h>`, que solo vienen con el Windows Driver Kit. El WDK
está **licenciado y no es redistribuible** dentro de un CI de Linux. Por eso la
compilación del `.sys` completo está condicionada a `$WDK_ROOT`: si apunta a un
WDK montado, se compila con `clang-cl` + `lld-link`; si no, se **omite con aviso**
—nunca se finge—. El CI lo dice:

```
==> Windows · cross-compilacion del driver (clang/lld-link)
    OK  objeto COFF x86-64 (IMAGE_FILE_MACHINE_AMD64)
    OK  .sys PE x86-64 enlazado (subsistema NATIVE); contiene el codigo real de la politica
    OMITIDO: $WDK_ROOT no apunta a un WDK. El .sys completo necesita <ntddk.h>...
```

---

## 43.3 Frontera de realidad, en una tabla

| Verificación | Antes de FASE 48 | Ahora | Muro que queda |
|---|---|---|---|
| Kafka de extremo a extremo | escrita, **no ejecutada** | corredor Apache Kafka **real** levantado y verificado en `make ci` | ninguno aquí; en runners sin Java/red, omite con aviso |
| Driver de Windows | "no se compila aquí" | política real → objeto Windows x64; cadena `clang→lld-link` → `.sys` PE real | el `.sys` completo necesita headers del WDK (licenciados), gated por `$WDK_ROOT` |

La regla no cambia desde la FASE 47: **lo que puede estar mal de forma peligrosa
se compila y se prueba de verdad; lo que es físicamente imposible aquí se declara,
no se finge.**
