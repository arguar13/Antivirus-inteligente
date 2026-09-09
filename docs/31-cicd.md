# Módulo 31 — CI/CD: pipeline blindado y runner local de respaldo

> Componentes: `.github/workflows/aegis_ci.yml`, `tools/ci/`, `tools/local_runner.sh`.

Un pipeline que solo corre en la infraestructura de un tercero es un **punto único
de fallo**. Si la cuenta se bloquea, si los runners se agotan o si la plataforma
cae, el proyecto se queda sin puerta de calidad justo cuando más falta hace. Este
módulo resuelve las dos caras: un pipeline remoto robusto **y** la capacidad de
ejecutarlo íntegro en local.

---

## 31.1 Una sola fuente de verdad

El error clásico es escribir los comandos del pipeline dentro del YAML y luego
mantener un script local "parecido". Los dos divergen en semanas, y el día que
hace falta el respaldo resulta que no comprueba lo mismo.

Aquí no: cada job del workflow invoca un **script de `tools/ci/`**, y el runner
local invoca **esos mismos scripts**. El YAML aporta la orquestación (matriz,
cachés, permisos, artefactos); los scripts aportan los comandos. Cambiar un job
se hace en un sitio.

| Job | Script | Qué comprueba |
|---|---|---|
| `lint` | `tools/ci/lint.sh` | formato y clippy, en depuración **y** en release |
| `test` | `tools/ci/test.sh` | pruebas del workspace + cotejo de ABI C↔Rust (gcc y clang) |
| `ebpf` | `tools/ci/ebpf.sh` | compila, firma y **carga** los programas ante el verificador |
| `sanitizers` | `tools/sanitize.sh` | rutas `unsafe` bajo AddressSanitizer |
| `fuzz-smoke` | `tools/fuzz.sh 20` | pasada corta de libFuzzer por cada parser |
| `supply-chain` | `tools/ci/supply_chain.sh` | `cargo-deny` + `cargo-audit` |
| `docs` | `tools/check-links.sh` | enlaces relativos de la documentación |
| `artifacts` | `tools/ci/artifacts.sh` | binarios de lanzamiento con procedencia |

---

## 31.2 Detección de deriva: el respaldo no puede mentir

El runner local compara su tabla de jobs con la del workflow y **aborta** si
divergen, nombrando exactamente qué falta y dónde:

```
FALLO el runner local y .github/workflows/aegis_ci.yml han divergido
  | jobs en el workflow que el runner NO ejecuta: job-fantasma
  | corrige la tabla JOBS de tools/local_runner.sh
```

Así es imposible añadir un job al pipeline remoto y que el local se quede corto
sin que nadie se entere. Un respaldo que comprueba menos de lo que cree es peor
que no tener respaldo, porque da una confianza falsa.

---

## 31.3 Tres modos, por orden de fidelidad

`tools/local_runner.sh` elige solo:

1. **`act`** — ejecuta el workflow real en contenedores. Máxima fidelidad.
2. **`docker`** — ejecuta los scripts de job en un contenedor tipo `ubuntu-latest`.
3. **`nativo`** — ejecuta los scripts directamente en la máquina.

Y dice cuál eligió y por qué. En una máquina con el CLI de Docker pero sin
daemon, por ejemplo, informa de ello y cae a nativo en vez de fallar:

```
== Modo de ejecucion ==
    OK nativo
    OMITIDO hay CLI de docker pero su daemon no responde: se corre en el anfitrion
```

Uso:

```
tools/local_runner.sh              # todos los jobs
tools/local_runner.sh --job lint   # uno solo
tools/local_runner.sh --modo act   # fuerza un modo
tools/local_runner.sh --list       # lista los jobs
```

---

## 31.4 La semántica de tres estados

Los scripts distinguen **OK**, **FALLO** y **OMITIDO**. Un job que no puede
correr en esta máquina —sin `clang` no hay eBPF, sin root no se carga en el
kernel, sin nightly no hay sanitizador— se omite **diciéndolo**. Nunca se hace
pasar por éxito. Es la misma honestidad que el resto del producto aplica al
hardware ausente (sin TPM, sin PMU): informar de lo que la máquina no ofrece en
vez de fingir que pasó.

---

## 31.5 Artefactos con procedencia

El job `artifacts` no solo compila: produce el material que un cliente despliega,
y de eso hay que poder responder byte a byte.

- **Binarios estáticos.** Se compila contra `x86_64-unknown-linux-musl`, que
  produce binarios sin dependencia de la libc del sistema: despliegan en
  cualquier distribución, que es justo lo que hace falta en una flota
  heterogénea. En CI se instala `musl-tools` porque varias dependencias llevan C
  (`yara-x`, `ring`, `libbpf`); donde falte, el script cae al objetivo del
  anfitrión y **declara** que el binario es dinámico.
- **`strip`** de símbolos: en un binario distribuido son información de más para
  un atacante.
- **`SHA256SUMS`** de cada artefacto.
- **`MANIFIESTO.txt`** con la procedencia: commit, rama, si el árbol estaba
  limpio, objetivo, tipo de enlazado, versión exacta de `rustc` y `cargo`, perfil
  y fecha UTC.
- **Prueba de humo**: cada artefacto tiene que ser un ELF de 64 bits válido y no
  estar truncado. No se exige que respondan a `--help`, porque varios son
  demonios cuyo comportamiento correcto es quedarse ejecutando.

---

## 31.6 La puerta única

El job `gate` agrega el resultado de todos los demás y es el **único** check que
hay que exigir en la protección de rama. Añadir un job nuevo al pipeline no
obliga a reconfigurar GitHub: entra solo en la agregación. Falla si cualquier
dependencia falló o fue cancelada.

El pipeline nocturno pesado —fuzzing profundo con corpus persistente,
sanitizadores completos, auditoría— vive aparte en
[`devsecops.yml`](30-devsecops.md): son comprobaciones que cuestan demasiado para
cada push y demasiado para dejarlas fuera.
