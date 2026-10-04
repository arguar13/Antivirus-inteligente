# Módulo 55 — Resiliencia empresarial: ABI de ELAM/PPL y tamper criptográfico

> **Windows no es producto.** Hace falta ser miembro de la Microsoft Virus Initiative (MVI), un driver ELAM y la firma del driver por atestación en el portal de hardware de Microsoft (con certificado EV), y PPL para el servicio; lo decide Microsoft, no este repositorio. Lo que este documento cuenta de Windows es biblioteca o diseño: no protege ninguna máquina Windows. Ver [Plataformas](matriz-capacidades.md#plataformas).

> Componentes: `crates/aegis-selfdefense/` (módulos `abi`, `resiliencia`, sobre
> las piezas de autodefensa del módulo 50).

## 55.1 De la decisión al contrato con el kernel

El módulo 50 dejó la **decisión** de autodefensa: clasificar un driver de
arranque (ELAM), comprobar los requisitos de proceso protegido (PPL), y el OTP
firmado con el que el dueño autoriza parar o desinstalar el agente. La FASE 60
lleva esa decisión hasta donde de verdad se ejecuta: el **contrato binario** con
el kernel de Windows, y el **guardián** que intercepta una señal de parada real.

Son dos piezas distintas:

- **`abi`** — las estructuras exactas con las que la decisión cruza al kernel.
- **`resiliencia`** — `AegisResilience`, que convierte una señal del sistema
  operativo en la decisión de permitir o denegar la parada.

## 55.2 La línea que no se cruza (otra vez)

La autodefensa de un EDR camina por el filo: de menos, un atacante con privilegios
de administrador mata el agente justo cuando hace falta; de más, el **dueño** no
puede desinstalarlo, y un producto que no se deja quitar por su dueño es un
rootkit. AegisCore resuelve las dos con una sola regla: **la autorización del
dueño —un OTP firmado por el Control Plane— siempre gana**. Con OTP válido, parar
o desinstalar se permite; sin él, sobre un recurso protegido, se deniega. Toda la
autodefensa empresarial se apoya en APIs y contratos oficiales del sistema
operativo (el certificado ELAM, PPL respaldado por el kernel), nunca en secuestrar
el arranque contra el dueño.

## 55.3 Los contratos de ABI, verificados en compilación

Un driver ELAM del WDK recibe del kernel una estructura `BDCB_IMAGE_INFORMATION`
y devuelve un código `BDCB_CLASSIFICATION`; un proceso protegido lleva un byte
`PS_PROTECTION` con un formato de bits exacto. Si el tamaño, el orden de los
campos o el valor de un enum no coinciden **al byte** con los del `ntddk.h`, el
driver lee basura o el kernel rechaza la petición. Como aquí no hay un kernel de
Windows contra el que ejecutar, la única forma honesta de "probar" la ABI es
**verificarla en compilación**: cada estructura lleva su tamaño, su alineación y
sus offsets comprobados con `assert!` en contexto `const`. Si alguien la
desincroniza, no compila.

Esta capa además **arregla de raíz** una trampa: los códigos internos de la
decisión (`ClasificacionElam`) **no** son los que Windows espera. En el WDK, `0`
es *imagen desconocida*, no *buena*. Devolver el número interno equivocado haría
que el kernel bloqueara un driver bueno o cargara uno malo. Por eso la decisión y
el código de wire se separan, y el puente entre ambos —`From<ClasificacionElam>`
para `BdcbClassification`— se prueba explícitamente.

El byte de PPL-Antimalware de AegisCore es `0x31` (`Signer=Antimalware(3)`,
`Type=ProtectedLight(1)`), y la capa de ABI lo **ata en compilación** al mismo
valor que ya publicaba el módulo `ppl`: no pueden divergir.

## 55.4 El guardián de detención

`AegisResilience` toma una señal cruda del sistema operativo —una señal POSIX
(`SIGTERM`, `SIGINT`, `SIGQUIT`…), un control del SCM de Windows
(`SERVICE_CONTROL_STOP`, `…SHUTDOWN`) o una petición explícita de desinstalar—, la
traduce a la `OperacionProtegida` que representa, y aplica la política de tamper
del módulo 50 verificando el OTP **de verdad**: firma híbrida Ed25519+ML-DSA-65
del Control Plane, atado a este host y a esta operación, dentro de su ventana de
validez y de un solo uso (anti-replay). Un `kill -TERM` o un `sc stop` de un
atacante se topa con una negativa; el dueño, que tiene la llave, para y
desinstala cuando quiere. El OTP sólo se verifica —y se consume— si de verdad hace
falta: una parada legítima del watchdog no gasta un token de un solo uso.

### La honestidad que no se cruza: `SIGKILL` y `SIGSTOP`

`SIGKILL` (9) y `SIGSTOP` (19) **no se pueden interceptar desde el espacio de
usuario**: el kernel no deja instalar un manejador para ellas, por diseño. Ningún
guardián en Rust puede "rechazar" un `SIGKILL`. Por eso el guardián **declara la
verdad** en cada resultado (`interceptable_en_usuario`): calcula la decisión
correcta —un `SIGKILL` de un atacante debería denegarse— pero avisa de que su
cumplimiento no es cosa del espacio de usuario, sino del kernel, y ése es justo el
trabajo de PPL-Antimalware. Se decide con honestidad; no se finge un poder que no
se tiene.

## 55.5 Honestidad de validación

| Pieza | Verificable aquí | Muro |
|---|---|---|
| ABI ELAM `BDCB_IMAGE_INFORMATION`: tamaño (104 B), alineación y offsets x64 | sí, en compilación | — |
| Códigos `BDCB_CLASSIFICATION` reales del WDK y el puente desde la decisión | sí | — |
| Byte `PS_PROTECTION` (bits Type/Audit/Signer) atado a `0x31` (AM-Light) | sí, en compilación | — |
| Guardián: señal del SO → operación protegida | sí | — |
| Rechazo de una parada sin OTP; autorización con OTP híbrido **real** | sí, cero mocks | — |
| Atado a host / operación / ventana / anti-replay del OTP de detención | sí | — |
| Declarar que `SIGKILL`/`SIGSTOP` no son interceptables en usuario | sí (se declara) | imponerlos es del kernel (PPL); gated |
| Registrar el callback ELAM en vivo (`IoRegisterBootDriverCallback`) | — | necesita WDK + cert AM firmado por Microsoft; gated |
| Que el kernel conceda PPL-Antimalware al proceso | — | necesita el binario firmado y un Windows real; gated |

El núcleo que puede estar mal de forma peligrosa —traducir la señal, verificar y
consumir el OTP, decidir— se prueba de verdad en cada `make ci`, con firmas
híbridas reales. La puesta en vivo de la autodefensa (el driver ELAM firmado, la
concesión de PPL por el kernel, imponer una señal no interceptable) es un muro que
`tools/verificar-resiliencia.sh` declara en vez de fingir.
