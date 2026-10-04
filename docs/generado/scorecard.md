# Scorecard de AegisCore

> GENERADO por `cargo xtask marcador` en `make ci`, despues de la matriz de kernels. No editar a mano. Cada cifra sale de una linea medida; una celda sin dato dice «sin medir».

Arbol de los binarios medidos: `eb3228b602d3199fbf6e979418be4fe1c80d86e37cfff1f0b3bb52cb8e5b813f`

Imagenes con resultado: debian-11, rocky-9, ubuntu-22.04, debian-12, amazon-linux-2023, opensuse-leap-15.6, ubuntu-24.04, fedora-44, ubuntu-24.04-arm64, debian-12-arm64

## Cobertura ATT&CK (rango en vivo)

Emulaciones reales contra el agente publicado en cada microVM (`rango-en-vivo`). Celda: segundos hasta la señal del agente, «hueco» si no la hubo en su ventana.

| Tecnica | Motor que la detecto | debian-11 | rocky-9 | ubuntu-22.04 | debian-12 | amazon-linux-2023 | opensuse-leap-15.6 | ubuntu-24.04 | fedora-44 | ubuntu-24.04-arm64 | debian-12-arm64 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1053.003 | ninguno | hueco | hueco | hueco | hueco | hueco | hueco | hueco | hueco | hueco | hueco |
| T1071.001 | l7hunter | hueco | hueco | hueco | hueco | hueco | hueco | hueco | 97 s | hueco | hueco |
| T1098.004 | conductual | 45 s | 46 s | 45 s | 45 s | 45 s | hueco | 45 s | 45 s | 46 s | 45 s |
| T1486 | ninguno | hueco | hueco | hueco | hueco | hueco | hueco | hueco | hueco | hueco | hueco |
| T1564 | nucleo | hueco | hueco | hueco | hueco | hueco | hueco | 91 s | hueco | 91 s | hueco |

| Imagen | Tecnicas detectadas |
|---|---|
| debian-11 | 1/5 |
| rocky-9 | 1/5 |
| ubuntu-22.04 | 1/5 |
| debian-12 | 1/5 |
| amazon-linux-2023 | 1/5 |
| opensuse-leap-15.6 | 0/5 |
| ubuntu-24.04 | 2/5 |
| fedora-44 | 2/5 |
| ubuntu-24.04-arm64 | 2/5 |
| debian-12-arm64 | 1/5 |

## Deteccion y falsos positivos por motor (corpus en VM)

Corpus de laboratorio analizado dentro de una microVM sin red (`corpus-en-vivo`). Por mil binarios, con el recuento al lado; se suman las imagenes que lo ejecutaron.

| Motor | Deteccion (maliciosos) | Falsos positivos (benignos) |
|---|---|---|
| baliza | sin medir | sin medir |
| conducta | sin medir | sin medir |
| estatico | sin medir | sin medir |
| integridad | sin medir | sin medir |
| memoria | sin medir | sin medir |
| modelo | sin medir | sin medir |
| nucleo | sin medir | sin medir |
| postura | sin medir | sin medir |
| rol | sin medir | sin medir |
| secuestro | sin medir | sin medir |
| sigma | sin medir | sin medir |
| triaje | sin medir | sin medir |
| **cualquier motor** | sin medir | sin medir |

## Latencia de veredicto

| Medida | Imagen | Valor |
|---|---|---|
| analisis p99 en el trabajador confinado | debian-11 | 509.28 ms |
| analisis p99 en el trabajador confinado | rocky-9 | 572.41 ms |
| analisis p99 en el trabajador confinado | ubuntu-22.04 | 637.41 ms |
| analisis p99 en el trabajador confinado | debian-12 | 343.71 ms |
| analisis p99 en el trabajador confinado | amazon-linux-2023 | 335.06 ms |
| analisis p99 en el trabajador confinado | opensuse-leap-15.6 | 279.23 ms |
| analisis p99 en el trabajador confinado | ubuntu-24.04 | 368.26 ms |
| analisis p99 en el trabajador confinado | fedora-44 | 369.09 ms |
| analisis p99 en el trabajador confinado | ubuntu-24.04-arm64 | 156.14 ms |
| analisis p99 en el trabajador confinado | debian-12-arm64 | 1302.64 ms |
| desde la emulacion hasta la señal (mediana, rango) | todas | 45 s |

Latencia de veredicto sobre el corpus: sin medir.

## Modelo estatico

| Campo | Valor |
|---|---|
| Clase segun su tarjeta | referencia |
| Version | 1 |
| AUC (evaluacion posterior al corte) | sin medir |
| Recall en bloqueo | sin medir |
| Cota 95 % del FPR en bloqueo | sin medir |
| FPR objetivo (tools/config/modelo.toml) | 1.0e-4 |

El agente usa el modelo solo si su tarjeta corresponde por hash al modelo empotrado y cumple ese objetivo (`crates/aegis-ml/src/puerta.rs`); si no, su puntuacion sale NoConcluyente. Detalle: `docs/generado/tarjeta-modelo-estatico.md`.

## Solo-auditoria frente a imponer

Un motor sin falsos positivos medidos no puede pasar de solo-auditoria a imponer. Sin medir hoy: baliza, conducta, estatico, integridad, memoria, modelo, nucleo, postura, rol, secuestro, sigma, triaje.
