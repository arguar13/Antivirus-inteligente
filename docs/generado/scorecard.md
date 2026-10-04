# Scorecard de AegisCore

> GENERADO por `cargo xtask marcador` en `make ci`, despues de la matriz de kernels. No editar a mano. Cada cifra sale de una linea medida; una celda sin dato dice «sin medir».

Arbol de los binarios medidos: `fa81e97425eb4d5765d08054679cb7e7f304b72fbc0745ff65f2ca1df6d10f07`

Imagenes con resultado: debian-11, rocky-9, ubuntu-22.04, debian-12, amazon-linux-2023, opensuse-leap-15.6, ubuntu-24.04, fedora-44, ubuntu-24.04-arm64, debian-12-arm64

## Cobertura ATT&CK (rango en vivo)

Emulaciones reales contra el agente publicado en cada microVM (`rango-en-vivo`). Celda: segundos hasta la señal del agente, «hueco» si no la hubo en su ventana.

| Tecnica | Motor que la detecto | debian-11 | rocky-9 | ubuntu-22.04 | debian-12 | amazon-linux-2023 | opensuse-leap-15.6 | ubuntu-24.04 | fedora-44 | ubuntu-24.04-arm64 | debian-12-arm64 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1053.003 | ninguno | hueco | hueco | hueco | hueco | hueco | hueco | hueco | hueco | hueco | hueco |
| T1071.001 | l7hunter | hueco | hueco | hueco | hueco | hueco | hueco | hueco | 97 s | hueco | hueco |
| T1098.004 | conductual | 45 s | 45 s | 45 s | 45 s | 45 s | hueco | 45 s | 45 s | 46 s | 45 s |
| T1486 | ninguno | hueco | hueco | hueco | hueco | hueco | hueco | hueco | hueco | hueco | hueco |
| T1564 | nucleo | hueco | hueco | hueco | hueco | hueco | hueco | 90 s | hueco | 91 s | hueco |

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
| analisis p99 en el trabajador confinado | debian-11 | 536.91 ms |
| analisis p99 en el trabajador confinado | rocky-9 | 449.46 ms |
| analisis p99 en el trabajador confinado | ubuntu-22.04 | 580.97 ms |
| analisis p99 en el trabajador confinado | debian-12 | 343.95 ms |
| analisis p99 en el trabajador confinado | amazon-linux-2023 | 313.10 ms |
| analisis p99 en el trabajador confinado | opensuse-leap-15.6 | 288.65 ms |
| analisis p99 en el trabajador confinado | ubuntu-24.04 | 358.35 ms |
| analisis p99 en el trabajador confinado | fedora-44 | 410.84 ms |
| analisis p99 en el trabajador confinado | ubuntu-24.04-arm64 | 118.99 ms |
| analisis p99 en el trabajador confinado | debian-12-arm64 | 1242.12 ms |
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
