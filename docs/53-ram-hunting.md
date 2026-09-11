# Módulo 53 — Forense de memoria a escala: YARA sobre la RAM de la flota

> Componentes: `crates/aegis-scan/src/memscanner.rs`,
> `crates/aegis-parser/src/esquema.rs` (tabla `memory`),
> `crates/aegis-hunt/src/ejecutor.rs` (`tabla_yara`).

## 53.1 Llevar el threat hunting a la RAM

Escanear el disco solo ve lo que el atacante dejó en un fichero. El malware
moderno no deja nada: se descomprime en memoria, se inyecta en un proceso
legítimo, o corre desde un descriptor que nunca tocó el disco. La caza tiene que
poder correr reglas YARA sobre la **RAM** —y a través de toda la flota de diez
mil endpoints—. `AegisMemScanner` es el motor que lo hace sin congelar ninguna
máquina.

## 53.2 El peligro sutil: la firma partida

Escanear gigabytes de una vez se come la CPU y la E/S del endpoint de un cliente,
así que el escáner es **particionado**: lee la memoria en trozos (`chunks`). Pero
partir introduce un bug traicionero —el que separa un escáner correcto de uno
roto—: una firma que cae **a caballo entre dos chunks** no aparece entera en
ninguno de los dos, y un escáner ingenuo la pierde.

`AegisMemScanner` arrastra un **solapamiento** entre chunks, de tamaño mayor o
igual que la firma más larga del conjunto YARA: la cola del chunk anterior se
antepone al siguiente, de modo que toda coincidencia queda entera dentro de
alguna ventana. El caso decisivo lo prueba de verdad: una firma colocada
cruzando la frontera **se encuentra** con solapamiento y **se pierde** sin él —y,
además, no se cuenta dos veces cuando cae dentro de la zona re-escaneada—.

## 53.3 No congelar el endpoint: particionado y estrangulado

Tras cada chunk, el escáner avisa a un **estrangulador** con los bytes leídos.
El estrangulado real de E/S/CPU lo aplica el sistema operativo por fuera
—**cgroups** en Linux, **Job Objects** en Windows— sobre el proceso de la caza,
que es el mecanismo que garantiza que un barrido de RAM no le robe la CPU al
trabajo del usuario. El escáner además ofrece un estrangulador de ritmo máximo
en proceso (`RitmoMaximo`), cuya pausa se calcula con una función pura y probada.
El límite de tiempo de AegisQL acota el conjunto por arriba: una caza cara
devuelve lo hallado hasta agotar su presupuesto, marcado como incompleto.

## 53.4 `SELECT pid FROM memory WHERE yara_match = 'APT29_Core'`

El hunting a escala se expresa en **AegisQL**, el mismo lenguaje de la FASE 38
que ya se difunde a la flota entera y se agrega en tiempo real. La FASE 57 añade
la tabla `memory`: cada fila es un proceso, y la columna `yara_match` es
**existencial** —igual que `network.port`—: `yara_match = 'APT29_Core'` significa
"alguna región de la memoria de este proceso coincide con esa regla". El ejecutor
escanea la memoria de cada proceso con `AegisMemScanner` y filtra. El esquema
vive en el parser, así que un nombre de regla mal escrito es un error inmediato
en la consola, no diez mil fallos remotos.

## 53.5 Honestidad de validación

| Pieza | Verificable aquí | Muro |
|---|---|---|
| Partición en chunks con **solapamiento** (firma partida encontrada) | sí, con reglas YARA reales sobre buffers reales | — |
| Deduplicación (una coincidencia por regla y región) | sí | — |
| Contabilidad de bytes hacia el estrangulador | sí | — |
| Cálculo de la pausa de ritmo (`pausa_para_ritmo`) | sí, función pura | — |
| Tabla `memory` de AegisQL y la query exacta de la fase | sí, parseo + plan | — |
| Filtro existencial `yara_match` | sí | — |
| Leer la memoria FÍSICA cruda / de OTROS procesos | — | necesita privilegios o el driver de kernel; gated |
| Estrangulado real por cgroups / Job Objects | — | lo aplica el SO; gated |

El núcleo que puede estar mal de forma peligrosa —partir sin perder una firma,
escanear, deduplicar y filtrar— se prueba de verdad en cada `make ci`. Leer la
memoria física cruda y aplicar los límites por cgroups son muros del sistema, que
`tools/verificar-memscanner.sh` declara en vez de fingir.
