<!--
  GENERADO por `cargo xtask docs`. NO SE EDITA AQUI.
  La prosa vive en tools/config/auditoria.toml y los datos en el codigo.
-->

# Paquete para auditoria externa

Lo que un auditor externo necesita para empezar sin preguntar: qué hay, cómo está construido, de qué está hecho, de dónde sale cada binario y qué se propone atacar. Todo se genera desde el código con `cargo xtask docs`, y `make ci` falla si deja de coincidir. Lo que no se puede derivar del código está en [`tools/config/auditoria.toml`](../../../tools/config/auditoria.toml), con una evidencia que se comprueba en cada generación.

## Contenido

| Pieza | Donde | Como se obtiene | Puerta en `make ci` |
|---|---|---|---|
| Modelo de amenazas | [`docs/modelo-de-amenazas.md`](../../../docs/modelo-de-amenazas.md) | Escrito a mano; su estructura y sus evidencias se comprueban | `cargo xtask amenazas` (grupo `arquitectura`) |
| Arquitectura | [capas](#arquitectura) y diagrama del [README](../../../README.md) | `cargo metadata` y [`tools/config/capas.toml`](../../../tools/config/capas.toml) | `cargo xtask capas` (grupo `arquitectura`) |
| Matriz de capacidades | [`docs/matriz-capacidades.md`](../../../docs/matriz-capacidades.md) | Binarios compilados, pruebas e2e de la matriz de kernels y medidas | `cargo xtask docs --comprobar` (grupo `documentacion`) |
| SBOM (CycloneDX 1.5) | [sbom/](sbom/) | `Cargo.lock` y `cargo tree --locked` | `cargo xtask sbom --comprobar` (grupo `auditoria`) y `docs --comprobar` |
| SBOM con el hash de cada binario y procedencia del build | `dist-hermetico/sbom/` y `dist-hermetico/procedencia.intoto.json` | El build hermetico de la misma tanda | `cargo xtask sbom --dist dist-hermetico` (grupo `auditoria`) |
| Nivel SLSA | [slsa.md](slsa.md) | Requisitos con evidencia comprobada | `cargo xtask docs --comprobar` |
| Alcance del pentest | [alcance-pentest.md](alcance-pentest.md) | Puntos de entrada extraidos del codigo | `cargo xtask docs --comprobar` |

## Modelo de amenazas

[`docs/modelo-de-amenazas.md`](../../../docs/modelo-de-amenazas.md) (version 1): 32 filas (9 ausente, 8 existente, 4 no-aplica, 11 parcial).

## Arquitectura

Una dependencia solo puede bajar de capa; la lista de excepciones solo puede menguar. Detalle y excepciones en la [matriz de capacidades](../../../docs/matriz-capacidades.md#excepciones-de-arquitectura).

| Capa | Crates | Cuales |
|---|---:|---|
| nucleo | 12 | `aegis-case`, `aegis-entidad`, `aegis-ipc`, `aegis-macho`, `aegis-parser`, `aegis-patron`, `aegis-pe`, `aegis-pqc`, `aegis-presupuesto`, `aegis-procedencia`, `aegis-share`, `aegis-sync` |
| plataforma | 12 | `aegis-audit`, `aegis-contenido`, `aegis-enforce`, `aegis-firmware`, `aegis-harden`, `aegis-kguard`, `aegis-resp`, `aegis-sandbox`, `aegis-scal`, `aegis-sensor`, `aegis-update`, `aegis-vmi` |
| motores | 52 | `aegis-attest`, `aegis-behavior`, `aegis-captura`, `aegis-cloudnative`, `aegis-confinar`, `aegis-conocimiento`, `aegis-custodia`, `aegis-deception`, `aegis-decompile`, `aegis-detonate`, `aegis-disasm`, `aegis-disectores`, `aegis-edgeml`, `aegis-emu`, `aegis-emular`, `aegis-enrich`, `aegis-estado`, `aegis-evasion`, `aegis-flujo`, `aegis-forensics`, `aegis-fwaudit`, `aegis-hardsense`, `aegis-honeytoken`, `aegis-instrumentar`, `aegis-integridad`, `aegis-ips`, `aegis-itdr`, `aegis-kintegrity`, `aegis-l7hunter`, `aegis-memhunter`, `aegis-ml`, `aegis-motor`, `aegis-net`, `aegis-orchestrator`, `aegis-postura`, `aegis-predict`, `aegis-ptguard`, `aegis-rango`, `aegis-ransom`, `aegis-rollback`, `aegis-ruleforge`, `aegis-sbom`, `aegis-scan`, `aegis-selfdefense`, `aegis-sigma`, `aegis-swarm`, `aegis-syscallguard`, `aegis-trabajador`, `aegis-unpacker`, `aegis-volcado`, `aegis-vuln`, `aegis-wire` |
| E/S | 18 | `aegis-agent`, `aegis-almacen-pcap`, `aegis-almacen`, `aegis-consola`, `aegis-ctl`, `aegis-firehose`, `aegis-fleet`, `aegis-hunt`, `aegis-ingest`, `aegis-intel`, `aegis-invitado`, `aegis-mesh`, `aegis-pipeline`, `aegis-scale`, `aegis-server`, `aegis-swarm-net`, `aegis-tejido`, `aegis-watchdog` |
| herramientas (no se instalan) | 3 | `aegis-e2e`, `aegis-prueba`, `fleet-simulator` |

Excepciones conocidas, con causa y plan: 3.

## Matriz de capacidades

| Espacio de trabajo | Producto | Condicional | Biblioteca | Herramienta |
|---|---:|---:|---:|---:|
| Agente (`crates/`) | 8 | 1 | 65 | 2 |
| Plano de control (`server/crates/`) | 0 | 0 | 19 | 1 |
| Enjambre (`swarm-net/`) | 0 | 0 | 1 | 0 |

**Producto** = lo invoca un ejecutable instalable, lo ejerce una prueba de extremo a extremo en la matriz de kernels y tiene una medida. **Condicional** = lo mismo, pero depende de hardware o de un certificado y lo declara. **Biblioteca** = código probado que hoy no protege ninguna máquina. Detalle crate a crate, con lo que le falta a cada uno: [matriz de capacidades](../../../docs/matriz-capacidades.md).

## SBOM

Un CycloneDX 1.5 JSON por instalable. «En ejecucion» es lo que llega al binario; «solo al compilar», las dependencias de `build.rs` y las macros procedurales con lo que solo ellas usan (`scope: excluded`).

| Instalable | SBOM | Objetivo | Caracteristicas | En ejecucion | Solo al compilar | Licencias distintas | Incrustados | C incluido | Sistema |
|---|---|---|---|---:|---:|---:|---:|---:|---:|
| `aegis-agent` | [`aegis-agent.cdx.json`](sbom/aegis-agent.cdx.json) | `x86_64-unknown-linux-musl` | `hermetico` | 208 | 34 | 18 | 14 | 3 | 3 |
| `aegisctl` | [`aegisctl.cdx.json`](sbom/aegisctl.cdx.json) | `x86_64-unknown-linux-musl` | — | 42 | 7 | 7 | 2 | 0 | 3 |
| `aegis-watchdog` | [`aegis-watchdog.cdx.json`](sbom/aegis-watchdog.cdx.json) | `x86_64-unknown-linux-musl` | — | 3 | 5 | 3 | 0 | 0 | 3 |
| `aegis-fleet` | [`aegis-fleet.cdx.json`](sbom/aegis-fleet.cdx.json) | `x86_64-unknown-linux-musl` | — | 68 | 22 | 10 | 0 | 0 | 3 |
| `aegis-server` | [`aegis-server.cdx.json`](sbom/aegis-server.cdx.json) | `x86_64-unknown-linux-gnu` | — | 267 | 51 | 20 | 3 | 0 | 1 |

**Licencias de los crates** (todos los instalables, cada crate una vez). La politica la aplica `cargo-deny` (grupo `cadena`); el codigo C incluido en un crate no lo ve, y por eso va aparte:

| Licencia (SPDX) | Crates |
|---|---:|
| `(MIT OR Apache-2.0) AND Unicode-3.0` | 1 |
| `Apache-2.0` | 70 |
| `Apache-2.0 AND ISC` | 1 |
| `Apache-2.0 OR BSL-1.0` | 1 |
| `Apache-2.0 OR BSL-1.0 OR MIT` | 1 |
| `Apache-2.0 OR ISC OR MIT` | 1 |
| `Apache-2.0 OR MIT` | 44 |
| `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 2 |
| `BSD-2-Clause` | 1 |
| `BSD-2-Clause OR Apache-2.0 OR MIT` | 1 |
| `BSD-3-Clause` | 6 |
| `BlueOak-1.0.0 OR MIT OR Apache-2.0` | 1 |
| `CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception` | 1 |
| `CC0-1.0 OR MIT-0 OR Apache-2.0` | 1 |
| `CDLA-Permissive-2.0` | 2 |
| `ISC` | 2 |
| `LGPL-2.1-only OR BSD-2-Clause` | 1 |
| `MIT` | 55 |
| `MIT AND BSD-3-Clause` | 1 |
| `MIT OR Apache-2.0` | 210 |
| `MIT OR Apache-2.0 OR Zlib` | 1 |
| `Unicode-3.0` | 18 |
| `Unlicense OR MIT` | 4 |
| `Zlib` | 2 |
| `Zlib OR Apache-2.0 OR MIT` | 1 |

**Codigo C incluido en crates** (licencia declarada por el proyecto de origen, fuera de `cargo-deny`):

| Componente | Dentro de | Licencia | Nota |
|---|---|---|---|
| libbpf | `libbpf-sys` | `LGPL-2.1-only OR BSD-2-Clause` | libbpf-sys la compila desde su fuente incluida y queda enlazada estáticamente en el agente hermético. |
| libelf | `libbpf-sys` | `GPL-2.0-or-later OR LGPL-3.0-or-later` | De elfutils, enlazada estáticamente en el binario hermético. Qué exige su licencia en un binario estático (aviso, fuentes u objetos para reenlazar) NO está resuelto: queda pendiente de decisión del propietario y el auditor debe revisarlo. |
| zlib | `libbpf-sys` | `Zlib` | Enlazada estáticamente en el binario hermético. |

**Limites conocidos del SBOM**

- Solo x86_64. El agente y el watchdog de aarch64 (`dist-hermetico-aarch64/`, variante `estatico-sistema` con la libelf y la zlib de la distribución) aún no tienen SBOM ni `SHA256SUMS`.
- El servidor no tiene binario hermético: su SBOM no lleva hash, y glibc y las demás bibliotecas dinámicas del sistema donde se instala no aparecen.
- La granularidad es el crate. El código C que un crate compila por dentro solo aparece si está declarado en `[[vendorizado]]`, y su licencia la declara el proyecto de origen: `cargo-deny` no la ve. Declararla no resuelve sus obligaciones.
- La versión de la biblioteca estándar de Rust, de musl y de libunwind la fija el repositorio (`rust-toolchain.toml` y `tools/toolchain/fijado.toml`, grupo `toolchain` de `make ci`), pero la registra el SBOM del build, no este.
- Un crate enlazado cuyo código descarta el enlazador sigue apareciendo: el SBOM sobreaproxima. Lo que se ejecuta de verdad lo dice la matriz de capacidades.
- Los objetos eBPF incrustados se generan en `build.rs` y no llevan hash en el SBOM versionado.

## Procedencia del build

Los binarios herméticos no se versionan, y su SHA-256 depende del constructor: la reproducibilidad solo se comprueba en la misma máquina (grupo `reproducible` de `make ci`), con otros directorios de destino que los de `dist-hermetico/`. Por eso sus sumas no están aquí, sino junto a ellos en `dist-hermetico/`. El grupo `auditoria` de `make ci` comprueba que salen de este árbol (HUELLA) y que coinciden con `SHA256SUMS`, y solo entonces escribe a su lado el SBOM con el hash de cada binario y la procedencia del build.

| Fichero en `dist-hermetico/` | Que es | Lo escribe |
|---|---|---|
| `SHA256SUMS` | SHA-256 de cada binario hermetico | `tools/ci/hermetico.sh` |
| `HUELLA` | Huella del arbol del que salen (commit, cambios y ficheros sin seguir) | `tools/ci/hermetico.sh` con `tools/huella-arbol.sh` |
| `MANIFIESTO.txt` | Campos: `commit`, `arbol limpio`, `huella`, `objetivo`, `enlazado`, `sysroot`, `sello sysroot`, `compilador C`, `compilador`, `rustflags`, `fecha fuente`, `construido`, `binarios` | `tools/ci/hermetico.sh` |
| `sbom/<binario>.cdx.json` | El SBOM versionado mas el SHA-256 del binario, el commit y la huella | `cargo xtask sbom --dist` |
| `procedencia.intoto.json` | Declaracion in-toto v1 con predicado SLSA v1, **sin firmar** | `cargo xtask sbom --dist` |

## Nivel SLSA

Nivel SLSA alcanzado (v1.0, pista Build): **ninguno completo**. Para L1 falta: La procedencia se distribuye con los artefactos (parcial). Detalle y evidencias: [slsa.md](slsa.md).

## Alcance del pentest

Superficies: [Parsers del trabajador](alcance-pentest.md#parsers), [IPC entre el agente y el trabajador](alcance-pentest.md#ipc-trabajador), [Socket de control local](alcance-pentest.md#socket-control), [Actualización](alcance-pentest.md#actualizacion), [Malla P2P y enjambre](alcance-pentest.md#malla), [API del plano de control y canales de la flota](alcance-pentest.md#api). Detalle: [alcance-pentest.md](alcance-pentest.md).
