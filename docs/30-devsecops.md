# Módulo 30 — Pipeline DevSecOps: fuzzing, sanitizadores y auditoría

> Componentes: `fuzz/`, `tools/fuzz.sh`, `tools/sanitize.sh`, `tools/audit.sh`,
> `tools/devsecops.sh`, `.github/workflows/devsecops.yml`, `.cargo/audit.toml`.

`make ci` es la puerta por commit: rápida, para no frenar el desarrollo. Pero
hay comprobaciones de seguridad que cuestan demasiado para cada push y demasiado
para dejarlas fuera. Ese es el pipeline **DevSecOps**: una puerta **continua**,
más pesada, que corre programada cada noche y sobre tres frentes.

---

## 30.1 Fuzzing continuo — que ningún parser caiga ante un byte

Todo lo que AegisCore lee de una fuente que no controla es un parser, y un parser
que entra en pánico ante entrada malformada es una vía de denegación de servicio:
basta un paquete para tumbar el agente. El fuzzing lo encuentra antes que el
atacante.

Se fuzzean (`fuzz/fuzz_targets/`) las seis superficies de entrada no confiable:

| Objetivo | Qué parsea |
|---|---|
| `fleet_proto` | los mensajes protobuf del servicio de flota (llegan por red) |
| `fleet_x509` | el DER de un certificado, al extraer su CN |
| `fleet_frame` | la cabecera de longitud de una trama RPC |
| `firmware_eventlog` | el registro de eventos TCG del firmware |
| `firmware_uefi` | las variables efivarfs y las listas de firmas DBX |
| `scal_maps` | `/proc/<pid>/maps` |

Cada objetivo corre bajo **libFuzzer** (con AddressSanitizer integrado). La
invariante es dura: ante cualquier secuencia de bytes, el parser devuelve `Err`,
nunca pánico ni acceso inválido. El corpus persiste entre ejecuciones, así que el
fuzzing es de verdad **continuo**: cada noche arranca donde quedó la anterior y
explora más profundo. Un hallazgo deja un reproductor en `fuzz/artifacts/`.

`fuzz/` es un workspace aparte del producto a propósito: libFuzzer exige nightly
y banderas de instrumentación que no deben contaminar el build normal. El
workspace principal lo excluye.

---

## 30.2 Sanitización de memoria — las rutas `unsafe` bajo vigilancia

AegisCore tiene `unsafe` allí donde toca el kernel: `ptrace`, `process_vm_readv`,
`perf_event_open`, el ring buffer compartido con el driver, las sondas de ABI. El
compilador no comprueba esas rutas; un fallo ahí —una lectura fuera de rango, un
uso después de liberar— no da un error de compilación, da corrupción silenciosa.

`tools/sanitize.sh` corre las pruebas de los crates con `unsafe` de primera parte
bajo **AddressSanitizer** (`-Zsanitizer=address`), que instrumenta cada acceso a
memoria y aborta ante el primer error. Cubre `aegis-scal`, `aegis-ipc`,
`aegis-syscallguard`, `aegis-firmware` y `aegis-fleet`. Es la comprobación en
ejecución de que las rutas que el `unsafe` promete son, de hecho, seguras.

---

## 30.3 Auditoría de dependencias — la cadena de suministro

Cada crate de terceros que acaba dentro del agente es superficie de ataque: si se
compromete, se compromete el EDR. `tools/audit.sh` cruza el árbol de
dependencias contra la base de avisos de **RustSec** (`cargo-audit`), y
complementa a `deny.toml` (que cubre licencias, fuentes y versiones duplicadas).

La política, en `.cargo/audit.toml`, es explícita:

1. **Se corrige** todo aviso con versión parcheada dentro del rango semver. Así se
   cerró `RUSTSEC-2026-0217` (desbordamiento de entero en el parser de tensores de
   `tract-nnef`), subiendo `tract` a 0.21.18.
2. **Se acepta**, listado y justificado, solo el aviso que no tiene arreglo
   alcanzable sin un salto de versión mayor de una dependencia de terceros Y cuya
   vía de explotación no aplica a cómo AegisCore usa el crate. El grueso son
   avisos del subárbol `yara-x → wasmtime`: wasmtime ejecuta las reglas YARA que
   **nosotros** compilamos, no WebAssembly de un atacante, así que los escapes del
   sandbox del invitado no tienen vía de entrada.
3. **Rompe el pipeline** cualquier aviso nuevo que no esté triado. Eso obliga a
   revisarlo: corregir o documentar.

---

## 30.4 El pipeline y cómo se ejecuta

`tools/devsecops.sh` reúne las tres patas y emite un veredicto único. En local:

```
make devsecops     # las tres patas
make fuzz          # solo fuzzing
make sanitize      # solo sanitizadores
make vulns         # solo auditoría de dependencias
```

En CI, `.github/workflows/devsecops.yml` lo corre **programado cada noche** (y al
tocar `Cargo.lock`, los objetivos de fuzzing o la política de auditoría), no en
cada push: el fuzzing y la instrumentación cuestan tiempo, y su sitio es la puerta
continua, no la puerta por commit.

Cada pata se **omite con honestidad** donde el entorno no la soporta (sin nightly
no hay fuzzing ni sanitizador; sin `cargo-audit` no hay auditoría), igual que el
resto del proyecto informa de lo que la máquina no ofrece en vez de fingir que
pasó.
