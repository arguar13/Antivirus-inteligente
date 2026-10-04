<!--
  GENERADO por `cargo xtask docs`. NO SE EDITA AQUI.
  La prosa vive en tools/config/auditoria.toml y los datos en el codigo.
-->

# Nivel SLSA declarado

Nivel SLSA alcanzado (v1.0, pista Build): **ninguno completo**. Para L1 falta: La procedencia se distribuye con los artefactos (parcial).

El nivel no se escribe: se calcula con los requisitos de abajo. Un requisito solo cumple si su evidencia existe en el repositorio, y un «no» que un fichero del repositorio desmiente hace fallar la generacion.

## Requisitos de la pista Build

| Nivel | Requisito | Estado | Evidencia | Detalle |
|---|---|---|---|---|
| L1 | Proceso de construcción consistente y guionizado | **cumple** | [`tools/ci/hermetico.sh`](../../../tools/ci/hermetico.sh), [`tools/ci-local.sh`](../../../tools/ci-local.sh) | Un solo guion construye todos los binarios herméticos desde `tools/config/instalables.toml`, con `--locked`, dentro de `make ci`. |
| L1 | La procedencia existe y la genera el build | **cumple** | [`xtask/src/sbom.rs`](../../../xtask/src/sbom.rs), [`tools/ci-local.sh`](../../../tools/ci-local.sh) | `dist-hermetico/procedencia.intoto.json`: declaración in-toto v1 con predicado SLSA v1 (sujetos con su SHA-256, commit, `Cargo.lock`, toolchain y huella del árbol), escrita por el grupo `auditoria` de `make ci` tras comprobar que los binarios salen de este árbol. Antes solo existía `MANIFIESTO.txt`, texto libre. |
| L1 | La procedencia se distribuye con los artefactos | parcial | [`.gitignore`](../../../.gitignore) | Se escribe junto a los binarios, pero no hay canal de publicación: `dist-hermetico/` está fuera de git y solo existe en la máquina que construye. Hasta que una publicación lleve juntos binarios, `SHA256SUMS`, `sbom/` y `procedencia.intoto.json`, solo la tiene quien recibe el directorio entero. |
| L2 | Plataforma de construcción alojada | **no** | [`docs/ci-remoto.md`](../../../docs/ci-remoto.md), [`docs/ci-remoto.md`](../../../docs/ci-remoto.md), [`docs/07-estado-ci.md`](../../../docs/07-estado-ci.md) | El runner corre en el PC de desarrollo, dentro de WSL (ver «Donde corre el constructor»), y GitHub Actions está bloqueado a nivel de cuenta. |
| L2 | Procedencia auténtica, firmada por la plataforma | **no** | [`crates/aegis-procedencia/src/verificacion.rs`](../../../crates/aegis-procedencia/src/verificacion.rs) | La declaración de procedencia se escribe sin firmar. `aegis-procedencia` no verifica ninguna firma de procedencia: recibe como un booleano el resultado de la firma del artefacto, que verifica `aegis-update`. Sin coste: Sigstore sin clave desde Actions, o `ssh-keygen -Y sign` con una clave de publicación que no viva en el PC de desarrollo. |
| L3 | Constructor aislado entre ejecuciones | **no** | [`.forgejo/workflows/ci.yml`](../../../.forgejo/workflows/ci.yml), [`.forgejo/workflows/ci.yml`](../../../.forgejo/workflows/ci.yml) | El runner corre en modo host y como root, con caché de compilación compartida entre ejecuciones. |
| L3 | Procedencia infalsificable | **no** | — | Exige que la clave de firma sea inaccesible a los pasos del build (flujo reutilizable tipo `slsa-github-generator`). Se declarará L3 solo cuando `slsa-verifier` lo verifique desde otra máquina. |

## Garantias complementarias

No son niveles SLSA, pero un auditor las pide junto a ellos.

| Nivel | Garantia | Estado | Evidencia | Detalle |
|---|---|---|---|---|
| — | SBOM de cada instalable ligado al Cargo.lock, con licencias | **cumple** | [`xtask/src/sbom.rs`](../../../xtask/src/sbom.rs), [`tools/ci-local.sh`](../../../tools/ci-local.sh) | CycloneDX 1.5 por instalable en `docs/generado/auditoria/sbom/`. La puerta falla si no corresponde al `Cargo.lock` o si un crate no declara licencia. Declara la licencia del código C incluido; no revisa su cumplimiento. |
| — | Build reproducible del producto en el mismo constructor | **cumple** | [`tools/construir-reproducible.sh`](../../../tools/construir-reproducible.sh), [`tools/ci-local.sh`](../../../tools/ci-local.sh) | El grupo `reproducible` de `make ci` construye dos veces los instalables herméticos desde el mismo árbol, en dos directorios de destino (uno desde cero) y con `SOURCE_DATE_EPOCH` del commit, y falla si el SHA-256 de alguno difiere. Es reproducibilidad temporal en esta máquina: mismo compilador, mismo sysroot, misma ruta. No compara esos binarios con los de `dist-hermetico/`, que se construyen con otra lista de remapeos de ruta. |
| — | Build reproducible verificado desde una segunda máquina | **no** | [`tools/construir-reproducible.sh`](../../../tools/construir-reproducible.sh) | Nadie ha reconstruido un commit en otra máquina para comparar los bytes: no hay segunda máquina (el runner es el PC de desarrollo). La toolchain sí está fijada en el repositorio (`rust-toolchain.toml`, `tools/toolchain/fijado.toml` y el sello del sysroot), que es lo que esa segunda máquina tendría que reproducir. |
| — | Toolchain de Rust fijada | **cumple** | [`rust-toolchain.toml`](../../../rust-toolchain.toml), [`tools/toolchain/fijado.toml`](../../../tools/toolchain/fijado.toml), [`tools/toolchain/comprobar_toolchain.sh`](../../../tools/toolchain/comprobar_toolchain.sh), [`tools/ci-local.sh`](../../../tools/ci-local.sh), [`tools/ci/hermetico.sh`](../../../tools/ci/hermetico.sh) | `rust-toolchain.toml` elige el canal y `tools/toolchain/fijado.toml` fija la salida exacta de `rustc` y `cargo`, el SHA-256 de cada `rust-std` y las versiones de los paquetes del sysroot musl. El grupo `toolchain` de `make ci` falla con otro compilador, y `hermetico.sh` no construye nada sin un sysroot sellado por la receta actual con esas versiones. `instalar-runner.sh` y la imagen leen o comprueban el mismo canal. |
| — | Firma de SHA256SUMS y de los binarios | **no** | [`tools/ci/hermetico.sh`](../../../tools/ci/hermetico.sh) | Las sumas se escriben sin firmar: prueban la integridad frente a un error, no frente a quien pueda reescribir el directorio. |

## Donde corre el constructor

El runner de CI (Forgejo con KVM, `.forgejo/workflows/ci.yml`) corre hoy **en el mismo PC en el que se desarrolla**, dentro de WSL, por decisión del propietario. [`docs/ci-remoto.md`](../../ci-remoto.md) exige una máquina dedicada; hoy no lo es. Nada de lo que produce cuenta como plataforma de construcción independiente: comparte usuario, disco y red con quien escribe el código, y quien puede cambiar el código puede cambiar el build. La procedencia lo registra (`constructorEnWsl` y el identificador del constructor). GitHub Actions, que daría una plataforma alojada y procedencia firmada sin coste en repositorios públicos, sigue bloqueado a nivel de cuenta ([`docs/07-estado-ci.md`](../../07-estado-ci.md)). Pasar a L2 sin coste exige resolver ese bloqueo (y que el repositorio sea público para las atestaciones de GitHub) o una máquina dedicada con una clave de firma que no esté en el PC de desarrollo.
