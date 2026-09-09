#!/usr/bin/env bash
#
# Job de CI: formato y lints.
#
# Corre clippy en depuracion Y en release: el perfil de release activa LTO y
# optimizaciones, y con ellas lints que el perfil de depuracion no llega a
# disparar. Un aviso es un error: en un producto de seguridad, el codigo que
# "casi" esta bien es el que falla en produccion.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
cd "$RAIZ"

titulo "Job: lint (formato, clippy y estructura del pipeline)"
FALLOS=0

# La estructura del pipeline se valida ANTES que el codigo: descubrir aqui que
# un `needs` apunta al vacio cuesta segundos; descubrirlo en remoto cuesta una
# ejecucion entera.
correr "estructura de los workflows" ./tools/ci/validate_workflow.py || FALLOS=$((FALLOS+1))

correr "cargo fmt --all --check"            cargo fmt --all -- --check || FALLOS=$((FALLOS+1))
correr "clippy (depuracion, -D warnings)"   cargo clippy --all-targets -- -D warnings || FALLOS=$((FALLOS+1))
correr "clippy (release, -D warnings)"      cargo clippy --release --workspace --all-targets -- -D warnings || FALLOS=$((FALLOS+1))

[ "$FALLOS" -eq 0 ] && exit 0 || exit 1
