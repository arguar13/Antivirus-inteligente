#!/usr/bin/env bash
#
# Job: supply-chain — las dependencias de terceros de los CUATRO espacios de
# trabajo, con tres herramientas que miran cosas distintas:
#
#   cargo-deny   politica: licencias, fuentes, comodines y avisos (deny.toml)
#   cargo-audit  vulnerabilidades de RustSec sobre el Cargo.lock COMPLETO,
#                dependencias de desarrollo incluidas (.cargo/audit.toml)
#   cargo-vet    que cada crate de terceros este AUDITADO por alguien de
#                confianza o figure como excepcion registrada (supply-chain/)
#
# POR QUE FALLA SI FALTA UNA HERRAMIENTA
#
# Hasta la FASE 0 del MP-15 este job salia con «OMITIDO» cuando no encontraba
# cargo-deny o cargo-audit, y ademas no estaba en make ci: solo lo llamaba el
# workflow de GitHub, que no arranca. El resultado fue que la auditoria de
# dependencias no se ejecuto nunca, y la primera vez que corrio encontro
# vulnerabilidades reales. Una puerta que se omite a si misma no es una puerta.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
cd "$RAIZ"

titulo "Job: supply-chain (dependencias de terceros)"

# Los espacios de trabajo: el agente (raiz), el plano de control, el transporte
# del enjambre y las herramientas del repositorio.
ESPACIOS=(. server swarm-net xtask)
FALLOS=0

for herramienta in cargo-deny cargo-audit cargo-vet; do
    if ! hay "$herramienta"; then
        paso "$herramienta"
        fallo "falta $herramienta: cargo install --locked $herramienta"
        FALLOS=$((FALLOS + 1))
    fi
done
[ "$FALLOS" -eq 0 ] || exit 1

for ws in "${ESPACIOS[@]}"; do
    correr "cargo deny ($ws)" \
        cargo deny --manifest-path "$ws/Cargo.toml" --config "$RAIZ/deny.toml" check \
        || FALLOS=$((FALLOS + 1))
done

for ws in "${ESPACIOS[@]}"; do
    correr "cargo audit ($ws)" \
        cargo audit --no-yanked --file "$ws/Cargo.lock" \
        || FALLOS=$((FALLOS + 1))
done

for ws in "${ESPACIOS[@]}"; do
    correr "cargo vet ($ws)" \
        bash -c "cd '$ws' && cargo vet --locked" \
        || FALLOS=$((FALLOS + 1))
done

# La excepcion de RUSTSEC-2023-0071 (rsa, «Marvin Attack») en deny.toml y en
# .cargo/audit.toml se sostiene SOLO mientras rsa se use para verificar con
# clave publica. Si alguien introduce una operacion con clave privada RSA en
# codigo que se distribuye, el ataque pasa a aplicar y la excepcion a mentir:
# esto lo impide. Las pruebas (`tests/`) quedan fuera: generan un par de claves
# para fabricar quotes TPM de ejemplo, y Marvin es un ataque por tiempos contra
# un servicio que descifra o firma, no contra un fixture.
paso "rsa solo con clave publica (sostiene la excepcion de RUSTSEC-2023-0071)"
privadas="$(grep -rnE 'RsaPrivateKey|pkcs1v15::(SigningKey|DecryptingKey)|pss::SigningKey|oaep::DecryptingKey|Pkcs1v15Encrypt' \
    --include='*.rs' crates server swarm-net 2>/dev/null \
    | grep -v -e '/target/' -e '/tests/' || true)"
if [ -z "$privadas" ]; then
    ok
else
    fallo "hay operaciones con clave privada RSA: la excepcion ya no vale"
    printf '%s\n' "$privadas" | sed 's/^/      | /'
    FALLOS=$((FALLOS + 1))
fi

[ "$FALLOS" -eq 0 ] && exit 0 || exit 1
