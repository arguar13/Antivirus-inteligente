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
#   codigo_nativo.py  que el C, C++ y ensamblador que los crates compilan y
#                enlazan en los instalables este REVISADO, con la licencia de
#                cada parte (tools/config/codigo-nativo.toml). cargo-deny ve la
#                licencia del crate, no la del C que vendoriza.
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
if ! hay python3; then
    paso "python3"
    fallo "falta python3: lo usa la revision del codigo nativo"
    FALLOS=$((FALLOS + 1))
fi
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

# El codigo nativo que cargo-deny no ve: el C, C++ y ensamblador que compilan
# los crates con script de construccion y que acaba enlazado en los
# instalables. Cada crate que lo aporta tiene que estar revisado en su version
# exacta, con la licencia de cada parte (tools/config/codigo-nativo.toml). Asi
# entro libelf de elfutils (GPL-2.0-or-later OR LGPL-3.0-or-later) en el agente
# estatico sin que ninguna puerta lo viera: libbpf-sys declara BSD-2-Clause.
# Las decisiones de licencia pendientes no fallan, pero se imprimen siempre.
paso "codigo nativo revisado (tools/config/codigo-nativo.toml)"
log="$(mktemp)"
if python3 "$RAIZ/tools/ci/codigo_nativo.py" comprobar > "$log" 2>&1; then
    ok "$(tail -1 "$log")"
    grep '^DECISION PENDIENTE' "$log" | sed 's/^/      | /'
else
    fallo; tail -40 "$log" | sed 's/^/      | /'; FALLOS=$((FALLOS + 1))
fi
rm -f "$log"

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

# wasmtime solo como oraculo de PRUEBAS, sin modelo de componentes. Sostiene las
# excepciones de wasmtime de .cargo/audit.toml: todas suponen que wasmtime no
# llega a nada que se distribuye (solo lo arrastra yara-x, dependencia de prueba
# de aegis-patron) y RUSTSEC-2026-0327 supone ademas que `component-model` no se
# compila. Si cualquiera deja de ser cierto, las excepciones mienten: esto falla.
paso "wasmtime solo en pruebas y sin modelo de componentes (sostiene sus excepciones)"
distribuido="$(cargo tree -q --workspace -e no-dev --target all -i wasmtime 2>&1 || true)"
componentes="$(cargo tree -q --workspace --target all -e features -i wasmtime 2>/dev/null \
    | grep -o 'wasmtime feature "component-model[a-z-]*"' | sort -u || true)"
if [ -z "$distribuido" ] && [ -z "$componentes" ]; then
    ok
else
    fallo "wasmtime llega a lo que se distribuye o compila el modelo de componentes: sus excepciones ya no valen"
    printf '%s\n%s\n' "$distribuido" "$componentes" | sed '/^$/d; s/^/      | /'
    FALLOS=$((FALLOS + 1))
fi

[ "$FALLOS" -eq 0 ] && exit 0 || exit 1
