#!/usr/bin/env python3
"""Cuenta las omisiones de una tanda y las contrasta con tools/config/omisiones.toml.

POR QUE (hallazgos H-10 y H-20)

Las pruebas que no pueden ejercerse —les falta PostgreSQL, root, un kernel con
BTF, una herramienta externa o un conjunto de datos— se omitian con un aviso por
stderr que `cargo test` se tragaba en las pruebas que pasan: la tanda daba verde
sin haberlas ejecutado y sin decirlo. Ahora cada omision pasa por
`aegis_prueba::omitir` (crates/aegis-prueba, compartido por el workspace del
agente y el del plano de control), que la anota en el fichero de
AEGIS_OMISIONES: una linea por omision, cinco campos separados por
tabuladores (requisito, fichero, linea, prueba, motivo). Un verificador de
tools/ que omite a nivel de script anota con el mismo formato. Este script es
el que las cuenta y las dice.

Uso:  tools/ci/omisiones.py FICHERO [--exigir-declaradas]

Salida 0: ninguna omision, o todas declaradas, o hay sin declarar pero no se
          paso --exigir-declaradas (solo se informa).
Salida 1: una omision sin declarar con --exigir-declaradas; o el fichero de
          omisiones esta mal formado; o la configuracion miente (un fichero
          que no existe, una entrada sin motivo o sin fase, un requisito
          desconocido, o uno de una clase que make ci EXIGE: esas no se
          declaran, se arreglan).
"""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python < 3.11
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        print("FALLO: hace falta tomllib (Python 3.11+) o tomli para leer tools/config/omisiones.toml")
        sys.exit(1)

RAIZ = Path(__file__).resolve().parents[2]
CONFIG = RAIZ / "tools" / "config" / "omisiones.toml"

# Clave del requisito -> clase. Las mismas que `aegis_prueba::Requisito`
# (crates/aegis-prueba/src/lib.rs); si se anade una variante alli, se anade aqui.
CLASES = {
    "postgresql": "servicios",
    "redis": "servicios",
    "kafka": "red",
    "attack": "datos",
    "medida": "medidas",
    "optimizado": "medidas",
    "root": "privilegios",
    "ptrace": "privilegios",
    "ebpf": "kernel",
    "btf": "kernel",
    "kfuncs-tareas": "version-kernel",
    "landlock": "kernel",
    "seccomp": "kernel",
    "sonda": "kernel",
    "acpi": "hardware",
    "pci": "hardware",
    "drx": "hardware",
    "herramienta": "herramientas",
    "entorno": "entorno",
}

# Clases que make ci EXIGE (AEGIS_EXIGIR en tools/ci-local.sh): una prueba a la
# que le falten falla antes de anotarse, asi que declararlas seria mentir.
EXIGIDAS_EN_CI = {"servicios", "privilegios", "kernel"}


def normal(ruta: str) -> str:
    """Ruta con barras normales y sin `./` delante."""
    ruta = ruta.replace("\\", "/")
    while ruta.startswith("./"):
        ruta = ruta[2:]
    return ruta


def misma_ruta(declarada: str, anotada: str) -> bool:
    """El compilador da la ruta relativa a la raiz del workspace (`crates/...`),
    la configuracion la da desde la raiz del repositorio (`server/crates/...`
    en el plano de control, `crates/...` en el agente): casan si son iguales o
    si una termina en la otra por un limite de directorio."""
    d, a = normal(declarada), normal(anotada)
    return d == a or d.endswith("/" + a) or a.endswith("/" + d)


def claves_del_crate() -> set[str] | None:
    """Las claves que declara `Requisito::clave` en crates/aegis-prueba: las de
    aqui tienen que ser las mismas, o una omision valida se leeria como mala."""
    lib = RAIZ / "crates" / "aegis-prueba" / "src" / "lib.rs"
    if not lib.is_file():
        return None
    texto = lib.read_text(encoding="utf-8")
    ini = texto.find("pub fn clave(self)")
    fin = texto.find("pub fn detalle(self)", ini)
    if ini < 0 or fin < 0:
        return None
    # Una clave puede llevar cifras y guiones («kfuncs-tareas»): un patron solo
    # de letras la perdia y la tanda la daba por desconocida.
    return set(re.findall(r'=> "([a-z][a-z0-9-]*)",', texto[ini:fin]))


def leer_config() -> tuple[list[dict], list[str]]:
    """Las omisiones declaradas y los problemas de la propia configuracion."""
    problemas: list[str] = []
    claves = claves_del_crate()
    if claves is None:
        problemas.append("no se pudieron leer las claves de crates/aegis-prueba/src/lib.rs")
    elif claves != set(CLASES):
        problemas.append(
            "CLASES de tools/ci/omisiones.py y Requisito::clave de aegis-prueba no coinciden: "
            f"solo en el crate {sorted(claves - set(CLASES))}, solo aqui {sorted(set(CLASES) - claves)}"
        )
    if not CONFIG.exists():
        return [], [f"no existe {CONFIG.relative_to(RAIZ)}"]
    with CONFIG.open("rb") as f:
        doc = tomllib.load(f)
    declaradas = doc.get("omision", [])
    for i, d in enumerate(declaradas, 1):
        donde = f"omisiones.toml, entrada {i}"
        req = d.get("requisito", "")
        if req not in CLASES:
            problemas.append(f"{donde}: requisito desconocido {req!r} (validos: {', '.join(CLASES)})")
        elif CLASES[req] in EXIGIDAS_EN_CI:
            problemas.append(
                f"{donde}: {req} es de la clase {CLASES[req]}, que make ci EXIGE; no se declara, "
                "se arregla (servicios: tools/ci/servicios.sh --arrancar; privilegios y kernel: "
                "la tanda corre como root sobre un kernel con BTF, Landlock y seccomp)"
            )
        fichero = d.get("fichero", "")
        if not fichero or not (RAIZ / normal(fichero)).is_file():
            problemas.append(f"{donde}: el fichero {fichero!r} no existe desde la raiz del repositorio")
        for campo in ("motivo", "fase"):
            if not str(d.get(campo, "")).strip():
                problemas.append(f"{donde}: sin {campo} (toda omision declarada dice por que y que fase la cierra)")
    return declaradas, problemas


def leer_omisiones(ruta: Path) -> tuple[list[tuple[str, ...]], list[str]]:
    """Las omisiones anotadas y las lineas mal formadas."""
    filas: list[tuple[str, ...]] = []
    malas: list[str] = []
    if not ruta.exists():
        return filas, malas
    texto = ruta.read_text(encoding="utf-8", errors="replace")
    for n, linea in enumerate(texto.splitlines(), 1):
        if not linea.strip():
            continue
        campos = linea.split("\t")
        if len(campos) != 5:
            malas.append(f"{ruta}:{n}: {len(campos)} campos, se esperan 5: {linea[:160]!r}")
            continue
        if campos[0] not in CLASES:
            malas.append(f"{ruta}:{n}: requisito desconocido {campos[0]!r}: {linea[:160]!r}")
            continue
        filas.append(tuple(campos))
    return filas, malas


def declarada(declaradas: list[dict], fila: tuple[str, ...]) -> dict | None:
    requisito, fichero, _linea, prueba, _motivo = fila
    for d in declaradas:
        if d.get("requisito") != requisito:
            continue
        if not misma_ruta(d.get("fichero", ""), fichero):
            continue
        p = d.get("prueba")
        if p and not (prueba == p or prueba.endswith("::" + p)):
            continue
        return d
    return None


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    estricto = "--exigir-declaradas" in sys.argv[1:]
    if len(args) != 1:
        print(__doc__)
        return 1
    ruta = Path(args[0])

    declaradas, problemas = leer_config()
    filas, malas = leer_omisiones(ruta)
    problemas.extend(malas)

    sin_declarar = 0
    if not filas:
        print("omisiones: ninguna; toda prueba que depende de un servicio, de unos datos,")
        print("de un privilegio, del kernel, del hardware o de una herramienta se ejecuto")
    else:
        cuenta = Counter((r, normal(f), p, m) for r, f, _l, p, m in filas)
        print(f"omisiones: {len(filas)} en esta tanda ({len(cuenta)} distintas)")
        for (req, fichero, prueba, motivo), n in sorted(cuenta.items()):
            d = declarada(declaradas, (req, fichero, "", prueba, motivo))
            veces = f" x{n}" if n > 1 else ""
            clase = CLASES.get(req, "?")
            if d is None:
                sin_declarar += 1
                print(f"  NO DECLARADA  [{req}/{clase}] {fichero} :: {prueba}{veces}")
                print(f"                motivo: {motivo}")
            else:
                print(f"  declarada     [{req}/{clase}] {fichero} :: {prueba}{veces}")
                print(f"                la cierra: {d.get('fase', '').strip()}")

    for p in problemas:
        print(f"  CONFIGURACION: {p}")

    if sin_declarar:
        print()
        print(f"{sin_declarar} omision(es) sin declarar en tools/config/omisiones.toml.")
        print("Un verde con pruebas que no se ejecutaron tiene que decir cuales y por que:")
        print("o se arregla lo que falta, o se declara con su motivo y la fase que la cierra.")
        if not estricto:
            print("(grupo suelto: solo se informa; en la tanda completa de make ci esto falla)")

    if problemas:
        return 1
    if sin_declarar and estricto:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
