#!/usr/bin/env python3
"""Codigo nativo de terceros en los binarios instalables: la puerta.

POR QUE EXISTE
--------------
cargo-deny juzga cada crate por el campo `license` de su Cargo.toml. Un crate
que vendoriza codigo C declara ahi la licencia de sus enlaces de Rust, no la del
C que compila y enlaza estaticamente. libbpf-sys declara BSD-2-Clause y lleva
dentro libelf de elfutils (GPL-2.0-or-later OR LGPL-3.0-or-later) y zlib: con la
feature `hermetico` las dos acaban dentro del agente estatico y ninguna puerta
lo veia.

QUE HACE
--------
  comprobar   (tools/ci/supply_chain.sh, grupo `cadena` de make ci) todo crate
              de terceros del grafo de dependencias normales de los instalables
              (tools/config/instalables.toml) que compile o traiga codigo
              nativo tiene que estar en tools/config/codigo-nativo.toml con su
              version exacta y una licencia admisible (deny.toml) o una
              decision pendiente declarada. Las decisiones pendientes no hacen
              fallar, pero se imprimen siempre.

No elige licencias ni genera avisos de terceros: eso depende de decisiones del
propietario que estan abiertas. Sale con 0 si todo esta en regla y con 1 en
cualquier otro caso. Nunca omite: una puerta que no puede mirar no puede aprobar.
"""

import json
import os
import pathlib
import subprocess
import sys
import tomllib

RAIZ = pathlib.Path(__file__).resolve().parents[2]
LISTA = RAIZ / "tools" / "config" / "codigo-nativo.toml"
INSTALABLES = RAIZ / "tools" / "config" / "instalables.toml"
DENY = RAIZ / "deny.toml"

# Herramientas de construccion que, como dependencia de construccion, delatan
# que el script compila codigo nativo.
HERRAMIENTAS_C = {"cc", "cmake", "autotools", "nasm-rs"}
# Extensiones de fuente nativa u objeto precompilado.
EXTENSIONES_NATIVAS = {".c", ".cc", ".cpp", ".cxx", ".s", ".S", ".asm", ".a", ".o", ".obj", ".lib"}
# Directorios que no se compilan en el crate publicado.
DIRECTORIOS_AJENOS = {"tests", "test", "examples", "benches", "fuzz", "target", ".git"}


class Fallo(Exception):
    pass


def leer_toml(ruta):
    try:
        with open(ruta, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise Fallo(f"no se puede leer {ruta.relative_to(RAIZ)}: {e}")


def instalables_por_espacio():
    """{workspace: {paquete}} de tools/config/instalables.toml (la lista unica)."""
    datos = leer_toml(INSTALABLES)
    espacios = {}
    for i in datos.get("instalable", []):
        espacios.setdefault(i.get("workspace", "?"), set()).add(i["paquete"])
    if not espacios:
        raise Fallo("tools/config/instalables.toml no declara instalables")
    return espacios


def metadatos(manifiesto, objetivo):
    """`cargo metadata` de un workspace, con TODAS sus features, para un
    objetivo: da los datos de cada paquete (licencia, `links`, build.rs, fuentes)
    y las aristas para nombrar el camino. QUE se compila no lo decide este grafo
    sino `compilados`, que resuelve las features como el compilador."""
    orden = [
        "cargo", "metadata", "--format-version", "1", "--locked", "--all-features",
        "--filter-platform", objetivo, "--manifest-path", str(RAIZ / manifiesto),
    ]
    r = subprocess.run(orden, cwd=RAIZ, capture_output=True, text=True)
    if r.returncode != 0:
        raise Fallo(f"cargo metadata ({manifiesto}, {objetivo}) fallo:\n{r.stderr.strip()}")
    return json.loads(r.stdout)


def compilados(manifiesto, objetivo, raices):
    """Los paquetes que se COMPILAN de verdad para los instalables `raices`, por
    dependencias normales y con todas sus features, como {(nombre, version)}.

    `cargo metadata` no resuelve las features con precision: su grafo trae
    dependencias opcionales que solo activan features debiles (`dep?/feat`) que
    nadie pide. Asi aparecia libsqlite3-sys (via sqlx-sqlite) en el servidor, que
    no la compila. `cargo tree` resuelve las features como el compilador; con
    `--all-features` sigue cubriendo todo lo que PUEDE entrar."""
    orden = [
        "cargo", "tree", "-q", "--locked", "--all-features", "-e", "normal",
        "--target", objetivo, "--prefix", "none", "--format", "{p}",
        "--manifest-path", str(RAIZ / manifiesto),
    ]
    for r in sorted(raices):
        orden += ["-p", r]
    r = subprocess.run(orden, cwd=RAIZ, capture_output=True, text=True)
    if r.returncode != 0:
        raise Fallo(f"cargo tree ({manifiesto}, {objetivo}) fallo:\n{r.stderr.strip()}")
    vistos = set()
    for linea in r.stdout.splitlines():
        partes = linea.split()
        if len(partes) >= 2 and partes[1].startswith("v"):
            vistos.add((partes[0], partes[1][1:]))
    if not vistos:
        raise Fallo(f"cargo tree ({manifiesto}, {objetivo}) no devolvio ningun paquete")
    return vistos


def alcanzables(meta, raices, se_compilan):
    """Paquetes alcanzables desde los instalables por dependencias NORMALES (las
    de desarrollo no llegan al binario; las de construccion se ejecutan al
    compilar y no quedan dentro) y que de verdad se compilan (`se_compilan`, de
    `compilados`). Devuelve {id: id del que lo trae}."""
    nodos = {n["id"]: n for n in meta["resolve"]["nodes"]}
    paquetes = {p["id"]: p for p in meta["packages"]}
    miembros = set(meta["workspace_members"])
    inicio = [i for i in miembros if paquetes[i]["name"] in raices]
    faltan = raices - {paquetes[i]["name"] for i in inicio}
    if faltan:
        raise Fallo(f"instalables que no son miembros de su workspace: {sorted(faltan)}")
    padre = {i: None for i in inicio}
    pila = list(inicio)
    while pila:
        actual = pila.pop()
        for d in nodos[actual]["deps"]:
            normal = any(k.get("kind") is None for k in d.get("dep_kinds", []))
            hijo = paquetes[d["pkg"]]
            if (hijo["name"], hijo["version"]) not in se_compilan:
                continue
            if normal and d["pkg"] not in padre:
                padre[d["pkg"]] = actual
                pila.append(d["pkg"])
    return padre


def camino(padre, paquetes, pid):
    nombres = []
    while pid is not None:
        nombres.append(paquetes[pid]["name"])
        pid = padre[pid]
    return " <- ".join(nombres)


def fuentes_nativas(directorio):
    encontradas = []
    for raiz, dirs, ficheros in os.walk(directorio):
        dirs[:] = sorted(d for d in dirs if d not in DIRECTORIOS_AJENOS)
        for f in ficheros:
            if os.path.splitext(f)[1] in EXTENSIONES_NATIVAS:
                encontradas.append(os.path.relpath(os.path.join(raiz, f), directorio))
    return encontradas


def motivos_nativo(paquete):
    """Por que un paquete aporta codigo nativo: (motivos, solo_links)."""
    motivos = []
    if paquete.get("links"):
        motivos.append(f"links = \"{paquete['links']}\"")
    compila = False
    construye = any("custom-build" in t["kind"] for t in paquete["targets"])
    if construye:
        herramientas = sorted(
            {d["name"] for d in paquete["dependencies"] if d.get("kind") == "build"} & HERRAMIENTAS_C
        )
        if herramientas:
            motivos.append("su build.rs compila con " + ", ".join(herramientas))
            compila = True
        fuentes = fuentes_nativas(pathlib.Path(paquete["manifest_path"]).parent)
        if fuentes:
            motivos.append(f"{len(fuentes)} fuentes u objetos nativos (p. ej. {fuentes[0]})")
            compila = True
    return motivos, bool(motivos) and not compila


def normalizar(expresion):
    return " ".join(expresion.replace("/", " OR ").split())


def admisible(origen, permitidas):
    """Alguna alternativa (OR) con todas sus partes (AND) permitidas."""
    for alternativa in normalizar(origen).split(" OR "):
        partes = [p.strip().strip("()") for p in alternativa.split(" AND ")]
        if partes and all(p in permitidas for p in partes):
            return True
    return False


def comprobar():
    lista = leer_toml(LISTA)
    permitidas = set(leer_toml(DENY).get("licenses", {}).get("allow", []))
    if not permitidas:
        raise Fallo("deny.toml no declara [licenses] allow")
    declarados = {}
    for c in lista.get("crate", []):
        clave = f"{c['nombre']}@{c['version']}"
        if clave in declarados:
            raise Fallo(f"{clave} esta dos veces en la lista")
        declarados[clave] = c

    errores = []
    espacios_lista = lista.get("espacios", {})
    detectados = {}  # clave -> [paquete, motivos, solo_links, objetivos, camino]
    for espacio, raices in sorted(instalables_por_espacio().items()):
        conf = espacios_lista.get(espacio)
        if not conf or not conf.get("objetivos") or not conf.get("manifiesto"):
            errores.append(
                f"el workspace «{espacio}» tiene instalables y no esta en [espacios] de "
                "tools/config/codigo-nativo.toml (manifiesto y objetivos)"
            )
            continue
        for objetivo in conf["objetivos"]:
            meta = metadatos(conf["manifiesto"], objetivo)
            padre = alcanzables(meta, raices, compilados(conf["manifiesto"], objetivo, raices))
            paquetes = {p["id"]: p for p in meta["packages"]}
            for pid in padre:
                p = paquetes[pid]
                if p.get("source") is None:
                    continue  # codigo del repositorio
                motivos, solo_links = motivos_nativo(p)
                if not motivos:
                    continue
                clave = f"{p['name']}@{p['version']}"
                if clave not in detectados:
                    detectados[clave] = [p, motivos, solo_links, [], camino(padre, paquetes, pid)]
                detectados[clave][3].append(f"{espacio}/{objetivo}")
    for espacio in sorted(set(espacios_lista) - set(instalables_por_espacio())):
        errores.append(f"[espacios.{espacio}] no tiene instalables: entrada caducada, se borra")

    pendientes = []
    for clave, (p, motivos, solo_links, objetivos, via) in sorted(detectados.items()):
        if clave not in declarados:
            errores.append(
                f"{clave} aporta codigo nativo y no esta revisado en tools/config/codigo-nativo.toml\n"
                f"      motivo: {'; '.join(motivos)}\n"
                f"      llega por: {via}  ({', '.join(objetivos)})"
            )
            continue
        c = declarados[clave]
        if normalizar(c.get("licencia_cargo", "")) != normalizar(p.get("license") or ""):
            errores.append(
                f"{clave}: licencia_cargo dice «{c.get('licencia_cargo')}» y su Cargo.toml «{p.get('license')}»"
            )
        componentes = c.get("componente", [])
        if c.get("sin_codigo_nativo"):
            if not solo_links:
                errores.append(
                    f"{clave} dice sin_codigo_nativo y esta version compila o trae codigo nativo "
                    f"({'; '.join(motivos)}): se revisa otra vez"
                )
            if componentes:
                errores.append(f"{clave}: sin_codigo_nativo y componentes a la vez")
            continue
        if not componentes:
            errores.append(f"{clave}: sin componentes; cada parte nativa se declara con su licencia")
        dir_crate = pathlib.Path(p["manifest_path"]).parent
        for comp in componentes:
            donde = f"{clave} / {comp.get('nombre', '?')}"
            origen = comp.get("origen", "")
            if not origen:
                errores.append(f"{donde}: sin `origen` (la licencia SPDX del autor)")
            pendiente = (comp.get("decision_pendiente") or "").strip()
            if admisible(origen, permitidas):
                if pendiente:
                    errores.append(
                        f"{donde}: declara decision_pendiente pero «{origen}» ya es admisible "
                        "(deny.toml): se quita"
                    )
            elif pendiente:
                pendientes.append(f"{donde} ({origen}): {' '.join(pendiente.split())}")
            else:
                errores.append(
                    f"{donde}: ninguna alternativa de «{origen}» es admisible (deny.toml [licenses] allow) "
                    "y no hay decision_pendiente declarada"
                )
            for f in comp.get("ficheros_licencia", []):
                if not (dir_crate / f).is_file():
                    errores.append(f"{donde}: no existe el fichero de licencia {f}")
    for clave in sorted(set(declarados) - set(detectados)):
        errores.append(
            f"{clave} esta en la lista y ya no aporta codigo nativo a ningun instalable: "
            "entrada caducada, se borra (o se corrige su version)"
        )

    for x in pendientes:
        print(f"DECISION PENDIENTE: {x}")
    if errores:
        print("Codigo nativo sin revisar o mal declarado:\n")
        for e in errores:
            print(f"  - {e}")
        print("\nCada entrada de tools/config/codigo-nativo.toml es una revision: se lee el crate en esa")
        print("version y se anota que C trae y bajo que licencia esta cada parte.")
        return 1
    print(f"{len(detectados)} crates con codigo nativo, todos revisados "
          f"({len(pendientes)} decision(es) de licencia pendiente(s)): " + ", ".join(sorted(detectados)))
    return 0


def main(argv):
    try:
        if len(argv) == 2 and argv[1] == "comprobar":
            return comprobar()
    except Fallo as e:
        print(f"FALLO: {e}")
        return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
