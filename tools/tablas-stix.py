#!/usr/bin/env python3
"""Genera las dos tablas de relaciones de la FASE 98 desde sus fuentes, fijadas.

  relaciones-stix21.tsv   las relaciones que define STIX 2.1, del validador
                          oficial de OASIS (cti-stix-validator, v21/enums.py)
  relaciones-opencti.tsv  las que OpenCTI admite (stixCoreRelationshipsMapping de
                          opencti-graphql/src/database/stix.ts), con cada constante
                          RESUELTA leyendo el fichero que la define, no adivinada
                          por su nombre

Uso: tools/tablas-stix.py <dir-de-fuentes> <dir-de-salida>
El directorio de fuentes lo llena tools/verificar-conocimiento.sh (enums.py,
stix.ts, validator.sha, opencti.sha y los ficheros de constantes de OpenCTI).
"""
import ast, json, os, re, sys, urllib.request

fuentes, salida = sys.argv[1], sys.argv[2]
val_sha = open(f"{fuentes}/validator.sha").read().strip()
oc_sha = open(f"{fuentes}/opencti.sha").read().strip()

# --- STIX 2.1: el validador es Python; se leen sus literales con ast, sin ejecutarlo.
arbol = ast.parse(open(f"{fuentes}/enums.py").read())
lits = {}
for n in arbol.body:
    if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
        try:
            lits[n.targets[0].id] = ast.literal_eval(n.value)
        except ValueError:
            pass
validador = set()
for origen, rels in lits["RELATIONSHIPS"].items():
    for rel, destinos in rels.items():
        for d in ([destinos] if isinstance(destinos, str) else destinos):
            validador.add((origen, rel, d))

# --- El Apendice B del texto normativo (pdftotext -layout del PDF oficial).
espec_txt = open(f"{fuentes}/espec.txt").read()
inicio = espec_txt.rindex("Appendix B. Relationship Summary Table")
fin = espec_txt.index("Appendix C. Additional Examples", inicio)
apendice = []  # [origen, [tipos], [destinos]]
for linea in espec_txt[inicio:fin].splitlines():
    if not linea.strip() or linea.startswith(("stix-v2.1-os", "Standards Track")) or "Source" in linea:
        continue
    sangria = len(linea) - len(linea.lstrip())
    trozos = re.split(r"\s{2,}", linea.strip())
    if sangria <= 2 and len(trozos) >= 3 and re.fullmatch(r"[a-z-]+", trozos[0]):
        apendice.append([trozos[0], [trozos[1]], [" ".join(trozos[2:])]])
    elif apendice and sangria < 40:
        apendice[-1][1].append(linea.strip())
    elif apendice:
        apendice[-1][2].append(linea.strip())
SCO = sorted(lits["OBSERVABLE_TYPES"])
def lista(partes):
    texto = ""
    for p in partes:
        texto += p if texto.endswith("-") else (" " + p if texto else p)
    return [x.strip() for x in texto.split(",") if x.strip()]
espec = set()
for origen, tipos, destinos in apendice:
    for t in lista(tipos):
        # Errata del Apendice B: la seccion 4.11 (Malware), que la propia
        # especificacion declara autoritativa, escribe exfiltrates-to.
        t = "exfiltrates-to" if t == "exfiltrate-to" else t
        for d in lista(destinos):
            if d.startswith("<All STIX"):
                espec.update((origen, t, s) for s in SCO)
            elif d.startswith("Cyber-observable"):
                continue
            else:
                espec.add((origen, t, d))

# Procedencia de cada fila: el Apendice B; o el validador si el nombre de la
# relacion aparece en las secciones de cada objeto (que mandan sobre el
# Apendice); o SOLO el validador, que se registra y queda fuera del canon.
filas = {}
for f in espec:
    filas[f] = "espec" if f in validador else "espec-apendice"
for f in validador - espec:
    en_texto = re.search(rf"\b{re.escape(f[1])}\b", espec_txt[:inicio]) is not None
    filas[f] = "espec-seccion" if en_texto else "solo-validador"
with open(f"{salida}/relaciones-stix21.tsv", "w") as f:
    f.write(f"# STIX 2.1: relaciones definidas por tipo de objeto.\n")
    f.write("# Fuentes: el Apendice B de https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.pdf\n")
    f.write(f"#   y https://github.com/oasis-open/cti-stix-validator/blob/{val_sha}/stix2validator/v21/enums.py (RELATIONSHIPS)\n")
    f.write("# Columnas: origen, relacion, destino, procedencia:\n")
    f.write("#   espec          en el Apendice B y en el validador\n")
    f.write("#   espec-apendice solo en el Apendice B\n")
    f.write("#   espec-seccion  solo en el validador, pero su nombre esta en las secciones de cada objeto\n")
    f.write("#   solo-validador ni en el Apendice ni en el texto: resto de borradores, FUERA del canon\n")
    f.write(f"# Comunes a todo objeto: {','.join(lits['COMMON_RELATIONSHIPS'])}\n")
    f.write(f"# SDO: {','.join(sorted(lits['TYPES']))}\n")
    f.write(f"# SCO: {','.join(sorted(lits['OBSERVABLE_TYPES']))}\n")
    for (o, r, d), p in sorted(filas.items()):
        f.write(f"{o}\t{r}\t{d}\t{p}\n")
from collections import Counter
print(f"stix21: {len(filas)} relaciones {dict(Counter(filas.values()))}")

# --- OpenCTI. Sus relaciones se declaran en DOS sitios: el mapeo central de
# database/stix.ts (stixCoreRelationshipsMapping) y la definicion de cada modulo
# (registerDefinition con `relations: [{ name, targets: [...] }]`, p. ej.
# Malware-Analysis). Se leen los dos, y cada constante se RESUELVE leyendo el
# fichero que la define, fijado al mismo commit.
RAIZ = "opencti-platform/opencti-graphql/src"


def bajar(rel):
    """Descarga (una vez) un fichero del repositorio de OpenCTI y lo devuelve."""
    local = f"{fuentes}/opencti/{rel}"
    if not os.path.exists(local):
        os.makedirs(os.path.dirname(local), exist_ok=True)
        try:
            urllib.request.urlretrieve(
                f"https://raw.githubusercontent.com/OpenCTI-Platform/opencti/{oc_sha}/{rel}", local)
        except Exception:
            open(local, "w").close()
    return open(local).read()


def importado(ruta_fichero, ruta_import):
    base = os.path.dirname(ruta_fichero)
    rel = os.path.normpath(os.path.join(base, ruta_import)).replace("\\", "/")
    for sufijo in (".ts", ".js", "/index.ts", "/index.js"):
        texto = bajar(rel + sufijo)
        if texto:
            return texto
    return ""


def constantes_de(ruta, texto):
    """Las constantes de texto que un fichero define o importa."""
    c = dict(re.findall(r"export const (\w+)\s*=\s*'([^']+)'", texto))
    c.update(re.findall(r"^const (\w+)\s*=\s*'([^']+)'", texto, re.M))
    for bloque, origen in re.findall(r"import \{([^}]*)\} from '([^']+)'", texto):
        if not origen.startswith("."):
            continue
        nombres = [x.strip().split(" as ")[0].replace("type ", "") for x in bloque.split(",") if x.strip()]
        otro = importado(ruta, origen)
        for n in nombres:
            m = re.search(rf"export const {n}\s*=\s*'([^']+)'", otro)
            if m:
                c[n] = m.group(1)
    c.update({"REL_BUILT_IN": "builtin", "REL_NEW": "new", "REL_EXTENDED": "extended"})
    return c


opencti, sin_resolver = set(), set()

# 1. El mapeo central.
ruta_stix = f"{RAIZ}/database/stix.ts"
ts = open(f"{fuentes}/stix.ts").read()
constantes = constantes_de(ruta_stix, ts)
inicio = ts.index("export const stixCoreRelationshipsMapping")
cuerpo = ts[inicio:ts.index("\n};", inicio)]
for a, b, lista in re.findall(r"\[`\$\{(\w+)\}_\$\{(\w+)\}`\]:\s*\[(.*?)\]", cuerpo, re.S):
    for rel, tipo in re.findall(r"name:\s*(\w+),\s*type:\s*(\w+)", lista):
        partes = [constantes.get(x) for x in (a, b, rel, tipo)]
        if None in partes:
            sin_resolver.update(x for x in (a, b, rel, tipo) if x not in constantes)
            continue
        opencti.add((partes[0], partes[1], partes[2], partes[3], "stix.ts"))

# 2. Las definiciones de modulo.
arbol = json.load(open(f"{fuentes}/arbol.json"))
modulos = sorted(x["path"] for x in arbol["tree"]
                 if x["type"] == "blob" and x["path"].startswith(f"{RAIZ}/modules/") and x["path"].endswith(".ts"))
con_relaciones = 0
for ruta in modulos:
    texto = bajar(ruta)
    if "registerDefinition" not in texto or "relations: [" not in texto:
        continue
    con_relaciones += 1
    c = constantes_de(ruta, texto)
    m = re.search(r"type:\s*\{[^}]*?name:\s*(\w+)", texto, re.S)
    origen = c.get(m.group(1)) if m else None
    if origen is None:
        sin_resolver.add(f"{ruta}: tipo {m.group(1) if m else '?'}")
        continue
    i = texto.index("relations: [")
    # El bloque `relations: [...]`, con sus corchetes casados.
    prof, j = 0, i + len("relations: ")
    while j < len(texto):
        prof += {"[": 1, "]": -1}.get(texto[j], 0)
        j += 1
        if prof == 0:
            break
    bloque = texto[i:j]
    for rel, destinos in re.findall(r"name:\s*(\w+),\s*targets:\s*\[(.*?)\]", bloque, re.S):
        for d, t in re.findall(r"name:\s*(\w+),\s*type:\s*(\w+)", destinos):
            partes = [c.get(x) for x in (rel, d, t)]
            if None in partes:
                sin_resolver.update(f"{ruta}: {x}" for x in (rel, d, t) if x not in c)
                continue
            opencti.add((origen, partes[1], partes[0], partes[2], ruta.split("/modules/")[1]))

with open(f"{salida}/relaciones-opencti.tsv", "w") as f:
    f.write("# OpenCTI: relaciones que admite entre tipos de entidad.\n")
    f.write(f"# Fuentes: https://github.com/OpenCTI-Platform/opencti/tree/{oc_sha}/{RAIZ}\n")
    f.write("#   database/stix.ts (stixCoreRelationshipsMapping) y cada modulo con registerDefinition(relations)\n")
    f.write("# Columnas: origen, relacion, destino, clase (builtin | new | extended), donde se declara\n")
    for o, d, r, t, donde in sorted(set(opencti)):
        f.write(f"{o}\t{r}\t{d}\t{t}\t{donde}\n")
print(f"opencti: {len(opencti)} relaciones ({con_relaciones} modulos con relaciones propias); "
      f"sin resolver: {sorted(sin_resolver)}")
if sin_resolver:
    sys.exit(1)
