#!/usr/bin/env bash
#
# Runbooks y despliegue: cada orden de NUESTROS binarios que se cita existe en
# el binario (FASE 7 del MP-16).
#
# LA CAUSA RAIZ que cierra: el rol de Ansible lanzaba `aegis-agent --config`, y
# llamaba a `aegis-agent enrolar`, `--comprobar-config` y `estado --json`; el
# agente rechaza las cuatro (H-30, H-40). Nadie lo vio porque ningun paso de CI
# contrastaba lo que un texto ordena con lo que el binario acepta. Un runbook
# con una opcion que no existe falla a las tres de la madrugada, que es cuando
# se lee.
#
# Que hace:
#   1. construye aegis-agent, aegisctl y aegis-watchdog en depuracion y guarda
#      su `--help`. Reutiliza lo que dejo el grupo `rust` donde las features
#      coinciden; donde no (cargo resuelve las features solo para estos tres
#      paquetes), recompila esa parte: minutos la primera vez, nada despues;
#   2. busca cada invocacion de esos binarios en docs/operacion/*.md (bloques
#      de codigo y codigo en linea) y en deploy/ (salvo deploy/windows/, que no
#      es producto): una invocacion es el binario, por nombre o por ruta
#      (`/x/aegis-agent`), EN POSICION DE ORDEN (inicio de la linea, tras
#      `sudo`, `env`, `|`, `&&`, `if`, `cmd:`, `ExecStart=`...). Un binario que
#      es el argumento de otra orden (`install -m 0755 dist/aegis-agent ...`,
#      `--program /x/aegis-agent`) no es una invocacion suya;
#   3. cada `--opcion` citada tiene que salir en el `--help` de su binario; las
#      que se pasan al agente por `aegis-watchdog --arg` se miran en el del
#      agente; el primer argumento suelto de `aegisctl` tiene que ser uno de
#      sus COMANDOS;
#   4. existen los runbooks obligatorios y el indice los enlaza;
#   5. los umbrales que gobiernan el paso a imponer (runbook del anillo) son
#      los del codigo de la FASE 4.5 (aegis-contenido), si ese crate existe;
#   6. la puerta muerde: un texto con `aegis-agent --config` y `aegisctl
#      enrolar` tiene que fallar, y uno correcto pasar.
set -uo pipefail
cd "$(dirname "$0")/.."
VERDE=$'\033[32m'; GRIS=$'\033[90m'; ROJO=$'\033[31m'; FIN=$'\033[0m'
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

echo "==> Runbooks: los tres binarios y su --help"
if ! cargo build --locked -q -p aegis-agent -p aegis-ctl -p aegis-watchdog --bins > "$TMP/build.log" 2>&1; then
    echo "    ${ROJO}FALLO${FIN}: no se pudieron construir los binarios"
    sed 's/^/    | /' "$TMP/build.log" | tail -30
    exit 1
fi
OBJETIVO="$(cargo metadata --format-version 1 --no-deps \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
for b in aegis-agent aegisctl aegis-watchdog; do
    if ! "$OBJETIVO/debug/$b" --help > "$TMP/$b.ayuda" 2>&1; then
        echo "    ${ROJO}FALLO${FIN}: $b --help no sale con 0"
        sed 's/^/    | /' "$TMP/$b.ayuda"
        exit 1
    fi
done
echo "    ${VERDE}OK${FIN} (ayudas de aegis-agent, aegisctl y aegis-watchdog)"

python3 - "$TMP" <<'PY'
import pathlib, re, shlex, sys

TMP = pathlib.Path(sys.argv[1])
VERDE, ROJO, GRIS, FIN = "\033[32m", "\033[31m", "\033[90m", "\033[0m"
BINARIOS = ("aegis-agent", "aegisctl", "aegis-watchdog")
OBLIGATORIOS = [
    "instalar.md", "actualizar.md", "revertir.md", "desinstalar.md",
    "diagnostico.md", "anillo-a-imponer.md", "incidentes-agente.md",
]
fallos = []


def opciones_de(ayuda):
    return set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", ayuda)) | {"-h", "--help"}


def verbos_de(ayuda):
    verbos, dentro = set(), False
    for l in ayuda.splitlines():
        if l.strip().startswith("COMANDOS"):
            dentro = True
            continue
        if dentro:
            if not l.strip():
                break
            p = l.split()[0]
            if not p.endswith(":") and re.fullmatch(r"[a-z][a-z-]*", p):
                verbos.add(p)
    return verbos


AYUDA = {b: (TMP / f"{b}.ayuda").read_text(errors="replace") for b in BINARIOS}
OPC = {b: opciones_de(t) for b, t in AYUDA.items()}
# Las opciones que llevan valor: en la ayuda van seguidas de un nombre en
# mayusculas (`--latido RUTA`, `--arg A`, `--max-age-ms N`).
CON_VALOR = {b: set(re.findall(r"(--[a-z][a-z0-9-]*)\s+\[?[A-Z]+\b", t)) for b, t in AYUDA.items()}
VERBOS = verbos_de(AYUDA["aegisctl"])
if not VERBOS:
    print(f"    {ROJO}FALLO{FIN}: no se leyeron los COMANDOS de `aegisctl --help`")
    sys.exit(1)

SEPARADORES = {"|", "||", "&&", ";", ")", "&", "then", "do"}
PREVIOS_DE_ORDEN = {"sudo", "exec", "env", "nohup", "time", "cmd:", "-", "$(", "(", "!",
                    "|", "||", "&&", ";", "then", "do", "else", "if", "elif", "while",
                    "until", "command:", "shell:"}


def nombre_de(tok):
    """El binario que nombra un token (por nombre o por ruta), o None."""
    t = tok.strip("\"'`(){}[],")
    t = t.split("=", 1)[1] if t.startswith(("ExecStart=", "ExecStartPre=", "ExecStop=")) else t
    base = t.rsplit("/", 1)[-1]
    return base if base in BINARIOS else None


def trozos(linea):
    # Una expresion de Jinja (Ansible) es un valor, nunca una orden.
    linea = re.sub(r"\{\{.*?\}\}", "JINJA", linea)
    try:
        return shlex.split(linea, comments=False, posix=True)
    except ValueError:
        return linea.split()


def revisar(linea, donde, cuenta):
    toks = trozos(linea)
    # Una orden entre comillas (`cmd: "/x/aegis-agent estado --json"`,
    # `validate: "..."`) es un solo token: se mira por dentro.
    for t in toks:
        if " " in t and any(b in t for b in BINARIOS):
            revisar(t, donde, cuenta)
    toks = [t for t in toks if " " not in t]
    i = 0
    while i < len(toks):
        b = nombre_de(toks[i])
        previo = toks[i - 1] if i > 0 else None
        en_orden = previo is None or previo in PREVIOS_DE_ORDEN or re.fullmatch(r"[A-Z_]+=.*", previo or "")
        if not b or not en_orden:
            i += 1
            continue
        args = []
        for t in toks[i + 1:]:
            if t in SEPARADORES or t.startswith((">", "<", "2>", "1>", "]", ";", "}", "|", "&")):
                break
            if t.endswith(";"):
                args.append(t[:-1])
                break
            args.append(t)
        cuenta[0] += 1
        comprobar(b, args, donde)
        # Lo que ya es argumento de esta orden no es otra orden: en
        # `aegis-watchdog --program /x/aegis-agent --arg --latido` el agente es
        # el VALOR de --program, y sus opciones van por --arg.
        i += 1 + len(args)


def comprobar(b, args, donde):
    j = 0
    verbo_visto = False
    while j < len(args):
        a = args[j]
        if a.startswith("--") and len(a) > 2:
            nombre = a.split("=", 1)[0]
            if nombre not in OPC[b]:
                fallos.append(f"{donde}: `{b} {nombre}`: {b} no tiene esa opcion")
                # Su valor, si lo lleva, no es otro error.
                if "=" not in a and j + 1 < len(args) and not args[j + 1].startswith("-"):
                    j += 2
                    continue
            if b == "aegis-watchdog" and nombre == "--arg" and j + 1 < len(args):
                hijo = args[j + 1]
                if hijo.startswith("--") and hijo.split("=", 1)[0] not in OPC["aegis-agent"]:
                    fallos.append(f"{donde}: `aegis-watchdog --arg {hijo}`: aegis-agent no tiene esa opcion")
                j += 2
                continue
            if b == "aegisctl" and nombre == "--socket":
                j += 2
                continue
            if nombre in CON_VALOR[b] and "=" not in a:
                j += 2
                continue
        elif b == "aegisctl" and not verbo_visto and not a.startswith("-") and not a.startswith("$") and not a.startswith("<"):
            verbo_visto = True
            if a not in VERBOS:
                fallos.append(f"{donde}: `aegisctl {a}`: no es un comando de aegisctl ({', '.join(sorted(VERBOS))})")
        elif b != "aegisctl" and not a.startswith("-"):
            # El agente y el watchdog no tienen subordenes: un argumento suelto
            # que no es el valor de una opcion es una orden que no existe
            # (`aegis-agent enrolar`, `aegis-agent estado --json`).
            fallos.append(f"{donde}: `{b} {a}`: {b} no admite argumentos sueltos (no tiene subordenes)")
        j += 1


def lineas_de_codigo_md(texto):
    """(numero, linea) de los bloques de codigo y del codigo en linea."""
    dentro = False
    previa = ""
    for n, l in enumerate(texto.splitlines(), 1):
        if l.lstrip().startswith("```"):
            dentro = not dentro
            previa = ""
            continue
        if dentro:
            s = l.strip()
            if s.startswith("#"):
                continue
            s = re.sub(r"^\$ ", "", s)
            if previa:
                s = previa + " " + s
            if s.endswith("\\"):
                previa = s[:-1]
                continue
            previa = ""
            yield n, s
        else:
            for m in re.finditer(r"`([^`]+)`", l):
                yield n, m.group(1)


def lineas_de_fichero(texto):
    previa = ""
    for n, l in enumerate(texto.splitlines(), 1):
        s = l.strip()
        if s.startswith("#") and not s.startswith("#!"):
            continue
        if previa:
            s = previa + " " + s
        if s.endswith("\\"):
            previa = s[:-1]
            continue
        previa = ""
        yield n, s


def recorrer(rutas, md):
    cuenta = [0]
    for f in rutas:
        try:
            t = f.read_text(errors="replace")
        except OSError:
            continue
        gen = lineas_de_codigo_md(t) if md else lineas_de_fichero(t)
        for n, l in gen:
            revisar(l, f"{f}:{n}", cuenta)
    return cuenta[0]


# ── 6. La puerta muerde (antes de mirar el arbol, con los MISMOS binarios) ──
prueba = TMP / "muerde.md"
prueba.write_text(
    "# x\n\n```sh\nsudo /usr/libexec/aegis/aegis-agent --config /etc/a.toml\naegisctl enrolar\n"
    "aegis-watchdog --program /x --arg --config\n"
    "    cmd: \"{{ dir }}/aegis-agent estado --json\"\n```\n"
)
antes = len(fallos)
recorrer([prueba], md=True)
mordidas = len(fallos) - antes
del fallos[antes:]
bueno = TMP / "bueno.md"
bueno.write_text(
    "# x\n\n```sh\nsudo /usr/libexec/aegis/aegis-agent --diagnostico --json > d.json\n"
    "aegisctl --socket /run/aegiscore/agent.sock status\njournalctl -u aegis-agent.service --since hoy\n"
    "/usr/libexec/aegis/aegis-agent --diagnostico --control-socket /run/x.sock --latido /run/l\n"
    "aegis-watchdog --program /usr/libexec/aegis/aegis-agent --arg --latido --arg /run/l --max-age-ms 15000\n"
    "apt-get purge aegis-agent\n"
    "install -m 0755 \"$DIST/aegis-agent\" \"$raiz/usr/libexec/aegis/aegis-agent\"\n"
    "if \"$BIN/aegis-watchdog\" --help > /dev/null; then :; fi\n```\n"
)
recorrer([bueno], md=True)
falsos = len(fallos) - antes
del fallos[antes:]
if mordidas != 4 or falsos != 0:
    print(f"    {ROJO}FALLO{FIN}: la puerta no muerde como debe (cazo {mordidas} de 4 errores; "
          f"{falsos} falso(s) positivo(s))")
    sys.exit(1)
print(f"==> Runbooks: la puerta muerde")
print(f"    {VERDE}OK{FIN} (caza --config, comandos y subordenes inexistentes y --arg --config; ningun falso positivo)")

# ── 2 y 3. Runbooks y despliegue ────────────────────────────────────────────
ops = pathlib.Path("docs/operacion")
mds = sorted(ops.glob("*.md"))
desp = sorted(
    p for p in pathlib.Path("deploy").rglob("*")
    if p.is_file()
    and "windows" not in p.parts
    and p.suffix in {"", ".yml", ".yaml", ".j2", ".service", ".sh", ".tftpl", ".conf", ".md"}
)
print("==> Runbooks: cada orden citada existe en su binario")
n_md = recorrer(mds, md=True)
n_desp = recorrer([p for p in desp if p.suffix != ".md"], md=False)
n_desp += recorrer([p for p in desp if p.suffix == ".md"], md=True)

# ── 4. Los obligatorios y el indice ─────────────────────────────────────────
indice = (ops / "README.md").read_text() if (ops / "README.md").exists() else ""
if not indice:
    fallos.append("docs/operacion/README.md: falta el indice de runbooks")
for r in OBLIGATORIOS:
    if not (ops / r).exists():
        fallos.append(f"docs/operacion/{r}: falta (runbook obligatorio del piloto)")
    elif f"({r})" not in indice:
        fallos.append(f"docs/operacion/README.md: no enlaza {r}")
for f in mds:
    if f.name != "README.md" and f.name not in OBLIGATORIOS and f"({f.name})" not in indice:
        fallos.append(f"docs/operacion/README.md: no enlaza {f.name}")

# ── 5. Umbrales del paso a imponer, contra el codigo ────────────────────────
anillo = ops / "anillo-a-imponer.md"
fuente = sorted(pathlib.Path("crates/aegis-contenido/src").glob("*.rs"))
contrastados = 0
if anillo.exists():
    citados = re.findall(r"^\|[^|\n]*\|\s*`([A-Z][A-Z0-9_]+)`\s*\|\s*([0-9][0-9 .]*)\s*\|", anillo.read_text(), re.M)
    if not citados:
        fallos.append(f"{anillo}: no cita ningun umbral con su constante (`NOMBRE` | valor)")
    if fuente:
        codigo = "\n".join(p.read_text() for p in fuente)
        for nombre, valor in citados:
            m = re.search(rf"pub const {nombre}: \w+ = ([0-9_]+);", codigo)
            if not m:
                fallos.append(f"{anillo}: `{nombre}` no es una constante de crates/aegis-contenido/src")
            elif int(m.group(1).replace("_", "")) != int(re.sub(r"[ .]", "", valor)):
                fallos.append(f"{anillo}: `{nombre}` dice {valor.strip()} y el codigo {m.group(1)}")
            else:
                contrastados += 1

if fallos:
    print(f"    {ROJO}FALLO{FIN}:")
    for f in fallos:
        print(f"    | {f}")
    sys.exit(1)
print(f"    {VERDE}OK{FIN} ({n_md} orden(es) en {len(mds)} runbook(s) y {n_desp} en deploy/, "
      f"todas en el --help de su binario)")
if fuente:
    print(f"    {VERDE}OK{FIN} ({contrastados} umbral(es) del paso a imponer iguales al codigo de aegis-contenido)")
else:
    print(f"    {GRIS}SIN CONTRASTAR: crates/aegis-contenido no existe todavia (FASE 4.5); "
          f"los umbrales del runbook del anillo se comprobaran cuando exista{FIN}")
print(f"AEGIS-MEDIDA runbooks ordenes={n_md + n_desp} runbooks={len(mds)}")
PY
estado=$?
if [ "$estado" -eq 0 ]; then
    echo "${VERDE}==> Runbooks verificados${FIN}"
else
    echo "${ROJO}==> Runbooks: fallo${FIN}"
fi
exit "$estado"
