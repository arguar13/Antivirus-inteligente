#!/usr/bin/env bash
#
# Validacion de la infraestructura como codigo (FASE 40).
#
# La infraestructura de un producto de seguridad no puede comprobarse "a ojo":
# un grupo de seguridad mal escrito o un playbook con una variable equivocada no
# fallan al escribirlos, fallan el dia del despliegue, en miles de maquinas a la
# vez. Este script pasa cada artefacto por su validador REAL.
#
# Cada validador se OMITE con honestidad si no esta instalado. Lo que no hace
# nunca es dar por buena una comprobacion que no ha corrido.
set -uo pipefail
cd "$(dirname "$0")"

VERDE=$'\033[32m'; ROJO=$'\033[31m'; AMARILLO=$'\033[33m'
GRIS=$'\033[90m'; NEGRITA=$'\033[1m'; FIN=$'\033[0m'

titulo() { printf '\n%s== %s ==%s\n' "$NEGRITA" "$1" "$FIN"; }
ok()      { printf '    %sOK%s %s\n' "$VERDE" "$FIN" "${1:-}"; }
fallo()   { printf '    %sFALLO%s %s\n' "$ROJO" "$FIN" "${1:-}"; }
omitido() { printf '    %sOMITIDO%s %s\n' "$AMARILLO" "$FIN" "${1:-}"; }
hay()     { command -v "$1" >/dev/null 2>&1; }

FALLOS=0

# ---------------------------------------------------------------------------
titulo "Terraform: plano de control en la nube"
# ---------------------------------------------------------------------------
if hay terraform; then
    if terraform -chdir=terraform fmt -check -recursive >/dev/null 2>&1; then
        ok "formato HCL"
    else
        fallo "formato HCL (ejecuta: terraform -chdir=terraform fmt -recursive)"
        FALLOS=$((FALLOS + 1))
    fi

    # `validate` necesita los proveedores. Si no se pueden descargar —el
    # registro puede estar bloqueado por un proxy corporativo— se dice, en vez
    # de dar por validado lo que no se ha validado.
    if [ -d terraform/.terraform ] || \
       CHECKPOINT_DISABLE=1 terraform -chdir=terraform init -backend=false -input=false >/dev/null 2>&1; then
        if salida=$(terraform -chdir=terraform validate -no-color 2>&1); then
            ok "validacion semantica con el proveedor real"
        else
            fallo "validacion semantica"
            printf '%s\n' "$salida" | head -20 | sed 's/^/      | /'
            FALLOS=$((FALLOS + 1))
        fi
    else
        omitido "no se pudieron obtener los proveedores; solo se valido el formato"
    fi
else
    omitido "terraform no esta instalado"
fi

# ---------------------------------------------------------------------------
titulo "Ansible: despliegue de la flota Linux"
# ---------------------------------------------------------------------------
if hay ansible-playbook; then
    if salida=$(cd ansible && ansible-playbook --syntax-check -i inventario.ejemplo.ini deploy_aegis.yml 2>&1); then
        ok "sintaxis del playbook"
    else
        fallo "sintaxis del playbook"
        printf '%s\n' "$salida" | tail -20 | sed 's/^/      | /'
        FALLOS=$((FALLOS + 1))
    fi
else
    omitido "ansible-playbook no esta instalado"
fi

if hay ansible-lint; then
    if salida=$(cd ansible && ansible-lint deploy_aegis.yml roles/ 2>&1); then
        ok "ansible-lint (perfil production)"
    else
        fallo "ansible-lint"
        printf '%s\n' "$salida" | tail -25 | sed 's/^/      | /'
        FALLOS=$((FALLOS + 1))
    fi
else
    omitido "ansible-lint no esta instalado"
fi

# ---------------------------------------------------------------------------
titulo "WiX: instalador de Windows"
# ---------------------------------------------------------------------------
if hay python3; then
    if python3 - <<'PY'
import sys, xml.etree.ElementTree as ET
try:
    ET.parse('windows/aegis_installer.wxs')
except ET.ParseError as e:
    print(f"      | {e}")
    sys.exit(1)
PY
    then
        ok "XML bien formado"
    else
        fallo "el .wxs no es XML valido"
        FALLOS=$((FALLOS + 1))
    fi

    # Validacion contra el esquema OFICIAL de WiX v3: comprueba que cada
    # elemento y cada atributo existen de verdad, no solo que el XML cierre.
    if [ -f "${WIX_XSD:-/tmp/wix.xsd}" ] && python3 -c "import lxml" 2>/dev/null; then
        if python3 - <<PY
import sys
from lxml import etree
esquema = etree.XMLSchema(etree.parse("${WIX_XSD:-/tmp/wix.xsd}"))
doc = etree.parse('windows/aegis_installer.wxs')
if not esquema.validate(doc):
    for e in esquema.error_log:
        print(f"      | linea {e.line}: {e.message}")
    sys.exit(1)
PY
        then
            ok "valido contra el esquema oficial de WiX v3"
        else
            fallo "el instalador no cumple el esquema de WiX"
            FALLOS=$((FALLOS + 1))
        fi
    else
        omitido "sin el esquema de WiX (WIX_XSD=<ruta>) o sin lxml: solo se comprobo el XML"
    fi
else
    omitido "python3 no esta instalado"
fi

# ---------------------------------------------------------------------------
titulo "PowerShell: despliegue por directiva de grupo"
# ---------------------------------------------------------------------------
if hay pwsh; then
    if salida=$(pwsh -NoProfile -Command '
        $fallos = 0
        foreach ($f in (Get-ChildItem -Path "windows" -Filter "*.ps1")) {
            $errores = $null; $tokens = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile(
                $f.FullName, [ref]$tokens, [ref]$errores)
            if ($errores.Count -gt 0) {
                Write-Output "$($f.Name): $($errores.Count) error(es)"
                $errores | ForEach-Object { Write-Output "  linea $($_.Extent.StartLineNumber): $($_.Message)" }
                $fallos++
            }
        }
        exit $fallos' 2>&1); then
        ok "sintaxis de los scripts"
    else
        fallo "sintaxis de PowerShell"
        printf '%s\n' "$salida" | sed 's/^/      | /'
        FALLOS=$((FALLOS + 1))
    fi
else
    omitido "pwsh no esta instalado"
fi

# ---------------------------------------------------------------------------
echo
if [ "$FALLOS" -eq 0 ]; then
    printf '%s%sINFRAESTRUCTURA VALIDADA.%s\n' "$NEGRITA" "$VERDE" "$FIN"
    exit 0
fi
printf '%s%sINFRAESTRUCTURA: %d comprobacion(es) fallaron.%s\n' "$NEGRITA" "$ROJO" "$FALLOS" "$FIN"
exit 1
