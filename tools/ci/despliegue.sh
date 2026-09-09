#!/usr/bin/env bash
#
# Job de CI: infraestructura como codigo (deploy/).
#
# Un grupo de seguridad mal escrito o un playbook con una variable equivocada no
# fallan al escribirlos: fallan el dia del despliegue, en miles de maquinas a la
# vez. Este job pasa cada artefacto por su validador real antes de que llegue a
# la rama principal.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_comun.sh"
cd "$RAIZ"

titulo "Job: despliegue (infraestructura como codigo)"

# El esquema de WiX no se versiona (es de terceros); se toma de la ruta que
# indique el entorno, y si no esta, el validador lo dice y omite esa parte.
WIX_XSD="${WIX_XSD:-/tmp/wix.xsd}" ./deploy/validar.sh
