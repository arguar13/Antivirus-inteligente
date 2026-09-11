#!/bin/bash
#
# Hook SessionStart: prepara el contenedor efimero de Claude Code en la web para
# que `make ci` funcione (instala protoc/libelf/libbpf/bpftool y genera los
# modelos ONNX gitignoreados). La logica vive en tools/preparar-entorno.sh; este
# hook solo la dispara en el entorno remoto.
set -euo pipefail

# En una maquina local las dependencias ya estan; esto es solo para la web.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# La salida detallada va a un log para no ensuciar el contexto de la sesion.
"$CLAUDE_PROJECT_DIR/tools/preparar-entorno.sh" > /tmp/aegis-preparar-entorno.log 2>&1 || true
echo "AegisCore: entorno preparado para 'make ci' (protoc, libelf/libbpf, bpftool, modelos ONNX). Detalle en /tmp/aegis-preparar-entorno.log"
