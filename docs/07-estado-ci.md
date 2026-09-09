# Estado del CI remoto

> **Resumen: GitHub Actions está bloqueado a nivel de repositorio o cuenta.
> No es un defecto del workflow, y no se puede arreglar desde el código.**
> Mientras dure, la puerta de calidad del proyecto es `make ci`.

## Síntoma

Las cinco ejecuciones registradas terminan igual:

```
conclusion: startup_failure
path:       BuildFailed
name:       ""
state:      deleted
```

`startup_failure` significa que la ejecución muere **antes de arrancar ningún
job**. `path: BuildFailed` con `name` vacío es el registro sintético que crea
GitHub cuando no consigue construir el workflow. Los tiempos lo confirman:
`created_at`, `run_started_at` y `updated_at` son idénticos al segundo.

## Descarte de causas

| Hipótesis | Comprobación | Resultado |
|---|---|---|
| YAML inválido | `yaml.safe_load()` sobre el fichero | Parsea; 5 jobs bien formados |
| Tabuladores, CRLF o BOM | `grep -P '\t\|\r\|[^\x00-\x7F]'` + `file` | ASCII limpio, sin tabuladores |
| Fichero ausente o mal ubicado | API de contenidos de GitHub | Presente en `.github/workflows/ci.yml`, 1922 B |
| Acción externa inaccesible | Workflow mínimo de 5 líneas **sin ninguna acción externa** | **También falla con `startup_failure`** |

La última fila es la concluyente. Este workflow:

```yaml
name: Smoke
on:
  push:
    branches: [main]
jobs:
  hello:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
```

falló igual, y GitHub ni siquiera le creó una entrada de workflow propia: lo
atribuyó al mismo `BuildFailed` sintético. Si GitHub no llega a parsear ni ese
fichero, el problema no está en ningún fichero.

## Causa probable y cómo resolverlo

Queda fuera del alcance del repositorio. Requiere una acción del propietario en
la configuración de GitHub. Por orden de probabilidad:

1. **Actions deshabilitado para el repositorio.**
   `Settings → Actions → General → Actions permissions` → seleccionar
   *Allow all actions and reusable workflows*.
2. **Límite de gasto o minutos agotados.**
   `Settings → Billing and plans → Spending limits` (aplica a repos privados;
   los públicos tienen minutos gratuitos ilimitados). Hacer el repositorio
   público también lo resuelve.
3. **Política de organización** que restringe las acciones permitidas, si el
   repositorio se mueve a una organización.

Después de cambiarlo, basta con volver a lanzar la última ejecución o empujar un
commit; el workflow ya está en el repositorio y es correcto.

## Mientras tanto

Que el CI remoto no arranque **no relaja ninguna comprobación**. Todas se
ejecutan localmente y son obligatorias antes de cada commit:

```bash
make ci
```

`tools/ci-local.sh` ejecuta exactamente el mismo conjunto que
`.github/workflows/ci.yml`: formato, clippy con `-D warnings`, tests,
verificación cruzada del layout del ABI con gcc y con clang, compilación de los
programas eBPF, paso por el verificador del kernel, y comprobación de enlaces de
la documentación.

Cuando Actions vuelva, el workflow remoto y el script local seguirán corriendo
el mismo conjunto; el script no es un sustituto degradado.
