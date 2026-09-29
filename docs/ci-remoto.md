# CI remoto

> Documento vivo. Sustituye a la vía de GitHub Actions descrita en
> [07-estado-ci.md](07-estado-ci.md), que sigue bloqueada a nivel de cuenta.

## Qué es

`make ci` completo —incluida la [matriz de kernels](matriz-capacidades.md#matriz-de-kernels)—
ejecutado en cada `push` a `main` y en cada petición de cambio, en una máquina que
no es la de ningún desarrollador.

```
  desarrollador ──git push──▶ Forgejo (forja) ──tarea──▶ runner con KVM ──▶ make ci
                                   ▲                           │
                                   └──────── veredicto ◀───────┘
```

| Pieza | Qué es | Dónde está |
|---|---|---|
| Workflow | La definición de la tanda | [`.forgejo/workflows/ci.yml`](../.forgejo/workflows/ci.yml) |
| Forja | Forgejo con Actions activado | [`deploy/ci/forja-local.sh`](../deploy/ci/forja-local.sh) |
| Runner | `forgejo-runner` en modo host, etiqueta `kvm` | [`deploy/ci/instalar-runner.sh`](../deploy/ci/instalar-runner.sh) |

## Por qué así

- **Por qué no GitHub Actions.** Está bloqueado a nivel de cuenta: falla incluso un
  workflow de cinco líneas sin acciones externas. Un runner autoalojado de GitHub
  depende de la misma cuenta, así que no lo resuelve.
- **Por qué un runner propio.** La matriz de kernels arranca cada distribución en
  una microVM y necesita **KVM**, que los runners alojados no ofrecen, y las pruebas
  cargan programas eBPF e inspeccionan memoria de otros procesos, que exige root.
- **Por qué Forgejo.** Es software libre y autoalojable, entiende la sintaxis de
  workflows de GitHub y su runner admite el modo *host* que KVM necesita. Woodpecker o
  GitLab CI servirían igual; el workflow y el script del runner son la parte que
  importa, y se trasladan.

## Seguridad del runner

El runner ejecuta el código del repositorio **como root** en modo host. Eso impone
tres reglas, que no son opcionales:

1. **Máquina dedicada.** Física o virtual con virtualización anidada; nunca el equipo
   de un desarrollador ni un servidor con otros servicios.
2. **Solo código de confianza.** La forja no acepta registros abiertos y el
   repositorio es privado: una petición de cambio de un desconocido ejecutaría código
   arbitrario como root en el runner.
3. **Sin secretos de producción.** El runner no tiene acceso a claves de firma de
   versiones ni a la CA de la flota; construye y prueba, no publica.

## Cómo se monta

```bash
# 1. La forja (en su propia máquina en producción, detrás de TLS)
sudo deploy/ci/forja-local.sh

# 2. El runner, en la máquina dedicada con KVM
sudo deploy/ci/instalar-runner.sh --instancia https://forja.ejemplo \
     --token "$(sudo deploy/ci/forja-local.sh --token)"

# 3. Que cada push llegue también a la forja
git remote set-url --add --push origin https://forja.ejemplo/aegis/aegiscore.git
git remote set-url --add --push origin "$(git remote get-url origin)"
```

`deploy/ci/instalar-runner.sh --comprobar` dice qué le falta a una máquina para
servir de runner.

## Lo que no es código

Una máquina dedicada, su dirección y las credenciales de la forja son decisiones y
recursos del propietario del proyecto, igual que el certificado de Microsoft o el
*entitlement* de Apple. El repositorio trae todo lo necesario para montarlo en una
orden; elegir dónde vive es un paso administrativo.
