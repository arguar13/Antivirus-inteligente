# `kernel/windows/` — la mitad de Windows

| Directorio | Qué hay | Dónde se compila |
|---|---|---|
| `aegis/` | Driver de auto-defensa (`ObRegisterCallbacks`) | WDK, en Windows |
| `aegis/aegis_politica.c` | **La decisión**: qué acceso se recorta y qué evento de ETW-Ti es inyección | En cualquier sitio, con gcc y clang |
| `etwti/` | Dónde y por qué se consume ETW Threat Intelligence | — |

La separación entre «la decisión» y «la fontanería del driver» no es estética.
La decisión es la parte que puede estar mal **de forma peligrosa** —quitar un
bit de acceso de más deja al usuario sin gestor de tareas; quitar uno de menos
deja al atacante matar el EDR— y es la única que se puede compilar y probar sin
un Windows delante.

Con esta separación, esa lógica se ejercita en **cada** `make ci`:

```bash
./tools/verificar-windows.sh
```

Ver el [módulo 42](../../docs/42-windows.md) para el porqué de cada regla, y el
[módulo 01](../../docs/01-kernel-ring0.md) para la cadena
ELAM → PPL → ETW-Ti.
