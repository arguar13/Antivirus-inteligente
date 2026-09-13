# Módulo 17 — Auditoría final de release

> Componente: `tests/final_audit.sh` (`make audit`).

`make ci` es la puerta **por commit**: rápida, para no frenar el desarrollo. La
auditoría final es la puerta **de release**: más exhaustiva, porque incluye la
prueba de carga completa y un barrido de advertencias que no tendría sentido
correr en cada cambio.

Ejecuta **en paralelo** las cuatro validaciones independientes y después mide los
recursos:

| Comprobación | Qué exige |
|---|---|
| **Compilación limpia** | Todo el árbol compila y produce **cero advertencias** del compilador. Una release no sale con warnings. |
| **Clippy** | `-D warnings` sobre todos los targets. |
| **Red Team** | Los 5 escenarios de ataque real resisten (FASES 9, 10, 13, 14, 22). |
| **Estrés del ring** | Un millón de eventos por el ring buffer, en orden, sin pérdidas, con YARA y ML compitiendo por la CPU. |
| **Recursos** | El agente de release arranca por debajo de **las dos puertas**: el presupuesto de reposo del host (que escala con su RAM) y la línea base de arranque de 32 MiB (que no escala, y es la que caza una regresión en una máquina grande). |

Corren en paralelo porque son independientes: mientras compila, la simulación de
Red Team monta sus ataques y el estrés inunda el ring. El veredicto es único: si
cualquiera falla, la auditoría falla.

### Corrida de referencia

```
  Compilacion sin avisos       OK  0 advertencias
  Clippy (-D warnings)         OK
  Red Team (5 escenarios)      OK  Todas las defensas resistieron (5 escenarios).
  Estres del ring (1M eventos) OK  ritmo del ring: 519708 eventos/seg (objetivo 100000)
  Recursos en reposo           OK  22368 KB · reposo 81920 KB · linea base 32768 KB · perfil estacion

AUDITORIA FINAL SUPERADA. AegisCore listo para release.
```
