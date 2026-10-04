# Operación del agente: runbooks del piloto

Estos runbooks son para quien instala, opera y da soporte al agente en un
piloto (FASE 7 del MP-16): de 10 a 50 equipos Linux reales, dos semanas en
solo-auditoría y después imponer por anillos, si los números lo permiten.

**Cada orden de nuestros binarios que aparece aquí se comprueba en `make ci`**
(grupo `runbooks`, `tools/verificar-runbooks.sh`): la puerta construye
`aegis-agent`, `aegisctl` y `aegis-watchdog`, lee su `--help` y falla si un
runbook —o un fichero de `deploy/`— cita una opción o un comando que el binario
no tiene. Es la puerta que habría cazado la opción `--config` que el rol de
Ansible pasaba al agente, y que el agente rechaza (H-30, H-40). Las órdenes del sistema (`systemctl`, `apt-get`, `rpm`)
no se comprueban: son de su distribución.

| Runbook | Para qué | Ensayado |
|---|---|---|
| [Instalar](instalar.md) | Un equipo o una flota, con el paquete verificado | Ciclo de vida del paquete en la matriz de kernels (prueba `paquete-en-vivo`, FASE 3) |
| [Actualizar](actualizar.md) | Versión nueva, por anillos, con vuelta atrás automática | Ídem |
| [Revertir](revertir.md) | Volver a la versión anterior, automática o a mano | Ídem (la vuelta atrás automática) |
| [Desinstalar](desinstalar.md) | Quitar el agente con el token de la consola | Ídem |
| [Recolectar el diagnóstico](diagnostico.md) | Lo que soporte necesita, redactado, en un fichero | Pruebas unitarias del formato y de la redacción; en vivo, pendiente |
| [Pasar un anillo a imponer](anillo-a-imponer.md) | La decisión, gobernada por los números de la FASE 4 | **No ejecutable hoy**: el agente no tiene modo imponer |
| [Incidentes del propio agente](incidentes-agente.md) | Cuando el que falla es el EDR | Por partes: lo que usa órdenes del agente, sí; el resto, no |

## Convenciones

- Todo se ejecuta como root (`sudo`): el canal de control es un socket 0600 de
  root en `/run/aegiscore/`, y eso es lo que se quiere.
- Rutas del paquete: `/usr/libexec/aegis/aegis-agent`,
  `/usr/libexec/aegis/aegis-watchdog`, `/usr/bin/aegisctl`; la unidad es
  `aegis-agent.service` (el watchdog lanza al agente y lo vigila por su latido).
- El agente nace en **solo-auditoría**: detecta, informa y no bloquea ni mata
  nada. Ningún runbook de aquí lo cambia.
- Lo que un runbook no puede hacer todavía lo dice en su sitio, con la fase que
  lo trae. Un paso que no existe no se escribe como si existiera.

## Guardia

| Severidad | Qué es | Respuesta |
|---|---|---|
| S1 | Un equipo del piloto degradado por el agente (cuelgues, OOM, arranque roto), o sospecha de manipulación del agente | 30 min en horario de piloto; parar el anillo |
| S2 | El agente no protege en un equipo (no late, sin telemetría de kernel, trabajador caído) | 4 h hábiles |
| S3 | Degradación declarada, pérdidas de eventos, plano de control desconectado | Siguiente día hábil |

Detalle de cada caso: [incidentes del propio agente](incidentes-agente.md).
