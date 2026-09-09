# Módulo 10 — Canal de control local (`aegisctl`)

> Componente: `crates/aegis-ctl` (Rust) + binario `aegisctl`.

El operador necesita hablar con el agente en ejecución: ver su estado, lanzar un
escaneo, aislar la red en una emergencia, consultar la cuarentena. `aegisctl` es
esa interfaz.

---

## 10.1 El canal

Es un **socket Unix** con permisos **0600**. La elección no es casual: el canal
de control es una vía para escanear ficheros, cortar la red del equipo y
consultar la cuarentena. Esa vía no puede quedar abierta a cualquier usuario del
sistema. Es el mismo criterio que rige los mapas eBPF y el registro de
auditoría: **lo que controla el EDR lo controla root.**

El protocolo es de **texto, una petición por conexión**. El canal es local y de
bajo volumen —un operador escribe un comando de vez en cuando—, así que no hay
ninguna necesidad de un formato binario ni de multiplexar. Un protocolo de texto
es inspeccionable con `socat` y trivial de razonar: se lee una línea de
petición, se escribe la respuesta, se cierra.

```
aegisctl                              agente (servidor de control)
────────                              ────────────────────────────
connect(/run/aegiscore/agent.sock)
"status\n"                       ──►  handler.handle(Status)
                                 ◄──  "OK\nrss_kb=19712\nstate=running\n..."
close
```

El servidor no lanza un hilo por conexión: el volumen es de una petición humana
ocasional, y un manejador secuencial no puede sufrir contención ni condiciones
de carrera. Un cliente lento no bloquea al agente porque el socket tiene plazo
de lectura.

---

## 10.2 Los comandos

| Comando | Qué hace |
|---|---|
| `aegisctl status` | Estado de recursos (memoria residente, tiempo en marcha) y del pipeline (eventos recibidos y escalados). |
| `aegisctl scan <ruta>` | Escaneo YARA bajo demanda de una ruta **absoluta**. Devuelve el veredicto y las reglas que dispararon. |
| `aegisctl isolate [containment\|total]` | Aislamiento de red de emergencia vía `nftables`. `containment` deja abierta la ruta de administración; `total` corta todo salvo loopback. |
| `aegisctl quarantine list` | Lista los identificadores de la cuarentena. |

### Detalles que importan

- **`scan` exige ruta absoluta.** Una ruta relativa dependería del directorio
  de trabajo del agente, que no es predecible desde `aegisctl`.
- **El motor YARA se carga en diferido.** Cargar las reglas cuesta memoria, y el
  presupuesto del agente en reposo (< 45 MB) no debe incluir un motor que quizá
  no se use en toda la vida del proceso. La primera petición de escaneo paga su
  coste; las siguientes lo reutilizan.
- **`isolate` aplica en una transacción.** El conjunto de reglas se aplica
  entero de una vez; aplicarlo por partes dejaría ventanas en las que la máquina
  está a medio aislar, peor que cualquiera de los dos estados completos.

---

## 10.3 Cómo se prueba

De extremo a extremo, sobre un socket Unix **real**: se levanta un servidor en
un socket de verdad, se conecta un cliente de verdad, y se comprueba lo que llega
al otro lado. El `scan` se prueba contra un fichero EICAR real escrito en disco.
Un canal de control que solo se probara en memoria no demostraría que el marco de
mensajes, los permisos 0600 y el cierre de conexión funcionan.

El agente embebe el servidor cuando se arranca con `--control-socket <ruta>`,
respaldando `status` con los contadores reales de su pipeline.
