# Incidentes del propio agente

Cuando el que falla es el EDR. La regla de este runbook: **primero el equipo
del cliente, después el agente**. Un agente que degrada la máquina que protege
es peor que un agente ausente.

Siempre, lo primero:

```sh
sudo /usr/libexec/aegis/aegis-agent --diagnostico --json > diagnostico.json
systemctl status aegis-agent.service
journalctl -u aegis-agent.service --since "-2h"
```

## No late, o se reinicia en bucle (S2; S1 si degrada el equipo)

Señales: el diagnóstico dice «no hay latido» o «el latido tiene N s»; el
diario repite arranques.

1. ¿Fue tras una actualización? Si el paquete se revirtió solo, sigue
   [revertir](revertir.md).
2. ¿Hay telemetría de kernel? Mira `kernel.degradaciones` o directamente:

```sh
sudo /usr/libexec/aegis/aegis-agent --capacidades
```

3. ¿Lo mata el techo de memoria? `memoria.cgroup_servicio.events.oom_kill`
   mayor que cero: caso «memoria».
4. Si el bucle degrada el equipo, para el agente de forma autorizada (la marca
   impide que el watchdog lo relance) y abre S1 con el diagnóstico:

```sh
sudo touch /run/aegiscore/agent.shutdown
sudo systemctl stop aegis-agent.service
```

   El equipo queda sin EDR: anótalo en la incidencia y reactívalo
   (`sudo systemctl start aegis-agent.service`) en cuanto haya arreglo.

## Memoria: `oom_kill` o uso por encima de `high` (S1)

El techo del servicio lo calcula el paquete para este equipo
(`/etc/systemd/system/aegis-agent.service.d/10-presupuesto.conf`). Que el kernel
mate procesos del servicio quiere decir que el agente o su trabajador no
caben. No se sube el techo a mano: es el presupuesto del producto. Recoge el
diagnóstico (lleva la memoria por motor) y escala a ingeniería.

## CPU alta (S2)

El diagnóstico da el p99 del árbitro y de cada motor (`arbitro`, `motores`) y
los motores suspendidos por exceder su presupuesto (`suspensiones`). Mira quién
come CPU dentro del servicio:

```sh
systemd-cgtop -1 system.slice/aegis-agent.service
```

Si degrada el equipo, parada autorizada como en el caso «no late».

## Pérdidas de eventos (S3; S2 si son sostenidas)

`perdidas.kernel.perdidos` mayor que cero es un **punto ciego**, no una
métrica de rendimiento: el ring se llenó. `perdidas.por_familia` dice de qué
(ejecución, red, ficheros). Anota la carga del equipo en ese momento y escala si
se repite en reposo.

## Trabajador confinado caído (S2)

`trabajador.disponible = no`: los motores de análisis estático no miran;
`trabajador.al_arrancar` dice por qué (sin cgroup v2, sin uid propio,
confinamiento insuficiente). El resto del agente protege igual.

## Motor no registrado o «sin datos» (S3)

`motores[].registrado = no` con su `requisito`: es una degradación declarada;
compárala con lo que la matriz espera en esa distribución. «Sin datos» repetido
con el mismo `ultimo_sin_datos`: escálalo con el motivo literal.

## Plano de control desconectado (S3)

El agente protege en local; los veredictos esperan en una cola acotada y lo que
no cabe se cuenta como perdido, nunca en silencio (`plano_control.enlace`:
`en_cola`, `perdidos`, `ultimo_error`). Comprueba la red hasta el servidor y la
caducidad de su certificado (H-39). No reinicies el agente para «arreglarlo»: la
cola vive en memoria y se perdería.

## Sospecha de manipulación del propio agente (S1)

Señales: marca de parada que nadie pidió, `sha256_binario` o `huella_arbol`
distintos de los publicados, latido que desaparece sin reinicio de systemd,
desinstalación sin token.

1. **No reinstales todavía**: destruirías la evidencia.
2. Aísla la red del equipo dejando la ruta de administración:

```sh
sudo aegisctl isolate containment
```

3. Guarda el diagnóstico, la cuarentena y el diario:

```sh
sudo aegisctl quarantine list
journalctl -u aegis-agent.service --since "-7d" > diario-agente.txt
```

4. Escala a seguridad con todo lo anterior. La parada por marca sin autenticar
   es un hallazgo abierto (H-31): cualquiera con root puede crearla.

## Escalar a ingeniería

Adjunta siempre `diagnostico.json`, la salida de `systemctl status` y el diario
de las dos últimas horas. Di la versión del paquete y el anillo.
