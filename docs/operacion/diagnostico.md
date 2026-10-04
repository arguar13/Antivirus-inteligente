# Recolectar el diagnóstico

`aegis-agent --diagnostico` reúne en un informe lo que soporte necesita para
entender un equipo, **sin datos sensibles**. No arranca otro agente ni para el
que está en marcha: lee lo estático él mismo y le pregunta lo vivo al agente por
su canal de control.

## Recoger

Legible, para mirarlo en el equipo:

```sh
sudo /usr/libexec/aegis/aegis-agent --diagnostico
```

En JSON, para adjuntarlo a la incidencia:

```sh
sudo /usr/libexec/aegis/aegis-agent --diagnostico --json > diagnostico.json
```

Si el agente escucha en otro socket (no es el caso del paquete):

```sh
sudo /usr/libexec/aegis/aegis-agent --diagnostico --control-socket /run/aegiscore/agent.sock
```

Sale con 0 si pudo escribir el informe, **aunque el informe diga que hay
problemas**: decirlo es su trabajo. Con un agente que no responde, el informe
sigue y lo dice.

## Qué lleva

| Sección | Qué dice |
|---|---|
| `resumen` | `sano` o `atencion`, y la lista de avisos (abajo) |
| `agente` | versión del binario, del paquete (`VERSION`), `huella_arbol` (el fichero `HUELLA` del build) y `sha256_binario` |
| `kernel` | capacidades (BTF, tracefs, BPF LSM, cgroup, lockdown...) y degradaciones con su efecto y su remedio |
| `servicio` | edad del latido, marca de parada, si el canal de control responde |
| `agente_en_ejecucion` | estado, memoria residente, tiempo en marcha, eventos |
| `motores` | cada motor: camino, evaluaciones, señales, p99, excesos, suspensiones, `sin_datos` y su `ultimo_sin_datos`; y los que no se registraron, con el requisito que falta |
| `trabajador` | si arrancó y con qué confinamiento; muertes, plazos, análisis |
| `perdidas` | eventos perdidos por el kernel, en total y por familia |
| `memoria` | memoria del agente, y del cgroup del servicio: `max`, `high`, `current`, `peak` y sus eventos (`oom_kill`); el drop-in del presupuesto |
| `plano_control` | la configuración, leída con el mismo analizador estricto que el agente (servidor, ficheros y su modo; nunca su contenido; el error si la rechaza) y, si el agente enlaza, el estado del enlace y sus cuentas |
| `ultimos_veredictos` | los 16 últimos, con su resultado, severidad, motores y porqué |
| `redaccion` | cuánto se tapó de cada clase |

## Qué se tapa

Todo texto pasa por la redacción antes de salir (por construcción: el informe
no admite texto sin redactar). Se tapan las credenciales en claro (con el
redactor de `aegis-captura`: `Authorization`, `password=`, `api_key=`...), el
nombre del equipo, las rutas de usuario (`/home/<usuario>`, `/run/user/<uid>`),
los correos y las direcciones IPv4 que no son de bucle local. El equipo se
identifica con un seudónimo estable (`seudonimo_equipo`, derivado del
`machine-id`), que sirve para juntar informes del mismo equipo.

**Lo que no tapa** (revisa el fichero antes de enviarlo fuera de la
organización): secretos con forma propia en una línea de órdenes
(`-pSECRETO`), direcciones IPv6 y nombres de otros equipos que aparezcan en el
porqué de un veredicto.

## Qué hacer con cada aviso

| Aviso (el texto del informe va sin tildes) | Qué es | Siguiente paso |
|---|---|---|
| «el agente no responde por su canal de control» | No está en marcha, está colgado o no tienes permiso | ¿`sudo`? Si sí: [incidentes](incidentes-agente.md), «no late» |
| «no hay latido» / «el latido tiene N s» | El watchdog lo reiniciará o ya lo intenta | [incidentes](incidentes-agente.md), «no late» |
| «existe /run/aegiscore/agent.shutdown» | Parada autorizada en curso, o alguien la ha forzado | Si nadie la pidió: S1, «sospecha de manipulación» |
| «sin telemetria de kernel» | El kernel no da lo mínimo | `sudo /usr/libexec/aegis/aegis-agent --capacidades`; el remedio está en la degradación |
| «el kernel perdio N eventos» | Ring lleno: punto ciego | [incidentes](incidentes-agente.md), «pérdidas» |
| «el trabajador confinado no arranco» | Los motores de análisis estático no miran | [incidentes](incidentes-agente.md), «trabajador» |
| «motor X no registrado» | Al host le falta un requisito; está declarado | Comprobar que la matriz lo espera en esa distribución |
| «motor X: sin datos alguna vez» | El motor no pudo mirar; el motivo va al lado | Si se repite, S3 con el motivo |
| «registra oom_kill» | El techo de memoria mató procesos del servicio | S1: [incidentes](incidentes-agente.md), «memoria» |
| «no hay drop-in de presupuesto» | Corre sin techo calculado | Reinstalar el paquete (el `postinst` lo escribe) |
| «enlace ... desconectado» / «no cuadran» | El plano de control no recibe | [incidentes](incidentes-agente.md), «plano de control» |
| «la clave del agente la puede leer alguien mas que root» | El enlace la rechazará | `sudo chmod 0600 /etc/aegiscore/pki/agente.key` y reiniciar |
| «la configuracion del plano de control ... no es valida» | El agente la rechaza al arrancar (el mismo analizador estricto) y no reporta; el motivo va en `plano_control.configuracion.error` | Corregir `/etc/aegiscore/plano-control.toml` (o volver a pasar el rol de Ansible) y reiniciar |
| «es valida pero el agente no publica su enlace» | No pudo arrancar el enlace (CA, certificado o clave ilegibles o que no casan) o aún no ha dado su primer informe | `journalctl -u aegis-agent.service`, líneas «plano de control»; repetir el diagnóstico pasado un minuto |
| «no hay fichero HUELLA» | No se sabe de qué árbol salió el binario | Reinstalar desde el pipeline; un binario sin procedencia no va al piloto |

## Enviar

Adjunta `diagnostico.json` a la incidencia. Si son varios equipos de un anillo,
un fichero por equipo con su seudónimo en el nombre.
