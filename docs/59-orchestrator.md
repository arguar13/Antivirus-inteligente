# Módulo 59 — AegisOrchestrator (AI-RO): remediación automática de flota

> Componentes: `server/crates/aegis-orchestrator/`.

## 59.1 Responder en segundos, no en minutos

Detectar un **Golden Ticket** —la prueba de que alguien forjó un TGT con la clave
de `krbtgt` y controla el dominio— y esperar a que un humano lea la alerta y
reaccione es regalar minutos al atacante, justo los que necesita para moverse
lateralmente. El Control Plane tiene la vista de toda la flota y puede responder
solo. AegisOrchestrator es esa respuesta: una **máquina de estados transaccional**
que, ante una detección crítica del motor ITDR, lanza un **playbook** de acciones
sobre el endpoint afectado.

Ante un Golden Ticket, el playbook son cuatro acciones **en paralelo**:

- **A. Aislar la red** del endpoint (por XDP): cortarle el oxígeno al atacante.
- **B. Matar los procesos sospechosos** asociados.
- **C. Revocar los tickets Kerberos anómalos** de la identidad implicada.
- **D. Volcado forense de memoria** para la investigación posterior.

Cada clase de amenaza tiene su playbook: un Silver Ticket contiene el endpoint y
recoge evidencia (no hay un `krbtgt` que revocar); un Kerberoasting revoca los
tickets pedidos; una escalada de privilegios aísla y revoca la identidad.

## 59.2 Transaccional, resiliente e idempotente

Tres propiedades hacen de esto una máquina de estados y no un simple bucle:

- **Resiliente a fallos parciales**: un agente puede estar caído, una red
  particionada, un volcado fallar por espacio. La orquestación **no se rinde a la
  primera**: lanza todas las acciones y deja que cada una triunfe o falle por su
  cuenta. Aislar la red no depende de que el volcado forense funcione. El informe
  registra el estado exacto de cada acción.
- **Idempotente en el reintento**: reintentar re-ejecuta **sólo** las acciones que
  fallaron, nunca las que ya tuvieron éxito. Repetir un aislamiento ya hecho es,
  en el mejor caso, ruido; en el peor, dispara efectos colaterales.
- **Con umbral**: por debajo de una severidad (por defecto, `Alta`) no se toca la
  flota. Una sospecha débil se deja para el analista; la remediación automática es
  para lo que no admite espera.

## 59.3 La frontera con la flota, y por qué es el muro

La orquestación decide *qué* hacer; *ejecutarlo* de verdad —programar el XDP en el
kernel del endpoint, matar un proceso, revocar un ticket en la KDC, volcar la RAM—
ocurre en el **agente**, contra un sistema real, por el canal gRPC/mTLS. Esa
frontera es un `trait` (`EjecutorRemediacion`): en producción, la implementación
habla con la flota; en las pruebas, un **doble controlable** ocupa su lugar,
registrando qué se le pidió y devolviendo éxito o fallo a voluntad. Así la máquina
de estados se prueba de verdad y la ejecución real queda declarada como el muro.

## 59.4 Honestidad de validación

| Pieza | Verificable aquí | Muro |
|---|---|---|
| Selección del playbook por clase de amenaza | sí | — |
| Lanzar las acciones en paralelo | sí | — |
| Resiliencia a fallo parcial (un fallo no aborta las demás) | sí, cero mocks de la lógica | — |
| Reintento idempotente (sólo repite lo fallido) | sí | — |
| Umbral de severidad (no actuar por sospecha débil) | sí | — |
| Informe transaccional del estado de cada acción | sí | — |
| Ejecución **real** de cada acción contra la flota | — | ocurre en el agente (XDP/kill/revoke/dump por gRPC/mTLS); gated |

El núcleo que puede estar mal de forma peligrosa —elegir bien, lanzar en paralelo,
sobrevivir a fallos, no repetir lo hecho, terminar consistente— se prueba entero
en cada `make ci`, con la frontera de ejecución representada por un doble que
sustituye a la flota. La ejecución real de las acciones es un muro que
`tools/verificar-orchestrator.sh` declara en vez de fingir.

---

## 59.5 Integración viva: del veredicto ITDR al playbook, sin manos

Todo lo anterior es la **máquina de estados**. Lo que la FASE 64 dejó pendiente era
el cable: los veredictos del motor ITDR (FASE 58) se traducían a alertas del panel
y ahí se quedaban, esperando a que un humano pulsara «aislar». Este apartado cubre
el cierre de ese circuito, ya en `main`:

```
telemetría de identidad  →  MotorItdr  →  Orquestador  →  comandos a la flota
      (colector / API)       (grafo vivo)   (playbook)      (el agente los aplica)
```

La pieza es `aegis_server::remediacion::MotorRemediacion`. Un ciclo hace cuatro
cosas, en este orden y con estas garantías:

1. **Analiza** el lote contra el grafo de identidad de **toda** la flota, que es
   uno solo y vive entre lotes. El motor se toma bajo un cerrojo que **nunca cruza
   un `await`**: el análisis es síncrono y de microsegundos, y un mutex asíncrono
   ahí pagaría una tarea despertada por lote para no ganar nada.
2. **Persiste cada detección como alerta**, pase lo que pase con la respuesta.
3. **Filtra por umbral** con `Orquestador::remediaria`, el mismo predicado que
   aplica `remediar`. No es una copia del umbral en el integrador: dos sitios que
   deciden lo mismo acaban decidiendo distinto.
4. **Lanza los playbooks concurrentemente entre sí** y compone el informe.

### Las tres formas en que esto sale mal, y su defensa

Automatizar acciones destructivas sobre la flota de un cliente falla de tres
maneras concretas:

| Riesgo | Qué pasaría | Defensa |
|---|---|---|
| **Repetir el playbook en bucle** | El motor ITDR es *sin estado por lote*: un barrido de Kerberoasting de veinte minutos aparece en veinte lotes. Un puente ingenuo lanzaría veinte playbooks contra el mismo endpoint. | **Cerrojo distribuido**: una remediación abierta por `(clase, sujeto, endpoint)` + enfriamiento de 15 min tras concluir. |
| **Perder la alerta por culpa de la respuesta** | Si el orquestador falla y el ciclo aborta, la evidencia del analista desaparece; si falla la base de alertas, el aislamiento no sale. | Las dos ramas son **independientes**: un fallo de una se acumula en `incidencias` y la otra continúa. |
| **Bloquear la ingesta** | Un endpoint caído convertiría la respuesta en latencia para toda la flota. | Las remediaciones de un lote van **concurrentes**; el ciclo devuelve el informe de cada una. |

### Por qué el cerrojo vive en PostgreSQL y no en memoria

Porque el plano de control corre en **varias instancias** tras un balanceador, y
dos instancias en memoria no se ven. La garantía la da un índice único parcial:

```sql
CREATE UNIQUE INDEX idx_remediacion_abierta_unica
    ON remediaciones (clase, sujeto, cn_agente) WHERE concluida_en IS NULL;
```

Hacen falta **dos** mecanismos y no uno, porque cubren casos distintos:

- El `WHERE NOT EXISTS` aplica el **enfriamiento**, que mira filas ya cerradas —y
  esas son invisibles para un índice parcial sobre `concluida_en IS NULL`—.
- El `ON CONFLICT DO NOTHING` contra ese índice resuelve la **carrera** de dos
  instancias que pasan el `WHERE` en el mismo instante.

Con sólo el primero, dos instancias abrirían dos remediaciones. Con sólo el
segundo, el enfriamiento no existiría y el atacante marcaría la cadencia de la
respuesta automática con el ritmo al que genera eventos: una denegación de
servicio contra la propia flota, disparada por su defensa.

### La orden que viaja al endpoint

Cada acción abstracta se materializa en un comando que el agente recoge en su
siguiente latido. **Aislar usa el mismo comando `aislar` que el botón de la
consola**, deliberadamente: dos caminos distintos para aislar una máquina se
desincronizan, y el que se usa menos es el que se rompe sin que nadie lo note.

| Acción del playbook | Orden encolada | Parámetros |
|---|---|---|
| `AislarRed` | `aislar` | `motivo`, `sujeto` |
| `MatarProcesosSospechosos` | `matar_procesos` | `sujeto`, `alcance: procesos_de_la_identidad` |
| `RevocarTicketsKerberos` | `revocar_tickets_kerberos` | `sujeto`, `alcance: tickets_anomalos` |
| `VolcadoForenseMemoria` | `volcado_memoria` | `sujeto`, `alcance: procesos_de_la_identidad` |

El `sujeto` viaja en **todas**: una orden de matar procesos sin identidad
obligaría al agente a adivinar a quién, y un agente que adivina a quién matar es
un incidente esperando a ocurrir. El `alcance` acota por el mismo motivo.

### Superficie nueva

| Método | Ruta | Qué hace |
|---|---|---|
| `POST` | `/api/agentes/{cn}/itdr/telemetria` | Ingiere un lote de identidad y **dispara** la respuesta. Responde `202`, no `200`: describe lo que se **ordenó**, no lo que el endpoint ya aplicó. |
| `GET` | `/api/remediaciones` | Las remediaciones recientes con su detalle por acción. |

Las cotas del lote (`10 000` elementos por colección, `512` bytes por nombre) se
comprueban **antes** de tocar el motor: un colector comprometido no puede
convertir un lote en una vía de agotamiento de memoria del plano de control.

Y dos eventos nuevos en el bus WebSocket, `RemediacionLanzada` y
`RemediacionConcluida`. El primero se publica **al empezar**, no al terminar: un
playbook tarda lo que tarde el endpoint más lento, y el analista tiene que ver que
la máquina se está remediando *mientras ocurre*.

### Un defecto real que encontró esta integración

La primera versión del ejecutor sólo comprobaba el inventario en la rama del
aislamiento. Contra un endpoint no enrolado, las otras tres acciones llegaban a
`encolar_comando`, que choca con la clave foránea `comandos.cn_agente → agentes(cn)`:
el informe que leía el analista llevaba **tres errores de PostgreSQL en crudo**.
La corrección no fue capturar el error, sino comprobar el inventario **una vez, al
principio**: si el endpoint no existe, no hay canal por el que entregarle nada, y
el motivo es uno solo y se entiende. Lo destapó la prueba contra una base de datos
real; con un doble no habría aparecido nunca.

### Honestidad de validación de la integración

| Pieza | Verificable | Cómo |
|---|---|---|
| Detección → playbook sobre el endpoint correcto | sí | pruebas del puente, cero mocks de la lógica |
| Un ataque de varios lotes no relanza el playbook | sí | el caso que define la integración |
| La alerta se persiste aunque la respuesta falle | sí | con un `PgPool` real apuntando a una base que no existe: el fallo es auténtico |
| Dos instancias concurrentes abren **una** remediación | sí, contra PostgreSQL real | `tests/remediacion_viva.rs` |
| Enfriamiento: impide relanzar y después deja | sí, contra PostgreSQL real | `tests/remediacion_viva.rs` |
| El aislamiento se marca y la orden se encola | sí, contra PostgreSQL real | `tests/remediacion_viva.rs` |
| Circuito completo identidad → comandos encolados | sí, contra PostgreSQL real | `tests/remediacion_viva.rs` |
| Que el endpoint **aplique** la orden | — | ocurre en el agente; gated |

Donde no hay PostgreSQL, las cuatro filas «contra PostgreSQL real» se **omiten con
aviso** y `tools/verificar-orchestrator.sh` lo dice explícitamente. La diferencia
entre «probado contra infraestructura real» y «no se pudo probar aquí» tiene que
verse en la puerta de calidad, no quedarse en un comentario del código.
