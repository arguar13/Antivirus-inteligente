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
