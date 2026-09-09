# Módulo 35 — Despliegue corporativo: nube, flota Linux y flota Windows

> Componentes: `deploy/terraform/`, `deploy/ansible/`, `deploy/windows/`,
> `deploy/validar.sh`, `tools/ci/despliegue.sh`.

Un EDR que solo funciona en la máquina del que lo escribió no protege a nadie.
Este módulo es lo que lo lleva a una organización de verdad: el plano de control
a la nube, y el agente a miles de endpoints Linux y Windows.

---

## 35.1 La infraestructura se valida con las herramientas reales

Un grupo de seguridad mal escrito o un playbook con una variable equivocada **no
fallan al escribirlos**: fallan el día del despliegue, en miles de máquinas a la
vez. Por eso `deploy/validar.sh` —y el job `despliegue` del pipeline— pasan cada
artefacto por su validador auténtico:

| Artefacto | Validación | Qué garantiza |
|---|---|---|
| Terraform | `terraform validate` **con el proveedor de AWS real** | que cada recurso y cada atributo existen |
| Ansible | `--syntax-check` + `ansible-lint` perfil **production** | el perfil más estricto que define el proyecto |
| WiX | esquema **oficial de WiX v3** (XSD) | que cada elemento y atributo es WiX legal |
| PowerShell | analizador oficial de PowerShell | sintaxis real, no una aproximación |

Cada validador se **omite diciéndolo** si no está instalado. Lo que nunca hace
es dar por buena una comprobación que no corrió.

> Nota sobre `wixl`: la reimplementación libre de WiX no soporta
> `<ComponentGroup>` ni `<Condition>`, así que no puede construir este
> instalador. Adaptarlo a `wixl` habría significado escribir un instalador
> **peor** para el producto real. Se mantuvo el `.wxs` idiomático de WiX v3 y se
> validó contra su esquema oficial, que comprueba lo mismo que comprobaría el
> compilador antes de empaquetar.

---

## 35.2 El punto que decide la seguridad del despliegue en nube

El canal de flota pasa por un **balanceador de red (capa 4), no de aplicación**.
No es una preferencia de arquitectura: es lo que sostiene la identidad del
sistema entero.

El canal es **mTLS mutuo** — el agente verifica el certificado del plano de
control **y** el plano de control autentica al agente por el CN de *su*
certificado. Un balanceador de aplicación **termina** el TLS: si terminara ahí,
el certificado del agente moriría en el balanceador y al servidor le llegaría
una conexión anónima. La autenticación de la flota entera desaparecería, y con
ella la garantía de que un agente no puede hacerse pasar por otro.

El balanceador de red reenvía los bytes sin mirarlos. El handshake ocurre de
extremo a extremo, entre el endpoint y el proceso que lo atiende.

### Otras decisiones que no son cosméticas

- **`redes_administracion` sin valor por defecto**, y con validación que
  **rechaza `0.0.0.0/0`**. La consola puede aislar toda la flota; un valor por
  defecto cómodo es exactamente como se expone una consola a Internet.
- **La CA de la flota en almacenamiento replicado con copias**, no en el disco
  de una instancia. Si se pierde, todos los certificados dejan de validar y los
  miles de endpoints quedan fuera a la vez. Cierra el círculo que abrió la
  [FASE 37](32-plano-control.md#328-custodia-de-la-ca-de-la-flota): el código
  persiste la CA, la infraestructura le da dónde persistir.
- **La capa de datos no tiene ruta a Internet**, ni saliente. Una base de datos
  comprometida no puede exfiltrar por su cuenta.
- **IMDSv2 obligatorio**: con la versión 1, una vulnerabilidad de petición
  falsificada desde el servidor bastaría para robar las credenciales del rol.
- **El arranque no descarga nada**: el binario viene en la AMI que construyó el
  pipeline, con su suma y su procedencia. La instancia arranca con el artefacto
  auditado, no con lo que hubiera en un repositorio en ese momento.

---

## 35.3 Desplegar en la flota Linux sin tumbarla

Desplegar un EDR en miles de máquinas a la vez es la forma más rápida de tumbar
una organización con un solo paquete defectuoso. El playbook avanza **por
tandas** y se detiene al primer signo de problema:

- **Servidores críticos**: de uno en uno; cualquier fallo detiene todo.
- **Resto de servidores**: tandas del 10 %, parando si falla más del 10 % —esa
  proporción distingue una máquina rara de un paquete defectuoso—.
- **Estaciones**: tandas del 20 %.

Antes de tocar nada comprueba que el sistema está soportado y que el kernel
llega a 4.18 (sin eso no hay eBPF utilizable), y **avisa si convive otro EDR**:
dos agentes compitiendo por los mismos enganches del kernel pueden bloquearse.

Después de instalar, **verifica**: que el servicio quedó activo y que el agente
alcanza el plano de control. Un despliegue que no comprueba el resultado no es
un despliegue, es una esperanza.

### La clave privada del endpoint no viaja nunca

El agente genera su clave **en la máquina** y envía solo una petición de firma.
No pasa por la red, ni por el inventario, ni por el nodo de control. Es la
diferencia entre *aprovisionar identidades* y *repartir credenciales*.

### Endurecido, pero no encerrado

La tentación con `systemd` es activar todas las protecciones que existen. Con un
EDR **no se puede**: necesita ver el sistema entero y hablar con el kernel. Si
se le encierra del todo deja de detectar, y un antivirus que no detecta es peor
que ninguno porque da confianza sin darla.

El servicio concede capacidades **concretas** sin ser root —`CAP_BPF`,
`CAP_PERFMON`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`, `CAP_KILL`— y deja tres
protecciones desactivadas **con su motivo escrito al lado**:

| Desactivada | Por qué |
|---|---|
| `ProtectKernelModules` | lee la lista de módulos cargados para cazar rootkits |
| `ProtectProc` / `ProcSubset` | mirar `/proc` de otros procesos es literalmente su trabajo |
| `MemoryDenyWriteExecute` | el desempaquetador ejecuta código en su recinto para observar el malware |

No están `CAP_SYS_ADMIN` ni `CAP_SYS_MODULE`: un agente comprometido **no debe
poder cargar un módulo de kernel**.

Y `StartLimitIntervalSec=0`, sin límite de reintentos: un EDR que se rinde tras
cinco fallos deja el endpoint desprotegido justo cuando algo lo está tumbando a
propósito.

---

## 35.4 Windows: silencioso, idempotente, y que no rompa el arranque

El script de la directiva de grupo corre en **cada equipo, en cada arranque**.
De ahí sus dos obsesiones:

1. **Es idempotente.** Si la versión correcta ya está instalada y operativa,
   termina en milisegundos. Sin eso, reiniciaría el EDR de toda la organización
   cada mañana.
2. **No rompe el arranque.** Sale con código cero aunque falle (salvo
   `-FallarEnError`, para el piloto): un script de inicio que aborta puede
   impedir que los equipos completen el arranque. El fallo queda en el registro
   de eventos, origen `AegisDeploy`.

Además **verifica la firma Authenticode** del MSI antes de instalarlo —es lo que
impide que un recurso compartido comprometido sirva un instalador manipulado a
toda la organización— y, si encuentra el agente instalado **pero con el servicio
parado** (exactamente lo que deja un malware que consigue detenerlo), lo levanta
y deja constancia.

`Deploy-AegisGPO.ps1` **pide confirmación** si la unidad organizativa alcanza más
de 500 equipos y no se indicó grupo piloto. Con grupo piloto, la GPO se enlaza a
la unidad entera sin aplicarse todavía a todos: ampliar el despliegue es añadir
miembros al grupo.
