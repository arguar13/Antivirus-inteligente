# Despliegue corporativo de AegisCore

Tres piezas, tres públicos distintos:

| Directorio | Qué despliega | Con qué |
|---|---|---|
| [`terraform/`](terraform/) | el **plano de control** en la nube | Terraform sobre AWS |
| [`ansible/`](ansible/) | el **agente** en la flota Linux | Ansible sobre SSH |
| [`windows/`](windows/) | el **agente** en la flota Windows | MSI silencioso por directiva de grupo |

Todo se valida con las herramientas reales antes de llegar a la rama principal:

```
WIX_XSD=/tmp/wix.xsd ./validar.sh
```

Ese script corre `terraform validate` con el proveedor de AWS de verdad,
`ansible-lint` en perfil **production**, el esquema **oficial de WiX v3** y el
analizador de PowerShell. Cada validador se **omite diciéndolo** si no está
instalado; lo que nunca hace es dar por buena una comprobación que no corrió.

---

## 1. Plano de control (Terraform)

```bash
cd terraform
cp terraform.tfvars.ejemplo terraform.tfvars   # y editarlo
terraform init
terraform plan -out=plan.tfplan
terraform apply plan.tfplan
```

### Lo que hay que entender antes de aplicarlo

**`redes_administracion` no tiene valor por defecto, a propósito.** La consola
puede aislar toda la flota: dejarla accesible desde Internet por omisión sería
el fallo de configuración más caro que este despliegue podría cometer, y un
valor por defecto cómodo es exactamente como ocurren esos fallos. La variable
además **rechaza `0.0.0.0/0`**.

**El canal de flota pasa por un balanceador de RED, no de aplicación.** Esto no
es una preferencia: el canal es mTLS **mutuo**, y un balanceador de aplicación
*termina* el TLS. Si terminara ahí, el certificado del agente moriría en el
balanceador y al servidor le llegaría una conexión anónima — la autenticación de
la flota entera desaparecería. El balanceador de red reenvía los bytes sin
mirarlos y el handshake ocurre de extremo a extremo.

**La CA de la flota vive en almacenamiento replicado con copias automáticas.**
Es el recurso más crítico del despliegue: si se pierde, todos los certificados
emitidos dejan de validar y los miles de endpoints quedan fuera a la vez. Entra
en el plan de recuperación con la misma prioridad que la base de datos.

---

## 2. Flota Linux (Ansible)

```bash
cd ansible
cp inventario.ejemplo.ini inventario.ini       # y adaptarlo
ansible-playbook -i inventario.ini deploy_aegis.yml \
  -e "aegis_agente_sha256=<suma> aegis_agente_version=1.0.0" \
  -e "aegis_agente_servidor_flota=$(terraform -chdir=../terraform output -raw flota_endpoint)" \
  -e "@secretos/ca.yml" \
  --check --diff        # ensayo primero, sin tocar nada
```

### Despliegue por tandas, parando al primer problema

Desplegar un EDR en miles de máquinas a la vez es la forma más rápida de tumbar
una organización entera con un solo paquete defectuoso:

- **Servidores críticos**: de **uno en uno** (`serial: 1`), y cualquier fallo
  detiene todo.
- **Resto de servidores**: tandas del 10 %, parando si falla más del 10 %.
- **Estaciones**: tandas del 20 %.

Se comprueba **antes** que el sistema está soportado y que el kernel llega a
4.18 (sin eso no hay eBPF utilizable), y se **avisa si convive otro EDR**: dos
agentes compitiendo por los mismos enganches del kernel pueden bloquearse.

### La clave privada del endpoint no viaja

El agente genera su clave **en la máquina** y envía solo una petición de firma.
La clave no pasa por la red, ni por el inventario, ni por el nodo de control. Es
la diferencia entre *aprovisionar identidades* y *repartir credenciales*.

### El servicio `systemd` está endurecido, pero no encerrado

La tentación con systemd es activar todas las protecciones. Con un EDR no se
puede: necesita ver el sistema entero y hablar con el kernel. Si se le encierra
del todo deja de detectar — y un antivirus que no detecta es peor que ninguno,
porque da confianza sin darla.

Por eso el servicio concede capacidades **concretas** (`CAP_BPF`, `CAP_PERFMON`,
`CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`…) sin ser root, y deja explícitamente
desactivadas tres protecciones, cada una con su motivo escrito al lado:
`ProtectKernelModules` (lee la lista de módulos para cazar rootkits),
`ProtectProc` (mirar `/proc` de otros procesos es literalmente su trabajo) y
`MemoryDenyWriteExecute` (el desempaquetador ejecuta código en su recinto).

No están `CAP_SYS_ADMIN` ni `CAP_SYS_MODULE`: un agente comprometido no debe
poder cargar un módulo de kernel.

---

## 3. Flota Windows (MSI + GPO)

```powershell
# Una sola vez, desde un controlador de dominio o una estación con RSAT:
.\Deploy-AegisGPO.ps1 -RutaMsi .\aegis-1.0.0.0.msi -Version 1.0.0.0 `
    -ServidorFlota aegis.empresa.local:8443 -ServidorRecurso dc01 `
    -UnidadOrganizativa "OU=Piloto,OU=Equipos,DC=empresa,DC=local" `
    -GrupoPiloto "GG-AegisPiloto"
```

Instalación silenciosa manual:

```
msiexec /i aegis.msi /qn SERVIDOR_FLOTA=aegis.empresa.local:8443
```

### Decisiones del instalador

- **El servicio se instala detenido** y lo arranca un paso posterior, cuando ya
  tiene identidad. Un EDR que arranca sin poder autenticarse genera ruido en
  cada endpoint de la organización a la vez.
- **Desinstalar no borra la identidad del endpoint.** Reinstalar tras una
  actualización fallida no puede obligar a reenrolar miles de máquinas.
- **Bajar de versión está prohibido**: en una flota, volver atrás por accidente
  es como se reintroduce una vulnerabilidad ya corregida.
- **Reinicio automático indefinido del servicio.** Un EDR que se rinde tras dos
  intentos deja la máquina desprotegida justo cuando algo lo está tumbando a
  propósito.
- El directorio de la identidad solo lo leen **SYSTEM y administradores**: si un
  usuario del equipo puede leer esa clave, puede suplantar a esa máquina.

### El script de GPO no puede romper el arranque

Corre en **cada equipo, en cada arranque**, así que:

- **Es idempotente**: si la versión correcta ya está instalada y operativa,
  termina en milisegundos. Sin eso, reiniciaría el EDR de toda la organización
  cada mañana.
- **Sale con código cero aunque falle** (salvo `-FallarEnError`, para el
  piloto). Un script de inicio que aborta puede impedir que los equipos
  completen el arranque, y el remedio sería peor que la enfermedad. El fallo
  queda en el registro de eventos, origen `AegisDeploy`, que es donde
  operaciones mira.
- **Verifica la firma Authenticode** del MSI antes de instalarlo: es lo que
  impide que un recurso compartido comprometido sirva un instalador manipulado a
  toda la organización.
- Si encuentra el agente instalado **pero con el servicio parado** —que es
  exactamente lo que deja un malware que consigue detenerlo— lo levanta y deja
  constancia.

### Piloto obligatorio de facto

`Deploy-AegisGPO.ps1` **avisa y pide confirmación** si la unidad organizativa
alcanza más de 500 equipos y no se ha indicado un grupo piloto. Con grupo
piloto, la GPO puede enlazarse a la unidad entera sin aplicarse todavía a todos:
ampliar el despliegue es añadir miembros al grupo.
