# Módulo 42 — Paridad de defensa en Windows: ETW-Ti y ObRegisterCallbacks

> Componentes: `kernel/windows/aegis/`, `kernel/windows/etwti/`,
> `tools/verificar-windows.sh`.

En Linux el agente se defiende con eBPF y LSM. En Windows hacen falta otras dos
piezas, y ninguna de las dos es opcional si el producto tiene que sobrevivir a
un atacante que ya es SYSTEM.

---

## 42.1 El descriptor de seguridad no protege de SYSTEM

Windows decide si un proceso puede abrir a otro consultando el descriptor de
seguridad. Contra un atacante con `SeDebugPrivilege` —que tiene cualquier cosa
que corra como SYSTEM, incluida casi toda la administración remota— ese
descriptor no sirve: el privilegio se lo salta.

`ObRegisterCallbacks` es el gancho del propio gestor de objetos. Se ejecuta
**después** de que Windows haya concedido el acceso y permite recortar la
máscara antes de que el handle llegue a manos del solicitante. Es la única forma
soportada de que un proceso de usuario sobreviva a SYSTEM.

### Se recorta, no se deniega

Devolver `STATUS_ACCESS_DENIED` rompe a quien pide `MAXIMUM_ALLOWED` —que es lo
que hacen muchas APIs de Windows por dentro— y convierte una protección en una
avería. Recortando, el llamante recibe un handle válido con menos derechos, que
es exactamente lo que Windows espera.

### Qué se quita, y por qué cada bit

| Derecho | El ataque concreto |
|---|---|
| `PROCESS_TERMINATE` | Matar el EDR: el primer paso de casi todo |
| `PROCESS_VM_WRITE` / `VM_OPERATION` | Parchear una comprobación o meter un hook: desactiva la detección **sin matar el proceso**, y el panel lo sigue viendo vivo |
| `PROCESS_VM_READ` | La clave privada de la flota vive en memoria y nunca toca el disco |
| `PROCESS_CREATE_THREAD` | Ejecutar código *dentro* del EDR, con su identidad |
| `PROCESS_SUSPEND_RESUME` | Congelarlo: no muere, pero deja de detectar |
| `PROCESS_DUP_HANDLE` | Obtener por la puerta de atrás el handle que se acaba de recortar |
| `THREAD_SET_CONTEXT` | Secuestro de hilo: cambiarle el puntero de instrucción |
| `THREAD_TERMINATE` | Matar los hilos uno a uno deja al EDR inerte sin haberlo matado |

### Qué NUNCA se quita, y por qué importa tanto como lo anterior

`PROCESS_QUERY_LIMITED_INFORMATION` y `SYNCHRONIZE`. Los usan el gestor de
tareas, WMI, el gestor de servicios y cualquier herramienta de inventario.

Un EDR que se los quite convierte su propio proceso en algo que el sistema no
puede describir: el usuario ve una entrada rara que no responde, el
administrador cree que la máquina está rota, y **la reacción normal a una
máquina rota es desinstalar el EDR**. La auto-defensa que hace que te
desinstalen no defiende nada.

### Cuatro casos en los que no se toca nada

1. **El kernel.** Abre handles contra todo constantemente —el gestor de memoria,
   el planificador, el propio subsistema de objetos—. Recortarle un bit no
   protege de nada (quien ya está en el kernel no necesita un handle) y rompe el
   sistema operativo de formas que se manifiestan como pantallazos aleatorios.
2. **Procesos ajenos.** Solo nos defendemos a nosotros. Filtrar handles contra
   procesos del cliente convertiría el EDR en la razón por la que sus
   aplicaciones fallan.
3. **El proceso consigo mismo.** Sus propios hilos, su manejo de excepciones y
   su recolector abren su propio proceso. Recortárselo es romperse a uno mismo.
4. **Los demás componentes de AegisCore**, verificados por firma. El watchdog
   tiene que poder supervisar al agente y reiniciarlo: sin esta excepción, la
   auto-defensa impediría la auto-recuperación.

### Un PID no es una identidad

La lista de procesos protegidos guarda el PID **y la hora de creación**. Un PID
se reutiliza, y proteger «el PID 4820» después de que ese proceso muera
significa proteger a lo que el sistema ponga ahí después. Es un fallo clásico y
silencioso.

---

## 42.2 ETW-Ti se consume desde usuario, no desde el driver

`Microsoft-Windows-Threat-Intelligence` es la única fuente **soportada** de
eventos de `VirtualAllocEx`, `WriteProcessMemory`, `NtQueueApcThread` y
`SetThreadContext` entre procesos. Sin ella hay que parchear el kernel, lo que
rompe PatchGuard.

Windows no ofrece API soportada para consumir ETW desde el kernel: lo que hay en
el kernel es la parte proveedora. **Un producto que afirmara que su driver «se
suscribe a ETW-Ti» estaría describiendo algo que no existe.** El consumidor es
el servicio del agente, y solo puede suscribirse si corre como PPL-Antimalware:

```
driver ELAM firmado con certificado ELAM de Microsoft
        │   (sección de recursos con MSElamCertInfoID)
        ▼
servicio con PPL-Antimalware
        ▼
suscripción a Microsoft-Windows-Threat-Intelligence
```

Sin ELAM no hay PPL; sin PPL no hay ETW-Ti. Y sin el EKU de protección
antimalware (`1.3.6.1.4.1.311.61.4.1`) no hay `ObRegisterCallbacks`. Tres
requisitos encadenados; el driver deja constancia del código de error exacto
cuando uno falta, para que no haya que adivinarlo.

### La regla de oro de la clasificación

**La operación sobre uno mismo no es inyección.** Un compilador JIT reserva y
hace ejecutable su propia memoria constantemente. Un EDR que avisara de eso
enterraría al analista en ruido hasta que dejara de mirar — y entonces la
detección de verdad tampoco se vería.

| Evento | Severidad | Por qué |
|---|---|---|
| RWX en **otro** proceso | Crítica | El cargador de shellcode clásico |
| Memoria de datos en otro proceso | Media | Raro, pero lo hacen inyectores de DLL legítimos |
| `RW → RX` en otro proceso | Crítica | El cargador que **evita** reservar RWX para no llamar la atención: reserva RW, escribe, y luego pasa a ejecutable. Esa transición remota casi no tiene uso legítimo |
| Sección ejecutable mapeada en otro proceso | Alta | La variante que evita `WriteProcessMemory` por completo |
| APC de usuario en un hilo ajeno | Crítica | La primitiva de la inyección por APC, y de la variante *early bird* |
| `SetThreadContext` ajeno | Crítica | Secuestro de hilo |
| Cualquiera de las anteriores en el **propio** proceso | Informativa | JIT, E/S alertable: el trabajo normal de un programa |

Un origen declarado como depurador **se rebaja a informativa, no se descarta**:
si alguien secuestra esa autorización, la evidencia sigue estando.

---

## 42.3 Lo que se puede verificar sin Windows, y por qué se hizo así

El driver solo se compila con el WDK, en Windows. Pero la parte que puede estar
mal **de forma peligrosa** no es la fontanería del driver: es la decisión.
Quitar un bit de más deja al usuario sin gestor de tareas; quitar uno de menos
deja al atacante matar el EDR.

Así que la decisión —recorte de acceso y clasificación de ETW-Ti— es C portable,
sin una línea del WDK, en `aegis_politica.c`. El driver incluye **ese mismo
header**, así que no hay dos definiciones que puedan divergir. Y se ejercita en
cada `make ci`, con **gcc y con clang**: un comportamiento que dependa del
compilador, en código que decide si el producto se defiende, es por sí mismo un
defecto.

**33 afirmaciones**, cada una con el ataque o la avería que impide.

### El error que esto encontró

Al escribir el despacho del driver cometí un error de copia-pega real: la rama
de `OB_OPERATION_HANDLE_DUPLICATE` **de proceso** llamaba a la política **de
hilo**. Las máscaras de proceso y de hilo comparten números pero significan
cosas distintas, así que el recorte no habría fallado de forma visible: habría
dejado pasar derechos peligrosos a cualquiera que duplicara un handle ya
abierto.

`tools/verificar-windows.sh` comprueba estáticamente ese despacho —qué política
llama cada rama, que las dos operaciones estén cubiertas, que los callbacks se
desregistren al descargar—. Se comprobó que el chequeo **falla** con el error
reintroducido y **pasa** sin él; si no, sería una comprobación decorativa.

### Lo que NO se verifica aquí

La compilación del driver con el WDK y su comportamiento en un Windows real. El
CI lo dice explícitamente en vez de dejarlo en un comentario del código:

```
==> Windows · politica de auto-defensa y clasificacion ETW-Ti
    OK: 33 afirmaciones de la politica de Windows se cumplen.  (gcc)
    OK: 33 afirmaciones de la politica de Windows se cumplen.  (clang)
==> Driver WDK: no se compila aqui (hace falta WDK y Windows).
    La decision SI se comprueba, arriba. La fontaneria del driver no.
```

---

## 42.4 Si el registro falla, se arranca igual

Si `ObRegisterCallbacks` falla —típicamente por la firma— el driver **no** se
niega a cargar. El resto de la protección sigue siendo útil, y un endpoint sin
ninguna protección es peor que uno sin auto-defensa. Lo que no se hace es
callarlo: queda con su código de error y el agente lo reporta al plano de
control como degradación.

Fallar al cargar convertiría un problema de firma en una flota entera sin EDR,
que es exactamente lo que un atacante conseguiría manipulando el almacén de
certificados.

---

## 42.5 Uso

```bash
# La parte verificable, en cualquier máquina
./tools/verificar-windows.sh

# El driver, en Windows con el WDK
msbuild kernel\windows\aegis\aegis.vcxproj /p:Configuration=Release /p:Platform=x64
signtool sign /fd sha256 /ac ELAM.cer /f aegis-antimalware.pfx aegis.sys
```
