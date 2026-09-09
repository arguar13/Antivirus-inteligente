# Módulo 11 — Simulación de Red Team defensiva

> Componente: `tests/red_team_sim.py`, integrado como paso final de `make ci`.

Las pruebas unitarias comprueban que cada pieza hace lo que dice. La simulación
de Red Team comprueba algo distinto y complementario: que las defensas resisten
un **ataque real de extremo a extremo**, montado con las mismas primitivas que
usaría un atacante. No hay mocks: monta memoria ejecutable de verdad, manipula
señuelos de verdad en disco, parchea bytecode de verdad.

Cada escenario valida una fase concreta, y el script falla —y con él `make ci`—
si cualquier defensa cede.

---

## Los escenarios

### 1. Auto-defensa del binario (FASE 13)

Lee los bytes del binario compilado del agente y exige que **ninguna cadena
crítica aparezca en claro** (endpoints, marcadores de autodefensa, ruta del
socket), y que el binario de release esté **stripped** (sin tabla de símbolos).
Es la primera línea contra la ingeniería inversa: lo que un analista ve al abrir
el binario.

### 2. Inyección de shellcode en memoria RWX anónima (FASE 10)

Compila una víctima en C que reproduce la primitiva de un cargador reflectivo:
`mmap` de memoria **RWX anónima** y escritura en ella. Con la víctima viva, el
escáner de evasión analiza su PID real y tiene que marcarla. Si la inyección
pasara desapercibida, el análisis de la FASE 10 no serviría contra malware sin
fichero.

### 3. Manipulación de un señuelo de ransomware (FASE 9)

Despliega señuelos reales en un directorio, conservando sus sumas de
comprobación originales en memoria, y **reescribe uno con datos de alta
entropía** como haría un cifrador. El barrido de verificación tiene que
detectar la manipulación. Es importante que las sumas originales se conserven
en memoria durante el ataque: reconstruirlas leyendo el fichero después
captaría el estado ya manipulado como si fuera el bueno.

### 4. Integridad del bytecode eBPF (FASE 14)

Toma un `.bpf.o` compilado, **parchea un byte** como haría quien sustituye la
telemetría por la suya, y comprueba que la verificación por firma HMAC lo
**rechaza**. Es la defensa que impide que el agente cargue en el kernel un
programa que no es el suyo.

---

## Sobre el SIGKILL

Un `SIGKILL` de root no se puede impedir desde el proceso víctima: es una
limitación del sistema operativo, no del producto. La resiliencia ante la
terminación la aporta el **Watchdog** (FASE 22), que reinicia el agente
manteniendo las políticas activas. La "auto-defensa" que este script valida
ahora es la anti-ingeniería-inversa, que sí es responsabilidad del propio
binario. Cuando el watchdog esté, este script se ampliará con el escenario de
matar y verificar el reinicio.

---

## Por qué está en `make ci`

Es el último paso de la puerta de validación, después de las pruebas unitarias y
la compilación: necesita los binarios de ejemplo compilados y ejercita el
sistema entero. Si falta `python3` o un compilador de C, se omite en vez de
fallar —un CI que falla por algo que no es un defecto enseña a la gente a
ignorarlo—, pero donde están, un fallo de cualquier escenario es un fallo de la
puerta.
