# Módulo 110 — Integración, ola A: cuatro motores detrás del árbitro (FASE 2 del MP-16)

> [Modelo de amenazas](modelo-de-amenazas.md) que toca: **AM-1.5** (cegar
> telemetría: cada motor publica ahora el motivo de su «sin datos», no solo un
> contador), **AM-1.9** (ocultar el compromiso del kernel: la verificación
> cruzada de tareas entra en el agente, pero su detección aún no se ejerce en la
> matriz; el control del modelo, la atestación por TPM, sigue ausente) y
> **AM-2.1** (entrada del atacante: dos analizadores nuevos leen ficheros que un
> atacante escribe —`sshd_config`, `sudoers`, `authorized_keys`—, acotados a
> 1 MiB y sin `unsafe`).

> Informe de fase. Las cifras (crates enlazados, estado de cada crate, pruebas,
> medidas por imagen) **no se repiten aquí**: salen generadas en
> [matriz-capacidades.md](matriz-capacidades.md) y en el README. Este documento
> dice qué se hizo, qué no y por qué.

## Hecho

| Motor | Crate | Qué ve | Camino | Prueba en vivo |
|---|---|---|---|---|
| `integridad` | aegis-integridad | Una puerta trasera en `sshd_config`, `sudoers` o `authorized_keys`, dicha por su significado y con su autor | frío: relee un segundo después de la apertura | `integridad-en-vivo` |
| `memoria` | aegis-memhunter | Código sin fichero, carga reflexiva, *module stomping* en procesos que el agente ha visto | frío: tras un `exec`, tras un `ptrace` que escribe, y en ronda | — (pendiente del rango real) |
| `nucleo` | aegis-kintegrity | Procesos que el sistema esconde (tres censos comparados y confirmados) | frío, en hilo propio | `nucleo-en-vivo` |
| `baliza` | aegis-l7hunter | Mando y control por el ritmo de las conexiones | frío: análisis cada 10 s de las series que crecieron | — (pendiente del rango real) |

Todos nacen en **solo-auditoría**: señalan y nada más. La restauración de
integridad existe en el crate y no se ejecuta.

Cambios del contrato, todos con prueba:

- `Motor::mantener` entrega lo que el camino frío terminó, y el árbitro lo
  combina como cualquier otra aportación.
- Requisitos nuevos sondeados de verdad en el host: `MemoriaAjena`
  (CAP_SYS_PTRACE y Yama por debajo de 3) y `KfuncsTareas` (nombres en el BTF).
- Cada motor publica el **motivo** de su último «sin datos», no solo un contador.
- `Motor::Nucleo` en el vocabulario único (plano Plataforma).

## Hallazgos que dejó la matriz, cada uno arreglado en su causa raíz

1. **La matriz probaba un binario viejo.** El grupo `kernels` tomaba el agente de
   `dist-hermetico/` sin preguntar de qué árbol salía. Ahora el binario lleva la
   huella del árbol (`tools/huella-arbol.sh`, definición única) y la matriz se
   niega a arrancar si no coincide.
2. **Evasión en integridad.** El analizador de `sshd_config` aplicaba el último
   valor de cada directiva; sshd aplica el primero. Un `PermitRootLogin yes`
   insertado arriba abría root sin señal. Ahora: primer valor, bloques `Match`
   aparte y nombrados, forma `Clave=valor`.
3. **Las pruebas actuaban antes que su agente.** Esperaban «algún latido» y
   quedaba el de la prueba anterior; el agente nuevo tomaba la línea base después
   del cambio. Ahora cada prueba arranca su agente con un latido propio.
4. **Un rechazo del verificador se publicaba como falta de permisos.** kintegrity
   confundía EACCES con EPERM. Ahora lee el errno y adjunta la línea decisiva del
   verificador.
5. **Credenciales inventadas.** Un autor sin credenciales capturadas salía con
   `uid 4294967295`. Ahora se dice «credenciales no capturadas».
6. **Falso positivo de baliza** sobre el resolvedor DNS del propio sistema.
7. **El veredicto no decía qué vio cada motor.** En solo-auditoría el registro es
   el producto: ahora cada señal se imprime con su porqué.
8. **Premisa falsa en la prueba de integridad.** openSUSE Leap ya trae
   `PermitRootLogin yes`; plantarlo no cambia nada y el motor acertaba al callar.
   La prueba planta además un cambio que ninguna imagen trae.

## No hecho, y por qué

- **Detección de un proceso oculto, sin ejercer en la matriz.** En los kernels
  sin kfuncs de tareas el motor se declara degradado; en Ubuntu 24.04 (6.8) los
  kfuncs existen pero no se admiten en programas `syscall` (solo desde 6.10), y
  el agente lo declara en ejecución; en Fedora 44 el kernel o su política impiden
  ocultar un proceso montando sobre `/proc/<pid>`. Hay un rediseño con
  iteradores `iter.s/task` (6.7+) en curso. Mientras tanto la matriz mide **cero
  falsos positivos en reposo** y nada más: no se afirma que detecte.
- **`memoria` y `baliza` sin prueba en vivo** propia: llegan con el rango ATT&CK
  real (FASE 4), que ejecuta las técnicas dentro del rango declarado.
- **Rollback** no se integró: su gancho de permiso suspende cada apertura y un
  agente colgado colgaría el sistema. Diseño seguro escrito; implementación en
  curso.
- **Lectura de TLS en claro** (uprobes de l7hunter): gancho nuevo sobre
  bibliotecas de terceros, para una entrega propia.

## Muros

- La vista de espacio de PID de kintegrity solo cubre los primeros 65 536 PID;
  `pid_max` es 4 194 304 en Ubuntu y Fedora. Arreglo en curso.
- La ABI de eventos no trae el uid del autor: integridad lo lee de `/proc` un
  segundo después y puede no estar. Llevarlo en el evento es un cambio de ABI
  (versión 2).
