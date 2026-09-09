# Módulo 15 — Monitorización de integridad de ficheros (FIM)

> Componente: `crates/aegis-fim` (Rust, inotify + BLAKE3).

Un cambio no autorizado en `/etc`, en los directorios de arranque o en los
binarios del sistema es la firma de casi cualquier persistencia: una puerta
trasera en `sshd`, una tarea de cron maliciosa, un `sudoers` alterado, una cuenta
con UID 0 añadida a `/etc/passwd`. El FIM los detecta comparando el estado actual
contra una **línea base** conocida-buena.

El foco es **exclusivamente** ficheros de sistema críticos. Vigilar todo el disco
sería caro y ruidoso; la persistencia vive en un puñado de sitios conocidos
(`/etc`, `/boot`, `/bin`, `/sbin`, `/usr/bin`, `/etc/cron.d`).

---

## 15.1 inotify, no sondeo

Detectar una modificación releyendo todos los ficheros cada pocos segundos es
caro (hashea todo constantemente) y lento (entre sondeos hay una ventana ciega).
**inotify avisa al kernel de cada cambio** y el agente reacciona en milisegundos,
rehasheando solo el fichero que cambió. La prueba
`inotify_detecta_una_modificacion_real_en_milisegundos` inyecta una cuenta UID 0
en un `passwd` vigilado y comprueba que el evento llega y se convierte en alerta.

Se usa la API cruda de inotify por `libc` —cuatro llamadas al sistema y un parseo
de estructura de tamaño variable— en vez de una caja externa, para dejar la
superficie de kernel que toca el FIM en un único fichero auditable, sin arrastrar
una dependencia. Un barrido completo de respaldo cubre el caso de que la cola de
inotify se desborde y se pierda un evento.

---

## 15.2 BLAKE3, no SHA-256

El FIM recalcula el hash cada vez que un fichero cambia, y en el arranque el de
todos los ficheros vigilados. **BLAKE3 es varias veces más rápido que SHA-256** y
paraleliza internamente sobre un mismo fichero grande, así que el coste de
recalcular es una fracción. Para integridad —detectar que un fichero cambió— no
hace falta nada de SHA-2; lo que importa es resistencia a colisiones y velocidad,
y BLAKE3 es ambas. Se verifica contra los vectores oficiales de BLAKE3.

Los ficheros se hashean **en paralelo** repartidos entre hilos: en el arranque
hay cientos de ficheros de sistema, y hacerlo en serie retrasaría la protección.

---

## 15.3 Línea base y actualizaciones legítimas

La línea base es el mapa `ruta → hash` del estado íntegro. Una divergencia es una
modificación no autorizada: modificado (el hash cambió), añadido (un fichero que
no estaba), borrado (uno que estaba desapareció).

No todo cambio es un ataque: una actualización legítima del sistema cambia
binarios y configuración. `accept_current` marca el estado actual de un fichero
como el nuevo conocido-bueno, de modo que tras aplicar un parche por la vía
legítima (el módulo de actualización firmada de la FASE 18) el FIM no lo reporte
como manipulación.
