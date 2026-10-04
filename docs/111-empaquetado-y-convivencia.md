# Módulo 111 — Empaquetado, ciclo de vida y convivencia (FASE 3 del MP-16)

> [Modelo de amenazas](modelo-de-amenazas.md) que toca: **AM-1.2** (parar o
> quitar el agente: la desinstalacion exige token, y contra root queda el
> latido que deja de llegar).

Lo que se instala, como se actualiza y se revierte, como se
quita, y con quien comparte el host. Todo lo que aqui se afirma lo ejerce una
prueba de la matriz de kernels (`paquete-en-vivo`, `convivencia-en-vivo`,
`sobrecoste-en-vivo` en [`tools/config/kernels.toml`](../tools/config/kernels.toml));
lo que ninguna prueba ejerce esta en la ultima seccion, con su motivo.

Ninguna cifra de este documento se escribe a mano: los tiempos, el sobrecoste y
los picos de memoria salen de las lineas `AEGIS-MEDIDA` de la matriz y los
publica la matriz de capacidades.

## Lo que instala el paquete

| Ruta | Que es |
|---|---|
| `/usr/libexec/aegis/aegis-watchdog` | proceso principal de la unidad; lanza y vigila al agente |
| `/usr/libexec/aegis/aegis-agent` | el agente; tambien es el trabajador confinado (`--trabajador`) |
| `/usr/libexec/aegis/VERSION` | la version del paquete (el agente no tiene `--version`) |
| `/usr/bin/aegisctl` | CLI del socket de control (solo donde se publica: hoy x86-64) |
| `/usr/lib/systemd/system/aegis-agent.service` | la UNICA unidad |

Y crea al instalar, fuera de lo que el gestor posee:

| Que | Quien lo crea | Quien lo quita |
|---|---|---|
| `/etc/systemd/system/aegis-agent.service.d/10-presupuesto.conf` | postinst (`aegis-watchdog --unidad`) | postrm |
| cuenta `aegis-trabajador` (uid 64701, reservado con nombre) | postinst, si el uid esta libre | postrm, si la creo el paquete |
| `/run/aegiscore/` | systemd (`RuntimeDirectory`) | systemd al parar; postrm por si acaso |
| `/var/lib/aegiscore/` (cuarentena, linea base del motor rol) | systemd (`StateDirectory`) | purga (dpkg) o `AEGIS_PURGAR=1` (rpm) |
| `/etc/aegiscore/` (enlace con el plano de control y su PKI, resumen del token de desinstalacion) | el operador o el rol de Ansible | purga (dpkg) o `AEGIS_PURGAR=1` (rpm) |
| `/var/lib/aegiscore/anterior/` | preinst, al actualizar | postinst si la nueva late; postrm |
| cgroup `aegis-agent.service/{supervision,aegis-trabajador-*}` | watchdog y agente (`Delegate=yes`) | systemd al parar |

Un solo directorio de configuracion, `/etc/aegiscore`: el que lee el agente
(`/etc/aegiscore/plano-control.toml`, H-23) y el que la purga borra entero. Con
dos (`/etc/aegis`, el del rol de Ansible anterior, y `/etc/aegiscore`, el del
enlace), una purga que solo conociera el primero dejaria en el host
retirado la identidad con la que seguiria pudiendo hablar con la flota (H-41).

`/usr/libexec` y no `/usr/lib/aegis`: con SELinux, lo que hay bajo `/usr/lib`
se etiqueta `lib_t`, que no es un ejecutable de servicio; `/usr/libexec` es
`bin_t` en Fedora, RHEL/Rocky y SUSE, y systemd lo arranca en
`unconfined_service_t`. En Debian y Ubuntu la ruta es igual de valida.

## La unidad, y por que cada decision

Una sola unidad cuyo proceso principal es el watchdog. Las capacidades son las
que el agente usa HOY (la lista y el motivo de cada una estan en la propia
unidad, [`deploy/paquete/aegis-agent.service`](../deploy/paquete/aegis-agent.service));
la matriz comprueba en el proceso vivo que estan las necesarias y que NO estan
`CAP_SYS_MODULE`, `CAP_DAC_OVERRIDE` ni `CAP_NET_RAW`.

Protecciones de systemd que se dejan FUERA a proposito:

| Opcion | Por que no |
|---|---|
| `PrivateTmp=yes` | el motor estatico lee por ruta el ejecutable notificado; con un `/tmp` privado, `/tmp/x` seria otro fichero, y `/tmp` es donde cae lo primero que se descarga un atacante |
| `ProtectKernelModules=yes` | esconde `/usr/lib/modules`, que la integridad del nucleo compara |
| `ProtectClock=yes` | implica `DeviceAllow=char-rtc r` y cierra el resto de `/dev` (TPM incluido) |
| `PrivateDevices`, `ProtectProc`, `ProcSubset` | un EDR tiene que ver `/proc` y `/dev` enteros |

`Delegate=yes`: el subarbol de cgroup del servicio es del agente. El watchdog se
baja a la hoja `supervision` y el agente cuelga de alli el cgroup del
trabajador. Antes el trabajador se creaba en la RAIZ de `/sys/fs/cgroup`, que es
de systemd: podia quitarle el reparto de `cpu` al reajustar la raiz, y la parada
del servicio no lo alcanzaba. Consecuencia que se acepta y se mide: la memoria
del trabajador cuenta en el `MemoryMax` del servicio; su techo es el hueco entre
`MemoryHigh` y `MemoryMax` de la unidad, y su `oom_score_adj` es 1000 para que
un OOM del servicio mate al trabajador y nunca al nucleo.

El trabajador se relanza desde `/proc/self/exe` y no por su ruta: al actualizar,
la ruta ya es el binario NUEVO, y un trabajador relanzado entre el
desempaquetado y el reinicio del postinst tiene que ser de la version que habla
su protocolo. Su linea de ordenes (`argv[0]`) es la ruta del agente; su `comm`,
el nombre corto que muestran `ps -e`, `top` y los registros de auditoria, es
`exe`. Por eso la prueba reconoce sus denegaciones por `exe=/usr/libexec/aegis/`
y no por `comm`.

## Ciclo de vida

| Paso | dpkg | rpm | Lo que se exige en la matriz |
|---|---|---|---|
| instalar | `preinst install`, `postinst configure` | `%pre 1`, `%post 1` | late; habilitado; drop-in con `MemoryMax`; uid reservado; capacidades justas; SELinux/AppArmor sin denegaciones |
| actualizar | `prerm upgrade` (no para), `preinst upgrade` (copia), `postinst configure` (reinicia y espera latido) | `%pre 2`, `%post 2`, y los `%preun 1`/`%postun 1` del viejo, que no hacen nada | proceso nuevo; latido nuevo; la copia se borra |
| version que no late | `postinst` restaura los binarios anteriores, deja `revertido` y sale con 1: half-configured | igual; el `%post` falla | binario ELF anterior latiendo; el gestor la marca; reconfigurarla se niega |
| reconciliar | `dpkg -i` de la anterior | `rpm -U --oldpackage` de la anterior | `dpkg -V` / `rpm -V` limpios |
| quitar sin token | `prerm remove` sale con 1; `postinst abort-remove` | `%preun 0` sale con 1; rpm aborta | el agente sigue |
| quitar con token | `prerm`, `postrm purge` | `%preun 0`, `%postun 0` con `AEGIS_PURGAR=1` | ni procesos, unidad, drop-in, enlace, `/run`, cgroups, cuenta, ficheros ni registro del gestor |

La vuelta atras es de BINARIOS, no de la base de datos del gestor: el host
vuelve a estar protegido por la version anterior en segundos, y el gestor queda
en la nueva marcada como fallida hasta que alguien reconcilia. Es la forma
honesta: ni dpkg ni rpm (que quito su `--rollback`) deshacen una transaccion
desde un script de mantenimiento.

El token de desinstalacion frena a un script, a un operador despistado o a un
malware que llama al gestor. NO frena a root, que puede borrar el resumen o los
ficheros: contra root queda que el latido desaparece y el plano de control lo
ve (modelo de amenazas, AM-1.2).

## Reproducible

`tools/empaquetar.sh --comprobar-reproducible` construye dos veces y compara los
SHA-256 (grupo `paquetes` de `make ci`): fechas fijadas a `SOURCE_DATE_EPOCH`
(la del commit), dueño root, orden estable, xz de un hilo, `_buildhost` fijo y
`use_source_date_epoch_as_buildtime` en rpm. Compresion xz a proposito: el
dpkg-deb de Ubuntu comprime con zstd por defecto y el dpkg de Debian 11 no lo
abre.

## Convivencia

| Vecino | Conflicto real | Que hace AegisCore | Prueba |
|---|---|---|---|
| SELinux enforcing (Rocky 9, Fedora 44) | un binario mal etiquetado no arranca o corre en otro dominio | `/usr/libexec` (`bin_t`), `restorecon` tras la vuelta atras; corre en `unconfined_service_t` | `paquete-en-vivo`: dominio del proceso y 0 AVC con `comm=aegis-*` |
| AppArmor (Ubuntu, Debian, Leap) | ninguno hoy: no hay perfil y corre `unconfined`. La restriccion de userns de Ubuntu 24.04 no aplica: el trabajador hace `unshare(CLONE_NEWNET)` como root con `CAP_SYS_ADMIN`, no un userns sin privilegios | nada que hacer | `paquete-en-vivo`: perfil `unconfined` y 0 `apparmor="DENIED"` |
| auditd | con reglas anchas, cada exec/open del propio agente genera registros; si auditd va lento y el backlog se llena, el kernel duerme a CUALQUIER proceso que audite (`backlog_wait_time`), el agente incluido | se recomienda excluirlo: `-a never,exit -F exe=/usr/libexec/aegis/aegis-agent` | `convivencia-en-vivo`: regla sobre execve, los dos ven la rafaga, 0 perdidos |
| Otro programa eBPF en los mismos tracepoints (Falco, Tetragon, otro EDR) | ninguno: el kernel encadena los programas del mismo tracepoint. SI habria conflicto en XDP (un programa por interfaz sin dispatcher) y en BPF LSM (cualquier denegacion gana), que el agente aun no usa | nada hoy; al activar XDP/LSM, deteccion y degradacion declarada | `convivencia-en-vivo`: segundo consumidor (nuestro binario), los dos ven, al irse uno el otro sigue |
| Antivirus con fanotify de permiso (clamonacc, MDE, ESET) | el analista del agente lee por ruta: su lectura espera a que el otro conteste | el camino caliente no depende del analista | `convivencia-en-vivo`: vecino que tarda 15 s; latido y eventos siguen; matarlo no cuelga nada |
| Contenedores con seccomp propio | una llamada que el seccomp del contenedor rechaza NO llega a la sonda `sys_enter_*`: en el kernel, seccomp va antes que el tracepoint de entrada | declarado: se ve el intento que el kernel ejecuta, no el que el contenedor prohibe | no ejercido (sin runtime de contenedores en las imagenes) |
| `lockdown=integrity` / `confidentiality` | `confidentiality` prohibe leer memoria del kernel desde BPF | `--capacidades` lo detecta y lo declara degradado | no ejercido (exige arrancar con otro cmdline) |
| Otro EDR comercial | desconocido: sus licencias no se pueden meter en la matriz | el playbook avisa si ve `/opt/CrowdStrike`, `/opt/sentinelone`, `/opt/microsoft/mdatp` | no ejercido |

## Lo que no se ha probado, y por que

- **Otro EDR real** (Falco, Tetragon, MDE, CrowdStrike): el segundo consumidor
  eBPF es nuestro propio agente. Prueba que dos programas en el mismo
  tracepoint no se estorban; no prueba el comportamiento de un tercero.
- **auditd donde la imagen no lo trae** (Ubuntu y Debian cloud): la matriz no
  instala nada desde la red; la prueba lo declara «NO-EJERCIDO» y la medida
  `convivencia_auditd_ejercida` vale 0.
- **Lockdown y Secure Boot**: las imagenes arrancan sin Secure Boot; cambiar el
  cmdline exige un segundo arranque que la matriz no hace.
- **Contenedores con seccomp**: sin podman/docker en las imagenes.
- **Terraform**: despliega el PLANO DE CONTROL en AWS; ejecutarlo exige una
  cuenta de AWS (muro del propietario). El rol de Ansible instala este mismo
  paquete, pero no se ha ejecutado contra las VMs de la matriz, que no tienen SSH.
