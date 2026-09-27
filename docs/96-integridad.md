# Módulo 96 — AegisIntegrity: integridad sin carrera y por significado (FASE 104)

> Componentes: `crates/aegis-integridad/` (sustituye a `crates/aegis-fim/`),
> ampliación de `crates/aegis-selfdefense/`, `tools/verificar-integridad.sh`.

## 96.1 Las cuatro cosas que lo separan de Wazuh FIM, AIDE y Tripwire

1. **Sin carrera, y con AUTOR.** `inotify` —lo que usan Wazuh FIM y lo que usaba
   `aegis-fim`— dice «este fichero cambió». No dice quién. Para saberlo hay que ir
   a `/proc` **después** del evento, y para entonces el atacante ya recicló el PID:
   esa es la carrera TOCTOU que la invariante 9 prohíbe. Aquí el cambio nace de un
   `aegis_sensor::Evento` del gancho LSM (FASE 103) y lleva su autor —proceso,
   credenciales y **linaje**— capturado **en el kernel**. Es la diferencia entre
   «cambió `authorized_keys`» y «lo cambió un shell **descendiente del servidor
   web**, con euid 0 tras escalar». Verificado por lo que **falta**: cero
   relecturas de `/proc` o del disco en el crate.
2. **Por significado, no por hash.** Los ficheros de configuración se **parsean** y
   el cambio se expresa en su semántica: «`PermitRootLogin` cambió de `no` a `yes`»,
   «se concedió `NOPASSWD` a `alice`», «se añadió esta clave autorizada». Un diff de
   hash no distingue un comentario de una puerta trasera; aquí un cambio de solo
   comentarios o espacios produce **cero** alertas, y la puerta trasera se ve. Es lo
   que separa una alerta accionable del ruido que entrena a ignorar al FIM.
3. **Línea base firmada y sellada contra el TPM.** El fallo clásico de AIDE y
   Tripwire: un atacante con root reescribe el fichero **y** la base de datos de
   integridad, y la recalcula. Aquí la línea base la **firma el plano de control**
   (firma híbrida Ed25519 + ML-DSA-65) y se **sella contra un PCR**. Root puede
   reescribir los bytes, pero no puede volver a firmarla sin la clave privada del
   plano de control ni reproducir el sello de un arranque que no ocurrió: la firma
   deja de verificar y el cambio se ve. **Root no basta.**
4. **Cobertura de lo que no es un fichero.** La persistencia no vive solo en `/etc`:
   unidades de systemd, `cron`, módulos del kernel, `initramfs`, entradas de
   arranque, ACL, atributos extendidos, capacidades de fichero y el **propio árbol
   del agente**. Cada objeto se reduce a una identidad estable y una huella
   canónica; las clases están en el tipo, así que la cobertura es comprobable.

## 96.2 El propio agente: proteger la CAPACIDAD DE AVISAR, no solo el proceso

PPL protege el proceso: impide que lo maten. Pero un atacante con kernel no lo mata
—lo **ciega**: le corta la telemetría—, y el proceso sigue vivo, sano en
apariencia, sin nada que contar. Lo que importa no es que el proceso siga en pie,
sino que la **capacidad de avisar** sobreviva. Por eso tres centinelas se vigilan:
el programa del **kernel** vigila al **proceso**, el **proceso** vigila a los
programas del kernel, y el **plano de control** (remoto) vigila a los dos.
Silenciar a cualquiera produce una **señal** desde otro —para no dejar ni un aviso
hay que matar a los tres a la vez, y el remoto es el más difícil—. La muerte del
agente es un **evento de seguridad con su testigo** («yo, el kernel, vi morir al
proceso»), no la ausencia de un latido interpretada tarde. Y la manipulación se
**clasifica** con su evidencia: torpe (matar), competente (parar el servicio y
borrar la unidad), con root (tocar ficheros y la línea base), con kernel
(desenganchar los programas).

La **invariante 10** se vuelve a comprobar: por muy endurecido que esté el agente,
el dueño de la flota **siempre** puede desinstalarlo con un OTP del plano de
control. Hay una prueba que recorre todos los vectores de manipulación y, después,
la desinstalación autorizada.

## 96.3 La frontera, dicha en voz alta

El inventario de `drivers/linux/aegis-bpf` (hecho antes de escribir una línea, como
manda el disparador) dice la verdad incómoda: **hoy no existe ningún gancho LSM en
ese árbol**. Solo hay tracepoints de `sys_enter_*`, que (a) solo **ven**, no pueden
negar; (b) tienen **carrera** —disparan antes de la operación y leen la ruta de un
puntero de usuario—; y (c) **no capturan credenciales**. Para «integridad sin
carrera con autor en el instante del cambio» hay que introducir un programa
**LSM-BPF nuevo** (`security_file_open`, `path_rename`, `inode_unlink`,
`bprm_check`...) que lea `task->cred`. Sobre este entorno **BPF LSM está activo**
(FASE 103), así que ese gancho **se puede** enganchar; construirlo es el incremento
siguiente. Lo que se entrega aquí es el **lado que decide**, que es race-free **por
construcción**: solo actúa sobre lo que el evento capturó, y jamás relee el sistema.

## 96.4 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Cambio con autor (proceso, credenciales, linaje) | **sí** | nace de un `Evento` del kernel; conserva la ruta del instante aunque el mundo cambie |
| Cero relectura de `/proc`/disco (invariante 9) | **sí, por ausencia** | `verificar-integridad.sh` cuenta cero lecturas del sistema en el crate |
| Cambio por significado (sshd, sudoers, authorized_keys) | **sí** | un comentario nuevo no es alerta; `PermitRootLogin yes`, `NOPASSWD`, clave nueva sí |
| Línea base firmada: root no puede recalcularla | **sí** | root reescribe y re-firma con su clave → `FirmaInvalida` con la clave del plano de control |
| Línea base sellada contra PCR | **sí** | un PCR distinto (arranque cambiado) → `SelloRoto` |
| Cobertura de lo que no es un fichero | **sí, modelada** | 9 clases de objeto con identidad y huella canónica; un cambio se detecta |
| Recuperación como acción, nunca automática | **sí** | `PropuestaRestauracion` no tiene `es_automatica()=true`; sin base atestada no se propone |
| Vigilancia mutua a tres bandas | **sí** | matar a cualquiera de los tres produce señal desde otro; la muerte es un evento con testigo |
| Clasificación de la manipulación | **sí** | torpe/competente/con-root/con-kernel por la evidencia más grave |
| Desinstalación autorizada tras todo ataque (inv. 10) | **sí** | OTP híbrido real verifica y `tamper::decidir` permite |
| Parseo semántico de systemd/cron/módulos | **incremento siguiente** | hoy se cubren por huella canónica opaca; el significado de esos formatos se añade encima |
| Captura eBPF-LSM en vivo con `task->cred` | **frontera** | vive en `drivers/linux/aegis-bpf`; BPF LSM activo lo habilita; aquí se prueba el lado que decide |
| Des-sellado real contra el chip TPM | **muro de entorno (gated)** | como en `aegis-attest`, la fontanería del chip va tras una feature de hardware |
| PPL/ELAM en Windows | **muro declarado** | necesitan el certificado de Microsoft; se compensa con la vigilancia mutua, y la tabla de qué para PPL vs. qué para la vigilancia mutua es un incremento medido declarado |

El alcance por partes es la decisión honesta: se construye el mecanismo distintivo
—autor sin carrera por construcción, significado, línea base que root no puede
falsificar, vigilancia mutua— y la captura LSM en vivo, el parseo semántico de más
formatos y la tabla medida contra PPL se añaden sobre estos cimientos, en vez de
afirmar una cobertura que no se ejerció.

Mensaje de commit:
`feat(integrity): implement race-free semantic file integrity with TPM-sealed baselines and mutual agent tamper watch`
