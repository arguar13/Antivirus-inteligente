# Módulo 8 — Blindaje del agente contra ingeniería inversa

> Componente: `crates/aegis-harden` (Rust) + `tools/obfuscate.py`.

El malware que se topa con un EDR tiene dos caminos: evadirlo o desactivarlo.
Los dos empiezan por entenderlo, y entenderlo empieza por abrir el binario en
Ghidra o adjuntarle un depurador. Este módulo sube el coste de ambas cosas.

**La promesa es honesta: "sube el coste", no "es irrompible".** Un producto de
seguridad que mintiera sobre su propia resistencia sería una contradicción. Cada
técnica de aquí tiene un límite conocido, y se documenta.

---

## 8.1 Cifrado de cadenas críticas

### El problema

Un binario compilado lleva sus cadenas en claro. `strings agente` revelaría de
un vistazo los endpoints de la nube, los nombres de las reglas YARA, las rutas
que vigila y los marcadores internos: un mapa del producto regalado. Es lo
primero que mira cualquier analista y lo más barato de conseguir.

### El mecanismo

Las cadenas sensibles **no se compilan en claro**. `tools/obfuscate.py` las
cifra con **AES-256-GCM** y genera `crates/aegis-harden/src/generated_strings.rs`
con una tabla de textos cifrados. En el binario solo hay ruido. Al arrancar, el
agente deriva la clave y descifra la tabla en un `Vault` que se pone a cero al
liberarse.

```
tools/secrets.json  ──(obfuscate.py, AES-256-GCM)──►  generated_strings.rs
   (texto en claro)                                      (solo texto cifrado)
                                                              │
                                              arranque del agente: Vault::unseal
                                                              │
                                                   cadenas en memoria, cifradas en disco
```

### La derivación de clave

La clave de 256 bits es `SHA-256(shard0 ‖ shard1 ‖ shard2 ‖ shard3 ‖ sal ‖
contexto)`. Los cuatro fragmentos de 64 bits están **dispersos a propósito**: no
hay 32 bytes contiguos en el binario que un analista pueda reconocer como "la
clave". El paso de SHA-256 rompe además cualquier relación visible entre los
fragmentos y los bytes de la clave.

### El límite, sin adornos

La clave **tiene que estar en el binario** para que el propio binario pueda
descifrarse. Es una propiedad inherente de la ofuscación de cadenas, no un
defecto de esta implementación: detiene el análisis **estático** (`strings`, la
vista de cadenas de Ghidra/IDA, un `grep`), no a un analista con un depurador
que lea la memoria descifrada. Por eso el blindaje no se queda aquí.

### Interoperabilidad verificada

La derivación de clave y de nonce es idéntica en Python y en Rust, byte a byte.
El cifrado lo hace `tools/obfuscate.py` con OpenSSL (vía `libcrypto`), y el
descifrado el crate con la caja `aes-gcm`: **dos implementaciones
independientes que tienen que coincidir**. Un cifrado que solo se probara contra
su propio descifrado no demostraría nada. La prueba
`lo_que_cifra_python_lo_descifra_el_crate` lo comprueba sobre las ocho cadenas
reales, y `las_cadenas_no_aparecen_en_claro_en_el_fichero_generado` verifica que
ningún texto en claro sobrevive en el código generado.

Los nonces son deterministas (derivados de la clave y del contenido), de modo
que la salida es **reproducible**: el fichero generado se versiona, y
`tools/obfuscate.py --check` —incluido en `make ci`— detecta si alguien cambió
una cadena sin regenerar.

---

## 8.2 Anti-depuración

### Por qué un EDR se defiende de los depuradores

Un agente que se deja depurar entrega su lógica de detección al atacante: puede
ver exactamente qué se detecta, cómo y con qué umbrales. La anti-depuración le
niega esa ventaja al analista oportunista y al análisis automatizado.

### Los dos mecanismos

En Linux un proceso solo puede tener **un** trazador a la vez. De ahí salen dos
comprobaciones complementarias:

1. **`TracerPid` de `/proc/self/status`.** Si ya hay un depurador adjunto, ese
   campo trae su PID. Es una lectura pura: detecta al depurador que arrancó el
   proceso bajo su control, sin cambiar nada.
2. **`ptrace(PTRACE_TRACEME)`.** El proceso se declara trazado por su padre. Si
   ya había un trazador, la llamada **falla** y lo delata. Si no lo había, ocupa
   el único hueco de trazador, de modo que un depurador que intente adjuntarse
   **después** se encuentra el sitio tomado. Una sola llamada detecta al que ya
   estaba y bloquea al que vendría.

### Dos políticas, y por qué la agresiva es opcional

`Policy::ReportOnly` solo informa. `Policy::Terminate` cierra el proceso con
`_exit` —sin desenredar la pila, que le daría al analista el mensaje y el
rastro— en cuanto detecta un depurador.

La respuesta agresiva se activa con `--harden`, **no por defecto**, por una
razón operativa concreta: un proceso que ha reclamado el trazador convierte la
señal de parada del sistema (SIGTERM) en una parada de trazado en vez de una
terminación. Un supervisor genérico que lo detenga con `kill` se quedaría
esperando. En producción el agente lo lanza el watchdog, que sabe de esto y pasa
`--harden`; en un arranque manual o bajo un supervisor genérico, la comprobación
pasiva (`TracerPid`) sigue activa y es segura.

### El límite

`ptrace` se puede interceptar desde un kernel modificado o con `LD_PRELOAD` sobre
la libc. Como el cifrado de cadenas, esto sube el coste, no lo hace infinito. Las
dos técnicas juntas —estática y dinámica— dejan fuera al atacante oportunista y
al script que automatiza el análisis, que es el objetivo realista de un producto
que también tiene que caber en 45 MB de RAM.

---

## 8.3 Blindaje del binario compilado

El perfil de `release` (en `Cargo.toml`) elimina todo lo que ayuda a un
desensamblador a partir de algo:

| Opción | Efecto |
|---|---|
| `strip = true` | Borra la tabla de símbolos **y** la información de depuración: sin nombres de función ni líneas de código. |
| `debug = false` | No se emite DWARF que reintroduzca esos nombres. |
| `lto = "fat"` + `codegen-units = 1` | El inlining agresivo disuelve los límites de función, de modo que ni siquiera la estructura del código refleja el fuente. |
| `panic = "abort"` | Sin tablas de desenrollado de pila que revelen la estructura de llamadas. |

---

## 8.4 Integridad del bytecode eBPF (Ring 0)

### El problema

El agente carga en el kernel unos programas eBPF compilados a parte. Entre que
se compilan y que se cargan hay una ventana, y un programa en Ring 0 con los
permisos del agente es lo más valioso que puede robar un atacante. Cargarlo con
las manos del defensor es la vía más limpia: bastaría sustituir un `.bpf.o` por
otro.

El bytecode se empotra en el binario del agente con `include_bytes!`, así que no
hay un `.o` suelto que sustituir. Pero el binario en disco sí se puede parchear:
la defensa es **firmar el bytecode y verificarlo antes de cargarlo**.

### Por qué HMAC y no un hash

Un `sha256sum` detecta la corrupción accidental, no al atacante: si cambia el
bytecode, recalcula el hash y ya está. El **HMAC-SHA256** exige una clave que el
atacante no tiene. Puede cambiar el bytecode, pero no puede producir el HMAC
válido sin la clave, así que la comparación falla.

```
build.rs (compilación)                 bpf.rs (arranque)
─────────────────────                  ─────────────────
HMAC(clave, bytecode) ──► constante ──► HMAC(clave, BPF_OBJECT)
                          empotrada          │
                                      ¿coincide? ── no ──► BytecodeTampered, no se carga
```

La verificación es lo **primero** que hace el cargador, antes incluso del
preflight del entorno: no tiene sentido comprobar capacidades o BTF para un
binario en el que ya no se confía. Y la comparación es en **tiempo constante**,
para no filtrar por el tiempo de respuesta cuántos bytes acertó un atacante.

### El pipeline de firma

`drivers/linux/aegis-bpf/tools/sign_bytecode.py` firma los `.bpf.o` compilados y
escribe `out/bytecode.manifest` (formato `nombre  hex64`, como `sha256sum`).
`make check-integrity` —incluido en `make ci`— verifica que los objetos
compilados coinciden con sus firmas.

La firma la produce Python (HMAC-SHA256 de la biblioteca estándar) y la verifica
el crate `aegis-kguard` (la caja `hmac` de Rust): **dos implementaciones
independientes que tienen que coincidir**, comprobado tanto contra el vector 2
de la RFC 4231 como en una prueba de interoperabilidad directa.

En desarrollo la clave es fija y pública (no debilita nada mientras solo firme
el pipeline de desarrollo). En producción es un secreto de compilación que se
pasa por `AEGIS_BPF_HMAC_KEY` y sustituye a la de desarrollo.

## 8.5 Bloqueo de permisos de los mapas eBPF

Los mapas eBPF son la memoria compartida entre Ring 0 y Ring 3: el ring buffer
de eventos, la configuración, las tablas de estado. Cuando un mapa se **fija**
(pin) en el sistema de ficheros bpf para sobrevivir a reinicios del agente,
aparece como un fichero con permisos. Fijado con permisos laxos, cualquier
usuario podría volcar su contenido —rutas vigiladas, PIDs, configuración de
detección— o escribir en la configuración para desactivar sondas.

La regla: los mapas críticos se fijan con **0600 y propietario root**. No 0640
ni 0644; el contenido de los mapas de un EDR no es información que un usuario sin
privilegios deba leer, y un grupo con acceso amplía la superficie sin necesidad.

`aegis-kguard::mapperms` no fija los mapas (eso lo hace el cargador con libbpf):
**calcula y verifica** los permisos, que es la parte con lógica. El bloqueo se
hace en dos pasos deliberados —`chmod` a 0600 y después **comprobar** que quedó
así— porque un `umask` heredado puede recortar bits de forma que el resultado no
sea el pedido. Verificar el resultado es lo que convierte "pedimos 0600" en "es
0600".
