# Módulo 37 — Construcción hermética y BPF CO-RE universal

> Componentes: `tools/toolchain/imagen/`, `tools/toolchain/`, `tools/ci/hermetico.sh`,
> `drivers/linux/aegis-bpf/`.

Hasta aquí, dos piezas de AegisCore dependían de la máquina que las compilaba: el
binario del agente, enlazado contra la glibc del *runner*, y el bytecode eBPF,
que declaraba a mano los campos del kernel. Las dos fallan en el mismo sitio —el
endpoint del cliente— y ninguna falla en el laboratorio.

---

## 37.1 El binario: de «casi estático» a autónomo

`ldd` sobre el artefacto de la FASE 41 decía esto:

```
libbpf.so.1 => /lib/x86_64-linux-gnu/libbpf.so.1
libelf.so.1 => /lib/x86_64-linux-gnu/libelf.so.1
libc.so.6   => /lib/x86_64-linux-gnu/libc.so.6
```

Un agente así **no arranca** en un endpoint cuya glibc sea más antigua que la del
runner. El mensaje que ve el cliente es `version 'GLIBC_2.38' not found`, y llega
en mitad de un despliegue de miles de máquinas.

### El sysroot que no existía

`musl-gcc`, tal y como lo empaquetan las distribuciones, **no es un toolchain
cruzado**: es gcc con un fichero de `specs` que lo apunta a las cabeceras y las
bibliotecas de musl. Ese sysroot trae la libc y nada más. En cuanto una
dependencia con código C incluye `<asm/unistd.h>` —libbpf lo hace en su primera
línea— la compilación muere:

```
bpf.c:28:10: fatal error: asm/unistd.h: No such file or directory
```

La tentación es añadir `-I/usr/include/x86_64-linux-gnu` y seguir. **No se hizo**,
y conviene decir por qué: ese directorio es el *multiarch de glibc*. Además de
`asm/` contiene `bits/`, `gnu/` y `sys/`, así que con él en la ruta de búsqueda
las cabeceras de glibc entran en una compilación contra musl. El binario mezcla
dos ABIs de libc: puede enlazar, puede incluso arrancar, y corromper en silencio
`struct stat`, `errno` o los tipos de tiempo más adelante.

`tools/toolchain/preparar_musl.sh` compone en su lugar un sysroot completo, que
es lo que produce un toolchain cruzado de verdad:

| Pieza | De dónde sale | Por qué es correcto combinarla |
|---|---|---|
| Cabeceras y `libc.a` de musl | `musl-dev` | Es la libc del objetivo |
| `linux/`, `asm/`, `asm-generic/` | `linux-libc-dev` | Son la salida de `make headers_install`: **independientes de la libc** por definición |

Y comprueba que no se coló nada: si aparece `gnu/stubs.h`, `bits/libc-header-start.h`
o un `features.h` que define `__GLIBC__`, el script aborta. La barrera es
permanente, no una comprobación de una vez.

### Las dos funciones que musl no tiene

`elfutils` —de quien depende libbpf para leer ELF— usa dos extensiones de GNU:

```
configure: error: failed to find argp_parse
configure: error: failed to find _obstack_free
```

Se resuelve como lo resuelve Alpine Linux, que empaqueta elfutils sobre musl:
aportando esas funciones como bibliotecas independientes compiladas contra este
mismo sysroot (`argp-standalone` y `musl-obstack`, fijadas por etiqueta **y por
commit**). No se parchea elfutils, no se desactivan comprobaciones de su
`configure` y no se sustituye libelf por otra cosa: el agujero es la ausencia de
unas funciones, y lo que corresponde es aportarlas.

### El desenrollador: un camino que se probó y no servía

Rust enlaza `-lunwind` en el objetivo musl. El desenrollador «natural» de un
toolchain gcc es `libgcc_eh.a`… y el que instala la distribución **no vale**:

```
libgcc_eh.a(unwind-dw2-fde-dip.o): undefined reference to `_dl_find_object'
```

Está compilado contra glibc y llama a una API que glibc añadió en 2.35 y que musl
no tiene. Un `libgcc_eh` válido para musl solo sale de un gcc construido *contra*
musl. La pieza correcta es la libunwind de LLVM que el propio toolchain de Rust
distribuye ya compilada para musl: es la que rustc espera y viene emparejada con
el compilador. El script la instala en el sysroot y comprueba dos cosas —que
define los símbolos `_Unwind_*` y que **no referencia ningún símbolo exclusivo de
glibc**—. Esa segunda comprobación es la que habría cazado el intento anterior
antes de llegar al enlazador, y por eso se queda ahí.

### static-pie y no «estático a secas»

El encargo pedía que `ldd` respondiera `not a dynamic executable`. El artefacto
por defecto responde `statically linked`, y la diferencia merece una explicación
porque **no es un incumplimiento, es una decisión**:

| | `ldd` dice | Dependencias | ASLR |
|---|---|---|---|
| `static-pie` (por defecto) | `statically linked` | ninguna | **sí** |
| estático no-PIE (`AEGIS_PIE=0`) | `not a dynamic executable` | ninguna | **no** |

Las dos son igual de autónomas. Un binario no-PIE se carga siempre en la misma
dirección y pierde la aleatorización del espacio de direcciones. En un agente que
corre como root y procesa datos que controla un atacante, regalar ASLR para que
`ldd` imprima otra frase es un mal negocio. Quien necesite la variante no-PIE
—por ejemplo, para un cargador antiguo que no maneje `ET_DYN`— la obtiene con
`AEGIS_PIE=0`.

Por eso el CI **no comprueba la frase de `ldd`**, sino la propiedad real, sobre
el ELF:

```
| aegis-agent        sin interprete, sin NEEDED, sin UND
| aegisctl           sin interprete, sin NEEDED, sin UND
| aegis-watchdog     sin interprete, sin NEEDED, sin UND
| aegis-fleet        sin interprete, sin NEEDED, sin UND
```

Sin `PT_INTERP` (nadie tiene que cargar un enlazador dinámico), sin `DT_NEEDED`
(no pide bibliotecas compartidas), sin `RPATH`/`RUNPATH` (no busca en rutas del
constructor), sin símbolos dinámicos indefinidos — y además arrancan.

---

## 37.2 El bytecode: CO-RE de verdad

### Lo que estaba mal en la versión anterior

Los programas declaraban a mano los campos del kernel que leen, marcados con
`preserve_access_index`. Eso **también** es CO-RE y compilaba. El fallo era de
raíz: CO-RE reubica el *desplazamiento* de un campo, no su *tamaño*. Si una
declaración a mano se equivoca en el ancho o en el signo —o si el kernel lo
cambia— el programa sigue compilando, sigue cargando, y lee basura en silencio.
En un EDR eso es un punto ciego de detección que nadie detecta.

Ahora los tipos salen de `vmlinux.h`, generado del BTF del kernel, así que son
los auténticos por construcción. El fichero **no se versiona**: se produce en
`out/` desde una fuente de BTF fijable con `AEGIS_BTF`, y se registra al lado su
SHA-256 y su procedencia. Meter 116.000 líneas generadas en el repositorio solo
serviría para enterrar los cambios reales en cada revisión.

Dos declaraciones a mano desaparecieron con la migración, y las dos eran
exactamente del tipo que acierta hoy y miente mañana: un `typedef int s32` y una
`struct bpf_iter_task` opaca en el módulo de integridad de kernel.

### Compilar no demuestra nada: `aegis_core_check`

Un objeto puede llevar los desplazamientos del kernel de construcción grabados a
fuego. `tools/aegis_core_check.c` abre el `.o`, parsea la sección `.BTF.ext` y
exige que haya reubicaciones y que ninguna esté malformada:

```
==> out/aegis_probes.bpf.o
    tracepoint/syscalls/sys_enter_execve              6 reubicaciones
    tracepoint/sock/inet_sock_set_state              12 reubicaciones
    ...
    .BTF 36396 B, .BTF.ext 17516 B, 9 seccion(es), 49 reubicacion(es)
    tipos: byte-offset=49
```

### La prueba que convierte la promesa en un hecho

«Compile once, run everywhere» es una afirmación, y una afirmación sin prueba
vale cero. El verificador acepta ahora `--btf`, que le dice a libbpf que resuelva
las reubicaciones contra el BTF de **otro** kernel. Los BTF de referencia los
trae `tools/toolchain/traer_btf.sh` desde BTFHub.

El primer resultado fue un hallazgo real:

```
--- 5.4.0-42-generic.btf ---
failed to resolve CO-RE relocation <byte_off> struct task_struct.start_boottime
```

`task_struct` guarda el instante de arranque de la tarea en un campo que se llamó
`real_start_time` hasta Linux 5.4 y `start_boottime` desde 5.5. AegisCore lo
necesita porque es **la mitad de la identidad estable de un proceso**: el PID se
recicla, el par (pid, instante de arranque) no. Sin él, dos procesos distintos que
reutilizan un PID se confunden en el grafo de linaje — y ahí es donde se esconde
un atacante.

Es justo el problema para el que existe CO-RE, y se resolvió con sus dos
mecanismos:

```c
struct task_struct___pre55 {
    __u64 real_start_time;
} __attribute__((preserve_access_index));

static __always_inline __u64 aegis_inicio_de_tarea(struct task_struct *tarea)
{
    if (bpf_core_field_exists(tarea->start_boottime))
        return BPF_CORE_READ(tarea, start_boottime);

    struct task_struct___pre55 *antigua = (void *)tarea;
    return BPF_CORE_READ(antigua, real_start_time);
}
```

`bpf_core_field_exists` pregunta al BTF del kernel de destino, al cargar y no al
compilar. El sufijo `___` declara un «sabor» de tipo: libbpf ignora todo lo que
sigue a `___` al buscar el tipo en el kernel, así que este sabor casa con
`struct task_struct` y permite pedir un campo que el `vmlinux.h` actual ya no
tiene. La rama que no corresponda queda como código muerto y el verificador la
poda.

### Dos fallos que no se parecen en nada

Al probar contra el BTF de otro kernel hay que distinguir:

- **`failed to resolve CO-RE relocation`** — el código lee un campo que en ese
  kernel no existe. Es un defecto real de portabilidad y rompe la construcción.
- **el verificador rechaza tras reubicar bien** — el bytecode quedó ajustado a
  otro kernel y se está cargando en el de esta máquina. Es una limitación del
  método de prueba, no del producto.

Sin esa distinción el segundo caso se leería como el primero, y el equipo acabaría
persiguiendo un defecto inexistente o —peor— silenciando la comprobación entera.
El verificador lo separa con `--solo-core`.

### Suelo de compatibilidad, medido

| Componente | Kernel mínimo | Evidencia |
|---|---|---|
| Sondas de telemetría | **5.4** | Las reubicaciones resuelven contra el BTF de 5.4 (Ubuntu 20.04 GA, RHEL 8) |
| Filtro XDP | **5.8** | Carga completa contra el BTF de 5.8. Los BTF de 5.4 no incluyen `struct xdp_md` |
| Integridad de kernel | **6.x** | Usa las kfuncs `bpf_iter_task_*`, que no existen antes |

No es una estimación: es lo que sale de reubicar el bytecode contra esos kernels.

---

## 37.3 La imagen hermética

`tools/toolchain/imagen/Dockerfile` empaqueta todo lo anterior: Rust fijado, el sysroot
musl completo, clang/LLVM y `bpftool` compilado desde fuente. Tres decisiones
merecen mención:

**La base se fija por digest, no por etiqueta.** `24.04` apunta a una imagen
distinta cada pocas semanas, y con ella cambiarían en silencio gcc, binutils y
musl. Es Ubuntu 24.04 y no otra distribución porque es la misma base que usan los
runners de `.github/workflows/aegis_ci.yml`: si la imagen y el CI partieran de
distribuciones distintas, un fallo que solo aparece en una costaría días.

**`bpftool` se compila desde fuente.** El paquete de la distribución es un
envoltorio que despacha a un binario ligado a la versión exacta del kernel del
anfitrión. Dentro de un contenedor ese binario no existe, y el envoltorio imprime
un aviso y **devuelve éxito** — la peor forma posible de fallar.

**Rust se instala verificando la suma**, no con `curl https://sh.rustup.rs | sh`.
En una tubería, un fallo de `curl` no detiene la orden: `sh` recibe entrada vacía,
termina con éxito, y el error aparece líneas después como `rustup: not found`.
Además, ejecutar sin verificar un guion descargado, dentro de la imagen que
construye un producto de seguridad, es exactamente lo que este producto detecta
como sospechoso en un endpoint.

El sysroot lo construye **el mismo script** que usa un desarrollador en su
máquina. Si los dos caminos divergieran, el CI dejaría de probar lo que la gente
ejecuta.

---

## 37.4 Uso

```bash
# Toolchain local (una vez)
tools/toolchain/preparar_musl.sh
tools/toolchain/traer_btf.sh

# Artefactos herméticos
tools/ci/hermetico.sh              # static-pie, con ASLR
AEGIS_PIE=0 tools/ci/hermetico.sh  # no-PIE, `ldd` dice "not a dynamic executable"

# O dentro de la imagen, sin instalar nada
docker build -f tools/toolchain/imagen/Dockerfile -t aegis/hermetico:1 .
docker run --rm -v "$PWD:/aegis" -w /aegis aegis/hermetico:1 tools/ci/hermetico.sh

# eBPF
make -C drivers/linux/aegis-bpf build        # genera vmlinux.h y compila
make -C drivers/linux/aegis-bpf core-check   # ¿lleva reubicaciones CO-RE?
make -C drivers/linux/aegis-bpf core-matrix  # ¿reubican contra otros kernels?
make -C drivers/linux/aegis-bpf verify       # ¿las acepta el verificador?
```

## 37.5 Toolchain fijada y código nativo revisado

Un artefacto hermético es función del código **y** de la toolchain. Hasta ahora
nada fijaba el compilador —cada máquina usaba el `default` de su rustup; el
runner instalaba un canal, la imagen otro y el workflow `stable`— ni el sysroot,
que se componía con la musl y las cabeceras que tuviera la distribución.

- `rust-toolchain.toml` elige el canal; `tools/toolchain/fijado.toml` fija la
  salida exacta de `rustc --version` y `cargo --version`, el manifiesto del
  canal, el SHA-256 de cada `rust-std` y las versiones de los paquetes con los
  que se compone el sysroot y se compila el C (musl, UAPI, gcc, binutils).
- `preparar_musl.sh` no compone un sysroot con otras versiones y deja en él un
  `SELLO`: la receta por su SHA-256, el `rustc` del que sale la libunwind, las
  versiones y la huella del árbol. Cambiar la receta obliga a rehacer el
  sysroot.
- `tools/toolchain/comprobar_toolchain.sh` es la puerta: grupo `toolchain` de
  `make ci` (Rust) y primer paso de `hermetico.sh` (Rust y sysroot).

El agente estático lleva dentro código C y ensamblador de terceros: libbpf,
**libelf de elfutils** y zlib (desde `libbpf-sys`), ring, BLAKE3 y los kernels
de `tract-linalg`. cargo-deny no lo ve: juzga el campo `license` de cada crate,
y libbpf-sys declara BSD-2-Clause. `tools/config/codigo-nativo.toml` es la lista
revisada de ese código, crate a crate y versión a versión, para todos los
instalables; `tools/ci/codigo_nativo.py comprobar` (grupo `cadena`) falla si
entra código nativo sin revisar o con una licencia que `deny.toml` no admite
sin una decisión declarada.

La licencia de libelf (GPL-2.0-or-later OR LGPL-3.0-or-later) dentro de un
binario estático, y con ella la licencia del propio proyecto y los avisos de
terceros que acompañen a los binarios, son **decisiones pendientes del
propietario**. La puerta las imprime en cada ejecución; hasta que se tomen, el
repositorio no genera avisos de terceros.
