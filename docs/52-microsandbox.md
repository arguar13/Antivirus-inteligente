# Módulo 52 — Micro-sandbox de emulación: desplegar lo desconocido sin riesgo

> Componentes: `crates/aegis-emu/`, `crates/aegis-agent/src/microsandbox.rs`.

## 52.1 El problema: el análisis estático se rinde ante el ofuscamiento

El malware moderno casi nunca lleva su código en claro. Un empaquetador —UPX
mutado, un cifrador a medida— guarda el código real comprimido o cifrado y lleva
un pequeño descompresor que, al ejecutarse, lo despliega en memoria y salta a él.
Una firma sobre el fichero de disco no ve nada: el código que busca todavía no
existe, está cifrado.

## 52.2 Emular, no ejecutar

La FASE 27 (`aegis-unpacker`) ya resuelve esto **ejecutando** el binario bajo
`ptrace`, confinado por seccomp. Esta fase aporta la vía **complementaria y más
segura**: **emular** el binario en una CPU virtual. La diferencia es tajante —bajo
`ptrace` las instrucciones corren en el procesador real, aunque confinadas; aquí
**ni una sola instrucción del binario desconocido toca el host**—. El descompresor
se ejecuta dentro del emulador; sus escrituras caen en memoria virtual; sus
llamadas al sistema se **interceptan** en vez de realizarse. Se puede desplegar y
observar un binario hostil con riesgo cero, y hacerlo en microsegundos, muy por
debajo del presupuesto de 100 ms de la fase.

## 52.3 Por qué un emulador propio y no `unicorn-engine`

El planteamiento inicial sugería un binding a `unicorn-engine`. Se descartó **a
propósito**: unicorn es un emulador en C de decenas de miles de líneas (derivado
de QEMU). Meterlo en el árbol de dependencias del **agente** —la pieza que defiende
el endpoint— sería añadir una superficie de ataque nativa enorme dentro de nuestra
propia defensa, justo lo que la disciplina del proyecto prohíbe. Se eligió un
emulador **propio, en Rust puro** (solo `thiserror`), con dos consecuencias
honestas:

1. Lo que soporta se prueba de verdad contra **código máquina x86-64 real** —stubs
   ensamblados a mano en las pruebas—, cero mocks.
2. Lo que **no** soporta se rechaza **ruidosamente** (`InstruccionNoSoportada`): el
   emulador nunca finge haber ejecutado un opcode que no entiende. El subconjunto
   cubierto —movimiento de datos, aritmética/lógica, desplazamientos y rotaciones,
   control de flujo, y la frontera `syscall`/`int 0x80`— es el que usan los
   descompresores y el shellcode, y está documentado en el decodificador.

El emulador decodifica de verdad la codificación de x86-64: prefijos `REX` y
`0x66`, `ModRM`, `SIB`, desplazamientos e inmediatos, con la semántica correcta
(escribir un registro de 32 bits pone a cero la parte alta, las banderas de
acarreo/desbordamiento/signo se calculan como en el hardware).

## 52.4 Detección de desempaquetado y el caso decisivo

La memoria virtual **recuerda qué direcciones se escribieron** durante la
emulación. Cuando el flujo salta a ejecutar código en una de esas direcciones
—el momento exacto en que un empaquetador despliega su carga real—, se emite un
evento de desempaquetado y la región queda disponible para volcarla al motor
YARA.

El caso decisivo está calcado del de `aegis-unpacker`: una firma que **no** está
en el fichero de disco **sí** aparece tras desempaquetar. La prueba construye un
stub que descifra (XOR) seis bytes y salta a ellos; descifrados son
`mov eax, 0xCAFEBABE; hlt`. En el código de disco el marcador `0xCAFEBABE` no se
ve; tras emular, el sandbox lo extrae —y, además, la carga se **ejecuta** de
verdad (el `hlt` descifrado detiene la emulación), lo que prueba el
desempaquetado de extremo a extremo—. El `mmap` emulado reparte regiones reales,
así que los empaquetadores que **reservan-escriben-saltan** también se despliegan
de verdad.

## 52.5 La heurística de comportamiento (y no marcar de más)

De la traza de eventos —syscalls interceptadas y desempaquetados— sale un
veredicto. La parte que puede estar **mal de forma peligrosa** es el falso
positivo: marcar software legítimo empaquetado como una amenaza ahogaría al
analista. Por eso el veredicto distingue:

- **Auto-inyección** (crítico): reservar/reproteger memoria como ejecutable y
  saltar a código recién escrito, o manipular otro proceso.
- **C2** (alto): actividad de red.
- **Ransomware** (alto): abrir y sobrescribir muchos ficheros.
- **Desempaquetador** (medio, **no** concluyente): se desplegó a sí mismo —hay
  carga que escanear, pero empaquetar no es, por sí solo, malicioso—.

El caso decisivo de no marcar de más: un binario que solo lee un fichero y
termina se clasifica **benigno**. El agente (`microsandbox.rs`) solo aísla cuando
el veredicto es concluyentemente malicioso.

## 52.6 Honestidad de validación: no hay muro

A diferencia de las fases de TPM, Intel PT o el driver de Windows, esta **no tiene
muro físico**: es Rust puro y todo se prueba en cada `make ci` con `cargo test`
—el decodificador contra instrucciones reales, el ejecutor corriendo programas
reales (un bucle que suma, un descifrador XOR, un `mmap` de auto-inyección), y la
heurística con sus casos decisivos—. Lo único que el emulador declara es su
**frontera**: fuera del subconjunto de instrucciones soportado, se detiene y lo
dice, con la traza obtenida hasta ese punto intacta. Cargar un binario PE/ELF
completo (parsear secciones y punto de entrada, que ya hace `aegis-parser`) para
alimentar al sandbox es la extensión natural documentada.
