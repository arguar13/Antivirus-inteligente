# Módulo 46 — Intel PT: cazar ROP/JOP desde el hardware

> Componentes: `crates/aegis-ptguard/`.

## 46.1 El problema: evasión sin código nuevo

Los atacantes modernos evaden los hooks de un EDR con **ROP** y **JOP**
(return/jump-oriented programming). En vez de inyectar código nuevo —que un EDR
detecta— encadenan trocitos de código **ya presente y legítimo** ("gadgets"),
cada uno terminado en un `ret` o un salto indirecto. Como no hay código nuevo ni
llamadas a APIs sospechosas, la detección clásica no lo ve.

**Intel Processor Trace** lo delata desde el hardware: la CPU emite un registro
de *cada* salto que ejecuta el proceso, con un coste mínimo. Reconstruido el
flujo, una cadena ROP se distingue de la ejecución normal por su **forma**: una
ráfaga de bloques cortísimos, cada uno terminado en un salto indirecto, con los
`ret` desparejados de sus `call`.

## 46.2 La frontera de realidad de esta fase

La **captura** en vivo necesita el flag `intel_pt` en la CPU y `perf_event_open`
con permiso. Este Xeon virtual **no lo tiene** (`/proc/cpuinfo` sin `intel_pt`,
`perf_event_paranoid=2`), así que la captura es físicamente imposible aquí.
Siguiendo el patrón de la FASE 47:

- El **núcleo** —decodificar los paquetes, reconstruir el flujo y decidir si es
  ROP/JOP— es Rust puro y se **prueba** con trazas en formato binario real y
  código x86-64 real en cada `make ci`, sin un solo mock.
- La **fontanería** —`perf_event_open`, el `mmap` del área AUX donde la CPU
  vuelca la traza por DMA— vive tras la feature `pt-live`, y el CI declara que no
  se ejercitó aquí.

## 46.3 El decodificador: el formato es el formato

La CPU vuelca la traza como un flujo de paquetes muy comprimidos: por cada salto
**condicional** manda un solo bit (tomado/no tomado, empaquetados de seis en seis
en un byte, `TNT`), y por cada salto **indirecto** manda la dirección destino
(`TIP`), y aún esa comprimida contra la anterior. `paquete.rs` decodifica esto a
mano contra el Intel SDM. Se prueba con flujos binarios reales construidos byte a
byte: sin un chip con Intel PT, la **corrección** del decodificador se demuestra
igual, porque el formato es el formato.

## 46.4 Reconstrucción con desensamblado real

La traza sola dice *"aquí hubo un salto indirecto a X"*, pero no qué código hay
en X. Cruzándola con la **imagen** del proceso y desensamblando con `iced-x86`
(desensamblador x86-64 en Rust puro) se reconstruye la secuencia de gadgets: el
trozo de código que se ejecutó desde el destino de un salto indirecto hasta el
siguiente. Cuántas instrucciones y cómo termina cada gadget es lo que distingue
una cadena ROP de la ejecución normal. Es la aproximación de kBouncer/ROPecker.

## 46.5 La decisión, y su falso positivo

`analisis.rs` es el núcleo de decisión: un falso positivo interrumpe un proceso
legítimo, uno negativo deja pasar la evasión que justifica toda la fase. La regla
no decide sobre **un** gadget —un `ret` corto suelto es normal— sino sobre una
**ventana**: hace falta una ráfaga de varios gadgets cortos seguidos, terminados
en `ret` (ROP) o en salto indirecto (JOP), para gritar evasión. Los tests lo
verifican en ambos sentidos: una cadena de 10 gadgets reales se detecta; tres
gadgets sueltos, no (evita el falso positivo); un retorno de función normal
(bloque largo), tampoco.

## 46.6 El overhead y la ABI

Intel PT escribe por DMA en un buffer circular sin interrumpir al proceso
trazado: por eso el overhead es de un pequeño porcentaje y no del 10× de un
tracer por software. El coste está en **vaciar** ese buffer y decodificarlo, y se
hace en un hilo aparte para no meterse en el camino del proceso vigilado.

`perf_pt.rs` es el espejo `repr(C)` de `perf_event_attr`. `libc` no lo expone, y
un layout mal copiado es un fallo silencioso peligroso: `perf_event_open` valida
`size` contra su idea del `struct`, y un campo desalineado hace que el kernel lea
basura donde espera los flags. **El test de tamaño atrapó exactamente eso durante
el desarrollo**: el espejo se había quedado en 120 bytes (una versión de ABI
anterior) por faltarle el campo `sig_data`; se completó a los 128 de
`PERF_ATTR_SIZE_VER7`.

## 46.7 Frontera de realidad

| Pieza | Verificable aquí | Muro |
|---|---|---|
| Decodificador de paquetes PT | sí, con trazas binarias reales | — |
| Reconstrucción (iced-x86) | sí, con código x86-64 real | — |
| Análisis ROP/JOP | sí, cadenas reales + casos benignos | — |
| ABI `perf_event_attr` | sí, layout aseverado a 128 bytes | — |
| Captura en vivo (`perf_event_open` + AUX) | — | necesita `intel_pt` en la CPU, gated tras `pt-live` |
