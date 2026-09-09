# Módulo 13 — Análisis forense de memoria en vivo

> Componente: `crates/aegis-forensics` (Rust).

Cuando otra señal ya ha señalado a un proceso, este módulo lo mira por dentro
**sin pararlo**, buscando las marcas de un exploit de corrupción de memoria que
el análisis estático de ficheros no puede ver: el código malicioso vive en la
memoria de un proceso legítimo y nunca tocó el disco.

---

## 13.1 Volcado en vivo, sin congelar el proceso

La forma clásica de volcar la memoria de un proceso es pararlo con `ptrace`,
leerla y reanudarlo. Contra un proceso malicioso es contraproducente: **el parón
es observable** —el malware puede detectar que lo trazan y borrarse o cambiar de
comportamiento— y además congela un proceso que quizá sea legítimo y esté dando
servicio.

`process_vm_readv` lee la memoria de otro proceso **sin pararlo ni adjuntarse**:
una sola llamada copia de su espacio al nuestro. La foto no es perfectamente
coherente —el proceso sigue corriendo—, pero para buscar patrones de exploit esa
incoherencia es irrelevante, y a cambio no se altera el objetivo. Se prueba
contra memoria real: se mapea una región, se escribe un marcador, y el volcado
lo recupera.

La política de volcado acota qué regiones (ejecutables, escribibles) y cuánto de
cada una (2 MB por región, 64 MB en total), para no arriesgar la memoria del
propio agente ante un proceso enorme.

---

## 13.2 Detección de secuestro de vtable

En C++ una **vtable** es un array de punteros a función: cada llamada a un método
virtual salta a través de ella. Secuestrarla —hacer que una entrada apunte a
código del atacante— redirige llamadas virtuales sin tocar el código original,
lo que la hace invisible a una comparación memoria-disco del `.text`.

La marca es inequívoca: un array de punteros a código en el que **alguna entrada
apunta a memoria ejecutable anónima**, sin fichero detrás, donde no vive ningún
método legítimo. El detector desliza sobre las regiones de datos buscando tramos
de al menos tres punteros a código (menos se confunde con datos que
casualmente parecen punteros) y marca los que tienen alguna entrada anónima. Es
concluyente: no hay motivo legítimo para que una llamada virtual salte a código
anónimo.

---

## 13.3 Stack pivots y shellcode

Un exploit de corrupción desvía el puntero de pila (**stack pivot**) a un buffer
que controla, y ejecuta shellcode. Dos señales, en dos sitios distintos:

- **Gadgets de pivote en el código**: remates como `xchg eax,esp; ret`,
  `pop rsp; ret`, `mov rsp,rax; ret`. Se buscan en las regiones ejecutables,
  sobre todo las inyectadas.
- **Firmas de shellcode en los datos**: stubs de syscall (`0F 05`, `CD 80`),
  toboganes de NOP (una tirada larga de `0x90`), acceso al PEB por GS, la técnica
  GetPC (`call $+5`). Se buscan en la pila y el montón, donde no debería haber
  código ejecutándose.

Ninguna de las dos basta sola —una secuencia de bytes o un tobogán de NOP puede
aparecer por casualidad en datos—, pero **shellcode en los datos más un gadget
de pivote** es la combinación de un exploit real, y el informe lo marca como
malicioso. Una vtable secuestrada, en cambio, es concluyente por sí sola.
