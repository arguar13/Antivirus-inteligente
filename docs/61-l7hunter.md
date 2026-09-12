# Módulo 61 — AegisL7Hunter: caza de C2 sobre TLS con uprobes de eBPF

> Componentes: `crates/aegis-l7hunter/`, `drivers/linux/aegis-bpf/src/aegis_sslsniff.bpf.c`,
> `tools/verificar-l7hunter.sh`, `tools/abi-check-l7.sh`.

## 61.1 El IDS de red se quedó ciego

El malware moderno cifra su canal de Comando y Control. Un IDS de red ve bytes
opacos: puede contar paquetes y mirar el SNI, pero no el contenido. La respuesta
clásica —un proxy que hace *Man-In-The-Middle*— tiene dos problemas graves:

1. **Rompe el *certificate pinning***. Cualquier cliente que verifique el
   certificado que espera deja de funcionar, y el malware bien hecho lo verifica.
2. **Obliga a instalar una CA de interceptación en cada endpoint**, que es en sí
   misma una superficie de ataque enorme: quien robe esa clave descifra el
   tráfico de toda la organización.

## 61.2 No interceptar: observar en el origen

Las bibliotecas TLS exponen dos funciones de usuario por las que pasa, **en
claro**, todo lo que se va a cifrar y todo lo que se acaba de descifrar:

```c
SSL_write(ssl, buf, num)  →  buf está EN CLARO al ENTRAR
SSL_read(ssl, buf, num)   →  buf está EN CLARO al SALIR
```

Un **uprobe** en la entrada de la primera y un **uretprobe** en el retorno de la
segunda dan el texto plano sin tocar el cifrado, sin romper el pinning y sin
ninguna clave de interceptación que robar. El cifrado sigue siendo de extremo a
extremo; simplemente, uno de los extremos es un endpoint que defendemos y en el
que el dueño ha instalado un EDR.

Se cubren cuatro pilas: **OpenSSL/BoringSSL/LibreSSL** (misma API),
**GnuTLS** —que en una distribución típica se lleva la mitad del tráfico TLS:
`wget`, `apt`, todo lo que pase por glib-networking—, **NSS** y **`crypto/tls` de
Go**.

### El detalle que hay que acertar: la correlación de `SSL_read`

En la **entrada** de `SSL_read` el buffer todavía no tiene nada: son datos
cifrados por recibir. El texto plano sólo existe **al retornar**. Pero en el
retorno ya no están los argumentos.

Hay que recordar el puntero entre las dos sondas, y **la clave de ese recuerdo es
el TID, no el PID**. Un proceso con varios hilos hace `SSL_read` a la vez desde
todos; con el PID como clave, la entrada de un hilo pisaría la de otro y en el
retorno se leería el buffer de **otra conexión**. Es un fallo que no se ve en
pruebas de un solo hilo y que en producción mezcla el tráfico de dos sesiones.

## 61.3 Dónde enganchar: el error que no falla ruidosamente

Para enganchar un uprobe hacen falta la **ruta** del fichero y el
**desplazamiento dentro del fichero** de la función. Lo segundo **no** es la
dirección virtual del símbolo. La traducción correcta es, sobre el `PT_LOAD` que
contiene el símbolo:

```
desplazamiento_fichero = vaddr_símbolo − p_vaddr + p_offset
```

En la inmensa mayoría de bibliotecas compartidas `p_offset == p_vaddr`, así que
la versión ingenua (`desplazamiento = vaddr`) acierta **por casualidad**. Es
exactamente el tipo de error que pasa todas las pruebas y falla en producción,
además sin hacer ruido: un uprobe en el sitio equivocado no da error, lee basura
o no dispara nunca.

Medido sobre esta máquina, en 1 107 binarios de `/usr/lib/x86_64-linux-gnu` y
`/usr/bin`: **20 tienen el segmento ejecutable con `p_offset != p_vaddr`**, todos
con un desfase de `0x400000` por ser ejecutables **no-PIE**. Entre ellos,
`/usr/bin/python3.10` y `containerd-shim-runc-v2`, que es un binario de **Go**.

Y ésos son justo los que importan: **el malware moderno en Go enlaza `crypto/tls`
estáticamente**, así que el objetivo del uprobe no es una `libssl` compartida sino
el propio ejecutable, y el símbolo no se llama `SSL_write` sino
`crypto/tls.(*Conn).Write`. Con la traducción ingenua, el enganche caería 4 MiB
más allá de la función.

La resolución es **por símbolo, no por nombre de fichero**. El nombre sólo ordena
los candidatos y nunca descarta: un cazador que sólo mire ficheros llamados
`libssl*` es ciego contra quien se molesta en esconderse, que es el único que
importa.

## 61.4 La matemática de las balizas

Un implante no mantiene una conexión abierta: eso lo delataría. Duerme un
intervalo `S`, pregunta si hay órdenes, y vuelve a dormir. Para disimular añade
***jitter***, y el modelo que usan Cobalt Strike, Sliver y prácticamente todos es
**uniforme**: `intervalo ~ U[S·(1−J), S]`.

Para esa distribución:

```
media  μ = S·(1 − J/2)
desv.  σ = S·J / √12
CV = σ/μ = J / ( √12 · (1 − J/2) )
```

El **coeficiente de variación** es *adimensional*: no depende de `S`. Es creciente
en `J`, así que alcanza su máximo con jitter total:

```
J = 1  →  CV = 2/√12 = 0,5774
```

**Ninguna baliza con jitter uniforme puede superar un CV de 0,578**, duerma lo que
duerma. No es un umbral elegido a ojo: es una cota derivada del modelo que usa el
atacante, y está comprobada para `J` de 0 a 1 y para sueños de 0,5 s a 1 h. El
tráfico legítimo es a ráfagas, de cola pesada, y su CV se va muy por encima de 1.

### La cota no depende de cómo el atacante implemente el jitter

Hay dos formas de implementarlo, y las dos se usan: restando —`U[S(1−j), S]`, que
es lo que hace Cobalt Strike— o alrededor del sueño, `U[S(1−j), S(1+j)]`. Llegan
al mismo máximo, y no por casualidad:

```
un solo lado:  CV_max = 2/√12
simétrico:     CV_max = 1/√3
2/√12 = 2/(2√3) = 1/√3          ← el mismo número
```

Que la cota sea invariante al modelo de jitter es lo que la hace utilizable: no
hay que saber qué framework hay al otro lado.

De propina, `2·MAD/mediana` **estima el jitter configurado**: es exacto para el
modelo simétrico (mediana `S`, MAD `S·j/2`) y monótono creciente para el de un
solo lado. Es evidencia de primer orden para el analista —«baliza de 60 s con 40 %
de jitter»— y cotejable con inteligencia externa. Al usar MAD y mediana, un corte
de red no la falsea.

### Por qué la desviación típica sola no vale…

Un portátil que se suspende media hora mete **un** intervalo enorme en la serie.
Ese único valor dispara σ y hunde el CV: la baliza se vuelve invisible por un
evento que no tiene nada que ver con ella, y un atacante podría esconderse
provocando el corte. Por eso se calcula también la **desviación absoluta mediana**
(MAD), que es robusta: hace falta corromper la mitad de la muestra para moverla.

### …ni la MAD sola tampoco

Y aquí está el defecto simétrico, que costó un rediseño. El tráfico a ráfagas de
un navegador tiene **exactamente la misma firma** que una baliza con un corte de
red —CV alto, MAD baja— porque la mediana la fijan los milisegundos de dentro de
la ráfaga, no el ritmo. **Con esas dos métricas los dos casos son
indistinguibles**, y un detector que se fiara de la robusta convertiría cada
navegador de la flota en una alerta.

Lo que sí los separa es que **una baliza da cuenta de su propia línea de tiempo**:

| | mediana | intervalos | tiempo explicado | observado | cobertura |
|---|---|---|---|---|---|
| Baliza de 1 min | 60 s | 60 | 3 600 s | 5 400 s (con corte) | **0,67** |
| Navegador | 30 ms | 192 | 5,8 s | ~1 200 s | **0,005** |

Esa es la **cobertura temporal**, y es la que decide cuál de las dos dispersiones
vale. Dos órdenes de magnitud de separación, por una razón estructural y no por
un umbral afinado a ojo.

### El ritmo vive en el lado que inicia

Una iteración de baliza son **dos** eventos: la petición, y la respuesta unas
decenas de milisegundos después. La serie **mezclada** alterna 0,03 s y 60 s: es
bimodal, y sus métricas salen idénticas a las del tráfico a ráfagas. Medido: una
baliza perfecta sin jitter daba `CV = 1,018` y cobertura `0,001` — se habría
clasificado como tráfico irregular.

El ritmo pertenece al lado que **inicia**: el implante decide cuándo pregunta;
cuándo llega la respuesta lo deciden el servidor y la red. Midiendo sólo las
peticiones, esa misma baliza da `CV = 0,0000`.

## 61.5 El falso positivo que de verdad importa

Un agente de monitorización —Prometheus, un *health-check*, un `kube-probe`— es
**perfectamente periódico**, con mensajes igual de pequeños y constantes, contra
un solo host. Por la forma temporal es **indistinguible** de una baliza sin
jitter. Un clasificador que decidiera por periodicidad marcaría toda la
observabilidad del cliente, y a la semana nadie miraría las alertas.

La primera versión del modelo hacía exactamente eso: el sondeo puntuaba **1,0**.
La corrección no fue subir el sesgo —eso sólo mueve la frontera— sino **exigir
evidencia de contenido**: metadata codificada en cookie o URI, ausencia de
`User-Agent`, un agente inventado, o directamente no hablar HTTP. Y restar fuerte
cuando las URIs son estables y legibles, que es lo que hace un health-check y lo
que una baliza no puede permitirse, porque necesita llevar su metadata.

| Sesión | Riesgo |
|---|---|
| Baliza clásica (sin jitter, cookie con metadata) | **0,99** |
| Baliza con jitter del 40 % | **0,98** |
| Canal binario propio, alta entropía, **no periódico** | **0,97** |
| Exfiltración (POST grandes, respuestas mínimas) | **0,85** |
| Navegador | 0,04 |
| **Agente de monitorización** (igual de periódico) | **0,03** |

Un matiz que costó otro fallo: una baliza que lleva su metadata en la **cookie**
también pide siempre la misma URI. La característica «URI estable» significa
*peticiones predecibles, legibles y sin metadata*, no *siempre la misma ruta*; con
la condición puesta sólo sobre la URI, esa característica valía 1 para la baliza y
—al restar en los conceptos de ataque— **la protegía justo a ella**.

## 61.6 El agente no puede observarse a sí mismo

El agente habla TLS con su Control Plane. Con el comodín «observar todo» activo se
observaría a sí mismo: cada evento que emite viaja por TLS, ese envío dispara el
uprobe, que emite otro evento, que viaja por TLS… Es una **realimentación
positiva** que satura el ring, la CPU y el enlace, y que además mete el contenido
del canal de gestión —incluidos los veredictos— dentro de la propia telemetría.

No se resuelve «acordándose» de excluirlo desde Ring 3: si el agente engancha
primero y puebla el filtro después, la realimentación ya arrancó. Por eso la
exclusión es un **mapa aparte que se consulta primero** y que el agente escribe
**antes** de adjuntar ninguna sonda.

Y el filtrado ocurre dentro del kernel por una razón que no es sólo de
rendimiento: el texto plano de procesos que no interesan **no debe cruzar** al
espacio de usuario. Eso es el correo, la banca y las sesiones de trabajo de la
persona que usa la máquina. El comodín existe para una caza dirigida durante un
incidente, no como configuración por defecto.

## 61.7 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Los 9 programas eBPF | **sí** | cargados y aceptados por el **verificador real del kernel** |
| ABI del evento (C ↔ Rust) | **sí** | 15 entradas de layout, cotejadas con **gcc y clang** |
| Traducción vaddr → desplazamiento | **sí** | contra **todos** los binarios reales de la máquina, no-PIE incluidos |
| Resolución de símbolos TLS | **sí** | contra la **OpenSSL real** de la máquina |
| Cota teórica del CV | **sí** | para `J` de 0 a 1 y sueños de 0,5 s a 1 h |
| Robustez ante cortes y ráfagas | sí | series generadas con PRNG **determinista y sembrado** |
| Parseo L7 ante entrada hostil | sí | ninguna entrada puede provocar pánico |
| Inferencia ONNX | sí | modelo real, cargado con tract |
| **Enganchar el uprobe en un proceso vivo** | — | necesita `CAP_BPF`/`CAP_PERFMON` y una víctima con TLS en curso; **gated** |

El PRNG de las pruebas es determinista **por requisito del producto**, no por
comodidad: un veredicto que aísla la máquina de un cliente no puede cambiar entre
dos ejecuciones con la misma entrada.

Un defecto real que encontró la prueba de entrada hostil: un desbordamiento
aritmético en los lectores del ELF. Un binario de 64 bytes con `e_phoff` cercano a
`usize::MAX` —que un atacante deja en el disco— hacía entrar en pánico al
analizador, porque el perfil de release de este producto lleva `overflow-checks`
activados a propósito. Un EDR que se cae al mirar un fichero es una vía de
denegación contra sí mismo.
