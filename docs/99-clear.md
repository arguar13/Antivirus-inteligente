# Módulo 99 — AegisClear: telemetría en claro sin desplazamientos adivinados (FASE 107)

> Componentes: ampliación de `crates/aegis-l7hunter/` (`desplazamiento`,
> `verificacion`, `privacidad`, `bibliotecas`), `tools/verificar-l7hunter.sh`.

## 99.1 El defecto estructural de eCapture, y cómo se cierra

eCapture y todo lo que engancha bibliotecas TLS necesita saber en qué
desplazamiento del fichero está la función y dónde están sus argumentos. Traen esos
desplazamientos **precalculados por versión**: cuando el binario no es una de las
versiones conocidas —recompilado, despojado, estático, una rama que no vieron—,
leen en el sitio de siempre y devuelven **basura con aspecto de dato**. Un dato
falso es peor que un hueco: nadie sospecha de él.

Aquí un desplazamiento **solo existe si se pudo DERIVAR**, y se dice de dónde: de la
tabla de símbolos, de DWARF, de BTF, o —cuando no hay nada de eso— **analizando el
binario con el desensamblador (FASE 85) y el decompilador (FASE 100)**: el producto
se usa a sí mismo. Si ninguna vía lo deriva, el resultado es `NoConcluyente` con su
motivo. **La tercera salida —leer igualmente— no existe en el tipo**: no hay ningún
camino que devuelva un offset a ciegas.

## 99.2 Verificación en caliente: telemetría vs. adivinación

Derivar bien el offset es necesario pero no basta: puede ser correcto y el gancho
leer aun así un argumento equivocado (un cambio de convención de llamada, un
parámetro en registro y no en pila). La única forma de **saber** que un gancho ve lo
que dice ver es probarlo. Antes de confiar en un gancho, el agente abre una conexión
de prueba **propia**, envía un canario conocido a través de la biblioteca
enganchada, y comprueba que lo que salió por el gancho es exactamente el canario. Un
gancho que no pasa esa prueba **no se usa**. Nadie hace esto, y es la diferencia
entre telemetría y adivinación.

## 99.3 Privacidad obligatoria en el tipo

Lo que se captura en claro es lo más sensible del sistema: contraseñas, tokens,
cookies de sesión. Un cazador que guarde eso sin redactar es, él mismo, la mayor
fuga de la máquina. Por eso la redacción es parte del **tipo**: la única forma de
obtener una `CapturaEnClaro` es aplicando una `PoliticaRedaccion`, y el tipo **no
expone** el texto sin redactar —no hay un `bruto()` que llamar—. La difusión pasa
por el **estrangulamiento de la FASE 78**: hay un presupuesto de cuánto puede salir,
y excederlo para. Una fuga con interfaz bonita sigue siendo una fuga.

## 99.4 Cobertura declarada de 13 pilas TLS

`bibliotecas::COBERTURA` es una tabla tipada: OpenSSL (3.x y 1.1.x), BoringSSL,
LibreSSL, GnuTLS, NSS, wolfSSL, Go `crypto/tls`, rustls, JSSE, .NET, Node.js y
Python. Cada una dice **cómo** se engancha —símbolo exportado, herencia de la API de
OpenSSL, o derivación por análisis del binario (Go, rustls, JSSE)— y si está
cubierta hoy o **declarada** como incremento. Node, Python y .NET comparten OpenSSL
por debajo: un solo enganche vale.

## 99.5 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Offset derivado, nunca adivinado | **sí** | `derivar` prueba tabla→DWARF→BTF→análisis y se queda con la primera; dice la fuente |
| Binario despojado → `NoConcluyente` | **sí** | sin ninguna fuente que lo derive, `NoConcluyente`, `offset()==None`; nunca a ciegas |
| Verificación en caliente | **sí** | canario de ida y vuelta; un gancho que lee basura no se usa |
| Redacción obligatoria en el tipo | **sí** | `CapturaEnClaro` solo se construye redactando; no expone el texto bruto |
| Contraseñas, tokens, Authorization, Cookie redactados | **sí** | los secretos marcados no aparecen; la estructura se conserva |
| Presupuesto de difusión (FASE 78) | **sí** | la difusión no puede exceder el tope |
| Cobertura de 13 pilas TLS | **sí, declarada** | catálogo tipado con estrategia de enganche por biblioteca |
| Resolución del objetivo sobre binarios reales | **sí** (ya existía) | `objetivo`/`elf` sobre la OpenSSL real y `/proc/self/maps` |
| Derivación real de DWARF/BTF/análisis del binario | **frontera** | la decisión (derivar o `NoConcluyente`) se prueba; la fontanería de cada fuente se apoya en FASE 85/100 |
| Enganche del uprobe en un proceso vivo | **muro (gated)** | necesita `CAP_BPF`/`CAP_PERFMON` y una víctima TLS real; se declara |
| Cada biblioteca con prueba real de extremo a extremo | **muro de entorno** | lo que no se puede instalar en el CI se declara con su motivo |
| Comparativa medida contra eCapture | **muro de entorno** | requiere desplegar eCapture y un corpus; se declara |

El alcance por partes es la decisión honesta: se construye el mecanismo distintivo
—offset derivado o `NoConcluyente`, verificación en caliente, redacción en el tipo,
cobertura declarada— y la derivación real por DWARF/BTF/análisis, el enganche en
vivo y la comparativa medida se declaran en vez de fingirse.

Mensaje de commit:
`feat(tls): derive hook offsets from binary analysis with in-vivo verification and mandatory redaction policy`
