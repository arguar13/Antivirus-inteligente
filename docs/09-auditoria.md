# Módulo 9 — Registro de auditoría local cifrado

> Componente: `crates/aegis-audit` (Rust, SQLite embebida + AES-256-GCM).

Un EDR tiene que dejar constancia de lo que ve: para el análisis forense
posterior, para el operador, para poder responder a "¿por qué aislaste ese
proceso?". Pero esa constancia es a la vez un activo y un riesgo, y el módulo se
diseña alrededor de los dos.

---

## 9.1 El registro es información sensible

El detalle de un evento lleva rutas, líneas de comando, direcciones de red: un
mapa de la actividad del equipo. Si el registro se guardara en claro, robar el
fichero sería robar esa información.

**El cuerpo de cada evento se cifra con AES-256-GCM, por fila.** Los metadatos
—instante, gravedad, tipo, actor— se guardan en claro.

### Por qué metadatos en claro y cuerpo cifrado

Es un compromiso deliberado, no un descuido:

- Cifrar **también** los metadatos (como haría SQLCipher a nivel de página)
  impediría consultar sin la clave. El agente necesita consultar en caliente
  ("dame los incidentes críticos de la última hora") sin tener que descifrar
  todo el fichero.
- Dejar el **cuerpo** en claro expondría lo que de verdad importa.

Con este reparto, un atacante con el fichero ve la **forma** de la actividad
(cuántos incidentes, cuándo, de qué tipo) pero no su **contenido**. Se elige
poder consultar y proteger el detalle.

### Dos propiedades criptográficas, y de quién es cada una

1. **El nonce no se repite jamás bajo la misma clave.** GCM se rompe por
   completo si un par (clave, nonce) se reutiliza. El nonce se construye como
   `id ‖ secuencia_de_segmento`, ambos monótonos: el `id` es único dentro de un
   fichero, y la secuencia del segmento es única entre ficheros rotados, así que
   el par no se repite en toda la vida del despliegue.
2. **El texto cifrado está ligado a su fila.** El dato autenticado adicional
   (AAD) incluye id, segmento, instante, tipo y actor. Sin esa ligadura, un
   atacante podría **intercambiar** los cuerpos de dos filas —mover el detalle
   de un incidente a una fila benigna, o borrar el rastro de un ataque— sin
   romper ningún tag GCM, porque cada tag solo protege su propio texto. Con la
   AAD, mover un cuerpo a otra fila invalida la autenticación.

Las dos propiedades se prueban abriendo el fichero SQLite **por fuera** del
registro: se verifica que el detalle sensible no aparece en claro, que un byte
cambiado en un cuerpo se detecta, y que intercambiar dos filas rompe la
autenticación. Un cifrado que se probara solo contra su propio descifrado no
probaría nada.

---

## 9.2 El registro no puede llenar el disco

Un registro que crece sin límite es un fallo de disponibilidad esperando a
ocurrir. Cuando el fichero activo supera un tamaño (**100 MB** por defecto, el
límite que fija el presupuesto de disco), se **sella** —se renombra con su
secuencia— y se abre uno nuevo. Se conserva un número acotado de segmentos
sellados; los más antiguos se borran. El coste en disco está acotado por diseño.

El tamaño no se comprueba en cada evento —sería una llamada al sistema por
evento— sino cada N escrituras, lo bastante a menudo para no pasarse del límite
más de un lote.

---

## 9.3 Por qué SQLite embebida

La base es SQLite compilada **dentro** del binario (sin depender de una librería
del sistema), así que consultar por instante o por gravedad es una consulta
**indexada** y no un recorrido de todo el fichero. Se usa WAL para que las
escrituras no bloqueen las lecturas de la consola, y `synchronous = NORMAL` para
no pagar un `fsync` por evento: un registro de auditoría prioriza no frenar la
detección sobre no perder el último evento ante un corte de corriente.
