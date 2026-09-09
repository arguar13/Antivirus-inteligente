# Módulo 34 — Consola de administración en tiempo real

> Componentes: `server/panel/{index.html,estilo.css,app.js}`,
> `server/crates/aegis-server/src/{panel,eventos}.rs`,
> `server/crates/aegis-server/examples/poblar_flota.rs`.

La consola es la pieza desde la que una persona puede **aislar miles de máquinas
de producción con un clic**. Esa frase condiciona todo lo que sigue.

---

## 34.1 Por qué no hay `npm` ni cadena de construcción

La recomendación habitual sería React o un frontend en WASM. Aquí se descartaron
las dos, y conviene decir por qué con precisión:

- **Superficie de ataque.** Una aplicación React típica arrastra del orden de mil
  paquetes transitivos. El `deny.toml` de este proyecto dice literalmente que *la
  lista se mantiene deliberadamente corta*, y esa disciplina no puede aflojarse
  justo en el componente con más poder de todo el sistema.
- **Auditabilidad.** Sin empaquetador, **lo que se revisa es exactamente lo que
  ejecuta el navegador del operador**. No hay transformación entre el fuente
  auditado y el fichero servido.
- **Despliegue.** La consola va **embebida en el binario** con `include_str!`, así
  que forma parte del mismo artefacto cuyo SHA-256 y procedencia publica el
  pipeline. No hay un directorio de estáticos que pueda divergir de lo auditado
  ni un proceso Node aparte que parchear.

Módulos ES nativos y SVG bastan para lo que la consola hace. Una prueba
automática lo mantiene honesto:
`la_consola_no_carga_nada_de_fuera_del_servidor` falla si alguien introduce una
referencia a cualquier origen externo.

---

## 34.2 Dos fuentes de datos, y por qué hacen falta las dos

| Vía | Para qué | Cuándo |
|---|---|---|
| **REST** | el **estado**: inventario, alertas, reglas, inteligencia | al abrir una vista y cuando algo la invalida |
| **WebSocket** | los **sucesos**: una alerta que entra, un endpoint que late, una regla que se publica | solos, en el instante en que ocurren |

Un panel que solo sondeara llegaría tarde a lo único que importa —la alerta
crítica— y, multiplicado por cada operador conectado, sería carga constante sobre
la base de datos para no descubrir nada la mayoría de las veces. Uno que solo
escuchara sucesos no sabría pintar nada al abrirse. Por eso el canal entrega una
**instantánea** como primer mensaje.

### El canal pierde mensajes a propósito

El bus usa `broadcast`, que descarta lo más viejo cuando un receptor se queda
atrás, en vez de crecer sin límite. Es lo correcto: una consola lenta no puede
consumir la memoria del servidor. Cuando eso pasa, al cliente se le envía
`desincronizada` con cuántos perdió, y **vuelve a pedirlo todo** en lugar de
seguir con un estado incompleto creyendo que está al día.

---

## 34.3 Las tres vistas que resuelven una guardia

**Topología.** Rejilla de endpoints donde lo que exige atención va **primero**:
aislados, luego amenazados, luego caídos, y al final los sanos. El color solo se
usa para eso, para que un vistazo baste.

**Alertas.** Ordenadas por severidad y con su **técnica de MITRE ATT&CK**, que es
lo que permite correlacionarlas con inteligencia externa en vez de quedarse en
una etiqueta que solo entiende este producto.

**Linaje.** El árbol de procesos en SVG. Una detección aislada casi nunca
concluye nada: `python` abriendo un socket es rutina; `libreoffice → sh → python`
abriendo un socket es un incidente. Cada nodo muestra su puntuación de
comportamiento y los contaminados se marcan; al pulsarlo se despliega su ruta,
línea de comandos, claves de linaje y marcas de contaminación.

---

## 34.4 Respuesta de un clic

Aislar un endpoint **corta su red salvo con el plano de control**. La consola lo
trata con el peso que tiene:

- Pide **confirmación explícita** con el nombre de la máquina. No por burocracia:
  por un clic de más en la tarjeta equivocada.
- Explica **qué va a pasar** antes de hacerlo.
- Queda **registrado con el usuario** que lo ordenó — una acción destructiva
  sobre la máquina de alguien no puede ser anónima.
- El cambio se **difunde a las demás consolas** al instante: dos operadores
  actuando a ciegas sobre el mismo incidente es como se duplican las acciones de
  respuesta.

El servidor **encola** el comando y el agente lo recoge por su canal de política.
El aislamiento lo aplica el endpoint, no el servidor: así funciona aunque la
máquina esté tras un NAT y el plano de control no pueda alcanzarla.

---

## 34.5 Defensas de la propia consola

- **CSP sin `unsafe-inline` ni `unsafe-eval`**, `default-src 'self'`,
  `frame-ancestors 'none'`. En cabecera **y** en el documento.
- **`X-Frame-Options: DENY`** — una consola dentro de un marco ajeno es un
  secuestro de clics sobre botones que aíslan máquinas.
- **`X-Content-Type-Options: nosniff`** y **`Referrer-Policy: no-referrer`**.
- **Nunca `innerHTML` con datos del endpoint.** El hostname y la línea de
  comandos los declara una máquina que puede estar comprometida; se insertan con
  `textContent` para que no puedan inyectar marcado en la consola de quien los
  investiga.
- **Reconexión con espera creciente y tope**: la caída del servidor no convierte
  cada consola abierta en una fuente de tráfico en bucle.

### El token del WebSocket viaja en la consulta

El API de WebSocket del navegador **no permite añadir cabeceras** al handshake:
es una limitación del estándar. Las alternativas reales son una cookie o el
parámetro de consulta. Se eligió el parámetro para mantener la sesión en el mismo
mecanismo que el resto de la API —token portador, sin estado de cookie ni
exposición a CSRF— a cambio de que el token pueda aparecer en registros de
acceso; por eso las sesiones caducan y se pueden cerrar, y por eso esto viaja
siempre sobre TLS en producción.

---

## 34.6 Un fallo que solo el navegador podía encontrar

Durante la verificación se renderizó la consola en un **Chromium real**. El
estado del DOM era correcto —`#consola` visible, `#acceso` oculto— y aun así la
pantalla mostraba el formulario de acceso y, mucho peor, **el diálogo de aislar
endpoints permanentemente abierto**.

La causa: `.acceso` y `.modal` declaran `display: grid`, y una regla de autor
**sobreescribe** el `display: none` que el navegador aplica al atributo `hidden`.
El arreglo es una línea, `[hidden] { display: none !important; }`, pero el
hallazgo importa por otra razón: **ninguna prueba de unidad ni de API lo habría
detectado**, porque el DOM decía la verdad. Solo pintar la página lo reveló.

---

## 34.7 Sembrar una flota de demostración

```
AEGIS_CA_DIR=/var/lib/aegis/ca AEGIS_FLEET_ADDR=127.0.0.1:8443 \
  cargo run -p aegis-server --example poblar_flota
```

Enrola endpoints **reales** —el mismo `ClienteFlota` que corre en producción— con
certificados emitidos por la CA persistida del servidor, y les hace latir,
reportar alertas con su linaje de procesos y entregar inteligencia STIX. Sirve
para dejar la consola con datos y, de paso, para comprobar de extremo a extremo
que la cadena entera funciona junta: mTLS, protobuf, PostgreSQL, WebSocket y
consola.
