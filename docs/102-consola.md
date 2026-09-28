# Módulo 102 — AegisConsole: la consola del SOC (FASE 110)

> Componentes: nuevo `server/crates/aegis-consola/` (lado servidor que guarda), y
> el cliente web `panel/` (frontera declarada). Cubierto por `Servidor · tests`.

## 102.1 La derrota que cierra, y las dos invariantes que no se saltan

Wazuh, TheHive, MISP, OpenCTI, Velociraptor, Arkime y Timesketch tienen interfaz, y
en varios de ellos la interfaz **es** el producto. AegisCore tenía API y CLI. Esta
fase construye el lado servidor de la consola, y lo hace respetando dos invariantes
que la interfaz no puede saltarse:

- **La consola CONSULTA y GUARDA; no decide** (invariante 9). No hay lógica de
  veredicto aquí: si el panel calculara un riesgo por su cuenta, habría dos
  verdades. Lo que la consola enseña es lo que dijo el árbitro.
- **La consola no es un camino de salida nuevo** (invariante 8). Todo lo que
  exporta pasa por el **mismo** estrangulamiento de la FASE 78 que TAXII, la
  federación y el enjambre.

## 102.2 Lo que gana a las demás: el linaje unificado

Esas consolas enseñan lo que su producto sabe: una de red, otra de ficheros, otra
de procesos. Ninguna cruza los cinco planos en **una** cadena, porque ninguna tiene
un modelo de entidad único. AegisCore sí: `linaje::Linaje` es un solo grafo que va
de una baliza de red → al proceso que la emitió → al fichero que lo lanzó → a la
identidad que lo ejecutó → a la respuesta que se ordenó, **navegable en las dos
direcciones**. Es el linaje unificado que solo puede enseñar quien tiene el modelo
único, y es la superioridad estructural de esta vista.

## 102.3 El lado servidor que guarda (lo que puede estar mal de forma peligrosa)

La API de hoy tenía autenticación pero **ninguna autorización** y **ningún
aislamiento real por inquilino**. Esta fase pone la parte que decide quién ve qué y
qué puede salir —que es la que, mal hecha, es una fuga— en Rust puro y probado:

- **RBAC** (`rbac`): roles del SOC (analista, responsable, administrador, auditor)
  y un permiso por acción. El auditor **solo lee** —su poder es no tener poder—; un
  analista no aísla la flota por sí solo; gestionar usuarios y detección es solo del
  administrador. La autorización es una función pura sobre una tabla a la vista.
- **Aislamiento multi-inquilino** (`inquilino`): el inquilino va ligado a la
  **sesión**, no a un parámetro que el cliente elige, y un recurso de otro inquilino
  no se ve —ni por una consulta, ni por un id adivinado—. El filtrado se hace en un
  solo sitio para que ninguna vista nueva se olvide.
- **Coste de consulta antes de ejecutar** (`consulta`): hoy la caza devuelve el
  coste **después** de lanzarla; aquí `previsualizar` lo calcula **sin efectos**,
  para que el analista decida antes de tocar la flota.
- **Estrangulamiento de exportación** (`exportacion`): todo lo que la consola
  exporta pasa por `aegis-share::Difusor` (FASE 78). Un indicador `TLP:RED` no sale
  ni exportando a fichero; no hay un `exportar_sin_juez`.

## 102.4 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| RBAC por acción | **sí** | auditor solo lee; analista no contiene; admin gestiona; deniega con motivo |
| Aislamiento multi-inquilino | **sí** | una sesión no ve recursos de otro inquilino, ni por id adivinado |
| Coste de consulta antes de ejecutar | **sí** | `previsualizar` es puro, sin efectos; una consulta cara se detecta antes |
| Exportación por el juez de la FASE 78 | **sí** | `TLP:RED` no sale; revocado no sale; el tope del destino se respeta |
| Linaje unificado navegable | **sí** | una cadena cruza los 5 planos y se navega en las dos direcciones |
| Autoataque: consola como fuga y abuso de rol | **sí** | export retenido, RBAC deniega, inquilino ajeno no se ve |
| Cliente web (panel/) con las 10 vistas | **frontera declarada** | el lado servidor está; el render directo en TS y cada vista se construyen encima |
| Cableado de vistas a sus subsistemas | **frontera declarada** | entidad, veredicto multi-motor, análisis (100), enriquecimiento (77), procedencia (108), pérdida del sensor (103) y atestación (105) se exponen cableando esos crates a `aegis-server` |
| RBAC/tenant aplicados en cada endpoint de `aegis-server` | **incremento siguiente** | la lógica de guarda está en `aegis-consola`; su aplicación en el router es el cableado |
| Tiempo real | **ya existe** | el bus WebSocket de `aegis-server` (12 eventos) se reutiliza |

El alcance por partes es la decisión honesta: se construye la parte que puede estar
mal de forma peligrosa —quién ve qué, qué puede salir, cuánto cuesta una consulta,
y el linaje unificado— en Rust puro y probado, y el cliente web completo con sus
diez vistas y el cableado de cada una a su subsistema se construyen sobre este lado
servidor, en vez de fingir una interfaz terminada.

Mensaje de commit:
`feat(console): implement the SOC console with unified lineage navigation and pre-execution query cost`
