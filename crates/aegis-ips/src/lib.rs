//! # `aegis-ips` — AegisIPS: prevención en línea (FASE 71)
//!
//! ## De detectar a bloquear, que no es un paso pequeño
//!
//! Todo lo anterior del producto **observa**. Esta fase **corta**. La diferencia
//! práctica cabe en una frase:
//!
//! > Un falso positivo en un IDS es una alerta que alguien descarta. Un falso
//! > positivo en un IPS es una **interrupción de servicio**.
//!
//! Eso gobierna el diseño entero. No es que haya salvaguardas *además* del motor
//! de bloqueo: es que las salvaguardas **son** el diseño, y el motor de bloqueo
//! es la parte fácil.
//!
//! ## Dónde corre cada cosa, y por qué ahí
//!
//! | | Quién | Dónde | Por qué |
//! |---|---|---|---|
//! | **Juzgar** | [`decisor::Decisor`] | Ring 3 | aplicar reglas con contexto no cabe en un programa que el verificador acota |
//! | **Aplicar** | programa TC | kernel | un paquete que sube a userland para decidirse ya pagó el coste que esto existe para evitar |
//!
//! El veredicto de un flujo se **escribe en un mapa eBPF**. El primer paquete
//! sospechoso sube, se juzga una vez, y el veredicto baja. A partir de ahí el
//! resto del flujo se corta con una búsqueda de mapa, sin volver a subir. Ésa es
//! la única forma de que bloquear no cueste rendimiento.
//!
//! ## Por qué TC y no XDP
//!
//! XDP es más barato y corre antes, y por eso el filtro de barridos de
//! [`aegis_net`](../aegis_net/index.html) sigue ahí. Pero **XDP no tiene camino
//! de salida**: es un gancho de recepción y nada más.
//!
//! Y para un EDR el sentido que más importa cortar es justamente el **saliente**:
//! la baliza hacia el C2, la exfiltración, el movimiento lateral hacia otra
//! máquina de la propia red. Un IPS que sólo filtre lo que entra deja pasar
//! precisamente el tráfico que confirma que la máquina ya está comprometida.
//!
//! TC con `clsact` tiene los dos ganchos, así que un solo programa cubre la
//! conversación entera — y convive con el filtro XDP en la misma interfaz, de
//! modo que esta fase no tiene que quitar ni reescribir nada de lo que ya
//! funciona.
//!
//! ## Las cuatro salvaguardas
//!
//! | # | Salvaguarda | Dónde se comprueba | Qué impide |
//! |---|---|---|---|
//! | 1 | Sólo la confianza **alta** corta ([`Confianza`]) | Ring 3 | que una heurística tire la red de un cliente |
//! | 2 | **Activos protegidos** ([`Protegidos`]) | Ring 3 **y kernel** | que un incidente se convierta en un apagón, o que el atacante use la defensa como arma |
//! | 3 | **Modo** ([`Modo`]), por defecto sólo detección | Ring 3 **y kernel** | llegar bloqueando el primer día |
//! | 4 | **Tope de bloqueos** con degradación ([`Limitador`]) | Ring 3 | que un motor que se equivoca siga equivocándose a escala |
//!
//! Las dos que dicen «y kernel» se comprueban **otra vez** abajo, antes de
//! cortar. No es redundancia por gusto: una salvaguarda que depende de que el
//! código de decisión esté bien no protege del caso que importa, que es
//! justamente que el código de decisión esté mal.
//!
//! ## El camino escalonado, que es el producto de verdad
//!
//! 1. **Sólo detección** *(por defecto)*. Se ve lo que hay, no se toca nada.
//! 2. **Bloqueo con aprendizaje.** Se registra lo que se HABRÍA cortado, con su
//!    regla y su flujo. El cliente mira esa lista.
//! 3. **Bloqueo.** Sólo cuando esa lista ya no tiene sorpresas.
//!
//! El paso 2 es lo que hace posible el 3 sin apostar. Sin él, activar el bloqueo
//! es un salto a ciegas sobre la red de otro.
//!
//! ## Las reglas miran hechos, no bytes
//!
//! Un IPS clásico busca cadenas dentro del paquete: se evade partiendo la cadena
//! entre dos segmentos, y no dice nada del tráfico cifrado.
//!
//! Aquí las reglas miran lo que produce [`aegis_wire`]: un nombre DNS ya
//! descomprimido, una huella JA3 ya calculada, el SHA-256 de un fichero ya
//! reensamblado. Eso cierra las dos evasiones —el disector ya reensambló y ya
//! normalizó— y permite escribir reglas sobre sesiones cifradas **sin descifrar
//! nada**, porque la huella y el SNI viajan en claro.
//!
//! ## Honestidad de validación
//!
//! | Pieza | Verificable aquí | Cómo |
//! |---|---|---|
//! | Un activo protegido no se corta jamás | **Sí** | con la regla de máxima confianza, en modo bloqueo y con el limitador libre |
//! | Sólo la confianza alta corta | **Sí** | las tres confianzas contra la misma regla y el mismo hecho |
//! | El modo aprendizaje registra y no corta | **Sí** | y se comprueba que lo **cuenta**, que es su razón de ser |
//! | La degradación se dispara y se declara | **Sí** | y que es pegajosa: no se re-arma sola |
//! | Ráfaga a caballo del corte de ventana | **Sí** | ventana deslizante; un contador que se reinicia no la vería |
//! | Decisión reproducible | **Sí** | el mismo conjunto de reglas decide igual sea cual sea el orden de carga |
//! | Los programas eBPF pasan el verificador **real** | **Sí** | `make -C drivers/linux/aegis-bpf verify`, en cada `make ci` |
//! | Corte real sobre tráfico generado de verdad | **Sí, con privilegios** | `tests/corte_vivo.rs` monta un par `veth` y mide; sin `CAP_NET_ADMIN` se **declara omitido**, no se da por bueno |
//! | Que el plano de datos no pierde paquetes | **Medido, no prometido** | contadores del propio programa, contrastados con lo enviado |
//! | IPv6 | **No, y se declara** | el plano de datos juzga IPv4; lo demás pasa y **se cuenta** en `NO_CLASIFICADOS` |
//! | Cortar a velocidad de 10 GbE | **No aquí** | eso se mide en hardware real con carga real, no en un contenedor de CI |

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod confianza;
pub mod decisor;
pub mod error;
pub mod latencia;
pub mod limitador;
pub mod modo;
pub mod protegidos;
pub mod regla;
pub mod veredicto;

#[cfg(all(target_os = "linux", feature = "kernel"))]
pub mod plano;

pub use confianza::Confianza;
pub use decisor::{ConfigDecisor, ContadoresDecisor, Decisor, VIGENCIA_US};
pub use error::ErrorIps;
pub use latencia::MedidorLatencia;
pub use limitador::{Limitador, Permiso, TOPE_POR_VENTANA, VENTANA_US};
pub use modo::Modo;
pub use protegidos::{MotivoProteccion, Protegidos};
pub use regla::{Criterio, Regla};
pub use veredicto::{Accion, Flujo, MotivoNoCorte, Veredicto};
