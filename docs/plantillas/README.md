# AegisCore

**EDR/XDR para Linux escrito en Rust.** Telemetría desde el kernel con eBPF,
correlación y respuesta en el endpoint, y un plano de control para la flota. Sin
bloatware: solo detección, aislamiento y respuesta.

> **Cómo leer este documento.** Todo lo que aquí es una cifra, una tabla de
> estado o un diagrama se **genera desde el código** (`cargo xtask docs`) y una
> puerta de `make ci` falla si deja de coincidir. Lo que se afirma sin cifra es
> diseño. Lo que no funciona todavía está escrito más abajo, en
> [Huecos conocidos](#huecos-conocidos), y no en una nota al pie.

## Estado del producto

Un componente cuenta como **Producto** solo si lo ejecuta un binario instalable,
lo ejerce una prueba de extremo a extremo sobre kernels reales y está medido.
Todo lo demás es **Biblioteca**: código probado que hoy no protege ninguna
máquina.

{{estado}}

## En cifras

{{cifras}}

## Por qué otro antivirus

Las suites comerciales fallan en dos ejes a la vez. Por un lado se han convertido
en plataformas de venta cruzada: VPN, limpiador de registro, gestor de
contraseñas, avisos de renovación. Por otro, su detección sigue anclada en firmas
de fichero justo cuando el malware moderno ha dejado de tocar el disco: ejecución
en memoria, *living off the land*, llamadas al sistema directas para saltarse los
ganchos de espacio de usuario, y ransomware que cifra miles de ficheros antes de
que un escaneo programado se entere.

AegisCore ataca el problema desde donde el atacante no puede mentir: el kernel.
Un proceso puede desengancharse de sus bibliotecas, falsificar su proceso padre o
ejecutar código que nunca existe como fichero. Lo que no puede hacer, sin haber
comprometido antes el propio kernel, es ocultarle al kernel lo que hace.

## Principios de diseño

| Principio | Compromiso concreto | Cómo se verifica |
|---|---|---|
| **Verdad antes que cobertura** | Cada capacidad se declara Producto, Condicional o Biblioteca según lo que se ejecuta, no según lo que se escribió | [Matriz de capacidades](docs/matriz-capacidades.md), generada de los binarios |
| **Nunca en silencio** | Una familia de telemetría que no se puede sostener es `SinDatos` y se dice al arrancar; nunca «limpio» | `aegis-agent --capacidades` en cada kernel de la matriz |
| **Eficiencia permanente** | Presupuesto de memoria por clase de host, impuesto por el kernel | Tabla de abajo, calculada con el código del agente; cgroup v2 |
| **Cero bloatware** | Solo defensa, detección, aislamiento y respuesta | Revisión: lo que no reduce el riesgo de compromiso no entra |
| **Seguridad de memoria** | Rust; `unsafe` prohibido salvo con justificación escrita | `tools/lineabase-unsafe.txt` y la invariante que la comprueba |
| **La nube fuera de la decisión** | El veredicto local manda y bloquea; la nube solo refina después | Pruebas con el enlace cortado de verdad |

## Presupuesto de recursos

El agente no gasta un número fijo: gasta una **fracción de la RAM del host, con
suelo y con techo**. La fracción hace que escale, el suelo mantiene capaz al
host pequeño y el techo impide que en un host enorme el agente crezca solo
porque puede. Hay tres regímenes, porque vigilar, escanear y amenazar al host
son situaciones distintas:

- **Reposo**: vigilancia sin trabajo pesado. Es lo que el administrador ve casi
  siempre.
- **Pico**: escaneo completo, recarga de firmas, desempaquetado. Es transitorio;
  quedarse aquí es la señal de contención.
- **Techo duro**: a partir de aquí el agente es un riesgo para la máquina que
  protege. El cgroup lo detiene y el watchdog lo levanta.

{{presupuesto}}

En una pasarela pequeña el agente es una parte apreciable del host, y la tabla
lo dice en vez de disimularlo: quien decide si lo despliega tiene que saberlo.

Tres capas lo imponen, y la tercera existe porque las dos primeras las ejecuta un
proceso que puede estar comprometido o simplemente tener un fallo:

| Capa | Quién la aplica | Qué hace |
|---|---|---|
| Reparto | Cada componente, vía `Presupuesto::cuota` | Pide lo que le toca en vez de llevar una constante inventada |
| Contención | El agente sobre sí mismo | Suelta lo elástico y rechaza trabajo pesado **antes** de llegar al techo |
| Obligación | El **kernel**, vía `MemoryHigh`/`MemoryMax` de cgroup v2 | Detención dentro del cgroup y reinicio, sin tocar al host |

## Arquitectura

{{c4}}

**La decisión central:** la nube está fuera de la ruta de decisión. El veredicto
local es autoritativo y bloquea; la nube solo refina a posteriori. Un diseño que
exija una consulta remota para permitir una ejecución añade latencia de red a
cada proceso nuevo y deja la máquina sin protección en cuanto cae el enlace.

Los **dos espacios de trabajo están separados a propósito**. El agente es
síncrono, sin runtime asíncrono, con presupuesto de memoria y `panic = "abort"`;
el plano de control es justo lo contrario (tokio, axum, tonic, sqlx). Mezclarlos
contaminaría el árbol de dependencias del agente, que en un EDR **es** superficie
de ataque, con cientos de crates que solo necesita el servidor.

### Ejecutables instalables

Lo que llega de verdad a una máquina. La lista única está en
[`tools/config/instalables.toml`](tools/config/instalables.toml) y la leen los
scripts de construcción, la matriz y este documento.

{{instalables}}

### Capas

Cada crate pertenece a una capa —núcleo, plataforma, motores o E/S— y solo puede
depender de su capa o de una inferior. `cargo xtask capas` lo comprueba en cada
`make ci`; las pocas excepciones que quedan tienen su causa y su plan en
[`tools/config/capas.toml`](tools/config/capas.toml) y la lista solo puede
menguar.

## Huecos conocidos

Lo que la documentación de fases anteriores daba por hecho y el código no hace.
Cada punto está reflejado en la [matriz de capacidades](docs/matriz-capacidades.md)
o en el [modelo de amenazas](docs/modelo-de-amenazas.md), y es trabajo de las fases
de integración y de endurecimiento:

- **La API de administración no autentica** ([AM-3.3](docs/modelo-de-amenazas.md#am-3--atacante-en-la-red-contra-grpc-la-api-y-la-malla)).
  El inicio de sesión emite una sesión a cualquier nombre de usuario, sin
  credenciales, y no hay control de acceso por rol en el servidor instalado. Hoy
  solo lo contiene que la API escuche en la interfaz local por defecto: **no se
  debe exponer a una red**.
- **El bucle del agente solo usa el grafo de linaje y el triaje.** Los motores
  conductual, de ransomware, de TinyML y el micro-sandbox están en el árbol de
  dependencias, pero `main` no los llama y el enlazador los descarta.
- **Las capacidades avanzadas son bibliotecas.** Caza en memoria, TLS en claro,
  integridad por significado, reversión de ransomware, antirootkit o auditoría de
  firmware tienen pruebas y verificadores, pero ningún ejecutable instalable las
  invoca.
- **El watchdog vigila un latido que el agente no escribe.** El supervisor espera
  un fichero de latido que el agente todavía no produce.
- **El cliente de flota es una demostración autocontenida.** `aegis-fleet` levanta
  su propia autoridad de certificación y su propio plano de control y se habla a sí
  mismo; no se conecta al `aegis-server` real, y el diagrama no dibuja esa flecha.
- **El despliegue con Ansible llama a órdenes que el agente no tiene** (enrolar,
  estado en JSON, comprobar la configuración).
- **Windows y macOS no son producto.** El driver de Windows compila pero cargar la
  protección viva exige un certificado de Microsoft; en macOS hay análisis de
  binarios, no un agente. La reputación en la nube tiene cliente pero no servicio.

## Estructura del repositorio

```
crates/                 Workspace del AGENTE: síncrono, sin runtime asíncrono, panic=abort
server/crates/          Workspace del PLANO DE CONTROL: tokio, axum, tonic, sqlx
swarm-net/              Transporte libp2p del enjambre, fuera del agente a propósito
xtask/                  Tareas del repositorio: cargo xtask <orden>
drivers/linux/aegis-bpf Sondas eBPF CO-RE y filtro XDP (C, libbpf)
kernel/windows/         Driver de Windows (C, WDK): compila; su carga viva es un muro
shared/include/         Contrato ABI Ring 0 ↔ Ring 3 (fuente de verdad)
server/panel/           Consola SOC web, embebida en el binario del servidor
deploy/                 Terraform, Ansible e instalador de Windows
tools/                  CI local, verificadores y configuración (tools/config/)
docs/                   Documentos vivos y registro de fases
```

## Componentes

### Agente — `crates/`

Corre en cada endpoint, con privilegios.

{{componentes_agente}}

### Plano de control — `server/crates/`

{{componentes_servidor}}

## Documentación

{{documentacion}}

## Desarrollo

```bash
make ci                        # la puerta de calidad completa
cargo xtask docs               # regenera este README y la matriz de capacidades
cargo xtask arquitectura       # capas e idioma de los nombres
cargo xtask kernels traer      # descarga las imágenes de la matriz de kernels
cargo xtask kernels ejecutar   # arranca cada distribución en una microVM
cargo xtask                    # ayuda completa
```

### Cómo editar esta documentación

| Quieres cambiar… | Edita… | Y luego |
|---|---|---|
| La prosa de este README | [`docs/plantillas/README.md`](docs/plantillas/README.md) | `cargo xtask docs` |
| Los ejecutables que se publican | [`tools/config/instalables.toml`](tools/config/instalables.toml) | `cargo xtask docs` |
| El diagrama de arquitectura | [`tools/config/documentacion.toml`](tools/config/documentacion.toml) | `cargo xtask docs` |
| Las distribuciones y kernels probados | [`tools/config/kernels.toml`](tools/config/kernels.toml) | `cargo xtask kernels ejecutar` |
| La capa de un crate | [`tools/config/capas.toml`](tools/config/capas.toml) | `cargo xtask capas` |
| Una capacidad que depende de hardware | [`tools/config/condiciones.toml`](tools/config/condiciones.toml) | `cargo xtask docs` |

`README.md` y `docs/matriz-capacidades.md` **no se editan a mano**: se
sobrescriben. La prosa de la plantilla no admite cifras escritas a mano —una
cantidad con unidad fuera de un bloque de código hace fallar la generación—,
porque las cifras escritas a mano envejecen solas y nadie se entera.

Las partes que tocan el kernel necesitan `CAP_BPF`, `CAP_PERFMON` y
`CAP_NET_ADMIN`, un kernel con BTF y `tracefs` montado. En una máquina de
desarrollo sin ellos, las pruebas unitarias correspondientes se saltan con aviso;
la **matriz de kernels**, en cambio, es obligatoria en el CI y no se salta.

`tools/abi-check.sh` es obligatorio: las aserciones `const` de Rust fijan los
desplazamientos esperados, pero no pueden ver la cabecera de C, y sin la
comparación cruzada un cambio en `aegis_abi.h` se vería en producción como campos
desplazados.

## Licencia

Apache-2.0.
