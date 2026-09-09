# Módulo 3 — Motor de detección

> Componente: `crates/aegis-scan` (Rust).

Tres motores independientes que votan: firmas YARA, modelo ML sobre ficheros y
reglas conductuales. Independientes a propósito: cada uno falla de forma
distinta, y su combinación cubre lo que ninguno cubre solo.

| Motor | Detecta | Ciego ante | Latencia |
|---|---|---|---|
| YARA-X | Familias conocidas, packers, cadenas concretas | Variantes nuevas | 50 µs – 5 ms |
| ML sobre PE/ELF | Binarios desconocidos por estructura | Todo lo que no es fichero | 200 µs – 1 ms |
| Reglas conductuales | Ransomware, inyección, *living off the land* | Lo que aún no ha actuado | Continua |

---

## 3.1 La restricción que domina el diseño: la tasa base

Antes de cualquier decisión sobre modelos, hay un hecho aritmético que decide
qué umbrales son admisibles.

Un endpoint típico tiene ~300.000 ficheros ejecutables entre binarios del
sistema, aplicaciones y dependencias. En un mes normal, los ficheros
efectivamente maliciosos son **0 o 1**.

Con una tasa de falsos positivos del 1 % —una cifra que en un artículo académico
se presentaría como excelente— eso son **3.000 falsos positivos** en el primer
escaneo completo. El producto es inutilizable. Con 0,1 %, son 300: sigue siendo
inutilizable.

**El objetivo operativo es FPR ≤ 10⁻⁵ en el punto de operación de bloqueo**, es
decir, ~3 falsos positivos por endpoint en un escaneo completo, y solo para la
acción de bloqueo. De ahí se derivan tres reglas que el resto del módulo respeta:

1. El umbral se elige sobre un conjunto de validación **con la proporción real
   de un endpoint** (cientos de miles de benignos, decenas de maliciosos), nunca
   sobre un conjunto equilibrado. Una precisión del 99 % medida sobre 50/50 no
   dice absolutamente nada sobre el comportamiento en producción.
2. Un único motor **nunca** bloquea por sí solo salvo con confianza muy alta. Lo
   normal es que bloquear exija corroboración.
3. La respuesta es **escalonada por confianza**, no binaria.

```rust
pub enum Respuesta {
    /// Solo telemetría. La inmensa mayoría de las puntuaciones altas acaba aquí.
    Registrar,
    /// Vigilancia reforzada: se activa el escaneo de memoria del proceso.
    Vigilar,
    /// Se impide la ejecución, el fichero permanece. Reversible por el usuario.
    Bloquear,
    /// Bloqueo + cuarentena cifrada + aislamiento de red del proceso.
    Contener,
}
```

---

## 3.2 Motor de firmas: YARA-X

Se usa **YARA-X** (la reescritura en Rust de VirusTotal), no libyara: sin
`unsafe` en el parseo de entrada hostil, y más rápido en la mayoría de conjuntos
de reglas.

### Concurrencia sin bloqueo de E/S

El error clásico es un `Mutex<Rules>` global: convierte el motor en
monohilo bajo carga, justo cuando más falta hace el paralelismo.

```rust
pub struct MotorYara {
    /// Reglas compiladas, inmutables y compartidas. El swap atómico permite
    /// recargar sin detener los escaneos en curso: los lectores que ya tienen
    /// un Arc terminan con la versión antigua y los nuevos toman la nueva.
    reglas: ArcSwap<Rules>,
}

impl MotorYara {
    pub fn escanear(&self, datos: &[u8]) -> Vec<Coincidencia> {
        // Carga sin locks: en la práctica un load atómico.
        let reglas = self.reglas.load();
        // Scanner barato y por hilo. El estado caro está en `reglas`.
        let mut scanner = Scanner::new(&reglas);
        scanner.scan(datos).into()
    }

    /// Recarga desde otro hilo. Compilar tarda cientos de ms; el swap es
    /// instantáneo y ningún escaneo en curso se interrumpe.
    pub fn recargar(&self, fuente: &str) -> Result<(), CompileError> {
        let nuevas = Compiler::new().add_source(fuente)?.build();
        self.reglas.store(Arc::new(nuevas));
        Ok(())
    }
}
```

### E/S fuera de la ruta caliente

El driver **nunca** espera a que se lea un fichero. La secuencia es:

1. El minifilter emite el evento y, si necesita veredicto, se queda esperando con
   plazo (módulo 2).
2. El agente encola el trabajo en una cola **acotada** (4096 elementos).
3. Un pool de hilos (tantos como núcleos físicos, prioridad por debajo de lo
   normal) lee el fichero mapeándolo y escanea.
4. El resultado se cachea por `(FILE_ID_128, USN)` y se responde.

Con la cola llena no se encola: se responde de inmediato con la política de
vencimiento. Es preferible dejar pasar un fichero desconocido durante una ráfaga
de compilación a que el sistema se arrastre.

Ficheros grandes: por encima de 64 MB solo se escanean cabecera, cola y las
secciones ejecutables. Escanear una ISO de 4 GB entera para buscar cadenas es
gastar segundos de CPU con probabilidad de detección casi nula.

---

## 3.3 Modelo ML local

### Elección: árboles con gradiente, no red neuronal

**LightGBM entrenado offline → exportado a ONNX → cuantizado a int8.** Frente a
una red neuronal sobre bytes crudos (tipo MalConv):

| Criterio | GBDT sobre características | Red sobre bytes crudos |
|---|---|---|
| Inferencia | ~200 µs | 10–50 ms |
| Tamaño | 6 MB int8 | 50–350 MB |
| Explicabilidad | SHAP por característica | Prácticamente nula |
| Robustez adversarial | Requiere alterar la estructura real | Se evade **añadiendo bytes al final** |
| Reentrenamiento | Minutos | Horas con GPU |

El punto decisivo es la robustez. Los modelos sobre bytes crudos son vulnerables
a ataques de *append*: añadir un bloque de bytes al final del ejecutable, sin
tocar una sola instrucción, cambia la clasificación. Un modelo cuyas
características son la estructura del PE obliga al atacante a modificar la
estructura real del binario, que es un coste que sí sube.

Explicabilidad no es un lujo: cuando el motor bloquea el instalador interno de
una empresa, hace falta poder decir *por qué* en segundos.

### Características (≈256 dimensiones)

```
Generales (16)
  log(tamaño), entropía global, entropía por bloques (media/máx/desv),
  ratio de bytes imprimibles, ratio de nulos

Histogramas (48)
  histograma de bytes en 16 cubos, histograma de entropía por bloque (32)

Cabecera PE (32)
  máquina, características, subsistema, versión del enlazador,
  bits de DllCharacteristics (ASLR, NX/DEP, CFG, integridad forzada),
  anomalía de marca temporal, tamaño de cabeceras vs real, checksum válido

Secciones (48)
  número de secciones, nombres no estándar, entropía por sección,
  presencia de secciones escribibles+ejecutables,
  ratio tamaño virtual / tamaño en disco (indicador de packer),
  punto de entrada en la última sección, punto de entrada fuera de sección

Importaciones (64)
  hashing de nombres de DLL y API en 64 cubos (truco del hash),
  número de importaciones, tabla de importación vacía (carga dinámica),
  presencia de APIs de inyección, de cifrado, anti-depuración

Cadenas y recursos (32)
  número de cadenas, longitud media, URLs, IPs, rutas, claves de registro,
  entropía de recursos, presencia de PE embebido

Firma (16)
  firmado, cadena válida, firmante conocido, sellado de tiempo,
  desajuste entre firma y contenido
```

El **truco del hash** en las importaciones evita un vocabulario fijo que
quedaría obsoleto: una API nueva cae en su cubo sin reentrenar el esquema.

Extracción presupuestada en < 2 ms para un binario de 5 MB, con parseo
tolerante a fallos: los PE malformados son habitualmente maliciosos, así que un
fallo de parseo es **una característica más**, no un error que aborta.

### Punto de operación y ciclo de vida

```rust
pub struct Umbrales {
    /// FPR objetivo 10^-5, medido sobre distribución real de endpoint.
    pub bloquear: f32,      // ~0.995
    /// FPR objetivo 10^-3.
    pub vigilar: f32,       // ~0.90
    /// Todo lo demás solo se registra.
    pub registrar: f32,     // ~0.60
}
```

Los umbrales se **calibran** (escalado de Platt sobre un conjunto retenido) para
que la salida sea una probabilidad interpretable y no una puntuación arbitraria.
Sin calibrar, «0,9» no significa lo mismo entre dos versiones del modelo y los
umbrales dejan de ser comparables entre despliegues.

Ciclo de vida del modelo:

- **Distribución**: paquete firmado (Ed25519). El agente verifica antes de
  cargar. Un modelo es código ejecutándose con privilegios altos: sustituirlo es
  equivalente a sustituir el binario.
- **Despliegue por fases**: 1 % → 10 % → 100 % de la flota, con parada
  automática si la tasa de detecciones se desvía más de 3σ de la anterior. Un
  pico de detecciones tras un despliegue es casi siempre un modelo roto, no una
  epidemia.
- **Reversión**: la versión anterior se conserva en disco; volver atrás es
  atómico y no requiere red.
- **Deriva**: el software benigno evoluciona (nuevos compiladores, nuevos
  packers legítimos). Reentrenamiento mensual con la línea base benigna
  actualizada.

---

## 3.4 Motor de reglas conductuales

### Ransomware: el caso que fija el presupuesto de latencia

El ransomware es la única amenaza donde el tiempo de detección se traduce
directamente en daño irreversible. Un cifrador moderno procesa 1.000–5.000
ficheros por minuto.

**Presupuesto: detener en < 500 ms desde el primer fichero cifrado, con menos de
20 ficheros perdidos**, y esos 20 recuperables desde el almacén de rollback
(módulo 4).

Cuatro señales, de menor a mayor concluyencia:

**1. Salto de entropía.** El kernel ya calcula entropía antes y después sobre el
buffer residente (módulo 1). Un documento pasa de ~4,5 a >7,9 bits/byte al
cifrarse. Barato y sin E/S adicional, pero por sí solo confunde cifrado con
compresión legítima.

**2. Dispersión.** Un proceso legítimo trabaja sobre pocos directorios. Un
cifrador recorre el árbol de documentos. Se mide con HyperLogLog (módulo 2).

**3. Renombrado masivo a extensión desconocida.** Casi todas las familias
renombran. Extensión no vista antes en el sistema + tasa alta = señal fuerte.

**4. Ficheros señuelo.** Ficheros con contenido plausible, sembrados en los
directorios de documentos, marcados en el minifilter. **Ninguna aplicación
legítima los abre para escritura**, porque nadie sabe que existen. Una sola
escritura sobre un señuelo es concluyente por sí misma.

```rust
regla! {
    nombre: "ransomware_cifrado_masivo",
    ventana: 10.segundos(),

    cuando: cualquiera![
        // Vía concluyente: un señuelo basta.
        senuelos_tocados >= 1,

        // Vía acumulativa: la combinación, no cada parte.
        todas![
            escrituras_alta_entropia >= 12,
            dispersion_directorios   >= 3,
            !es_proceso_de_respaldo_conocido(),
        ],

        todas![
            renombrados_extension_nueva >= 20,
            extension_no_vista_antes(),
        ],
    ],

    entonces: Respuesta::Contener,
}
```

### Contención determinista

Al confirmarse, el proceso hay que detenerlo **en el acto**. La forma de hacerlo
importa:

```rust
fn contener(proc: ProcKey) -> Result<()> {
    // 1. Denegar E/S en el kernel. Efecto inmediato y documentado: la siguiente
    //    escritura del proceso falla en el minifilter. No depende de suspender
    //    hilos ni de APIs no documentadas, que son frágiles entre versiones.
    driver.añadir_a_lista_denegacion(proc, DenyIo::EscrituraTodos)?;

    // 2. Aislar la red (módulo 4): impide la exfiltración previa al cifrado.
    resp.aislar_red(proc)?;

    // 3. Congelar para triaje forense, no para detener el daño: el daño ya
    //    está detenido en el paso 1.
    resp.suspender(proc)?;

    // 4. Restaurar desde el almacén copy-on-write lo que se perdió.
    resp.rollback_desde(proc, ventana: 60.segundos())?;
    Ok(())
}
```

El orden es deliberado. Se corta primero la escritura por la vía documentada del
minifilter, y solo después se suspende. Suspender un proceso multihilo mientras
tiene E/S en vuelo tiene condiciones de carrera; denegar en el filtro no.

### Otras familias de reglas

- **Cadenas de *living off the land***: `winword → cmd → powershell -enc`. La
  regla se apoya en los *taints* del grafo (módulo 2), no en nombres de proceso.
- **Inyección**: asignación remota de memoria ejecutable + escritura remota +
  creación de hilo remoto sobre esa región, por el mismo actor y en ventana
  corta. La secuencia completa es lo que detecta; cada paso por separado ocurre
  legítimamente.
- **Borrado de evidencia**: `vssadmin delete shadows`, `wbadmin delete catalog`,
  `bcdedit /set recoveryenabled no`, limpieza de registros de eventos. Preludio
  clásico del cifrado y, por sí solo, ya justifica bloquear.
- **Persistencia**: escritura en claves de arranque desde un proceso con
  contaminación `FROM_INTERNET` o `OFFICE_CHILD`.

### Gestión de falsos positivos

Un motor conductual sin gestión de falsos positivos es un generador de ruido:

- **Línea base por endpoint**: los primeros 7 días se aprende qué es normal en
  *esa* máquina (un servidor de compilación escribe miles de ficheros de alta
  entropía; un portátil de contabilidad no).
- **Lista de exclusión firmada**: procesos de respaldo y sincronización
  conocidos, identificados por firma del editor, nunca por ruta (una ruta la
  ocupa cualquiera).
- **Exclusiones del usuario**: por hash y firma, con caducidad. Nunca por
  comodín de directorio: `C:\temp\*` es la exclusión que el atacante busca.

→ Siguiente: [Módulo 4 — Respuesta y aislamiento](04-respuesta.md)

---

## Anexo: el umbral de entropía que no se podía cruzar

`crates/aegis-ransom` nació comparando la entropía de la muestra de escritura
contra **7,9 bits/byte absolutos**. Es el número que aparece en toda la
literatura para "datos cifrados o comprimidos", y es correcto — sobre ficheros
completos.

La sonda de kernel no entrega ficheros completos. Entrega **512 bytes** del
principio del búfer que el proceso acaba de pasar a `write`, porque copiar más
en el camino caliente de cada escritura del sistema no es aceptable y porque
`bpf_ringbuf_reserve` exige un tamaño constante.

Y con 512 muestras sobre 256 símbolos, la entropía **medida** de datos
perfectamente aleatorios no llega a 8,0. Ni se acerca:

| Tamaño de muestra | Entropía media de `/dev/urandom` | Mínimo observado |
|---|---|---|
| 64 B | 5,77 | 5,50 |
| 512 B | **7,59** | **7,47** |
| 4 KB | 7,96 | 7,94 |
| 64 KB | 8,00 | 8,00 |

*(400 extracciones por tamaño.)*

El umbral de 7,9 sobre una muestra de 512 bytes **no lo cruza ningún dato real,
por aleatorio que sea**. Las dos señales que dependían de él —
`HighEntropyBurst` y, sobre todo, `EntropyTransition` — estaban muertas: el
motor habría corrido en producción reportando sólo velocidad y dispersión, que
por sí solas no llegan al umbral de confirmación.

Lo que hace especialmente incómodo el fallo es que **ninguna prueba que inyecte
valores de entropía a mano lo detecta**. Un test que llama
`on_write(actor, pid, ruta, 7.95, ...)` pasa perfectamente y no prueba nada: el
7,95 es una ficción que el sistema real nunca produce.

### La corrección

`aegis_ml::entropy::entropia_maxima_esperada(n)` devuelve la entropía que de
hecho producen datos aleatorios a ese tamaño de muestra, interpolando la tabla
medida arriba. La comparación pasa a ser una **fracción**:

```text
fracción = H_medida / H_máxima_esperada(n)
```

- `FRACCION_CIFRADO = 0,95` — por debajo de la peor extracción aleatoria
  observada a cualquier tamaño desde 64 B.
- `FRACCION_ESTRUCTURADA = 0,85` — a 512 B equivale a 6,45 bits/byte, por
  encima de un ejecutable sin empaquetar (~6,0) y muy por debajo de datos
  cifrados.

A 512 bytes, texto plano da 0,51 y datos cifrados 0,98–1,00. El margen es
enorme, que es como tiene que ser un umbral: no algo que haya que ajustar con
decimales, sino una separación que no dependa de la calibración fina.

La misma corrección se aplicó al atributo de "sección empaquetada" de
`aegis-ml`: una sección de menos de 1 KB no podía superar 7,5 bits/byte aunque
fuese ruido puro, y por tanto se clasificaba como limpia por construcción.

### Muestras que no se juzgan

Una escritura por debajo del mínimo de muestreo llega **sin** muestra. Anotarla
como entropía cero fabricaría una fase estructurada que nunca se observó, y con
ella una transición falsa en cuanto el proceso escribiese algo comprimido. Por
eso `WriteObservation::entropy_ratio` es `Option<f64>`: cuenta para velocidad y
dispersión, y no toca el historial de entropía.
