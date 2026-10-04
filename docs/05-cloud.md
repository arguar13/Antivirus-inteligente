# Módulo 5 — Nube y threat intelligence

> Componentes: `cloud/api` y `cloud/sandbox` (Go).

Todo lo de este módulo es **asíncrono y opcional**. Un endpoint sin red se
defiende con YARA, el modelo local y las reglas conductuales. La nube aporta
tres cosas que no caben en el disco del cliente: reputación de miles de millones
de hashes, detonación en sandbox y agregación de señales entre endpoints.

**Invariante de arquitectura:** ninguna consulta a la nube está en la ruta de
decisión. Si lo estuviera, cada `CreateProcess` pagaría latencia de red y un
corte del enlace dejaría al usuario sin protección.

---

## 5.1 Reputación con k-anonimato

### El problema de privacidad

Enviar el SHA-256 completo de cada fichero que se ejecuta parece inocuo y no lo
es. El hash **identifica el fichero de forma única**. La secuencia de hashes de
un equipo revela qué software usa, qué documentos abre y qué binarios internos
propietarios tiene esa empresa. Es un registro de actividad con nombre y
apellidos, y el servidor no debería poder construirlo aunque quisiera.

### El mecanismo

El cliente envía solo un **prefijo** del hash. El servidor devuelve todos los
hashes conocidos que empiezan por ese prefijo. El cliente compara localmente.

```
Cliente:  sha256(fichero) = a3f2b8c1d4e5...
          envía prefijo de 20 bits: a3f2b
Servidor: devuelve los ~1.000 hashes que empiezan por a3f2b, con su veredicto
Cliente:  busca el suyo en la lista, localmente
```

El servidor sabe que el cliente preguntó por *algo* dentro de un conjunto de
~1.000 candidatos. No sabe cuál. Y como el resto del hash nunca sale del equipo,
tampoco puede saberlo después.

### Elegir el tamaño del prefijo

Con un corpus de N ≈ 10⁹ hashes conocidos (≈ 2³⁰) y un prefijo de *p* bits, el
tamaño esperado del cubo es 2^(30−p):

| Prefijo | Cubo (k) | Respuesta sin comprimir | Valoración |
|---:|---:|---:|---|
| 16 bits | ~16.384 | ~180 KB | Anonimato excelente, tráfico prohibitivo |
| **20 bits** | **~1.024** | **~11 KB** | **Elegido** |
| 24 bits | ~64 | ~700 B | k demasiado pequeño: con consultas repetidas el servidor correlaciona |
| 32 bits | ~0,25 | ~30 B | Equivale a enviar el hash completo |

**20 bits** deja k ≈ 1.000, que resiste la correlación entre consultas
sucesivas, con 11 KB por consulta que bajan a ~4 KB con compresión y que en la
práctica se amortizan: el 95 % de las consultas se resuelve en la caché local
sin salir a la red.

Cada entrada devuelve solo los 12 bytes restantes del hash (no los 32: los
primeros ya los conoce el cliente) más el veredicto y su antigüedad.

### Protocolo

```go
// POST /v1/reputation/lookup
type LookupRequest struct {
    // Prefijos de 20 bits, empaquetados. Se agrupan varios ficheros por
    // petición: además de ahorrar viajes, mete cada consulta en un lote y
    // dificulta correlacionar una consulta con un momento concreto.
    Prefixes []uint32 `json:"p"`
}

type LookupResponse struct {
    Buckets []Bucket `json:"b"`
}

type Bucket struct {
    Prefix  uint32  `json:"p"`
    Entries []Entry `json:"e"`
}

type Entry struct {
    // 12 bytes restantes del SHA-256. El cliente ya tiene los 20 bits iniciales.
    Suffix    [12]byte `json:"s"`
    Verdict   Verdict  `json:"v"`   // Benigno | Malicioso | PUA | Desconocido
    Confidence uint8   `json:"c"`   // 0-100
    FirstSeen  int64   `json:"f"`   // un fichero visto por primera vez hace
                                    // 10 minutos es sospechoso por sí mismo
    Prevalence uint32  `json:"n"`   // cuántos endpoints lo han visto; la baja
                                    // prevalencia correlaciona con malware dirigido
}
```

Transporte: TLS 1.3 con **Encrypted Client Hello**, de modo que ni el SNI revele
el servicio consultado. Sin cookies, sin identificador de cliente, sin cabecera
`User-Agent` distintiva. La IP se descarta en el borde y no llega a los registros
de aplicación.

Para desplegar más adelante: **Oblivious HTTP**, que interpone un relé de modo
que quien ve la IP no ve el contenido y quien ve el contenido no ve la IP. Es la
protección que elimina la última correlación posible.

### Caché en el cliente

| Tipo de resultado | TTL | Motivo |
|---|---:|---|
| Malicioso | 7 días | Un veredicto malicioso rara vez se revoca |
| Benigno con alta prevalencia | 30 días | `kernel32.dll` no va a cambiar de bando |
| Benigno con baja prevalencia | 24 h | Puede haber sido comprometido |
| Desconocido | 1 h | Merece la pena volver a preguntar pronto |

Caché **negativa** incluida: sin ella, un fichero desconocido que se ejecuta
cada minuto genera una consulta por minuto para siempre.

### Por qué no PSI

La intersección privada de conjuntos (PSI) daría privacidad criptográfica
completa: el servidor no aprendería *nada*. Se descarta por coste: los protocolos
PSI prácticos requieren varios viajes y operaciones de curva elíptica por
elemento, lo que multiplica por ~50 la latencia y por ~20 el coste de servidor.
El k-anonimato con k = 1.000 es una protección suficiente para esta amenaza a una
fracción del coste. Queda anotado como línea de evolución si el modelo de
amenaza cambia.

---

## 5.2 Envío de muestras

### Consentimiento y límites

El envío de muestras está **desactivado por defecto** y requiere activación
explícita. Incluso activado, hay clases de fichero que **nunca** se envían:

```go
func puedeEnviarse(f *FileContext) (bool, string) {
    switch {
    case f.IsDocument():
        return false, "los documentos contienen datos personales por definición"
    case f.InUserDataDirs() && !cfg.OptInUserDirs:
        return false, "ruta de datos de usuario sin consentimiento explícito"
    case f.SizeBytes > 64<<20:
        return false, "supera el límite de tamaño"
    case f.IsSignedByTrustedPublisher():
        return false, "firmado por editor de confianza: no aporta nada"
    case f.LooksLikeCredentialStore():
        return false, "posible almacén de credenciales"
    case f.HasHighPIIScore():
        return false, "heurística de datos personales"
    }
    return true, ""
}
```

El perfil típico de lo que sí se envía: PE sin firmar, con alta entropía,
aparecido en un directorio temporal, con baja prevalencia global y puntuación ML
en zona intermedia — justo donde el veredicto local es dudoso y la detonación
aporta información real.

Antes de subir se muestra al usuario qué se va a enviar y por qué. Un producto de
seguridad que exfiltra ficheros de forma opaca es, funcionalmente, lo que dice
combatir.

---

## 5.3 Sandbox de detonación

### Aislamiento

Cada muestra se detona en una **microVM Firecracker** efímera:

- Arranque en ~125 ms; se destruye completa tras el análisis.
- Aislamiento por hipervisor, no por espacio de nombres. Un escape de contenedor
  es un problema conocido; ejecutar malware real en un contenedor compartido es
  imprudente.
- Sin egreso real a Internet: **INetSim** simula DNS, HTTP, SMTP e IRC, de modo
  que la muestra crea su tráfico C2 y lo capturamos, sin que llegue a ningún
  sitio real ni participe en un ataque.
- Una VM por muestra, jamás reutilizada.

```go
type SandboxJob struct {
    SampleID    uuid.UUID
    Platform    Platform      // Windows10x64 | Windows11x64 | Ubuntu2204
    Duration    time.Duration // 90 s por defecto
    Interaction bool          // simular clics para muestras que esperan al usuario
}

type SandboxReport struct {
    ProcessTree   []ProcessNode
    FileOps       []FileOperation
    RegistryOps   []RegistryOperation
    NetworkFlows  []NetworkFlow    // capturado por INetSim
    MemoryDumps   []MemoryArtifact // regiones ejecutables no respaldadas
    APISequence   []APICall
    Screenshots   [][]byte
    Verdict       Verdict
    MITRE         []TechniqueID    // T1055, T1486, ...
    EvasionSignals []EvasionSignal // ver abajo
}
```

### El límite honesto: malware consciente del sandbox

Una parte relevante del malware moderno detecta el entorno de análisis y no
detona: busca sinónimos de VM en el hardware, cuenta núcleos, mide tiempos,
espera interacción humana, o simplemente duerme más que el análisis.

Se mitiga, no se resuelve:

- Enmascarar los indicadores obvios (cadenas de CPUID, direcciones MAC,
  dispositivos y drivers característicos).
- Simular interacción: movimiento de ratón, clics, documentos abiertos, historial
  de navegador plausible.
- Adelantar el reloj para desarmar las esperas largas.
- **Registrar la evasión como señal**: una muestra que comprueba `CPUID`,
  enumera drivers de VM y sale sin hacer nada es, con altísima probabilidad,
  maliciosa. *No detonar es en sí mismo un indicador.*

Ese último punto es lo que convierte la limitación en información. Un informe con
`Verdict: NoDetona` más `EvasionSignals: [CheckCPUID, CheckMAC, SleepLargo]` es
un veredicto útil, no un fallo del análisis.

---

## 5.4 Ciclo de realimentación

```
Muestra → Sandbox → Informe → ┬→ Generación de reglas YARA (revisión humana)
                              ├→ Datos etiquetados para reentrenar el modelo
                              ├→ Actualización del corpus de reputación
                              └→ Indicadores para el motor conductual
```

La generación automática de reglas YARA **pasa por revisión humana antes de
publicarse**. Una regla generada automáticamente sobre una cadena que también
aparece en software legítimo se convierte en un incidente masivo de falsos
positivos en toda la flota, y la historia del sector está llena de ejemplos.

Toda regla nueva se valida contra un corpus benigno de ~5 millones de ficheros
antes de salir. Cero coincidencias es requisito para publicar.

---

## 5.5 Funcionamiento sin red

| Componente | Sin red |
|---|---|
| YARA | Funciona con las reglas empaquetadas |
| Modelo ML | Funciona; es local |
| Reglas conductuales | Funcionan; son locales |
| Reputación | Solo caché; los fallos de caché se tratan como Desconocido |
| Envío de muestras | Se encola con límite de disco y se envía al recuperar la red |
| Sandbox | No disponible |

La degradación es **gradual**: se pierde contexto adicional, no capacidad de
detección. Un portátil desconectado durante un mes sigue parando ransomware,
porque nada de lo que lo para depende de la nube.

→ Siguiente: [Módulo 6 — Stack y hoja de ruta](06-stack-y-roadmap.md)
