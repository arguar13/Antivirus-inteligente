# Módulo 4 — Respuesta, aislamiento y cuarentena

> Componente: `crates/aegis-resp` (Rust) + callout WFP en el driver.

Detectar sin responder es telemetría, no protección. Este módulo ejecuta la
decisión, y su requisito transversal es que **toda acción sea reversible**: un
falso positivo debe poder deshacerse por completo, incluidos los metadatos.

---

## 4.1 Aislamiento de red

### Windows: Windows Filtering Platform

WFP permite bloquear tráfico por proceso sin tocar la pila de red ni instalar un
LSP. La clave está en distinguir dos casos que se suelen confundir:

**Conexiones nuevas** — se bloquean desde userland, sin driver:

```c
/* Sublayer propia con peso alto: nuestros filtros ganan a los de terceros. */
FWPM_SUBLAYER0 sublayer = {
    .subLayerKey  = AEGIS_SUBLAYER_GUID,
    .displayData  = { L"AegisCore", L"Aislamiento de endpoint" },
    .weight       = 0xFFFF,
};
FwpmSubLayerAdd0(engine, &sublayer, NULL);

/* El App ID identifica al ejecutable por su ruta NT normalizada. */
FWP_BYTE_BLOB *appId = NULL;
FwpmGetAppIdFromFileName0(L"C:\\ruta\\al\\proceso.exe", &appId);

FWPM_FILTER_CONDITION0 cond = {
    .fieldKey            = FWPM_CONDITION_ALE_APP_ID,
    .matchType           = FWP_MATCH_EQUAL,
    .conditionValue      = { .type = FWP_BYTE_BLOB_TYPE, .byteBlob = appId },
};

FWPM_FILTER0 filter = {
    .layerKey            = FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    .subLayerKey         = AEGIS_SUBLAYER_GUID,
    .action.type         = FWP_ACTION_BLOCK,
    .weight              = { .type = FWP_UINT8, .uint8 = 15 },
    .numFilterConditions = 1,
    .filterCondition     = &cond,
};
FwpmFilterAdd0(engine, &filter, NULL, &filterId);
```

Se replica en `ALE_AUTH_CONNECT_V6`, `ALE_AUTH_RECV_ACCEPT_V4` y `_V6`. Añadir
un filtro tarda cientos de microsegundos y surte efecto inmediato.

**Conexiones ya establecidas** — aquí está la parte que un filtro no resuelve.
Un filtro en `ALE_AUTH_CONNECT` solo evalúa conexiones **nuevas**: el canal C2
que ya está abierto sigue funcionando. Para cortarlo hace falta un **callout
driver** en `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4` que llame a `FwpsFlowAbort0`
sobre los flujos del proceso.

Sin esa pieza, «aislar» significa «impedir que abra conexiones nuevas mientras
exfiltra por la que ya tenía». Es la diferencia entre contención real y aparente.

**Añadir todo en una transacción** (`FwpmTransactionBegin0` /
`FwpmTransactionCommit0`): si el aislamiento se aplica a medias, queda un proceso
que puede recibir pero no enviar, o al revés, y eso es peor que no aislar.

### La lista de permitidos que evita el desastre operativo

Aislar un endpoint comprometido y perder el acceso remoto a él es un error
clásico y caro. El aislamiento **siempre** preserva:

| Se permite | Por qué |
|---|---|
| Tráfico del propio `aegis-agent` a la nube | Si no, se pierde la telemetría justo del incidente |
| DNS a los resolutores configurados | Sin él, hasta el propio EDR falla al resolver |
| Rango de administración configurado | Para que el operador pueda entrar a investigar |
| DHCP | Sin él, el equipo pierde IP y se vuelve inalcanzable |

El aislamiento **total** —sin excepciones— existe como modo separado, requiere
confirmación explícita y avisa de que el equipo quedará inalcanzable.

### Linux

`cgroup/connect4` y `connect6` en eBPF devolviendo 0 bloquean conexiones nuevas
por cgroup, que es la unidad natural para aislar un proceso y sus hijos. Los
flujos existentes se cortan con `nft` sobre la tabla propia más
`ss --kill` sobre los sockets del proceso.

---

## 4.2 Cuarentena

### Por qué se cifra

No por confidencialidad. Por tres razones operativas:

1. **Impedir la re-ejecución**: un fichero en cuarentena no debe poder ejecutarse
   ni por accidente ni si alguien copia el directorio.
2. **Evitar detecciones cruzadas**: si otro antivirus escanea nuestra cuarentena
   y encuentra muestras en claro, las «desinfecta» y destruye la evidencia.
3. **Integridad demostrable**: la etiqueta GCM prueba que el fichero restaurado
   es bit a bit el original.

### Formato del contenedor

```
┌──────────────────────────────────────────────────────────────────┐
│ CABECERA (en claro, 64 B)                                        │
│   magic      "AEGISQ" 6 B                                        │
│   version    u16                                                 │
│   key_id     u128    identifica la clave maestra (rotación)      │
│   nonce      96 bits aleatorio, único por fichero                │
│   meta_len   u32                                                 │
│   tag        128 bits (GCM)                                      │
├──────────────────────────────────────────────────────────────────┤
│ METADATOS (CBOR, cifrados, AUTENTICADOS como AAD)                │
├──────────────────────────────────────────────────────────────────┤
│ CONTENIDO ORIGINAL (AES-256-GCM)                                 │
└──────────────────────────────────────────────────────────────────┘
```

La cabecera va en claro pero **autenticada como AAD**: alterar `key_id` o
`nonce` para intentar un ataque de sustitución invalida la etiqueta.

### Derivación de claves

```rust
/// Clave maestra sellada en el TPM 2.0 (NCryptCreatePersistedKey con el
/// Platform Crypto Provider). Nunca sale del TPM en claro. Si no hay TPM, se
/// degrada a DPAPI-NG vinculado a la cuenta del servicio y se registra que la
/// protección es más débil.
fn clave_de_fichero(maestra: &TpmKey, id: Uuid) -> Zeroizing<[u8; 32]> {
    // Clave distinta por fichero: comprometer una no ayuda con las demás, y
    // hace imposible reutilizar un nonce entre ficheros aunque el generador
    // aleatorio falle, porque la clave ya es distinta.
    hkdf_sha256(maestra.derive(), salt: id.as_bytes(), info: b"aegis-quarantine-v1")
}
```

Reutilizar un *nonce* con la misma clave en GCM es catastrófico: revela el flujo
de claves y permite falsificar etiquetas. Derivar por fichero elimina esa clase
de fallo por construcción, en vez de depender de que el generador aleatorio
nunca repita.

### Metadatos forenses

Restaurar el contenido no basta. Un fichero restaurado sin sus permisos ni sus
marcas de tiempo es evidencia destruida y, a menudo, una aplicación rota.

```rust
#[derive(Serialize, Deserialize)]
pub struct MetadatosCuarentena {
    // --- Identidad ---
    pub ruta_original: PathBuf,          // con GUID de volumen, no letra de unidad
    pub file_id: u128,                   // FILE_ID_128 / inode
    pub volume_id: u64,
    pub usn: u64,
    pub sha256: [u8; 32],
    pub tamano: u64,

    // --- Atributos a restaurar ---
    pub marcas_macb: [SystemTime; 4],    // creación, modificación, acceso, cambio MFT
    pub descriptor_seguridad: String,    // SDDL (Windows)
    pub modo_posix: Option<u32>,         // modo + uid + gid (Linux)
    pub atributos: u32,                  // oculto, sistema, solo lectura
    pub flujos_alternativos: Vec<(String, Vec<u8>)>,  // ADS, incluido Zone.Identifier
    pub atributos_extendidos: Vec<(String, Vec<u8>)>, // xattr

    // --- Contexto de la detección ---
    pub detectado_en: SystemTime,
    pub motor: Motor,                    // Yara { regla } | Ml { version, score } | Conducta { regla }
    pub proceso_creador: Option<ProcKey>,
    pub linaje: Vec<ImageId>,            // instantánea de ancestros
    pub veredicto: Respuesta,
}
```

`Zone.Identifier` merece mención aparte: es el flujo alternativo que marca un
fichero como descargado de Internet (*Mark of the Web*). Perderlo al restaurar
convierte un fichero que Windows trataría con desconfianza en uno de confianza
local. Restaurar los ADS no es un detalle de pulido, es parte del modelo de
seguridad.

### Almacén

- Directorio con DACL que solo concede acceso al servicio PPL. Ni siquiera
  `Administrators` entra.
- El minifilter **deniega** toda apertura sobre ese directorio que no venga de
  nuestro agente (módulo 1). La ACL sola no basta: un administrador puede
  tomar posesión y cambiarla; el filtro de kernel, no.
- Nombres de fichero aleatorios (UUID) con extensión `.aegisq`, excluida del
  escaneo para evitar recursión.
- Cuota configurable (2 GB por defecto) con expulsión FIFO y aviso antes de
  expulsar.

### Restauración

```rust
pub fn restaurar(id: Uuid, motivo: MotivoRestauracion) -> Result<PathBuf> {
    let contenedor = almacen.abrir(id)?;
    // El descifrado GCM falla si contenido o metadatos fueron alterados.
    let (meta, datos) = contenedor.descifrar_y_verificar()?;

    // Se comprueba el destino ANTES de escribir: si algo ocupa ya la ruta
    // original, restaurar encima destruiría ese fichero.
    let destino = resolver_destino(&meta)?;

    escribir_atomico(&destino, &datos)?;      // escribir a temporal + rename
    restaurar_ads(&destino, &meta)?;          // Zone.Identifier incluido
    restaurar_descriptor_seguridad(&destino, &meta)?;
    restaurar_marcas_temporales(&destino, &meta)?;

    // La restauración añade una exclusión por hash con caducidad de 30 días.
    // Sin ella, el motor vuelve a poner el fichero en cuarentena a los segundos
    // y el usuario entra en un bucle.
    exclusiones.añadir_por_hash(meta.sha256, Duracion::dias(30), motivo)?;

    auditoria.registrar(EventoRestauracion { id, motivo, destino: destino.clone() })?;
    Ok(destino)
}
```

---

## 4.3 Rollback de ficheros

### Por qué no basta con VSS

Las instantáneas de volumen (VSS) son el mecanismo obvio y son insuficientes:

- **Granularidad**: el intervalo mínimo entre instantáneas se mide en horas. El
  ransomware trabaja en minutos.
- **El atacante las borra**: `vssadmin delete shadows /all` es el primer paso de
  prácticamente toda familia moderna. Se puede bloquear ese comando, pero
  también se puede llegar al mismo sitio por IOCTL directo al proveedor.
- **Presupuesto**: VSS reserva un porcentaje del volumen fuera de nuestro control.

VSS se integra como **complemento** —si hay instantáneas válidas, se usan— pero
la garantía la da un almacén propio.

### Almacén copy-on-write

El minifilter, ante la **primera** escritura de un proceso no confiable sobre un
fichero protegido, copia el original antes de dejar pasar la operación:

```c
FLT_PREOP_CALLBACK_STATUS AegisPreWrite(...)
{
    if (!AegisEsRutaProtegida(ctx) || AegisActorEsConfiable(ctx))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* Solo la PRIMERA escritura de esta sesion sobre este fichero. El flag
     * vive en el contexto de flujo, asi que comprobarlo no cuesta E/S.
     * Sin esto, un editor que guarda 50 veces genera 50 copias. */
    if (AegisYaTieneSombra(ctx))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /* La copia se difiere a un work item a PASSIVE_LEVEL: copiar sincronamente
     * dentro del pre-write anadiria la latencia del disco a cada escritura. */
    AegisEncolarCopiaSombra(ctx);
    AegisMarcarConSombra(ctx);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
```

### Qué se protege

Copiar **toda** escritura del sistema es inviable: un servidor de compilación
generaría cientos de GB por hora. El alcance está acotado:

- Extensiones de documento, imagen, archivo comprimido y código fuente.
- Directorios de usuario (Documentos, Escritorio, Imágenes) y rutas configuradas.
- Se **excluyen** temporales, cachés de compilación, ficheros de máquina virtual
  y bases de datos activas (tienen sus propios mecanismos y su tamaño rompería
  cualquier cuota).

### Gestión del almacén

| Parámetro | Valor por defecto | Motivo |
|---|---|---|
| Cuota | 2 GB o 2 % del volumen | Acotado y predecible |
| Retención | 24 h | Cubre el tiempo de detección con margen |
| Expulsión | Por antigüedad, más antiguo primero | |
| Compresión | zstd nivel 3 | ~3× en documentos por ~5 % de CPU en el work item |
| Protección | Igual que la cuarentena: DACL + denegación en el minifilter | Un almacén de rollback borrable no sirve de nada |

### Restauración tras confirmar ransomware

```rust
pub fn rollback_de_proceso(proc: ProcKey, ventana: Duration) -> InformeRollback {
    // El grafo sabe qué ficheros tocó ese proceso y sus hijos: el cifrador
    // suele generar procesos auxiliares, y restaurar solo los del padre
    // dejaría ficheros cifrados.
    let tocados = grafo.ficheros_escritos_por_subarbol(proc, ventana);

    let mut informe = InformeRollback::default();
    for f in tocados {
        match almacen_sombra.restaurar(f.file_id) {
            Ok(_) => informe.restaurados += 1,
            // Sin sombra: escrito antes de la ventana, o fichero nuevo creado
            // por el cifrador (esos se eliminan, no se restauran).
            Err(SinSombra) => informe.sin_copia.push(f),
            Err(e) => informe.fallos.push((f, e)),
        }
    }
    informe   // se muestra al usuario: qué se recuperó y qué no
}
```

El informe se presenta siempre, incluidos los fallos. Un rollback que dice
«hecho» ocultando que 30 ficheros no se pudieron recuperar destruye la confianza
en el producto la primera vez que el usuario lo descubre por su cuenta.

→ Siguiente: [Módulo 5 — Nube y threat intelligence](05-cloud.md)
