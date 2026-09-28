# Módulo 100 — AegisProvenance: la procedencia del propio producto (FASE 108)

> Componentes: `crates/aegis-procedencia/`, `tools/construir-reproducible.sh`,
> cambio en `crates/aegis-update/`, `tools/verificar-procedencia.sh`.

## 100.1 La única fase que audita al proyecto

AegisCore pide a sus clientes SBOM, alcanzabilidad en ejecución (FASE 94) y
atestación (FASE 105). Pedir a un cliente lo que uno no hace es la grieta de
credibilidad más común del sector. Esta fase cierra esa grieta: el producto se
somete a sí mismo a la procedencia que exige. Frente a in-toto, SLSA y Sigstore,
gana en cuatro cosas.

## 100.2 Construcción reproducible bit a bit

in-toto **atestigua lo que pasó**; esto demuestra que se puede **repetir**, que es
una afirmación mucho más fuerte y que casi nadie sostiene. `tools/construir-reproducible.sh`
compila el mismo fuente dos veces con los flags que cierran las fuentes conocidas
de no-determinismo (`--remap-path-prefix`, `-C codegen-units=1`, `SOURCE_DATE_EPOCH`)
y comprueba que dan el **mismo binario byte a byte**. Lo que no sea reproducible no
se maquilla: se declara con su motivo (`reproducible::comparar` dice el primer byte
que difiere) para arreglar la **causa**. En una máquina se demuestra la
reproducibilidad **temporal** (dos builds seguidos); la **cross-máquina** de la
flota se cierra con dos runners distintos, y se declara.

## 100.3 La atestación se verifica en el endpoint, ANTES de aplicar

SLSA es un marco de publicación: alguien firma y alguien, quizá, comprueba. Aquí la
verificación está en el **camino crítico**: `aegis-update::Updater::aplicar_con_procedencia`
consulta la puerta de `verificacion::verificar_antes_de_aplicar` **antes de tocar
nada**. El agente **no aplica** una actualización cuya atestación no case con su
SBOM y su política —firma válida, huella del artefacto, cadena completa,
reproducible—. No es un informe que se lee después; es una puerta que no se abre. Y
cada rechazo se **registra** (`Bitacora`): un rechazo silencioso es una
actualización maliciosa que nadie investiga.

## 100.4 Una sola cadena de linaje, hasta el TPM

`cadena::CadenaProcedencia` es **una** cadena: fuente → dependencias (con su hash) →
compilador (con su hash) → artefacto → firma híbrida → atestación → despliegue →
**medida en el TPM del endpoint (FASE 105)**, con un `Eid` del modelo único por
eslabón. Un hueco —falta el hash del compilador— es un eslabón roto: sin la cadena
entera, no se sabe que el binario que corre salió de la fuente que se auditó. No son
siete sistemas que se apuntan entre sí.

## 100.5 Transparencia sin depender de nadie

Sigstore apoya su transparencia en un servicio público: para comprobar que una
atestación está en el registro, hay que preguntarle a alguien. Una flota aislada no
puede. `transparencia::RegistroTransparencia` es un árbol de Merkle de **solo
apéndice** (esquema RFC 6962 con BLAKE3), y el agente verifica **sin conexión**:

- **Inclusión**: «esta atestación está en el registro», con una prueba de tamaño
  `O(log n)`.
- **Consistencia**: «el registro nuevo **extiende** al viejo, no lo reescribió». Es
  la que caza un registro **bifurcado**: si el operador reescribe una atestación
  vieja para ocultar una actualización maliciosa ya aplicada, ninguna prueba
  reconstruye la raíz que el agente recordaba, y se detecta.

La corrección de las pruebas compactas se cruza en las pruebas contra el recómputo
del árbol completo para todos los tamaños de 1 a 33.

## 100.6 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Inclusión Merkle | **sí** | verifica para todo `(n, m)`; una hoja falsa no verifica |
| Consistencia Merkle (detección de fork) | **sí** | verifica para todo `(m, n)`; un registro reescrito NO es consistente |
| Cadena de linaje hasta el TPM | **sí** | contigüidad comprobada; un hueco da el eslabón que falta |
| Gate: no aplicar sin atestación que case | **sí** | huella≠SBOM, sin firma, cadena rota o no reproducible → `Rechazar`, registrado |
| Integración en el camino crítico | **sí** | `aegis-update::aplicar_con_procedencia` consulta la puerta antes de aplicar |
| Reproducibilidad temporal (dos builds) | **sí** | `construir-reproducible.sh`: dos builds del mismo fuente → mismo sha256 |
| Autoataque: la actualización como ejecución | **sí** | ninguna variante maliciosa se aplica; cada rechazo se registra |
| Reproducibilidad cross-máquina de la flota | **frontera declarada** | necesita dos runners distintos; el mecanismo de comparación está |
| SBOM propio por alcanzabilidad (FASE 94) | **incremento siguiente** | el gate consume el resultado; el análisis completo del SBOM propio se declara |
| Firma híbrida real del artefacto | **ya existía** | la hace `aegis-update` (Ed25519 + ML-DSA-65); aquí llega el resultado a la puerta |

El alcance por partes es la decisión honesta: se construye el mecanismo distintivo
—reproducibilidad demostrada, puerta en el camino crítico, cadena única,
transparencia Merkle offline con detección de fork— y la reproducibilidad
cross-máquina y el análisis del SBOM propio se declaran en vez de fingirse.

Mensaje de commit:
`feat(supply-chain): implement reproducible builds with endpoint-verified provenance attestation and offline transparency log`
