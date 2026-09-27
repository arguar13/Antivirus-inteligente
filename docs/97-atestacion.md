# Módulo 97 — AegisAttest: atestación continua que supera a Keylime (FASE 105)

> Componentes: ampliación de `crates/aegis-attest/`, `tools/verificar-attest.sh`.

## 97.1 De dónde parte

`aegis-attest` ya tenía el cimiento: verificar un *quote* de TPM 2.0 —firma con la
clave de atestación, frescura por nonce, recómputo del `pcrDigest`, contraste con
valores dorados— y el tri-estado (`NoAplicable` sin TPM). Eso es el cimiento, no la
casa. Keylime tiene recorrido operativo: política de PCR, revocación e IMA. Esta
fase construye ese recorrido, y lo hace ganando en cinco cosas.

## 97.2 Las cinco cosas que lo separan de Keylime y tpm2-tools

1. **La política de PCR es un TIPO, no un fichero.** En Keylime la política es
   configuración: un fichero que dice qué valores son aceptables. Un fichero se
   **desincroniza** —se actualiza el kernel y nadie toca la política, o dos copias
   dejan de coincidir—. Aquí `PoliticaPcr` es un tipo: hay **una** exigencia por
   PCR, y una contradicción —exigir que el PCR 7 valga a la vez X e Y— devuelve
   `Err` **al construirla**, no un comportamiento raro en producción.
2. **IMA unido a la PROCEDENCIA.** Keylime **mide**: recoge la lista de IMA y
   comprueba que cada hash está en una lista de permitidos. Pero una lista de
   hashes buenos no dice de **dónde** salió un fichero. Aquí cada `MedidaIma` se
   **casa** contra el `InventarioProcedencia` —los paquetes de la FASE 81 y la
   línea base de la FASE 104—: una medida cuyo fichero ningún paquete ni la línea
   base avala es `SinProcedencia`. Eso es lo que convierte una lista de hashes en
   una respuesta: «este binario se ejecutó y no viene de ninguna parte que
   conozcamos».
3. **La revocación HACE algo.** En Keylime la revocación es una notificación. Aquí
   un agente que falla la atestación **pierde autoridad** en la malla de la FASE 68
   —sus pares dejan de aceptar sus órdenes— y se le baja el **tope de confianza** en
   el árbitro a cero: lo que diga deja de mover un veredicto. La revocación cambia
   el comportamiento del producto.
4. **Una sola cadena de linaje.** firmware (FASE 92) → arranque medido → kernel →
   agente → proceso, con un `Eid` del modelo único por eslabón. Casi todo el mundo
   tiene esto repartido en sistemas que se apuntan entre sí; aquí es **una** cadena,
   y un hueco —falta el kernel entre el arranque y el agente— se detecta como
   eslabón roto: sin la cadena entera, el proceso no hereda una raíz de confianza.
5. **Tri-estado, de verdad.** Un host sin TPM es `NoAplicable` **con su motivo**,
   jamás «confiable por defecto» —que es como casi todo el mundo trata la ausencia
   de TPM, y es exactamente el hueco por el que se cuela un endpoint sin medir—.

## 97.3 La atestación de la malla, y la revocación como arma

**La malla:** la FASE 68 deja a los agentes actuar sin el plano de control. Un nodo
comprometido que conserve su sitio podría dar órdenes a sus pares. La regla que lo
cierra: un `Par` **no acepta** autoridad de un nodo cuyo estado de atestación no sea
bueno. La autoridad se hereda de la atestación, no de estar conectado.

**La revocación como denegación de servicio:** si un atacante puede provocar fallos
de atestación, revocar media flota la derriba. Por eso la revocación pasa por el
`LimitadorRevocacion`, con **degradación pegajosa** (FASE 71): pasado un tope de la
flota, una oleada de revocaciones se trata como lo que casi seguro es —un ataque a
la propia atestación, no media flota comprometida a la vez— y se **corta**. El freno
no se recupera solo: un operador lo revisa y lo rearma. Fallar cerrado aquí es **no
revocar de más**.

## 97.4 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Verificación del quote (firma, nonce, PCR digest) | **sí** (ya existía) | firma real; una cita falsificada da `FirmaInvalida`; nonce fresco exigido |
| Política de PCR como tipo | **sí** | una contradicción (`exigir_igual` incompatible) devuelve `Err` al construir |
| IMA unido a procedencia | **sí** | una medida sin origen en el inventario es `SinProcedencia`; parser de IMA robusto |
| Revocación baja autoridad y confianza | **sí** | `EstadoNodo::revocado()`: sin autoridad, tope `Confianza::NULA` |
| Revocación masiva cortada (DoS) | **sí** | revocar media flota (6000/10000) se corta en el tope; freno pegajoso |
| Malla: par rechaza nodo no atestado | **sí** | `Par::acepta_autoridad_de` es falso para un nodo revocado |
| Cadena de linaje única, hueco detectado | **sí** | falta el kernel → `Err(Nivel::Kernel)`; no arranca en firmware → `Err(Nivel::Firmware)` |
| Tri-estado sin TPM | **sí** (ya existía) | `CheckState::NoAplicable` con su motivo, nunca `Ok` por defecto |
| Emisión del quote / sellado contra el chip | **muro de entorno (gated)** | `emisor` tras la feature `tpm-hardware`; no se compila sin chip |
| Atestación con TPM real / `swtpm` | **frontera declarada** | donde no hay chip, se declara `swtpm`; la verificación se prueba con firmas reales |
| Propagación de la revocación por la malla, medida en tiempo | **incremento siguiente** | el mecanismo (autoridad + tope) está; la medida de propagación a escala es de la FASE 111 (escala real) |

El alcance por partes es la decisión honesta: se construye el recorrido operativo
distintivo —política como tipo, medida unida a procedencia, revocación que actúa con
freno pegajoso, cadena única, malla atestada— sobre el cimiento de verificación que
ya existía, y la fontanería del chip y la medida a escala se declaran en vez de
fingirse.

Mensaje de commit:
`feat(attestation): implement continuous TPM attestation with typed PCR policy, IMA provenance and authority revocation`
