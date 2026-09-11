# Módulo 44 — Atestación TPM 2.0: la raíz de confianza que sobrevive a un SO comprometido

> Componentes: `crates/aegis-attest/`, `server/crates/aegis-server/src/atestacion.rs`.

## 44.1 El problema: el software no puede certificarse a sí mismo

El plano de control recibe telemetría de diez mil agentes y les emite órdenes.
Hasta la FASE 49 confiaba en que un latido que dice *"soy el agente 4820 y estoy
sano"* lo manda de verdad el agente 4820 y de verdad está sano. Un atacante que
ha comprometido el endpoint miente en ambas cosas: el binario del agente puede
estar parcheado en disco o en memoria, y la telemetría fabricada. **Ninguna
firma de software lo detecta, porque el software que firma es el comprometido.**

La única raíz de confianza que sobrevive a un sistema operativo comprometido es
el hardware. El TPM 2.0 mide el arranque en sus PCR y **firma** una declaración
de esos valores —un *quote*— con una clave (la AK) que nunca sale del chip. El
plano de control verifica esa firma antes de creerse nada. Si el arranque fue
manipulado, o el binario no es el matriculado, o alguien reproduce un quote
viejo, la verificación falla y se invoca la **Cuarentena de Enjambre de la FASE
44** —que ya existe; aquí se dispara, no se reescribe—.

## 44.2 La línea que no se cruza aquí, declarada

Emitir el quote exige hablar con `/dev/tpmrm0` en una máquina con TPM. Este
entorno no tiene ninguno —ni chip, ni simulador `swtpm` (que `apt` no puede
instalar)—. Siguiendo el patrón de la FASE 47:

- La parte que **puede estar mal de forma peligrosa** —verificar el quote— es
  Rust portable y se prueba con firmas **reales** en cada `make ci`.
- La **fontanería** que habla con el chip (`aegis-attest::emisor`) está tras la
  feature `tpm-hardware` y el CI declara que no se compiló aquí.

Se rechaza a propósito `tss-esapi`/`tpm2-tss`: arrastran la librería `libtss2` en
C, y `apt` está bloqueado. Los comandos TPM se ensamblan byte a byte, igual que
`construir_pcr_read` de `aegis-firmware`, sin una sola dependencia nativa nueva.

## 44.3 La cadena de verificación, y por qué su orden

`aegis-attest::verificador::verificar_quote` decide si creerse un quote. El orden
de los pasos es una decisión de seguridad:

1. **Parsear** el `TPMS_ATTEST`.
2. **Verificar la firma** sobre los bytes marshalados, despachando por algoritmo
   (RSA-2048 PKCS#1 v1.5-SHA256, ECDSA P-256, Ed25519). *Antes que nada del
   contenido*: hasta que la firma no verifica, el contenido son bytes de un
   atacante.
3. Exigir el **magic `TCG`** y el **tipo QUOTE**: una estructura sin ellos no la
   generó un TPM, o es otra atestación (una clave, el tiempo) que no dice nada de
   los PCR.
4. Exigir que el `qualifiedSigner` sea el **Name de la AK matriculada**: no basta
   una firma válida de *cualquier* clave.
5. Exigir que `extraData` sea el **nonce del desafío** (frescura). Sin esto, un
   quote de un arranque limpio se reproduce eternamente sobre una máquina ya
   comprometida.
6. **Recomputar el `pcrDigest`** a partir de los PCR presentados y exigir que
   case: así la firma ata los valores presentados sin que el TPM los firme uno a
   uno (el quote solo lleva su *digest*).
7. Si hay valores **dorados**, exigir que los PCR presentados coincidan.

Cada paso tiene su vector de prueba negativo: firma manipulada, magic mal, tipo
mal, nonce reproducido, PCR alterado, PCR dorado distinto. Las claves de prueba
son **reales** (`ed25519-dalek`, `p256`, `rsa`): se firma un `TPMS_ATTEST`
auténtico y el verificador lo comprueba, demostrando que aceptará la firma de un
TPM real sin tener uno delante.

## 44.4 Frescura y anti-replay

El desafío es un nonce de 32 bytes de `getrandom` —no de un PRNG sembrado: un
desafío predecible es uno que un atacante precomputa—. El `RegistroNonces` lo
**consume** al verificarlo: un segundo quote con el mismo nonce (una
reproducción) se rechaza, y uno más viejo que la ventana de validez también.

## 44.5 Un endpoint sin TPM no es "inseguro": es `NoAplicable`

Media flota puede ser microVMs sin TPM. Tratar *"no hay TPM"* como fallo
cuarentenaría a todas por algo que no es un ataque. Se reutiliza el tri-estado de
`aegis-firmware`: sin matrícula de atestación, la decisión es `NoAtestado`
(el `NoAplicable`), nunca `Ok` (aceptar telemetría no atestada como si lo
estuviera) ni fallo.

## 44.6 El enganche con la cuarentena, separado de la decisión

En el servidor, `atestacion::decidir` es una **función pura** —reporte + matrícula
→ `Decision`— que se prueba con firmas reales sin tocar la base de datos.
`RegistroAtestacion::procesar` traduce esa decisión en una llamada a
`Almacen::poner_en_cuarentena` (FASE 44) y solo se ejercita de verdad con un
PostgreSQL real. Es la misma separación de siempre: la lógica que puede estar mal
de forma peligrosa se prueba; el wiring de base de datos se ejercita donde hay
base de datos.

## 44.7 El riesgo de los valores dorados

Los PCR 0–7 cambian **legítimamente** tras una actualización de firmware o
microcódigo. Comparar contra un dorado obsoleto cuarentenaría media flota: un
falso positivo masivo que dispara la FASE 44. Por eso el flujo de actualización
de dorados debe atarse al pipeline firmado de `aegis-update`, y el contraste se
ciñe a `PCRS_DE_ARRANQUE`. La atadura AK↔EK (activación de credencial), que es la
raíz última de confianza en la *identidad* del atestador, es fontanería **gated**:
hasta ejecutarla sobre hardware, esa identidad no está demostrada.
