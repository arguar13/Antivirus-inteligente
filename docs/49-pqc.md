# Módulo 49 — Criptografía post-cuántica: el canal que sobrevive a la computadora cuántica

> Componentes: `crates/aegis-pqc/`, `crates/aegis-update/src/signature.rs`,
> `crates/aegis-fleet/src/pqc.rs`, `server/crates/aegis-server/src/pqc.rs`.

## 49.1 El problema real: *Harvest Now, Decrypt Later*

Un adversario con recursos no necesita romper el cifrado de AegisCore **hoy**. Le
basta con **grabar** el tráfico cifrado entre el agente y el plano de control y
guardarlo. El día que exista una computadora cuántica criptográficamente
relevante (una CRQC), corre el algoritmo de Shor y rompe **de golpe** el
intercambio de claves X25519 del canal y las firmas Ed25519/ECDSA/RSA. Todo lo
grabado durante años se descifra de una vez. Por eso la migración es urgente
aunque la CRQC todavía no exista: lo que se cifra mal hoy ya está perdido.

Grover, en cambio, solo **debilita** lo simétrico: AES-256 baja a ~128 bits
efectivos, que siguen siendo seguros. **No se toca.** Hay que migrar dos cosas:

1. El **intercambio de claves** del canal C2 (lo urgente por HNDL).
2. El **firmado** de binarios y actualizaciones (para no depender de una clave
   que una CRQC romperá, y de la que cuelga la ejecución de código en la flota).

## 49.2 La decisión clave: híbrido, nunca PQC en solitario

Las implementaciones post-cuánticas son jóvenes; podrían tener un fallo aún no
descubierto (un error de implementación, o incluso un avance criptoanalítico
sobre los retículos). Por eso cada primitivo PQC se combina con uno **clásico**,
muy escrutado, de modo que el canal es seguro si aguanta **cualquiera de los
dos**. Es el consenso de la industria (IETF, Cloudflare, NSA CNSA 2.0):

- **KEM híbrido `X25519MLKEM768`**: el secreto de sesión sale de
  `HKDF(x25519_ss ‖ mlkem768_ss ‖ transcript)`, **atado al transcript** (la suite
  y todo el material público de la sesión). Cambiar cualquiera de los dos
  secretos, su orden, o el transcript, cambia la clave derivada.
- **Firma híbrida `Ed25519 + ML-DSA-65`**: un artefacto se acepta **solo si
  verifican las dos** firmas. Un falsificador tendría que romper el clásico
  (imposible hoy) **y** el post-cuántico (la apuesta del NIST) a la vez.

## 49.3 Algoritmos (estándares NIST 2024, con los nombres correctos)

| Rol | Estándar | Nombre FIPS | Nombre viejo | Nivel |
|---|---|---|---|---|
| KEM   | FIPS 203 | **ML-KEM-768** | CRYSTALS-Kyber     | 3 |
| Firma | FIPS 204 | **ML-DSA-65**  | CRYSTALS-Dilithium | 3 |

En el código se usan los nombres FIPS; el nombre viejo solo aparece en
comentarios. Las implementaciones son **Rust puro, sin C inestable**: ML-KEM con
`libcrux-ml-kem` de Cryspen (formalmente verificado con hax, el que usa Firefox)
y ML-DSA con `ml-dsa` de RustCrypto (la misma familia que `aes-gcm` y `sha2` que
el proyecto ya usa).

## 49.4 Las dos migraciones

### El canal C2: una capa HPKE híbrida POR ENCIMA del mTLS

El canal agente↔plano de control ya va por mTLS (rustls). Pero rustls negocia
X25519. En vez de esperar a que rustls traiga un KEM híbrido, AegisCore **sella
el payload** con un secreto derivado del KEM híbrido **antes** de entregarlo al
mTLS, al estilo HPKE de un disparo (RFC 9180): el emisor encapsula contra la
clave pública del receptor, deriva con HKDF una clave AES-256-GCM y cifra. Es
defensa en profundidad: aunque el túnel TLS caiga ante la cuántica, el contenido
sigue protegido por ML-KEM-768. La capa es nuestra, así que se prueba de verdad,
y no depende de la hoja de ruta de una dependencia.

El agente (`aegis-fleet::pqc`) sella su telemetría con la clave pública del plano
de control y genera su propia identidad híbrida para recibir comandos sellados;
el plano de control (`aegis-server::pqc`) guarda su par híbrido, abre lo que
suben los agentes y sella los comandos de vuelta. El secreto de sesión solo vive
en memoria.

### El firmado de actualizaciones: aceptar sii verifican las dos

Un motor de actualización es la vía directa a ejecutar código con los permisos
del defensor. La firma del canal de `aegis-update` pasa de Ed25519 a **híbrida
Ed25519 + ML-DSA-65**: se acepta un artefacto solo si verifican ambas. El
contexto de firma ata cada firma al **tipo** de artefacto (una firma de reglas no
vale como binario del agente), y el verificador híbrido **rechaza una firma
clásica** (anti-downgrade): un atacante no puede forzar a la flota de vuelta a la
criptografía rompible.

## 49.5 Agilidad criptográfica

Migrar diez mil agentes no se hace en un «día bandera». El formato de wire lleva
un **byte de suite** al principio, de modo que emisor y receptor saben qué
esperar y la flota recorre la transición en tres escalones sin cortarse:

```text
  clásico        →   híbrido            →   PQC-puro
  X25519             X25519MLKEM768         ML-KEM-768
  Ed25519            Ed25519+ML-DSA-65      ML-DSA-65
```

Hoy la política acepta el escalón **híbrido** y rechaza tanto la degradación a
clásico como el salto prematuro a PQC-puro, que se reserva para cuando las
implementaciones acumulen los años de escrutinio que hoy tiene lo clásico.

## 49.6 Honestidad de validación: esta fase no tiene muro de hardware

A diferencia de TPM, Intel PT o el driver de Windows, aquí **todo se prueba de
verdad, con cero mocks**. El ancla son los **Known Answer Tests oficiales del
NIST** (vectores ACVP de FIPS 203/204): una implementación sutilmente mal pasa un
roundtrip casero pero **falla** los KAT.

| Propiedad | Verificable aquí | Muro |
|---|---|---|
| KAT oficiales ML-KEM keyGen/encaps/decaps | sí, byte a byte contra ACVP | — |
| KAT oficiales ML-DSA keyGen/sigGen | sí, byte a byte contra ACVP | — |
| KAT oficiales ML-DSA sigVer (con **negativos** del NIST) | sí, el camino de verificación | — |
| Rechazo implícito IND-CCA2 (1 bit en el ct → secreto distinto, no fallo) | sí | — |
| Binding del combinador híbrido (secretos/orden/transcript) | sí | — |
| Firma híbrida: aceptar **sii** ambas verifican | sí, ambos sentidos | — |
| X25519 contra el vector de RFC 7748 | sí | — |
| Canal sellado: roundtrip y negativos (ct/encapsulado/aad/clave) | sí, de extremo a extremo | — |
| Tamaños/ABI (pk/sk/ct/firma) contra las constantes FIPS | sí, en **compilación** | — |

Los asserts de tamaño son comprobaciones `const`: si una futura versión de una
dependencia cambiara un tamaño respecto a FIPS, el crate **no compila**, en vez
de corromperse en silencio.

## 49.7 MSRV: 1.82 → 1.85

El crate `ml-dsa` es edición 2024 y exige rustc 1.85. El agente que **verifica**
las actualizaciones depende de él, así que 1.85 es el piso real del producto, no
una aspiración. El criterio es el mismo que cuando entró `tract-onnx` (1.77 →
1.82): una declaración de MSRV que el código ya no cumple oculta las violaciones
reales. La matriz del CI remoto prueba el nuevo piso.
