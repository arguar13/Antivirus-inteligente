# Módulo 50 — Autodefensa legítima: ELAM, PPL y Tamper Protection con OTP

> Componentes: `crates/aegis-selfdefense/`,
> `kernel/windows/aegis/aegis_tamper_politica.c`,
> `server/crates/aegis-server/src/autodefensa.rs`.

## 50.1 La línea que no se cruza

Un EDR tiene que **sobrevivir** a un atacante con privilegios de administrador
que intenta matarlo, borrarlo o cegarlo: desarmar la defensa es el primer paso de
casi todo ataque serio. Pero hay una línea roja que AegisCore **nunca** cruza:
jamás pelear contra el **dueño legítimo** del equipo. Prohibido —y por eso la
antigua "FASE 55: bootkit UEFI" se **rechazó** por ser malware— bootkits,
persistencia en firmware contra el dueño, evadir la eliminación autorizada u
ocultarse. **Siempre** existe un camino de desinstalación autorizado que controla
el dueño de la flota.

Eso es exactamente lo que separa un EDR de un rootkit: **un rootkit no le da a
nadie la llave para quitarlo.** AegisCore sí: un **OTP** (una orden de operación
autorizada) que solo el plano de control puede emitir.

## 50.2 El OTP: la llave que el dueño tiene y el atacante no

El motor de tamper deniega borrar, parar o matar a AegisCore. Si esa negativa
fuera absoluta, sería imposible de desinstalar. La forma de darle al dueño esa
capacidad **sin** dársela también al atacante es un token que solo el Control
Plane puede fabricar (`crates/aegis-selfdefense/src/otp.rs`):

- **Firmado** con la firma híbrida Ed25519 + ML-DSA-65 de la FASE 59: un atacante
  no puede forjarlo sin la clave privada del Control Plane, ni siquiera con una
  computadora cuántica.
- **Atado a este host** (`host_id`): un OTP capturado en un endpoint no autoriza
  nada en otro.
- **Atado a una operación**: uno para "parar el servicio" no vale para "borrar el
  binario".
- **Con ventana de validez**: caduca.
- **De un solo uso**: el `nonce` se consume; un OTP reproducido se rechaza.

La verificación comprueba, en orden, cada una de esas defensas —firma, host,
operación, ventana, anti-replay— y solo entonces autoriza. El plano de control lo
emite desde `server/crates/aegis-server/src/autodefensa.rs`; el agente lleva solo
la clave pública, con la que verifica.

## 50.3 La decisión de tamper

La política decide `Permitir` o `Denegar` una operación destructiva sobre un
recurso de AegisCore. Es la parte que puede estar **mal de forma peligrosa**:
denegar de menos deja que el atacante borre el EDR; denegar de más impide al dueño
desinstalarlo. El orden de las reglas es la decisión de seguridad:

1. Al **kernel**, a **uno mismo** y a los **componentes de AegisCore** (el
   watchdog, que tiene que poder reiniciar al agente) no se les pelea nunca.
2. Sobre un recurso **ajeno** no nos metemos.
3. **La línea ética**: recurso protegido pero con **OTP válido** del dueño →
   `Permitir` (desinstalación autorizada).
4. Recurso protegido, sin autorización → `Denegar` (sabotaje).

Vive dos veces: en Rust (`tamper.rs`, el espejo probado) y en **C portable**
(`aegis_tamper_politica.c`), que el futuro minifilter del WDK incluirá —igual que
la auto-defensa de la FASE 47 y el rollback de la FASE 50—. La criptografía del
OTP **no** vive en el C (sería frágil en kernel): la hace Rust, y a la política
solo le llega el booleano ya verificado. Las dos se prueban contra la **misma
tabla de verdad**.

## 50.4 ELAM: arrancar antes que el rootkit, sin dejar la máquina sin arrancar

Un driver **ELAM** (Early Launch Anti-Malware) es de los primeros que Windows
carga en el arranque, y clasifica los que vienen detrás como bueno / malo /
desconocido, de modo que un rootkit de arranque no se cargue antes que el EDR. La
clasificación (`elam.rs`) se decide por la **medida** (SHA-256) del driver, no por
su nombre —que un atacante controla—.

Aquí vuelve la línea ética, dentro del arranque: bloquear un driver que resulta
ser **crítico para el arranque** dejaría la máquina del dueño sin poder arrancar.
Por eso un driver dudoso y crítico se marca `MaloPeroCritico` (Windows lo deja
cargar) en vez de bloquearse. **Nunca se convierte una sospecha en un ladrillo.**

## 50.5 PPL: que ni un administrador pueda tocar el proceso

Como **Proceso Protegido Antimalware** (PPL), el kernel de Windows bloquea
cualquier intento —incluso de un administrador con `SeDebugPrivilege`— de
terminar el agente, inyectarle hilos o volcar su memoria. Complementa a la
defensa por `ObRegisterCallbacks` de la FASE 47: a PPL lo respalda el kernel, no
un callback nuestro.

El muro está declarado (`ppl.rs`): correr como PPL-Antimalware exige un
certificado con el EKU de Early Launch Anti-Malware (`1.3.6.1.4.1.311.61.4.1`)
co-firmado por Microsoft. Ese certificado no se puede fabricar; sin él, el kernel
rechaza la solicitud. La comprobación de **requisitos** es pura y se prueba aquí;
la protección **real** solo ocurre en un Windows con el binario debidamente
firmado.

## 50.6 Honestidad de validación

| Pieza | Verificable aquí | Muro |
|---|---|---|
| OTP: firma híbrida + host + operación + ventana + anti-replay | sí, cripto real, cero mocks | — |
| Emisión del OTP por el Control Plane | sí, extremo a extremo con el agente | — |
| Decisión de tamper (Rust y C, misma tabla de verdad) | sí, con gcc **y** clang | — |
| Clasificación ELAM (incluye "no dejar la máquina sin arrancar") | sí | — |
| Requisitos PPL (código de nivel, EKU) | sí | — |
| Política de tamper cross-compilada a objeto Windows x64 | sí, exporta `aegis_decidir_tamper` | — |
| Driver del minifilter (FltRegisterFilter, callbacks de registro) | — | necesita el WDK; gated por `$WDK_ROOT` |
| Registro del callback ELAM y PPL reales | — | necesita el certificado AM de Microsoft |

La parte que puede estar mal de forma peligrosa —verificar el OTP y decidir— se
prueba de verdad en cada `make ci`. La fontanería del WDK y el certificado AM son
muros físicos declarados, no fingidos.
