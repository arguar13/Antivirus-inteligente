# Módulo 26 — Integridad de firmware: TPM, arranque medido y Secure Boot

> Componente: `crates/aegis-firmware`.

Un bootkit tipo **BlackLotus** se ejecuta ANTES que el kernel. Cuando el agente
arranca, el compromiso ya está en marcha y el sistema entero —incluido el propio
EDR— corre sobre una base manipulada. No se puede detectar preguntándole al
sistema, porque el sistema es lo comprometido. Se detecta mirando lo que quedó
grabado **antes** de que el bootkit tuviera control: el estado del hardware de
arranque.

---

## 26.1 El arranque medido, y por qué no se puede falsificar

El firmware, mientras arranca, va **midiendo** cada componente antes de
ejecutarlo —el propio firmware, la tabla de particiones, el gestor de arranque,
sus variables— y **extendiendo** cada medida en un PCR del TPM. Extender es la
única operación que cambia un PCR:

```
PCR_nuevo = SHA256(PCR_viejo ‖ medida)
```

Como el hash no se invierte, un PCR con un valor dado solo se pudo alcanzar por
**una** secuencia concreta de medidas, y el TPM no ofrece ninguna forma de
escribirle otro valor sin la clave que no sale del chip.

El **event log** (`binary_bios_measurements`) dice cuál fue esa secuencia.
Reproducirlo —empezar en cero, extender cada digest en orden— tiene que dar
exactamente el PCR que el TPM guarda. Si no da, hay compromiso:

- el log fue **reescrito** (un bootkit puso la medida del gestor legítimo para
  esconder la suya), o
- hay una medida que el log **no registró** (algo se ejecutó sin medirse).

El bootkit no puede evitarlo: no tiene la clave del TPM para cambiar el PCR que
ya se extendió con la medida de su propio código. La prueba central del módulo
construye ese ataque byte a byte y comprueba que el PCR reproducido del log
manipulado **no coincide** con el del TPM.

---

## 26.2 Las tres endianidades y otras trampas que cambian todo

El firmware es un campo minado de detalles binarios donde un error no da un
fallo visible, sino una medición que parece válida y no lo es. Los que el módulo
tiene aislados y probados:

- **El event log es little-endian; el protocolo del TPM es big-endian.** Usar
  una sola convención da números que parecen razonables y no lo son. Los dos
  analizadores llevan su lector con su endianidad, y hay pruebas con los bytes
  exactos de cada uno.
- **`EV_NO_ACTION` no extiende el PCR.** El primer registro del log
  crypto-ágil es de ese tipo y declara el formato; tratarlo como una medida
  rompe la reproducción. Hay una prueba de que un log con solo ese evento deja
  todos los PCRs a cero.
- **El primer registro es siempre de formato heredado**, aunque el resto sea
  crypto-ágil, y su contenido (`Spec ID Event03`) decide cómo se lee todo lo
  demás. Analizar el resto con el formato equivocado produce basura que parece
  válida.

---

## 26.3 Secure Boot: activo no es lo mismo que imponiendo

`SecureBoot == 1` **no basta**. Con `SetupMode == 1` cualquiera puede matricular
una clave sin autenticación, que es exactamente el estado que busca un bootkit.
La comprobación exige `SecureBoot == 1` **y** `SetupMode == 0`, y hay una prueba
para cada combinación.

---

## 26.4 La lista de revocación (DBX), y el prefijo de 4 bytes

UEFI publica en `dbx` los hashes de los gestores de arranque comprometidos
conocidos; un BlackLotus se revoca añadiendo su hash. Comprobar si el binario
arrancado está en la DBX es la detección directa de un bootkit conocido.

El detalle que rompe todo lo demás: **cada fichero de `efivarfs` empieza con 4
bytes de atributos** en little-endian, y solo después vienen los datos
(`file_size == 4 + data_size`). Saltárselos desplaza cada offset del análisis y
`SignatureListSize` se lee como basura. El módulo separa atributos y datos en un
único sitio, con prueba.

Los demás errores de la DBX, cada uno con su prueba:

- La DBX son **varias** `EFI_SIGNATURE_LIST` concatenadas; quedarse en la
  primera pierde la mayoría de las revocaciones. El bucle recorre todas.
- `SignatureSize` **incluye** los 16 bytes del GUID de propietario: el hash
  empieza en +16, no en +0.
- `EFI_CERT_X509_SHA256` mide **64** bytes, no 56, porque `EFI_TIME` son 16
  bytes, no 8. (Corrección del reconocimiento de hardware sobre su propia
  primera versión.)
- El GUID de EFI es **mixed-endian**: los tres primeros campos van
  intercambiados en el cable. Volcarlos tal cual da un GUID que no casa con
  ninguno.
- La DBX guarda el hash **Authenticode** del PE/COFF, no un `sha256sum` plano
  del fichero: comparar contra el hash plano da siempre «no revocado».

Los ficheros de `efivarfs` se abren **estrictamente en solo lectura**: borrar
variables EFI ha dejado inservibles máquinas reales, y un producto de detección
no escribe nunca.

---

## 26.5 La regla que atraviesa el crate: si no está, no se inventa

La mitad de las máquinas —microVMs, contenedores, equipos con BIOS heredada— no
tienen ni TPM ni UEFI. En ellas la respuesta correcta es un **tercer estado**,
«no aplicable», nunca «inseguro» y **jamás** un PCR sintético: un valor que
parece una atestación y no viene de un TPM es una atestación falsa, y la política
de aguas abajo confiaría en ella. Reportar «Secure Boot desactivado» en cada
máquina sin UEFI es un falso positivo por máquina, y un producto que grita en
cada arranque limpio se apaga.

Hay una prueba que fija esa propiedad: en una máquina sin firmware, ninguna
comprobación puede ser un fallo. Y los bancos de PCR **no se inventan**: no
existe ningún fichero `active_banks` en ningún kernel —enumerarlo sería leer una
ruta que no hay—; los bancos se descubren enumerando los directorios
`pcr-<alg>`.

---

## 26.6 Qué se prueba, y contra qué

Esta máquina de integración es una microVM sin TPM ni UEFI (kernel sin
`CONFIG_TCG_TPM` ni `CONFIG_EFI`), así que las **lecturas** del hardware se
ejercitan solo hasta detectar honestamente la ausencia. Pero la lógica que de
verdad puede fallar —los **analizadores** del event log, del wire del TPM y de
la DBX, y el recálculo de PCRs— se prueba con **vectores binarios reales**
construidos byte a byte según el estándar TCG y la especificación UEFI: son los
mismos bytes que escriben un TPM y un firmware reales.

El escenario 11 de la simulación de Red Team ejecuta el mecanismo completo:
construye un arranque intacto (que no da falsa alarma) y uno con un gestor de
arranque manipulado, y comprueba que el PCR reproducido del log delata al
bootkit. `make ci` imprime en cada ejecución qué capas de firmware ofrece la
máquina, para que la diferencia entre «verificado» y «no aplicable aquí» esté
siempre a la vista.
