# Módulo 45 — Rollback de ransomware: deshacer el cifrado en milisegundos

> Componentes: `crates/aegis-rollback/`, `kernel/windows/aegis/aegis_rollback_politica.c`.

## 45.1 No es un detector nuevo: es la capacidad de deshacer

El detector ya existía. `aegis-ransom` mira velocidad de escritura, honeypots y
entropía y produce un veredicto; `KillResponder` ya mata el árbol de procesos.
Lo que faltaba es **deshacer**: cuando el veredicto llega, los primeros ficheros
ya están cifrados. La FASE 50 no añade un detector; añade el rollback y orquesta
lo que ya hay.

La idea: interceptar la escritura **antes** de que ocurra, guardar una
copia-sombra **cifrada** del contenido original, y —si se confirma ransomware—
matar el proceso y restaurar los ficheros desde las copias-sombra. Si el
veredicto no llega, las copias caducan.

## 45.2 La parte que puede estar mal de forma peligrosa: el diario

`journal` decide **qué** escritura merece copia y **cuándo**. Dos errores
opuestos, y los dos se pagan con ficheros:

- **Copiar la versión equivocada.** Si se guarda la copia *después* de que el
  ransomware cifre el fichero, la copia-sombra es la versión cifrada y el
  rollback restaura basura. Por eso la copia se hace del contenido **previo** a
  la escritura, y solo la **primera** vez que se toca cada fichero (dedup): la
  segunda pasada ya no pisa la copia buena.
- **No copiar a tiempo.** Si se espera al veredicto del detector, los primeros
  ficheros ya están cifrados y perdidos. Por eso el diario también dispara ante
  la **señal cruda** —una escritura que convierte un documento de baja entropía
  en algo de alta entropía— antes de que el veredicto global llegue.

Se prueba con un **cifrador sintético real** (ChaCha20) que sube la entropía
igual que el ransomware, restaurando ficheros de verdad en un directorio
temporal. La propiedad central verificada: **lo restaurado es el original, no la
basura cifrada.**

## 45.3 Las copias-sombra van cifradas, y por una razón

Las copias del contenido original se guardan en disco, al alcance del mismo
ransomware que intenta cifrarlo todo. Si estuvieran en claro, las vería y las
cifraría o borraría como a cualquier otro fichero. Por eso `shadowstore` las
cifra con **AES-256-GCM** bajo una clave que el proceso atacante no tiene:
aunque las encuentre, para él son ruido, y GCM **detecta** cualquier intento de
alterarlas (un test lo comprueba volteando un byte del blob: el descifrado
falla, no devuelve basura). Es el mismo stack criptográfico que la cuarentena de
`aegis-resp`.

## 45.4 Restaurar sin dejar ficheros a medias

`ReverterFichero` escribe a un temporal y hace `rename` atómico: si el proceso
muere a media restauración, el fichero no queda a medias entre cifrado y
original. Y `ejecutar_plan` **no se detiene ante el primer error**: en un
incidente, restaurar 900 de 1000 ficheros es mejor que restaurar 0 porque el 456
falló; los errores se acumulan y se devuelven al final.

## 45.5 La decisión del minifilter, portable y probada

Igual que la política de auto-defensa de la FASE 47, la **decisión** del
minifilter —ante una escritura, ¿copiar sombra?— vive en
`aegis_rollback_politica.c`, C portable sin una línea del WDK. El orden de las
reglas es la decisión de seguridad:

1. **Jamás** interceptar al propio EDR (bucle infinito, disco lleno).
2. **Jamás** re-copiar lo ya copiado (pisaría la versión buena).
3. Nunca copiar ruido del sistema (temporales, caché).
4. Con incidente confirmado, copiar todo lo que el proceso toque.
5. Sin incidente, copiar solo ante la firma cruda del cifrado.

Se ejercita en cada `make ci` con gcc y clang (**7 aserciones**), y se
cross-compila a un objeto Windows x64 real. El minifilter completo
(`FltRegisterFilter`, callback pre-op `IRP_MJ_WRITE`) necesita el WDK y queda
gated, igual que el driver de la FASE 47. En Linux, la captura equivalente
(fanotify `FAN_PRE_ACCESS`) está tras la feature `fanotify` porque necesita
`CAP_SYS_ADMIN`; el CI declara si se ejercitó.

## 45.6 Frontera de realidad

| Pieza | Verificable aquí | Muro |
|---|---|---|
| Diario (qué/cuándo copiar) | sí, con cifrador ChaCha20 real y ficheros reales | — |
| Almacén cifrado de sombras | sí, AES-256-GCM real + detección de manipulación | — |
| Plan y reversión | sí, restaura ficheros reales byte a byte | — |
| Decisión del minifilter (C) | sí, gcc+clang + cross-compile a objeto Windows | — |
| Captura CoW en vivo | — | fanotify (`CAP_SYS_ADMIN`) / minifilter `.sys` (WDK), gated |
