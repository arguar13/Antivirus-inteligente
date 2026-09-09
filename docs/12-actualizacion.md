# Módulo 12 — Actualización segura y auto-parcheo (AegisUpdater)

> Componente: `crates/aegis-update` (Rust, Ed25519).

Un motor de actualización es una vía directa para ejecutar código del atacante
con los permisos del defensor: si el agente descarga y aplica un binario, una
regla YARA o un modelo ONNX que alguien pudo sustituir en tránsito o en el
servidor, el atacante ya no necesita evadir el EDR, lo pilota. Dos defensas lo
impiden, y el módulo se construye alrededor de ambas.

---

## 12.1 Nada se aplica sin firma válida

El servidor de actualizaciones firma cada artefacto con una clave privada
**Ed25519** que solo él tiene. El agente lleva la clave **pública**
correspondiente y **verifica la firma antes de tocar nada**. Un artefacto
manipulado, o firmado con otra clave, no verifica y no se aplica.

La verificación ocurre **antes** de escribir el artefacto en producción: un
fichero que no verifica no llega ni a escribirse en su sitio. La prueba
`un_artefacto_sin_firma_valida_no_llega_a_escribirse` lo confirma mirando el
disco.

### Por qué Ed25519 y no RSA

Firmas y claves pequeñas (64 y 32 bytes), verificación rápida, y **sin los
parámetros que hay que elegir bien en RSA** (tamaño, relleno) y que son una
fuente habitual de fallos de implementación. Los tres tipos de artefacto
—binario del agente, reglas YARA, modelo ONNX, más el bytecode eBPF— se validan
exactamente igual.

---

## 12.2 Aplicar es todo o nada, y siempre hay marcha atrás

```
        verificar firma          escribir ensayo         rename atómico
descarga ─────────────► (falla → parar) ──► <name>.staging ──► <name>
                                                    │ (la versión viva
                                                    ▼  pasa a <name>.prev)
                                          si la nueva falla la salud:
                                          rename <name>→<name>.failed
                                          rename <name>.prev→<name>
```

El artefacto nuevo se escribe en un fichero de ensayo (`<name>.staging`) en el
**mismo directorio** que el vivo, se fuerza a disco, y solo entonces se activa
con un `rename`, que es **atómico** en POSIX: en ningún instante hay un fichero
a medio escribir en la ruta de producción. La versión anterior se preserva como
`<name>.prev`.

### Por qué el respaldo va en el mismo directorio

El `rename` solo es atómico dentro de un mismo sistema de ficheros. Guardar el
respaldo en otra partición haría que restaurarlo fuese una copia no atómica, con
una ventana en la que no hay binario. El respaldo vive junto al fichero vivo, y
restaurarlo es un `rename` atómico.

---

## 12.3 Rollback automático ante un arranque fallido

`apply_checked` aplica la versión nueva y ejecuta una **comprobación de salud**;
si falla —la nueva versión no arranca, o se cae al iniciar— restaura la anterior
**sola**, sin dejar la máquina sin protección. La versión defectuosa no se borra
en silencio: se aparta como `<name>.failed` para el análisis forense.

La comprobación de salud es un rasgo (`HealthCheck`), no una llamada fija: en
producción arranca el binario nuevo con un `--self-check` y mira que salga 0; en
las pruebas es una función. La prueba `una_version_que_no_pasa_la_salud_se_
revierte_sola` instala una versión "que pánica", verifica que se revierte a la
estable, y comprueba en disco que la estable quedó activa y la rota apartada.

Las firmas se ejercitan con una clave Ed25519 **generada en la prueba** y su
pública: un ciclo de firma real, no un vector fijo.
