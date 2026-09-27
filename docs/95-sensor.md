# Módulo 95 — AegisSensor: telemetría de kernel sin ceguera silenciosa (FASE 103)

> Componentes: `crates/aegis-sensor/`, `tools/verificar-sensor.sh`.

## 95.1 Las cuatro cosas que lo separan de Falco, Tracee y Tetragon

1. **Un sensor que pierde, lo dice y lo cuenta — por familia.** Falco publica un
   contador global de eventos perdidos; un anillo lleno se convierte en un hueco
   que aguas arriba se lee como «no pasó nada». Aquí la pérdida es una **cifra por
   familia** (`registrar_perdida`), y una familia con pérdida produce un
   `NoConcluyente` de su motor —un `SinDatos` con su cuenta—, no un silencio. Tapar
   con ruido **no puede** convertir «perdí eventos de red» en «la red está limpia».
2. **La degradación por presupuesto es visible y prioriza por valor.** Si el coste
   de las familias activas supera el presupuesto, `degradar` apaga familias por
   **valor ascendente** —la de menor valor primero, con desempate estable por
   nombre— y **devuelve cuáles apagó** para decirlo. La ejecución de procesos, la de
   más valor, se conserva hasta el final. Una familia apagada también es `SinDatos`:
   el cliente sabe que ahí no se está mirando. Una degradación silenciosa es una
   ceguera que el cliente no sabe que tiene.
3. **Ninguna decisión sobre datos que pudieron cambiar.** El atacante renombra el
   fichero entre la llamada y la lectura, o recicla el PID; un sensor que relee
   `/proc` **después** del evento decide sobre el estado nuevo, no sobre el que
   provocó el evento — una evasión TOCTOU documentada. Aquí el `Evento` lleva sus
   campos **ya capturados en el kernel** (la ruta resuelta, los argumentos copiados,
   el `Eid` derivado) y **no existe ninguna operación que vuelva a leer el sistema**.
   Se verifica por lo que **falta** del código: `verificar-sensor.sh` cuenta **cero**
   relecturas de `/proc` o del disco en el crate.
4. **La ceguera habla el idioma del producto.** Cada punto ciego se traduce en una
   `Senal` `NoConcluyente` del motor de esa familia, con `Confianza::NULA` a
   propósito: no empuja el veredicto hacia malicioso, solo declara la ausencia de
   datos en ese plano. El árbitro (`arbitrar`) con solo esas señales da `SinDatos`
   —no `Limpio`—, integrado con el **modelo de entidad único** de todo el producto.

## 95.2 Las familias, y por qué valor y coste son del tipo

`Familia` es una lista **cerrada** de trece superficies del kernel (proceso, fichero,
red, memoria, IPC, credenciales, espacios de nombres, módulos, BPF, ptrace, perf,
keyctl, io_uring). Cada una lleva su **valor** (cuánto importa para detección:
proceso 100 … perf 50), su **coste** (cuánto pesa capturarla), su **motor** de
`aegis-entidad` y su **plano**. La degradación usa el valor; el presupuesto usa el
coste. Ambos son del tipo, no configuración suelta: el orden en que se sacrifica
cobertura bajo presión es **parte del programa**, y por eso es demostrable.

## 95.3 La frontera: dónde vive la captura eBPF

La captura en vivo —programas eBPF CO-RE con ganchos LSM y tracepoints por familia—
vive en `drivers/linux/aegis-bpf`. Este crate es el **lado que decide**: consume
eventos ya capturados y decide qué se puede y qué no se puede afirmar. Sobre el
entorno de CI **BPF LSM está activo** (`/sys/kernel/security/lsm` incluye `bpf`), y
`verificar-sensor.sh` lo comprueba, porque es el habilitador de los ganchos LSM
sobre los que se apoya la ampliación de los programas eBPF a familias completas.

## 95.4 El autoataque: la inundación como ceguera

El ataque contra un sensor es **cegarlo**: generar ruido para llenar el anillo y
tapar la acción real. Es el ataque que hunde a los sensores que cuentan pérdida en
un solo número. Aquí se ejerce en `tests/autoataque.rs` y en la invariante 9: una
inundación de una familia produce `SinDatos` en ese plano (no `Limpio`); bajo
presupuesto ridículo se conserva la ejecución de procesos y las apagadas se dicen;
y la cuenta es **por familia**, que es lo que permite nombrar el plano ciego.

## 95.5 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Pérdida contada por familia | **sí** | `estado(f).perdidos` por familia; `perdida_total` suma; global de Falco no distingue plano |
| Pérdida ⇒ `SinDatos`, no `Limpio` | **sí** | familia con pérdida ⇒ `NoConcluyente`; `arbitrar` da `SinDatos` |
| Degradación visible y por valor | **sí** | `degradar` apaga por valor ascendente, conserva proceso, devuelve las apagadas |
| Familia apagada ⇒ `SinDatos` | **sí** | apagada produce `NoConcluyente` con motivo «APAGADA por presupuesto» |
| Sin relectura del sistema (TOCTOU) | **sí, por ausencia** | cero `/proc`/`fs::read`/`File` en el crate; el evento conserva lo capturado aunque el mundo cambie |
| Confianza nula del `NoConcluyente` | **sí** | `Confianza::NULA`: declara ausencia, no empuja a malicioso |
| BPF LSM activo (habilitador) | **sí, comprobado** | `/sys/kernel/security/lsm` incluye `bpf` |
| Autoataque (inundación como ceguera) | **sí** | `--test autoataque`: inundar no vuelve «limpio»; presión conserva lo de más valor |
| Captura eBPF en vivo por familia completa | **frontera** | vive en `drivers/linux/aegis-bpf`; aquí se prueba el lado que decide |
| Comparativa medida contra Falco / Tetragon | **muro de entorno** | requiere desplegarlos y un corpus de carga; se declara |

El alcance por partes es la decisión honesta: se construye el mecanismo distintivo
—pérdida por familia que se dice, degradación visible por valor, cero relectura del
sistema por tipo, y ceguera traducida a `SinDatos` en el modelo único— y la captura
eBPF en vivo se amplía sobre el habilitador (BPF LSM) ya verificado, en vez de
afirmar una cobertura de familias que no se ejerció.

Mensaje de commit:
`feat(sensor): expand kernel telemetry to full syscall families with LSM hooks, declared loss policy and in-kernel argument capture`
