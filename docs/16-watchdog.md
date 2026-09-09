# Módulo 16 — Watchdog de alta disponibilidad

> Componente: `crates/aegis-watchdog` (Rust) + binario `aegis-watchdog`.

Un EDR que se puede tumbar con un `kill` no protege nada: lo primero que hace un
atacante es apagar la vigilancia. **El agente no puede impedir su propia
terminación** —un `SIGKILL` de root no se puede bloquear desde el proceso
víctima—, así que la resiliencia la aporta un proceso aparte, mínimo, que lo
vuelve a arrancar.

Es minimalista a propósito: su única misión es que el agente siga en marcha, y
cuanto menos haga y menos memoria ocupe, menos superficie tiene quien quiera
tumbarlo a él.

---

## 16.1 Vivo, no solo presente

Un proceso puede estar **presente** (su PID existe) y sin embargo **colgado**: un
interbloqueo, un bucle infinito, un `read` que nunca vuelve. Comprobar solo el
PID no lo detecta. El agente escribe periódicamente un **latido** —un instante
del reloj monótono— en un fichero conocido; el watchdog lo lee y, si deja de
avanzar, sabe que el agente está colgado aunque su proceso siga ahí.

El fichero de latido es diminuto y la escritura es atómica por renombrado, para
que el watchdog nunca lea un valor a medias. Se usa el reloj **monótono** y no la
hora del sistema: un ajuste de reloj (NTP) no debe hacer creer al watchdog que el
agente lleva colgado horas.

---

## 16.2 Muerto, colgado, o parado a propósito

El watchdog distingue tres situaciones y actúa distinto en cada una:

| Estado observado | Decisión |
|---|---|
| El proceso ya no existe | **Reiniciar** (un `SIGKILL` cae aquí) |
| Existe pero el latido dejó de avanzar | **Reiniciar** (colgado) |
| Acaba de arrancar, aún sin latir | Esperar |
| Existe una marca de apagado autorizado | **No reiniciar** |

La **parada autorizada** es la frontera entre "lo mataron" y "lo pararon". Cuando
alguien con permiso le pide al agente que se detenga, este deja una marca de
apagado limpio; el watchdog la ve y no reinicia. Sin esto sería imposible parar
el agente: el watchdog lo resucitaría una y otra vez. La marca manda sobre todo
lo demás, incluso si el proceso murió.

Al reiniciar **no se pierden las políticas de seguridad**: el agente las recarga
de disco al arrancar (la configuración firmada, la línea base del FIM, la
cuarentena), y el watchdog solo lo vuelve a poner en marcha.

---

## 16.3 Cómo se prueba

Con un proceso hijo **real**: se lanza, se le hace `SIGKILL` —que no se puede
bloquear— y se comprueba que el watchdog lo detecta muerto (recolectando el
zombi) y arranca uno nuevo. Es el escenario que la FASE 17 dejó pendiente, y
ahora forma el **escenario 5** de la simulación de Red Team: se levanta el
binario `aegis-watchdog` supervisando un agente de mentira, se mata a ese agente
con `SIGKILL`, y se verifica que aparece un proceso nuevo.

También se prueba el reinicio ante cuelgue (latido rancio) y que una parada
autorizada nunca reinicia.

---

## 16.4 El presupuesto de 45 MB

El presupuesto de memoria del agente en pico se fija en **45 MB** y se mide en
cada `make ci` arrancando el binario de release y leyendo su RSS. Es un
compromiso del producto, no una aspiración: un componente que se lo salta es un
bug atribuible, y por eso se mide en la misma puerta que el resto. El agente
arranca holgadamente por debajo, con el blindaje activo y el canal de control
embebido.
