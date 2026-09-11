# Módulo 48 — TinyML en el borde: zero-day sin nube

> Componentes: `crates/aegis-edgeml/`, `crates/aegis-agent/src/edge_ml.rs`.

## 48.1 Por qué en el agente y no en la nube

La FASE 45 correlaciona comportamiento en toda la flota desde el plano de control.
Es potente, pero tiene una latencia y una dependencia: hace falta red, y hace
falta que el evento llegue, se agregue y vuelva un veredicto. **Un ransomware
cifra miles de ficheros en ese viaje de ida y vuelta.** Y un endpoint aislado —una
fábrica sin salida a internet, un portátil en un avión— no tiene plano de control
al que preguntar.

Por eso el agente lleva su propio clasificador: un modelo pequeño **embebido en el
binario** que, a partir de la secuencia de syscalls y del grafo de procesos, emite
un veredicto de aislamiento **sin preguntarle a nadie**. No sustituye a la nube;
decide en los milisegundos en que la nube todavía no sabe nada. Y como viaja dentro
del binario (unos pocos KB), no hay fichero externo que un atacante pueda borrar
para cegarlo.

## 48.2 Detecta por la forma, no por el nombre

Un zero-day, por definición, no tiene firma conocida. El modelo no busca familias:
busca la **forma** del comportamiento. Una ráfaga de leer-cifrar-borrar es
ransomware aunque la familia sea nueva; leer la memoria de otro proceso es robo de
credenciales lo haga quien lo haga; `memfd_create` seguido de `execve` es ejecución
sin fichero.

El modelo es una **red neuronal con una capa oculta** donde **cada neurona es un
concepto de ataque** —ransomware, robo de credenciales, ejecución sin fichero, C2—
expresado como una combinación de features de comportamiento, y la capa de salida
los combina. Los pesos están **calibrados a mano, no son aleatorios**, por la misma
razón que el clasificador estático de la FASE anterior: un modelo aleatorio hace
que las pruebas comprueben solo que *"el tensor entra y sale un número"*, y eso pasa
mientras el producto no detecta nada. Con conceptos calibrados, la salida es
**explicable** y las pruebas tienen contenido.

## 48.3 El caso que separa un buen modelo de uno malo

El test decisivo no es *"detecta ransomware"* —eso lo hace cualquier umbral sobre el
volumen de escritura—. Es que **no bloquea un backup legítimo**. Un backup escribe
tantísimo como el ransomware; lo que los separa es que el ransomware **cifra** (datos
de alta entropía) y **borra** el original, y el backup no. Un modelo que decida por
volumen de escritura bloquea el backup nocturno de la empresa —y bloquear eso es como
se pierde la confianza del cliente—. El modelo puntúa el ransomware por encima de
0,90 y el backup por debajo de 0,50, separados por más de 0,45; los tests lo exigen.

## 48.4 Sin muro de hardware: todo se prueba aquí

A diferencia de las fases de TPM, Intel PT o el driver de Windows, esta **no tiene
muro físico**. El modelo ONNX se carga con `tract` (Rust puro, sin dependencias
nativas, corre en el borde sin conexión) y se infiere sobre secuencias de syscalls
reales en cada `make ci`. Lo único que un despliegue de producción cambia es el
modelo —entrenado sobre la telemetría real de la flota (FASE 45)— que llega por el
canal firmado de `aegis-update`, con la misma forma de grafo y dimensión de entrada,
así que el agente no cambia.

## 48.5 El espejo que no puede desalinearse

El vector de 64 features tiene que significar lo mismo en el extractor
(`behavior.rs`) y en el generador del modelo (`build_behavior_model.py`): si un
índice aquí no es el de allí, el modelo puntúa sobre la feature equivocada y el
veredicto es basura **sin dar ningún error**. Por eso los índices tienen nombre en
los dos lados, y son un espejo exacto.

| Pieza | Verificable aquí | Muro |
|---|---|---|
| Extracción de features de comportamiento | sí, secuencias de syscalls reales | — |
| Inferencia con tract del modelo embebido | sí, en cada `make ci` | — |
| Separación ransomware / backup legítimo | sí, exigida por los tests | — |
| Integración en el binario del agente | sí, `aegis-agent` carga y clasifica | — |
| Modelo entrenado sobre corpus real | línea base calibrada a mano | el modelo de producción llega por el canal firmado |
