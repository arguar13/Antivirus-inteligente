# Módulo 64 — AegisPredict: predecir el ataque y contenerlo antes

> Componentes: `server/crates/aegis-predict/`,
> `server/crates/aegis-server/src/prediccion.rs`, `tools/verificar-predict.sh`.

## 64.1 La pregunta que hace un CISO

Todo lo anterior del producto responde **después**: algo pasó, se detectó, se
remedió. Esta fase responde otra cosa:

> Dado cómo está montada mi organización, **¿por dónde va a entrar y hasta dónde
> llega?**

El plano de control ya tenía con qué contestarla: el **grafo de identidad** de la
[FASE 58](58-dop.md) —quién puede actuar como quién— y la topología de red. Lo
que faltaba era unirlos y calcular.

Unirlos importa: un atacante no se mueve por el grafo de identidad **o** por el
de red, los alterna. Roba credenciales en una máquina, las usa para llegar a
otra, y allí saca las credenciales cacheadas de alguien con más privilegio.
Mirar cada grafo por separado deja fuera justo los caminos que el atacante usa:
los que cambian de plano.

## 64.2 Tres preguntas, tres respuestas exactas

### El camino más probable: Dijkstra sobre `−log p`

La probabilidad de que un atacante recorra un camino entero es el **producto** de
las de sus pasos. Dijkstra no maximiza productos, minimiza sumas — pero el
logaritmo convierte una cosa en la otra:

```
maximizar  ∏ pᵢ     ⟺     minimizar  Σ −log(pᵢ)
```

y como cada `pᵢ ∈ (0, 1]`, cada `−log(pᵢ) ≥ 0`: **todos los pesos son no
negativos**, que es exactamente la condición que Dijkstra necesita. El resultado
no es una heurística ni una aproximación: es **el óptimo exacto**.

Eso importa en un caso concreto que una búsqueda en anchura falla siempre: **el
camino más probable no es el más corto.** Un atajo de un salto a través de un
firewall (`p = 0,15`) es peor que un rodeo de dos saltos por pertenencia a grupos
(`0,99 · 0,99 = 0,98`). Hay una prueba dedicada a ese caso.

### El radio de explosión: percolación Monte Carlo

«Dado que el atacante controla X, ¿cuántos activos caen?» es la **fiabilidad de
una red**, y calcularla de forma exacta es **#P-completo**: no hay fórmula cerrada
ni algoritmo eficiente, y no lo habrá. Lo que sí hay es percolación: se sortea
cada arista según su probabilidad, se mira qué queda alcanzable, y se repite. La
media converge al valor real con error `∝ 1/√n`.

Eso no es una aproximación vergonzante, es *la* forma de responder a esta
pregunta. Lo que sí sería un error es presentarla como exacta, y por eso **el
margen viaja dentro del resultado**: un número de Monte Carlo sin su margen se lee
como exacto, y no lo es.

Se comprueba contra el valor **analítico**: una cadena de dos aristas de
probabilidad `p` alcanza en media `p + p²`, y el motor lo reproduce con error
< 0,02. Y el margen encoge como debe, medido con 200 y con 20 000 pasadas.

### La criticidad: un portátil vale lo que alcanza

Un portátil de becario no vale nada por sí mismo. Vale exactamente lo que valen
las cosas a las que da acceso. La criticidad propaga el valor **hacia atrás**
desde las joyas de la corona:

```
c(v) = valor(v) + α · Σ  p(v→u) · c(u)
                   v→u
```

Es *message passing* sobre el grafo, con los pesos puestos a mano. El factor
`α = 0,85` no es decorativo: hace que la iteración sea una **contracción**, y sin
él un ciclo —y los hay siempre: A puede actuar como B y B como A— haría que el
valor diera vueltas amplificándose. No sería un número grande: sería infinito.

## 64.3 Lo que este motor autoriza, y por qué lo cambia todo

AegisPredict no escribe informes: **propone aislar máquinas de producción**. Esa
frase gobierna cada decisión del crate.

**Por eso nada está entrenado.** Ni las probabilidades de las aristas ni los pesos
de la criticidad. Están a mano, documentados con su razón, y el resultado se
imprime en una frase:

```
alice se autentica en pc-alice tiene credenciales cacheadas de svc-backup
      es miembro de Domain Admins (p = 0,5643)
```

Un analista puede leer eso y decir que no. Un vector de activaciones no se
discute, y lo que no se discute no se pone delante de un cliente cuya máquina se
va a quedar sin red.

Un modelo entrenado, además, necesitaría un corpus etiquetado de brechas reales
de **esta** organización, que no existe; con datos de otra, aprendería la
topología de otra.

**Y por eso todo es determinista.** Mismo grafo, mismo camino, mismo radio, misma
propuesta — desempates exactos incluidos, y con el PRNG sembrado a partir del
origen del análisis. No es comodidad: el informe que justifica aislar una máquina
el lunes tiene que dar lo mismo cuando alguien lo audite el martes.

Un detalle que parece menor y no lo es: la semilla se deriva con **FNV-1a**, no
con `DefaultHasher`. La salida de `DefaultHasher` puede cambiar entre versiones
de Rust, así que el radio de un endpoint cambiaría **al recompilar**. Hay una
prueba que fija el valor.

## 64.4 Los dos peligros de la contención preventiva

### (a) El modelo se equivoca y la cura es la enfermedad

Aislar doscientas máquinas porque una heurística de grafos predijo un radio es
una denegación de servicio auto-infligida. Por encima de cierto tamaño **la
contención ES la interrupción**, y da igual que la predicción fuera buena.

Por eso hay un tope duro, y pasado él el motor **no actúa: escala a una persona**.
No es una degradación elegante, es la decisión correcta — a esa escala quien debe
decidir es alguien que responde de la decisión.

### (b) El atacante dirige la predicción

Éste es el peligro que no se puede ignorar. El atacante **es quien fabrica
aristas**: es el que se mueve lateralmente, el que se autentica, el que deja
credenciales cacheadas. Si el motor actuara sobre cualquier camino, un adversario
podría construirse uno *a través de la máquina que quiere tirar* y conseguir que
la propia defensa la aísle. AegisPredict convertido en una primitiva de
denegación de servicio manejada por el adversario.

Es el problema de la [FASE 68](63-swarm.md) en otra capa, y se resuelve con la
misma idea: **la evidencia débil no mueve nada automáticamente**. Una arista vista
una sola vez, hace diez minutos y por un solo observador, pesa un tercio y nunca
dispara una acción sola — escala.

No se borra, ojo: la observación es real y esconderla sería peor. Se le quita el
peso que haría que mueva una decisión automática.

Y las tres condiciones de «evidencia sólida» hacen falta **a la vez**: verse
varias veces, por más de un observador, y llevar más de un día. Exigir sólo una
deja el hueco: un atacante puede repetir la misma acción mil veces en un minuto
desde la misma máquina, y eso no es corroboración, es la misma observación mil
veces.

## 64.5 Los cinco frenos

1. **Un activo protegido no se toca jamás** — el plano de control, los
   controladores de dominio, y lo que el cliente declare. Sin esto, una predicción
   puede cortar la capacidad del defensor de responder, que es exactamente lo que
   el atacante busca.
2. **Tope de radio**: por encima, se escala.
3. **Sólo evidencia corroborada** mueve una acción automática.
4. **Umbral de probabilidad**: un camino improbable no justifica nada.
5. **Mínima y reversible**: se prefiere cortar la *identidad* —revocar tickets,
   matar el proceso que cachea credenciales— a *aislar la máquina*. Revocar deja
   el equipo trabajando; aislarlo lo saca de producción. Aislar es el último
   recurso, y sólo para saltos de red, que no se pueden cortar más fino.

### Dos correcciones que costaron pensarlas

**La protección se comprueba sólo en el origen del paso.** Todas las acciones se
aplican sobre quien tiene la capacidad que hay que quitar, que es el origen:
aislar *su* red, matar *sus* procesos, revocar *sus* tickets. Un destino protegido
**no** impide cortar, porque cortar el paso lo **protege** en vez de dañarlo.

Mirar también el destino era un error grave y silencioso: los caminos
interesantes terminan por definición en una joya de la corona, y las joyas suelen
estar protegidas — así que la salvaguarda habría **desactivado la contención
exactamente en los casos que importan**, pareciendo que funcionaba.

**La guarda porcentual necesita un suelo.** Un porcentaje sobre un grafo diminuto
no se puede satisfacer jamás: con tres activos, contener *cualquier cosa* supera
el 5 %, así que el motor escalaría absolutamente todo y la contención automática
quedaría silenciosamente inútil. Por debajo de 50 activos manda el tope absoluto;
por encima, mandan los dos, y el porcentual suele ser el estricto (en una
organización de cien máquinas, aislar veinticinco automáticamente es demasiado
aunque el tope absoluto lo permita).

## 64.6 Predecir no es detectar

Una **detección** confirmada dispara el playbook entero de la FASE 64: aislar,
matar, revocar y volcar, en paralelo. Una **predicción** dispara como mucho **una**
acción acotada. En un caso ha pasado algo; en el otro podría pasar, y borrar esa
diferencia sería tratar una hipótesis como un hecho.

La orden sale por el **mismo camino** que la de remediación —mismo ejecutor, mismo
verbo, mismo canal— porque tres caminos distintos para la misma orden serían tres
sitios donde arreglar el mismo fallo. Pero lleva un **ordenante distinto**
(`ai-predict` frente a `ai-ro`): cuando un analista abra el informe a las tres de
la mañana, la diferencia entre «esto se aisló porque detectamos un Golden Ticket»
y «esto se aisló porque el modelo predijo un camino» es la primera pregunta que va
a hacer, y tiene que estar en el dato.

## 64.7 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Camino más probable | **sí** | contra un producto calculado a mano, y con el caso donde el óptimo **no** es el más corto |
| Radio de explosión | **sí** | converge al valor **analítico** `p + p²` con error < 0,02 |
| El margen encoge como `1/√n` | **sí** | medido con 200 y 20 000 pasadas |
| Criticidad | **sí** | valor exacto a mano, y un ciclo **converge** en vez de dispararse |
| Determinismo | **sí** | decenas de repeticiones, empates exactos incluidos |
| Los cinco frenos | **sí** | uno por uno, incluido el ataque de aristas fabricadas |
| Que segmentar **reduce** el radio | **sí** | si no, el modelo aconsejaría al revés |
| El circuito vivo | **sí** | contra **PostgreSQL real**: la propuesta acaba siendo una orden encolada, con su ordenante preventivo |
| **Calibración contra brechas reales** | — | exigiría un corpus etiquetado de esta organización, que no existe |

**No hay muro de hardware ni de sistema operativo en esta fase**: es matemática
sobre un grafo, y se comprueba entera.

Lo único que no se puede verificar aquí es la **calibración**: el motor no sabe si
`0,60` es la probabilidad real de que alguien se autentique en otro host de *esta*
empresa. Sabe que autenticarse cuesta más que heredar un grupo y menos que cruzar
un firewall, y ese **orden** —que sí se prueba— es lo que hace que el ranking y
los caminos sean útiles aunque los valores absolutos se ajusten después.

Por eso los números están **explícitos y discutibles** en `grafo::probabilidad`,
con su razón al lado, en vez de escondidos dentro de un modelo. Un cliente tiene
que poder ver —y rebatir— con qué números se decide aislar una de sus máquinas.
