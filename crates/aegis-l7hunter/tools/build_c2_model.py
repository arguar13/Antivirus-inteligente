#!/usr/bin/env python3
"""Genera el modelo ONNX de clasificacion de canales C2 sobre TLS (FASE 66).

QUE ES ESTE MODELO
==================
Una red pequena de una capa oculta con pesos FIJADOS A MANO, siguiendo la misma
filosofia que los modelos de las FASES 48 y 53 (build_model.py y
build_behavior_model.py): cada neurona oculta representa un CONCEPTO de canal
—baliza clasica, baliza con jitter, canal binario propio, exfiltracion, trafico
benigno, sondeo legitimo— como combinacion lineal de features, y la salida los
combina.

POR QUE CALIBRADO Y NO ENTRENADO
================================
Por lo mismo que en las fases anteriores: con pesos aleatorios, las pruebas solo
comprueban que "entra un tensor y sale un numero". Con conceptos calibrados, la
salida es EXPLICABLE —se puede decir POR QUE una sesion puntuo alto— y las
pruebas pueden afirmar cosas con contenido: que una baliza de Cobalt Strike con
jitter del 40 % puntua por encima de 0,85 y que un agente de monitorizacion, que
es igual de periodico, se queda por debajo de 0,35.

EL CASO QUE DEFINE LA CALIBRACION
=================================
Un agente de monitorizacion legitimo (Prometheus, Zabbix, un health-check) es
PERFECTAMENTE periodico. Por la serie temporal es indistinguible de una baliza
sin jitter. Un modelo que decidiera solo por periodicidad marcaria toda la
infraestructura de observabilidad del cliente, y a la semana nadie miraria las
alertas. Lo que los separa es el CONTENIDO: el sondeo habla HTTP con un
User-Agent identificable, va a un host interno y sus URIs son estables y
legibles; la baliza lleva metadata codificada, o directamente no habla HTTP.

El modelo de PRODUCCION sale del pipeline de entrenamiento sobre la telemetria
real de la flota y sustituye a este por el canal firmado de aegis-update, con la
misma forma de grafo y la misma dimension de entrada.

Uso:  python3 build_c2_model.py <salida.onnx>
"""
import sys
import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

DIM = 32
HIDDEN = 6  # baliza, baliza-jitter, canal-binario, exfiltracion, benigno, sondeo

# --- Indices del vector de features (espejo exacto de modelo.rs) -----------
# Temporales (de aegis-l7hunter::baliza)
F_REGULARIDAD, F_CV_INV, F_CV_ROBUSTO_INV, F_COBERTURA, F_PERIODO_NORM = 0, 1, 2, 3, 4
# Volumen
F_BYTES_SAL_NORM, F_BYTES_ENT_NORM, F_TAM_CONSTANTE, F_RATIO_ENT_SAL, F_FRAC_PEQUENOS = 5, 6, 7, 8, 9
# Contenido L7
F_FRAC_HTTP, F_FRAC_DESCONOCIDO, F_COOKIE_B64, F_URI_B64, F_ENTROPIA = 10, 11, 12, 13, 14
F_SIN_AGENTE, F_AGENTE_RARO, F_FRAC_POST, F_UN_SOLO_HOST, F_URI_ESTABLE = 15, 16, 17, 18, 19
# Contexto
F_MUESTRA_NORM, F_PROC_NAVEGADOR = 20, 21


def concepto(pesos, sesgo):
    v = np.zeros(DIM, dtype=np.float32)
    for i, p in pesos.items():
        v[i] = p
    return v, sesgo


# Capa oculta: cada fila es un concepto. Se "enciende" (ReLU > 0) cuando sus
# features estan presentes por encima de su sesgo negativo.
CONCEPTOS = [
    # h0 BALIZA CLASICA: periodica, mensajes pequenos y constantes, un solo
    # destino... Y ADEMAS alguna evidencia de CONTENIDO malicioso.
    #
    # POR QUE LA FORMA NO BASTA, Y ESTA ES LA LECCION DE LA CALIBRACION
    # ----------------------------------------------------------------
    # La primera version de este concepto pesaba solo la forma temporal, y un
    # agente de monitorizacion puntuaba 1,0: es TAN periodico como una baliza sin
    # jitter, con mensajes igual de pequenos y constantes, y contra un solo host.
    # Toda la observabilidad del cliente habria sido una alerta critica.
    #
    # La correccion no fue subir el sesgo —eso solo habria movido la frontera—,
    # sino EXIGIR contenido: metadata codificada en cookie o URI, ausencia de
    # agente, un agente inventado, o directamente no hablar HTTP. Y restar fuerte
    # cuando las URIs son estables y legibles, que es lo que hace un health-check
    # y lo que una baliza no puede permitirse (necesita llevar su metadata).
    concepto({F_REGULARIDAD: 2.0, F_TAM_CONSTANTE: 1.5, F_FRAC_PEQUENOS: 1.0,
              F_UN_SOLO_HOST: 1.0,
              F_COOKIE_B64: 2.0, F_URI_B64: 2.0, F_SIN_AGENTE: 1.5,
              F_AGENTE_RARO: 1.5, F_FRAC_DESCONOCIDO: 1.5,
              F_URI_ESTABLE: -3.0}, -6.0),

    # h1 BALIZA CON JITTER: igual, pero la periodicidad la sostienen la medida
    # ROBUSTA y la cobertura temporal, porque con jitter el CV clasico ya no es
    # concluyente. Misma exigencia de contenido.
    concepto({F_CV_ROBUSTO_INV: 2.0, F_COBERTURA: 1.5, F_TAM_CONSTANTE: 1.0,
              F_FRAC_PEQUENOS: 1.0, F_UN_SOLO_HOST: 1.0,
              F_COOKIE_B64: 2.0, F_URI_B64: 2.0, F_SIN_AGENTE: 1.5,
              F_AGENTE_RARO: 1.5, F_FRAC_DESCONOCIDO: 1.5,
              F_URI_ESTABLE: -3.0}, -6.0),

    # h2 CANAL BINARIO PROPIO: dentro de TLS no habla HTTP y su carga tiene
    # entropia alta. Es contenido cifrado DOS veces, que el trafico legitimo no
    # hace. Se enciende SIN periodicidad a proposito: un canal interactivo de un
    # operador no es periodico y sigue siendo un C2.
    concepto({F_FRAC_DESCONOCIDO: 3.0, F_ENTROPIA: 2.5, F_UN_SOLO_HOST: 1.0}, -3.5),

    # h3 EXFILTRACION: mucho saliente, poco entrante, sostenido en el tiempo.
    concepto({F_BYTES_SAL_NORM: 3.0, F_RATIO_ENT_SAL: -2.0, F_FRAC_POST: 1.5,
              F_MUESTRA_NORM: 0.5}, -3.0),

    # h4 BENIGNO: irregular, HTTP, muchos destinos, proceso de navegador. Resta.
    concepto({F_FRAC_HTTP: 2.0, F_UN_SOLO_HOST: -2.0, F_REGULARIDAD: -2.0,
              F_SIN_AGENTE: -1.5, F_AGENTE_RARO: -1.5, F_PROC_NAVEGADOR: 2.0}, -1.5),

    # h5 SONDEO LEGITIMO: EL CASO DIFICIL. Tan periodico como una baliza, pero
    # habla HTTP con URIs estables y legibles, con agente identificable y sin
    # metadata codificada. Resta, y es lo que impide que la observabilidad del
    # cliente se convierta en un incidente.
    concepto({F_REGULARIDAD: 2.0, F_FRAC_HTTP: 2.0, F_URI_ESTABLE: 2.0,
              F_COOKIE_B64: -2.5, F_URI_B64: -2.5, F_SIN_AGENTE: -1.5,
              F_FRAC_DESCONOCIDO: -3.0, F_ENTROPIA: -1.5}, -4.0),
]

# Capa de salida: los conceptos de ataque suman; los benignos restan.
W2 = np.array([[1.35, 1.45, 1.25, 1.15, -1.30, -1.55]], dtype=np.float32)
B2 = np.array([-0.30], dtype=np.float32)


def construir():
    W1 = np.stack([c[0] for c in CONCEPTOS]).astype(np.float32)   # (HIDDEN, DIM)
    B1 = np.array([c[1] for c in CONCEPTOS], dtype=np.float32)

    entrada = helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, DIM])
    salida = helper.make_tensor_value_info("riesgo", TensorProto.FLOAT, [1, 1])

    iniciales = [
        numpy_helper.from_array(W1.T.copy(), "W1"),   # (DIM, HIDDEN)
        numpy_helper.from_array(B1, "B1"),
        numpy_helper.from_array(W2.T.copy(), "W2"),   # (HIDDEN, 1)
        numpy_helper.from_array(B2, "B2"),
    ]
    nodos = [
        helper.make_node("MatMul", ["features", "W1"], ["h_lin"]),
        helper.make_node("Add", ["h_lin", "B1"], ["h_bias"]),
        helper.make_node("Relu", ["h_bias"], ["h"]),
        helper.make_node("MatMul", ["h", "W2"], ["o_lin"]),
        helper.make_node("Add", ["o_lin", "B2"], ["o_bias"]),
        helper.make_node("Sigmoid", ["o_bias"], ["riesgo"]),
    ]
    grafo = helper.make_graph(nodos, "aegis-c2-l7-v1", [entrada], [salida], iniciales)
    modelo = helper.make_model(
        grafo,
        producer_name="aegiscore",
        opset_imports=[helper.make_opsetid("", 13)],
    )
    modelo.ir_version = 8
    onnx.checker.check_model(modelo)
    return modelo, (W1, B1, W2, B2)


def puntuar(v, pesos):
    W1, B1, W2, B2 = pesos
    h = np.maximum(W1 @ v + B1, 0.0)
    o = W2 @ h + B2
    return float(1.0 / (1.0 + np.exp(-o[0])))


def vec(d):
    v = np.zeros(DIM, dtype=np.float32)
    for i, x in d.items():
        v[i] = x
    return v


def comprobar(pesos):
    # Baliza clasica de Cobalt Strike: 60 s, sin jitter, HTTP con cookie de
    # metadata, siempre al mismo host, mensajes pequenos y constantes.
    baliza = vec({F_REGULARIDAD: 0.98, F_CV_INV: 0.97, F_CV_ROBUSTO_INV: 0.98,
                  F_COBERTURA: 1.0, F_TAM_CONSTANTE: 0.95, F_FRAC_PEQUENOS: 1.0,
                  F_UN_SOLO_HOST: 1.0, F_FRAC_HTTP: 1.0, F_COOKIE_B64: 1.0,
                  F_MUESTRA_NORM: 1.0, F_PERIODO_NORM: 0.5})

    # Baliza con jitter del 40 %: el CV clasico ya no es concluyente, la medida
    # robusta y la cobertura si.
    jitter = vec({F_REGULARIDAD: 0.70, F_CV_INV: 0.75, F_CV_ROBUSTO_INV: 0.92,
                  F_COBERTURA: 0.95, F_TAM_CONSTANTE: 0.85, F_FRAC_PEQUENOS: 1.0,
                  F_UN_SOLO_HOST: 1.0, F_FRAC_HTTP: 1.0, F_URI_B64: 1.0,
                  F_MUESTRA_NORM: 1.0, F_PERIODO_NORM: 0.5})

    # Canal binario propio dentro de TLS, interactivo (NO periodico).
    binario = vec({F_REGULARIDAD: 0.1, F_CV_ROBUSTO_INV: 0.2, F_FRAC_DESCONOCIDO: 1.0,
                   F_ENTROPIA: 0.98, F_UN_SOLO_HOST: 1.0, F_MUESTRA_NORM: 0.8})

    # Exfiltracion: POST grandes, respuestas minimas.
    exfil = vec({F_BYTES_SAL_NORM: 0.95, F_RATIO_ENT_SAL: 0.02, F_FRAC_POST: 1.0,
                 F_FRAC_HTTP: 1.0, F_UN_SOLO_HOST: 1.0, F_MUESTRA_NORM: 0.9})

    # Navegador: irregular, muchos destinos, agente conocido.
    navegador = vec({F_REGULARIDAD: 0.05, F_CV_INV: 0.1, F_COBERTURA: 0.02,
                     F_FRAC_HTTP: 1.0, F_UN_SOLO_HOST: 0.1, F_PROC_NAVEGADOR: 1.0,
                     F_BYTES_ENT_NORM: 0.7, F_RATIO_ENT_SAL: 0.9, F_MUESTRA_NORM: 1.0})

    # EL CASO DIFICIL: un agente de monitorizacion. Tan periodico como la baliza
    # sin jitter, pero habla HTTP legible con agente identificable y sin metadata
    # codificada. Un modelo que decidiera por periodicidad lo marcaria.
    sondeo = vec({F_REGULARIDAD: 0.99, F_CV_INV: 0.98, F_CV_ROBUSTO_INV: 0.99,
                  F_COBERTURA: 1.0, F_TAM_CONSTANTE: 0.9, F_FRAC_PEQUENOS: 1.0,
                  F_UN_SOLO_HOST: 1.0, F_FRAC_HTTP: 1.0, F_URI_ESTABLE: 1.0,
                  F_MUESTRA_NORM: 1.0, F_PERIODO_NORM: 0.3})

    s = {k: puntuar(v, pesos) for k, v in dict(
        baliza=baliza, jitter=jitter, binario=binario, exfil=exfil,
        navegador=navegador, sondeo=sondeo).items()}
    for k, val in s.items():
        print(f"  {k:10s} -> {val:.4f}")

    assert s["baliza"] > 0.90, f"la baliza clasica deberia superar 0,90: {s['baliza']:.4f}"
    assert s["jitter"] > 0.85, f"la baliza con jitter deberia superar 0,85: {s['jitter']:.4f}"
    assert s["binario"] > 0.80, f"el canal binario deberia superar 0,80: {s['binario']:.4f}"
    assert s["exfil"] > 0.70, f"la exfiltracion deberia superar 0,70: {s['exfil']:.4f}"
    assert s["navegador"] < 0.15, f"un navegador no puede puntuar {s['navegador']:.4f}"
    # EL CASO CLAVE: el sondeo es TAN periodico como la baliza. Si el modelo
    # decidiera por periodicidad, aqui puntuaria igual de alto y toda la
    # observabilidad del cliente seria una alerta.
    assert s["sondeo"] < 0.35, (
        f"un agente de monitorizacion puntua {s['sondeo']:.4f}: el modelo decide "
        "por periodicidad en vez de por contenido")
    assert s["baliza"] - s["sondeo"] > 0.55, (
        "no separa una baliza de un sondeo legitimo, que son igual de periodicos")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    m, pesos = construir()
    print("Comprobaciones de separacion:")
    comprobar(pesos)
    onnx.save(m, sys.argv[1])
    print(f"Modelo escrito en {sys.argv[1]} ({len(m.SerializeToString())} bytes)")
