#!/usr/bin/env python3
"""Genera el modelo ONNX residente de AegisCore.

QUE ES ESTE MODELO
==================

Una regresion logistica con pesos FIJADOS A MANO a partir de las heuristicas
documentadas en docs/03-motor-deteccion.md. No esta entrenado sobre un corpus:
es una LINEA BASE CALIBRADA que existe para que el pipeline de inferencia sea
real y ejecutable de extremo a extremo desde el primer dia.

Se elige asi, y no un modelo con pesos aleatorios, por dos razones:

1. Un modelo aleatorio hace que las pruebas de inferencia comprueben solo que
   "el tensor entra y sale un numero", que es exactamente el tipo de prueba que
   pasa mientras el producto no detecta nada.
2. Con pesos derivados de heuristicas conocidas, la salida es EXPLICABLE: se
   puede decir por que una muestra puntuo alto, y las pruebas pueden afirmar
   que un binario con seccion RWX y entropia 7,99 puntua por encima de
   /bin/true. Eso si es una comprobacion con contenido.

El modelo de PRODUCCION viene del pipeline de entrenamiento offline (LightGBM
exportado a ONNX) y sustituye a este por el canal de actualizacion firmado. La
forma del grafo y la dimension de entrada son las mismas, asi que el agente no
cambia.

Uso:  python3 build_model.py <ruta_de_salida.onnx>
"""

import sys

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

# --- Disposicion del vector, espejo de features.rs -------------------------
DIM = 256
OFF_HEADER = 64
OFF_SECTIONS = 96
OFF_IMPORTS = 144
OFF_STRINGS = 208
OFF_SIGNATURE = 240

# Indices con nombre, para que los pesos se lean como lo que significan.
F_ENTROPY = 1
F_BLOCK_MEAN = 2
F_BLOCK_MAX = 3
F_BLOCK_STDDEV = 5
F_HIGH_RATIO = 6
F_PRINTABLE = 7
F_PARSE_FAILED = 14

H_NX = OFF_HEADER + 8
H_PIE = OFF_HEADER + 9
H_RELRO = OFF_HEADER + 10
H_STRIPPED = OFF_HEADER + 12
H_RWX_SEGMENT = OFF_HEADER + 13
H_ENTRY_LAST = OFF_HEADER + 14
H_ENTRY_OUTSIDE = OFF_HEADER + 15
H_N_IMPORTS = OFF_HEADER + 19
H_HAS_SIGNATURE = OFF_HEADER + 23
H_DYN_NO_IMPORTS = OFF_HEADER + 24
H_OVERLAY_RATIO = OFF_HEADER + 25
H_OVERLAY_BIG = OFF_HEADER + 26

S_ENT_MEAN = OFF_SECTIONS + 1
S_ENT_MAX = OFF_SECTIONS + 2
S_ENT_HIGH_RATIO = OFF_SECTIONS + 5
S_WX_RATIO = OFF_SECTIONS + 6
S_NONSTD_RATIO = OFF_SECTIONS + 7
S_VIRT_RAW_MAX = OFF_SECTIONS + 9
S_VIRT_RAW_HIGH = OFF_SECTIONS + 11
S_HAS_TEXT = OFF_SECTIONS + 17
S_HAS_DATA = OFF_SECTIONS + 18
S_HAS_RODATA = OFF_SECTIONS + 19

# Categorias de cadena: presencia en OFF_STRINGS + 10 + i*2 (espejo de CATEGORIAS).
CAT_RED, CAT_CRIPTO, CAT_PERSIST, CAT_INYECCION, CAT_ANTIANALISIS, CAT_INTERP, CAT_RESCATE, CAT_RECON = range(8)
def cat_presencia(i):
    return OFF_STRINGS + 10 + i * 2

# --- Pesos ----------------------------------------------------------------
# Positivos: empujan hacia malicioso. Negativos: hacia benigno.
PESOS = {
    # Entropia: la senal mas basica de empaquetado o cifrado.
    F_ENTROPY:        1.8,
    F_BLOCK_MEAN:     1.2,
    F_BLOCK_MAX:      1.5,
    F_BLOCK_STDDEV:   1.0,   # mezcla de regiones dispares: patron de packer
    F_HIGH_RATIO:     2.0,
    F_PRINTABLE:     -1.5,   # mucho texto legible => guion o datos, no packer
    # Un binario malformado que aun asi ejecuta es evasion deliberada.
    F_PARSE_FAILED:   2.5,

    # Mitigaciones activas: senal de un compilador moderno y una cadena de
    # construccion normal.
    H_NX:            -1.2,
    H_PIE:           -0.8,
    H_RELRO:         -0.8,
    H_HAS_SIGNATURE: -2.5,
    H_STRIPPED:       0.5,

    # Segmento escribible y ejecutable: casi ningun compilador lo produce.
    H_RWX_SEGMENT:    3.0,
    H_ENTRY_LAST:     1.5,   # el punto de entrada en la seccion anadida
    H_ENTRY_OUTSIDE:  2.5,   # cabecera manipulada
    H_N_IMPORTS:     -1.0,   # muchas importaciones => enlazado normal
    H_DYN_NO_IMPORTS: 2.5,   # dinamico sin importaciones => resolucion manual
    H_OVERLAY_RATIO:  1.5,
    H_OVERLAY_BIG:    1.0,

    S_ENT_MEAN:       1.0,
    S_ENT_MAX:        1.2,
    S_ENT_HIGH_RATIO: 2.0,
    S_WX_RATIO:       2.5,
    S_NONSTD_RATIO:   1.8,   # nombres de seccion que ningun compilador emite
    S_VIRT_RAW_MAX:   2.2,   # tamano en memoria >> tamano en fichero: packer
    S_VIRT_RAW_HIGH:  1.5,
    S_HAS_TEXT:      -0.7,
    S_HAS_DATA:      -0.5,
    S_HAS_RODATA:    -0.5,

    cat_presencia(CAT_INYECCION):    1.8,
    cat_presencia(CAT_ANTIANALISIS): 1.5,
    cat_presencia(CAT_RESCATE):      2.5,
    cat_presencia(CAT_PERSIST):      1.0,
    cat_presencia(CAT_RECON):        0.8,
    cat_presencia(CAT_CRIPTO):       0.4,
    cat_presencia(CAT_RED):          0.3,
    cat_presencia(CAT_INTERP):       0.2,
}

# Sesgo. Se elige para que un ELF normal del sistema (entropia ~5,5, NX, PIE,
# RELRO, secciones estandar, sin RWX) quede claramente por debajo del umbral de
# vigilancia de 0,90, y un binario empaquetado con seccion RWX lo supere.
SESGO = -3.2


def construir():
    w = np.zeros((DIM, 1), dtype=np.float32)
    for idx, valor in PESOS.items():
        if not 0 <= idx < DIM:
            raise ValueError(f"indice {idx} fuera del vector de {DIM}")
        w[idx, 0] = valor
    b = np.array([SESGO], dtype=np.float32)

    entrada = helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, DIM])
    salida = helper.make_tensor_value_info("score", TensorProto.FLOAT, [1, 1])

    nodos = [
        helper.make_node("MatMul", ["features", "W"], ["logit_raw"], name="matmul"),
        helper.make_node("Add", ["logit_raw", "B"], ["logit"], name="add_bias"),
        helper.make_node("Sigmoid", ["logit"], ["score"], name="sigmoid"),
    ]

    grafo = helper.make_graph(
        nodos,
        "aegis_static_v1",
        [entrada],
        [salida],
        initializer=[
            numpy_helper.from_array(w, name="W"),
            numpy_helper.from_array(b, name="B"),
        ],
    )

    modelo = helper.make_model(
        grafo,
        producer_name="aegiscore-build-model",
        # opset 13 es el suelo que soportan todos los motores relevantes.
        opset_imports=[helper.make_opsetid("", 13)],
    )
    modelo.ir_version = 8
    modelo.doc_string = (
        "AegisCore static classifier v1. Linea base calibrada a mano a partir de "
        "las heuristicas de docs/03-motor-deteccion.md. NO esta entrenada sobre "
        "un corpus: el modelo de produccion llega por el canal de actualizacion "
        "firmado con la misma forma de grafo y la misma dimension de entrada."
    )
    onnx.checker.check_model(modelo)
    return modelo


def comprobar(modelo):
    """Verifica que el modelo separa los casos que dice separar.

    Un modelo que carga pero no discrimina pasa cualquier prueba de "el tensor
    entra y sale un numero". Estas comprobaciones son las que tienen contenido.
    """
    w = numpy_helper.to_array(modelo.graph.initializer[0])
    b = numpy_helper.to_array(modelo.graph.initializer[1])

    def puntuar(v):
        z = float((v @ w + b).reshape(-1)[0])
        return 1.0 / (1.0 + np.exp(-z))

    # Binario tipico del sistema: entropia moderada, mitigaciones activas,
    # secciones estandar, sin RWX.
    benigno = np.zeros((1, DIM), dtype=np.float32)
    benigno[0, F_ENTROPY] = 5.6 / 8
    benigno[0, F_BLOCK_MEAN] = 5.4 / 8
    benigno[0, F_BLOCK_MAX] = 6.4 / 8
    benigno[0, F_PRINTABLE] = 0.35
    benigno[0, H_NX] = 1
    benigno[0, H_PIE] = 1
    benigno[0, H_RELRO] = 1
    benigno[0, H_N_IMPORTS] = 0.15
    benigno[0, S_ENT_MEAN] = 5.0 / 8
    benigno[0, S_ENT_MAX] = 6.4 / 8
    benigno[0, S_HAS_TEXT] = 1
    benigno[0, S_HAS_DATA] = 1
    benigno[0, S_HAS_RODATA] = 1

    # Muestra empaquetada: entropia casi maxima, segmento RWX, punto de entrada
    # en la ultima seccion, nombres no estandar, sin importaciones.
    malicioso = np.zeros((1, DIM), dtype=np.float32)
    malicioso[0, F_ENTROPY] = 7.95 / 8
    malicioso[0, F_BLOCK_MEAN] = 7.9 / 8
    malicioso[0, F_BLOCK_MAX] = 7.99 / 8
    malicioso[0, F_HIGH_RATIO] = 0.95
    malicioso[0, F_PRINTABLE] = 0.05
    malicioso[0, H_RWX_SEGMENT] = 1
    malicioso[0, H_ENTRY_LAST] = 1
    malicioso[0, H_DYN_NO_IMPORTS] = 1
    malicioso[0, H_STRIPPED] = 1
    malicioso[0, S_ENT_MEAN] = 7.9 / 8
    malicioso[0, S_ENT_MAX] = 7.99 / 8
    malicioso[0, S_ENT_HIGH_RATIO] = 1.0
    malicioso[0, S_WX_RATIO] = 0.5
    malicioso[0, S_NONSTD_RATIO] = 0.6
    malicioso[0, S_VIRT_RAW_MAX] = 0.4
    malicioso[0, cat_presencia(CAT_INYECCION)] = 1
    malicioso[0, cat_presencia(CAT_ANTIANALISIS)] = 1

    # EL CASO QUE PRODUCE LOS FALSOS POSITIVOS REALES: software legitimo
    # distribuido comprimido. Entropia casi maxima, igual que el malware, pero
    # con firma, mitigaciones activas y secciones estandar. Un modelo que solo
    # mire la entropia bloquea a este, y bloquear el instalador de un producto
    # comercial firmado es como se pierde la confianza del cliente.
    empaquetado_legitimo = np.zeros((1, DIM), dtype=np.float32)
    empaquetado_legitimo[0, F_ENTROPY] = 7.92 / 8
    empaquetado_legitimo[0, F_BLOCK_MEAN] = 7.88 / 8
    empaquetado_legitimo[0, F_BLOCK_MAX] = 7.99 / 8
    empaquetado_legitimo[0, F_HIGH_RATIO] = 0.92
    empaquetado_legitimo[0, F_PRINTABLE] = 0.06
    empaquetado_legitimo[0, H_NX] = 1
    empaquetado_legitimo[0, H_PIE] = 1
    empaquetado_legitimo[0, H_RELRO] = 1
    empaquetado_legitimo[0, H_HAS_SIGNATURE] = 1
    empaquetado_legitimo[0, H_N_IMPORTS] = 0.08
    empaquetado_legitimo[0, S_ENT_MEAN] = 7.8 / 8
    empaquetado_legitimo[0, S_ENT_MAX] = 7.99 / 8
    empaquetado_legitimo[0, S_ENT_HIGH_RATIO] = 0.8
    empaquetado_legitimo[0, S_HAS_TEXT] = 1
    empaquetado_legitimo[0, S_HAS_DATA] = 1
    empaquetado_legitimo[0, S_HAS_RODATA] = 1

    sb, sm = puntuar(benigno), puntuar(malicioso)
    sp = puntuar(empaquetado_legitimo)
    print(f"  benigno              -> {sb:.4f}")
    print(f"  empaquetado legitimo -> {sp:.4f}")
    print(f"  malicioso            -> {sm:.4f}")

    assert sb < 0.30, f"un binario normal del sistema no puede puntuar {sb:.4f}"
    assert sm > 0.995, f"una muestra empaquetada maliciosa deberia superar 0,995, dio {sm:.4f}"
    assert sm - sb > 0.60, "el modelo no separa lo suficiente los dos casos"

    # Umbral de bloqueo del producto: 0,995. El empaquetado legitimo tiene que
    # quedar por debajo, aunque su entropia sea indistinguible de la del
    # malware: lo que lo separa son la firma y las mitigaciones, no la entropia.
    assert sp < 0.995, (
        f"software legitimo empaquetado puntua {sp:.4f} y se bloquearia. "
        "El modelo esta decidiendo por entropia en vez de por estructura."
    )
    assert sp > sb, "el empaquetado legitimo deberia puntuar por encima del binario normal"
    # Un vector todo a cero es la ausencia de informacion: debe quedar por
    # debajo de cualquier umbral de accion.
    vacio = puntuar(np.zeros((1, DIM), dtype=np.float32))
    print(f"  vacio     -> {vacio:.4f}")
    assert vacio < 0.10, f"el vector vacio puntua {vacio:.4f}"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    m = construir()
    print("Comprobaciones de separacion:")
    comprobar(m)
    onnx.save(m, sys.argv[1])
    print(f"Modelo escrito en {sys.argv[1]} ({len(m.SerializeToString())} bytes)")
