#!/usr/bin/env python3
"""Genera el modelo ONNX de COMPORTAMIENTO residente de AegisCore (FASE 53).

QUE ES ESTE MODELO
==================
Una red neuronal pequena (una capa oculta) con pesos FIJADOS A MANO, no
aleatorios, siguiendo la misma filosofia que el clasificador estatico
(build_model.py): cada neurona oculta representa un CONCEPTO de ataque conocido
—ransomware, robo de credenciales, ejecucion sin fichero, shell de C2— como una
combinacion lineal de features de comportamiento, y la capa de salida los combina.

Se elige asi, y no un modelo con pesos aleatorios, por lo mismo que el estatico:
un modelo aleatorio hace que las pruebas comprueben solo que "el tensor entra y
sale un numero". Con conceptos calibrados, la salida es EXPLICABLE —se puede
decir por que una secuencia de syscalls puntuo alto— y las pruebas pueden afirmar
que una rafaga de cifrado-y-borrado puntua por encima de un `ls`.

El modelo de PRODUCCION viene del pipeline de entrenamiento offline sobre la
telemetria real de la flota (FASE 45) y sustituye a este por el canal de
actualizacion firmado, con la misma forma de grafo y dimension de entrada.

Uso:  python3 build_behavior_model.py <salida.onnx>
"""
import sys
import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

DIM = 64
HIDDEN = 6  # ransomware, robo-cred, sin-fichero, c2-shell, benigno, ruido

# --- Indices del vector de comportamiento (espejo de behavior.rs) ----------
# Frecuencias de categoria de syscall (normalizadas 0..1)
F_OPEN, F_READ, F_WRITE, F_UNLINK, F_RENAME = 0, 1, 2, 3, 4
F_PROC_CREATE, F_PTRACE, F_PROC_VM, F_MMAP_EXEC, F_MEMFD = 5, 6, 7, 8, 9
F_NET, F_CHMOD, F_GETRANDOM = 10, 11, 12
# Ratios de comportamiento
R_WRITE_READ, R_UNLINK, R_WRITE_ENTROPY, R_BURST, R_DISTINCT_FILES = 16, 17, 18, 19, 20
# N-gramas caracteristicos (presencia 0/1)
NG_ORWC = 24        # open-read-write-close: acceso normal
NG_ORW_UNLINK = 25  # open-read-write-unlink: ransomware
NG_PTRACE_VMREAD = 26   # robo de credenciales
NG_MEMFD_EXECVE = 27    # ejecucion sin fichero
NG_MPROTECT_EXEC = 28   # shellcode rw->rx
NG_SOCKET_EXECVE = 29   # reverse shell
# Grafo de procesos (DAG)
DAG_FANOUT, DAG_DEPTH, DAG_ORPHANS, DAG_SHORTLIVED = 32, 33, 34, 35

def concepto(pesos, sesgo):
    v = np.zeros(DIM, dtype=np.float32)
    for i, p in pesos.items():
        v[i] = p
    return v, sesgo

# Capa oculta: cada fila es un concepto. Un concepto "se enciende" (ReLU > 0)
# cuando sus features estan presentes por encima de su sesgo negativo.
CONCEPTOS = [
    # h0 RANSOMWARE: escribir mucho de alta entropia y borrar el original.
    concepto({F_WRITE: 2.0, F_UNLINK: 2.0, R_WRITE_READ: 1.5, R_WRITE_ENTROPY: 2.5,
              R_UNLINK: 2.0, NG_ORW_UNLINK: 3.0, R_DISTINCT_FILES: 1.5, F_READ: 0.5}, -3.0),
    # h1 ROBO DE CREDENCIALES: leer la memoria de otro proceso.
    concepto({F_PTRACE: 2.5, F_PROC_VM: 3.0, NG_PTRACE_VMREAD: 3.5}, -2.5),
    # h2 EJECUCION SIN FICHERO: codigo que nunca toca el disco.
    concepto({F_MEMFD: 2.5, F_MMAP_EXEC: 2.0, NG_MEMFD_EXECVE: 3.0, NG_MPROTECT_EXEC: 2.5}, -2.5),
    # h3 SHELL DE C2: red + ejecucion + arbol de procesos raro.
    concepto({F_NET: 1.2, NG_SOCKET_EXECVE: 3.0, F_PROC_CREATE: 1.0,
              DAG_FANOUT: 1.0, DAG_SHORTLIVED: 1.0}, -2.5),
    # h4 BENIGNO: acceso a fichero normal, red moderada, sin patrones de ataque.
    concepto({NG_ORWC: 2.5, F_READ: 1.0, F_OPEN: 0.8}, -1.0),
    # h5 RUIDO: actividad baja e indistinta; ancla el sesgo.
    concepto({R_BURST: 0.5}, -2.0),
]

# Capa de salida: los conceptos maliciosos empujan hacia 1; el benigno, hacia 0.
W2 = np.array([[ 2.2],   # ransomware
               [ 2.2],   # robo credenciales
               [ 2.0],   # sin fichero
               [ 1.8],   # c2 shell
               [-2.5],   # benigno
               [-0.5]],  # ruido
              dtype=np.float32)
B2 = np.array([-1.2], dtype=np.float32)


def construir():
    W1 = np.stack([c[0] for c in CONCEPTOS], axis=1)  # (DIM, HIDDEN)
    B1 = np.array([c[1] for c in CONCEPTOS], dtype=np.float32)  # (HIDDEN,)

    entrada = helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, DIM])
    salida = helper.make_tensor_value_info("score", TensorProto.FLOAT, [1, 1])
    nodos = [
        helper.make_node("MatMul", ["features", "W1"], ["z1"], name="mm1"),
        helper.make_node("Add", ["z1", "B1"], ["a1"], name="add1"),
        helper.make_node("Relu", ["a1"], ["h1"], name="relu1"),
        helper.make_node("MatMul", ["h1", "W2"], ["z2"], name="mm2"),
        helper.make_node("Add", ["z2", "B2"], ["logit"], name="add2"),
        helper.make_node("Sigmoid", ["logit"], ["score"], name="sig"),
    ]
    grafo = helper.make_graph(
        nodos, "aegis_behavior_v1", [entrada], [salida],
        initializer=[
            numpy_helper.from_array(W1, name="W1"),
            numpy_helper.from_array(B1, name="B1"),
            numpy_helper.from_array(W2, name="W2"),
            numpy_helper.from_array(B2, name="B2"),
        ],
    )
    modelo = helper.make_model(grafo, producer_name="aegiscore-build-behavior",
                               opset_imports=[helper.make_opsetid("", 13)])
    modelo.ir_version = 8
    modelo.doc_string = (
        "AegisCore behavior classifier v1. Red de una capa oculta con pesos "
        "calibrados a mano: cada neurona oculta es un concepto de ataque "
        "(ransomware, robo de credenciales, ejecucion sin fichero, C2). El modelo "
        "de produccion llega por el canal firmado, entrenado sobre la telemetria "
        "real de la flota, con la misma forma de grafo.")
    onnx.checker.check_model(modelo)
    return modelo, (W1, B1, W2, B2)


def puntuar(v, pesos):
    W1, B1, W2, B2 = pesos
    h = np.maximum(0.0, v @ W1 + B1)
    z = float((h @ W2 + B2).reshape(-1)[0])
    return 1.0 / (1.0 + np.exp(-z))


def comprobar(pesos):
    def vec(d):
        v = np.zeros((1, DIM), dtype=np.float32)
        for i, val in d.items():
            v[0, i] = val
        return v

    # Ransomware: rafaga de open-read-write-unlink de alta entropia.
    ransom = vec({F_OPEN: 0.8, F_READ: 0.7, F_WRITE: 0.9, F_UNLINK: 0.8,
                    R_WRITE_READ: 0.9, R_WRITE_ENTROPY: 0.98, R_UNLINK: 0.85,
                    NG_ORW_UNLINK: 1.0, R_DISTINCT_FILES: 0.9})
    # Robo de credenciales: ptrace + process_vm_readv.
    cred = vec({F_PTRACE: 0.7, F_PROC_VM: 0.9, NG_PTRACE_VMREAD: 1.0})
    # Sin fichero: memfd_create + execve.
    fileless = vec({F_MEMFD: 0.8, F_MMAP_EXEC: 0.7, NG_MEMFD_EXECVE: 1.0, NG_MPROTECT_EXEC: 1.0})
    # Benigno: un editor guardando un fichero (open-read-write-close), algo de red.
    benigno = vec({F_OPEN: 0.5, F_READ: 0.6, F_WRITE: 0.3, NG_ORWC: 1.0, F_NET: 0.2})
    # Backup legitimo: escribe MUCHO, pero NO borra el original ni cifra (baja
    # entropia). Es el falso positivo que un modelo solo-de-escritura cometeria.
    backup = vec({F_OPEN: 0.7, F_READ: 0.8, F_WRITE: 0.9, NG_ORWC: 1.0,
                    R_WRITE_READ: 0.5, R_DISTINCT_FILES: 0.8, R_WRITE_ENTROPY: 0.15})

    s = {k: puntuar(v, pesos) for k, v in
         dict(ransom=ransom, cred=cred, fileless=fileless, benigno=benigno, backup=backup).items()}
    for k, val in s.items():
        print(f"  {k:9s} -> {val:.4f}")

    assert s["ransom"] > 0.90, f"ransomware deberia superar 0,90, dio {s['ransom']:.4f}"
    assert s["cred"] > 0.90, f"robo de credenciales deberia superar 0,90, dio {s['cred']:.4f}"
    assert s["fileless"] > 0.85, f"ejecucion sin fichero deberia superar 0,85, dio {s['fileless']:.4f}"
    assert s["benigno"] < 0.15, f"un guardado normal no puede puntuar {s['benigno']:.4f}"
    # EL CASO CLAVE: un backup escribe tanto como el ransomware, pero sin cifrar
    # ni borrar. Un modelo que decida por volumen de escritura lo bloquearia;
    # este tiene que dejarlo pasar.
    assert s["backup"] < 0.50, (
        f"un backup legitimo puntua {s['backup']:.4f}: el modelo decide por volumen "
        "de escritura en vez de por cifrado-y-borrado")
    assert s["ransom"] - s["backup"] > 0.45, "no separa ransomware de backup legitimo"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(2)
    m, pesos = construir()
    print("Comprobaciones de separacion:")
    comprobar(pesos)
    onnx.save(m, sys.argv[1])
    print(f"Modelo escrito en {sys.argv[1]} ({len(m.SerializeToString())} bytes)")
