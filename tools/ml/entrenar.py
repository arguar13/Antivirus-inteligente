#!/usr/bin/env python3
"""Entrenamiento y tarjeta del modelo estatico de AegisCore (FASE 4.4 del MP-16).

QUE HACE
========

  entrenar   manifiesto(s) + vectores de aegis-vectorizar
             -> modelo ONNX + tarjeta plana (la lee la puerta del agente)
                + tarjeta legible (docs/generado/tarjeta-modelo-estatico.md)
  referencia tarjeta del modelo de REFERENCIA actual (sin metricas: «sin medir»)
  comprobar  las dos tarjetas corresponden por hash al ONNX del repositorio

POR QUE ASI
===========

- Las caracteristicas NO se calculan aqui. Se leen de la salida de
  `aegis-vectorizar` (crates/aegis-trabajador/src/bin/), que llama a
  `aegis_ml::vectorizar`, la misma funcion que el trabajador confinado usa antes
  de inferir. Un segundo extractor en Python divergeria del de produccion sin
  dar ningun error. La huella del extractor viaja a la tarjeta y el agente la
  comprueba (crates/aegis-ml/src/puerta.rs).
- Division por FECHA de primera vista: ajuste y calibracion con lo ANTERIOR al
  corte, evaluacion con lo POSTERIOR. Una division aleatoria mezcla variantes de
  la misma familia a ambos lados y mide memoria, no deteccion.
- Los umbrales se eligen sobre la CALIBRACION (el ultimo 20 % anterior al
  corte), nunca sobre la evaluacion: elegirlos sobre el conjunto con el que se
  mide daria un FPR optimista por construccion.
- El FPR se publica con su cota superior al 95 % (Clopper-Pearson unilateral).
  Cero falsos positivos sobre mil benignos no es un FPR de cero.
- Modelo: regresion logistica (IRLS, determinista, sin semillas que importen),
  con la estandarizacion plegada en los pesos. Es el MISMO grafo que el modelo de
  referencia (MatMul + Add + Sigmoid, opset 13), que tract ya ejecuta en el
  agente: cambiar el algoritmo no cambia una linea del agente.
- Evasion basica: para un modelo lineal, el peor caso de una perturbacion
  acotada sobre las caracteristicas que mueve un relleno o una seccion anadida
  tiene forma cerrada. Se publica como COTA (lo peor que esa familia de cambios
  podria hacer), sin fabricar ningun binario.

Todas las cifras de la tarjeta salen de este codigo; las que no se pueden medir
dicen «sin medir».

FORMATOS
========

Manifiesto (TSV, `#` comenta; cabecera opcional):
    sha256  etiqueta(malicioso|benigno)  familia  primera_vista(AAAA-MM-DD)  origen
Vectores (salida de aegis-vectorizar):
    # aegis-vectorizar version_vector=N dim=256 huella_extractor=HEX aegis-ml=V
    sha256  OK  microsegundos  v0,v1,...,v255
    sha256  SINDATOS  motivo

Dependencias fijadas en tools/ml/requisitos.txt (numpy, onnx). `referencia` y
`comprobar` solo usan la biblioteca estandar.
"""

import argparse
import hashlib
import math
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODELO = os.path.join(RAIZ, "crates", "aegis-ml", "models", "aegis-static-v1.onnx")
TARJETA = os.path.join(RAIZ, "crates", "aegis-ml", "models", "aegis-static-v1.tarjeta")
TARJETA_MD = os.path.join(RAIZ, "docs", "generado", "tarjeta-modelo-estatico.md")
CONFIG = os.path.join(RAIZ, "tools", "config", "modelo.toml")

DIM = 256
SIN_MEDIR = "sin medir"

# Caracteristicas que mueve barato un RELLENO al final del fichero (tamano,
# entropia global y por bloques, imprimibles, nulos, apendice) y una SECCION
# ANADIDA (bloque de secciones y punto de entrada en la ultima). Espejo de la
# disposicion de crates/aegis-ml/src/features.rs.
OFF_HEADER = 64
OFF_SECTIONS = 96
RELLENO = [0, 1, 2, 3, 4, 5, 6, 7, 8, 15, OFF_HEADER + 25, OFF_HEADER + 26]
SECCIONES = list(range(OFF_SECTIONS, OFF_SECTIONS + 48)) + [OFF_HEADER + 14]
PRESUPUESTOS = [0.10, 0.25]


# ── utilidades sin dependencias ─────────────────────────────────────────────

def leer_plano(ruta):
    """`clave = valor` por linea: el mismo subconjunto que lee el agente."""
    m = {}
    with open(ruta, encoding="utf-8") as f:
        for linea in f:
            l = linea.strip()
            if not l or l.startswith("#") or l.startswith("["):
                continue
            if "=" in l:
                k, v = l.split("=", 1)
                v = v.split(" #", 1)[0].strip().strip('"')
                m[k.strip()] = v
    return m


def sha256_fichero(ruta):
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for trozo in iter(lambda: f.read(1 << 20), b""):
            h.update(trozo)
    return h.hexdigest()


def sha256_de(rutas):
    h = hashlib.sha256()
    for r in sorted(rutas):
        h.update(os.path.basename(r).encode())
        h.update(sha256_fichero(r).encode())
    return h.hexdigest()


def escribir(ruta, texto):
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    with open(ruta, "w", encoding="utf-8", newline="\n") as f:
        f.write(texto)


def cota_clopper_pearson(k, n, confianza=0.95):
    """Cota superior unilateral de una proporcion binomial (k exitos de n)."""
    if n <= 0:
        return None
    if k >= n:
        return 1.0
    alfa = 1.0 - confianza
    if k == 0:
        return 1.0 - alfa ** (1.0 / n)

    def cdf(p):
        # P(X <= k) con X ~ Bin(n, p), en escala logaritmica.
        lp, lq = math.log(p), math.log1p(-p)
        s = 0.0
        for i in range(k + 1):
            s += math.exp(
                math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
                + i * lp + (n - i) * lq
            )
        return s

    lo, hi = k / n, 1.0 - 1e-15
    for _ in range(200):
        mid = (lo + hi) / 2
        if cdf(mid) > alfa:
            lo = mid
        else:
            hi = mid
    return hi


def fmt(x, dec=4):
    if x is None:
        return SIN_MEDIR
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        return str(x)
    if x != 0 and (abs(x) < 1e-3 or abs(x) >= 1e6):
        return f"{x:.3e}"
    return f"{x:.{dec}f}"


def plano(clave, valor):
    """Una linea de la tarjeta plana. Los textos van entre comillas."""
    if valor is None:
        return f'{clave} = "{SIN_MEDIR}"'
    if isinstance(valor, str):
        return f'{clave} = "{valor}"'
    if isinstance(valor, int):
        return f"{clave} = {valor}"
    # 10 cifras significativas: los umbrales se comparan en f32 en el agente.
    return f"{clave} = {float(valor):.10g}"


# ── lectura ─────────────────────────────────────────────────────────────────

def leer_manifiestos(rutas):
    filas = {}
    conflictos = set()
    for ruta in rutas:
        with open(ruta, encoding="utf-8") as f:
            for n, linea in enumerate(f, 1):
                l = linea.rstrip("\r\n")
                if not l or l.startswith("#") or l.lower().startswith("sha256\t"):
                    continue
                c = l.split("\t")
                if len(c) < 4:
                    raise SystemExit(f"{ruta}:{n}: faltan columnas (sha256, etiqueta, familia, fecha)")
                h, etiqueta, familia, fecha = c[0].strip().lower(), c[1].strip(), c[2].strip(), c[3].strip()
                if len(h) != 64 or any(ch not in "0123456789abcdef" for ch in h):
                    raise SystemExit(f"{ruta}:{n}: sha256 invalido")
                if etiqueta not in ("malicioso", "benigno"):
                    raise SystemExit(f"{ruta}:{n}: etiqueta «{etiqueta}» (malicioso|benigno)")
                if len(fecha) < 10 or fecha[4] != "-" or fecha[7] != "-":
                    raise SystemExit(f"{ruta}:{n}: fecha «{fecha}» (AAAA-MM-DD)")
                y = 1 if etiqueta == "malicioso" else 0
                if h in filas and filas[h][0] != y:
                    conflictos.add(h)
                previa = filas.get(h)
                # Si un hash aparece dos veces, cuenta su PRIMERA vista.
                if previa is None or fecha[:10] < previa[2]:
                    filas[h] = (y, familia or "-", fecha[:10])
    for h in conflictos:
        filas.pop(h, None)
    return filas, len(conflictos)


def leer_vectores(rutas):
    vectores, latencias, sin_datos = {}, [], 0
    huellas, versiones = set(), set()
    for ruta in rutas:
        with open(ruta, encoding="utf-8") as f:
            for n, linea in enumerate(f, 1):
                l = linea.rstrip("\r\n")
                if l.startswith("# aegis-vectorizar"):
                    campos = dict(p.split("=", 1) for p in l.split()[2:] if "=" in p)
                    if int(campos.get("dim", "0")) != DIM:
                        raise SystemExit(f"{ruta}: dim {campos.get('dim')} != {DIM}")
                    huellas.add(campos.get("huella_extractor", ""))
                    versiones.add(campos.get("version_vector", ""))
                    continue
                if not l or l.startswith("#"):
                    continue
                c = l.split("\t")
                if len(c) >= 2 and c[1] == "SINDATOS":
                    sin_datos += 1
                    continue
                if len(c) != 4 or c[1] != "OK":
                    raise SystemExit(f"{ruta}:{n}: linea de vector ilegible")
                v = [float(x) for x in c[3].split(",")]
                if len(v) != DIM:
                    raise SystemExit(f"{ruta}:{n}: {len(v)} componentes, se esperaban {DIM}")
                vectores[c[0].strip().lower()] = v
                latencias.append(int(c[2]))
    if len(huellas) != 1 or "" in huellas:
        raise SystemExit(
            "los vectores no vienen de un unico extractor identificado "
            f"(huellas: {sorted(huellas)}): regeneralos con el mismo aegis-vectorizar"
        )
    return vectores, latencias, sin_datos, huellas.pop(), versiones.pop()


# ── modelo ──────────────────────────────────────────────────────────────────

def irls(np, X, y, lam):
    """Regresion logistica L2 por Newton (IRLS). Determinista."""
    n, d = X.shape
    Xb = np.hstack([np.ones((n, 1)), X])
    beta = np.zeros(d + 1)
    reg = np.full(d + 1, lam)
    reg[0] = 0.0
    for _ in range(100):
        z = np.clip(Xb @ beta, -40, 40)
        p = 1.0 / (1.0 + np.exp(-z))
        w = np.maximum(p * (1 - p), 1e-9)
        g = Xb.T @ (p - y) + reg * beta
        H = (Xb * w[:, None]).T @ Xb + np.diag(reg)
        paso = np.linalg.solve(H, g)
        beta -= paso
        if np.max(np.abs(paso)) < 1e-8:
            break
    return beta


def plegar(np, beta, mu, sigma):
    """Pesos sobre el vector CRUDO: la estandarizacion entra en W y B."""
    w = beta[1:] / sigma
    b = beta[0] - float(np.sum(beta[1:] * mu / sigma))
    return w.astype(np.float32), np.float32(b)


def puntuar(np, X, w, b):
    """Como el agente: f32, no finitos a cero, sigmoide."""
    X = np.nan_to_num(X.astype(np.float32), nan=0.0, posinf=0.0, neginf=0.0)
    z = (X @ w.astype(np.float32) + np.float32(b)).astype(np.float64)
    return 1.0 / (1.0 + np.exp(-np.clip(z, -40, 40)))


def onnx_de(w, b, version, corte):
    import numpy as np
    import onnx
    from onnx import TensorProto, helper, numpy_helper

    grafo = helper.make_graph(
        [
            helper.make_node("MatMul", ["features", "W"], ["logit_raw"], name="matmul"),
            helper.make_node("Add", ["logit_raw", "B"], ["logit"], name="add_bias"),
            helper.make_node("Sigmoid", ["logit"], ["score"], name="sigmoid"),
        ],
        "aegis_static",
        [helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, DIM])],
        [helper.make_tensor_value_info("score", TensorProto.FLOAT, [1, 1])],
        initializer=[
            numpy_helper.from_array(w.reshape(DIM, 1).astype(np.float32), name="W"),
            numpy_helper.from_array(np.array([b], dtype=np.float32), name="B"),
        ],
    )
    m = helper.make_model(grafo, producer_name="aegiscore-entrenar",
                          opset_imports=[helper.make_opsetid("", 13)])
    m.ir_version = 8
    m.doc_string = (
        f"AegisCore static classifier v{version}. Regresion logistica entrenada por "
        f"tools/ml/entrenar.py con corte de fecha {corte}. Ver su tarjeta."
    )
    onnx.checker.check_model(m)
    return m


def pesos_de_onnx(ruta):
    """W y B de un modelo lineal (el de referencia o uno anterior), o None."""
    import onnx
    from onnx import numpy_helper

    try:
        m = onnx.load(ruta)
        ops = [n.op_type for n in m.graph.node]
        if ops != ["MatMul", "Add", "Sigmoid"]:
            return None
        ini = {i.name: numpy_helper.to_array(i) for i in m.graph.initializer}
        return ini["W"].reshape(-1), float(ini["B"].reshape(-1)[0])
    except Exception:  # noqa: BLE001 - un anterior ilegible es «sin medir»
        return None


# ── metricas ────────────────────────────────────────────────────────────────

def auc(np, s, y):
    pos, neg = int(y.sum()), int(len(y) - y.sum())
    if pos == 0 or neg == 0:
        return None
    orden = np.argsort(s, kind="mergesort")
    ss = s[orden]
    rangos = np.empty(len(s))
    i = 0
    while i < len(ss):
        j = i
        while j + 1 < len(ss) and ss[j + 1] == ss[i]:
            j += 1
        rangos[orden[i:j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1
    return float((rangos[y == 1].sum() - pos * (pos + 1) / 2.0) / (pos * neg))


def calibracion(np, s, y, cubos=10):
    filas, ece = [], 0.0
    if len(s) == 0:
        return None, filas
    for i in range(cubos):
        lo, hi = i / cubos, (i + 1) / cubos
        m = (s >= lo) & ((s < hi) if i < cubos - 1 else (s <= hi))
        n = int(m.sum())
        if n == 0:
            filas.append((lo, hi, 0, None, None))
            continue
        pm, fp = float(s[m].mean()), float(y[m].mean())
        ece += n / len(s) * abs(pm - fp)
        filas.append((lo, hi, n, pm, fp))
    return ece, filas


def umbral_para_fpr(np, s_ben, fpr):
    """El umbral mas bajo con fraccion de benignos >= umbral no mayor que fpr.

    Se compara en f32 como el agente, con un margen que absorbe la diferencia
    de redondeo entre este calculo y tract.
    """
    if len(s_ben) == 0:
        return None
    orden = np.sort(s_ben)[::-1]
    k = int(math.floor(fpr * len(orden)))
    if k >= len(orden):
        return float(orden[-1])
    t = float(np.nextafter(np.float32(orden[k]), np.float32(1.0))) + 1e-6
    return min(t, 1.0)


def en_umbral(np, s, y, t):
    pred = s >= t
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    return {
        "tp": tp, "fp": fp, "pos": pos, "neg": neg,
        "recall": tp / pos if pos else None,
        "fpr": fp / neg if neg else None,
        "precision": tp / (tp + fp) if (tp + fp) else None,
        "cota": cota_clopper_pearson(fp, neg),
    }


def psi(np, a, b, bordes):
    if len(a) == 0 or len(b) == 0:
        return None
    ha = np.histogram(a, bins=bordes)[0] / len(a) + 1e-6
    hb = np.histogram(b, bins=bordes)[0] / len(b) + 1e-6
    return float(np.sum((hb - ha) * np.log(hb / ha)))


def evasion_peor_caso(np, X, w, b, t, indices, eps):
    """Fraccion de detecciones (>= t) que una perturbacion de L-infinito eps,
    solo sobre `indices` y dentro de [0,1], podria llevar por debajo de t.

    Exacto para un modelo lineal: en cada componente se elige el extremo del
    intervalo que mas baja el logit. Es una COTA de lo que ese tipo de cambio
    puede conseguir, no una muestra de lo que consigue un empaquetador concreto.
    """
    X = np.nan_to_num(X.astype(np.float64))
    if len(X) == 0:
        return None
    s = puntuar(np, X, w, b)
    det = s >= t
    if det.sum() == 0:
        return None
    idx = np.array(indices)
    sub = X[det][:, idx]
    wi = w.astype(np.float64)[idx]
    lo = np.clip(sub - eps, 0.0, 1.0)
    hi = np.clip(sub + eps, 0.0, 1.0)
    mejor = np.where(wi > 0, lo, hi)
    Xp = X[det].copy()
    Xp[:, idx] = mejor
    sp = puntuar(np, Xp, w, b)
    return float((sp < t).mean())


# ── ordenes ─────────────────────────────────────────────────────────────────

def tarjeta_anterior():
    try:
        return leer_plano(TARJETA)
    except OSError:
        return {}


def orden_referencia(_args):
    texto, md = textos_referencia()
    escribir(TARJETA, texto)
    escribir(TARJETA_MD, md)
    print(f"tarjeta de referencia escrita en {TARJETA}")


def textos_referencia(ruta_modelo=MODELO):
    """La tarjeta del modelo de referencia: solo hechos que se pueden medir sin corpus."""
    h = sha256_fichero(ruta_modelo)
    lineas = [
        "# GENERADO por tools/ml/entrenar.py (orden «referencia»). No editar a mano.",
        "# Lo lee crates/aegis-ml/src/puerta.rs: clase = referencia -> NoConcluyente.",
        "version_tarjeta = 1",
        plano("clase", "referencia"),
        "version_modelo = 1",
        plano("sha256_modelo", h),
        plano("origen", "crates/aegis-ml/tools/build_model.py (pesos fijados a mano)"),
        plano("huella_extractor", None),
        plano("fpr_cota95_bloqueo", None),
        plano("auc_eval", None),
        "",
    ]
    md = (
        "# Tarjeta del modelo estático\n\n"
        "> Generado por `tools/ml/entrenar.py referencia`. No editar a mano.\n\n"
        "| Campo | Valor |\n|---|---|\n"
        "| Clase | **referencia** (pesos fijados a mano, sin entrenar) |\n"
        "| Versión | 1 |\n"
        f"| SHA-256 del modelo | `{h}` |\n"
        "| Corpus, corte por fecha | sin medir |\n"
        "| Precisión, recall, ROC/AUC, calibración | sin medir |\n"
        "| Umbral para el FPR objetivo | sin medir |\n"
        "| Deriva frente a la versión anterior | sin medir |\n"
        "| Evasión básica (relleno, secciones añadidas) | sin medir |\n\n"
        "Mientras la clase sea `referencia`, el agente publica la puntuación como "
        "`NoConcluyente` (crates/aegis-ml/src/puerta.rs).\n"
    )
    return "\n".join(lineas), md


def orden_comprobar(_args):
    t = leer_plano(TARJETA)
    h = sha256_fichero(MODELO)
    if t.get("sha256_modelo") != h:
        raise SystemExit(
            f"la tarjeta habla de {t.get('sha256_modelo')} y el modelo es {h}: "
            "regenera la tarjeta (entrenar o referencia)"
        )
    try:
        with open(TARJETA_MD, encoding="utf-8") as f:
            md = f.read()
    except OSError:
        md = ""
    if f"`{h}`" not in md:
        raise SystemExit(
            f"{TARJETA_MD} no habla del modelo {h}: regenera la tarjeta (entrenar o referencia)"
        )
    print(f"tarjeta y modelo coinciden ({t.get('clase')}, v{t.get('version_modelo')})")


def orden_entrenar(args):
    import numpy as np

    conf = leer_plano(CONFIG)
    fpr_obj = float(conf["fpr_objetivo"])
    fpr_vig = float(conf.get("fpr_vigilar", "1e-3"))
    factor = float(conf.get("factor_contener", "10"))
    min_ben = int(conf.get("min_benignos_evaluacion", "0"))
    min_mal = int(conf.get("min_maliciosos_evaluacion", "0"))
    corte = args.corte or conf.get("fecha_corte")
    lam = float(args.lambda_l2)

    filas, n_conflictos = leer_manifiestos(args.manifiesto)
    vectores, latencias, n_sindatos, huella, version_vector = leer_vectores(args.vectores)
    comunes = sorted(h for h in filas if h in vectores)
    n_sin_vector = len(filas) - len(comunes)
    if not comunes:
        raise SystemExit("ningun hash del manifiesto tiene vector")

    X = np.array([vectores[h] for h in comunes], dtype=np.float64)
    X = np.nan_to_num(X)
    y = np.array([filas[h][0] for h in comunes], dtype=np.float64)
    fam = [filas[h][1] for h in comunes]
    fecha = np.array([filas[h][2] for h in comunes])

    previo = fecha < corte
    ev = ~previo
    # Ajuste y calibracion: los anteriores al corte, ordenados por fecha; el
    # ultimo 20 % (lo mas reciente) calibra los umbrales.
    idx_prev = np.where(previo)[0]
    idx_prev = idx_prev[np.argsort(fecha[idx_prev], kind="mergesort")]
    n_cal = max(1, int(len(idx_prev) * 0.2)) if len(idx_prev) > 1 else 0
    aj, cal = idx_prev[: len(idx_prev) - n_cal], idx_prev[len(idx_prev) - n_cal:]
    if len(aj) == 0 or y[aj].sum() == 0 or (1 - y[aj]).sum() == 0:
        raise SystemExit("el ajuste necesita maliciosos y benignos anteriores al corte")

    mu = X[aj].mean(axis=0)
    sigma = X[aj].std(axis=0)
    sigma[sigma < 1e-9] = 1.0
    beta = irls(np, (X[aj] - mu) / sigma, y[aj], lam)
    w, b = plegar(np, beta, mu, sigma)

    s = puntuar(np, X, w, b)
    s_cal_ben = s[cal][y[cal] == 0]
    t_blo = umbral_para_fpr(np, s_cal_ben, fpr_obj)
    t_vig = umbral_para_fpr(np, s_cal_ben, fpr_vig)
    t_con = umbral_para_fpr(np, s_cal_ben, fpr_obj / factor)
    if t_blo is None:
        raise SystemExit("la calibracion no tiene benignos: no se puede elegir umbral")
    t_vig = min(t_vig, t_blo)
    t_con = max(t_con, t_blo)

    se, ye = s[ev], y[ev]
    m_blo = en_umbral(np, se, ye, t_blo)
    m_vig = en_umbral(np, se, ye, t_vig)
    a_ev = auc(np, se, ye)
    ece, filas_cal = calibracion(np, se, ye)
    roc = []
    s_ev_ben = se[ye == 0]
    for f in (1e-5, 1e-4, 1e-3, 1e-2, 1e-1):
        t = umbral_para_fpr(np, s_ev_ben, f)
        r = en_umbral(np, se, ye, t) if t is not None else None
        roc.append((f, t, r))

    # Deriva frente al modelo anterior (el que hay ahora en el repositorio).
    ant = tarjeta_anterior()
    version = int(ant.get("version_modelo", "1")) + 1
    pa = pesos_de_onnx(MODELO)
    deriva = {"psi": None, "delta_auc": None, "cambio_veredicto": None, "auc_anterior": None}
    if pa is not None and ev.any():
        sa = puntuar(np, X[ev], pa[0], pa[1])
        deriva["psi"] = psi(np, sa, se, np.linspace(0, 1, 11))
        aa = auc(np, sa, ye)
        deriva["auc_anterior"] = aa
        if aa is not None and a_ev is not None:
            deriva["delta_auc"] = a_ev - aa
        t_ant = float(ant["umbral_bloquear"]) if ant.get("umbral_bloquear", SIN_MEDIR) != SIN_MEDIR else 0.995
        deriva["cambio_veredicto"] = float(((sa >= t_ant) != (se >= t_blo)).mean())
    # Deriva de datos: PSI por caracteristica entre ajuste y evaluacion.
    deriva_datos = []
    if ev.any():
        for i in range(DIM):
            a_i, e_i = X[aj][:, i], X[ev][:, i]
            bordes = np.unique(np.quantile(a_i, np.linspace(0, 1, 11)))
            if len(bordes) < 3:
                continue
            # Bordes finitos que cubren las dos muestras (np.histogram no
            # admite infinitos).
            bordes[0] = min(bordes[0], a_i.min(), e_i.min())
            bordes[-1] = max(bordes[-1], a_i.max(), e_i.max())
            p = psi(np, a_i, e_i, bordes)
            if p is not None:
                deriva_datos.append((p, i))
        deriva_datos.sort(reverse=True)

    # Evasion basica (cota de peor caso, sin fabricar binarios).
    Xmal_ev = X[ev][ye == 1]
    evasion = {}
    for nombre, ind in (("relleno", RELLENO), ("secciones", SECCIONES)):
        for eps in PRESUPUESTOS:
            evasion[(nombre, eps)] = evasion_peor_caso(np, Xmal_ev, w, b, t_blo, ind, eps)

    # Recall por familia en la evaluacion.
    fam_ev = [fam[i] for i in np.where(ev)[0]]
    por_familia = {}
    for f, sc, yy in zip(fam_ev, se, ye):
        if yy == 1:
            d = por_familia.setdefault(f, [0, 0])
            d[0] += 1
            d[1] += int(sc >= t_blo)
    familias = sorted(por_familia.items(), key=lambda kv: (-kv[1][0], kv[0]))[:20]

    # Modelo y comprobacion de que el grafo puntua lo mismo que este calculo.
    m = onnx_de(w, b, version, corte)
    import onnx
    from onnx import numpy_helper
    ini = {i.name: numpy_helper.to_array(i) for i in m.graph.initializer}
    s_graf = puntuar(np, X[:64], ini["W"].reshape(-1), float(ini["B"][0]))
    if not np.allclose(s_graf, s[:64], atol=1e-6):
        raise SystemExit("el grafo ONNX no reproduce las puntuaciones del entrenamiento")
    bytes_modelo = m.SerializeToString()
    sha_modelo = hashlib.sha256(bytes_modelo).hexdigest()

    n = {
        "ajuste_mal": int(y[aj].sum()), "ajuste_ben": int((1 - y[aj]).sum()),
        "cal_mal": int(y[cal].sum()), "cal_ben": int((1 - y[cal]).sum()),
        "eval_mal": int(ye.sum()), "eval_ben": int((1 - ye).sum()),
    }
    cumple = (m_blo["cota"] is not None and m_blo["cota"] <= fpr_obj and n["eval_ben"] >= min_ben)
    lat = sorted(latencias)
    p50 = lat[len(lat) // 2] / 1000.0 if lat else None
    p99 = lat[min(len(lat) - 1, int(len(lat) * 0.99))] / 1000.0 if lat else None

    lineas = [
        "# GENERADO por tools/ml/entrenar.py (orden «entrenar»). No editar a mano.",
        "# Lo lee crates/aegis-ml/src/puerta.rs; la decision la toma el agente.",
        "version_tarjeta = 1",
        plano("clase", "entrenado"),
        f"version_modelo = {version}",
        plano("sha256_modelo", sha_modelo),
        plano("huella_extractor", huella),
        plano("version_vector", version_vector),
        f"dim = {DIM}",
        plano("algoritmo", f"regresion logistica L2 (IRLS), lambda={lam}"),
        plano("fecha_corte", corte),
        plano("sha256_manifiestos", sha256_de(args.manifiesto)),
        plano("sha256_vectores", sha256_de(args.vectores)),
        f"n_ajuste_maliciosos = {n['ajuste_mal']}",
        f"n_ajuste_benignos = {n['ajuste_ben']}",
        f"n_calibracion_maliciosos = {n['cal_mal']}",
        f"n_calibracion_benignos = {n['cal_ben']}",
        f"n_eval_maliciosos = {n['eval_mal']}",
        f"n_eval_benignos = {n['eval_ben']}",
        f"n_sin_vector = {n_sin_vector}",
        f"n_sin_datos = {n_sindatos}",
        f"n_conflictos_etiqueta = {n_conflictos}",
        plano("umbral_vigilar", t_vig),
        plano("umbral_bloquear", t_blo),
        plano("umbral_contener", t_con),
        f"fp_eval_bloqueo = {m_blo['fp']}",
        plano("fpr_eval_bloqueo", m_blo["fpr"]),
        plano("fpr_cota95_bloqueo", m_blo["cota"]),
        plano("recall_eval_bloqueo", m_blo["recall"]),
        plano("precision_eval_bloqueo", m_blo["precision"]),
        plano("recall_eval_vigilar", m_vig["recall"]),
        plano("fpr_eval_vigilar", m_vig["fpr"]),
        plano("auc_eval", a_ev),
        plano("ece_eval", ece),
        plano("fpr_objetivo", fpr_obj),
        plano("cumple_objetivo", "si" if cumple else "no"),
        plano("deriva_psi_puntuaciones", deriva["psi"]),
        plano("deriva_delta_auc", deriva["delta_auc"]),
        plano("deriva_cambio_veredicto", deriva["cambio_veredicto"]),
        plano("latencia_vector_p50_ms", p50),
        plano("latencia_vector_p99_ms", p99),
    ]
    for (nombre, eps), v in sorted(evasion.items()):
        lineas.append(plano(f"evasion_{nombre}_{int(eps * 100):03d}", v))
    lineas.append("")
    tarjeta = "\n".join(lineas)

    md = tarjeta_md(version, sha_modelo, huella, corte, lam, n, n_sin_vector, n_sindatos,
                    n_conflictos, fpr_obj, min_ben, min_mal, t_vig, t_blo, t_con, m_blo,
                    m_vig, a_ev, ece, filas_cal, roc, deriva, deriva_datos, evasion,
                    familias, cumple, p50, p99)

    if args.en_seco:
        print(tarjeta)
        return
    with open(MODELO, "wb") as f:
        f.write(bytes_modelo)
    escribir(TARJETA, tarjeta)
    escribir(TARJETA_MD, md)
    print(f"modelo v{version} -> {MODELO} ({len(bytes_modelo)} bytes, sha256 {sha_modelo})")
    print(f"tarjeta -> {TARJETA}; legible -> {TARJETA_MD}")
    print(f"cota95 FPR en bloqueo {fmt(m_blo['cota'])} frente a objetivo {fmt(fpr_obj)}: "
          f"{'CUMPLE' if cumple else 'NO cumple (el agente lo tratara como referencia)'}")


def tarjeta_md(version, sha, huella, corte, lam, n, n_sv, n_sd, n_conf, fpr_obj, min_ben,
               min_mal, t_vig, t_blo, t_con, m_blo, m_vig, a_ev, ece, filas_cal, roc,
               deriva, deriva_datos, evasion, familias, cumple, p50, p99):
    o = []
    o.append("# Tarjeta del modelo estático\n")
    o.append("> Generado por `tools/ml/entrenar.py entrenar`. No editar a mano. "
             "La decisión de usarlo la toma el agente (`crates/aegis-ml/src/puerta.rs`) "
             "con `tools/config/modelo.toml`.\n")
    o.append("## Identidad\n")
    o.append("| Campo | Valor |\n|---|---|")
    o.append(f"| Versión | {version} |")
    o.append(f"| SHA-256 del modelo | `{sha}` |")
    o.append(f"| Huella del extractor | `{huella}` |")
    o.append(f"| Algoritmo | regresión logística L2 (IRLS), λ = {lam} |")
    o.append(f"| Corte por fecha de primera vista | {corte} |\n")
    o.append("## Datos\n")
    o.append("| Conjunto | Maliciosos | Benignos |\n|---|---|---|")
    o.append(f"| Ajuste (anterior al corte) | {n['ajuste_mal']} | {n['ajuste_ben']} |")
    o.append(f"| Calibración de umbrales (último 20 % anterior al corte) | {n['cal_mal']} | {n['cal_ben']} |")
    o.append(f"| Evaluación (posterior al corte) | {n['eval_mal']} | {n['eval_ben']} |\n")
    o.append(f"Sin vector: {n_sv}. Sin datos en el vectorizador: {n_sd}. "
             f"Hashes con etiquetas contradictorias (excluidos): {n_conf}.\n")
    if n["eval_mal"] < min_mal:
        o.append(f"**Aviso:** {n['eval_mal']} maliciosos de evaluación, por debajo del mínimo "
                 f"declarado ({min_mal}); recall y AUC son orientativos.\n")
    o.append("## Punto de operación (umbrales elegidos en calibración, medidos en evaluación)\n")
    o.append("| Umbral | Valor | Recall | FPR observado | FP | Cota 95 % FPR | Precisión |\n|---|---|---|---|---|---|---|")
    o.append(f"| Vigilar | {fmt(t_vig)} | {fmt(m_vig['recall'])} | {fmt(m_vig['fpr'])} | {m_vig['fp']} | {fmt(m_vig['cota'])} | {fmt(m_vig['precision'])} |")
    o.append(f"| Bloquear | {fmt(t_blo)} | {fmt(m_blo['recall'])} | {fmt(m_blo['fpr'])} | {m_blo['fp']} | {fmt(m_blo['cota'])} | {fmt(m_blo['precision'])} |")
    o.append(f"| Contener | {fmt(t_con)} | | | | | |\n")
    o.append(f"FPR objetivo en bloqueo: {fmt(fpr_obj)} con al menos {min_ben} benignos de "
             f"evaluación. **{'Cumple' if cumple else 'No cumple'}**: "
             f"{'el agente lo usará' if cumple else 'el agente lo seguirá tratando como referencia (NoConcluyente)'}.\n")
    o.append("La precisión depende de la proporción de maliciosos del corpus de evaluación, "
             "no de la de un endpoint real.\n")
    o.append("## ROC (evaluación)\n")
    o.append(f"AUC: **{fmt(a_ev)}**\n")
    o.append("| FPR fijado | Umbral | Recall | FP |\n|---|---|---|---|")
    for f, t, r in roc:
        if r is None:
            o.append(f"| {fmt(f)} | sin medir | sin medir | sin medir |")
        else:
            o.append(f"| {fmt(f)} | {fmt(t)} | {fmt(r['recall'])} | {r['fp']} |")
    o.append("")
    o.append("## Calibración (evaluación)\n")
    o.append(f"ECE (10 cubos): **{fmt(ece)}**\n")
    o.append("| Cubo | Muestras | Puntuación media | Fracción maliciosa |\n|---|---|---|---|")
    for lo, hi, cnt, pm, fp in filas_cal:
        o.append(f"| [{lo:.1f}, {hi:.1f}) | {cnt} | {fmt(pm)} | {fmt(fp)} |")
    o.append("")
    o.append("## Deriva frente a la versión anterior\n")
    o.append("| Medida | Valor |\n|---|---|")
    o.append(f"| AUC de la versión anterior sobre esta evaluación | {fmt(deriva['auc_anterior'])} |")
    o.append(f"| Δ AUC | {fmt(deriva['delta_auc'])} |")
    o.append(f"| PSI de las puntuaciones (anterior → nueva) | {fmt(deriva['psi'])} |")
    o.append(f"| Fracción de veredictos de bloqueo que cambian | {fmt(deriva['cambio_veredicto'])} |\n")
    o.append("Deriva de datos (PSI ajuste → evaluación), las 10 características que más se mueven:\n")
    if deriva_datos:
        o.append("| Índice | PSI |\n|---|---|")
        for p, i in deriva_datos[:10]:
            o.append(f"| {i} | {fmt(p)} |")
    else:
        o.append(SIN_MEDIR)
    o.append("")
    o.append("## Evasión básica (cota de peor caso)\n")
    o.append("Fracción de maliciosos de evaluación detectados en bloqueo que una perturbación "
             "acotada (L∞ ≤ ε, dentro de [0, 1]) de las características que mueve un relleno o "
             "una sección añadida podría llevar por debajo del umbral. Para un modelo lineal es "
             "exacta; ningún binario se modifica.\n")
    o.append("| Cambio | ε = 0,10 | ε = 0,25 |\n|---|---|---|")
    for nombre in ("relleno", "secciones"):
        o.append(f"| {nombre} | {fmt(evasion[(nombre, 0.10)])} | {fmt(evasion[(nombre, 0.25)])} |")
    o.append("")
    o.append("## Recall por familia (evaluación, 20 más frecuentes)\n")
    if familias:
        o.append("| Familia | Muestras | Detectadas en bloqueo |\n|---|---|---|")
        for f, (tot, det) in familias:
            o.append(f"| {f} | {tot} | {det} |")
    else:
        o.append(SIN_MEDIR)
    o.append("")
    o.append("## Coste\n")
    o.append(f"Vectorización por fichero (aegis-vectorizar): p50 {fmt(p50)} ms, p99 {fmt(p99)} ms.\n")
    return "\n".join(o)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="orden", required=True)
    e = sub.add_parser("entrenar")
    e.add_argument("--manifiesto", action="append", required=True)
    e.add_argument("--vectores", action="append", required=True)
    e.add_argument("--corte", help="AAAA-MM-DD (por defecto, tools/config/modelo.toml)")
    e.add_argument("--lambda-l2", default="1.0")
    e.add_argument("--en-seco", action="store_true", help="imprime la tarjeta sin escribir nada")
    sub.add_parser("referencia")
    sub.add_parser("comprobar")
    args = ap.parse_args()
    {"entrenar": orden_entrenar, "referencia": orden_referencia,
     "comprobar": orden_comprobar}[args.orden](args)


if __name__ == "__main__":
    main()
