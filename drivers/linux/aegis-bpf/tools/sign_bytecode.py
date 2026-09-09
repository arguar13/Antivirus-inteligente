#!/usr/bin/env python3
"""Firma HMAC-SHA256 del bytecode eBPF compilado (FASE 14).

Calcula el HMAC-SHA256 de cada fichero objeto .bpf.o con una clave y escribe un
manifiesto que el agente verifica ANTES de cargar el programa en el kernel. Si
alguien sustituye un .bpf.o en disco entre la compilacion y la carga, el HMAC no
coincide y el agente se niega a cargarlo.

Por que HMAC y no sha256sum: un hash a secas lo recalcula el atacante tras
cambiar el objeto. El HMAC exige una clave que el atacante no tiene.

La clave sale de AEGIS_BPF_HMAC_KEY (hex) si esta definida; si no, de una clave
de desarrollo fija para que `make ci` sea reproducible. En produccion la clave
es un secreto de compilacion.

Usa libcrypto (OpenSSL) via ctypes: el mismo HMAC-SHA256 que la caja `hmac` de
Rust, y sin depender de paquetes de Python que puedan faltar.

Uso:
  sign_bytecode.py sign   OBJ [OBJ...]   escribe out/bytecode.manifest
  sign_bytecode.py check  OBJ [OBJ...]   verifica los objetos contra el manifiesto
"""
import hashlib
import hmac as _pyhmac
import os
import sys

RAIZ_BPF = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFIESTO = os.path.join(RAIZ_BPF, "out", "bytecode.manifest")

# Clave de desarrollo. En produccion se pasa por AEGIS_BPF_HMAC_KEY.
CLAVE_DEV = bytes.fromhex(
    "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
)


def clave():
    env = os.environ.get("AEGIS_BPF_HMAC_KEY")
    if env:
        return bytes.fromhex(env)
    return CLAVE_DEV


def hmac_sha256(key, data):
    """HMAC-SHA256 estandar de la biblioteca de Python.

    Es exactamente el mismo algoritmo que la caja `hmac` de Rust (misma
    construccion de HMAC sobre SHA-256), asi que los dos lados producen el
    mismo digest byte a byte. No hace falta bajar a OpenSSL para esto.
    """
    return _pyhmac.new(key, data, hashlib.sha256).digest()


def nombre_objeto(ruta):
    return os.path.basename(ruta)


def firmar(objetos):
    k = clave()
    lineas = ["# @generated - firmas HMAC-SHA256 del bytecode eBPF de AegisCore"]
    for ruta in sorted(objetos, key=nombre_objeto):
        with open(ruta, "rb") as f:
            datos = f.read()
        h = hmac_sha256(k, datos)
        lineas.append("%s  %s" % (nombre_objeto(ruta), h.hex()))
    os.makedirs(os.path.dirname(MANIFIESTO), exist_ok=True)
    with open(MANIFIESTO, "w", encoding="utf-8") as f:
        f.write("\n".join(lineas) + "\n")
    print("firmado %d objeto(s) en %s" % (len(objetos), MANIFIESTO))


def cargar_manifiesto():
    m = {}
    with open(MANIFIESTO, "r", encoding="utf-8") as f:
        for linea in f:
            l = linea.strip()
            if not l or l.startswith("#"):
                continue
            nombre, hexd = l.split()
            m[nombre] = bytes.fromhex(hexd)
    return m


def verificar(objetos):
    if not os.path.exists(MANIFIESTO):
        sys.stderr.write("no hay manifiesto; ejecuta 'sign' primero\n")
        return 1
    m = cargar_manifiesto()
    k = clave()
    fallos = 0
    for ruta in objetos:
        nombre = nombre_objeto(ruta)
        if nombre not in m:
            sys.stderr.write("%s no esta firmado en el manifiesto\n" % nombre)
            fallos += 1
            continue
        with open(ruta, "rb") as f:
            datos = f.read()
        calc = hmac_sha256(k, datos)
        if not _pyhmac.compare_digest(calc, m[nombre]):
            sys.stderr.write("%s: HMAC no coincide (bytecode manipulado)\n" % nombre)
            fallos += 1
        else:
            print("%s: integridad verificada" % nombre)
    return 1 if fallos else 0


def main():
    if len(sys.argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    modo = sys.argv[1]
    objetos = sys.argv[2:]
    if modo == "sign":
        firmar(objetos)
        return 0
    if modo == "check":
        return verificar(objetos)
    sys.stderr.write("modo desconocido: %s\n" % modo)
    return 2


if __name__ == "__main__":
    sys.exit(main())
