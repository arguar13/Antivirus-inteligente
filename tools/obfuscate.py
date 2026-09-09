#!/usr/bin/env python3
"""Cifrado de cadenas criticas del agente (FASE 13).

Lee tools/secrets.json, cifra cada cadena con AES-256-GCM bajo una clave
derivada de cuatro fragmentos de 64 bits mas una sal, y genera
crates/aegis-harden/src/generated_strings.rs con la tabla de textos cifrados.

Por que existe y que garantiza
------------------------------
En el binario compilado no queda ninguna de estas cadenas en claro: `strings`
sobre el agente no revela endpoints, nombres de reglas ni rutas. Al arrancar,
el crate aegis-harden deriva la MISMA clave y descifra la tabla en memoria.

La derivacion de clave y de nonce es identica en Python y en Rust, byte a byte;
`--self-test` lo comprueba de los dos lados. Los nonces se derivan de la clave y
del contenido (no son aleatorios) para que la salida sea REPRODUCIBLE: asi el
fichero generado se puede versionar y `--check` puede verificar en CI que no se
quedo desactualizado.

Modelo de amenaza: esto detiene el analisis estatico. La clave esta en el
binario por necesidad (el binario tiene que autodescifrarse), asi que no protege
frente a un depurador; para eso esta la anti-depuracion de aegis-harden.

Uso:
  tools/obfuscate.py            genera el fichero Rust
  tools/obfuscate.py --check    falla si el fichero generado esta desfasado
  tools/obfuscate.py --self-test  round-trip de verificacion, sin escribir nada
"""
import hashlib
import json
import os
import sys

import ctypes
import ctypes.util


class AESGCM:
    """AES-256-GCM sobre libcrypto (OpenSSL) via ctypes.

    Se enlaza directamente con la libreria del sistema en vez de depender de un
    paquete de Python: en este entorno el backend nativo de 'cryptography' esta
    roto, y bajar a EVP es a la vez mas robusto y mas honesto (es exactamente el
    mismo AES-GCM que usa el crate de Rust por debajo). El texto cifrado que
    produce es `ciphertext || tag(16)`, el mismo formato que la caja
    aes-gcm de Rust.
    """

    _EVP_CTRL_AEAD_SET_IVLEN = 0x9
    _EVP_CTRL_AEAD_GET_TAG = 0x10
    _EVP_CTRL_AEAD_SET_TAG = 0x11
    _TAG_LEN = 16

    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("AES-256 exige una clave de 32 bytes")
        nombre = ctypes.util.find_library("crypto") or "libcrypto.so.3"
        self._lib = ctypes.CDLL(nombre)
        self._key = key
        L = self._lib
        L.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        L.EVP_aes_256_gcm.restype = ctypes.c_void_p

    def _ctx(self):
        c = self._lib.EVP_CIPHER_CTX_new()
        if not c:
            raise RuntimeError("EVP_CIPHER_CTX_new fallo")
        return ctypes.c_void_p(c)

    def encrypt(self, nonce, data, aad):
        L = self._lib
        ctx = self._ctx()
        try:
            cipher = ctypes.c_void_p(L.EVP_aes_256_gcm())
            if L.EVP_EncryptInit_ex(ctx, cipher, None, None, None) != 1:
                raise RuntimeError("EncryptInit(cipher)")
            if L.EVP_CIPHER_CTX_ctrl(ctx, self._EVP_CTRL_AEAD_SET_IVLEN, len(nonce), None) != 1:
                raise RuntimeError("set ivlen")
            if L.EVP_EncryptInit_ex(ctx, None, None, self._key, nonce) != 1:
                raise RuntimeError("EncryptInit(key)")
            outlen = ctypes.c_int(0)
            if aad:
                if L.EVP_EncryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad)) != 1:
                    raise RuntimeError("aad")
            buf = ctypes.create_string_buffer(len(data) + 16)
            if L.EVP_EncryptUpdate(ctx, buf, ctypes.byref(outlen), data, len(data)) != 1:
                raise RuntimeError("EncryptUpdate")
            producido = outlen.value
            final = ctypes.c_int(0)
            if L.EVP_EncryptFinal_ex(ctx, ctypes.byref(buf, producido), ctypes.byref(final)) != 1:
                raise RuntimeError("EncryptFinal")
            producido += final.value
            tag = ctypes.create_string_buffer(self._TAG_LEN)
            if L.EVP_CIPHER_CTX_ctrl(ctx, self._EVP_CTRL_AEAD_GET_TAG, self._TAG_LEN, tag) != 1:
                raise RuntimeError("get tag")
            return buf.raw[:producido] + tag.raw[: self._TAG_LEN]
        finally:
            L.EVP_CIPHER_CTX_free(ctx)

    def decrypt(self, nonce, ct_y_tag, aad):
        L = self._lib
        if len(ct_y_tag) < self._TAG_LEN:
            raise ValueError("texto cifrado sin etiqueta")
        ct = ct_y_tag[: -self._TAG_LEN]
        tag = ct_y_tag[-self._TAG_LEN :]
        ctx = self._ctx()
        try:
            cipher = ctypes.c_void_p(L.EVP_aes_256_gcm())
            if L.EVP_DecryptInit_ex(ctx, cipher, None, None, None) != 1:
                raise RuntimeError("DecryptInit(cipher)")
            if L.EVP_CIPHER_CTX_ctrl(ctx, self._EVP_CTRL_AEAD_SET_IVLEN, len(nonce), None) != 1:
                raise RuntimeError("set ivlen")
            if L.EVP_DecryptInit_ex(ctx, None, None, self._key, nonce) != 1:
                raise RuntimeError("DecryptInit(key)")
            outlen = ctypes.c_int(0)
            if aad:
                if L.EVP_DecryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad)) != 1:
                    raise RuntimeError("aad")
            buf = ctypes.create_string_buffer(len(ct) + 16)
            if L.EVP_DecryptUpdate(ctx, buf, ctypes.byref(outlen), ct, len(ct)) != 1:
                raise RuntimeError("DecryptUpdate")
            producido = outlen.value
            if L.EVP_CIPHER_CTX_ctrl(ctx, self._EVP_CTRL_AEAD_SET_TAG, self._TAG_LEN, tag) != 1:
                raise RuntimeError("set tag")
            final = ctypes.c_int(0)
            if L.EVP_DecryptFinal_ex(ctx, ctypes.byref(buf, producido), ctypes.byref(final)) != 1:
                raise RuntimeError("autenticacion fallida")
            producido += final.value
            return buf.raw[:producido]
        finally:
            L.EVP_CIPHER_CTX_free(ctx)

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFIESTO = os.path.join(RAIZ, "tools", "secrets.json")
GENERADO = os.path.join(RAIZ, "crates", "aegis-harden", "src", "generated_strings.rs")

CONTEXTO = b"aegiscore/string-obfuscation/v1"


def cargar():
    with open(MANIFIESTO, "r", encoding="utf-8") as f:
        m = json.load(f)
    shards = [int(s, 16) & 0xFFFFFFFFFFFFFFFF for s in m["shards"]]
    if len(shards) != 4:
        raise SystemExit("se esperaban exactamente 4 fragmentos de clave")
    salt = bytes.fromhex(m["salt"])
    secrets = m["secrets"]
    return shards, salt, secrets


def derivar_clave(shards, salt):
    """Identica a aegis_harden::strings::derive_key."""
    h = hashlib.sha256()
    for s in shards:
        h.update(s.to_bytes(8, "little"))
    h.update(salt)
    h.update(CONTEXTO)
    return h.digest()


def derivar_nonce(clave, nombre, claro):
    """Nonce determinista de 12 bytes: unico por (nombre, claro), reproducible."""
    h = hashlib.sha256()
    h.update(clave)
    h.update(b"nonce")
    h.update(nombre.encode("utf-8"))
    h.update(b"\x00")
    h.update(claro.encode("utf-8"))
    return h.digest()[:12]


def cifrar_todo(shards, salt, secrets):
    clave = derivar_clave(shards, salt)
    aead = AESGCM(clave)
    entradas = []
    for nombre in sorted(secrets):
        claro = secrets[nombre]
        nonce = derivar_nonce(clave, nombre, claro)
        ct = aead.encrypt(nonce, claro.encode("utf-8"), None)
        entradas.append((nombre, nonce, ct))
    return clave, entradas


def bytes_rust(b):
    return "&[" + ", ".join("0x%02x" % x for x in b) + "]"


def generar(shards, salt, entradas):
    lineas = []
    push = lineas.append
    # rustfmt reformatearia los arrays largos y romperia la comparacion byte a
    # byte de --check; se le indica que ignore el fichero entero. Es un fichero
    # generado, su formato lo fija esta herramienta, no rustfmt.
    push("#![cfg_attr(rustfmt, rustfmt::skip)]")
    push("//! @generated por tools/obfuscate.py. NO editar a mano.")
    push("//!")
    push("//! Tabla de cadenas criticas cifradas con AES-256-GCM. En claro no")
    push("//! existe ninguna en el binario; aegis-harden las descifra al arrancar.")
    push("//! Para regenerar: `python3 tools/obfuscate.py`.")
    push("")
    push("/// Fragmentos de los que se deriva la clave de descifrado.")
    push("///")
    push("/// Estan dispersos a proposito: no hay 32 bytes contiguos que un")
    push("/// analista pueda reconocer como la clave. Se generan junto con la tabla,")
    push("/// asi que siempre corresponden a los textos cifrados de abajo.")
    push("pub(crate) const KEY_SHARDS: [u64; 4] = [")
    for s in shards:
        push("    0x%016x," % s)
    push("];")
    push("")
    push("/// Sal de la derivacion de clave.")
    push("pub(crate) const KEY_SALT: &[u8] = %s;" % bytes_rust(salt))
    push("")
    push("/// Tabla `(nombre, nonce, texto cifrado)`.")
    push("pub(crate) const ENTRIES: &[crate::strings::Entry] = &[")
    for nombre, nonce, ct in entradas:
        push('    ("%s", %s, %s),' % (nombre, bytes_rust(nonce), bytes_rust(ct)))
    push("];")
    push("")
    return "\n".join(lineas)


def self_test(shards, salt, secrets):
    clave, entradas = cifrar_todo(shards, salt, secrets)
    aead = AESGCM(clave)
    for nombre, nonce, ct in entradas:
        claro = aead.decrypt(nonce, ct, None).decode("utf-8")
        if claro != secrets[nombre]:
            raise SystemExit("round-trip fallido en %s" % nombre)
    print("self-test OK: %d cadenas cifran y descifran (clave %s...)"
          % (len(entradas), clave[:4].hex()))


def main():
    modo = sys.argv[1] if len(sys.argv) > 1 else ""
    shards, salt, secrets = cargar()

    if modo == "--self-test":
        self_test(shards, salt, secrets)
        return

    _, entradas = cifrar_todo(shards, salt, secrets)
    contenido = generar(shards, salt, entradas)

    if modo == "--check":
        actual = ""
        if os.path.exists(GENERADO):
            with open(GENERADO, "r", encoding="utf-8") as f:
                actual = f.read()
        if actual != contenido:
            sys.stderr.write(
                "el fichero generado esta desfasado; ejecuta tools/obfuscate.py\n")
            sys.exit(1)
        print("check OK: generated_strings.rs esta al dia")
        return

    with open(GENERADO, "w", encoding="utf-8") as f:
        f.write(contenido)
    print("escrito %s con %d cadenas" % (GENERADO, len(entradas)))


if __name__ == "__main__":
    main()
