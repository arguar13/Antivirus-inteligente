#!/usr/bin/env python3
"""Simulacion de Red Team defensiva de AegisCore (FASE 17).

Somete a las defensas del producto a ataques REALES y comprueba que responden.
No son mocks: monta memoria RWX de verdad, manipula senuelos de verdad en disco,
y parchea bytecode de verdad. Cada escenario valida una fase concreta.

Escenarios:
  1. Auto-defensa del binario     -> el agente compilado no revela sus cadenas
                                      criticas ni sus simbolos (FASE 13).
  2. Inyeccion de shellcode anon. -> un proceso con memoria RWX anonima se
                                      detecta como evasion (FASE 10).
  3. Manipulacion de senuelo      -> modificar un fichero senuelo de ransomware
                                      se detecta al instante (FASE 9).
  4. Integridad del bytecode eBPF -> un .bpf.o parcheado se rechaza (FASE 14).

Nota sobre SIGKILL: un SIGKILL de root no se puede impedir desde el proceso
victima; la resiliencia ante terminacion la aporta el Watchdog (FASE 22), que
ampliara este script con el escenario de reinicio. Aqui la "auto-defensa" que se
valida es la anti-ingenieria-inversa, que si es responsabilidad del propio
binario.

Devuelve codigo 0 si todos los escenarios pasan, 1 si alguno falla.
"""
import os
import subprocess
import sys
import tempfile
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

VERDE = "\033[32m"
ROJO = "\033[31m"
GRIS = "\033[90m"
FIN = "\033[0m"

fallos = 0


def titulo(n, texto):
    print(f"{GRIS}==>{FIN} Escenario {n}: {texto}")


def ok(msg):
    print(f"    {VERDE}DEFENDIDO{FIN}: {msg}")


def fallo(msg):
    global fallos
    print(f"    {ROJO}BRECHA{FIN}: {msg}")
    fallos += 1


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=RAIZ, capture_output=True, text=True, **kw)


def ejemplo(paquete, nombre):
    """Ruta al binario de ejemplo, compilandolo si no existe."""
    ruta = os.path.join(RAIZ, "target", "debug", "examples", nombre)
    if not os.path.exists(ruta):
        run(["cargo", "build", "-q", "-p", paquete, "--example", nombre])
    return ruta


# ---------------------------------------------------------------------------
# 1. Auto-defensa del binario compilado (FASE 13)
# ---------------------------------------------------------------------------

def escenario_autodefensa():
    titulo(1, "auto-defensa del binario: cadenas cifradas y simbolos eliminados")
    # Se prefiere el binario de release (endurecido); si no esta, el de debug.
    candidatos = [
        os.path.join(RAIZ, "target", "release", "aegis-agent"),
        os.path.join(RAIZ, "target", "debug", "aegis-agent"),
    ]
    binario = next((c for c in candidatos if os.path.exists(c)), None)
    if binario is None:
        run(["cargo", "build", "-q", "-p", "aegis-agent"])
        binario = candidatos[1]
    if not os.path.exists(binario):
        fallo("no se pudo obtener el binario del agente")
        return

    with open(binario, "rb") as f:
        crudo = f.read()

    secretos = [b"aegiscore.internal", b"AEGISCORE-SELF-DEFENSE", b"/run/aegiscore/agent.sock"]
    filtrados = [s.decode() for s in secretos if s in crudo]
    if filtrados:
        fallo(f"el binario revela cadenas criticas en claro: {filtrados}")
    else:
        ok("ninguna cadena critica aparece en claro en el binario")

    # Comprobacion de stripping solo tiene sentido en release.
    if "release" in binario:
        r = run(["file", binario])
        if "not stripped" in r.stdout:
            fallo("el binario de release conserva la tabla de simbolos")
        else:
            ok("el binario de release esta stripped (sin simbolos)")


# ---------------------------------------------------------------------------
# 2. Inyeccion de shellcode en memoria RWX anonima (FASE 10)
# ---------------------------------------------------------------------------

VICTIMA_C = r"""
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    /* Un cargador reflectivo mapea memoria RWX y salta a ella. Se reproduce esa
       primitiva: RWX anonimo del tamano de una carga util. */
    void *p = mmap(NULL, 65536, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); return 2; }
    /* Se escribe algo, para que sea de verdad escribible y ejecutable. */
    memset(p, 0x90, 4096);
    printf("READY\n");
    fflush(stdout);
    sleep(30);
    return 0;
}
"""


def escenario_inyeccion():
    titulo(2, "inyeccion de shellcode: memoria RWX anonima en un proceso hijo")
    scan = ejemplo("aegis-evasion", "scan_pid")
    if not os.path.exists(scan):
        fallo("no se pudo compilar el escaner de evasion")
        return

    with tempfile.TemporaryDirectory() as d:
        fuente = os.path.join(d, "victima.c")
        binv = os.path.join(d, "victima")
        with open(fuente, "w") as f:
            f.write(VICTIMA_C)
        comp = run(["cc", "-O0", "-o", binv, fuente])
        if comp.returncode != 0:
            fallo(f"no se pudo compilar la victima: {comp.stderr.strip()}")
            return

        victima = subprocess.Popen([binv], stdout=subprocess.PIPE, text=True)
        try:
            # Espera a que la victima mapee la memoria y avise.
            linea = victima.stdout.readline().strip()
            if linea != "READY":
                fallo("la victima no llego a mapear la memoria RWX")
                return
            time.sleep(0.2)
            r = run([scan, str(victima.pid), "40"])
            print(f"    {GRIS}{r.stdout.strip()}{FIN}")
            if r.returncode == 3:
                ok("la memoria RWX anonima inyectada se detecto como evasion")
            elif r.returncode == 0:
                fallo("la inyeccion RWX paso desapercibida para el detector")
            else:
                fallo(f"el escaner fallo (codigo {r.returncode}): {r.stderr.strip()}")
        finally:
            victima.terminate()
            try:
                victima.wait(timeout=5)
            except subprocess.TimeoutExpired:
                victima.kill()


# ---------------------------------------------------------------------------
# 3. Manipulacion de un senuelo de ransomware (FASE 9)
# ---------------------------------------------------------------------------

def escenario_senuelo():
    titulo(3, "ransomware: manipulacion de un fichero senuelo")
    probe = ejemplo("aegis-ransom", "honeypot_probe")
    if not os.path.exists(probe):
        fallo("no se pudo compilar la sonda de senuelos")
        return

    with tempfile.TemporaryDirectory() as d:
        # El probe despliega, conserva las sumas originales en memoria y espera.
        vigilante = subprocess.Popen(
            [probe, "watch", d],
            cwd=RAIZ,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        canarios = []
        for linea in vigilante.stdout:
            linea = linea.strip()
            if linea == "READY":
                break
            if linea:
                canarios.append(linea)
        if not canarios:
            fallo("no se desplego ningun senuelo")
            vigilante.kill()
            return

        # Un cifrador reescribe un senuelo con datos de alta entropia.
        victima = canarios[0]
        with open(victima, "wb") as f:
            f.write(os.urandom(8192))

        # Se avisa al vigilante de que ya actuo el atacante.
        vigilante.stdin.write("go\n")
        vigilante.stdin.flush()
        vigilante.stdin.close()
        salida = vigilante.stdout.read()
        vigilante.wait(timeout=10)
        print(f"    {GRIS}{salida.strip()}{FIN}")
        if vigilante.returncode == 3 and "MANIPULADO" in salida:
            ok("la manipulacion del senuelo se detecto")
        else:
            fallo("modificar un senuelo no se detecto")


# ---------------------------------------------------------------------------
# 4. Integridad del bytecode eBPF (FASE 14)
# ---------------------------------------------------------------------------

def escenario_bytecode():
    titulo(4, "integridad del bytecode: un .bpf.o parcheado se rechaza")
    obj = os.path.join(RAIZ, "drivers", "linux", "aegis-bpf", "out", "aegis_probes.bpf.o")
    manifiesto = os.path.join(RAIZ, "drivers", "linux", "aegis-bpf", "out", "bytecode.manifest")
    tool = os.path.join(RAIZ, "drivers", "linux", "aegis-bpf", "tools", "sign_bytecode.py")

    if not os.path.exists(obj):
        run(["make", "-C", os.path.join(RAIZ, "drivers", "linux", "aegis-bpf"), "build", "sign"])
    if not os.path.exists(obj) or not os.path.exists(manifiesto):
        fallo("no hay bytecode compilado ni manifiesto para probar")
        return

    with open(obj, "rb") as f:
        datos = bytearray(f.read())
    # Se parchea un byte del medio del objeto, como haria quien sustituye la
    # telemetria por la suya.
    datos[len(datos) // 2] ^= 0x01

    with tempfile.TemporaryDirectory() as d:
        # El nombre tiene que coincidir con la entrada del manifiesto.
        tampered = os.path.join(d, "aegis_probes.bpf.o")
        with open(tampered, "wb") as f:
            f.write(datos)
        r = run(["python3", tool, "check", tampered])
        if r.returncode != 0 and "no coincide" in (r.stdout + r.stderr):
            ok("el bytecode parcheado se rechazo por firma HMAC invalida")
        else:
            fallo(f"un .bpf.o parcheado paso la verificacion (codigo {r.returncode})")


def main():
    print(f"{GRIS}Simulacion de Red Team defensiva de AegisCore{FIN}\n")
    escenario_autodefensa()
    escenario_inyeccion()
    escenario_senuelo()
    escenario_bytecode()
    print()
    if fallos == 0:
        print(f"{VERDE}Todas las defensas resistieron ({4} escenarios).{FIN}")
        return 0
    print(f"{ROJO}{fallos} escenario(s) encontraron una brecha.{FIN}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
