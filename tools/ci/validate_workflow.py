#!/usr/bin/env python3
"""Valida la ESTRUCTURA del workflow de CI antes de gastar runners en el.

Un pipeline mal definido —un `needs` que apunta a un job inexistente, una accion
de terceros sin anclar, un job sin timeout que deja un runner colgado— no falla
al escribirlo: falla en remoto, minutos despues, y a veces de forma silenciosa.
Estas comprobaciones son baratas y se hacen en el job mas barato del pipeline.

Uso:  tools/ci/validate_workflow.py [ruta_al_workflow ...]
Salida 0 si la estructura es correcta, 1 si hay errores.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("OMITIDO: falta PyYAML; no se puede validar la estructura del workflow")
    sys.exit(0)

# El job agregador de cada workflow: el unico que la proteccion de rama exige.
AGREGADORES = {"gate"}


def validar(ruta: Path) -> tuple[list[str], list[str]]:
    """Devuelve (errores, avisos) de un workflow."""
    errores: list[str] = []
    avisos: list[str] = []
    texto = ruta.read_text()
    doc = yaml.safe_load(texto)
    jobs = doc.get("jobs", {})

    if not jobs:
        return [f"{ruta}: no define ningun job"], []

    # 1. Todo `needs` apunta a un job que existe.
    for nombre, job in jobs.items():
        for dep in job.get("needs") or []:
            if dep not in jobs:
                errores.append(f"{ruta}: el job '{nombre}' depende de '{dep}', que no existe")

    # 2. Toda accion de terceros va anclada a una version.
    for m in re.finditer(r"uses:\s*(\S+)", texto):
        ref = m.group(1)
        if "@" not in ref:
            errores.append(f"{ruta}: accion sin version anclada: {ref}")

    # 3. Permisos minimos: ningun job de CI debe poder escribir en el repo.
    permisos = doc.get("permissions")
    if permisos != {"contents": "read"}:
        avisos.append(f"{ruta}: permisos del workflow = {permisos} (se espera contents: read)")

    # 4. Todo job con timeout: un runner colgado consume cuota hasta el limite
    #    de la plataforma (6 h por defecto).
    for nombre, job in jobs.items():
        if "timeout-minutes" not in job:
            avisos.append(f"{ruta}: el job '{nombre}' no declara timeout-minutes")

    # 5. Si hay job agregador, tiene que cubrir TODOS los demas. Si no, un job
    #    puede fallar sin que la puerta de calidad se entere.
    for agregador in AGREGADORES & set(jobs):
        cubiertos = set(jobs[agregador].get("needs") or [])
        esperados = set(jobs) - {agregador}
        if cubiertos != esperados:
            faltan = sorted(esperados - cubiertos)
            errores.append(
                f"{ruta}: el job agregador '{agregador}' no cubre: {faltan}"
            )

    # 6. Concurrencia: sin ella, una racha de pushes deja ejecuciones obsoletas
    #    consumiendo runners.
    if not doc.get("concurrency"):
        avisos.append(f"{ruta}: sin bloque 'concurrency'")

    return errores, avisos


def main() -> int:
    rutas = [Path(a) for a in sys.argv[1:]] or sorted(
        Path(".github/workflows").glob("*.yml")
    )
    errores: list[str] = []
    avisos: list[str] = []
    for ruta in rutas:
        if not ruta.exists():
            errores.append(f"{ruta}: no existe")
            continue
        e, a = validar(ruta)
        errores += e
        avisos += a

    for a in avisos:
        print(f"    AVISO: {a}")
    for e in errores:
        print(f"    ERROR: {e}")
    print(f"    {len(rutas)} workflow(s) validados")
    return 1 if errores else 0


if __name__ == "__main__":
    sys.exit(main())
