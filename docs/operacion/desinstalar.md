# Desinstalar el agente

Quitar el paquete para el agente de forma **autorizada** (la marca de parada
impide que el watchdog lo relance), deshabilita la unidad y borra lo que el
paquete creó al funcionar: drop-in de memoria, `/run/aegiscore`, cgroups vacíos
de trabajadores, la copia para la vuelta atrás y la cuenta `aegis-trabajador` si
la creó él.

## Antes

1. Recoge el [diagnóstico](diagnostico.md): es lo último que dirá este equipo.
2. Mira la cuarentena. Puede contener muestras que son **evidencia**; quitar
   sin purgar la conserva, purgar la borra:

```sh
sudo aegisctl quarantine list
```

3. Ten el token de desinstalación si el equipo tiene
   `/etc/aegiscore/desinstalacion.sha256` (lo emitió la consola al instalar). Sin él,
   el gestor de paquetes se niega y el agente sigue en marcha.

## Quitar (conserva configuración y cuarentena)

```sh
sudo env AEGIS_TOKEN_DESINSTALAR="$TOKEN" apt-get remove aegis-agent
```

```sh
sudo env AEGIS_TOKEN_DESINSTALAR="$TOKEN" rpm -e aegis-agent
```

## Purgar (borra también `/etc/aegiscore` y `/var/lib/aegiscore`)

```sh
sudo env AEGIS_TOKEN_DESINSTALAR="$TOKEN" apt-get purge aegis-agent
```

rpm no tiene purga; se pide con `AEGIS_PURGAR=1`:

```sh
sudo env AEGIS_TOKEN_DESINSTALAR="$TOKEN" AEGIS_PURGAR=1 rpm -e aegis-agent
```

Purgar borra también el enlace con el plano de control y la identidad del
agente (`/etc/aegiscore/`: `plano-control.toml`, su certificado y su clave): un
equipo retirado no puede seguir hablando con la flota. Revoca además su
certificado en la consola. Quitar sin purgar los conserva.

## Comprobar que no queda nada que actúe

```sh
systemctl status aegis-agent.service
ls /run/aegiscore /etc/systemd/system/aegis-agent.service.d
ls -d /sys/fs/cgroup/aegis-trabajador-*
```

Las tres tienen que decir que no existe. Si queda un cgroup de trabajador con
procesos, es un S2: el agente murió a la fuerza con un análisis en curso.

## Lo que esto protege y lo que no

El token frena la desinstalación por un script, un operador despistado o un
malware que llama al gestor de paquetes. **No frena a root**, que puede borrar el
resumen, parar el servicio o quitar los ficheros a mano: contra eso solo queda
que el agente deja de latir y la consola lo muestra fuera de línea (su último
latido). Una alerta automática por ese silencio no existe todavía.
