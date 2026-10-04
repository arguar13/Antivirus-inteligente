# Revertir a la versión anterior

## Lo que hace solo el paquete

Si una actualización no late en su plazo, el `postinst` del paquete:

1. deja la marca de parada autorizada y para el servicio;
2. restaura los binarios, el `VERSION` y la `HUELLA` anteriores (los guardó el `preinst` en
   `/var/lib/aegiscore/anterior/`), con un `rename` atómico cada uno;
3. arranca y comprueba que el anterior late;
4. escribe la versión rota en `/var/lib/aegiscore/revertido` y falla.

Lo que **no** hace: la base de datos del gestor de paquetes se queda en la
versión nueva marcada como fallida (dpkg: *half-configured*; rpm: `%post`
fallido). Mientras tanto, reconfigurar esa versión se niega en vez de fingir que
funciona.

## Saber si un equipo se revirtió

```sh
cat /var/lib/aegiscore/revertido
sudo /usr/libexec/aegis/aegis-agent --diagnostico
```

Si existe `revertido`, el diagnóstico tiene que enseñar la versión ANTERIOR en
`agente.version_paquete` y el agente latiendo.

## Reconciliar el gestor (a mano)

Instala explícitamente el paquete anterior. Debian y Ubuntu:

```sh
sudo apt-get install --allow-downgrades ./aegis-agent_0.1.0-1_amd64.deb
```

rpm:

```sh
sudo rpm -U --oldpackage aegis-agent-0.1.0-1.x86_64.rpm
```

El `postinst` de esa versión late, borra la copia y la marca, y el gestor queda
coherente.

## Revertir una versión que SÍ latía

Mismo procedimiento: instalar el paquete anterior con `--allow-downgrades` o
`--oldpackage`. Hazlo por anillos en sentido inverso (flota, 5 %, canario) solo
si el problema es de la versión y no de unos pocos equipos.

## Si tampoco la anterior late

El `postinst` lo dice («TAMPOCO la version anterior late»). Es un S1: sigue
[incidentes del propio agente](incidentes-agente.md), caso «no late».
