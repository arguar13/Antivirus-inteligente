# Instalar el agente

Instala el paquete `.deb` o `.rpm` que publica el pipeline (`tools/empaquetar.sh`,
FASE 3). El paquete pone la unidad de systemd, calcula el techo de memoria de
ESTE equipo, reserva el uid del trabajador confinado, arranca el servicio y
**comprueba que el agente late**; si no late, la instalación falla.

## Antes

1. El equipo está en la matriz de kernels soportada (ver
   [matriz de capacidades](../matriz-capacidades.md#matriz-de-kernels)) y es
   x86_64 o aarch64 con systemd.
2. No convive con otro EDR que use los mismos enganches sin haberlo probado
   (ver el documento de convivencia de la FASE 3).
3. Tienes el paquete y su `SHA256SUMS` del pipeline, y la suma cuadra:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

## Un equipo

Debian y Ubuntu:

```sh
sudo apt-get install ./aegis-agent_0.1.0-1_amd64.deb
```

RHEL, Rocky, Fedora y openSUSE:

```sh
sudo rpm -U aegis-agent-0.1.0-1.x86_64.rpm
```

Si el equipo es lento o está muy cargado, dale más plazo al arranque (por
defecto 120 s) con `AEGIS_PLAZO_SALUD`:

```sh
sudo env AEGIS_PLAZO_SALUD=300 apt-get install ./aegis-agent_0.1.0-1_amd64.deb
```

### Token de desinstalación (recomendado en el piloto)

La consola emite un token aleatorio por equipo o por anillo. En el equipo se
guarda solo su resumen; sin el token, el gestor de paquetes no quita el agente
(no frena a root, que puede borrar el resumen: lo dice el modelo de amenazas).

```sh
sudo install -d -m 0700 /etc/aegiscore
printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1 | sudo tee /etc/aegiscore/desinstalacion.sha256
sudo chmod 0600 /etc/aegiscore/desinstalacion.sha256
```

### Plano de control

Si este agente ya enlaza con el plano de control (H-23), lee
`/etc/aegiscore/plano-control.toml`; sin ese fichero protege en local y lo dice
al arrancar. El formato, la CA, el certificado y la clave (PKCS#8, 0600) los
escribe el rol de Ansible (abajo); a mano:

```toml
[flota]
servidor = "mtls://aegis-flota.empresa.local:8443"
ca = "/etc/aegiscore/pki/flota-ca.crt"
certificado = "/etc/aegiscore/pki/agente.crt"
clave = "/etc/aegiscore/pki/agente.key"
```

y se reinicia el servicio (`sudo systemctl restart aegis-agent.service`). La
matrícula por CSR no existe todavía: la identidad la emite la consola.

## Una flota

El rol `deploy/ansible/roles/aegis_agente` hace lo mismo que arriba en cada
equipo, por tandas (críticos de uno en uno, servidores al 10 %, estaciones al
20 %), y para la tanda al primer fallo:

```sh
cd deploy/ansible
ansible-playbook -i inventario.ini deploy_aegis.yml --ask-vault-pass \
  -e "aegis_agente_sha256=<suma del paquete> aegis_agente_version=0.1.0-1" \
  -e "@secretos/flota.yml"
```

`secretos/flota.yml` (cifrado con `ansible-vault`) lleva
`aegis_agente_servidor_flota` y los PEM de la CA, del certificado y de la clave
del agente; vacío, no se configura plano de control.

## Comprobar

```sh
systemctl is-active aegis-agent.service
sudo aegisctl status
sudo /usr/libexec/aegis/aegis-agent --diagnostico
```

El diagnóstico tiene que decir `estado: sano`, o avisos que entiendes y has
anotado (por ejemplo, la degradación de BPF LSM en una distribución que no lo
activa). Lo que cada aviso significa: [diagnóstico](diagnostico.md).

## Si falla

- El gestor de paquetes dice que el agente no late: el paquete queda marcado
  como fallido y, si era una actualización, ya ha vuelto a la versión anterior.
  Recoge el [diagnóstico](diagnostico.md) y sigue
  [incidentes del propio agente](incidentes-agente.md).
- El agente arranca pero sin telemetría de kernel: el diagnóstico lo dice en
  `kernel.degradaciones` con su remedio
  (`sudo /usr/libexec/aegis/aegis-agent --capacidades` lo detalla).
