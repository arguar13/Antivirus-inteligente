# Actualizar el agente

Una versión nueva del agente es un paquete nuevo. El gestor de paquetes la
instala encima; el paquete guarda antes los binarios en uso, reinicia el
servicio y **espera a que el agente nuevo lata**. Si no late en el plazo
(`AEGIS_PLAZO_SALUD`, 120 s por defecto), vuelve solo a los binarios anteriores,
lo deja escrito y la actualización falla. Ver [revertir](revertir.md).

La actualización por el propio agente (`aegis-update`) no se usa: no está
cableada y tiene hallazgos abiertos (H-32).

## Por anillos, nunca a toda la flota a la vez

| Anillo | Quién | Cuándo se pasa al siguiente |
|---|---|---|
| Canario | 1 a 3 equipos del equipo de operación | 24 h con el diagnóstico sano en todos |
| 5 % | Una muestra de cada tipo de equipo del piloto | 48 h sin ningún S1 ni S2 nuevo |
| Flota | El resto del piloto | — |

Con Ansible, el anillo es el grupo del inventario o `--limit`, y las tandas y la
parada al primer fallo las pone el propio playbook.

## Pasos en cada equipo

1. Guarda el diagnóstico de antes, para comparar:

```sh
sudo /usr/libexec/aegis/aegis-agent --diagnostico --json > /root/diagnostico-antes.json
```

2. Verifica la suma del paquete nuevo e instálalo:

```sh
sha256sum --check --ignore-missing SHA256SUMS
sudo apt-get install ./aegis-agent_0.1.1-1_amd64.deb
```

   o, en las distribuciones de rpm:

```sh
sudo rpm -U aegis-agent-0.1.1-1.x86_64.rpm
```

3. Comprueba que corre la versión nueva y que es el binario publicado:

```sh
sudo /usr/libexec/aegis/aegis-agent --diagnostico
```

   En la sección `agente`: `version_paquete` es la nueva, `huella_arbol` es la
   del build publicado y `sha256_binario` coincide con la línea del binario en el
   `SHA256SUMS` de los artefactos herméticos.

4. Compara con el de antes: los mismos motores registrados (o más), sin avisos
   nuevos que no entiendas, y la memoria del cgroup en el mismo orden.

## Si el gestor dice que falló

El host ya está protegido por la versión anterior (lo dice la salida del
gestor: «se restaura la anterior»). Sigue [revertir](revertir.md) para
reconciliar el gestor de paquetes, y abre un incidente con los dos
diagnósticos.
