# ETW Threat Intelligence: dónde se consume y por qué no en el driver

`Microsoft-Windows-Threat-Intelligence` (ETW-Ti) es la única fuente **soportada**
de eventos de `VirtualAllocEx`, `WriteProcessMemory`, `NtQueueApcThread` y
`SetThreadContext` entre procesos. Sin ella, obtener esa telemetría exige
parchear el kernel, lo que rompe PatchGuard y no es una opción en un producto
que se despliega en máquinas de clientes.

## El detalle que se suele contar mal

ETW-Ti se consume desde **modo usuario**, no desde el driver. Windows no ofrece
una API soportada para consumir ETW desde el kernel; lo que hay en el kernel es
la parte *proveedora*. Un producto que afirmara que su driver «se suscribe a
ETW-Ti» estaría describiendo algo que no existe.

El consumidor es el **servicio del agente**, y solo puede suscribirse si corre
como `SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT` (PPL-Antimalware). Eso encadena
tres requisitos que hay que cumplir en orden:

```
driver ELAM firmado con certificado ELAM de Microsoft
        │   (sección de recursos con MSElamCertInfoID)
        ▼
servicio con PPL-Antimalware
        ▼
suscripción a Microsoft-Windows-Threat-Intelligence
```

Sin ELAM no hay PPL; sin PPL no hay ETW-Ti. Ver el [módulo 01](../../../docs/01-kernel-ring0.md),
secciones 1.3 y 1.4.

## Qué se clasifica y dónde

La clasificación de los eventos —qué es inyección y qué es un compilador JIT
haciendo su trabajo— está en `../aegis/aegis_politica.c`, que es C portable y se
ejercita con gcc y con clang en cada `make ci`
(`tools/verificar-windows.sh`).

Está ahí, y no en el consumidor, por el mismo motivo que la política de acceso:
es la parte que puede estar mal de forma peligrosa, y es la única que se puede
probar sin un Windows delante.

## La regla de oro de la clasificación

**La operación sobre uno mismo no es inyección.** Un compilador JIT reserva y
hace ejecutable su propia memoria constantemente; un EDR que avisara de eso
enterraría al analista en ruido hasta que dejara de mirar — y entonces la
detección de verdad tampoco se vería. Lo que delata la inyección es que el
destino sea **otro** proceso.
