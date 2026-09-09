# Módulo 29 — Gestión de flota sobre gRPC/mTLS

> Componente: `crates/aegis-fleet`.

Un antivirus de una máquina se administra a mano. Una flota de miles, no:
necesita un **plano de control** que sepa qué endpoints están vivos, les entregue
política y recoja sus eventos. Ese canal, si se hace mal, es la mayor superficie
de ataque del producto: quien lo controle, controla todos los endpoints.

Este módulo lo hace bien, con dos garantías duras.

---

## 29.1 mTLS mutuo: los dos extremos se autentican

En un TLS normal solo el servidor prueba su identidad. Aquí también el agente:
el plano de control **exige** que el certificado de cliente esté firmado por la
CA de la flota. Un endpoint que solo alcanza el puerto —sin un certificado de la
flota— no pasa del handshake. No hay un «registro abierto» que envenenar.

Y al revés: el agente valida el certificado del servidor contra la misma CA, de
modo que no habla con un plano de control suplantado. La identidad autenticada
—el **CN** del certificado— se extrae del propio certificado, no de lo que el
agente diga en el cuerpo del mensaje: un agente con certificado válido para
`agente-A` no puede hacerse pasar por `agente-B`, porque el plano compara el id
declarado con el CN que probó el certificado.

---

## 29.2 Certificados de rotación automática, con la clave siempre en memoria

Un certificado de vida larga en el disco de un endpoint es una llave maestra: si
se filtra, sirve hasta que alguien lo revoca a mano. La flota emite certificados
de **vida corta** y los renueva sola antes de que caduquen. Una clave robada de
la memoria de un endpoint deja de valer en minutos, y no hay nada que revocar a
mano.

La clave del agente **nunca toca el disco**:

- Se genera en memoria (`rcgen`) en cada emisión.
- Se entrega a `rustls` como bytes en memoria.
- Al rotar, la identidad vieja se suelta y su clave se **borra** (`zeroize`, con
  escrituras volátiles que el compilador no puede eliminar).

En el despliegue de producción sobre varios nodos, la renovación va por **CSR**:
el endpoint genera su par de claves y una petición de firma que contiene solo la
clave **pública**; la CA firma y devuelve el certificado. **La CA nunca ve la
clave privada**, y esta no sale jamás del endpoint. Hay una prueba de que una
rotación completa no escribe ni un fichero.

---

## 29.3 El servicio: gRPC unario sobre el canal mTLS

El modelo es el de gRPC: llamadas unarias con petición y respuesta **protobuf**.
Los métodos del servicio `AegisFleet`:

| Método | Para qué |
|---|---|
| `Enrolar` | el agente entra en la flota; el plano valida su identidad |
| `Latir` | pulso periódico con RSS, amenazas activas y versión de política |
| `ReportarEvento` | el agente notifica un evento de seguridad y recibe un id de incidente |

Los mensajes se codifican en el **formato de cable real de protobuf** —varints y
campos delimitados por longitud— implementado a mano, sin `protoc`: es
interoperable byte a byte con cualquier cliente protobuf, y lo prueban las
vueltas de ida y vuelta.

**Sobre el transporte.** El enmarcado es el prefijo de longitud de gRPC (una
bandera de compresión y cuatro bytes de longitud) sobre el flujo mTLS, precedido
de un byte de enrutado que sobre HTTP/2 llevarían las cabeceras `:path` y
`grpc-status`. No son tramas HTTP/2: el resto de AegisCore es **síncrono** a
propósito —por el presupuesto de memoria (< 45 MB) y el control estricto de la
concurrencia— y el único HTTP/2 maduro de Rust exige un runtime asíncrono. Lo
que importa para la seguridad —autenticación mutua, protobuf real, certificados
rotativos, clave sin disco— es idéntico; lo que cambia es que el mensaje viaja
en el enmarcado anterior en vez de en tramas HTTP/2.

---

## 29.4 Por qué esto es real, y cómo se prueba

Nada está simulado: CA real, certificados X.509 reales, handshake mTLS real,
protobuf de verdad sobre el cable. Sobre el bucle de red local se monta un plano
de control y agentes que se enrolan, laten y reportan.

- **La autenticación mutua** se prueba con tres casos: un agente legítimo se
  enrola y autentica al servidor; un impostor con certificado de **otra CA** es
  rechazado en el handshake; un agente con certificado válido que **declara otra
  identidad** es rechazado por el plano.
- **La rotación** se prueba en su lógica de decisión (cuándo renovar según el
  margen de vida) y en el efecto real: rotar produce un certificado nuevo con
  clave nueva, y el CN estable se conserva.
- **La clave sin disco** se prueba directamente: diez rotaciones y un ciclo de
  enrolamiento completo no crean ni un fichero.
- **El flujo CSR** se prueba de extremo a extremo: el endpoint genera la petición
  (la clave se queda), la CA la firma sin verla, y la identidad ensamblada
  autentica.

El escenario 14 de la simulación de Red Team ejecuta el control de acceso de la
flota: el impostor no entra, el legítimo sí.
