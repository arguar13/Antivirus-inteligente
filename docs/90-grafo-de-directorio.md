# Módulo 90 — AegisDirectory: el grafo completo del directorio (FASE 95)

> Componentes: `server/crates/aegis-itdr/src/directorio/`,
> `server/crates/aegis-predict/src/directorio.rs`, `tools/verificar-directorio.sh`.

## 90.1 La pregunta

El movimiento lateral y la escalada en Active Directory casi nunca usan el camino
que el administrador cree que existe. Un usuario raso al que alguien, hace años, le
dio `WriteDacl` sobre el grupo «Domain Admins» puede hacerse administrador del
dominio **sin pertenecer a ningún grupo privilegiado y sin que ningún evento lo
delate**. La pregunta de esta fase es la de un defensor:

> Dado cómo está montado mi directorio, **¿qué relaciones débiles abren un camino a
> mis joyas de la corona, y cómo las cierro?**

Es la misma pregunta que responde BloodHound. La diferencia es qué se hace con la
respuesta: aquí el directorio se lee **en solo lectura**, se modelan las relaciones
y las configuraciones débiles, y cada hallazgo sale con su **remediación**. La
salida es el camino que hay que cortar, pasado por los cinco frenos de la FASE 69.

## 90.2 Cobertura: relación por relación frente a BloodHound

Antes de esta fase, el grafo de identidad del ITDR (FASE 58) era mínimo: nodos por
nombre, cinco relaciones, una arista por par, sin tiempo. Esta es la tabla que
`aegis-itdr::directorio` cierra, tomada del conjunto de aristas público de
BloodHound/Adalanche:

| Relación de BloodHound | ITDR antes | AegisDirectory |
|---|---|---|
| MemberOf (anidado) | parcial, sin ciclos | **sí**, anidado y con ciclos resueltos |
| Owns / GenericAll / GenericWrite / WriteDacl / WriteOwner | no | **sí**, del `ntSecurityDescriptor` byte a byte |
| AddMember / ForceChangePassword / AllExtendedRights | no | **sí**, por el GUID del derecho |
| DCSync (`DS-Replication-Get-Changes-All`) | no | **sí** (`ReplicaDirectorio`) |
| Delegación sin restricciones / restringida / RBCD | no | **sí**, las tres |
| AdminTo / CanRDP / ExecuteDCOM / CanPSRemote | no | **sí** |
| HasSession / HasCachedCredential | no | **sí, con ventana de caducidad** |
| GpLink / Contains (herencia, `enforced`, bloqueo) | no | **sí** |
| Trust (dirección, tipo, transitividad) | no | **sí** |
| Certificados (familia ESC) | no | **sí** (`certificados`) |
| **Alcance por red** | **no** | **sí — BloodHound no lo tiene** |

La comparativa a escala de cien mil cuentas contra el colector de BloodHound sobre
un dominio real es un **muro** (§90.8): no hay dominio de producción en la máquina
de integración. Se mide con el directorio sintético más grande que cabe
(`tests/escala_directorio.rs`: 10 002 principales, la ACL peligrosa plantada se
encuentra entre el ruido, y la auditoría es determinista).

## 90.3 Las dos cosas que BloodHound no puede dar

**La caducidad de la sesión está en la arista.** BloodHound modela «alice tiene una
sesión en PC01» como un hecho sin tiempo. Pero una sesión caduca. Un camino que
depende de una sesión que expiró hace dos meses **es un camino que ya no existe**, y
actuar sobre él es actuar sobre información vieja. Aquí cada arista de sesión o
credencial lleva su `Ventana`, y el puente a la predicción (§90.7) proyecta el grafo
**en un instante**: la misma consulta, evaluada antes y después de caducar una
sesión, da un camino distinto. Hay una prueba que lo demuestra
(`aegis-predict::directorio::la_caducidad_de_la_sesion_cambia_el_camino`).

**El alcance por red.** El endpoint es nuestro: sabemos qué máquina alcanza de
verdad a cuál, según la segmentación observada. BloodHound solo ve el directorio, así
que un camino que cruza un firewall que en realidad está cerrado se le cuela.
`AlcanzaPorRed` y `AlcanzaPorRedSegmentada` son aristas que solo un producto con los
dos lados —directorio y endpoint— bajo el mismo modelo de entidad puede tener.

## 90.4 El descriptor de seguridad, byte a byte

Las escaladas silenciosas no están en los grupos: están en las **listas de control
de acceso**. Encontrarlas exige leer el `ntSecurityDescriptor` de cada objeto, que
es una estructura binaria del formato **MS-DTYP** de Microsoft (un
`SECURITY_DESCRIPTOR` auto-relativo con su `ACL` y sus `ACE`). El parser
(`descriptor.rs`) recibe **bytes que vienen del directorio** —entrada que un
atacante con acceso podría manipular— y se comporta como el resto de los que comen
entrada hostil en el producto: comprueba cada longitud antes de leerla, no entra en
pánico ante nada, y ante una estructura que no cuadra **devuelve su motivo en vez de
adivinar**. Se prueba contra descriptores construidos byte a byte según la
especificación, igual que el núcleo Kerberos se prueba con tickets DER reales. De la
máscara de acceso y el GUID del derecho salen las aristas: `WRITE_DAC` →
`EscrituraDacl`, el GUID `00299570-…` → `ForzarCambioClave`, el GUID `1131f6ad-…` →
`ReplicaDirectorio` (DCSync), etc.

## 90.5 Grupos anidados, con ciclos

La pertenencia se resuelve de forma **anidada** (alice → Operadores → Domain Admins)
y **soporta ciclos**: en un directorio real, A puede ser miembro de B y B de A, y sin
un conjunto de visitados la resolución sería un bucle infinito. `miembros_efectivos`
recorre las aristas `MemberOf` entrantes con un conjunto de visitados; el ciclo se
recorre una vez, no infinitas.

## 90.6 El grafo no sale del plano de control

El grafo completo —quién puede sobre quién en toda la organización— es exactamente
el mapa que un atacante querría antes de elegir por dónde escalar. Es la misma clase
de dato que el inventario de la FASE 94, y se protege igual: el serializador es
**privado**, y la única salida (`salida::exportar`) pasa por el **juez de difusión**
—el único estrangulamiento del producto— con el grafo marcado `TLP:AMBER+STRICT`
(«solo mi organización»). El llamante no elige el marcado. La prueba de autoataque lo
comprueba canal a canal; armar el documento sin pasar por el juez **no compila**.

## 90.7 El puente a la predicción, y los cinco frenos

El grafo enriquecido alimenta `aegis-predict` (FASE 69) a través de un puente de
**producción** —hasta ahora solo lo hacía una prueba—. El puente proyecta cada
relación del directorio sobre el vocabulario de ataque de la predicción (pertenencia,
control por ACL → impersonación, DCSync/LAPS/gMSA → control de credenciales, sesión
→ control de credenciales invertida, ejecución → autenticación, alcance → salto de
red), evaluando solo las aristas vigentes en el instante. Sobre el grafo resultante,
los cinco frenos de la contención siguen gobernando lo que se puede tocar: un activo
protegido no se toca jamás, por encima del tope de radio se escala a una persona, la
evidencia recién fabricada no mueve nada, un camino improbable tampoco, y se corta la
identidad antes que aislar la máquina. La invariante 8 lo comprueba, y hay pruebas
del puente que lo ejercen sobre el grafo enriquecido.

## 90.8 Honestidad de validación

| Pieza | Verificable aquí | Cómo |
|---|---|---|
| Parseo del descriptor de seguridad | **sí** | byte a byte, contra estructuras MS-DTYP reales, y barrido de bytes hostiles sin pánico |
| Pertenencia anidada y ciclos | **sí** | valor exacto a mano, y un ciclo que termina |
| ACL peligrosa raso→privilegiado | **sí** | y el caso decisivo: privilegiado→privilegiado **no** es escalada |
| Delegación (sin restricciones / restringida / RBCD) | **sí** | la RBCD sale del descriptor del atributo |
| Plantillas de certificado (ESC) | **sí** | ESC1/ESC2, y la prueba de que la remediación cierra el hallazgo |
| La caducidad de sesión cambia el camino | **sí** | mismo grafo, dos instantes, dos caminos |
| Los cinco frenos sobre el grafo enriquecido | **sí** | invariante 8 y pruebas del puente |
| El grafo no sale del plano de control | **sí** | autoataque canal a canal + `compile_fail` |
| Escala | **parcial** | 10 002 principales sintéticos; los cien mil son muro |
| **Captura en vivo por LDAP** | **muro** | necesita un Active Directory real; el lector compila siempre y se ejerce si hay directorio local |
| **Comparativa a escala contra BloodHound** | **muro** | sin dominio de producción; se declara y se usa la cobertura de relaciones documentada |

Los dos muros son de **entorno**, no de código: la captura en vivo y la medida a
cien mil cuentas necesitan un dominio real. El modelo que **decide** —parsear el
descriptor, resolver los grupos, derivar las exposiciones y proyectar el grafo a la
predicción— es lógica pura y se prueba entera, sin red, con estructuras binarias
reales.

Mensaje de commit:
`feat(identity): model the complete directory graph with live session validity and network reachability`
