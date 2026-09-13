//! # `aegis-wire` — AegisWire: disección semántica de protocolos (FASE 70)
//!
//! ## Qué problema resuelve
//!
//! Hasta aquí, AegisCore veía la red como **metadatos**: quién habla con quién,
//! por qué puerto, cuántos bytes. Eso basta para detectar un escaneo o una
//! exfiltración masiva, y no basta para casi nada más. Un C2 que va por HTTPS al
//! 443 con un volumen normal es, en metadatos, indistinguible de un navegador.
//!
//! Esta fase convierte el tráfico crudo en **hechos con significado**: esta
//! consulta DNS pidió este nombre, este `ClientHello` tiene esta huella JA3, este
//! `bind` LDAP fue sin cifrar, este fichero que acaba de cruzar es un ejecutable
//! de Windows con este SHA-256 aunque se anunciara como PDF.
//!
//! ## Las tres decisiones que definen la fase
//!
//! ### 1. El protocolo se decide por CONTENIDO, no por puerto
//!
//! Identificar por puerto es cómodo y falla exactamente donde importa: el
//! malware pone su C2 en el 443 **porque** todo el mundo asume que el 443 es
//! TLS. Aquí el contenido manda y el puerto es sólo desempate. Cuando ninguna de
//! las dos cosas dice nada, el protocolo queda `Desconocido` — que en un puerto
//! conocido es una señal por sí misma, no un silencio. Ver [`motor`].
//!
//! ### 2. La política de reensamblado es explícita y se declara
//!
//! Cuando dos segmentos TCP se solapan **con contenido distinto**, el sistema
//! operativo del destino aplica *su* política al decidir cuál se queda. Si el
//! sensor aplica otra, reconstruye un flujo que el endpoint nunca verá, y a
//! partir de ahí todas sus reglas miran datos que no existieron. No es un fallo
//! de detección: es una **evasión completa y silenciosa** —Ptacek y Newsham,
//! 1998— y sigue funcionando contra productos mal hechos.
//!
//! Aquí la política es un enumerado ([`reensamblado::Politica`]), se elige a
//! propósito, y los solapes contradictorios **se cuentan**. Ese contador es una
//! señal de primer orden: el tráfico legítimo no solapa con contenido distinto
//! prácticamente nunca.
//!
//! ### 3. Todo lo que el atacante controla tiene cota, y la cota se cuenta
//!
//! El número de flujos, la secuencia TCP, la longitud de un campo, la
//! profundidad de una estructura DER, el tamaño de un fichero: los elige quien
//! manda los bytes. Cada uno tiene su tope, y cada vez que un tope recorta algo
//! **se cuenta**, porque un dato que se tira sin contarlo es un agujero de
//! visibilidad que nadie sabe que tiene.
//!
//! Dos topes son globales y no por flujo ([`flujo::MAX_MEMORIA`],
//! [`motor::MAX_MEMORIA_APP`]): una cota por flujo multiplicada por un número de
//! flujos que elige el atacante no es una cota, es un producto.
//!
//! ## Qué se disecta
//!
//! | Módulo | Protocolos | Lo que saca |
//! |---|---|---|
//! | [`dns`] | DNS sobre UDP y TCP | consultas, respuestas, indicios de tunelización por entropía |
//! | [`http`] | HTTP/1.x | petición, respuesta, cabeceras, y anomalías de **contrabando** |
//! | [`tls`] | TLS 1.0–1.3 | SNI, ALPN, huellas **JA3/JA3S/JA4**, certificados |
//! | [`smb`] | SMB1 y SMB2 | órdenes y recursos; SMB1 en uso se delata |
//! | [`directorio`] | Kerberos y LDAP | principales, servicios, cifrado débil, `bind` sin cifrar |
//! | [`texto`] | SSH, SMTP, FTP | versiones y órdenes, **sin registrar contraseñas** |
//! | [`udp`] | DHCP, NTP, QUIC | inventario pasivo y saludos QUIC |
//! | [`ficheros`] | cualquiera | tipo real por magia, tamaño y **SHA-256** |
//!
//! Y por debajo, las piezas que los sostienen: [`lector`] (lectura acotada y
//! explícita sobre el endianismo), [`der`] (ASN.1 **iterativo**, sin recursión),
//! [`md5`] (sólo como etiqueta de interoperabilidad JA3, **jamás** para
//! seguridad), [`ipv6`] (cadenas de extensiones), [`reensamblado`], [`flujo`],
//! [`hecho`] y [`registro`].
//!
//! ## Sans-io, y por qué eso es lo que hace verificable la fase
//!
//! [`motor::Motor`] no abre sockets, no toca la NIC y no tiene reloj propio: el
//! tiempo entra como parámetro. Se le dan bytes y devuelve hechos.
//!
//! La consecuencia es la que importa: **cada ataque de esta fase se construye
//! entero en una prueba**. La evasión por solape, el bucle de punteros DNS, la
//! cadena interminable de cabeceras IPv6, el contrabando de peticiones HTTP, el
//! fichero disfrazado — todos se ejercen de verdad, sin red, sin privilegios y
//! sin condiciones de carrera. Si el motor abriera el socket, cada uno de esos
//! sería «no se puede ejercitar aquí», y la fase se quedaría en una declaración
//! de intenciones.
//!
//! ## Cero dependencias externas nuevas
//!
//! No es una postura de estilo. Un disector analiza bytes que escribe el
//! atacante, sin autenticación previa y a velocidad de línea: es la superficie
//! de ataque más expuesta del producto, y es exactamente donde ClamAV, Suricata
//! y Zeek acumulan su historial de CVE de desbordamiento. Meter aquí una
//! biblioteca de *parsing* genérica sería importar código no auditado al sitio
//! más caliente del agente.
//!
//! ## Honestidad de validación
//!
//! | Pieza | Verificable aquí | Cómo |
//! |---|---|---|
//! | Evasión por solape TCP | **Sí, entera** | se construyen los segmentos contradictorios y se comprueba qué reconstruye y qué delata |
//! | Solape **sobre terreno ya entregado** | **Sí** | ventana de historia acotada ([`reensamblado::MAX_HISTORIA`]); más atrás se cuenta como retransmisión y **se dice** |
//! | Contrabando HTTP (CL.TE) | **Sí** | se manda el mensaje con las dos cabeceras y se comprueba la anomalía |
//! | Bucle de punteros DNS | **Sí** | se construye el bucle y se comprueba que corta con progreso estricto |
//! | Cadena de extensiones IPv6 | **Sí** | se encadenan hasta pasar el tope y se comprueba que **declara** que no pudo llegar |
//! | Huellas JA3/JA3S/JA4 | **Sí** | vectores construidos byte a byte, con GREASE dentro |
//! | Extracción de ficheros | **Sí** | descarga completa por paquetes, hash contrastado contra el del fichero entero |
//! | Un mensaje se cuenta **una vez** | **Sí** | conservar lo ya interpretado repetiría sus hechos en cada paquete y dejaría sin ver el mensaje siguiente |
//! | Peticiones **encadenadas** en una conexión reutilizada | **Sí** | se ven las cinco, una vez cada una, lleguen pegadas o en paquetes distintos |
//! | Sesión TLS larga | **Sí** | los registros cifrados se **enmarcan** aunque no se puedan leer: sin eso la memoria se iría en lo único que nunca se va a interpretar |
//! | Cotas de memoria | **Sí, medidas** | se ejerce el ataque de retención y se comprueba el techo global |
//! | Captura real desde la NIC | **No aquí** | el motor es *sans-io* a propósito; la captura vive en `aegis-net` |
//! | Defragmentación **IP** | **No**, y se declara | se marca el datagrama como fragmentado y los fragmentos posteriores **no** se analizan como transporte; reensamblar IP es otra superficie entera |
//! | Cuerpos HTTP **troceados** (`chunked`) | **No todavía** | sólo se extrae con longitud declarada; un cuerpo sin `Content-Length` no produce fichero |
//! | Tráfico **cifrado** por dentro | **No, y no se finge** | de TLS se ve el saludo y el certificado; el contenido lo ve `aegis-l7hunter` con uprobes, no este crate |
//!
//! La última fila es la que más importa decir en voz alta: esta fase **no**
//! descifra nada. Lo que da es el metadato de la sesión cifrada —huella, SNI,
//! certificado— que es justo lo que sirve para reconocer una familia de C2 sin
//! romper el cifrado de nadie.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod der;
pub mod directorio;
pub mod dns;
pub mod error;
pub mod ficheros;
pub mod flujo;
pub mod hecho;
pub mod http;
pub mod ipv6;
pub mod lector;
pub mod md5;
pub mod motor;
pub mod reensamblado;
pub mod registro;
pub mod smb;
pub mod texto;
pub mod tls;
pub mod udp;

pub use error::{ErrorDiseccion, Resultado};
pub use ficheros::{Extractor, TipoFichero};
pub use flujo::{ContadoresTabla, Flujo, TablaFlujos, MAX_FLUJOS, MAX_MEMORIA};
pub use hecho::{ClaveFlujo, Direccion, Hecho, HechoConContexto, ProtocoloApp, Transporte};
pub use lector::Lector;
pub use motor::{ConfigMotor, ContadoresMotor, Motor, MAX_MEMORIA_APP};
pub use reensamblado::{Anomalias, Politica, Sentido, MAX_HISTORIA};
pub use registro::{Cierre, RegistroConexion};
