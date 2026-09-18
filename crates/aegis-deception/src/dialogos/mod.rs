//! Los dialogos, uno por servicio fingido.
//!
//! # Lo que cada familia saca, y por que se llega hasta ahi y no mas
//!
//! Cada dialogo avanza en el protocolo **hasta el punto en que el siguiente paso
//! exigiria criptografia de verdad o ejecutar algo de verdad**, y ahi para. Ese
//! punto no es arbitrario ni es una limitacion que se disimule: es donde acaba lo
//! que se puede fingir sin construir un riesgo.
//!
//! Y resulta que el punto esta bastante mas alla de lo que la gente supone,
//! porque lo mas valioso de cada protocolo se entrega ANTES de la criptografia:
//!
//! | Familia | Hasta donde | Lo que se saca |
//! |---|---|---|
//! | SSH | intercambio de versiones y `KEXINIT` | version del cliente y su lista completa de algoritmos: la huella HASSH, que identifica la herramienta aunque cambie el banner |
//! | Telnet, FTP | sesion aceptada | **usuario y contrasena en claro**, y que hace despues de entrar |
//! | RDP | peticion X.224 | la `cookie mstshash`, que lleva el **nombre de usuario** que el cliente iba a usar |
//! | SMB | `SESSION_SETUP` con NTLMSSP | usuario, dominio y el **NTLMv2** de respuesta a un reto nuestro |
//! | VNC | reto de autenticacion | la respuesta al reto, que con el reto conocido da la contrasena que probaron |
//! | Web | peticion completa | rutas, cabeceras, agente, y las credenciales de `Authorization` |
//! | Bases | saludo y autenticacion | usuario, base y las primeras consultas |
//! | Industrial | orden completa | **si venia a leer o a escribir**, que es la diferencia entre inventariar y parar una planta |
//!
//! # Lo que ninguno hace
//!
//! Ejecutar. No hay interprete de ordenes, no hay sistema de ficheros y no hay
//! proceso hijo. Un `RETR /etc/passwd` devuelve un texto construido en memoria;
//! un `ls` de Telnet devuelve un listado escrito en una constante. La carcel no
//! puede fallar porque no hay carcel: no hay nada dentro de lo que escaparse.

pub mod acceso;
pub mod bases;
pub mod industrial;
pub mod web;
