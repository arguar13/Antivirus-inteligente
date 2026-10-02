# Matriz RBAC de la API del plano de control

> GENERADO por `aegis_server::autorizacion::matriz_markdown` (no editar a mano).
> Lo comprueba `server/crates/aegis-server/tests/rbac_matriz.rs`, que ademas RECORRE
> cada celda contra el servidor real. Regenerar: `AEGIS_REGENERAR=1 cargo test -p
> aegis-server --test rbac_matriz`.

`si` = el rol tiene el permiso. Las rutas de alcance `plataforma` exigen ademas una
sesion del inquilino `plataforma`; las de alcance `*-del-inquilino` responden 404 si el
recurso es de otro inquilino.

| Metodo | Ruta | Permiso | Alcance | analista | responsable | administrador | auditor |
|---|---|---|---|---|---|---|---|
| GET | `/salud` | - | publica | si | si | si | si |
| POST | `/api/sesion` | - | publica | si | si | si | si |
| DELETE | `/api/sesion` | - | sesion | si | si | si | si |
| GET | `/api/resumen` | leer | inquilino | si | si | si | si |
| GET | `/api/agentes` | leer | inquilino | si | si | si | si |
| GET | `/api/agentes/{cn}` | leer | agente-del-inquilino | si | si | si | si |
| GET | `/api/agentes/{cn}/comando` | contener | agente-del-inquilino | no | si | si | no |
| GET | `/api/alertas` | leer | inquilino | si | si | si | si |
| GET | `/api/agentes/{cn}/alertas` | leer | agente-del-inquilino | si | si | si | si |
| POST | `/api/agentes/{cn}/aislar` | contener | agente-del-inquilino | no | si | si | no |
| POST | `/api/agentes/{cn}/liberar` | contener | agente-del-inquilino | no | si | si | no |
| POST | `/api/politicas` | gestionar-deteccion | plataforma | no | no | si | no |
| GET | `/api/reglas` | leer | global | si | si | si | si |
| POST | `/api/reglas` | gestionar-deteccion | plataforma | no | no | si | no |
| DELETE | `/api/reglas/{id}` | gestionar-deteccion | plataforma | no | no | si | no |
| POST | `/api/reglas/{id}/activa` | gestionar-deteccion | plataforma | no | no | si | no |
| GET | `/api/stix/objetos` | leer | plataforma | si | si | si | si |
| GET | `/api/grafos` | leer | plataforma | si | si | si | si |
| GET | `/api/grafos/{id}` | leer | plataforma | si | si | si | si |
| GET | `/api/casos` | leer | inquilino | si | si | si | si |
| GET | `/api/casos/{id}` | leer | caso-del-inquilino | si | si | si | si |
| POST | `/api/casos/{id}/estado` | trabajar-caso | caso-del-inquilino | si | si | si | no |
| POST | `/api/casos/{id}/cerrar` | trabajar-caso | caso-del-inquilino | si | si | si | no |
| POST | `/api/casos/{id}/tareas` | trabajar-caso | caso-del-inquilino | si | si | si | no |
| POST | `/api/casos/{id}/tareas/{tarea}/cerrar` | trabajar-caso | caso-del-inquilino | si | si | si | no |
| GET | `/api/casos/{id}/auditoria` | leer | caso-del-inquilino | si | si | si | si |
| GET | `/api/casos/{id}/auditoria/verificar` | leer | caso-del-inquilino | si | si | si | si |
| POST | `/api/casos/{id}/auditoria/anclar` | trabajar-caso | caso-del-inquilino | si | si | si | no |
| GET | `/api/soc/metricas` | leer | inquilino | si | si | si | si |
| GET | `/api/cacerias` | leer | inquilino | si | si | si | si |
| POST | `/api/cacerias` | lanzar-caza | inquilino | si | si | si | no |
| GET | `/api/cacerias/{id}` | leer | caza-del-inquilino | si | si | si | si |
| POST | `/api/cacerias/{id}/cerrar` | lanzar-caza | caza-del-inquilino | si | si | si | no |
| GET | `/api/aegisql/esquema` | leer | global | si | si | si | si |
| GET | `/api/cuarentena` | contener | plataforma | no | si | si | no |
| POST | `/api/cuarentena` | contener | plataforma | no | si | si | no |
| POST | `/api/agentes/{cn}/cuarentena` | contener | plataforma | no | si | si | no |
| GET | `/api/cuarentena/difusion` | leer | plataforma | si | si | si | si |
| POST | `/api/agentes/{cn}/itdr/telemetria` | contener | agente-del-inquilino | no | si | si | no |
| GET | `/api/remediaciones` | leer | plataforma | si | si | si | si |
| GET | `/api/heuristicas` | leer | global | si | si | si | si |
| POST | `/api/heuristicas` | gestionar-deteccion | plataforma | no | no | si | no |
| POST | `/api/heuristicas/{id}/activa` | gestionar-deteccion | plataforma | no | no | si | no |
| GET | `/api/correlaciones` | leer | plataforma | si | si | si | si |
| GET | `/api/correlaciones/{id}` | leer | plataforma | si | si | si | si |
| POST | `/api/correlaciones/{id}/cerrar` | trabajar-caso | plataforma | si | si | si | no |
| GET | `/api/ws` | leer | inquilino | si | si | si | si |
| GET | `/api/reputacion/{prefijo}` | leer | global | si | si | si | si |
| POST | `/api/reputacion` | gestionar-deteccion | plataforma | no | no | si | no |

49 rutas x 4 roles = 196 celdas; 153 permitidas por rol.
