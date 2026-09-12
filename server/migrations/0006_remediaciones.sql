-- Remediacion automatica de flota: el registro duradero de lo que el Control
-- Plane hace SOLO sobre los endpoints (integracion viva del AI-RO, FASE 64).
--
-- QUE PROBLEMA RESUELVE
-- ---------------------
-- El orquestador (aegis-orchestrator) decide y ejecuta un playbook —aislar la
-- red, matar procesos, revocar tickets, volcar memoria— sin que intervenga un
-- humano. Un sistema que toca la flota de un cliente por su cuenta y no deja
-- rastro es indefendible: cuando el dueno pregunta "por que se aislo esta
-- maquina a las 03:14", la respuesta tiene que estar en una tabla, no en el log
-- de un proceso que ya rotó.
--
-- POR QUE AQUI Y NO EN MEMORIA
-- ----------------------------
-- Dos razones, y ninguna es la trazabilidad (que ya seria suficiente):
--
-- 1. IDEMPOTENCIA ENTRE INSTANCIAS. El motor ITDR es sin estado por lote: un
--    barrido de Kerberoasting que dura veinte minutos aparece en VEINTE lotes
--    consecutivos. Sin un cerrojo, cada lote relanzaria el playbook entero
--    contra el mismo endpoint. Y el plano de control corre en varias instancias
--    tras un balanceador, asi que un cerrojo en memoria de proceso no sirve:
--    dos instancias que reciben lotes distintos del mismo ataque decidirian
--    cada una por su cuenta. El indice unico parcial de abajo convierte "una
--    remediacion abierta por (clase, sujeto, endpoint)" en una garantia de la
--    base de datos, que es el unico sitio donde las dos instancias se ven.
--
-- 2. REINTENTO. El informe transaccional guarda que accion fallo y por que, que
--    es exactamente lo que `Orquestador::reintentar` necesita para re-ejecutar
--    SOLO lo fallido. Si eso vive en memoria, un reinicio del plano de control
--    deja un endpoint a medio remediar y nadie lo sabe.

CREATE TABLE IF NOT EXISTS remediaciones (
    id              UUID        PRIMARY KEY,
    -- Familia de amenaza que la disparo ('golden_ticket', 'silver_ticket',
    -- 'kerberoasting', 'escalada_privilegios'). Texto y no enum del esquema:
    -- una clase nueva en el motor no debe exigir una migracion para poder
    -- registrarse, y el conjunto lo valida el tipo de Rust antes de llegar.
    clase           TEXT        NOT NULL,
    -- La identidad implicada (la cuenta del ticket forjado, el SPN barrido).
    sujeto          TEXT        NOT NULL,
    -- El endpoint sobre el que se actuo.
    cn_agente       TEXT        NOT NULL,
    severidad       SMALLINT    NOT NULL CHECK (severidad BETWEEN 0 AND 4),
    -- Evidencia legible con la que el motor justifico la deteccion. Se
    -- materializa aqui y no se referencia a `alertas` a proposito: el analista
    -- que abre la remediacion tiene que ver POR QUE se toco su maquina sin
    -- depender de que la alerta siga dentro de la retencion.
    evidencia       TEXT        NOT NULL,
    -- 'en_curso' | 'completado' | 'completado_con_fallos'. El estado
    -- 'no_aplica' no llega a esta tabla: una deteccion por debajo del umbral no
    -- toca la flota, y registrar una remediacion que no existio confundiria el
    -- recuento de acciones automaticas.
    estado          TEXT        NOT NULL DEFAULT 'en_curso'
                                CHECK (estado IN ('en_curso','completado','completado_con_fallos')),
    lanzada_en      TIMESTAMPTZ NOT NULL DEFAULT now(),
    concluida_en    TIMESTAMPTZ,
    -- Quien la ordeno: 'ai-ro' cuando la decide el orquestador, el usuario
    -- cuando un analista fuerza un reintento desde la consola.
    ordenada_por    TEXT        NOT NULL DEFAULT 'ai-ro'
);

-- UNA remediacion abierta por (clase, sujeto, endpoint).
--
-- Es el cerrojo distribuido descrito arriba, y la razon de que sea un indice y
-- no una comprobacion en el codigo: dos instancias del plano de control que
-- procesan lotes del mismo ataque a la vez no se ven entre si, pero las dos
-- escriben aqui. La segunda choca con el indice, su INSERT no hace nada
-- (ON CONFLICT DO NOTHING) y no se lanza un segundo playbook contra un endpoint
-- que ya se esta remediando.
CREATE UNIQUE INDEX IF NOT EXISTS idx_remediacion_abierta_unica
    ON remediaciones (clase, sujeto, cn_agente) WHERE concluida_en IS NULL;

-- El listado del analista es "las ultimas", y el enfriamiento consulta "la
-- ultima de esta terna".
CREATE INDEX IF NOT EXISTS idx_remediaciones_recientes
    ON remediaciones (lanzada_en DESC);
CREATE INDEX IF NOT EXISTS idx_remediaciones_terna
    ON remediaciones (clase, sujeto, cn_agente, concluida_en DESC);

-- El detalle por accion: es el informe transaccional del orquestador hecho
-- filas. Sin el no hay reintento idempotente posible tras un reinicio, porque
-- no se sabria que se llego a conseguir.
CREATE TABLE IF NOT EXISTS remediacion_acciones (
    id_remediacion  UUID        NOT NULL REFERENCES remediaciones (id) ON DELETE CASCADE,
    -- 'aislar_red' | 'matar_procesos' | 'revocar_tickets_kerberos' |
    -- 'volcado_forense_memoria'.
    accion          TEXT        NOT NULL,
    exito           BOOLEAN     NOT NULL,
    -- El motivo del fallo, tal cual lo devolvio la frontera con la flota. Vacio
    -- cuando la accion tuvo exito.
    motivo          TEXT        NOT NULL DEFAULT '',
    -- Comando encolado al endpoint, cuando se llego a encolar. Permite cruzar
    -- esta fila con `comandos` y ver si el agente lo recogio de verdad: que el
    -- plano de control lo ordene y que el endpoint lo aplique son dos hechos
    -- distintos, y confundirlos es como se acaba creyendo aislada una maquina
    -- que no lo esta.
    id_comando      UUID,
    intentos        INT         NOT NULL DEFAULT 1 CHECK (intentos >= 1),
    actualizada_en  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id_remediacion, accion)
);
