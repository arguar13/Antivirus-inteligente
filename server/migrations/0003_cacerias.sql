-- Cacerias distribuidas AegisQL (FASE 43).
--
-- Una caceria es una pregunta que un analista le hace a TODA la flota a la vez.
-- Se guarda por tres motivos que no son el de "tener un historial":
--
--   1. Un endpoint apagado cuando se lanzo la caceria tiene que recibirla al
--      reconectar. Si la consulta viviera solo en memoria del servidor que la
--      lanzo, ese endpoint no se enteraria nunca y el analista creeria que su
--      caceria cubrio una flota que no cubrio.
--   2. El plano de control se despliega con varias instancias. La consulta la
--      recibe una y los agentes estan repartidos entre todas.
--   3. Una caceria es una accion de un operador sobre miles de maquinas
--      ajenas: tiene que quedar registrada con quien la ordeno y cuando.

CREATE TABLE IF NOT EXISTS cacerias (
    id            UUID        PRIMARY KEY,
    -- El texto EXACTO que escribio el analista. Se guarda literal y no
    -- reconstruido desde el arbol: si un dia hay que auditar que se ejecuto en
    -- las maquinas de un cliente, la respuesta tiene que ser lo que se escribio.
    consulta      TEXT        NOT NULL,
    tabla         TEXT        NOT NULL,
    columnas      TEXT[]      NOT NULL,
    -- Quien la ordeno. Sin esto, una consulta que leyo la memoria de miles de
    -- endpoints no tiene responsable.
    lanzada_por   TEXT        NOT NULL,
    lanzada_en    TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Mientras sea NULL, los agentes que reconecten la recibiran.
    cerrada_en    TIMESTAMPTZ,
    -- Agentes en linea en el momento de lanzarla. Es el denominador: sin el, un
    -- "12 endpoints encontraron algo" no dice si es sobre 20 o sobre 10.000.
    objetivo      BIGINT      NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_cacerias_abiertas
    ON cacerias (lanzada_en DESC) WHERE cerrada_en IS NULL;

-- Respuesta de UN endpoint a UNA caceria.
CREATE TABLE IF NOT EXISTS caza_respuestas (
    caza_id       UUID        NOT NULL REFERENCES cacerias (id) ON DELETE CASCADE,
    cn_agente     TEXT        NOT NULL,
    -- Filas como array de arrays de texto. El tipo de cada columna ya lo
    -- declara el esquema de AegisQL, asi que arrastrarlo por celda
    -- multiplicaria el tamano sin anadir nada que el analista pueda ver.
    filas         JSONB       NOT NULL DEFAULT '[]'::jsonb,
    coincidencias BIGINT      NOT NULL DEFAULT 0,
    examinadas    BIGINT      NOT NULL DEFAULT 0,
    -- Valores que el endpoint no pudo leer. Es lo que permite distinguir
    -- "no hay nada" de "no pude mirar".
    inaccesibles  BIGINT      NOT NULL DEFAULT 0,
    incompleto    BOOLEAN     NOT NULL DEFAULT FALSE,
    agotado       BOOLEAN     NOT NULL DEFAULT FALSE,
    duracion_ms   BIGINT      NOT NULL DEFAULT 0,
    error         TEXT        NOT NULL DEFAULT '',
    recibida_en   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Un agente responde UNA vez a cada caceria.
    --
    -- La clave primaria compuesta es lo que hace idempotente el reintento: si
    -- un agente pierde la conexion justo despues de responder y lo vuelve a
    -- intentar, su respuesta se sustituye en vez de contarse dos veces. Sin
    -- ella, un endpoint con mala red inflaria el recuento de coincidencias y
    -- el analista veria una amenaza mas extendida de lo que esta.
    PRIMARY KEY (caza_id, cn_agente)
);

-- La consulta que hace el panel al abrir una caceria: sus respuestas, primero
-- las que encontraron algo.
CREATE INDEX IF NOT EXISTS idx_caza_respuestas_utiles
    ON caza_respuestas (caza_id, coincidencias DESC, recibida_en DESC);
