-- Deteccion de APT distribuida: heuristicas globales (FASE 45).
--
-- QUE PROBLEMA RESUELVE
-- ---------------------
-- Un operador de APT que sabe lo que hace no dispara ninguna alerta en ninguna
-- maquina. Ejecuta `nltest /dclist` en una, `whoami /groups` en otra, lee un
-- recurso compartido en una tercera. Cada endpoint ve una accion administrativa
-- perfectamente normal —de hecho lo es, tomada de una en una— y ninguno tiene
-- motivo para avisar de nada.
--
-- Lo que delata la campana no esta en ningun endpoint: esta en el CONJUNTO.
-- Cincuenta maquinas enumerando el dominio bajo la misma cuenta en cuarenta y
-- ocho horas no es una accion administrativa; es un reconocimiento. Ese hecho
-- solo existe en el plano de control, porque es el unico que ve las cincuenta.
--
-- POR QUE LAS REGLAS SON COLUMNAS Y NO UN TEXTO
-- ---------------------------------------------
-- La tentacion es un segundo lenguaje de consulta. Ya hay uno (AegisQL, FASE
-- 43) y sirve para otra cosa: preguntar al endpoint. Una correlacion de flota
-- tiene una forma fija —que buscar, por que agrupar, en cuanto tiempo, cuantos
-- endpoints— y con columnas la valida el esquema. Un texto libre habria que
-- analizarlo, y un analizador es codigo que puede equivocarse sobre algo que
-- decide si se lanza una respuesta automatica contra la flota de un cliente.

-- ---------------------------------------------------------------------------
-- Las reglas
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS heuristicas_globales (
    id                  UUID        PRIMARY KEY,
    nombre              TEXT        NOT NULL UNIQUE,
    -- Que se le dice al analista cuando dispara. No es decorativo: una
    -- correlacion sin nombre de patron obliga a reconstruir el razonamiento
    -- desde la consulta, y eso se hace a las tres de la manana.
    patron              TEXT        NOT NULL,

    -- QUE BUSCAR. Una alerta entra si su tecnica esta en `tecnicas` O su
    -- categoria esta en `categorias`. Las dos listas vacias no se permiten: una
    -- regla que casa con todo no es una heuristica, es un contador de alertas.
    tecnicas            TEXT[]      NOT NULL DEFAULT '{}',
    categorias          TEXT[]      NOT NULL DEFAULT '{}',

    -- POR QUE AGRUPAR. Clave dentro de `alertas.detalles` (p. ej. 'cuenta',
    -- 'sha256', 'destino'). Las alertas sin ese atributo NO participan: agrupar
    -- por un valor ausente juntaria en un mismo grupo todo lo que no se pudo
    -- ver, y ese grupo dispararia siempre.
    clave_detalle       TEXT        NOT NULL,

    -- EN CUANTO TIEMPO. Ventana deslizante sobre `ocurrido_en`.
    ventana_horas       INT         NOT NULL CHECK (ventana_horas BETWEEN 1 AND 720),

    -- CUANTOS ENDPOINTS DISTINTOS. Distintos, no alertas: un endpoint ruidoso
    -- que ejecuta `whoami` quinientas veces no es movimiento lateral, y contar
    -- alertas lo convertiria en una campana de APT.
    minimo_endpoints    INT         NOT NULL CHECK (minimo_endpoints >= 2),

    severidad           SMALLINT    NOT NULL DEFAULT 4 CHECK (severidad BETWEEN 0 AND 4),
    tecnica_mitre       TEXT,
    tactica_mitre       TEXT,

    -- Claves que el analista ya declaro benignas. Es el mecanismo con el que se
    -- cierra un falso positivo para que no vuelva: sin el, la cuenta de servicio
    -- que inventaria el dominio cada noche dispara la misma correlacion cada
    -- noche, y a la tercera nadie mira las correlaciones.
    claves_excluidas    TEXT[]      NOT NULL DEFAULT '{}',

    activa              BOOLEAN     NOT NULL DEFAULT TRUE,
    creada_en           TIMESTAMPTZ NOT NULL DEFAULT now(),
    creada_por          TEXT        NOT NULL DEFAULT 'sistema',

    -- Una regla que no busca nada casaria con toda alerta de la flota.
    CONSTRAINT heuristica_busca_algo
        CHECK (cardinality(tecnicas) > 0 OR cardinality(categorias) > 0)
);

CREATE INDEX IF NOT EXISTS idx_heuristicas_activas ON heuristicas_globales (nombre)
    WHERE activa;

-- ---------------------------------------------------------------------------
-- Lo que las reglas encuentran
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correlaciones (
    id              UUID        PRIMARY KEY,
    id_regla        UUID        NOT NULL REFERENCES heuristicas_globales (id) ON DELETE CASCADE,
    -- Valor concreto de `clave_detalle` que agrupo (la cuenta, el hash...).
    clave           TEXT        NOT NULL,
    endpoints       INT         NOT NULL,
    alertas         INT         NOT NULL,
    -- Extremos de la evidencia, para que el analista vea de un vistazo si la
    -- campana lleva dos horas o tres semanas.
    primera_en      TIMESTAMPTZ NOT NULL,
    ultima_en       TIMESTAMPTZ NOT NULL,
    abierta_en      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Ultima vez que la evidencia crecio. Se distingue de `abierta_en` porque
    -- una correlacion que sigue creciendo es una campana en curso y una que no
    -- creció en dos dias es historia.
    vista_en        TIMESTAMPTZ NOT NULL DEFAULT now(),
    cerrada_en      TIMESTAMPTZ,
    cerrada_por     TEXT,
    -- 'confirmada' | 'falso_positivo'. NULL mientras esta abierta.
    veredicto       TEXT        CHECK (veredicto IN ('confirmada','falso_positivo'))
);

-- UNA correlacion abierta por (regla, clave).
--
-- Que lo garantice la base de datos y no el motor: el motor evalua cada minuto,
-- y sin esto, una campana que dura tres dias produciria cuatro mil
-- correlaciones identicas. El analista no veria una campana: veria una tormenta,
-- que es exactamente el ruido que hace que se dejen de mirar las alertas.
-- Con esto, la evaluacion siguiente ACTUALIZA la que ya existe.
CREATE UNIQUE INDEX IF NOT EXISTS idx_correlacion_abierta_unica
    ON correlaciones (id_regla, clave) WHERE cerrada_en IS NULL;

CREATE INDEX IF NOT EXISTS idx_correlaciones_abiertas
    ON correlaciones (vista_en DESC) WHERE cerrada_en IS NULL;

-- Los endpoints que contribuyeron, para poder responder "¿que maquinas?".
--
-- Se materializa en vez de recalcularse: la ventana es deslizante, asi que
-- dentro de dos dias la consulta que encontro la correlacion ya no devolveria
-- las mismas maquinas, y el analista que abre el caso el martes tiene que ver
-- la evidencia que lo abrio el lunes.
CREATE TABLE IF NOT EXISTS correlacion_endpoints (
    id_correlacion  UUID        NOT NULL REFERENCES correlaciones (id) ON DELETE CASCADE,
    cn_agente       TEXT        NOT NULL,
    alertas         INT         NOT NULL DEFAULT 1,
    primera_en      TIMESTAMPTZ NOT NULL,
    ultima_en       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (id_correlacion, cn_agente)
);

-- ---------------------------------------------------------------------------
-- Lo que la correlacion necesita de las alertas
-- ---------------------------------------------------------------------------

-- La ventana se recorre por `ocurrido_en`, no por `recibido_en`.
--
-- Un endpoint que estuvo apagado un dia entrega sus alertas al reconectar: con
-- el indice —y la consulta— sobre la hora de llegada, esas alertas caerian
-- todas en el mismo instante y una campana repartida en dos dias pareceria un
-- pico de un segundo, o al reves, una campana real quedaria fuera de la ventana
-- porque su evidencia llego tarde.
CREATE INDEX IF NOT EXISTS idx_alertas_correlacion
    ON alertas (tecnica_mitre, ocurrido_en DESC)
    WHERE tecnica_mitre IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_alertas_categoria_tiempo
    ON alertas (categoria, ocurrido_en DESC);

-- El motor agrupa por un atributo de `detalles`. Sin indice GIN, cada
-- evaluacion recorreria todas las alertas de la ventana leyendo su JSONB.
CREATE INDEX IF NOT EXISTS idx_alertas_detalles ON alertas USING GIN (detalles);
