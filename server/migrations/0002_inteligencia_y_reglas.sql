-- Inteligencia de amenazas y motor de reglas globales (FASE 38).
--
-- Anade tres realidades al plano de control: la inteligencia que llega en
-- formato estandar (STIX 2.1), el LINAJE de procesos que rodea a cada deteccion
-- —sin el, una alerta aislada casi nunca concluye nada— y las reglas globales
-- que el operador define y el servidor empuja a la flota.

-- ---------------------------------------------------------------------------
-- Inteligencia STIX 2.1
-- ---------------------------------------------------------------------------

-- Procedencia: que bundle llego, de quien y cuando.
CREATE TABLE IF NOT EXISTS stix_bundles (
    id            TEXT        PRIMARY KEY,
    cn_agente     TEXT        NOT NULL REFERENCES agentes (cn) ON DELETE CASCADE,
    objetos       INTEGER     NOT NULL DEFAULT 0,
    -- Cuando lo genero el endpoint frente a cuando llego: la diferencia delata
    -- un agente con el reloj desviado o una entrega retrasada.
    generado_en   TIMESTAMPTZ,
    recibido_en   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_stix_bundles_agente ON stix_bundles (cn_agente, recibido_en DESC);

-- Los objetos del bundle, uno por fila.
--
-- La clave es el identificador STIX, que la especificacion define para que dos
-- herramientas distintas que observen el MISMO artefacto produzcan el MISMO id.
-- Gracias a eso, dos endpoints que ven el mismo fichero malicioso no generan dos
-- objetos: generan uno con dos avistamientos.
CREATE TABLE IF NOT EXISTS stix_objetos (
    id            TEXT        PRIMARY KEY,
    tipo          TEXT        NOT NULL,
    id_bundle     TEXT        REFERENCES stix_bundles (id) ON DELETE CASCADE,
    cn_agente     TEXT        REFERENCES agentes (cn) ON DELETE SET NULL,
    contenido     JSONB       NOT NULL,
    -- Cuantas veces se ha vuelto a ver este objeto en la flota. Es la senal que
    -- distingue un indicador anecdotico de una campana en curso.
    avistamientos INTEGER     NOT NULL DEFAULT 1,
    primera_vez   TIMESTAMPTZ NOT NULL DEFAULT now(),
    ultima_vez    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_stix_objetos_tipo ON stix_objetos (tipo, ultima_vez DESC);
-- Los indicadores muy repetidos son los que interesan primero al analista.
CREATE INDEX IF NOT EXISTS idx_stix_objetos_avistamientos
    ON stix_objetos (avistamientos DESC) WHERE avistamientos > 1;

-- ---------------------------------------------------------------------------
-- Grafos de linaje de procesos
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS grafos (
    id            UUID        PRIMARY KEY,
    cn_agente     TEXT        NOT NULL REFERENCES agentes (cn) ON DELETE CASCADE,
    -- Clave del nodo que disparo la captura.
    raiz          BIGINT      NOT NULL,
    nodos         INTEGER     NOT NULL DEFAULT 0,
    capturado_en  TIMESTAMPTZ NOT NULL,
    recibido_en   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_grafos_agente ON grafos (cn_agente, recibido_en DESC);

CREATE TABLE IF NOT EXISTS grafo_nodos (
    id_grafo      UUID        NOT NULL REFERENCES grafos (id) ON DELETE CASCADE,
    -- Identidad ESTABLE del proceso, derivada de (pid, start_boottime). No es un
    -- PID: los PID se reciclan, y un ataque que espere al reciclado consigue que
    -- la telemetria atribuya sus acciones a un proceso inocente ya terminado.
    clave         BIGINT      NOT NULL,
    pid           BIGINT      NOT NULL,
    padre         BIGINT      NOT NULL,
    creador       BIGINT      NOT NULL,
    profundidad   INTEGER     NOT NULL,
    imagen        TEXT        NOT NULL,
    cmdline       TEXT        NOT NULL,
    clase         INTEGER     NOT NULL,
    iniciado_ns   BIGINT      NOT NULL,
    terminado_ns  BIGINT,
    taints        BIGINT      NOT NULL DEFAULT 0,
    puntuacion    INTEGER     NOT NULL DEFAULT 0,
    PRIMARY KEY (id_grafo, clave)
);

-- Buscar "donde mas se ha visto esta imagen" es la consulta con la que un
-- analista pasa de un endpoint a la campana entera.
CREATE INDEX IF NOT EXISTS idx_grafo_nodos_imagen ON grafo_nodos (imagen);

-- ---------------------------------------------------------------------------
-- Motor de reglas globales
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS reglas (
    id            UUID        PRIMARY KEY,
    nombre        TEXT        NOT NULL,
    -- Tipo de regla: determina como la interpreta el agente.
    tipo          TEXT        NOT NULL,
    parametros    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    activa        BOOLEAN     NOT NULL DEFAULT TRUE,
    severidad     SMALLINT    NOT NULL DEFAULT 2 CHECK (severidad BETWEEN 0 AND 4),
    creada_en     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Una regla que corta trafico en toda la flota no puede ser anonima.
    creada_por    TEXT        NOT NULL DEFAULT 'sistema'
);

-- Dos reglas con el mismo nombre serian indistinguibles en el panel y en los
-- registros de auditoria.
CREATE UNIQUE INDEX IF NOT EXISTS idx_reglas_nombre ON reglas (lower(nombre));
CREATE INDEX IF NOT EXISTS idx_reglas_activas ON reglas (tipo) WHERE activa;
