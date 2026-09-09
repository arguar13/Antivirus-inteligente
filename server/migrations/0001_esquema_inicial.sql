-- Esquema inicial del plano de control de AegisCore (FASE 37).
--
-- Tres realidades que modela: QUE endpoints existen (inventario de flota), QUE
-- ha pasado en ellos (alertas con mapeo MITRE ATT&CK) y QUE deben hacer
-- (politicas y comandos).
--
-- Nota de seguridad sobre la identidad: la clave primaria de un agente es el
-- CN de su certificado, NO un identificador que el propio agente declare. El CN
-- lo valida el handshake mTLS contra la CA de la flota, asi que es lo unico que
-- un agente no puede falsificar. Los campos que el agente declara (hostname,
-- version, id_agente) son datos, no identidad.

-- ---------------------------------------------------------------------------
-- Inventario de la flota
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agentes (
    -- Identidad autenticada: CN del certificado presentado en el mTLS.
    cn                  TEXT        PRIMARY KEY,
    -- Identificador que el agente declara de si mismo (dato, no identidad).
    id_agente           TEXT        NOT NULL,
    hostname            TEXT        NOT NULL,
    version_agente      TEXT        NOT NULL,
    -- Huella del certificado con el que se enrolo: permite detectar que un
    -- agente cambia de credencial (rotacion legitima o suplantacion).
    huella_cert         BYTEA,
    id_flota            TEXT        NOT NULL DEFAULT '',
    enrolado_en         TIMESTAMPTZ NOT NULL DEFAULT now(),
    ultimo_latido       TIMESTAMPTZ,
    latidos             BIGINT      NOT NULL DEFAULT 0,
    eventos             BIGINT      NOT NULL DEFAULT 0,
    -- Telemetria del ultimo latido.
    rss_kb              BIGINT      NOT NULL DEFAULT 0,
    amenazas_activas    BIGINT      NOT NULL DEFAULT 0,
    version_politica    BIGINT      NOT NULL DEFAULT 0,
    -- Respuesta de un clic: un endpoint aislado sigue reportando pero queda
    -- cortado del resto de la red por su propia politica local.
    aislado             BOOLEAN     NOT NULL DEFAULT FALSE,
    aislado_en          TIMESTAMPTZ
);

-- El panel pregunta constantemente "quien esta vivo": el indice sobre el ultimo
-- latido evita recorrer toda la flota en cada refresco del mapa de topologia.
CREATE INDEX IF NOT EXISTS idx_agentes_ultimo_latido ON agentes (ultimo_latido DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_agentes_aislado       ON agentes (aislado) WHERE aislado;

-- ---------------------------------------------------------------------------
-- Alertas de seguridad, con mapeo a MITRE ATT&CK
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alertas (
    id              UUID        PRIMARY KEY,
    cn_agente       TEXT        NOT NULL REFERENCES agentes (cn) ON DELETE CASCADE,
    -- 0 informativa .. 4 critica. SMALLINT basta y ocupa la mitad.
    severidad       SMALLINT    NOT NULL CHECK (severidad BETWEEN 0 AND 4),
    categoria       TEXT        NOT NULL,
    descripcion     TEXT        NOT NULL,
    -- Mapeo ATT&CK derivado de la categoria por el plano de control. Se guarda
    -- materializado (y no solo la categoria) porque el mapeo puede cambiar con
    -- el tiempo y una alerta historica debe conservar como se clasifico ENTONCES.
    tecnica_mitre   TEXT,
    tactica_mitre   TEXT,
    detalles        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    -- Cuando ocurrio en el endpoint frente a cuando llego: la diferencia delata
    -- un agente con el reloj desviado o una entrega retrasada.
    ocurrido_en     TIMESTAMPTZ NOT NULL,
    recibido_en     TIMESTAMPTZ NOT NULL DEFAULT now(),
    resuelta        BOOLEAN     NOT NULL DEFAULT FALSE
);

-- El panel lista "las criticas mas recientes": indice compuesto que sirve al
-- filtro y al orden a la vez.
CREATE INDEX IF NOT EXISTS idx_alertas_recientes ON alertas (recibido_en DESC);
CREATE INDEX IF NOT EXISTS idx_alertas_agente    ON alertas (cn_agente, recibido_en DESC);
CREATE INDEX IF NOT EXISTS idx_alertas_abiertas  ON alertas (severidad DESC, recibido_en DESC)
    WHERE NOT resuelta;
CREATE INDEX IF NOT EXISTS idx_alertas_tecnica   ON alertas (tecnica_mitre)
    WHERE tecnica_mitre IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Politicas globales empujadas a la flota
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS politicas (
    version     BIGINT      PRIMARY KEY,
    nombre      TEXT        NOT NULL,
    contenido   JSONB       NOT NULL,
    activa      BOOLEAN     NOT NULL DEFAULT FALSE,
    creada_en   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Solo puede haber UNA politica activa. Que lo garantice la base de datos y no
-- el codigo: dos politicas activas dejarian la flota en dos configuraciones
-- distintas segun a quien preguntara cada agente.
CREATE UNIQUE INDEX IF NOT EXISTS idx_politica_unica_activa ON politicas (activa) WHERE activa;

-- ---------------------------------------------------------------------------
-- Comandos pendientes por agente (respuesta de un clic desde el panel)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS comandos (
    id              UUID        PRIMARY KEY,
    cn_agente       TEXT        NOT NULL REFERENCES agentes (cn) ON DELETE CASCADE,
    -- 'aislar' | 'liberar' | 'escanear' | 'recoger_forense'
    accion          TEXT        NOT NULL,
    parametros      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    creado_en       TIMESTAMPTZ NOT NULL DEFAULT now(),
    entregado_en    TIMESTAMPTZ,
    -- Quien lo ordeno: sin esto, una accion destructiva sobre un endpoint no
    -- tiene responsable.
    ordenado_por    TEXT        NOT NULL DEFAULT 'sistema'
);

-- El latido pregunta "?hay algo para mi?" en cada ciclo de cada agente: es la
-- consulta mas frecuente de todo el sistema. El indice parcial la deja en una
-- busqueda sobre las pocas filas sin entregar.
CREATE INDEX IF NOT EXISTS idx_comandos_pendientes ON comandos (cn_agente, creado_en)
    WHERE entregado_en IS NULL;

-- ---------------------------------------------------------------------------
-- Politica inicial: la flota nunca debe arrancar sin una version de referencia.
-- ---------------------------------------------------------------------------
INSERT INTO politicas (version, nombre, contenido, activa)
VALUES (1, 'linea-base', '{"descripcion":"politica inicial de referencia"}'::jsonb, TRUE)
ON CONFLICT (version) DO NOTHING;
