-- 0009 · Lo que los flujos de respuesta (FASE 97) tocan y aun no tenia tabla
--
-- Aislar, matar y poner en cuarentena ya tenian su sitio: la tabla `comandos`
-- (el mismo camino que el boton de la consola y la remediacion de la FASE 64) y
-- la cuarentena de red de la FASE 44. Abrir un caso escribe en `casos` y en su
-- rastro encadenado. Lo que faltaba es lo que no vive en un endpoint: la cuenta
-- de un directorio y la notificacion a una persona.
--
-- POR QUE SON ESTADO Y NO SOLO ORDENES
--
-- Un flujo que falla a medias se revierte volviendo al estado de ANTES. Para
-- eso hay que poder preguntar «¿esta cuenta ya estaba deshabilitada antes del
-- flujo?». Con solo una cola de ordenes, la respuesta exigiria reconstruir la
-- historia entera del directorio; con una fila de estado, es una lectura.

-- Cuentas deshabilitadas por la respuesta.
--
-- Se rehabilita MARCANDO, no borrando, por la misma razon que la cuarentena de
-- red: hay que poder responder «quien y cuando devolvio el acceso a esta
-- cuenta».
CREATE TABLE IF NOT EXISTS cuentas_deshabilitadas (
    cuenta           TEXT        PRIMARY KEY,
    -- La orden que la deshabilito: distingue un reintento de la MISMA ejecucion
    -- (que no debe tomarse por «ya estaba deshabilitada») de otra orden.
    orden            UUID        NOT NULL,
    ordenada_por     TEXT        NOT NULL,
    ordenada_en      TIMESTAMPTZ NOT NULL DEFAULT now(),
    rehabilitada_en  TIMESTAMPTZ,
    rehabilitada_por TEXT,
    CONSTRAINT cuenta_no_vacia CHECK (length(trim(cuenta)) > 0)
);

-- Ordenes al conector del directorio (FASE 58): deshabilitar, rehabilitar,
-- revocar tickets. El conector las aplica y marca `aplicada_en`.
--
-- El identificador lo DERIVA el flujo de la ejecucion, el paso y el objetivo:
-- reintentar la misma ejecucion choca con la clave primaria y no encola dos
-- veces la misma orden.
CREATE TABLE IF NOT EXISTS ordenes_directorio (
    id            UUID        PRIMARY KEY,
    cuenta        TEXT        NOT NULL,
    accion        TEXT        NOT NULL,
    ordenada_por  TEXT        NOT NULL,
    creada_en     TIMESTAMPTZ NOT NULL DEFAULT now(),
    aplicada_en   TIMESTAMPTZ,
    CONSTRAINT accion_directorio CHECK (
        accion IN ('deshabilitar', 'rehabilitar', 'revocar_tickets'))
);

CREATE INDEX IF NOT EXISTS idx_ordenes_directorio_pendientes
    ON ordenes_directorio (creada_en) WHERE aplicada_en IS NULL;

-- Notificaciones a personas, como bandeja de salida.
--
-- Una notificacion enviada no se puede des-enviar. Revertirla es una
-- COMPENSACION: si aun no salio se anula; si ya salio, se envia otra que la
-- rectifica y la referencia. Las dos cosas quedan aqui.
CREATE TABLE IF NOT EXISTS notificaciones (
    id          UUID        PRIMARY KEY,
    destino     TEXT        NOT NULL,
    texto       TEXT        NOT NULL,
    creada_por  TEXT        NOT NULL,
    creada_en   TIMESTAMPTZ NOT NULL DEFAULT now(),
    enviada_en  TIMESTAMPTZ,
    anulada_en  TIMESTAMPTZ,
    rectifica   UUID        REFERENCES notificaciones (id) ON DELETE RESTRICT,
    -- Anulada y enviada a la vez no puede ser: o salio o no salio.
    CONSTRAINT anulada_o_enviada CHECK (anulada_en IS NULL OR enviada_en IS NULL)
);

CREATE INDEX IF NOT EXISTS idx_notificaciones_pendientes
    ON notificaciones (creada_en) WHERE enviada_en IS NULL AND anulada_en IS NULL;
