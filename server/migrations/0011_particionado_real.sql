-- 0011 · Particionado REAL: particiones mensuales que existen, y purga por DROP
--
-- LO QUE DECIA LA 0007 Y NO ERA VERDAD (H-19)
--
-- La 0007 declaro `eventos_normalizados` como PARTITION BY RANGE y escribio que
-- «las particiones mensuales las crea el arranque del servidor con
-- aegis_scale::particion::planificar, que ademas crea TRES MESES POR
-- ADELANTADO». Nadie las creaba: aegis-server no dependia de aegis-scale ni
-- llamaba a nada parecido. La tabla quedo como un padre sin hijas y sin
-- particion DEFAULT, en el que cualquier INSERT habria fallado. Tampoco existia
-- el corte HASH por inquilino que el comentario describe.
--
-- Y la tabla que crece de verdad —`alertas`, la unica en la que escribe la
-- ingesta (`Almacen::registrar_alerta`)— no estaba particionada. Su purga habria
-- sido el DELETE masivo que la propia 0007 describe como la bomba de relojeria.
--
-- La 0007 NO se reescribe: sqlx guarda la suma de cada migracion aplicada, y una
-- migracion editada impide arrancar a toda base ya migrada. Se corrige aqui.
--
-- LO QUE HACE ESTA
--
-- 1. Tres funciones que mantienen las particiones VIVEN EN LA BASE:
--      aegis_particion_crear(tabla, mes)
--      aegis_particiones_asegurar(tabla, adelanto_meses[, ahora])
--      aegis_particiones_purgar(tabla, retencion_meses[, motivo[, ahora]])
--    El servidor las llama al arrancar y cada hora (`aegis_server::particiones`)
--    y las pruebas las ejercen contra PostgreSQL real
--    (`server/crates/aegis-server/tests/particionado.rs`). Viven aqui y no en
--    Rust porque varios nodos del plano de control pueden mantener a la vez: se
--    serializan con un cerrojo consultivo y cada llamada es una transaccion.
-- 2. `alertas` pasa a PARTITION BY RANGE (recibido_en), una hija por mes UTC.
-- 3. `eventos_normalizados` recibe sus hijas, por `ocurrio_en`.
--
-- POR QUE `recibido_en` Y NO `ocurrido_en` EN LAS ALERTAS
--
-- `recibido_en` lo pone el reloj del SERVIDOR (DEFAULT now()). `ocurrido_en` lo
-- declara el agente: un endpoint con el reloj desviado —o uno comprometido—
-- podria mandar alertas de 1970 o de 2099, que no tendrian hija (el INSERT se
-- rechazaria y la alerta se perderia) o caerian en un mes ya purgado. Con la
-- hora de llegada, toda alerta cae en el mes en curso, que siempre existe.
-- Coste: las consultas de correlacion, que filtran por `ocurrido_en`, no podan
-- particiones; recorren el indice de cada hija (una por mes retenido).
--
-- LO QUE NO HACE
--
-- - No hay subparticion HASH por inquilino: `alertas` no tiene columna de
--   inquilino (el inquilino es `agentes.id_flota`), y en `eventos_normalizados`
--   nadie escribe todavia. Se deja dicho para que nadie lo vuelva a dar por
--   hecho.
-- - No hay particion DEFAULT, a proposito: se tragaria las filas sin hija y
--   despues impediria crear la hija de ese mes («updated partition constraint
--   for default partition would be violated»). Sin hija, el INSERT falla y se
--   ve; por eso las hijas se crean con tres meses de adelanto.
-- - No se purga nada en esta migracion: una migracion no borra datos. La purga
--   la hace el servidor con la retencion configurada (AEGIS_RETENCION_MESES).
--
-- COSTE DE LA CONVERSION
--
-- PostgreSQL no convierte una tabla en particionada: se crea la nueva, se copian
-- las filas y se tira la vieja, en la transaccion de la migracion. Con muchas
-- alertas, el primer arranque tras actualizar tarda lo que tarde esa copia.

-- ---------------------------------------------------------------------------
-- El registro de particiones (tabla `particiones`, 0007) pasa a usarse.
-- ---------------------------------------------------------------------------
COMMENT ON COLUMN particiones.filas_al_purgar IS
    'Estimacion del planificador (pg_class.reltuples) en el momento de purgar; '
    'NULL si la hija no se habia analizado nunca. No es un count(*): contar '
    'recorreria la particion entera, que es justo el barrido que la purga evita.';

-- ---------------------------------------------------------------------------
-- aegis_particion_crear: la hija de un mes, si falta.
--
-- Devuelve TRUE si la creo y FALSE si ya existia. Los limites son el primer
-- instante del mes en UTC y el del mes siguiente, sea cual sea la zona horaria
-- de la sesion: dos nodos con zonas distintas crean la misma particion.
--
-- Se niega a recrear un mes que el registro da por PURGADO: hacerlo borraria la
-- constancia de que esos datos se tiraron, y «faltan los datos de marzo» dejaria
-- de poder distinguirse de «marzo se purgo el dia tal».
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION aegis_particion_crear(p_tabla TEXT, p_mes DATE)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_mes      DATE        := date_trunc('month', p_mes::timestamp)::date;
    v_hija     TEXT        := p_tabla || '_' || to_char(v_mes, 'YYYY_MM');
    v_desde    TIMESTAMPTZ := v_mes::timestamp AT TIME ZONE 'UTC';
    v_hasta    TIMESTAMPTZ := (v_mes + INTERVAL '1 month')::timestamp AT TIME ZONE 'UTC';
    v_purgada  TIMESTAMPTZ;
BEGIN
    IF p_tabla NOT IN ('alertas', 'eventos_normalizados') THEN
        RAISE EXCEPTION 'aegis_particion_crear: % no es una tabla particionada por mes', p_tabla;
    END IF;

    IF to_regclass(v_hija) IS NOT NULL THEN
        INSERT INTO particiones (tabla, mes) VALUES (p_tabla, v_mes)
            ON CONFLICT (tabla, mes) DO NOTHING;
        RETURN FALSE;
    END IF;

    SELECT purgada_en INTO v_purgada
      FROM particiones
     WHERE tabla = p_tabla AND mes = v_mes;
    IF v_purgada IS NOT NULL THEN
        RAISE EXCEPTION
            'el mes % de % se purgo el %: recrearlo borraria la constancia de la purga',
            to_char(v_mes, 'YYYY-MM'), p_tabla, v_purgada;
    END IF;

    EXECUTE format(
        'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
        v_hija, p_tabla, v_desde, v_hasta
    );
    INSERT INTO particiones (tabla, mes) VALUES (p_tabla, v_mes)
        ON CONFLICT (tabla, mes) DO UPDATE SET creada_en = now();
    RETURN TRUE;
END
$$;

-- ---------------------------------------------------------------------------
-- aegis_particiones_asegurar: el mes en curso y los `p_adelanto_meses`
-- siguientes. Devuelve cuantas hijas creo (0 si ya estaban todas).
--
-- El adelanto es lo que evita que la primera insercion del mes que viene falle
-- a las cero horas del dia uno: con tres meses, un despliegue puede quedarse un
-- trimestre sin mantenimiento sin que la ingesta se pare.
--
-- `lock_timeout` local: crear una hija toma un cerrojo exclusivo breve sobre el
-- padre, y esperar indefinidamente detras de una consulta larga del panel
-- pondria en cola a toda la ingesta. Mejor fallar, registrarlo y reintentar en
-- la siguiente vuelta, que para eso esta el adelanto.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION aegis_particiones_asegurar(
    p_tabla          TEXT,
    p_adelanto_meses INTEGER,
    p_ahora          TIMESTAMPTZ DEFAULT now()
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_actual  DATE    := date_trunc('month', p_ahora AT TIME ZONE 'UTC')::date;
    v_creadas INTEGER := 0;
BEGIN
    IF p_adelanto_meses IS NULL OR p_adelanto_meses < 1 THEN
        RAISE EXCEPTION 'aegis_particiones_asegurar: adelanto % (tiene que ser >= 1)', p_adelanto_meses;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('aegis_particiones'));
    PERFORM set_config('lock_timeout', '2s', true);

    FOR i IN 0..p_adelanto_meses LOOP
        IF aegis_particion_crear(p_tabla, (v_actual + make_interval(months => i))::date) THEN
            v_creadas := v_creadas + 1;
        END IF;
    END LOOP;
    RETURN v_creadas;
END
$$;

-- ---------------------------------------------------------------------------
-- aegis_particiones_purgar: suelta con DROP TABLE las hijas de los meses
-- anteriores a (mes en curso - p_retencion_meses). Devuelve cuantas solto.
--
-- NUNCA DELETE. Un DROP de la hija es constante: no escribe en el WAL una
-- entrada por fila, no deja filas muertas que aspirar y no mantiene abierta una
-- transaccion larga.
--
-- POR QUE NO `DETACH ... CONCURRENTLY`: no puede ejecutarse dentro de un bloque
-- de transaccion ni de una funcion, y si se interrumpe deja la hija a medio
-- separar. El DROP toma un cerrojo exclusivo sobre el padre durante
-- milisegundos; `lock_timeout` acota la espera para que la purga ceda ante la
-- ingesta en vez de ponerla en cola. Si no consigue el cerrojo, falla entera y
-- se reintenta en la siguiente vuelta.
--
-- Cada hija soltada queda en `particiones` con fecha, motivo y la estimacion de
-- filas. Solo se tocan las hijas con el nombre que pone aegis_particion_crear;
-- una hija ajena (creada a mano) no se purga.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION aegis_particiones_purgar(
    p_tabla           TEXT,
    p_retencion_meses INTEGER,
    p_motivo          TEXT DEFAULT 'retencion',
    p_ahora           TIMESTAMPTZ DEFAULT now()
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_limite   DATE;
    v_hija     RECORD;
    v_mes      DATE;
    v_soltadas INTEGER := 0;
BEGIN
    IF p_tabla NOT IN ('alertas', 'eventos_normalizados') THEN
        RAISE EXCEPTION 'aegis_particiones_purgar: % no es una tabla particionada por mes', p_tabla;
    END IF;
    -- Con 0 se soltaria el mes en curso, que es donde esta entrando la ingesta.
    IF p_retencion_meses IS NULL OR p_retencion_meses < 1 THEN
        RAISE EXCEPTION 'aegis_particiones_purgar: retencion % (tiene que ser >= 1 mes)', p_retencion_meses;
    END IF;
    v_limite := (date_trunc('month', p_ahora AT TIME ZONE 'UTC')
                 - make_interval(months => p_retencion_meses))::date;

    PERFORM pg_advisory_xact_lock(hashtext('aegis_particiones'));
    PERFORM set_config('lock_timeout', '2s', true);

    FOR v_hija IN
        SELECT c.relname::text AS nombre, c.reltuples
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
         WHERE i.inhparent = p_tabla::regclass
         ORDER BY c.relname
    LOOP
        CONTINUE WHEN v_hija.nombre !~ ('^' || p_tabla || '_[0-9]{4}_[0-9]{2}$');
        v_mes := to_date(right(v_hija.nombre, 7), 'YYYY_MM');
        CONTINUE WHEN v_mes >= v_limite;

        EXECUTE format('DROP TABLE %I', v_hija.nombre);
        INSERT INTO particiones (tabla, mes, purgada_en, motivo_purga, filas_al_purgar)
        VALUES (
            p_tabla, v_mes, now(), p_motivo,
            CASE WHEN v_hija.reltuples < 0 THEN NULL ELSE v_hija.reltuples::bigint END
        )
        ON CONFLICT (tabla, mes) DO UPDATE SET
            purgada_en      = EXCLUDED.purgada_en,
            motivo_purga    = EXCLUDED.motivo_purga,
            filas_al_purgar = EXCLUDED.filas_al_purgar;
        v_soltadas := v_soltadas + 1;
    END LOOP;
    RETURN v_soltadas;
END
$$;

-- ---------------------------------------------------------------------------
-- alertas -> PARTITION BY RANGE (recibido_en)
--
-- Mismas columnas, mismo orden, mismos valores por defecto, la misma clave
-- ajena y los mismos siete indices (0001 y 0005), declarados en el PADRE para
-- que PostgreSQL los propague a cada hija nueva.
--
-- La clave primaria pasa de (id) a (id, recibido_en): PostgreSQL no admite una
-- clave unica sobre una tabla particionada que no incluya la columna de
-- particion. `id` es un UUID v4 que genera el servidor; nada hace
-- `ON CONFLICT (id)` sobre alertas ni la referencia con una clave ajena
-- (`caso_alertas.alerta` es TEXT sin FK).
-- ---------------------------------------------------------------------------
ALTER TABLE alertas RENAME TO alertas_sin_particionar;
-- Los nombres de indice son unicos por esquema: los de la tabla vieja se
-- liberan para que los nuevos conserven los suyos.
ALTER TABLE alertas_sin_particionar RENAME CONSTRAINT alertas_pkey TO alertas_sin_particionar_pkey;
DROP INDEX IF EXISTS idx_alertas_recientes;
DROP INDEX IF EXISTS idx_alertas_agente;
DROP INDEX IF EXISTS idx_alertas_abiertas;
DROP INDEX IF EXISTS idx_alertas_tecnica;
DROP INDEX IF EXISTS idx_alertas_correlacion;
DROP INDEX IF EXISTS idx_alertas_categoria_tiempo;
DROP INDEX IF EXISTS idx_alertas_detalles;

CREATE TABLE alertas (
    id              UUID        NOT NULL,
    cn_agente       TEXT        NOT NULL REFERENCES agentes (cn) ON DELETE CASCADE,
    severidad       SMALLINT    NOT NULL CHECK (severidad BETWEEN 0 AND 4),
    categoria       TEXT        NOT NULL,
    descripcion     TEXT        NOT NULL,
    tecnica_mitre   TEXT,
    tactica_mitre   TEXT,
    detalles        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    ocurrido_en     TIMESTAMPTZ NOT NULL,
    -- La hora del SERVIDOR: es la columna de particion (ver arriba).
    recibido_en     TIMESTAMPTZ NOT NULL DEFAULT now(),
    resuelta        BOOLEAN     NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id, recibido_en)
) PARTITION BY RANGE (recibido_en);

COMMENT ON TABLE alertas IS
    'Particionada por mes UTC de recibido_en (0011). Las hijas las crea '
    'aegis_particiones_asegurar y las suelta aegis_particiones_purgar; nunca DELETE masivo.';

CREATE INDEX IF NOT EXISTS idx_alertas_recientes ON alertas (recibido_en DESC);
CREATE INDEX IF NOT EXISTS idx_alertas_agente    ON alertas (cn_agente, recibido_en DESC);
CREATE INDEX IF NOT EXISTS idx_alertas_abiertas  ON alertas (severidad DESC, recibido_en DESC)
    WHERE NOT resuelta;
CREATE INDEX IF NOT EXISTS idx_alertas_tecnica   ON alertas (tecnica_mitre)
    WHERE tecnica_mitre IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alertas_correlacion
    ON alertas (tecnica_mitre, ocurrido_en DESC)
    WHERE tecnica_mitre IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alertas_categoria_tiempo
    ON alertas (categoria, ocurrido_en DESC);
CREATE INDEX IF NOT EXISTS idx_alertas_detalles ON alertas USING GIN (detalles);

COMMENT ON TABLE eventos_normalizados IS
    'Particionada por mes UTC de ocurrio_en (0007; hijas reales desde la 0011). '
    'Sin subparticion por inquilino, aunque el comentario de la 0007 la describa.';

-- ---------------------------------------------------------------------------
-- Las hijas: los meses que ya tienen filas, el mes en curso y tres de adelanto
-- (el mismo adelanto que `aegis_server::particiones::ADELANTO_MESES`; el
-- servidor lo vuelve a asegurar al arrancar). Solo los meses con datos, no
-- todos los intermedios: una fila vieja no obliga a crear cien hijas vacias.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_actual DATE := date_trunc('month', now() AT TIME ZONE 'UTC')::date;
    v_mes    DATE;
BEGIN
    FOR v_mes IN
        SELECT DISTINCT date_trunc('month', recibido_en AT TIME ZONE 'UTC')::date
          FROM alertas_sin_particionar
        UNION
        SELECT (v_actual + make_interval(months => i))::date
          FROM generate_series(0, 3) AS i
    LOOP
        PERFORM aegis_particion_crear('alertas', v_mes);
    END LOOP;

    FOR v_mes IN
        SELECT DISTINCT date_trunc('month', ocurrio_en AT TIME ZONE 'UTC')::date
          FROM eventos_normalizados
        UNION
        SELECT (v_actual + make_interval(months => i))::date
          FROM generate_series(0, 3) AS i
    LOOP
        PERFORM aegis_particion_crear('eventos_normalizados', v_mes);
    END LOOP;
END
$$;

INSERT INTO alertas
    (id, cn_agente, severidad, categoria, descripcion, tecnica_mitre, tactica_mitre,
     detalles, ocurrido_en, recibido_en, resuelta)
SELECT id, cn_agente, severidad, categoria, descripcion, tecnica_mitre, tactica_mitre,
       detalles, ocurrido_en, recibido_en, resuelta
  FROM alertas_sin_particionar;

DROP TABLE alertas_sin_particionar;
