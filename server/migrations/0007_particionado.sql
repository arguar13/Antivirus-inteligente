-- 0007 · Particionado por tiempo e inquilino, y la tabla de eventos normalizados
--
-- POR QUE ESTA MIGRACION EXISTE
--
-- Cien mil agentes generando un evento de seguridad al minuto son 144 millones
-- de filas al dia. El problema no es el tamano: es la PURGA.
--
-- Borrar con DELETE en una tabla asi escribe en el registro de transacciones
-- tanto como escribio la insercion original, no devuelve el espacio, mantiene
-- abierta una transaccion larga que bloquea la limpieza de todo lo demas, y
-- tarda cada dia un poco mas — hasta el dia en que no acaba antes de que empiece
-- la siguiente. Ese dia mata la instalacion y llega sin aviso.
--
-- Con particionado declarativo, la purga es un DROP de la particion entera:
-- constante, sin registro proporcional a las filas, sin filas muertas que
-- aspirar, y sin bloquear la ingesta de las particiones vivas.
--
-- EL ORDEN DE LAS DIMENSIONES NO ES ARBITRARIO
--
--   RANGO por tiempo PRIMERO, porque es la dimension por la que se PURGA, y la
--   purga es la operacion que decide si el sistema sobrevive. Particionar
--   primero por inquilino obligaria a borrar DENTRO de cada particion, que es
--   volver al DELETE.
--
--   HASH por inquilino DENTRO, porque es la dimension por la que se CONSULTA: un
--   analista mira su organizacion. Sin ese corte, cada consulta de un cliente
--   recorre los datos de todos, y ademas el aislamiento dependeria solo de que
--   la clausula WHERE este bien escrita en todas partes.
--
-- LAS PARTICIONES MENSUALES NO ESTAN AQUI
--
-- Las crea el arranque del servidor con `aegis_scale::particion::planificar`,
-- que ademas crea TRES MESES POR ADELANTADO. Sin adelanto, la primera insercion
-- del mes que viene falla porque no existe su particion, y falla a las cero
-- horas del dia uno, que es cuando menos gente esta mirando.
--
-- Ponerlas aqui las congelaria en el mes en que se escribio la migracion.

-- ---------------------------------------------------------------------------
-- Los eventos normalizados de AegisIngest (FASE 74).
--
-- Es la tabla que mas crece de todo el producto: recibe lo que escribe el resto
-- de la casa —syslog, journald, EVTX, ficheros y nubes—, no solo la telemetria
-- propia. Nace particionada.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eventos_normalizados (
    -- Identificador de deduplicacion, derivado del contenido Y DEL ANCLA.
    --
    -- Del ancla tambien, y no solo del contenido: veinte fallos de contrasena
    -- identicos byte a byte en el mismo segundo —RFC 3164 fecha con resolucion
    -- de segundo— se fundirian en uno, y la deteccion de fuerza bruta veria un
    -- intento aislado donde hubo veinte.
    id              TEXT        NOT NULL,
    -- De donde salio exactamente el registro dentro de su origen.
    ancla           TEXT        NOT NULL,
    -- Version del esquema con el que se normalizo. Un evento de una version
    -- desconocida NO se interpreta: leerlo mal produce correlaciones
    -- silenciosamente equivocadas, que es peor que no tenerlas.
    esquema         INTEGER     NOT NULL,
    inquilino       TEXT        NOT NULL,
    anfitrion       TEXT        NOT NULL,
    productor       TEXT        NOT NULL,
    -- CUANDO OCURRIO, que es por lo que se ordena y por lo que se particiona.
    ocurrio_en      TIMESTAMPTZ NOT NULL,
    -- Cuando se leyo. Se conserva SIEMPRE: la distancia entre las dos es en si
    -- misma un dato —dice cuanto tardo en llegar— y es lo unico que permite
    -- auditar despues si una hora de ocurrencia era creible.
    observado_en    TIMESTAMPTZ NOT NULL,
    -- De donde salio la hora de ocurrencia: del-origen, sospechosa o
    -- de-llegada. La hora la escribe quien escribe el registro, asi que lo
    -- inverosimil se MARCA, ni se cree ni se tira.
    reloj           TEXT        NOT NULL,
    clase           TEXT        NOT NULL,
    resultado       TEXT        NOT NULL,
    severidad       TEXT        NOT NULL,
    origen          TEXT        NOT NULL,
    mensaje         TEXT        NOT NULL,
    campos          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    -- El registro tal y como llego, si se conserva. Es la evidencia: si la
    -- normalizacion se equivoco, es lo unico que permite verlo despues.
    crudo           BYTEA,
    -- La clave primaria TIENE que incluir la columna de particion: PostgreSQL no
    -- admite un indice unico global sobre una tabla particionada. Con (id,
    -- ocurrio_en, inquilino) la deduplicacion sigue siendo exacta dentro de la
    -- ventana que importa, que es la que aplica el plano de control en memoria.
    PRIMARY KEY (id, ocurrio_en, inquilino)
) PARTITION BY RANGE (ocurrio_en);

-- Los indices se declaran en el PADRE: PostgreSQL los propaga a cada particion
-- nueva automaticamente. Declararlos particion a particion es como se acaba con
-- un mes sin indices que nadie nota hasta que una consulta tarda un minuto.
CREATE INDEX IF NOT EXISTS idx_eventos_inquilino_tiempo
    ON eventos_normalizados (inquilino, ocurrio_en DESC);
CREATE INDEX IF NOT EXISTS idx_eventos_anfitrion
    ON eventos_normalizados (anfitrion, ocurrio_en DESC);
CREATE INDEX IF NOT EXISTS idx_eventos_clase
    ON eventos_normalizados (clase, ocurrio_en DESC);

-- ---------------------------------------------------------------------------
-- Registro de las particiones que existen y de las que se purgaron.
--
-- No es decorativo: sin el, «faltan los datos de marzo» no se puede distinguir
-- de «marzo se purgo el dia tal por la politica de retencion», y esa diferencia
-- importa cuando lo que se busca es evidencia de un incidente.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS particiones (
    tabla           TEXT        NOT NULL,
    mes             DATE        NOT NULL,
    creada_en       TIMESTAMPTZ NOT NULL DEFAULT now(),
    purgada_en      TIMESTAMPTZ,
    -- Por que se purgo: la politica de retencion, o una orden manual. Un borrado
    -- manual de datos de seguridad tiene que dejar rastro.
    motivo_purga    TEXT,
    filas_al_purgar BIGINT,
    PRIMARY KEY (tabla, mes)
);

CREATE INDEX IF NOT EXISTS idx_particiones_vivas
    ON particiones (tabla, mes) WHERE purgada_en IS NULL;

-- ---------------------------------------------------------------------------
-- Cuotas por inquilino.
--
-- Viven en la base de datos y no en un fichero de configuracion porque un plano
-- de control con varios nodos tiene que aplicar la MISMA cuota en todos: con un
-- fichero por nodo, un cliente ruidoso encuentra el nodo cuyo fichero nadie
-- actualizo.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cuotas_inquilino (
    inquilino           TEXT        PRIMARY KEY,
    eventos_por_segundo BIGINT      NOT NULL DEFAULT 1000,
    rafaga              BIGINT      NOT NULL DEFAULT 10000,
    -- La parte reservada a la telemetria de seguridad.
    --
    -- Con un solo cubo, un atacante genera ruido en cualquier aplicacion del
    -- cliente, agota su cuota, y sus PROPIAS huellas dejan de subir. No tendria
    -- que hacer nada mas.
    reserva_seguridad   BIGINT      NOT NULL DEFAULT 2000,
    actualizado_en      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT cuota_positiva CHECK (eventos_por_segundo > 0 AND rafaga > 0),
    CONSTRAINT reserva_cabe CHECK (reserva_seguridad <= rafaga)
);

-- ---------------------------------------------------------------------------
-- Nodos del plano de control.
--
-- El reparto de la flota es una FUNCION PURA de (agente, lista de nodos): dos
-- nodos con la misma lista calculan la misma asignacion sin hablar entre ellos.
-- Esta tabla es esa lista, y la epoca es lo que impide que un mapa viejo y
-- autentico redirija a una fraccion de la flota hacia nodos que ya no existen.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS nodos_plano_control (
    id              TEXT        PRIMARY KEY,
    direccion       TEXT        NOT NULL,
    -- Capacidad relativa: un nodo con el doble de peso se lleva el doble de
    -- agentes. Existe porque una flota real no corre sobre maquinas iguales.
    peso            INTEGER     NOT NULL DEFAULT 100,
    version_mayor   INTEGER     NOT NULL DEFAULT 1,
    version_menor   INTEGER     NOT NULL DEFAULT 0,
    -- drenando: no acepta conexiones nuevas pero atiende las que tiene. Es la
    -- fase que casi siempre falta en una actualizacion progresiva, y sin ella
    -- actualizar un nodo corta de golpe sus conexiones y provoca la manada.
    fase            TEXT        NOT NULL DEFAULT 'activo',
    visto_en        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT peso_positivo CHECK (peso > 0),
    CONSTRAINT fase_conocida CHECK (fase IN ('activo', 'drenando', 'parado'))
);

CREATE TABLE IF NOT EXISTS epoca_membresia (
    id      BOOLEAN PRIMARY KEY DEFAULT TRUE,
    epoca   BIGINT  NOT NULL DEFAULT 1,
    CONSTRAINT unica_fila CHECK (id)
);

INSERT INTO epoca_membresia (id, epoca) VALUES (TRUE, 1)
    ON CONFLICT (id) DO NOTHING;
