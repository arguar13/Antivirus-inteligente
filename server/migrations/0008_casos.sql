-- 0008 · Casos, tareas y el rastro de auditoria encadenado
--
-- POR QUE EL RASTRO ES UNA TABLA APARTE Y NO UNAS COLUMNAS EN `casos`
--
-- Porque un caso de seguridad es potencialmente prueba judicial, y lo que hace
-- que sirva como tal no es que se guarde: es que no se pueda cambiar despues sin
-- que se note. Unas columnas `modificado_por` y `modificado_en` se sobrescriben
-- con un UPDATE y no queda nada.
--
-- Aqui cada cambio es una FILA NUEVA que lleva el resumen de la anterior. Alterar
-- una invalida el resumen de la siguiente, que invalida el de la siguiente, y asi
-- hasta el final: no se puede cambiar una linea sin reescribir todo lo que vino
-- despues.
--
-- Y LO QUE ESO NO GARANTIZA, dicho en la propia migracion para que no se olvide:
-- quien pueda reescribir la cadena ENTERA produce una cadena internamente
-- consistente. Por eso el resumen de la cabeza se ancla fuera periodicamente
-- (tabla `caso_anclas`), por el canal de atestacion que ya existe. A partir de un
-- anclaje, reescribir obliga a cuadrar con un valor que ya salio del sistema.
--
-- La frontera queda escrita: TODO LO ANTERIOR AL ULTIMO ANCLAJE ES INMUTABLE; LO
-- POSTERIOR ES DETECTABLE.

CREATE TABLE IF NOT EXISTS casos (
    id                  TEXT        PRIMARY KEY,
    inquilino           TEXT        NOT NULL,
    titulo              TEXT        NOT NULL,
    -- nuevo | en-curso | en-espera | contenido | cerrado
    --
    -- `en-espera` y `contenido` existen como estados propios y no como banderas
    -- porque si no, el tiempo esperando al cliente se cuenta como tiempo de
    -- trabajo del equipo, y «contenido» se confunde con «cerrado» — que hace que
    -- las metricas digan que se cierra mas rapido de lo que se cierra.
    estado              TEXT        NOT NULL DEFAULT 'nuevo',
    severidad           TEXT        NOT NULL,
    clase               TEXT        NOT NULL DEFAULT 'sin-clasificar',
    asignado_a          TEXT,
    -- Cuando ocurrio lo mas antiguo del caso, NO cuando se creo la fila: si una
    -- alerta mas vieja se fusiona despues, el caso empezo antes. Con la hora de
    -- creacion, la metrica de tiempo hasta deteccion sale corta justo en los
    -- ataques largos, que son los graves.
    abierto_en          TIMESTAMPTZ NOT NULL,
    primer_vistazo_en   TIMESTAMPTZ,
    contenido_en        TIMESTAMPTZ,
    cerrado_en          TIMESTAMPTZ,
    -- verdadero | falso-positivo | autorizado | no-concluyente
    --
    -- El tri-estado es obligatorio: sin `no-concluyente`, un caso que nadie pudo
    -- resolver se cierra como falso positivo, y entonces la metrica que decide
    -- que reglas se apagan cuenta como ruido una investigacion a medias.
    veredicto           TEXT,
    justificacion_cierre TEXT,
    tecnicas            TEXT[]      NOT NULL DEFAULT '{}',
    CONSTRAINT estado_conocido CHECK (
        estado IN ('nuevo', 'en-curso', 'en-espera', 'contenido', 'cerrado')),
    CONSTRAINT veredicto_conocido CHECK (
        veredicto IS NULL OR
        veredicto IN ('verdadero', 'falso-positivo', 'autorizado', 'no-concluyente')),
    -- Un caso cerrado SIN veredicto no puede existir: es exactamente la fila que
    -- rompe todas las metricas del SOC y nadie la nota.
    CONSTRAINT cerrado_con_veredicto CHECK (
        estado <> 'cerrado' OR veredicto IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_casos_abiertos
    ON casos (inquilino, abierto_en DESC) WHERE estado <> 'cerrado';
CREATE INDEX IF NOT EXISTS idx_casos_sin_asignar
    ON casos (inquilino) WHERE estado <> 'cerrado' AND asignado_a IS NULL;

-- Alertas fusionadas, con POR QUE entraron.
--
-- El motivo se guarda por alerta y no por caso: cuando un analista mira por que
-- hay trescientas alertas juntas, la respuesta util no es «por campana» sino
-- «esta por sujeto, estas doscientas por campana, y esta por tecnica». Sin eso,
-- una fusion equivocada no se puede ni discutir.
CREATE TABLE IF NOT EXISTS caso_alertas (
    caso        TEXT        NOT NULL REFERENCES casos(id) ON DELETE CASCADE,
    alerta      TEXT        NOT NULL,
    motivo      TEXT        NOT NULL,
    regla       TEXT        NOT NULL,
    anfitrion   TEXT        NOT NULL,
    sujeto      TEXT        NOT NULL,
    tecnica     TEXT,
    ocurrio_en  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (caso, alerta)
);

CREATE INDEX IF NOT EXISTS idx_caso_alertas_regla ON caso_alertas (regla);

CREATE TABLE IF NOT EXISTS caso_observables (
    caso    TEXT NOT NULL REFERENCES casos(id) ON DELETE CASCADE,
    tipo    TEXT NOT NULL,
    valor   TEXT NOT NULL,
    PRIMARY KEY (caso, tipo, valor)
);

CREATE TABLE IF NOT EXISTS caso_tareas (
    caso        TEXT        NOT NULL REFERENCES casos(id) ON DELETE CASCADE,
    id          INTEGER     NOT NULL,
    titulo      TEXT        NOT NULL,
    asignada_a  TEXT,
    estado      TEXT        NOT NULL DEFAULT 'pendiente',
    motivo      TEXT,
    PRIMARY KEY (caso, id),
    CONSTRAINT tarea_estado CHECK (estado IN ('pendiente', 'hecha', 'descartada'))
);

CREATE INDEX IF NOT EXISTS idx_caso_tareas_abiertas
    ON caso_tareas (caso) WHERE estado = 'pendiente';

-- EL RASTRO. Sin UPDATE ni DELETE: solo se inserta.
--
-- POR QUE AQUI **NO** HAY `ON DELETE CASCADE`, Y EN LAS TABLAS DE ARRIBA SI
--
-- Las alertas, los observables y las tareas son CONTENIDO del caso: si el caso
-- se va, se van con el. El rastro no es contenido: es la constancia de quien hizo
-- que. Con CASCADE, un `DELETE FROM casos WHERE id = 'X'` se lleva por delante,
-- EN SILENCIO Y COMO EFECTO SECUNDARIO, la prueba de la unica operacion que mas
-- evidentemente hay que auditar —destruir el caso—. Y ni siquiera hace falta mala
-- fe: basta una purga de retencion escrita sin pensar en esto.
--
-- Con RESTRICT, borrar un caso que tiene rastro es IMPOSIBLE mientras el rastro
-- exista. Y como todo caso nace con su entrada `creado`, en la practica un caso
-- no se borra: se cierra. Si alguna vez hay que purgar de verdad —una baja de
-- inquilino, un derecho de supresion—, hay que borrar el rastro EXPLICITAMENTE
-- primero, que es exactamente la propiedad que se busca: destruir una cadena de
-- custodia tiene que ser un acto deliberado, nunca la consecuencia de otra cosa.
CREATE TABLE IF NOT EXISTS caso_auditoria (
    caso        TEXT        NOT NULL REFERENCES casos(id) ON DELETE RESTRICT,
    secuencia   BIGINT      NOT NULL,
    actor       TEXT        NOT NULL,
    accion      TEXT        NOT NULL,
    detalle     TEXT        NOT NULL DEFAULT '',
    cuando      TIMESTAMPTZ NOT NULL,
    anterior    TEXT        NOT NULL,
    resumen     TEXT        NOT NULL,
    PRIMARY KEY (caso, secuencia),
    -- Una entrada sin actor no es una entrada de auditoria: es un registro de
    -- sucesos, que es otra cosa. Si el cambio lo hizo el sistema, el actor es el
    -- sistema y se dice.
    CONSTRAINT actor_no_vacio CHECK (length(trim(actor)) > 0)
);

-- El resumen de la cabeza es unico: dos entradas con el mismo resumen
-- significarian que la cadena se bifurco, que solo puede pasar si alguien la
-- manipulo.
CREATE UNIQUE INDEX IF NOT EXISTS idx_caso_auditoria_resumen
    ON caso_auditoria (resumen);

-- Los anclajes publicados. Es lo unico que detecta una reescritura COMPLETA.
--
-- RESTRICT por la misma razon que el rastro, y con mas motivo: el anclaje es el
-- valor contra el que se comprueba que el rastro no se reescribio entero. Borrarlo
-- como efecto secundario dejaria la cadena sin nada con que contrastarla, que es
-- justo lo que buscaria quien la reescribiera.
CREATE TABLE IF NOT EXISTS caso_anclas (
    caso        TEXT        NOT NULL REFERENCES casos(id) ON DELETE RESTRICT,
    hasta       BIGINT      NOT NULL,
    resumen     TEXT        NOT NULL,
    publicado_en TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Referencia al asiento del canal de atestacion donde salio del sistema.
    -- NULL significa que todavia no salio, y eso es un dato: hasta que sale, la
    -- cadena solo esta protegida contra manipulacion parcial.
    atestacion  TEXT,
    PRIMARY KEY (caso, hasta)
);
