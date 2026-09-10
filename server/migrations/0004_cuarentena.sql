-- Micro-segmentacion Zero-Trust: cuarentena de enjambre (FASE 44).
--
-- QUE ES
-- ------
-- Cuando el plano de control confirma que un endpoint esta comprometido, no
-- basta con aislar ESE endpoint: la maquina comprometida seguira intentando
-- moverse lateralmente hacia sus vecinas, y el aislamiento local depende de que
-- el agente de la maquina infectada siga siendo de fiar, que es justo lo que ha
-- dejado de estar claro.
--
-- La cuarentena de enjambre invierte el planteamiento: son TODAS LAS DEMAS
-- maquinas las que dejan de hablar con la comprometida. Cada endpoint sano
-- instala una regla en su propio kernel. Aunque el agente de la maquina
-- infectada este desactivado, secuestrado o mintiendo, sus paquetes no llegan a
-- ninguna parte.
--
-- POR QUE VIVE EN LA BASE DE DATOS
-- --------------------------------
-- Igual que la politica y las cacerias: un endpoint apagado tiene que recibir
-- la cuarentena vigente al reconectar, el plano de control corre con varias
-- instancias, y cortarle la red a una maquina de un cliente es una accion que
-- necesita responsable y registro.

-- La direccion se guarda como INET y no como texto.
--
-- Un texto admite "10.0.0.5 ", "010.0.0.5" y "10.0.0.05", que son la misma
-- direccion escrita de tres formas: con clave de texto se crearian tres
-- cuarentenas distintas para el mismo host y levantar una dejaria las otras
-- dos puestas. INET normaliza y compara por valor.
CREATE TABLE IF NOT EXISTS cuarentena (
    direccion     INET        PRIMARY KEY,
    -- Endpoint por cuya causa se ordeno, si se sabe. Puede ser NULL: tambien se
    -- puede poner en cuarentena una IP externa (un C2 conocido) que no
    -- corresponde a ningun agente.
    cn_origen     TEXT,
    motivo        TEXT        NOT NULL,
    ordenada_por  TEXT        NOT NULL,
    ordenada_en   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Caducidad. Una cuarentena permanente que nadie revisa acaba siendo una
    -- regla de firewall fantasma que nadie sabe por que esta: en tres meses,
    -- alguien reinstala esa maquina y no entiende por que no tiene red.
    -- NULL = hasta que un operador la levante.
    expira_en     TIMESTAMPTZ,
    -- Se levanta marcando, no borrando: hay que poder responder "quien y cuando
    -- dejo entrar otra vez a esa maquina".
    levantada_en  TIMESTAMPTZ,
    levantada_por TEXT
);

CREATE INDEX IF NOT EXISTS idx_cuarentena_vigente
    ON cuarentena (ordenada_en DESC)
    WHERE levantada_en IS NULL;

-- Direccion observada de cada agente.
--
-- La escribe el servidor desde el SOCKET de la conexion mTLS, nunca desde lo que
-- el agente declare: si el agente pudiera declararla, uno comprometido pondria
-- en cuarentena al controlador de dominio. Ver `ManejadorFlota::visto_en`.
ALTER TABLE agentes ADD COLUMN IF NOT EXISTS direccion_vista INET;
ALTER TABLE agentes ADD COLUMN IF NOT EXISTS direccion_vista_en TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_agentes_direccion
    ON agentes (direccion_vista) WHERE direccion_vista IS NOT NULL;
