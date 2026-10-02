-- Estado que declara el agente (H-23, E6.5 del MP-16).
--
-- El agente publicado late con el estado de sus motores (cuales corren, cuales
-- no pudieron registrarse y por que, cuantas veces no pudieron mirar) y con la
-- cuenta de su enlace con el plano de control: ofrecidos, enviados, en cola y
-- perdidos por causa. Es lo que permite al operador ver, por endpoint, si la
-- deteccion esta entera y si algo se perdio por el camino.
--
-- Una columna JSONB y no tablas: el estado se REEMPLAZA en cada latido (no es
-- historico) y su forma la decide el agente; el plano de control solo exige que
-- sea un objeto JSON acotado (`dominio::normalizar_estado_agente`).
ALTER TABLE agentes ADD COLUMN IF NOT EXISTS estado_agente    JSONB;
ALTER TABLE agentes ADD COLUMN IF NOT EXISTS estado_agente_en TIMESTAMPTZ;
