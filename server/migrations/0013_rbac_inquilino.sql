-- RBAC e inquilino ligados al operador; cazas con inquilino (H-03, FASE 6.2 del MP-16)
--
-- Hasta aqui la sesion solo guardaba el usuario: ni rol ni inquilino. El RBAC de
-- aegis-consola existia sin cablear y el inquilino era un parametro de consulta
-- que elegia el propio cliente (`?inquilino=`).
--
-- * `operadores.rol`: uno de los cuatro de `aegis_consola::rbac::Rol`. Por
--   defecto `auditor`, el que menos puede: un operador dado de alta antes de
--   esta migracion solo lee hasta que alguien le asigna rol con
--   `aegis-server asignar-rol <usuario> <rol> <inquilino>`.
-- * `operadores.inquilino`: el inquilino de su sesion. Vacio = ninguno: no ve
--   datos de ningun cliente (ningun agente tiene inquilino vacio; el
--   enrolamiento siempre pone `flota-...`). `plataforma` es el inquilino
--   reservado para el contenido global (ver `aegis_server::autorizacion`).
-- * `cacerias.inquilino`: de quien es la caza. Solo se entrega a los agentes de
--   ese inquilino (`Almacen::caza_pendiente_para`). NULL = caza de plataforma o
--   anterior a esta migracion: no la ve ningun cliente por la API.

ALTER TABLE operadores
    ADD COLUMN IF NOT EXISTS rol TEXT NOT NULL DEFAULT 'auditor'
        CHECK (rol IN ('analista', 'responsable', 'administrador', 'auditor'));

ALTER TABLE operadores
    ADD COLUMN IF NOT EXISTS inquilino TEXT NOT NULL DEFAULT ''
        CHECK (length(inquilino) <= 128);

ALTER TABLE cacerias
    ADD COLUMN IF NOT EXISTS inquilino TEXT;

-- La entrega de cazas y el tope de simultaneas filtran por inquilino.
CREATE INDEX IF NOT EXISTS idx_cacerias_inquilino_abiertas
    ON cacerias (inquilino, lanzada_en DESC) WHERE cerrada_en IS NULL;

-- Todos los listados por inquilino entran por aqui.
CREATE INDEX IF NOT EXISTS idx_agentes_id_flota ON agentes (id_flota);
