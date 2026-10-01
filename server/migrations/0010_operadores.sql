-- 0010 · Operadores de la consola con credencial verificada (H-02)
--
-- Hasta aqui, POST /api/sesion emitia una sesion a cualquier nombre no vacio.
-- Esta tabla guarda el DERIVADO de la clave de cada operador (PBKDF2-HMAC-SHA256,
-- ver server/crates/aegis-server/src/credenciales.rs), nunca la clave.
--
-- El alta se hace con `aegis-server alta-operador <usuario>`, que lee la clave
-- de la entrada estandar. No hay operador por defecto: un plano de control
-- recien instalado no admite ninguna sesion hasta que alguien da de alta uno,
-- que es exactamente lo que se quiere.

CREATE TABLE IF NOT EXISTS operadores (
    usuario         TEXT        PRIMARY KEY
                    CHECK (length(usuario) BETWEEN 1 AND 128),
    hash_clave      TEXT        NOT NULL
                    CHECK (hash_clave LIKE 'pbkdf2-sha256$%'),
    activo          BOOLEAN     NOT NULL DEFAULT TRUE,
    creado_en       TIMESTAMPTZ NOT NULL DEFAULT now(),
    ultimo_acceso   TIMESTAMPTZ
);
