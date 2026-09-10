Certificados de CA adicionales para la construccion hermetica
=============================================================

Deja aqui los `.crt` (formato PEM) de cualquier autoridad certificadora que
haga falta para llegar a la red desde dentro de la imagen: tipicamente la CA de
un proxy corporativo con inspeccion TLS.

El `Dockerfile` copia este directorio a `/usr/local/share/ca-certificates/` y
ejecuta `update-ca-certificates`, de modo que `curl`, `git` y `cargo` confien en
ella. Si el directorio solo contiene este fichero, no se anade ninguna CA y la
imagen usa el almacen de confianza estandar.

No se versiona ningun certificado: los de cada organizacion son suyos.
