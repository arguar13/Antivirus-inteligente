# Persistencia del plano de control: PostgreSQL, Redis y la CA de la flota.

# --- Credenciales -----------------------------------------------------------
# Las contrasenas se generan aqui y viven en Secrets Manager. Nunca aparecen en
# una variable, en un fichero de configuracion ni en la linea de comandos de un
# proceso, que es donde acaban leyendose por accidente.
resource "random_password" "base_datos" {
  length  = 48
  special = true
  # Se excluyen los caracteres que rompen una cadena de conexion tipo URL.
  override_special = "!#%*_-+=?"
}

resource "aws_secretsmanager_secret" "base_datos" {
  name       = "${var.nombre}/${var.entorno}/postgres"
  kms_key_id = aws_kms_key.datos.arn
  # Margen para recuperar un secreto borrado por error: sin el, un `destroy`
  # equivocado deja la base de datos inaccesible de forma permanente.
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret_version" "base_datos" {
  secret_id = aws_secretsmanager_secret.base_datos.id
  secret_string = jsonencode({
    usuario    = "aegis"
    contrasena = random_password.base_datos.result
    host       = aws_db_instance.principal.address
    puerto     = aws_db_instance.principal.port
    base       = aws_db_instance.principal.db_name
  })
}

resource "random_password" "redis" {
  length  = 64
  special = false # el token de autenticacion de Redis no admite todos los simbolos
}

resource "aws_secretsmanager_secret" "redis" {
  name                    = "${var.nombre}/${var.entorno}/redis"
  kms_key_id              = aws_kms_key.datos.arn
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret_version" "redis" {
  secret_id = aws_secretsmanager_secret.redis.id
  secret_string = jsonencode({
    token = random_password.redis.result
    host  = aws_elasticache_replication_group.principal.primary_endpoint_address
    tls   = true
  })
}

# --- PostgreSQL -------------------------------------------------------------
resource "aws_db_subnet_group" "principal" {
  name       = "${var.nombre}-${var.entorno}"
  subnet_ids = aws_subnet.datos[*].id
}

resource "aws_db_parameter_group" "principal" {
  name   = "${var.nombre}-${var.entorno}-pg16"
  family = "postgres16"

  # TLS obligatorio: el canal entre el plano de control y su base de datos lleva
  # el inventario entero de la flota y sus alertas.
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  # Registrar las conexiones y las sentencias lentas da la primera pista cuando
  # algo va mal, sin necesidad de reproducirlo.
  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "500"
  }
}

resource "aws_db_instance" "principal" {
  identifier     = "${var.nombre}-${var.entorno}"
  engine         = "postgres"
  engine_version = "16.4"
  instance_class = var.clase_base_datos

  db_name  = "aegis"
  username = "aegis"
  password = random_password.base_datos.result

  allocated_storage     = var.almacenamiento_base_datos_gb
  max_allocated_storage = var.almacenamiento_base_datos_gb * 5
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.datos.arn

  db_subnet_group_name   = aws_db_subnet_group.principal.name
  vpc_security_group_ids = [aws_security_group.base_datos.id]
  parameter_group_name   = aws_db_parameter_group.principal.name

  # Nunca accesible desde Internet. Es la afirmacion mas importante del fichero.
  publicly_accessible = false

  # Dos zonas: la caida de una zona no puede dejar sin plano de control a toda
  # la flota justo cuando mas falta hace.
  multi_az = var.entorno == "produccion"

  backup_retention_period  = var.retencion_copias_dias
  backup_window            = "02:00-03:00"
  maintenance_window       = "sun:03:30-sun:04:30"
  delete_automated_backups = false

  # Un `destroy` accidental no puede llevarse por delante el historico de
  # incidentes de un cliente.
  deletion_protection       = var.entorno == "produccion"
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.nombre}-${var.entorno}-final"

  auto_minor_version_upgrade      = true
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.datos.arn

  copy_tags_to_snapshot = true
}

# --- Redis ------------------------------------------------------------------
resource "aws_elasticache_subnet_group" "principal" {
  name       = "${var.nombre}-${var.entorno}"
  subnet_ids = aws_subnet.datos[*].id
}

resource "aws_elasticache_replication_group" "principal" {
  replication_group_id = "${var.nombre}-${var.entorno}"
  description          = "AegisCore ${var.entorno}: sesiones y reputacion k-anonima"

  engine         = "redis"
  engine_version = "7.1"
  node_type      = "cache.m7g.large"
  port           = 6379

  num_cache_clusters         = var.nodos_redis
  automatic_failover_enabled = var.nodos_redis > 1
  multi_az_enabled           = var.nodos_redis > 1

  subnet_group_name  = aws_elasticache_subnet_group.principal.name
  security_group_ids = [aws_security_group.cache.id]

  # Cifrado en transito y en reposo, con token de autenticacion. La cache
  # guarda tokens de sesion de la consola: leerla es suplantar a un operador.
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
  auth_token                 = random_password.redis.result
  kms_key_id                 = aws_kms_key.datos.arn

  snapshot_retention_limit = 7
  snapshot_window          = "01:00-02:00"
  maintenance_window       = "sun:04:30-sun:05:30"

  apply_immediately = false
}

# --- Almacenamiento de la CA de la flota ------------------------------------
# ESTE es el recurso mas delicado del despliegue.
#
# El plano de control ES la autoridad certificadora de la flota. Si esa CA se
# pierde, TODOS los certificados emitidos dejan de validar y los miles de
# endpoints desplegados quedan fuera a la vez, sin forma de volver salvo
# reprovisionarlos uno a uno. Por eso vive en un sistema de ficheros replicado y
# con copias automaticas, no en el disco efimero de una instancia.
resource "aws_efs_file_system" "ca" {
  creation_token = "${var.nombre}-${var.entorno}-ca"
  encrypted      = true
  kms_key_id     = aws_kms_key.datos.arn

  # Sin transicion a clase infrecuente: es un fichero diminuto que se lee en
  # cada arranque, y el ahorro seria nulo frente al riesgo de latencia.
  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"

  tags = { Name = "${var.nombre}-ca-flota" }
}

resource "aws_efs_backup_policy" "ca" {
  file_system_id = aws_efs_file_system.ca.id

  backup_policy {
    status = "ENABLED"
  }
}

resource "aws_efs_mount_target" "ca" {
  count = length(var.zonas)

  file_system_id  = aws_efs_file_system.ca.id
  subnet_id       = aws_subnet.aplicacion[count.index].id
  security_groups = [aws_security_group.ca.id]
}

# El punto de acceso fija dueno y permisos desde el propio almacenamiento: el
# servidor se niega a arrancar si la clave de la CA es legible por otros, asi
# que la infraestructura tiene que entregarla ya con el modo correcto.
resource "aws_efs_access_point" "ca" {
  file_system_id = aws_efs_file_system.ca.id

  posix_user {
    uid = 10001
    gid = 10001
  }

  root_directory {
    path = "/ca"

    creation_info {
      owner_uid   = 10001
      owner_gid   = 10001
      permissions = "0700"
    }
  }

  tags = { Name = "${var.nombre}-ca-punto-acceso" }
}
