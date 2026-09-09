# Cifrado, identidades y cortafuegos del plano de control.

data "aws_caller_identity" "actual" {}

# --- Claves de cifrado ------------------------------------------------------
# Claves propias y no las gestionadas por AWS: con una clave propia se puede
# revocar el acceso a los datos en reposo sin borrarlos, y su uso queda
# registrado. Con la clave por defecto del servicio, no.
resource "aws_kms_key" "datos" {
  description             = "AegisCore ${var.entorno}: datos en reposo (PostgreSQL, Redis, EFS)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "datos" {
  name          = "alias/${var.nombre}-${var.entorno}-datos"
  target_key_id = aws_kms_key.datos.key_id
}

resource "aws_kms_key" "registros" {
  description             = "AegisCore ${var.entorno}: registros"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  # CloudWatch Logs necesita permiso explicito para cifrar con esta clave.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RaizDeLaCuenta"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.actual.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "RegistrosDeCloudWatch"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
      }
    ]
  })
}

# --- Grupos de seguridad ----------------------------------------------------
# Reglas separadas del grupo (y no en linea) para que anadir una no obligue a
# recrear el grupo entero y con el, momentaneamente, dejar de proteger.

resource "aws_security_group" "consola" {
  name        = "${var.nombre}-consola"
  description = "Balanceador de la consola de administracion"
  vpc_id      = aws_vpc.principal.id
  tags        = { Name = "${var.nombre}-consola" }
}

resource "aws_vpc_security_group_ingress_rule" "consola_https" {
  for_each = toset(var.redes_administracion)

  security_group_id = aws_security_group.consola.id
  description       = "Consola HTTPS desde red de administracion"
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "consola_salida" {
  security_group_id            = aws_security_group.consola.id
  description                  = "Hacia el plano de control"
  referenced_security_group_id = aws_security_group.servidor.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "flota" {
  name        = "${var.nombre}-flota"
  description = "Balanceador de red del canal de flota (mTLS de extremo a extremo)"
  vpc_id      = aws_vpc.principal.id
  tags        = { Name = "${var.nombre}-flota" }
}

resource "aws_vpc_security_group_ingress_rule" "flota_mtls" {
  for_each = toset(var.redes_flota)

  security_group_id = aws_security_group.flota.id
  description       = "Canal de flota mTLS"
  cidr_ipv4         = each.value
  from_port         = 8443
  to_port           = 8443
  ip_protocol       = "tcp"
}

resource "aws_security_group" "servidor" {
  name        = "${var.nombre}-servidor"
  description = "Instancias del plano de control"
  vpc_id      = aws_vpc.principal.id
  tags        = { Name = "${var.nombre}-servidor" }
}

resource "aws_vpc_security_group_ingress_rule" "servidor_consola" {
  security_group_id            = aws_security_group.servidor.id
  description                  = "API de la consola, solo desde su balanceador"
  referenced_security_group_id = aws_security_group.consola.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "servidor_flota" {
  security_group_id = aws_security_group.servidor.id
  description       = "Canal de flota; el balanceador de red no reescribe el origen"
  cidr_ipv4         = var.cidr_vpc
  from_port         = 8443
  to_port           = 8443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "servidor_salida" {
  security_group_id = aws_security_group.servidor.id
  description       = "Salida a servicios de AWS y actualizaciones"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "base_datos" {
  name        = "${var.nombre}-postgres"
  description = "PostgreSQL del plano de control"
  vpc_id      = aws_vpc.principal.id
  tags        = { Name = "${var.nombre}-postgres" }
}

resource "aws_vpc_security_group_ingress_rule" "postgres" {
  security_group_id            = aws_security_group.base_datos.id
  description                  = "Solo desde el plano de control"
  referenced_security_group_id = aws_security_group.servidor.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "cache" {
  name        = "${var.nombre}-redis"
  description = "Redis del plano de control"
  vpc_id      = aws_vpc.principal.id
  tags        = { Name = "${var.nombre}-redis" }
}

resource "aws_vpc_security_group_ingress_rule" "redis" {
  security_group_id            = aws_security_group.cache.id
  description                  = "Solo desde el plano de control"
  referenced_security_group_id = aws_security_group.servidor.id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "ca" {
  name        = "${var.nombre}-efs-ca"
  description = "Almacenamiento persistente de la CA de la flota"
  vpc_id      = aws_vpc.principal.id
  tags        = { Name = "${var.nombre}-efs-ca" }
}

resource "aws_vpc_security_group_ingress_rule" "ca_nfs" {
  security_group_id            = aws_security_group.ca.id
  description                  = "NFS solo desde el plano de control"
  referenced_security_group_id = aws_security_group.servidor.id
  from_port                    = 2049
  to_port                      = 2049
  ip_protocol                  = "tcp"
}

# --- Identidad de las instancias -------------------------------------------
resource "aws_iam_role" "servidor" {
  name = "${var.nombre}-${var.entorno}-servidor"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# El plano de control solo puede leer SUS secretos y descifrar con SU clave.
# Un comodin aqui convertiria una intrusion en la instancia en acceso a los
# secretos de toda la cuenta.
resource "aws_iam_role_policy" "servidor_secretos" {
  name = "secretos"
  role = aws_iam_role.servidor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [aws_secretsmanager_secret.base_datos.arn, aws_secretsmanager_secret.redis.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [aws_kms_key.datos.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"]
        Resource = [aws_efs_file_system.ca.arn]
      }
    ]
  })
}

# Acceso por gestor de sesiones en vez de SSH: no hay puerto 22 abierto, no hay
# claves que rotar y cada sesion queda registrada con su usuario.
resource "aws_iam_role_policy_attachment" "servidor_ssm" {
  role       = aws_iam_role.servidor.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "servidor" {
  name = "${var.nombre}-${var.entorno}-servidor"
  role = aws_iam_role.servidor.name
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.nombre}-${var.entorno}-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "escritura"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}
