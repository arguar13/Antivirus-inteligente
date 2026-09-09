# Instancias del plano de control y balanceadores.

# --- Arranque de la instancia ----------------------------------------------
locals {
  # El arranque monta la CA, resuelve los secretos y levanta el servicio. No
  # descarga nada de Internet: el binario ya viene en la AMI que construyo el
  # pipeline, de modo que la instancia arranca con el artefacto auditado y no
  # con lo que hubiera en un repositorio en ese momento.
  arranque = base64encode(templatefile("${path.module}/plantillas/arranque.sh.tftpl", {
    region           = var.region
    efs_id           = aws_efs_file_system.ca.id
    efs_punto_acceso = aws_efs_access_point.ca.id
    secreto_postgres = aws_secretsmanager_secret.base_datos.name
    secreto_redis    = aws_secretsmanager_secret.redis.name
    entorno          = var.entorno
  }))
}

resource "aws_launch_template" "servidor" {
  name_prefix   = "${var.nombre}-${var.entorno}-"
  image_id      = var.imagen_servidor
  instance_type = var.clase_instancia_servidor
  user_data     = local.arranque

  iam_instance_profile {
    arn = aws_iam_instance_profile.servidor.arn
  }

  vpc_security_group_ids = [aws_security_group.servidor.id]

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 30
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.datos.arn
      delete_on_termination = true
    }
  }

  metadata_options {
    # IMDSv2 obligatorio. Con IMDSv1, una vulnerabilidad de peticion falsificada
    # desde el servidor (SSRF) en la aplicacion basta para robar las credenciales
    # del rol de la instancia; con v2 hace falta ademas poder hacer PUT.
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.nombre}-${var.entorno}-servidor" }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "servidor" {
  name                = "${var.nombre}-${var.entorno}"
  vpc_zone_identifier = aws_subnet.aplicacion[*].id

  min_size         = var.instancias_servidor
  max_size         = var.instancias_servidor * 3
  desired_capacity = var.instancias_servidor

  # La instancia no entra en servicio hasta que /salud dice que alcanza
  # PostgreSQL y Redis. Un plano de control en pie pero sin base de datos es
  # peor que uno caido: acepta conexiones y pierde telemetria.
  health_check_type         = "ELB"
  health_check_grace_period = 180

  target_group_arns = [
    aws_lb_target_group.consola.arn,
    aws_lb_target_group.flota.arn,
  ]

  launch_template {
    id      = aws_launch_template.servidor.id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"

    preferences {
      # Nunca por debajo de la mitad de la capacidad durante un despliegue.
      min_healthy_percentage = 50
      instance_warmup        = 180
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.nombre}-${var.entorno}-servidor"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

# --- Balanceador de la consola (HTTPS, capa 7) ------------------------------
resource "aws_lb" "consola" {
  name               = "${var.nombre}-${var.entorno}-consola"
  load_balancer_type = "application"
  internal           = false
  subnets            = aws_subnet.publica[*].id
  security_groups    = [aws_security_group.consola.id]

  drop_invalid_header_fields = true
  enable_deletion_protection = var.entorno == "produccion"
}

resource "aws_lb_target_group" "consola" {
  name     = "${var.nombre}-${var.entorno}-consola"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.principal.id

  health_check {
    path     = "/salud"
    matcher  = "200"
    interval = 15
    timeout  = 5
    # Dos comprobaciones fallidas sacan la instancia: /salud comprueba de verdad
    # PostgreSQL y Redis, asi que un fallo suyo es real, no ruido.
    unhealthy_threshold = 2
    healthy_threshold   = 2
  }

  # La consola usa WebSocket: sin persistencia, cada reconexion podria caer en
  # otra instancia. No rompe nada —el bus es por instancia y el aviso viaja por
  # PostgreSQL— pero evita reconexiones inutiles.
  stickiness {
    type            = "lb_cookie"
    enabled         = true
    cookie_duration = 3600
  }
}

resource "aws_lb_listener" "consola_https" {
  load_balancer_arn = aws_lb.consola.arn
  port              = 443
  protocol          = "HTTPS"
  # Politica moderna: sin TLS 1.0/1.1 ni suites sin secreto hacia delante.
  ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
  certificate_arn = var.certificado_consola_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.consola.arn
  }
}

# --- Balanceador del canal de flota (TCP puro, capa 4) ----------------------
#
# ESTO NO PUEDE SER UN BALANCEADOR DE APLICACION, Y LA RAZON ES EL NUCLEO DE LA
# SEGURIDAD DEL PRODUCTO.
#
# El canal de flota es mTLS MUTUO: el agente verifica el certificado del plano
# de control Y el plano de control autentica al agente por el CN de SU
# certificado. Toda la identidad del sistema descansa en eso.
#
# Un balanceador de aplicacion TERMINA el TLS. Si terminara aqui, el certificado
# del agente moriria en el balanceador y al servidor le llegaria una conexion
# anonima: la autenticacion de la flota entera desapareceria, y con ella la
# garantia de que un agente no puede hacerse pasar por otro.
#
# Por eso el trafico pasa por un balanceador de RED en modo TCP, que reenvia los
# bytes sin mirarlos. El handshake mTLS ocurre de extremo a extremo, entre el
# endpoint y el proceso que lo atiende.
resource "aws_lb" "flota" {
  name               = "${var.nombre}-${var.entorno}-flota"
  load_balancer_type = "network"
  internal           = false
  security_groups    = [aws_security_group.flota.id]

  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = var.entorno == "produccion"

  dynamic "subnet_mapping" {
    for_each = aws_subnet.publica

    content {
      subnet_id = subnet_mapping.value.id
    }
  }
}

resource "aws_lb_target_group" "flota" {
  name     = "${var.nombre}-${var.entorno}-flota"
  port     = 8443
  protocol = "TCP"
  vpc_id   = aws_vpc.principal.id

  # El canal de suscripcion de politica queda ABIERTO a la espera de que el
  # operador publique algo. Con el valor por defecto (350 s) el balanceador lo
  # cortaria una y otra vez; se sube al maximo y el latido del canal, cada 30 s,
  # lo mantiene vivo.
  deregistration_delay = 60

  health_check {
    protocol            = "TCP"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  # Que un agente vuelva a la misma instancia evita rehacer el handshake mTLS
  # —y la comprobacion del certificado— en cada reconexion.
  stickiness {
    type    = "source_ip"
    enabled = true
  }
}

resource "aws_lb_listener" "flota_mtls" {
  load_balancer_arn = aws_lb.flota.arn
  port              = 8443
  # TCP, no TLS: aqui no se termina nada. Ver el comentario del balanceador.
  protocol = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.flota.arn
  }
}
