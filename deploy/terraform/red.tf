# Red del plano de control.
#
# Principio: NADA que guarde datos o ejecute logica vive en una subred publica.
# Solo los balanceadores tocan Internet, y lo hacen sin poder ver el contenido
# del canal de flota (ver el comentario del balanceador de red).

resource "aws_vpc" "principal" {
  cidr_block           = var.cidr_vpc
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.nombre}-vpc" }
}

resource "aws_internet_gateway" "salida" {
  vpc_id = aws_vpc.principal.id
  tags   = { Name = "${var.nombre}-igw" }
}

# --- Subredes publicas: solo balanceadores y pasarelas NAT -------------------
resource "aws_subnet" "publica" {
  count = length(var.zonas)

  vpc_id            = aws_vpc.principal.id
  availability_zone = var.zonas[count.index]
  cidr_block        = cidrsubnet(var.cidr_vpc, 8, count.index)

  # Sin IP publica automatica: si algo aterriza aqui por error, que no salga
  # expuesto solo por estar en la subred.
  map_public_ip_on_launch = false

  tags = { Name = "${var.nombre}-publica-${var.zonas[count.index]}" }
}

# --- Subredes privadas: el plano de control ---------------------------------
resource "aws_subnet" "aplicacion" {
  count = length(var.zonas)

  vpc_id            = aws_vpc.principal.id
  availability_zone = var.zonas[count.index]
  cidr_block        = cidrsubnet(var.cidr_vpc, 8, count.index + 10)

  tags = { Name = "${var.nombre}-app-${var.zonas[count.index]}" }
}

# --- Subredes de datos: sin ruta a Internet, ni siquiera saliente ------------
resource "aws_subnet" "datos" {
  count = length(var.zonas)

  vpc_id            = aws_vpc.principal.id
  availability_zone = var.zonas[count.index]
  cidr_block        = cidrsubnet(var.cidr_vpc, 8, count.index + 20)

  tags = { Name = "${var.nombre}-datos-${var.zonas[count.index]}" }
}

# --- Salida a Internet para la capa de aplicacion ---------------------------
resource "aws_eip" "nat" {
  count  = length(var.zonas)
  domain = "vpc"
  tags   = { Name = "${var.nombre}-nat-${count.index}" }
}

# Una NAT por zona: con una sola, la caida de esa zona deja sin actualizaciones
# ni telemetria saliente a todo el plano de control.
resource "aws_nat_gateway" "salida" {
  count = length(var.zonas)

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.publica[count.index].id
  depends_on    = [aws_internet_gateway.salida]

  tags = { Name = "${var.nombre}-nat-${var.zonas[count.index]}" }
}

resource "aws_route_table" "publica" {
  vpc_id = aws_vpc.principal.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.salida.id
  }

  tags = { Name = "${var.nombre}-rt-publica" }
}

resource "aws_route_table_association" "publica" {
  count          = length(var.zonas)
  subnet_id      = aws_subnet.publica[count.index].id
  route_table_id = aws_route_table.publica.id
}

resource "aws_route_table" "aplicacion" {
  count  = length(var.zonas)
  vpc_id = aws_vpc.principal.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.salida[count.index].id
  }

  tags = { Name = "${var.nombre}-rt-app-${var.zonas[count.index]}" }
}

resource "aws_route_table_association" "aplicacion" {
  count          = length(var.zonas)
  subnet_id      = aws_subnet.aplicacion[count.index].id
  route_table_id = aws_route_table.aplicacion[count.index].id
}

# La capa de datos no tiene tabla con salida: sin ruta a Internet, una base de
# datos comprometida no puede exfiltrar por su cuenta.
resource "aws_route_table" "datos" {
  vpc_id = aws_vpc.principal.id
  tags   = { Name = "${var.nombre}-rt-datos" }
}

resource "aws_route_table_association" "datos" {
  count          = length(var.zonas)
  subnet_id      = aws_subnet.datos[count.index].id
  route_table_id = aws_route_table.datos.id
}

# --- Registro de trafico ----------------------------------------------------
# Sin registro de flujos, una intrusion en el plano de control se investiga a
# ciegas. Es la caja negra de la red.
resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.principal.id
  traffic_type         = "ALL"
  iam_role_arn         = aws_iam_role.flow_logs.arn
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  log_destination_type = "cloud-watch-logs"
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aegis/${var.entorno}/vpc-flow-logs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.registros.arn
}
