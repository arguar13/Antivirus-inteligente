# Entradas del despliegue del plano de control.

variable "region" {
  description = "Region de AWS donde se despliega el plano de control."
  type        = string
  default     = "eu-west-1"
}

variable "entorno" {
  description = "Entorno logico (produccion, preproduccion, laboratorio)."
  type        = string
  default     = "produccion"

  validation {
    condition     = contains(["produccion", "preproduccion", "laboratorio"], var.entorno)
    error_message = "El entorno debe ser produccion, preproduccion o laboratorio."
  }
}

variable "nombre" {
  description = "Prefijo de nombre para los recursos."
  type        = string
  default     = "aegis"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.nombre))
    error_message = "El nombre debe empezar por letra minuscula y usar solo minusculas, digitos y guiones (2-21 caracteres)."
  }
}

variable "cidr_vpc" {
  description = "Rango de la VPC del plano de control."
  type        = string
  default     = "10.60.0.0/16"
}

variable "zonas" {
  description = "Zonas de disponibilidad. Dos como minimo: una sola zona no sobrevive a su caida."
  type        = list(string)
  default     = ["eu-west-1a", "eu-west-1b"]

  validation {
    condition     = length(var.zonas) >= 2
    error_message = "Hacen falta al menos dos zonas de disponibilidad."
  }
}

variable "redes_administracion" {
  description = <<-DESC
    Rangos desde los que se permite abrir la consola de administracion.

    NO tiene valor por defecto a proposito. La consola puede aislar toda la
    flota: dejarla accesible desde Internet por omision seria el fallo de
    configuracion mas caro que este despliegue podria cometer, y un valor por
    defecto comodo es exactamente como ocurren esos fallos.
  DESC
  type        = list(string)

  validation {
    condition     = length(var.redes_administracion) > 0 && !contains(var.redes_administracion, "0.0.0.0/0")
    error_message = "Indica al menos un rango concreto; 0.0.0.0/0 expondria la consola a Internet."
  }
}

variable "redes_flota" {
  description = <<-DESC
    Rangos desde los que los agentes pueden alcanzar el puerto de flota.

    Suele ser mas amplio que el de administracion —los endpoints estan repartidos
    por toda la organizacion, incluso fuera de ella— y por eso ese puerto se
    protege con mTLS mutuo y no con la topologia de red.
  DESC
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "instancias_servidor" {
  description = "Numero de instancias del plano de control."
  type        = number
  default     = 2

  validation {
    condition     = var.instancias_servidor >= 2
    error_message = "Dos instancias como minimo: con una, cualquier despliegue o fallo deja la flota sin plano de control."
  }
}

variable "clase_instancia_servidor" {
  description = "Tipo de instancia EC2 del plano de control."
  type        = string
  default     = "c7g.large"
}

variable "clase_base_datos" {
  description = "Clase de la instancia de PostgreSQL."
  type        = string
  default     = "db.m7g.large"
}

variable "almacenamiento_base_datos_gb" {
  description = "Almacenamiento inicial de PostgreSQL en gibibytes."
  type        = number
  default     = 100
}

variable "retencion_copias_dias" {
  description = "Dias de retencion de copias automaticas de PostgreSQL."
  type        = number
  default     = 30

  validation {
    condition     = var.retencion_copias_dias >= 7
    error_message = "Menos de siete dias de copias deja sin margen para detectar un problema antes de perder el punto de restauracion."
  }
}

variable "nodos_redis" {
  description = "Numero de nodos de la replica de Redis."
  type        = number
  default     = 2
}

variable "imagen_servidor" {
  description = <<-DESC
    AMI del plano de control, construida por el pipeline con el binario
    `aegis-server` ya dentro. Se pasa explicitamente en vez de buscarla por
    filtro: el despliegue debe usar la imagen que se audito, no la ultima que
    aparezca con un nombre parecido.
  DESC
  type        = string

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,17}$", var.imagen_servidor))
    error_message = "Debe ser un identificador de AMI valido (ami-...)."
  }
}

variable "certificado_consola_arn" {
  description = "ARN del certificado de ACM para la consola HTTPS."
  type        = string
}
