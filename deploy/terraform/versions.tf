# Versiones fijadas a proposito.
#
# Un despliegue de seguridad que se recompone distinto cada vez que alguien lo
# aplica no es reproducible, y sin reproducibilidad no se puede afirmar que la
# infraestructura que corre es la que se reviso. El proveedor se fija a una
# version exacta; Terraform, a un minimo con techo de version mayor.
terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.82.2"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.6.3"
    }
  }
}

provider "aws" {
  region = var.region

  # Todo lo que crea este despliegue queda marcado. Sin etiquetas comunes, en
  # una cuenta compartida nadie sabe despues que recursos son de que sistema, y
  # los huerfanos acaban siendo la puerta de atras que nadie vigila.
  default_tags {
    tags = {
      Sistema       = "AegisCore"
      Componente    = "plano-de-control"
      Entorno       = var.entorno
      GestionadoPor = "terraform"
    }
  }
}
