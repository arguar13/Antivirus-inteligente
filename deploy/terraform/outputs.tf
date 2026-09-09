# Lo que el resto del despliegue necesita saber.

output "consola_url" {
  description = "URL de la consola de administracion."
  value       = "https://${aws_lb.consola.dns_name}/panel/"
}

output "flota_endpoint" {
  description = <<-DESC
    Direccion del canal de flota. Es el valor que se pone en `AEGIS_FLEET_ADDR`
    al aprovisionar los agentes (playbook de Ansible o instalador MSI).
  DESC
  value       = "${aws_lb.flota.dns_name}:8443"
}

output "base_datos_endpoint" {
  description = "Extremo de PostgreSQL (accesible solo desde la VPC)."
  value       = aws_db_instance.principal.endpoint
}

output "secreto_base_datos" {
  description = "Nombre del secreto con las credenciales de PostgreSQL."
  value       = aws_secretsmanager_secret.base_datos.name
}

output "ca_sistema_ficheros" {
  description = <<-DESC
    Sistema de ficheros que guarda la CA de la flota.

    Es el recurso mas critico del despliegue: si se pierde, todos los
    certificados emitidos dejan de validar y la flota entera queda fuera. Debe
    entrar en el plan de recuperacion ante desastres con la misma prioridad que
    la base de datos.
  DESC
  value       = aws_efs_file_system.ca.id
}

output "clave_kms_datos" {
  description = "Clave KMS que cifra los datos en reposo."
  value       = aws_kms_key.datos.arn
}
