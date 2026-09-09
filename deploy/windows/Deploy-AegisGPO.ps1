<#
.SYNOPSIS
    Prepara el despliegue masivo de AegisCore por directiva de grupo en un
    dominio de Active Directory.

.DESCRIPTION
    Se ejecuta UNA VEZ, desde un controlador de dominio o una estacion con las
    herramientas de administracion (RSAT). Deja montado:

      - Un recurso compartido de solo lectura con el paquete y el script.
      - Una GPO con el script de inicio apuntando a ese recurso.
      - La GPO enlazada a la unidad organizativa que se indique.

    NO despliega a todo el dominio de golpe. Por defecto exige una unidad
    organizativa concreta, porque el modo mas rapido de tumbar una organizacion
    es empujar un agente EDR a diez mil equipos a la vez sin haberlo probado en
    veinte.

.PARAMETER RutaMsi
    Paquete MSI firmado que produce el pipeline.

.PARAMETER Version
    Version del paquete (debe coincidir con la del MSI).

.PARAMETER ServidorFlota
    Direccion del plano de control.

.PARAMETER ServidorRecurso
    Servidor donde se publica el recurso compartido.

.PARAMETER UnidadOrganizativa
    DN de la unidad organizativa a la que se enlaza la GPO.

.PARAMETER GrupoPiloto
    Grupo de seguridad al que limitar la aplicacion. MUY recomendable en el
    primer despliegue: la GPO solo se aplica a sus miembros.

.EXAMPLE
    .\Deploy-AegisGPO.ps1 -RutaMsi .\aegis-1.0.0.0.msi -Version 1.0.0.0 `
        -ServidorFlota aegis.empresa.local:8443 -ServidorRecurso dc01 `
        -UnidadOrganizativa "OU=Piloto,OU=Equipos,DC=empresa,DC=local" `
        -GrupoPiloto "GG-AegisPiloto"
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$RutaMsi,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$ServidorFlota,
    [Parameter(Mandatory = $true)][string]$ServidorRecurso,
    [Parameter(Mandatory = $true)][string]$UnidadOrganizativa,
    [string]$GrupoPiloto,
    [string]$NombreGpo = 'AegisCore - Despliegue del agente',
    [string]$NombreRecurso = 'aegis$'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module GroupPolicy
Import-Module ActiveDirectory

function Paso { param([string]$Texto) Write-Host "[aegis] $Texto" -ForegroundColor Cyan }

# --- 1. Comprobaciones previas ----------------------------------------------
Paso 'Comprobando el paquete'
if (-not (Test-Path $RutaMsi)) { throw "No existe $RutaMsi" }

$firma = Get-AuthenticodeSignature -FilePath $RutaMsi
if ($firma.Status -ne 'Valid') {
    throw "El MSI no esta firmado correctamente (estado: $($firma.Status)). Publicar un instalador sin firmar convierte el recurso compartido en el punto desde el que se compromete el dominio entero."
}
Paso "Firma valida: $($firma.SignerCertificate.Subject)"

Paso 'Comprobando la unidad organizativa'
$ou = Get-ADOrganizationalUnit -Identity $UnidadOrganizativa -ErrorAction Stop
$equipos = (Get-ADComputer -Filter * -SearchBase $UnidadOrganizativa).Count
Paso "Unidad organizativa: $($ou.Name) ($equipos equipo(s) alcanzados)"

if ($equipos -gt 500 -and -not $GrupoPiloto) {
    Write-Warning "La unidad organizativa alcanza $equipos equipos y no se ha indicado un grupo piloto."
    Write-Warning 'Desplegar un EDR a esa escala sin piloto es como se tumba una organizacion con un solo paquete.'
    if (-not $PSCmdlet.ShouldContinue('Continuar sin grupo piloto?', 'Confirmacion')) { return }
}

# --- 2. Recurso compartido ---------------------------------------------------
$rutaLocal = "C:\\AegisDeploy"
$rutaUnc = "\\\\$ServidorRecurso\\$NombreRecurso"

Paso "Publicando el paquete en $rutaUnc"
if ($PSCmdlet.ShouldProcess($rutaUnc, 'Crear recurso compartido')) {
    Invoke-Command -ComputerName $ServidorRecurso -ScriptBlock {
        param($ruta, $nombre)
        if (-not (Test-Path $ruta)) { New-Item -ItemType Directory -Path $ruta -Force | Out-Null }

        if (-not (Get-SmbShare -Name $nombre -ErrorAction SilentlyContinue)) {
            # Solo lectura, y solo para las cuentas de equipo del dominio: los
            # equipos leen el paquete con su cuenta de maquina durante el
            # arranque, antes de que nadie inicie sesion.
            New-SmbShare -Name $nombre -Path $ruta -ReadAccess 'Domain Computers' -FullAccess 'Domain Admins' | Out-Null
        }

        # Los permisos del sistema de ficheros son la defensa real: el recurso
        # compartido por si solo no impide que un usuario con acceso al disco
        # sustituya el MSI.
        $acl = Get-Acl $ruta
        $acl.SetAccessRuleProtection($true, $false)
        $reglas = @(
            New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            New-Object System.Security.AccessControl.FileSystemAccessRule('Domain Admins', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            New-Object System.Security.AccessControl.FileSystemAccessRule('Domain Computers', 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        )
        foreach ($r in $reglas) { $acl.AddAccessRule($r) }
        Set-Acl -Path $ruta -AclObject $acl
    } -ArgumentList $rutaLocal, $NombreRecurso

    Copy-Item -Path $RutaMsi -Destination (Join-Path $rutaUnc "aegis-$Version.msi") -Force
    Copy-Item -Path (Join-Path $PSScriptRoot 'Install-AegisAgent.ps1') -Destination $rutaUnc -Force
}

# --- 3. Directiva de grupo ---------------------------------------------------
Paso "Creando la directiva '$NombreGpo'"
$gpo = Get-GPO -Name $NombreGpo -ErrorAction SilentlyContinue
if (-not $gpo) {
    $gpo = New-GPO -Name $NombreGpo -Comment "Despliegue del agente AegisCore $Version"
}

# El script de inicio corre como SYSTEM antes del inicio de sesion: instala el
# agente aunque nadie use el equipo, que es justo el caso de los servidores.
$argumentos = "-ExecutionPolicy Bypass -NoProfile -File `"$rutaUnc\\Install-AegisAgent.ps1`" " +
              "-Origen `"$rutaUnc`" -ServidorFlota `"$ServidorFlota`" -VersionEsperada `"$Version`""

if ($PSCmdlet.ShouldProcess($NombreGpo, 'Configurar script de inicio')) {
    Set-GPRegistryValue -Name $NombreGpo `
        -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0' `
        -ValueName 'Script' -Type String -Value 'powershell.exe' | Out-Null
    Set-GPRegistryValue -Name $NombreGpo `
        -Key 'HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0' `
        -ValueName 'Parameters' -Type String -Value $argumentos | Out-Null
}

# --- 4. Ambito ---------------------------------------------------------------
if ($GrupoPiloto) {
    Paso "Limitando la aplicacion al grupo '$GrupoPiloto'"
    if ($PSCmdlet.ShouldProcess($NombreGpo, "Filtrar por $GrupoPiloto")) {
        # Se quita el grupo por defecto y se deja solo el piloto: asi la GPO
        # puede enlazarse a la unidad organizativa entera sin aplicarse todavia
        # a todos, y ampliar el despliegue es anadir miembros al grupo.
        Set-GPPermission -Name $NombreGpo -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel None -Confirm:$false | Out-Null
        Set-GPPermission -Name $NombreGpo -TargetName $GrupoPiloto -TargetType Group -PermissionLevel GpoApply | Out-Null
        Set-GPPermission -Name $NombreGpo -TargetName 'Domain Computers' -TargetType Group -PermissionLevel GpoRead | Out-Null
    }
}

Paso "Enlazando la directiva a $UnidadOrganizativa"
if ($PSCmdlet.ShouldProcess($UnidadOrganizativa, 'Enlazar GPO')) {
    New-GPLink -Name $NombreGpo -Target $UnidadOrganizativa -LinkEnabled Yes -ErrorAction SilentlyContinue | Out-Null
}

# --- 5. Resumen --------------------------------------------------------------
Write-Host ''
Write-Host 'Despliegue preparado.' -ForegroundColor Green
Write-Host "  Paquete        : $rutaUnc\aegis-$Version.msi"
Write-Host "  Directiva      : $NombreGpo"
Write-Host "  Unidad org.    : $UnidadOrganizativa ($equipos equipos)"
Write-Host "  Ambito         : $(if ($GrupoPiloto) { "grupo piloto $GrupoPiloto" } else { 'todos los equipos de la unidad' })"
Write-Host "  Plano de control: $ServidorFlota"
Write-Host ''
Write-Host 'Los equipos instalaran el agente en su proximo arranque.' -ForegroundColor Yellow
Write-Host 'Para forzarlo en un equipo concreto: gpupdate /force y reiniciar.' -ForegroundColor Yellow
Write-Host 'El resultado de cada equipo queda en su registro de eventos (origen AegisDeploy).' -ForegroundColor Yellow
