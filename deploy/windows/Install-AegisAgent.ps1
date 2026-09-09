<#
.SYNOPSIS
    Instala el agente AegisCore en un endpoint Windows. Pensado para ejecutarse
    como script de inicio de una directiva de grupo (GPO).

.DESCRIPTION
    Este script corre en CADA equipo del dominio, en cada arranque. De ahi sus
    dos obsesiones:

      1. ES IDEMPOTENTE. Si la version correcta ya esta instalada, no hace nada
         y termina en milisegundos. Un script de inicio que reinstalara en cada
         arranque multiplicaria por el numero de equipos el trafico al recurso
         compartido y reiniciaria el EDR de toda la organizacion cada manana.

      2. NO ROMPE EL ARRANQUE. Cualquier fallo se registra y se sale con codigo
         cero salvo que se pida lo contrario: un script de inicio que aborta
         puede dejar equipos sin completar el inicio de sesion, y el remedio
         seria peor que la enfermedad.

.PARAMETER Origen
    Recurso compartido de solo lectura donde vive el MSI.

.PARAMETER ServidorFlota
    Direccion del plano de control (salida `flota_endpoint` de Terraform).

.PARAMETER VersionEsperada
    Version que debe quedar instalada.

.PARAMETER FallarEnError
    Devuelve codigo distinto de cero si algo falla. Util al probar la GPO en un
    grupo piloto; desaconsejado en produccion.

.EXAMPLE
    .\Install-AegisAgent.ps1 -Origen \\dc01\aegis$ -ServidorFlota aegis.empresa.local:8443 -VersionEsperada 1.0.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Origen,

    [Parameter(Mandatory = $true)]
    [string]$ServidorFlota,

    [Parameter(Mandatory = $true)]
    [string]$VersionEsperada,

    [switch]$FallarEnError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RutaRegistro = 'HKLM:\SOFTWARE\AegisCore\Agent'
$CarpetaLogs = Join-Path $env:ProgramData 'AegisCore\logs'
$Bitacora = Join-Path $CarpetaLogs 'despliegue.log'

function Escribir-Bitacora {
    param([string]$Mensaje, [string]$Nivel = 'INFO')
    $linea = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'), $Nivel, $Mensaje
    Write-Verbose $linea
    try {
        if (-not (Test-Path $CarpetaLogs)) {
            New-Item -ItemType Directory -Path $CarpetaLogs -Force | Out-Null
        }
        Add-Content -Path $Bitacora -Value $linea -ErrorAction SilentlyContinue
    } catch {
        # Si ni siquiera se puede registrar, no se interrumpe el arranque.
    }
    # El registro de eventos es donde el equipo de operaciones mira de verdad.
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('AegisDeploy')) {
            New-EventLog -LogName Application -Source 'AegisDeploy' -ErrorAction SilentlyContinue
        }
        $tipo = if ($Nivel -eq 'ERROR') { 'Error' } elseif ($Nivel -eq 'AVISO') { 'Warning' } else { 'Information' }
        Write-EventLog -LogName Application -Source 'AegisDeploy' -EntryType $tipo -EventId 1000 -Message $Mensaje -ErrorAction SilentlyContinue
    } catch {
        # Idem.
    }
}

function Obtener-VersionInstalada {
    try {
        $v = (Get-ItemProperty -Path $RutaRegistro -Name 'Version' -ErrorAction Stop).Version
        return $v
    } catch {
        return $null
    }
}

function Comprobar-Servicios {
    $agente = Get-Service -Name 'AegisAgent' -ErrorAction SilentlyContinue
    $supervisor = Get-Service -Name 'AegisWatchdog' -ErrorAction SilentlyContinue
    return @{
        AgenteActivo     = ($null -ne $agente) -and ($agente.Status -eq 'Running')
        SupervisorActivo = ($null -ne $supervisor) -and ($supervisor.Status -eq 'Running')
    }
}

$codigoSalida = 0

try {
    Escribir-Bitacora "Comprobando AegisCore en $env:COMPUTERNAME"

    # --- 1. Salida rapida si ya esta al dia ---------------------------------
    $instalada = Obtener-VersionInstalada
    if ($instalada -eq $VersionEsperada) {
        $estado = Comprobar-Servicios
        if ($estado.AgenteActivo -and $estado.SupervisorActivo) {
            Escribir-Bitacora "Version $instalada ya instalada y operativa; nada que hacer."
            exit 0
        }

        # Instalada pero con el servicio parado: es exactamente lo que deja un
        # malware que consigue detener el EDR. Se levanta y se deja constancia.
        Escribir-Bitacora "Version $instalada instalada pero con servicios detenidos; reiniciandolos." 'AVISO'
        foreach ($s in @('AegisAgent', 'AegisWatchdog')) {
            try { Start-Service -Name $s -ErrorAction Stop } catch {
                Escribir-Bitacora "No se pudo arrancar $s : $($_.Exception.Message)" 'ERROR'
                $codigoSalida = 1
            }
        }
        exit $codigoSalida
    }

    if ($instalada) {
        Escribir-Bitacora "Version instalada $instalada, se esperaba $VersionEsperada; actualizando."
    } else {
        Escribir-Bitacora "Sin AegisCore instalado; instalando $VersionEsperada."
    }

    # --- 2. Localizar y verificar el paquete --------------------------------
    $msi = Join-Path $Origen "aegis-$VersionEsperada.msi"
    if (-not (Test-Path $msi)) {
        throw "No se encuentra el paquete en $msi"
    }

    # La firma Authenticode es lo que impide que un recurso compartido
    # comprometido sirva un instalador manipulado a toda la organizacion.
    $firma = Get-AuthenticodeSignature -FilePath $msi
    if ($firma.Status -ne 'Valid') {
        throw "La firma del paquete no es valida (estado: $($firma.Status)). No se instala."
    }
    Escribir-Bitacora "Firma verificada: $($firma.SignerCertificate.Subject)"

    # Copia local: instalar directamente desde el recurso compartido deja la
    # instalacion a merced de un corte de red a medio camino.
    $temporal = Join-Path $env:TEMP "aegis-$VersionEsperada.msi"
    Copy-Item -Path $msi -Destination $temporal -Force

    # --- 3. Instalar en silencio --------------------------------------------
    $logMsi = Join-Path $CarpetaLogs "msi-$VersionEsperada.log"
    $argumentos = @(
        '/i', "`"$temporal`"",
        '/qn',
        '/norestart',
        "SERVIDOR_FLOTA=`"$ServidorFlota`"",
        'ARRANCAR_SERVICIO=1',
        '/l*v', "`"$logMsi`""
    )

    Escribir-Bitacora "Ejecutando msiexec $($argumentos -join ' ')"
    $proceso = Start-Process -FilePath 'msiexec.exe' -ArgumentList $argumentos -Wait -PassThru -NoNewWindow

    # 3010 = correcto, pero pide reinicio. No es un fallo: el agente ya corre.
    if ($proceso.ExitCode -eq 3010) {
        Escribir-Bitacora 'Instalado correctamente; el equipo pide reinicio (no se fuerza).' 'AVISO'
    } elseif ($proceso.ExitCode -ne 0) {
        throw "msiexec devolvio $($proceso.ExitCode). Detalle en $logMsi"
    }

    Remove-Item $temporal -Force -ErrorAction SilentlyContinue

    # --- 4. Verificar el resultado ------------------------------------------
    # Instalar sin comprobar es confiar; un despliegue de seguridad no confia.
    Start-Sleep -Seconds 10
    $estado = Comprobar-Servicios
    $ahora = Obtener-VersionInstalada

    if ($ahora -ne $VersionEsperada) {
        throw "Tras instalar, la version registrada es '$ahora' y se esperaba '$VersionEsperada'."
    }
    if (-not $estado.AgenteActivo) {
        throw 'El servicio AegisAgent no quedo en ejecucion.'
    }
    if (-not $estado.SupervisorActivo) {
        Escribir-Bitacora 'El supervisor de auto-defensa no esta activo; el agente queda sin proteccion contra su propia parada.' 'AVISO'
    }

    Escribir-Bitacora "AegisCore $VersionEsperada instalado y operativo."

} catch {
    Escribir-Bitacora "FALLO: $($_.Exception.Message)" 'ERROR'
    $codigoSalida = 1
}

# Por defecto se sale con cero aunque haya fallado: un script de inicio que
# aborta puede impedir que los equipos completen el arranque, y eso seria peor
# que quedarse sin agente en unos pocos. El fallo queda en el registro de
# eventos, que es donde operaciones lo va a ver.
if ($FallarEnError) { exit $codigoSalida }
exit 0
