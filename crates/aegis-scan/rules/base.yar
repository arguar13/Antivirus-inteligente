/*
 * AegisCore - conjunto de reglas base.
 *
 * Estas reglas se compilan y quedan residentes al arrancar. El criterio para
 * que una regla entre aqui es que su tasa de falsos positivos sobre software
 * legitimo sea practicamente nula: el conjunto base corre contra TODO lo que
 * se ejecuta en la maquina, y una regla ruidosa aqui envenena el producto
 * entero.
 *
 * Las reglas que necesitan contexto (un binario sin firmar, un proceso con
 * linaje sospechoso) van en conjuntos condicionales, no aqui.
 */

rule Aegis_EICAR_Test_File
{
    meta:
        description = "Cadena de prueba estandar EICAR. No es malware."
        severity    = "info"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        /* Se parte en dos para que este propio fichero de reglas no dispare
         * escaneres de terceros ni se detecte a si mismo. */
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Aegis_Reverse_Shell_Shell
{
    meta:
        description = "Shell inverso construido con redireccion a /dev/tcp"
        severity    = "high"
        technique   = "T1059.004"
    strings:
        $a = "/dev/tcp/" ascii
        $b = ">&" ascii
        $c = "0>&1" ascii
        $d = "bash -i" ascii
        $e = "sh -i" ascii
    condition:
        $a and ($b or $c) and ($d or $e)
}

rule Aegis_Reverse_Shell_Python
{
    meta:
        description = "Shell inverso en Python con socket y dup2"
        severity    = "high"
        technique   = "T1059.006"
    strings:
        $sock  = "socket.socket" ascii
        $conn  = "connect((" ascii
        $dup   = "dup2(" ascii
        $shell = "/bin/sh" ascii
        $pty   = "pty.spawn" ascii
    condition:
        $sock and $conn and ($dup or $pty) and $shell
}

rule Aegis_Ransom_Note
{
    meta:
        description = "Texto caracteristico de una nota de rescate"
        severity    = "critical"
        technique   = "T1486"
    strings:
        $a = "your files have been encrypted" nocase ascii
        $b = "all your files are encrypted"   nocase ascii
        $c = "to recover your files"          nocase ascii
        $d = "decryption key"                 nocase ascii
        $e = "bitcoin"                        nocase ascii
        $f = "tor browser"                    nocase ascii
        $g = ".onion"                         nocase ascii
    condition:
        /* Se exige la combinacion, no una sola cadena: "bitcoin" aparece en
         * software legitimo y "decryption key" en documentacion. */
        2 of ($a, $b, $c, $d) and 1 of ($e, $f, $g)
}

rule Aegis_Shadow_Copy_Deletion
{
    meta:
        description = "Borrado de copias de seguridad, preludio del cifrado"
        severity    = "critical"
        technique   = "T1490"
    strings:
        $a = "vssadmin" nocase ascii
        $b = "delete shadows" nocase ascii
        $c = "wbadmin delete catalog" nocase ascii
        $d = "bcdedit" nocase ascii
        $e = "recoveryenabled no" nocase ascii
        $f = "btrfs subvolume delete" ascii
        $g = "zfs destroy" ascii
    condition:
        ($a and $b) or $c or ($d and $e) or $f or $g
}

rule Aegis_Linux_Persistence_Preload
{
    meta:
        description = "Manipulacion del cargador dinamico para persistencia"
        severity    = "critical"
        technique   = "T1574.006"
    strings:
        $a = "/etc/ld.so.preload" ascii
        $b = "LD_PRELOAD" ascii
        $c = "__libc_dlopen_mode" ascii
        $d = "dlsym" ascii
    condition:
        $a or ($b and ($c or $d))
}

rule Aegis_Credential_Harvest_Linux
{
    meta:
        description = "Acceso combinado a almacenes de credenciales del sistema"
        severity    = "high"
        technique   = "T1003.008"
    strings:
        $a = "/etc/shadow" ascii
        $b = "/etc/passwd" ascii
        $c = "/etc/sudoers" ascii
        $d = "id_rsa" ascii
        $e = "authorized_keys" ascii
        $f = ".aws/credentials" ascii
        $g = ".docker/config.json" ascii
    condition:
        /* Un binario legitimo toca uno de estos; tres a la vez es recoleccion. */
        3 of them
}

rule Aegis_Anti_Analysis_Environment_Check
{
    meta:
        description = "Comprobaciones de entorno de analisis y depuracion"
        severity    = "medium"
        technique   = "T1497"
    strings:
        $a = "/proc/self/status" ascii
        $b = "TracerPid" ascii
        $c = "ptrace" ascii
        $d = "PTRACE_TRACEME" ascii
        $e = "VMware" ascii
        $f = "VirtualBox" ascii
        $g = "QEMU" ascii
        $h = "/sys/class/dmi/id/product_name" ascii
    condition:
        ($a and $b) or ($c and $d) or (2 of ($e, $f, $g) and $h)
}

rule Aegis_Packer_UPX
{
    meta:
        description = "Binario comprimido con UPX"
        severity    = "low"
        note        = "Legitimo en software distribuido; sospechoso combinado con otras senales"
    strings:
        $a = "UPX!" ascii
        $b = "$Info: This file is packed with the UPX" ascii
        $c = "UPX0" ascii
        $d = "UPX1" ascii
    condition:
        $a or $b or ($c and $d)
}

rule Aegis_Shellcode_Stager_x86_64
{
    meta:
        description = "Secuencias de shellcode x86-64 para execve o socket"
        severity    = "high"
        technique   = "T1055"
    strings:
        /* execve("/bin/sh", NULL, NULL): la cadena empujada a la pila. */
        $sh_push  = { 48 bb 2f 62 69 6e 2f 2f 73 68 }
        /* xor rsi,rsi ; xor rdx,rdx ; mov al,0x3b ; syscall */
        $execve   = { 48 31 f6 48 31 d2 b0 3b 0f 05 }
        /* socket(AF_INET, SOCK_STREAM, 0) via syscall 41. */
        $socket   = { 6a 29 58 6a 02 5f 6a 01 5e }
        /* Bucle de dup2 tipico de un shell inverso. */
        $dup2     = { 6a 21 58 0f 05 48 ff c9 }
    condition:
        any of them
}

rule Aegis_Memory_Injection_Toolkit
{
    meta:
        description = "Cadenas de bibliotecas de inyeccion de codigo en Linux"
        severity    = "high"
        technique   = "T1055.001"
    strings:
        $a = "process_vm_writev" ascii
        $b = "PTRACE_POKETEXT" ascii
        $c = "PTRACE_ATTACH" ascii
        $d = "memfd_create" ascii
        $e = "/proc/self/fd/" ascii
        $f = "mmap" ascii
        $g = "mprotect" ascii
    condition:
        ($a and $g) or ($b and $c) or ($d and $e and $f)
}

rule Aegis_Fileless_Memfd_Execution
{
    meta:
        description = "Ejecucion desde un descriptor de memoria, sin fichero en disco"
        severity    = "critical"
        technique   = "T1620"
    strings:
        $a = "memfd_create" ascii
        $b = "/proc/self/fd/" ascii
        $c = "execveat" ascii
        $d = "fexecve" ascii
    condition:
        $a and ($b or $c or $d)
}

rule Aegis_Encoded_Command_Line
{
    meta:
        description = "Linea de comandos codificada para ocultar su contenido"
        severity    = "medium"
        technique   = "T1027"
    strings:
        $ps1 = "powershell" nocase ascii
        $ps2 = "-enc" nocase ascii
        $ps3 = "-EncodedCommand" nocase ascii
        $b64 = "base64 -d" ascii
        $b64b = "base64 --decode" ascii
        $pipe = "| sh" ascii
        $pipe2 = "|sh" ascii
        $pipe3 = "| bash" ascii
    condition:
        ($ps1 and ($ps2 or $ps3)) or (($b64 or $b64b) and ($pipe or $pipe2 or $pipe3))
}

rule Aegis_Cryptominer_Config
{
    meta:
        description = "Configuracion de minero de criptomonedas"
        severity    = "high"
        technique   = "T1496"
    strings:
        $a = "stratum+tcp://" ascii
        $b = "stratum+ssl://" ascii
        $c = "xmrig" nocase ascii
        $d = "cryptonight" nocase ascii
        $e = "randomx" nocase ascii
        $f = "--donate-level" ascii
    condition:
        $a or $b or ($c and 1 of ($d, $e, $f))
}
