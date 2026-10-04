/*
 * Regla testigo del canal de contenido.
 *
 * No detecta ninguna amenaza: casa con un marcador inocuo que un operador puede
 * escribir en un fichero para comprobar, de extremo a extremo, que el canal
 * entrega el contenido firmado y que el motor lo usa. Nace en auditoria.
 */
rule Aegis_Canal_Marcador
{
    meta:
        description = "Marcador de prueba del canal de contenido firmado"
        severity    = "info"
    strings:
        $a = "AEGISCORE-CANAL-CONTENIDO-MARCADOR-DE-PRUEBA" ascii
    condition:
        $a
}
