/* Ejercita la politica de auto-defensa y de clasificacion de Windows.
 *
 * POR QUE ESTAS PRUEBAS EXISTEN EN LINUX
 * --------------------------------------
 * El driver solo se compila con el WDK, en Windows. Pero la parte que puede
 * estar MAL de forma peligrosa no es la fontaneria del driver: es la decision.
 * Quitar un bit de mas deja al usuario sin poder ver su propio gestor de
 * tareas; quitar uno de menos deja al atacante matar el EDR.
 *
 * Esa decision es C portable, asi que se ejercita en cada `make ci` con gcc y
 * con clang. La alternativa —comprobarlo a mano en un Windows cuando alguien se
 * acuerda— es como no comprobarlo.
 */

#include <stdio.h>
#include <string.h>

#include "../kernel/windows/aegis/include/aegis_politica.h"

static int fallos = 0;
static int total = 0;

static void afirmar(int condicion, const char *que)
{
    total++;
    if (!condicion) {
        fallos++;
        printf("  FALLO: %s\n", que);
    }
}

/* Un handle ajeno pidiendo todo contra el agente. */
static aegis_contexto_acceso ajeno(aegis_mascara_t solicitada)
{
    aegis_contexto_acceso c;
    memset(&c, 0, sizeof(c));
    c.objetivo_protegido = 1;
    c.solicitada = solicitada;
    return c;
}

static void pruebas_de_acceso(void)
{
    const aegis_mascara_t TODO = 0x1FFFFFu | AEGIS_SYNCHRONIZE;

    /* --- Lo que hay que quitar ------------------------------------------ */
    {
        aegis_contexto_acceso c = ajeno(TODO);
        aegis_mascara_t g = aegis_filtrar_acceso_proceso(&c);

        /* Matar el EDR es el primer paso de casi todo. */
        afirmar(!(g & AEGIS_PROCESS_TERMINATE), "TERMINATE tiene que quitarse");
        /* Escribir en su memoria: parchear una comprobacion o meter un hook
         * desactiva la deteccion sin matar el proceso, que es peor porque el
         * panel lo sigue viendo vivo. */
        afirmar(!(g & AEGIS_PROCESS_VM_WRITE), "VM_WRITE tiene que quitarse");
        afirmar(!(g & AEGIS_PROCESS_VM_OPERATION), "VM_OPERATION tiene que quitarse");
        /* Leer su memoria: la clave privada de la flota vive ahi y nunca toca
         * el disco. */
        afirmar(!(g & AEGIS_PROCESS_VM_READ), "VM_READ tiene que quitarse");
        /* Ejecutar codigo DENTRO del EDR, con su identidad. */
        afirmar(!(g & AEGIS_PROCESS_CREATE_THREAD), "CREATE_THREAD tiene que quitarse");
        /* Congelarlo: no muere, pero deja de detectar. */
        afirmar(!(g & AEGIS_PROCESS_SUSPEND_RESUME), "SUSPEND_RESUME tiene que quitarse");
        /* Conseguir por la puerta de atras el handle que aqui se recorta. */
        afirmar(!(g & AEGIS_PROCESS_DUP_HANDLE), "DUP_HANDLE tiene que quitarse");
    }

    /* --- Lo que NUNCA se puede quitar ------------------------------------ */
    {
        aegis_contexto_acceso c = ajeno(TODO);
        aegis_mascara_t g = aegis_filtrar_acceso_proceso(&c);

        /* El gestor de tareas, WMI y el gestor de servicios usan esto. Un EDR
         * que se los quite parece una maquina rota, y la reaccion normal a una
         * maquina rota es desinstalar el EDR. */
        afirmar(g & AEGIS_PROCESS_QUERY_LIMITED_INFORMATION,
                "QUERY_LIMITED_INFORMATION no se puede quitar");
        afirmar(g & AEGIS_SYNCHRONIZE, "SYNCHRONIZE no se puede quitar");
    }

    /* --- Recortar no es denegar ------------------------------------------ */
    {
        aegis_contexto_acceso c = ajeno(AEGIS_PROCESS_TERMINATE |
                                        AEGIS_PROCESS_QUERY_LIMITED_INFORMATION);
        aegis_mascara_t g = aegis_filtrar_acceso_proceso(&c);
        /* Devolver cero equivaldria a denegar, y quien pide MAXIMUM_ALLOWED
         * —que es lo que hacen muchas APIs de Windows por dentro— se
         * encontraria con una averia en vez de con menos derechos. */
        afirmar(g != 0u, "recortar no puede vaciar la mascara entera");
        afirmar(g == AEGIS_PROCESS_QUERY_LIMITED_INFORMATION,
                "tiene que quedar exactamente lo inofensivo");
    }

    /* --- Lo que NO se toca ------------------------------------------------ */
    {
        /* El kernel abre handles contra todo constantemente. Recortarle un bit
         * no protege de nada y rompe el sistema operativo. */
        aegis_contexto_acceso c = ajeno(TODO);
        c.es_kernel = 1;
        afirmar(aegis_filtrar_acceso_proceso(&c) == TODO,
                "al kernel no se le recorta nada");
    }
    {
        /* Solo nos defendemos a nosotros: filtrar handles ajenos convertiria el
         * EDR en la razon por la que las aplicaciones del cliente fallan. */
        aegis_contexto_acceso c = ajeno(TODO);
        c.objetivo_protegido = 0;
        afirmar(aegis_filtrar_acceso_proceso(&c) == TODO,
                "un proceso no protegido no se toca");
    }
    {
        /* Un proceso tiene que poder abrirse a si mismo: sus hilos, su manejo
         * de excepciones y su recolector lo hacen. */
        aegis_contexto_acceso c = ajeno(TODO);
        c.es_mismo_proceso = 1;
        afirmar(aegis_filtrar_acceso_proceso(&c) == TODO,
                "un proceso puede abrirse a si mismo");
    }
    {
        /* El watchdog tiene que poder supervisar al agente y reiniciarlo. Sin
         * esta excepcion, la auto-defensa impediria la auto-recuperacion. */
        aegis_contexto_acceso c = ajeno(TODO);
        c.solicitante_confiable = 1;
        afirmar(aegis_filtrar_acceso_proceso(&c) == TODO,
                "un componente confiable de AegisCore conserva su acceso");
    }

    /* --- Hilos ------------------------------------------------------------ */
    {
        aegis_contexto_acceso c = ajeno(TODO);
        aegis_mascara_t g = aegis_filtrar_acceso_hilo(&c);
        /* Secuestro de hilo: se le cambia el puntero de instruccion. */
        afirmar(!(g & AEGIS_THREAD_SET_CONTEXT), "SET_CONTEXT de hilo tiene que quitarse");
        /* Matar los hilos uno a uno deja al EDR inerte sin haberlo matado. */
        afirmar(!(g & AEGIS_THREAD_TERMINATE), "TERMINATE de hilo tiene que quitarse");
        afirmar(!(g & AEGIS_THREAD_SUSPEND_RESUME), "SUSPEND_RESUME de hilo tiene que quitarse");
        afirmar(!(g & AEGIS_THREAD_IMPERSONATE), "IMPERSONATE tiene que quitarse");
        afirmar(g & AEGIS_THREAD_QUERY_LIMITED_INFORMATION,
                "QUERY_LIMITED_INFORMATION de hilo no se puede quitar");
    }

    /* --- Un puntero nulo no puede conceder nada -------------------------- */
    afirmar(aegis_filtrar_acceso_proceso(NULL) == 0u, "NULL no concede acceso");
    afirmar(aegis_filtrar_acceso_hilo(NULL) == 0u, "NULL no concede acceso a hilo");
}

static aegis_etwti_evento evento(aegis_etwti_tipo tipo, uint32_t origen, uint32_t destino)
{
    aegis_etwti_evento e;
    memset(&e, 0, sizeof(e));
    e.tipo = tipo;
    e.pid_origen = origen;
    e.pid_destino = destino;
    e.tamano = 4096;
    return e;
}

static void pruebas_de_clasificacion(void)
{
    /* --- Sobre uno mismo no es inyeccion --------------------------------- */
    {
        /* Un compilador JIT reserva y hace ejecutable su propia memoria
         * constantemente. Avisar de eso enterraria al analista en ruido hasta
         * que dejara de mirar, y entonces la deteccion de verdad tampoco se ve. */
        aegis_etwti_evento e = evento(AEGIS_ETWTI_ALLOCVM, 1000, 1000);
        e.proteccion = AEGIS_PAGE_EXECUTE_READWRITE;
        afirmar(aegis_clasificar_etwti(&e) == AEGIS_SEV_INFORMATIVA,
                "RWX en el propio proceso no es inyeccion");
    }

    /* --- El cargador de shellcode clasico -------------------------------- */
    {
        aegis_etwti_evento e = evento(AEGIS_ETWTI_ALLOCVM, 1000, 2000);
        e.proteccion = AEGIS_PAGE_EXECUTE_READWRITE;
        afirmar(aegis_clasificar_etwti(&e) == AEGIS_SEV_CRITICA,
                "RWX en OTRO proceso es critico");
    }
    {
        /* Reservar memoria de datos en otro proceso tambien es raro, pero lo
         * hacen inyectores de DLL legitimos: se registra con menos severidad en
         * vez de callarse. */
        aegis_etwti_evento e = evento(AEGIS_ETWTI_ALLOCVM, 1000, 2000);
        e.proteccion = AEGIS_PAGE_READWRITE;
        afirmar(aegis_clasificar_etwti(&e) == AEGIS_SEV_MEDIA,
                "memoria de datos remota es sospechosa, no critica");
    }

    /* --- El cargador que EVITA reservar RWX ------------------------------ */
    {
        /* Reserva RW, escribe el shellcode, y despues pasa a ejecutable: asi
         * nunca existe una region RWX que delate. Esa TRANSICION en un proceso
         * ajeno casi no tiene uso legitimo, y es lo que se detecta. */
        aegis_etwti_evento e = evento(AEGIS_ETWTI_PROTECTVM, 1000, 2000);
        e.proteccion_anterior = AEGIS_PAGE_READWRITE;
        e.proteccion = AEGIS_PAGE_EXECUTE_READ;
        afirmar(aegis_clasificar_etwti(&e) == AEGIS_SEV_CRITICA,
                "la transicion RW -> RX remota es critica");
    }
    {
        /* Lo que ya era ejecutable y sigue siendolo no es esa transicion. */
        aegis_etwti_evento e = evento(AEGIS_ETWTI_PROTECTVM, 1000, 2000);
        e.proteccion_anterior = AEGIS_PAGE_EXECUTE_READ;
        e.proteccion = AEGIS_PAGE_EXECUTE_READWRITE;
        afirmar(aegis_clasificar_etwti(&e) == AEGIS_SEV_BAJA,
                "lo que ya era ejecutable no es la transicion que delata");
    }

    /* --- Inyeccion por APC y secuestro de hilo --------------------------- */
    {
        /* La primitiva de ejecucion de la inyeccion por APC, y de la variante
         * «early bird» que la encola antes de que la victima ejecute nada. */
        aegis_etwti_evento e = evento(AEGIS_ETWTI_QUEUEAPC, 1000, 2000);
        afirmar(aegis_clasificar_etwti(&e) == AEGIS_SEV_CRITICA,
                "una APC de usuario en un hilo ajeno es critica");
    }
    {
        /* En el propio proceso es E/S alertable perfectamente normal. */
        aegis_etwti_evento e = evento(AEGIS_ETWTI_QUEUEAPC, 1000, 1000);
        afirmar(aegis_clasificar_etwti(&e) == AEGIS_SEV_INFORMATIVA,
                "una APC en el propio proceso es E/S alertable normal");
    }
    {
        aegis_etwti_evento e = evento(AEGIS_ETWTI_SETTHREADCONTEXT, 1000, 2000);
        afirmar(aegis_clasificar_etwti(&e) == AEGIS_SEV_CRITICA,
                "cambiar el contexto de un hilo ajeno es secuestro");
    }

    /* --- Mapeo de seccion: la variante sin WriteProcessMemory ------------ */
    {
        aegis_etwti_evento e = evento(AEGIS_ETWTI_MAPVIEW, 1000, 2000);
        e.proteccion = AEGIS_PAGE_EXECUTE_READ;
        afirmar(aegis_clasificar_etwti(&e) == AEGIS_SEV_ALTA,
                "mapear una seccion ejecutable en otro proceso es alta");
    }

    /* --- El depurador declarado ------------------------------------------ */
    {
        /* Tiene permiso para hacer justo esto. Se REBAJA a informativa y no se
         * descarta: si alguien secuestra la autorizacion, la evidencia sigue. */
        aegis_etwti_evento e = evento(AEGIS_ETWTI_SETTHREADCONTEXT, 1000, 2000);
        e.origen_autorizado = 1;
        afirmar(aegis_clasificar_etwti(&e) == AEGIS_SEV_INFORMATIVA,
                "un origen autorizado se rebaja, no desaparece");
    }

    afirmar(aegis_clasificar_etwti(NULL) == AEGIS_SEV_INFORMATIVA,
            "NULL no puede clasificar nada");
}

int main(void)
{
    pruebas_de_acceso();
    pruebas_de_clasificacion();

    if (fallos == 0) {
        printf("OK: %d afirmaciones de la politica de Windows se cumplen.\n", total);
        return 0;
    }
    printf("FALLO: %d de %d afirmaciones no se cumplen.\n", fallos, total);
    return 1;
}
