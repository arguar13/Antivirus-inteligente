/*
 * Programa de prueba para aegis-confinar: hace cosas conocidas segun el modo,
 * para poder aprender su perfil, ensayarlo e imponerlo contra el kernel real.
 *
 *   normal    lee /etc/hostname y escribe una linea. Sale 0, o 3 si no pudo leer.
 *   desviado  lo mismo, y ADEMAS abre un socket de red y lee /etc/passwd, que
 *             el modo normal no hace. Imprime el resultado de cada cosa.
 *   caps      lo mismo que normal, e imprime su CapEff de /proc/self/status.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char *resultado(int r) { return r >= 0 ? "ok" : strerror(errno); }

int main(int argc, char **argv) {
    const char *modo = argc > 1 ? argv[1] : "normal";
    char b[256];

    int fd = open("/etc/hostname", O_RDONLY);
    ssize_t n = fd >= 0 ? read(fd, b, sizeof b) : -1;
    if (fd >= 0) close(fd);
    printf("hostname=%s\n", n > 0 ? "ok" : "fallo");

    if (strcmp(modo, "desviado") == 0) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        printf("socket=%s\n", resultado(s));
        if (s >= 0) close(s);
        int f = open("/etc/passwd", O_RDONLY);
        printf("passwd=%s\n", resultado(f));
        if (f >= 0) close(f);
    }
    if (strcmp(modo, "caps") == 0) {
        FILE *st = fopen("/proc/self/status", "r");
        char l[256];
        while (st && fgets(l, sizeof l, st)) {
            if (strncmp(l, "CapEff:", 7) == 0) printf("%s", l);
        }
        if (st) fclose(st);
    }
    fflush(stdout);
    return n > 0 ? 0 : 3;
}
