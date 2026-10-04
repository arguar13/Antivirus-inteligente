#!/usr/bin/env bash
#
# Construye los paquetes del agente: .deb (dpkg-deb) y .rpm (rpmbuild), con las
# herramientas NATIVAS de cada familia y ninguna de terceros. FASE 3 del MP-16.
#
#   tools/empaquetar.sh [--arq x86_64|aarch64] [--version V] [--revision N]
#                       [--roto] [--salida DIR]
#   tools/empaquetar.sh --matriz [--arq A]        los tres de la matriz de kernels
#   tools/empaquetar.sh --comprobar-reproducible [--arq A]
#
# Parte de los binarios herméticos ya verificados (dist-hermetico/ o
# dist-hermetico-aarch64/, con sus SHA256SUMS si los hay): el paquete no compila
# nada, y lo que se instala es exactamente lo que paso las puertas.
#
# REPRODUCIBLE: con el mismo arbol y los mismos binarios, dos construcciones dan
# los mismos bytes. SOURCE_DATE_EPOCH es la fecha del commit (o la que se
# exporte), las fechas de todos los ficheros se fijan a ella, el orden y el
# dueño no dependen del disco, y la compresion es xz de un solo hilo.
# `--comprobar-reproducible` lo DEMUESTRA construyendo dos veces y comparando.
#
# --matriz deja en dist-paquetes[-aarch64]/ la revision 1, la 2 y una 3 ROTA
# (su agente no arranca), y ORDEN con los nombres en ese orden: es como la
# matriz de kernels ejerce instalar, actualizar y la vuelta atras.
#
# Compresion: xz, no la de por defecto. dpkg-deb de Ubuntu comprime con zstd,
# que el dpkg de Debian 11 no sabe abrir; rpm 4.14 (Leap 15.6) y 4.16 (Rocky 9,
# AL2023) abren xz. Un paquete que no se instala en una distribucion de la
# matriz no es un paquete de la matriz.
set -euo pipefail
cd "$(dirname "$0")/.."
RAIZ="$(pwd)"

ARQ=x86_64
VERSION=""
REVISION=1
ROTO=0
SALIDA=""
MODO=uno
while [ $# -gt 0 ]; do
    case "$1" in
        --arq) ARQ="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --revision) REVISION="$2"; shift 2 ;;
        --roto) ROTO=1; shift ;;
        --salida) SALIDA="$2"; shift 2 ;;
        --matriz) MODO=matriz; shift ;;
        --comprobar-reproducible) MODO=reproducible; shift ;;
        -h | --help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "opcion desconocida: $1" >&2; exit 2 ;;
    esac
done

case "$ARQ" in
    x86_64) DIST=dist-hermetico; DEB_ARQ=amd64; SUF_DIST="" ;;
    aarch64) DIST=dist-hermetico-aarch64; DEB_ARQ=arm64; SUF_DIST="-aarch64" ;;
    *) echo "arquitectura desconocida: $ARQ" >&2; exit 2 ;;
esac
[ -n "$SALIDA" ] || SALIDA="dist-paquetes$SUF_DIST"
case "$REVISION" in
    '' | *[!0-9]*) echo "--revision tiene que ser un numero: $REVISION" >&2; exit 2 ;;
esac

# La version del workspace, si no se da otra.
if [ -z "$VERSION" ]; then
    VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p}' Cargo.toml)"
fi
[ -n "$VERSION" ] || { echo "no se pudo leer la version del workspace" >&2; exit 1; }
# La licencia, de la misma fuente: el paquete no declara otra que el codigo.
LICENCIA="$(sed -n '/^\[workspace.package\]/,/^\[/{s/^license *= *"\(.*\)"/\1/p}' Cargo.toml)"
[ -n "$LICENCIA" ] || { echo "no se pudo leer la licencia del workspace" >&2; exit 1; }

for h in dpkg-deb rpmbuild sha256sum; do
    command -v "$h" > /dev/null 2>&1 \
        || { echo "falta $h (en Debian/Ubuntu: apt-get install dpkg rpm)" >&2; exit 1; }
done
for b in aegis-agent aegis-watchdog; do
    [ -x "$DIST/$b" ] || { echo "falta $DIST/$b: tools/ci/hermetico.sh o construir-cruzado.sh" >&2; exit 1; }
done
if [ -f "$DIST/SHA256SUMS" ]; then
    (cd "$DIST" && sha256sum --quiet -c SHA256SUMS --ignore-missing) \
        || { echo "$DIST no cuadra con sus SHA256SUMS" >&2; exit 1; }
fi
for s in preinst postinst prerm postrm; do
    sh -n "deploy/paquete/$s" || { echo "deploy/paquete/$s no es sh valido" >&2; exit 1; }
done

# La fecha de TODO lo que va dentro: la del commit, o la que se exporte.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2> /dev/null || echo 0)"
fi
export SOURCE_DATE_EPOCH
export TZ=UTC LC_ALL=C
# dpkg >= 1.21.9: un solo hilo de xz (la salida de xz multihilo depende del
# reparto en bloques).
export DPKG_DEB_THREADS_MAX=1
umask 022

TMP_GLOBAL="$(mktemp -d)"
trap 'rm -rf "$TMP_GLOBAL"' EXIT

# construir <revision> <roto 0|1> <directorio de salida>
construir() {
    local rev="$1" roto="$2" salida="$3"
    local tmp version_completa sufijo raiz deb spec
    tmp="$(mktemp -d "$TMP_GLOBAL/c.XXXXXX")"
    version_completa="$VERSION-$rev"
    sufijo=""; [ "$roto" -eq 1 ] && sufijo=" (roto: el agente no arranca)"

    # ── El arbol que se instala ──────────────────────────────────────────────
    raiz="$tmp/raiz"
    install -d -m 0755 "$raiz/usr/libexec/aegis" "$raiz/usr/lib/systemd/system" "$raiz/usr/bin"
    install -m 0755 "$DIST/aegis-watchdog" "$raiz/usr/libexec/aegis/aegis-watchdog"
    if [ "$roto" -eq 1 ]; then
        printf '#!/bin/sh\n# Agente ROTO de prueba: no arranca, para ejercer la vuelta atras.\nexit 1\n' \
            > "$raiz/usr/libexec/aegis/aegis-agent"
        chmod 0755 "$raiz/usr/libexec/aegis/aegis-agent"
    else
        install -m 0755 "$DIST/aegis-agent" "$raiz/usr/libexec/aegis/aegis-agent"
    fi
    printf '%s%s\n' "$version_completa" "$sufijo" > "$raiz/usr/libexec/aegis/VERSION"
    chmod 0644 "$raiz/usr/libexec/aegis/VERSION"
    # La HUELLA del arbol del que salen los binarios (la graban hermetico.sh y
    # construir-cruzado.sh): la lee el autodiagnostico (FASE 7 del MP-16).
    # Sin ella no se empaqueta: un binario sin procedencia no va a un piloto.
    [ -s "$DIST/HUELLA" ] || { echo "falta $DIST/HUELLA: reconstruye con tools/ci/hermetico.sh" >&2; exit 1; }
    install -m 0644 "$DIST/HUELLA" "$raiz/usr/libexec/aegis/HUELLA"
    if [ -x "$DIST/aegisctl" ]; then
        install -m 0755 "$DIST/aegisctl" "$raiz/usr/bin/aegisctl"
    else
        rmdir "$raiz/usr/bin"
    fi
    install -m 0644 deploy/paquete/aegis-agent.service "$raiz/usr/lib/systemd/system/aegis-agent.service"

    # Las secuencias de mantenimiento, con la version de ESTE paquete dentro.
    install -d -m 0755 "$tmp/scripts"
    for s in preinst postinst prerm postrm; do
        sed "s/@VERSION@/$version_completa/g" "deploy/paquete/$s" > "$tmp/scripts/$s"
        chmod 0755 "$tmp/scripts/$s"
    done

    # ── .deb ─────────────────────────────────────────────────────────────────
    deb="$tmp/deb"
    cp -a "$raiz" "$deb"
    install -d -m 0755 "$deb/DEBIAN"
    {
        echo "Package: aegis-agent"
        echo "Version: $version_completa"
        echo "Architecture: $DEB_ARQ"
        echo "Maintainer: AegisCore <soporte@aegiscore.invalid>"
        echo "Installed-Size: $(du -sk --apparent-size "$raiz" | cut -f1)"
        echo "Section: admin"
        echo "Priority: optional"
        echo "Homepage: https://github.com/arguar13/Antivirus-inteligente"
        echo "Description: AegisCore, agente EDR para Linux"
        echo " Telemetria del kernel por eBPF, arbitro de veredictos y trabajador"
        echo " confinado para el analisis de ficheros, bajo su watchdog."
    } > "$deb/DEBIAN/control"
    chmod 0644 "$deb/DEBIAN/control"
    for s in preinst postinst prerm postrm; do
        install -m 0755 "$tmp/scripts/$s" "$deb/DEBIAN/$s"
    done
    find "$deb" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
    dpkg-deb --root-owner-group -Zxz -z6 --build "$deb" \
        "$salida/aegis-agent_${version_completa}_${DEB_ARQ}.deb" > /dev/null

    # ── .rpm ─────────────────────────────────────────────────────────────────
    # Los mismos scripts, en el spec (rpm pasa $1 numerico y los scripts ya lo
    # entienden), sin el #! y con cada % doblado: rpm expande macros tambien
    # dentro de los scripts, y `date +%s` o `stat -c %Y` no son macros.
    cuerpo() { tail -n +2 "$tmp/scripts/$1" | sed 's/%/%%/g'; }
    spec="$tmp/aegis-agent.spec"
    {
        echo "Name: aegis-agent"
        echo "Version: $VERSION"
        echo "Release: $rev"
        echo "Summary: AegisCore, agente EDR para Linux"
        echo "License: $LICENCIA"
        echo "URL: https://github.com/arguar13/Antivirus-inteligente"
        # Binarios estaticos: no hay dependencias que descubrir, y el
        # descubridor automatico mira el sistema que construye, no el destino.
        echo "AutoReqProv: no"
        echo "%description"
        echo "Telemetria del kernel por eBPF, arbitro de veredictos y trabajador confinado."
        echo "%install"
        echo "cp -a $raiz/. %{buildroot}/"
        echo "%files"
        echo "%dir %attr(0755,root,root) /usr/libexec/aegis"
        echo "%attr(0755,root,root) /usr/libexec/aegis/aegis-agent"
        echo "%attr(0755,root,root) /usr/libexec/aegis/aegis-watchdog"
        echo "%attr(0644,root,root) /usr/libexec/aegis/VERSION"
        echo "%attr(0644,root,root) /usr/libexec/aegis/HUELLA"
        echo "%attr(0644,root,root) /usr/lib/systemd/system/aegis-agent.service"
        [ -f "$raiz/usr/bin/aegisctl" ] && echo "%attr(0755,root,root) /usr/bin/aegisctl"
        echo "%pre"; cuerpo preinst
        echo "%post"; cuerpo postinst
        echo "%preun"; cuerpo prerm
        echo "%postun"; cuerpo postrm
    } > "$spec"
    find "$raiz" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
    # Sin BuildArch en el spec: con una arquitectura que no es la del anfitrion
    # rpmbuild la rechaza («No compatible architectures»); --target si vale.
    # Sin brp-* (strip, build-id, python): los binarios ya vienen terminados, y
    # el strip del anfitrion no sabe de aarch64.
    rpmbuild --quiet -bb --nodeps --target "$ARQ-linux" \
        --define "_topdir $tmp/rpm" \
        --define "_buildhost reproducible" \
        --define "use_source_date_epoch_as_buildtime 1" \
        --define "clamp_mtime_to_source_date_epoch 1" \
        --define "_binary_payload w6.xzdio" \
        --define "_binary_filedigest_algorithm 8" \
        --define "_build_id_links none" \
        --define "debug_package %{nil}" \
        --define "__os_install_post %{nil}" \
        --define "__spec_install_post %{nil}" \
        "$spec" > "$tmp/rpmbuild.log" 2>&1 \
        || { cat "$tmp/rpmbuild.log" >&2; return 1; }
    find "$tmp/rpm/RPMS" -name '*.rpm' -exec cp {} "$salida/" \;

    # ── Lo que tiene que haber dentro, comprobado en el paquete ya hecho ─────
    local f
    for f in ./usr/libexec/aegis/aegis-agent ./usr/libexec/aegis/aegis-watchdog \
        ./usr/lib/systemd/system/aegis-agent.service; do
        dpkg-deb -c "$salida/aegis-agent_${version_completa}_${DEB_ARQ}.deb" | grep >/dev/null " $f\$" \
            || { echo "el .deb no lleva $f" >&2; return 1; }
        rpm -qpl "$salida/aegis-agent-$VERSION-$rev.$ARQ.rpm" 2> /dev/null | grep >/dev/null -x "${f#.}" \
            || { echo "el .rpm no lleva ${f#.}" >&2; return 1; }
    done
}

sumas() {
    (cd "$1" && sha256sum ./*.deb ./*.rpm > SHA256SUMS)
}

case "$MODO" in
    uno)
        mkdir -p "$SALIDA"
        construir "$REVISION" "$ROTO" "$SALIDA"
        sumas "$SALIDA"
        ;;
    matriz)
        # La salida se rehace entera: un paquete de una vuelta anterior en la
        # carga de la matriz probaria un arbol que no es este. Y lleva la HUELLA
        # de los binarios de los que sale: `cargo xtask kernels` la compara con
        # la del arbol antes de meter los paquetes en la microVM, igual que con
        # los binarios sueltos.
        [ -s "$DIST/HUELLA" ] \
            || { echo "falta $DIST/HUELLA: reconstruye con tools/ci/hermetico.sh o construir-cruzado.sh" >&2; exit 1; }
        rm -rf "$SALIDA"
        mkdir -p "$SALIDA"
        cp "$DIST/HUELLA" "$SALIDA/HUELLA"
        construir 1 0 "$SALIDA"
        construir 2 0 "$SALIDA"
        construir 3 1 "$SALIDA"
        {
            for r in 1 2 3; do
                echo "deb $r aegis-agent_${VERSION}-${r}_${DEB_ARQ}.deb"
                echo "rpm $r aegis-agent-${VERSION}-${r}.${ARQ}.rpm"
            done
        } > "$SALIDA/ORDEN"
        sumas "$SALIDA"
        ;;
    reproducible)
        a="$TMP_GLOBAL/a"; b="$TMP_GLOBAL/b"
        mkdir -p "$a" "$b"
        construir "$REVISION" 0 "$a"
        # La segunda, en otro directorio temporal y un segundo despues: lo que
        # cambie entre las dos (rutas, reloj, orden del disco) es una fuente de
        # no-determinismo que arreglar en la causa.
        sleep 1
        construir "$REVISION" 0 "$b"
        sumas "$a"; sumas "$b"
        if diff -u "$a/SHA256SUMS" "$b/SHA256SUMS"; then
            echo "reproducible: dos construcciones -> los mismos paquetes"
            sed 's/^/    /' "$a/SHA256SUMS"
        else
            echo "NO reproducible: las dos construcciones difieren (ver arriba)" >&2
            exit 1
        fi
        exit 0
        ;;
esac
echo "paquetes en $SALIDA: $(ls "$SALIDA" | grep -cE '\.(deb|rpm)$')"
