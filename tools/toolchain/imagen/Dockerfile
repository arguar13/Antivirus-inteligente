#
# AegisCore - imagen de construccion hermetica (FASE 42).
#
# QUE PROBLEMA RESUELVE
# ---------------------
# Hasta la FASE 41 los artefactos salian enlazados dinamicamente contra la libc
# de la maquina que los compilo. Eso significa que el agente que se entrega a un
# cliente depende de que su endpoint tenga la MISMA glibc que el runner de CI, y
# el fallo no aparece en el laboratorio: aparece en el despliegue, en forma de
# "version `GLIBC_2.38' not found" en la mitad de la flota.
#
# Esta imagen empaqueta todo lo necesario para producir binarios que no dependen
# de nada del anfitrion:
#
#   - Rust fijado a una version concreta, con el objetivo musl.
#   - Un sysroot musl COMPLETO (libc + UAPI del kernel + argp + obstack +
#     desenrollador), que construye tools/toolchain/preparar_musl.sh.
#   - clang y llvm para compilar el bytecode eBPF.
#   - bpftool compilado desde fuente, que es quien genera vmlinux.h y hace
#     posible BPF CO-RE.
#
# POR QUE UNA IMAGEN Y NO UN SCRIPT DE INSTALACION
# ------------------------------------------------
# Porque "hermetico" quiere decir que la construccion no puede depender de lo
# que cada desarrollador tenga instalado. El script existe igual (y es el que
# corre aqui dentro), pero la imagen fija ademas la distribucion base, las
# versiones de los paquetes y el toolchain, y se puede publicar por digest.
#
# Uso:
#   docker build -f tools/toolchain/imagen/Dockerfile -t aegis/hermetico:1 .
#   docker run --rm -v "$PWD:/aegis" -w /aegis aegis/hermetico:1 \
#       tools/ci/hermetico.sh
#
# Version del contenido, no de la imagen: subir esto obliga a reconstruir.
# La base se fija por DIGEST, no por etiqueta. `24.04` es una etiqueta movil:
# apunta a una imagen distinta cada pocas semanas, y con ella cambiarian en
# silencio las versiones de gcc, binutils y musl con las que se construye el
# producto. Un digest es inmutable.
#
# Ubuntu 24.04 y no otra distribucion porque es la MISMA base que usan los
# runners de .github/workflows/aegis_ci.yml. Si la imagen hermetica y el CI
# partieran de distribuciones distintas, un fallo que solo aparece en una de las
# dos costaria dias de encontrar.
ARG BASE=ubuntu:24.04@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254

FROM ${BASE}

LABEL org.opencontainers.image.title="AegisCore hermetic builder" \
      org.opencontainers.image.description="Toolchain estatico musl + LLVM + BPF CO-RE" \
      org.opencontainers.image.source="https://github.com/arguar13/Antivirus-inteligente" \
      org.opencontainers.image.licenses="Apache-2.0"

# Versiones fijadas. Un toolchain que se mueve solo no es hermetico: dos
# construcciones del mismo commit darian binarios distintos y nadie sabria por
# que.
# Tiene que ser el `channel` de rust-toolchain.toml: lo comprueba
# tools/toolchain/comprobar_toolchain.sh (grupo `toolchain` de make ci).
ARG RUST_VERSION=1.94.0
ARG BPFTOOL_VERSION=v7.5.0
ARG LLVM_VERSION=18

# Espejo de paquetes. Se deja como argumento porque en una red corporativa la
# salida a archive.ubuntu.com suele estar cerrada y hay un espejo interno; y
# porque algunos proxies solo permiten CONNECT (HTTPS) y rechazan el GET en
# claro que usa apt por defecto. Cambiarlo a https:// resuelve ese caso.
ARG APT_MIRROR=http://archive.ubuntu.com/ubuntu
ARG APT_MIRROR_SEC=http://security.ubuntu.com/ubuntu

# ---------------------------------------------------------------------------
# 0. Certificados de CA adicionales (opcional)
#
# Muchas organizaciones salen a internet por un proxy con inspeccion TLS. Sin su
# CA en el almacen de confianza, `curl`, `git` y `cargo` fallan dentro de la
# imagen con errores de certificado que no dicen nada. El directorio se copia
# siempre; si solo trae su LEEME.md, no se anade ninguna CA.
# ---------------------------------------------------------------------------
COPY tools/toolchain/imagen/ca/ /usr/local/share/ca-certificates/aegis-extra/

# La imagen base no trae almacen de confianza: `ca-certificates` se instala mas
# abajo, y para instalarlo hace falta apt... que, si el espejo es https, ya
# necesita confiar en alguien. Se rompe el circulo apuntando apt directamente al
# certificado que se acaba de copiar, antes de que exista ningun almacen.
RUN set -eu; \
    rm -f /usr/local/share/ca-certificates/aegis-extra/LEEME.md; \
    if ls /usr/local/share/ca-certificates/aegis-extra/*.crt >/dev/null 2>&1; then \
        cat /usr/local/share/ca-certificates/aegis-extra/*.crt > /etc/aegis-ca.crt; \
        printf 'Acquire::https::CAInfo "/etc/aegis-ca.crt";\n' \
            > /etc/apt/apt.conf.d/99-aegis-ca; \
        echo "CA adicional instalada para apt"; \
    else \
        echo "sin CA adicional: se usa el almacen estandar"; \
    fi

# Espejo de paquetes, si se pidio uno distinto del de la imagen base.
ARG APT_MIRROR
ARG APT_MIRROR_SEC
RUN set -eu; \
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources; do \
        [ -f "$f" ] || continue; \
        sed -i -e "s#http://archive.ubuntu.com/ubuntu#${APT_MIRROR}#g" \
               -e "s#http://security.ubuntu.com/ubuntu#${APT_MIRROR_SEC}#g" "$f"; \
    done

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:$PATH \
    AEGIS_MUSL_SYSROOT=/opt/aegis/musl-sysroot \
    AEGIS_MUSL_CACHE=/opt/aegis/cache

# ---------------------------------------------------------------------------
# 1. Paquetes del sistema
#
# Cada grupo esta por un motivo concreto:
#   build-essential, binutils : compilador C anfitrion, ar, nm, readelf
#   musl-tools, musl-dev      : la libc estatica y su specs
#   linux-libc-dev            : las cabeceras UAPI del kernel para el sysroot
#   clang, llvm, libbpf-dev   : bytecode eBPF y las cabeceras de libbpf
#   libelf-dev, zlib1g-dev    : para compilar bpftool
#   autotools + gettext       : elfutils y los complementos musl los necesitan
#   file, python3, git, curl  : verificacion de artefactos, firma, fuentes
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        binutils \
        ca-certificates \
        curl \
        git \
        file \
        make \
        pkg-config \
        python3 \
        musl-tools \
        musl-dev \
        linux-libc-dev \
        clang-${LLVM_VERSION} \
        llvm-${LLVM_VERSION} \
        libbpf-dev \
        libelf-dev \
        zlib1g-dev \
        autoconf \
        automake \
        autopoint \
        libtool-bin \
        gettext \
        flex \
        bison \
        gawk \
        m4 \
        xz-utils \
    && rm -f /usr/local/share/ca-certificates/aegis-extra/LEEME.md \
    && update-ca-certificates \
    && ln -sf /usr/bin/clang-${LLVM_VERSION} /usr/bin/clang \
    && ln -sf /usr/bin/llvm-objdump-${LLVM_VERSION} /usr/bin/llvm-objdump \
    && ln -sf /usr/bin/llvm-strip-${LLVM_VERSION} /usr/bin/llvm-strip \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 2. bpftool desde fuente
#
# Es quien traduce el BTF del kernel a vmlinux.h, sin el cual no hay BPF CO-RE.
# Se compila desde fuente y no se instala del repositorio porque el paquete de
# la distribucion es un envoltorio que despacha a un binario ligado a la version
# EXACTA del kernel del anfitrion, y dentro de un contenedor ese binario no
# existe: el envoltorio imprime un aviso y devuelve exito, que es la peor forma
# posible de fallar.
# ---------------------------------------------------------------------------
RUN git clone --quiet --depth 1 --recurse-submodules --shallow-submodules \
        -b ${BPFTOOL_VERSION} https://github.com/libbpf/bpftool /tmp/bpftool \
    && make -C /tmp/bpftool/src -j"$(nproc)" \
    && install -m 0755 /tmp/bpftool/src/bpftool /usr/local/bin/bpftool \
    && rm -rf /tmp/bpftool \
    && bpftool version

# ---------------------------------------------------------------------------
# 3. Rust fijado, con el objetivo musl
# ---------------------------------------------------------------------------
# Se descarga el instalador CANONICO y se verifica su suma antes de ejecutarlo,
# en vez del habitual `curl https://sh.rustup.rs | sh`. Dos motivos, y ninguno
# es cosmetico:
#
#   1. En una tuberia, un fallo de curl NO detiene la orden: `sh` recibe una
#      entrada vacia, termina con exito, y el error solo aparece varias lineas
#      despues como "rustup: not found". La causa real queda enterrada.
#   2. Ejecutar sin verificar un guion descargado, dentro de la imagen que
#      construye un producto de seguridad, es precisamente lo que este producto
#      detecta como comportamiento sospechoso en un endpoint.
ARG RUSTUP_DIST=https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu
RUN set -eu; \
    curl -fsSL -o /tmp/rustup-init      "${RUSTUP_DIST}/rustup-init"; \
    curl -fsSL -o /tmp/rustup-init.sha256 "${RUSTUP_DIST}/rustup-init.sha256"; \
    cd /tmp && sha256sum -c rustup-init.sha256; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --profile minimal \
        --default-toolchain "${RUST_VERSION}" \
        --component clippy --component rustfmt; \
    rm -f /tmp/rustup-init /tmp/rustup-init.sha256; \
    rustup target add x86_64-unknown-linux-musl; \
    chmod -R a+w "${RUSTUP_HOME}" "${CARGO_HOME}"; \
    rustc --version; cargo --version

# ---------------------------------------------------------------------------
# 4. El sysroot musl
#
# Se construye con el MISMO script que usa un desarrollador en su maquina, no
# con una receta paralela: si los dos caminos divergieran, el CI dejaria de
# probar lo que la gente ejecuta.
# ---------------------------------------------------------------------------
COPY tools/toolchain/preparar_musl.sh /tmp/aegis/tools/toolchain/
COPY tools/ci/_comun.sh               /tmp/aegis/tools/ci/
COPY tools/toolchain/fijado.sh tools/toolchain/fijado.toml /tmp/aegis/tools/toolchain/
RUN /tmp/aegis/tools/toolchain/preparar_musl.sh && rm -rf /tmp/aegis

ENV CC_x86_64_unknown_linux_musl=/opt/aegis/musl-sysroot/bin/aegis-musl-gcc \
    AR_x86_64_unknown_linux_musl=ar \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/opt/aegis/musl-sysroot/bin/aegis-musl-gcc

WORKDIR /aegis
CMD ["/bin/bash"]
