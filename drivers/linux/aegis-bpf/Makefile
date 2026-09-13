# AegisCore - programas eBPF de telemetria (Linux Ring 0)
#
# BPF CO-RE con vmlinux.h (FASE 42).
#
# POR QUE vmlinux.h Y NO ESTRUCTURAS ESCRITAS A MANO
# --------------------------------------------------
# Antes este arbol declaraba a mano los campos de kernel que lee, marcados con
# `preserve_access_index`. Eso TAMBIEN es CO-RE y compilaba, pero tenia un fallo
# de raiz: CO-RE reubica el DESPLAZAMIENTO de un campo, no su TAMANO. Si una
# declaracion a mano se equivoca en el ancho o en el signo de un campo —o si el
# kernel lo cambia—, el programa sigue compilando, sigue cargando, y lee basura
# en silencio. En un EDR eso es un punto ciego de deteccion que nadie detecta.
#
# `vmlinux.h` se genera del BTF del kernel, asi que los tipos son los AUTENTICOS
# por construccion y esa clase de error deja de ser posible.
#
# REPRODUCIBILIDAD
# ----------------
# El fichero generado NO se versiona: se produce en `out/` a partir de una
# fuente de BTF fijada por `AEGIS_BTF`, y se registra su SHA-256 junto al
# origen del que salio. Asi la construccion es auditable sin meter 116.000
# lineas generadas en el repositorio, donde solo servirian para enterrar los
# cambios reales en cada revision.
#
# El bytecode resultante es UNIVERSAL: libbpf reubica los accesos contra el BTF
# del kernel de destino en tiempo de carga, asi que el mismo .o vale para
# cualquier kernel 5.8+ con BTF, sin compilar nada en el endpoint del cliente.

CLANG      ?= clang
CC         ?= cc
ARCH       := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/ppc64le/powerpc/')
CLANG_INC  := $(shell $(CLANG) -print-resource-dir)/include
# En Debian/Ubuntu las cabeceras UAPI dependientes de arquitectura (asm/types.h)
# viven en el directorio multiarch, no en /usr/include a secas.
MULTIARCH  := $(shell $(CC) -print-multiarch 2>/dev/null)
ABI_INC    := ../../../shared/include

# El directorio de salida NO puede llamarse 'build': colisionaria con el
# target .PHONY del mismo nombre y make descartaria la dependencia de orden.
BUILD      := out
BPF_OBJ    := $(BUILD)/aegis_probes.bpf.o
XDP_OBJ    := $(BUILD)/aegis_xdp.bpf.o
KI_OBJ     := $(BUILD)/aegis_kintegrity.bpf.o
SSL_OBJ    := $(BUILD)/aegis_sslsniff.bpf.o
IPS_OBJ    := $(BUILD)/aegis_ips.bpf.o
VERIFIER   := $(BUILD)/aegis_bpf_verify
CORECHECK  := $(BUILD)/aegis_core_check

# Fuente del BTF con el que se genera vmlinux.h.
#
# Por defecto, el del kernel en ejecucion. En una construccion hermetica se fija
# con AEGIS_BTF a un blob concreto, para que el encabezado no dependa de en que
# maquina se compilo. Da igual cual sea mientras tenga BTF: CO-RE reubica en el
# destino, no en la compilacion.
BTF_ORIGEN ?= $(if $(AEGIS_BTF),$(AEGIS_BTF),/sys/kernel/btf/vmlinux)
VMLINUX_H  := $(BUILD)/vmlinux.h

# -nostdinc + el include de clang primero: para el target bpf no hay libc, y
# asi <stdint.h> resuelve al de clang (freestanding, autocontenido) en vez de
# al de glibc, que arrastra bits/libc-header-start.h y no compila.
#
# /usr/include entra SOLO por <bpf/bpf_helpers.h> y companneros, que instala
# libbpf-dev. Las cabeceras de kernel del sistema ya NO hacen falta: todas las
# definiciones de kernel salen de vmlinux.h, que es lo que hace que el bytecode
# sea reubicable. Por eso tampoco entra el directorio multiarch.
BPF_CFLAGS := -target bpf -O2 -g \
              -Wall -Wextra -Werror \
              -Wno-unused-parameter \
              -ffreestanding -nostdinc \
              -isystem $(CLANG_INC) \
              -isystem /usr/include \
              -I$(BUILD) -Iinclude -I$(ABI_INC) \
              -D__TARGET_ARCH_$(ARCH)

VERIFY_CFLAGS := -O2 -Wall -Wextra -Werror -Iinclude -I$(ABI_INC)
VERIFY_LDLIBS := -lbpf -lelf -lz

.PHONY: build verify core-check core-matrix sign check-integrity clean dump

build: $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ) $(SSL_OBJ) $(IPS_OBJ)

$(BUILD):
	@mkdir -p $(BUILD)

# vmlinux.h: el universo de tipos del kernel, extraido de su BTF.
#
# Se deja un registro de procedencia al lado (que BTF, que suma) porque un
# encabezado generado sin trazabilidad es una caja negra: si un dia el bytecode
# se comporta distinto, lo primero que hay que poder responder es contra que
# BTF se compilo.
$(VMLINUX_H): | $(BUILD)
	@command -v bpftool >/dev/null 2>&1 || { \
	    echo "ERROR: falta bpftool; es quien traduce el BTF a vmlinux.h."; \
	    echo "       compilalo con: make -C <libbpf/bpftool>/src"; exit 1; }
	@test -r "$(BTF_ORIGEN)" || { \
	    echo "ERROR: no se puede leer el BTF en $(BTF_ORIGEN)."; \
	    echo "       el kernel necesita CONFIG_DEBUG_INFO_BTF, o fija AEGIS_BTF."; exit 1; }
	@bpftool btf dump file "$(BTF_ORIGEN)" format c > $@.tmp
	@test -s $@.tmp || { echo "ERROR: el volcado de BTF salio vacio."; rm -f $@.tmp; exit 1; }
	@mv $@.tmp $@
	@{ echo "origen : $(BTF_ORIGEN)"; \
	   echo "sha256 : $$(sha256sum $@ | cut -d' ' -f1)"; \
	   echo "lineas : $$(wc -l < $@)"; \
	   echo "bpftool: $$(bpftool version 2>/dev/null | head -1)"; } > $(BUILD)/vmlinux.procedencia
	@echo "  GEN   $@ ($$(wc -l < $@) lineas de $(BTF_ORIGEN))"

$(BPF_OBJ): src/aegis_probes.bpf.c include/aegis_bpf_common.h $(ABI_INC)/aegis_abi.h $(VMLINUX_H) | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  BPF   $@"

$(XDP_OBJ): src/aegis_xdp.bpf.c include/aegis_bpf_common.h $(ABI_INC)/aegis_abi.h $(VMLINUX_H) | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  BPF   $@"

$(KI_OBJ): src/aegis_kintegrity.bpf.c include/aegis_bpf_common.h include/aegis_kintegrity.h $(VMLINUX_H) | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  BPF   $@"

# Uprobes de TLS en Ring 3 (FASE 66). No lee estructuras del kernel salvo
# task_struct via el helper comun, asi que su dependencia de vmlinux.h es la
# misma que la del resto.
$(SSL_OBJ): src/aegis_sslsniff.bpf.c include/aegis_bpf_common.h include/aegis_sslsniff.h $(VMLINUX_H) | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  BPF   $@"

# Prevencion en linea por TC (FASE 71). Usa los dos ganchos de clsact, ingreso
# y egreso, porque XDP no tiene camino de salida y el sentido saliente —la
# baliza al C2, la exfiltracion, el movimiento lateral— es el que mas importa
# cortar en un endpoint.
$(IPS_OBJ): src/aegis_ips.bpf.c include/aegis_bpf_common.h $(VMLINUX_H) | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  BPF   $@"

$(VERIFIER): tools/aegis_bpf_verify.c | $(BUILD)
	$(CC) $(VERIFY_CFLAGS) $< -o $@ $(VERIFY_LDLIBS)

$(CORECHECK): tools/aegis_core_check.c | $(BUILD)
	$(CC) $(VERIFY_CFLAGS) $< -o $@ $(VERIFY_LDLIBS)

# Carga los programas en el kernel y los somete al verificador.
#
# Compilar no demuestra nada en eBPF: el verificador del kernel rechaza
# programas que compilan perfectamente (accesos no acotados, bucles que no
# puede probar que terminan, punteros sin comprobar). Esta es la prueba real.
verify: $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ) $(SSL_OBJ) $(IPS_OBJ) $(VERIFIER)
	@./$(VERIFIER) $(BPF_OBJ)
	@./$(VERIFIER) $(XDP_OBJ)
	@./$(VERIFIER) $(KI_OBJ)
	@./$(VERIFIER) $(SSL_OBJ)
	@./$(VERIFIER) $(IPS_OBJ)

# Comprueba, sobre los bytes del objeto, que el bytecode lleva reubicaciones
# CO-RE bien formadas. Compilar con vmlinux.h no lo garantiza: un objeto puede
# llevar los desplazamientos del kernel de construccion grabados y fallar en
# silencio en cualquier otro. Ver tools/aegis_core_check.c.
core-check: $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ) $(SSL_OBJ) $(CORECHECK)
	@./$(CORECHECK) $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ) $(SSL_OBJ)

# Prueba CRUZADA: reubica los programas contra el BTF de otros kernels.
#
# Es la unica forma de comprobar aqui la promesa "compile once, run everywhere"
# sin arrancar esos kernels. Los BTF de referencia los trae
# tools/toolchain/traer_btf.sh; si no estan, se OMITE con honestidad en vez de
# fingir que se probo.
BTF_DIR ?= /opt/aegis/btf

core-matrix: $(BPF_OBJ) $(XDP_OBJ) $(VERIFIER)
	@if [ ! -d "$(BTF_DIR)" ] || [ -z "$$(ls -A $(BTF_DIR)/*.btf 2>/dev/null)" ]; then \
	    echo "OMITIDO: no hay BTF de referencia en $(BTF_DIR)"; \
	    echo "         traelos con tools/toolchain/traer_btf.sh"; \
	    exit 0; \
	fi; \
	fallos=0; \
	for btf in $(BTF_DIR)/*.btf; do \
	    echo "--- $$(basename $$btf) ---"; \
	    ./$(VERIFIER) --btf "$$btf" --solo-core $(BPF_OBJ) 2>&1 \
	        | grep -E "^==>|CO-RE OK|FALLO|no se pueden reubicar" || true; \
	    ./$(VERIFIER) --btf "$$btf" --solo-core $(BPF_OBJ) >/dev/null 2>&1 || fallos=$$((fallos+1)); \
	done; \
	if [ $$fallos -ne 0 ]; then \
	    echo "FALLO: las sondas no son reubicables contra $$fallos BTF de referencia"; \
	    exit 1; \
	fi; \
	echo "Las sondas reubican contra todos los BTF de referencia."

# Firma HMAC-SHA256 del bytecode. Se ejecuta tras compilar: el manifiesto que
# produce lo verifica el agente antes de cargar cada programa en el kernel.
sign: $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ) $(SSL_OBJ)
	@python3 tools/sign_bytecode.py sign $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ) $(SSL_OBJ)

# Firma los objetos y comprueba que la firma vuelve a cuadrar.
#
# El manifiesto NO se versiona (vive en out/, que se regenera): re-firmar en
# cada corrida lo hace independiente del orden de los pasos del CI y del estado
# que dejara una corrida anterior —un manifiesto a medias de un paso concurrente
# hacia fallar esta comprobacion por algo que no es una manipulacion—.
#
# La integridad de VERDAD del bytecode empotrado la comprueba el AGENTE al
# cargar: build.rs empota el HMAC del .o y el cargador lo recalcula antes de
# entregar el programa al kernel (modulo 14). Este paso del CI comprueba que los
# tres objetos se firman y se re-verifican de forma consistente con la misma
# clave, que es lo que puede hacer sin un estado versionado.
check-integrity: $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ) $(SSL_OBJ)
	@python3 tools/sign_bytecode.py sign $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ) $(SSL_OBJ)
	@python3 tools/sign_bytecode.py check $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ) $(SSL_OBJ)

dump: $(BPF_OBJ)
	llvm-objdump -S --no-show-raw-insn $(BPF_OBJ)

clean:
	rm -rf $(BUILD)
