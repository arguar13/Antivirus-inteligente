# AegisCore - programas eBPF de telemetria (Linux Ring 0)
#
# No se usa vmlinux.h: los programas declaran solo los campos de kernel que
# leen, con preserve_access_index, y libbpf los reubica via CO-RE contra el BTF
# del kernel de destino. Eso elimina bpftool del pipeline y deja la superficie
# de kernel que toca el codigo en un unico fichero auditable.

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
VERIFIER   := $(BUILD)/aegis_bpf_verify

# -nostdinc + el include de clang primero: para el target bpf no hay libc, y
# asi <stdint.h> resuelve al de clang (freestanding, autocontenido) en vez de
# al de glibc, que arrastra bits/libc-header-start.h y no compila.
BPF_CFLAGS := -target bpf -O2 -g \
              -Wall -Wextra -Werror \
              -Wno-unused-parameter \
              -ffreestanding -nostdinc \
              -isystem $(CLANG_INC) \
              -isystem /usr/include \
              $(if $(MULTIARCH),-isystem /usr/include/$(MULTIARCH)) \
              -Iinclude -I$(ABI_INC) \
              -D__TARGET_ARCH_$(ARCH)

VERIFY_CFLAGS := -O2 -Wall -Wextra -Werror -Iinclude -I$(ABI_INC)
VERIFY_LDLIBS := -lbpf -lelf -lz

.PHONY: build verify sign check-integrity clean dump

build: $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ)

$(BUILD):
	@mkdir -p $(BUILD)

$(BPF_OBJ): src/aegis_probes.bpf.c include/aegis_bpf_common.h $(ABI_INC)/aegis_abi.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  BPF   $@"

$(XDP_OBJ): src/aegis_xdp.bpf.c include/aegis_bpf_common.h $(ABI_INC)/aegis_abi.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  BPF   $@"

$(KI_OBJ): src/aegis_kintegrity.bpf.c include/aegis_bpf_common.h include/aegis_kintegrity.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "  BPF   $@"

$(VERIFIER): tools/aegis_bpf_verify.c | $(BUILD)
	$(CC) $(VERIFY_CFLAGS) $< -o $@ $(VERIFY_LDLIBS)

# Carga los programas en el kernel y los somete al verificador.
#
# Compilar no demuestra nada en eBPF: el verificador del kernel rechaza
# programas que compilan perfectamente (accesos no acotados, bucles que no
# puede probar que terminan, punteros sin comprobar). Esta es la prueba real.
verify: $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ) $(VERIFIER)
	@./$(VERIFIER) $(BPF_OBJ)
	@./$(VERIFIER) $(XDP_OBJ)
	@./$(VERIFIER) $(KI_OBJ)

# Firma HMAC-SHA256 del bytecode. Se ejecuta tras compilar: el manifiesto que
# produce lo verifica el agente antes de cargar cada programa en el kernel.
sign: $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ)
	@python3 tools/sign_bytecode.py sign $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ)

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
check-integrity: $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ)
	@python3 tools/sign_bytecode.py sign $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ)
	@python3 tools/sign_bytecode.py check $(BPF_OBJ) $(XDP_OBJ) $(KI_OBJ)

dump: $(BPF_OBJ)
	llvm-objdump -S --no-show-raw-insn $(BPF_OBJ)

clean:
	rm -rf $(BUILD)
