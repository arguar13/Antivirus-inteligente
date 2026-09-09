# AegisCore - atajos de desarrollo.
#
# `make ci` corre las mismas comprobaciones que el pipeline remoto. Mientras
# GitHub Actions siga bloqueado (docs/07-estado-ci.md), es la puerta de calidad
# real del proyecto.

.PHONY: ci audit test lint fmt abi bpf bpf-verify devsecops fuzz sanitize vulns clean help

help:
	@echo "make ci          - todas las comprobaciones (equivalente al CI remoto)"
	@echo "make audit       - auditoria final de release (estres + red team en paralelo)"
	@echo "make test        - cargo test"
	@echo "make lint        - cargo clippy -D warnings"
	@echo "make fmt         - cargo fmt (aplica cambios)"
	@echo "make abi         - verifica que el layout de C y el de Rust coinciden"
	@echo "make bpf         - compila los programas eBPF"
	@echo "make bpf-verify  - carga los programas y los pasa por el verificador"
	@echo "make devsecops   - pipeline continuo: fuzzing + sanitizadores + auditoria"
	@echo "make fuzz        - fuzzing continuo de los parsers (libFuzzer)"
	@echo "make sanitize    - pruebas de los crates unsafe bajo AddressSanitizer"
	@echo "make vulns       - auditoria de vulnerabilidades de dependencias (RustSec)"
	@echo "make clean       - limpia artefactos"

ci:
	@./tools/ci-local.sh

audit:
	@./tests/final_audit.sh

test:
	cargo test --all

lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt --all

abi:
	@CC=gcc   ./tools/abi-check.sh
	@CC=clang ./tools/abi-check.sh

bpf:
	@$(MAKE) -C drivers/linux/aegis-bpf build

bpf-verify:
	@$(MAKE) -C drivers/linux/aegis-bpf verify

devsecops:
	@./tools/devsecops.sh

fuzz:
	@./tools/fuzz.sh

sanitize:
	@./tools/sanitize.sh

vulns:
	@./tools/audit.sh

clean:
	cargo clean
	@$(MAKE) -C drivers/linux/aegis-bpf clean
	rm -rf fuzz/target fuzz/corpus fuzz/artifacts fuzz/coverage
