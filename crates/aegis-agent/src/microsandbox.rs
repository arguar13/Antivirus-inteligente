//! Puente del micro-sandbox de emulacion (FASE 56).
//!
//! Cuando el agente se topa con un binario DESCONOCIDO —su hash no esta ni en la
//! lista de confianza ni en la de amenazas— el analisis estatico y las firmas no
//! bastan, sobre todo si viene empaquetado. En vez de EJECUTARLO en el host para
//! ver que hace (lo que el malware agradeceria), el agente lo **emula** en
//! `aegis-emu`: ni una instruccion del binario toca el procesador real, sus
//! escrituras caen en memoria virtual y sus llamadas al sistema se interceptan.
//! De la traza sale un veredicto de comportamiento en microsegundos.
//!
//! El emulador viaja DENTRO del binario del agente y es Rust puro: no hay
//! dependencia nativa que engorde la superficie de ataque de la propia defensa,
//! ni fichero externo que un atacante pueda borrar para cegarlo.

use aegis_emu::{AegisSandbox, InformeSandbox};

/// El micro-sandbox del agente. Se construye una vez; analizar despues es barato.
pub struct MicroSandbox {
    sandbox: AegisSandbox,
}

impl Default for MicroSandbox {
    fn default() -> Self {
        Self::nuevo()
    }
}

impl MicroSandbox {
    /// Crea el micro-sandbox con la configuracion por defecto.
    #[must_use]
    pub fn nuevo() -> Self {
        Self {
            sandbox: AegisSandbox::nuevo(),
        }
    }

    /// Emula el codigo de entrada de un binario desconocido y devuelve el informe
    /// completo (veredicto, traza de comportamiento y la carga desempaquetada si
    /// se desplego a si mismo).
    #[must_use]
    pub fn analizar(&self, codigo: &[u8]) -> InformeSandbox {
        self.sandbox.analizar(codigo)
    }

    /// Decision de respuesta del agente: aislar el binario si su comportamiento
    /// emulado es concluyentemente malicioso (auto-inyeccion, C2, ransomware). Un
    /// desempaquetador se marca para volcar y re-escanear su carga, pero no se
    /// aisla de plano: empaquetar no es, por si solo, malicioso.
    #[must_use]
    pub fn debe_aislar(&self, informe: &InformeSandbox) -> bool {
        informe.veredicto.malicioso
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_emu::ClaseComportamiento;

    #[test]
    fn aisla_un_binario_desconocido_que_se_auto_inyecta() {
        // mmap(RWX) + escribir un HLT en la region + saltar a ella.
        let stub = [
            0xB8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9 (mmap)
            0x31, 0xFF, // xor edi, edi
            0xBE, 0x00, 0x10, 0x00, 0x00, // mov esi, 0x1000
            0xBA, 0x07, 0x00, 0x00, 0x00, // mov edx, 7 (RWX)
            0x0F, 0x05, // syscall
            0xC6, 0x00, 0xF4, // mov byte [rax], 0xF4
            0xFF, 0xE0, // jmp rax
        ];
        let ms = MicroSandbox::nuevo();
        let informe = ms.analizar(&stub);
        assert_eq!(informe.veredicto.clase, ClaseComportamiento::AutoInyeccion);
        assert!(ms.debe_aislar(&informe), "el agente debe aislarlo");
    }

    #[test]
    fn no_aisla_un_binario_desconocido_benigno() {
        // read + exit: no hay razon para aislar.
        let stub = [
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0 (read)
            0x0F, 0x05, // syscall
            0xB8, 0x3C, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
            0x31, 0xFF, // xor edi, edi
            0x0F, 0x05, // syscall
        ];
        let ms = MicroSandbox::nuevo();
        let informe = ms.analizar(&stub);
        assert_eq!(informe.veredicto.clase, ClaseComportamiento::Benigno);
        assert!(!ms.debe_aislar(&informe));
    }
}
