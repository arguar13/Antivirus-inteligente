//! Autoataque de la integridad: reescribir la linea base, e inundar de ruido.
//!
//! Dos ataques contra un FIM: (a) el de AIDE/Tripwire —root reescribe la linea
//! base y la recalcula—, que aqui no cuela porque no puede volver a firmarla; y
//! (b) inundar de cambios de ruido (comentarios, espacios) para tapar el cambio
//! real y agotar al analista, que aqui no cuela porque se mira POR SIGNIFICADO.
//! Ademas, mil cambios sinteticos conservan cada uno su autor correcto.

use aegis_entidad::entidad;
use aegis_integridad::{
    analizar_cambio, Autor, CambioConAutor, CambioSemantico, Credenciales, ErrorLineaBase, Formato,
    LineaBase,
};
use aegis_pqc::firma_hibrida::ClaveFirmaHibrida;
use aegis_sensor::{Evento, Familia};

fn maq() -> aegis_entidad::Eid {
    entidad::maquina("m-1")
}

#[test]
fn mil_cambios_sinteticos_conservan_su_autor_correcto() {
    // Cada cambio lo hace un proceso distinto; el evento nace del kernel y el
    // autor viaja dentro. Al final, cada cambio dice QUIEN, sin ninguna relectura.
    let m = maq();
    for pid in 0..1000u32 {
        let evento = Evento::nuevo(
            Familia::Fichero,
            entidad::ubicacion(&m, "/etc/ssh/sshd_config"),
            Some("/etc/ssh/sshd_config".to_string()),
            vec![],
            u64::from(pid),
        );
        let proceso = entidad::proceso(&m, 0, pid, 0);
        let autor = Autor::nuevo(proceso.clone(), Credenciales::root(), vec![proceso.clone()]);
        let cambio = CambioConAutor::desde_evento(&evento, autor);
        assert_eq!(
            cambio.autor.proceso, proceso,
            "el autor es el del pid {pid}"
        );
        assert!(cambio.autor.desciende_de(&proceso));
        assert_eq!(cambio.cuando_ns, u64::from(pid));
    }
}

#[test]
fn root_reescribe_la_linea_base_y_no_cuela() {
    let sk = ClaveFirmaHibrida::desde_semillas(&[3u8; 32], &[5u8; 32]);
    let vk = sk.clave_verificacion();
    let pcr = [1u8; 32];
    let sellada = LineaBase::nueva()
        .con_binario("/usr/sbin/sshd", b"bueno")
        .sellar(pcr, &sk)
        .unwrap();
    // El atacante recalcula la linea base con su binario y la mete en su sitio,
    // pero no tiene la clave del plano de control para volver a firmarla.
    let malvada = LineaBase::nueva().con_binario("/usr/sbin/sshd", b"con puerta trasera");
    let bytes_malvados = malvada
        .sellar(
            pcr,
            &ClaveFirmaHibrida::desde_semillas(&[99u8; 32], &[99u8; 32]),
        )
        .unwrap();
    let reescrita = sellada.con_cuerpo_reescrito(bytes_malvados.cuerpo().to_vec());
    assert_eq!(
        reescrita.abrir(&vk, pcr),
        Err(ErrorLineaBase::FirmaInvalida)
    );
}

#[test]
fn inundar_de_comentarios_no_tapa_el_cambio_real() {
    // El atacante genera mil cambios de ruido (comentarios) para tapar su puerta
    // trasera y agotar al analista. Por significado, el ruido no produce NI UNA
    // alerta; el cambio real, si.
    let bueno = "PermitRootLogin no\nPort 22\n";
    for i in 0..1000 {
        let ruido = format!("# nota numero {i}\n{bueno}\n\n   \n");
        assert!(
            analizar_cambio(Formato::SshdConfig, bueno, &ruido).is_empty(),
            "el comentario {i} no puede ser una alerta"
        );
    }
    // Entre todo el ruido, la puerta trasera real se ve.
    let backdoor = "# ruido\nPermitRootLogin yes\nPort 22\n";
    let c = analizar_cambio(Formato::SshdConfig, bueno, backdoor);
    assert_eq!(c.len(), 1);
    assert!(matches!(&c[0], CambioSemantico::PermitRootLogin { .. }));
}
