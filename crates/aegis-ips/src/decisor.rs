//! El motor de decision: hechos entran, veredictos salen.
//!
//! # Sans-io, por la misma razon que la FASE 70
//!
//! Este tipo no carga programas eBPF, no escribe mapas y no toca la red. Se le
//! dan hechos y devuelve veredictos. Eso permite construir **entero, en una
//! prueba**, cada caso que importa: que un activo protegido no se corta ni con
//! la regla de maxima confianza, que el modo aprendizaje no corta, que el
//! limitador degrada y lo declara. Si decidir dependiera de tener privilegios de
//! kernel, la parte del producto que decide cortar la red de un cliente seria
//! justo la que no se puede probar.
//!
//! # El orden de las comprobaciones ES la seguridad
//!
//! 1. ¿Casa alguna regla? Si no, no hay nada que decidir.
//! 2. ¿Tiene confianza suficiente para cortar? Si no, alerta.
//! 3. ¿Hay un activo protegido en el flujo? Si lo hay, **jamas** se corta.
//! 4. ¿El modo corta? Si no, se anota lo que se habria cortado.
//! 5. ¿El limitador lo permite? Si no, se degrada y se declara.
//!
//! Cambiar ese orden cambia lo que el producto hace. En particular, el paso 3 va
//! antes que el 4 y el 5 a proposito: un activo protegido tiene que registrarse
//! como protegido aunque el modo ya no cortara, porque esa cifra —cuantas veces
//! la salvaguarda ha hecho falta— es la que dice si el motor de reglas se esta
//! equivocando en algo grave.

use aegis_wire::hecho::{HechoConContexto, Transporte};

use crate::limitador::{Limitador, Permiso};
use crate::modo::Modo;
use crate::protegidos::Protegidos;
use crate::regla::Regla;
use crate::veredicto::{Accion, Flujo, MotivoNoCorte, Veredicto};

/// Configuracion del motor de decision.
#[derive(Debug, Clone)]
pub struct ConfigDecisor {
    /// Modo de operacion. Por defecto, [`Modo::SoloDeteccion`].
    pub modo: Modo,
    /// Cuanto dura un veredicto de corte, en microsegundos.
    ///
    /// Un corte sin caducidad es un bloqueo permanente por accidente: el flujo
    /// se corta hoy y sigue cortado dentro de un mes, cuando la maquina ya se
    /// limpio y nadie recuerda por que no conecta.
    pub vigencia_us: u64,
}

/// Vigencia por defecto de un veredicto: una hora.
pub const VIGENCIA_US: u64 = 3600 * 1_000_000;

impl Default for ConfigDecisor {
    fn default() -> ConfigDecisor {
        ConfigDecisor {
            modo: Modo::default(),
            vigencia_us: VIGENCIA_US,
        }
    }
}

/// Contadores del motor de decision.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContadoresDecisor {
    /// Hechos examinados.
    pub hechos: u64,
    /// Reglas que casaron.
    pub coincidencias: u64,
    /// Veredictos de corte emitidos.
    pub cortes: u64,
    /// Cortes que no se aplicaron por el modo.
    pub no_por_modo: u64,
    /// Cortes que no se aplicaron por confianza insuficiente.
    pub no_por_confianza: u64,
    /// Cortes evitados por la lista de protegidos.
    ///
    /// Si este numero sube, el motor de reglas se esta equivocando en algo
    /// grave y hay que mirarlo: son cortes que habrian tirado infraestructura.
    pub no_por_protegido: u64,
    /// Cortes que no se aplicaron por estar el motor degradado.
    pub no_por_degradado: u64,
    /// Veces que el motor se ha degradado solo.
    pub degradaciones: u64,
}

/// El motor de decision.
pub struct Decisor {
    config: ConfigDecisor,
    reglas: Vec<Regla>,
    protegidos: Protegidos,
    limitador: Limitador,
    contadores: ContadoresDecisor,
}

impl Decisor {
    /// Un motor con la configuracion dada.
    #[must_use]
    pub fn nuevo(config: ConfigDecisor) -> Decisor {
        Decisor {
            config,
            reglas: Vec::new(),
            protegidos: Protegidos::nueva(),
            limitador: Limitador::default(),
            contadores: ContadoresDecisor::default(),
        }
    }

    /// Sustituye el limitador, para poder fijar tope y ventana.
    #[must_use]
    pub fn con_limitador(mut self, limitador: Limitador) -> Decisor {
        self.limitador = limitador;
        self
    }

    /// Carga las reglas.
    pub fn cargar_reglas(&mut self, reglas: Vec<Regla>) {
        self.reglas = reglas;
    }

    /// La lista de protegidos, para poder poblarla.
    pub fn protegidos_mut(&mut self) -> &mut Protegidos {
        &mut self.protegidos
    }

    /// La lista de protegidos.
    #[must_use]
    pub fn protegidos(&self) -> &Protegidos {
        &self.protegidos
    }

    /// Contadores.
    #[must_use]
    pub fn contadores(&self) -> &ContadoresDecisor {
        &self.contadores
    }

    /// Modo actual. Puede no ser el configurado si el motor se degrado.
    #[must_use]
    pub fn modo(&self) -> Modo {
        if self.limitador.degradado() {
            Modo::SoloDeteccion
        } else {
            self.config.modo
        }
    }

    /// Si el motor se degrado solo.
    #[must_use]
    pub fn degradado(&self) -> bool {
        self.limitador.degradado()
    }

    /// Reactiva el bloqueo tras una degradacion.
    ///
    /// Es una accion deliberada de un operador: ver [`crate::limitador`].
    pub fn rearmar(&mut self) {
        self.limitador.rearmar();
    }

    /// Cuanto dura un veredicto de corte.
    #[must_use]
    pub fn vigencia_us(&self) -> u64 {
        self.config.vigencia_us
    }

    /// Juzga un hecho y devuelve el veredicto, si alguna regla caso.
    ///
    /// Cuando varias reglas casan se queda la de MAYOR confianza: es la que
    /// mejor justifica lo que se vaya a hacer. Con igual confianza gana la de
    /// menor identificador, para que la decision sea reproducible y no dependa
    /// del orden en que se cargaron las reglas.
    pub fn juzgar(&mut self, hc: &HechoConContexto) -> Option<Veredicto> {
        self.contadores.hechos += 1;

        let mut mejor: Option<&Regla> = None;
        for r in &self.reglas {
            if !r.casa(&hc.hecho) {
                continue;
            }
            mejor = match mejor {
                None => Some(r),
                Some(m)
                    if (r.confianza, std::cmp::Reverse(r.id))
                        > (m.confianza, std::cmp::Reverse(m.id)) =>
                {
                    Some(r)
                }
                otro => otro,
            };
        }
        let regla = mejor?;
        self.contadores.coincidencias += 1;

        let flujo = flujo_de(hc);
        let mut veredicto = Veredicto {
            flujo,
            accion: Accion::Alertar,
            regla: regla.id,
            nombre_regla: regla.nombre.clone(),
            confianza: regla.confianza,
            no_corte: None,
            momento_us: hc.momento_us,
        };

        // 2. Confianza. Solo la alta puede llegar a cortar.
        if !regla.confianza.puede_cortar() {
            self.contadores.no_por_confianza += 1;
            veredicto.no_corte = Some(MotivoNoCorte::Confianza);
            return Some(veredicto);
        }

        // 3. Activos protegidos. ANTES que el modo y que el limitador, para que
        //    la cifra de «veces que la salvaguarda hizo falta» sea real.
        if let Some(m) = self.protegidos.alguno_protegido(&flujo.ip_a, &flujo.ip_b) {
            self.contadores.no_por_protegido += 1;
            veredicto.no_corte = Some(MotivoNoCorte::Protegido(m));
            return Some(veredicto);
        }

        // 4. El modo.
        if !self.config.modo.corta() {
            self.contadores.no_por_modo += 1;
            veredicto.no_corte = Some(MotivoNoCorte::Modo);
            return Some(veredicto);
        }

        // 5. El limitador.
        match self.limitador.pedir(hc.momento_us) {
            Permiso::Adelante => {
                self.contadores.cortes += 1;
                veredicto.accion = Accion::Cortar;
            }
            Permiso::Degradar => {
                self.contadores.degradaciones += 1;
                self.contadores.no_por_degradado += 1;
                veredicto.no_corte = Some(MotivoNoCorte::Degradado);
            }
            Permiso::YaDegradado => {
                self.contadores.no_por_degradado += 1;
                veredicto.no_corte = Some(MotivoNoCorte::Degradado);
            }
        }
        Some(veredicto)
    }
}

/// Traduce la clave de flujo de [`aegis_wire`] a la de aqui.
fn flujo_de(hc: &HechoConContexto) -> Flujo {
    let protocolo = match hc.flujo.transporte {
        Transporte::Tcp => 6,
        Transporte::Udp => 17,
        Transporte::Icmp => 1,
    };
    Flujo::normalizado(hc.flujo.a, hc.flujo.b, protocolo)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use aegis_wire::hecho::{ClaveFlujo, Direccion, Hecho};

    use crate::confianza::Confianza;
    use crate::protegidos::MotivoProteccion;
    use crate::regla::Criterio;

    fn ip(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, d))
    }

    fn hecho_dns(nombre: &str, origen: u8, destino: u8, momento_us: u64) -> HechoConContexto {
        let (clave, _) =
            ClaveFlujo::normalizada((ip(origen), 50_000), (ip(destino), 53), Transporte::Udp);
        HechoConContexto {
            flujo: clave,
            direccion: Direccion::ClienteAServidor,
            momento_us,
            hecho: Hecho::ConsultaDns {
                id: 1,
                nombre: nombre.to_string(),
                tipo: "A".to_string(),
            },
        }
    }

    fn regla_c2(confianza: Confianza) -> Regla {
        Regla {
            id: 100,
            nombre: "c2-conocido".to_string(),
            confianza,
            criterio: Criterio::SufijoDns("evil.com".to_string()),
        }
    }

    fn decisor(modo: Modo, confianza: Confianza) -> Decisor {
        let mut d = Decisor::nuevo(ConfigDecisor {
            modo,
            ..ConfigDecisor::default()
        });
        d.cargar_reglas(vec![regla_c2(confianza)]);
        d
    }

    #[test]
    fn en_modo_bloqueo_una_regla_de_confianza_alta_corta() {
        let mut d = decisor(Modo::Bloqueo, Confianza::Alta);
        let v = d.juzgar(&hecho_dns("a.evil.com", 1, 2, 10)).unwrap();
        assert_eq!(v.accion, Accion::Cortar);
        assert_eq!(v.no_corte, None);
        assert_eq!(d.contadores().cortes, 1);
    }

    /// LA INVARIANTE: una heuristica no corta la red de nadie, ni en modo
    /// bloqueo.
    #[test]
    fn una_regla_de_confianza_baja_no_corta_ni_en_modo_bloqueo() {
        for c in [Confianza::Baja, Confianza::Media] {
            let mut d = decisor(Modo::Bloqueo, c);
            let v = d.juzgar(&hecho_dns("a.evil.com", 1, 2, 10)).unwrap();
            assert_eq!(v.accion, Accion::Alertar, "confianza {c:?}");
            assert_eq!(v.no_corte, Some(MotivoNoCorte::Confianza));
            assert_eq!(d.contadores().cortes, 0);
        }
    }

    /// LA SALVAGUARDA QUE MAS IMPORTA: un activo protegido no se corta ni con la
    /// regla de maxima confianza, en modo bloqueo, con el limitador a cero.
    /// Cortar el controlador de dominio convierte un incidente en un apagon.
    #[test]
    fn un_activo_protegido_no_se_corta_jamas() {
        let mut d = decisor(Modo::Bloqueo, Confianza::Alta);
        d.protegidos_mut()
            .proteger(ip(2), MotivoProteccion::ControladorDeDominio);

        let v = d.juzgar(&hecho_dns("a.evil.com", 1, 2, 10)).unwrap();
        assert_eq!(v.accion, Accion::Alertar);
        assert_eq!(
            v.no_corte,
            Some(MotivoNoCorte::Protegido(
                MotivoProteccion::ControladorDeDominio
            ))
        );
        assert_eq!(d.contadores().no_por_protegido, 1);
        assert_eq!(d.contadores().cortes, 0);
    }

    /// Y da igual en que extremo este: proteger solo el destino dejaria sin
    /// cubrir el trafico que SALE del controlador.
    #[test]
    fn un_protegido_como_origen_tambien_salva_el_flujo() {
        let mut d = decisor(Modo::Bloqueo, Confianza::Alta);
        d.protegidos_mut()
            .proteger(ip(1), MotivoProteccion::ServidorDns);
        let v = d.juzgar(&hecho_dns("a.evil.com", 1, 2, 10)).unwrap();
        assert_eq!(v.accion, Accion::Alertar);
        assert!(matches!(v.no_corte, Some(MotivoNoCorte::Protegido(_))));
    }

    /// El modo aprendizaje REGISTRA lo que habria cortado y no corta. Es lo que
    /// hace posible que un cliente se atreva a activar el bloqueo despues.
    #[test]
    fn el_modo_aprendizaje_registra_pero_no_corta() {
        let mut d = decisor(Modo::BloqueoConAprendizaje, Confianza::Alta);
        let v = d.juzgar(&hecho_dns("a.evil.com", 1, 2, 10)).unwrap();
        assert_eq!(v.accion, Accion::Alertar);
        assert_eq!(v.no_corte, Some(MotivoNoCorte::Modo));
        assert_eq!(
            d.contadores().no_por_modo,
            1,
            "y se CUENTA, que es todo el sentido del modo"
        );
    }

    #[test]
    fn el_modo_por_defecto_no_corta_nada() {
        let mut d = decisor(Modo::default(), Confianza::Alta);
        let v = d.juzgar(&hecho_dns("a.evil.com", 1, 2, 10)).unwrap();
        assert_eq!(v.accion, Accion::Alertar);
    }

    /// LA DEGRADACION: al pasarse del tope el motor baja a solo deteccion, lo
    /// declara, y deja de cortar. Si el motor esta bloqueando media red, el
    /// motor esta mal, no la red.
    #[test]
    fn al_pasarse_del_tope_el_motor_se_degrada_y_lo_dice() {
        let mut d =
            decisor(Modo::Bloqueo, Confianza::Alta).con_limitador(Limitador::nuevo(3, 1_000_000));

        // Tres cortes caben.
        for i in 0..3u64 {
            let v = d
                .juzgar(&hecho_dns("a.evil.com", 1, 10 + i as u8, i))
                .unwrap();
            assert_eq!(v.accion, Accion::Cortar, "el corte {i} tenia que caber");
        }
        assert!(!d.degradado());

        // El cuarto degrada, y ESE no se aplica.
        let v = d.juzgar(&hecho_dns("a.evil.com", 1, 20, 4)).unwrap();
        assert_eq!(v.accion, Accion::Alertar);
        assert_eq!(v.no_corte, Some(MotivoNoCorte::Degradado));
        assert!(d.degradado());
        assert_eq!(d.modo(), Modo::SoloDeteccion, "el modo efectivo baja");
        assert_eq!(d.contadores().degradaciones, 1);

        // Y a partir de ahi no corta nada, aunque el modo configurado siga
        // siendo Bloqueo.
        let v = d.juzgar(&hecho_dns("a.evil.com", 1, 21, 5)).unwrap();
        assert_eq!(v.accion, Accion::Alertar);
        assert_eq!(
            d.contadores().degradaciones,
            1,
            "pero solo se avisa una vez"
        );
    }

    /// Reactivar es deliberado, y despues del rearme vuelve a cortar.
    #[test]
    fn tras_rearmar_el_motor_vuelve_a_cortar() {
        let mut d =
            decisor(Modo::Bloqueo, Confianza::Alta).con_limitador(Limitador::nuevo(1, 1_000_000));
        d.juzgar(&hecho_dns("a.evil.com", 1, 2, 0));
        d.juzgar(&hecho_dns("a.evil.com", 1, 3, 1));
        assert!(d.degradado());

        d.rearmar();
        assert!(!d.degradado());
        let v = d.juzgar(&hecho_dns("a.evil.com", 1, 4, 2)).unwrap();
        assert_eq!(v.accion, Accion::Cortar);
    }

    /// Un hecho que no casa ninguna regla no produce veredicto. Si produjera
    /// uno, el mapa del kernel se llenaria de entradas «permitir» inutiles.
    #[test]
    fn lo_que_no_casa_no_produce_veredicto() {
        let mut d = decisor(Modo::Bloqueo, Confianza::Alta);
        assert!(d.juzgar(&hecho_dns("www.ejemplo.com", 1, 2, 10)).is_none());
        assert_eq!(d.contadores().coincidencias, 0);
        assert_eq!(d.contadores().hechos, 1, "pero el hecho SI se cuenta");
    }

    /// Con varias reglas gana la de mas confianza: es la que mejor justifica lo
    /// que se vaya a hacer.
    #[test]
    fn cuando_varias_reglas_casan_gana_la_de_mas_confianza() {
        let mut d = Decisor::nuevo(ConfigDecisor {
            modo: Modo::Bloqueo,
            ..ConfigDecisor::default()
        });
        d.cargar_reglas(vec![
            Regla {
                id: 1,
                nombre: "heuristica".to_string(),
                confianza: Confianza::Baja,
                criterio: Criterio::SufijoDns("evil.com".to_string()),
            },
            Regla {
                id: 2,
                nombre: "indicador".to_string(),
                confianza: Confianza::Alta,
                criterio: Criterio::NombreDns("a.evil.com".to_string()),
            },
        ]);
        let v = d.juzgar(&hecho_dns("a.evil.com", 1, 2, 10)).unwrap();
        assert_eq!(v.regla, 2);
        assert_eq!(v.accion, Accion::Cortar);
    }

    /// Y con la misma confianza, la decision es REPRODUCIBLE: no depende del
    /// orden en que se cargaron las reglas. Un veredicto que cambia entre dos
    /// ejecuciones no se puede auditar.
    #[test]
    fn con_igual_confianza_la_decision_no_depende_del_orden_de_carga() {
        let a = Regla {
            id: 7,
            nombre: "siete".to_string(),
            confianza: Confianza::Alta,
            criterio: Criterio::SufijoDns("evil.com".to_string()),
        };
        let b = Regla {
            id: 3,
            nombre: "tres".to_string(),
            confianza: Confianza::Alta,
            criterio: Criterio::SufijoDns("evil.com".to_string()),
        };

        let mut elegidas = Vec::new();
        for reglas in [vec![a.clone(), b.clone()], vec![b, a]] {
            let mut d = Decisor::nuevo(ConfigDecisor {
                modo: Modo::Bloqueo,
                ..ConfigDecisor::default()
            });
            d.cargar_reglas(reglas);
            elegidas.push(d.juzgar(&hecho_dns("x.evil.com", 1, 2, 10)).unwrap().regla);
        }
        assert_eq!(elegidas[0], elegidas[1]);
        assert_eq!(elegidas[0], 3, "gana el identificador menor");
    }

    /// Los dos sentidos de LA MISMA conversacion producen el MISMO flujo, para
    /// que un veredicto escrito viendo la ida corte tambien la vuelta — que es
    /// por donde llega la respuesta del servidor de mando y control.
    #[test]
    fn los_dos_sentidos_de_una_conversacion_producen_el_mismo_flujo() {
        // Misma conversacion, leida al reves: el cliente sigue siendo el 1 en el
        // puerto 50000 y el servidor el 2 en el 53. Lo que cambia es quien manda
        // el paquete que produjo el hecho.
        let ida = ClaveFlujo::normalizada((ip(1), 50_000), (ip(2), 53), Transporte::Udp).0;
        let vuelta = ClaveFlujo::normalizada((ip(2), 53), (ip(1), 50_000), Transporte::Udp).0;
        assert_eq!(ida, vuelta, "la clave de aegis-wire ya es simetrica");

        let como_hecho = |clave, momento_us| HechoConContexto {
            flujo: clave,
            direccion: Direccion::ClienteAServidor,
            momento_us,
            hecho: Hecho::ConsultaDns {
                id: 1,
                nombre: "a.evil.com".to_string(),
                tipo: "A".to_string(),
            },
        };

        let mut d = decisor(Modo::Bloqueo, Confianza::Alta);
        let v_ida = d.juzgar(&como_hecho(ida, 10)).unwrap();
        let v_vuelta = d.juzgar(&como_hecho(vuelta, 11)).unwrap();
        assert_eq!(v_ida.flujo, v_vuelta.flujo);
    }

    /// Y el reverso, que es lo que impide cortar de mas: dos conversaciones
    /// DISTINTAS entre las mismas dos maquinas no comparten veredicto.
    #[test]
    fn dos_conversaciones_distintas_no_comparten_veredicto() {
        let mut d = decisor(Modo::Bloqueo, Confianza::Alta);
        let a = d.juzgar(&hecho_dns("a.evil.com", 1, 2, 10)).unwrap();
        let b = d.juzgar(&hecho_dns("a.evil.com", 2, 1, 11)).unwrap();
        assert_ne!(
            a.flujo, b.flujo,
            "puertos distintos en cada extremo son otra conversacion"
        );
    }
}
