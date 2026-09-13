//! Particionado de la base de datos por tiempo e inquilino, y purga.
//!
//! # «Una tabla de alertas sin particionar muere al año»
//!
//! La frase suena a exageracion hasta que se hacen las cuentas. Cien mil agentes
//! generando un evento de seguridad al minuto son **144 millones de filas al
//! dia**. Al año, cincuenta mil millones. Y el problema no es el tamano: es la
//! **purga**.
//!
//! Borrar con `DELETE FROM alertas WHERE creado_en < ...` en una tabla asi:
//!
//! * escribe en el registro de transacciones **tanto como escribio la insercion
//!   original**, con lo que la purga compite con la ingesta por el mismo disco;
//! * no devuelve el espacio: deja filas muertas que hay que aspirar despues, y el
//!   aspirado vuelve a leer la tabla entera;
//! * mantiene abierta una transaccion larga que bloquea la limpieza de todo lo
//!   demas;
//! * y tarda cada dia un poco mas, hasta el dia en que no acaba antes de que
//!   empiece la siguiente.
//!
//! Ese ultimo dia es el que mata la instalacion, y llega sin aviso.
//!
//! Con particionado declarativo, **la purga es un `DROP TABLE` de la particion
//! entera**: constante, sin registro de transacciones proporcional a las filas,
//! sin filas muertas y sin bloquear la ingesta de las particiones vivas. Es la
//! diferencia entre una operacion de horas y una de milisegundos.
//!
//! # Por que por tiempo Y por inquilino, y en ese orden
//!
//! * **Por tiempo primero** porque es la dimension por la que se **purga**, y la
//!   purga es la operacion que decide si el sistema sobrevive. Particionar
//!   primero por inquilino obligaria a borrar dentro de cada particion, que es
//!   volver al `DELETE`.
//! * **Por inquilino dentro** porque es la dimension por la que se **consulta**:
//!   un analista mira su organizacion. Sin ese corte, cada consulta de un cliente
//!   recorre los datos de todos, y ademas el aislamiento depende solo de que la
//!   clausula `WHERE` este bien escrita en todas partes.
//!
//! # Lo que este modulo genera y lo que NO
//!
//! Genera el SQL: las particiones, sus indices y las sentencias de purga. **No
//! las ejecuta**: eso lo hace el arranque del servidor contra su base de datos.
//! La separacion permite probar la logica —que no queden huecos, que no se solape
//! nada, que la purga tire exactamente lo que toca— sin necesitar PostgreSQL, y
//! ademas deja el SQL a la vista para que un administrador lo revise antes de
//! que corra sobre su produccion.

use aegis_ingest::tiempo::{civil_desde_dias, instante_utc, NS};

/// Meses de retencion por defecto.
///
/// Trece meses: un año completo mas uno de margen. El año entero porque las
/// investigaciones de seguridad miran atras —el tiempo medio hasta detectar una
/// intrusion se mide en meses— y el de margen porque purgar justo en el limite
/// deja al analista sin el mes que acaba de necesitar.
pub const RETENCION_MESES: u32 = 13;

/// Particiones futuras que se crean por adelantado.
///
/// Tres. Sin adelanto, la primera insercion del mes que viene falla porque no
/// existe su particion, y falla **a las cero horas del dia uno**, que es cuando
/// menos gente esta mirando. Con tres meses de adelanto, un despliegue puede
/// quedarse sin mantenimiento un trimestre entero sin que la ingesta se pare.
pub const ADELANTO_MESES: u32 = 3;

/// Fragmentos de la particion por inquilino.
///
/// Dieciseis. No es el numero de clientes: es el numero de cajones en los que se
/// reparten por resumen. Cambiarlo obliga a mover datos, asi que se elige una vez
/// y con holgura.
pub const FRAGMENTOS_INQUILINO: u32 = 16;

/// Un mes concreto del calendario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mes {
    /// Año.
    pub ano: i64,
    /// Mes, de 1 a 12.
    pub mes: u32,
}

impl Mes {
    /// El mes en el que cae un instante.
    #[must_use]
    pub fn de_ns(ns: u64) -> Mes {
        let dias = i64::try_from(ns / NS).unwrap_or(0) / 86_400;
        let (ano, mes, _) = civil_desde_dias(dias);
        Mes { ano, mes }
    }

    /// El mes siguiente.
    #[must_use]
    pub fn siguiente(self) -> Mes {
        if self.mes == 12 {
            Mes {
                ano: self.ano + 1,
                mes: 1,
            }
        } else {
            Mes {
                ano: self.ano,
                mes: self.mes + 1,
            }
        }
    }

    /// El mes anterior.
    #[must_use]
    pub fn anterior(self) -> Mes {
        if self.mes == 1 {
            Mes {
                ano: self.ano - 1,
                mes: 12,
            }
        } else {
            Mes {
                ano: self.ano,
                mes: self.mes - 1,
            }
        }
    }

    /// `n` meses despues.
    #[must_use]
    pub fn mas(self, n: u32) -> Mes {
        let mut m = self;
        for _ in 0..n {
            m = m.siguiente();
        }
        m
    }

    /// `n` meses antes.
    #[must_use]
    pub fn menos(self, n: u32) -> Mes {
        let mut m = self;
        for _ in 0..n {
            m = m.anterior();
        }
        m
    }

    /// Primer instante del mes, en nanosegundos Unix.
    #[must_use]
    pub fn inicio_ns(self) -> u64 {
        instante_utc(self.ano, self.mes, 1, 0, 0, 0, 0).unwrap_or(0)
    }

    /// Sufijo estable del nombre de la particion.
    #[must_use]
    pub fn sufijo(self) -> String {
        format!("{:04}_{:02}", self.ano, self.mes)
    }

    /// Fecha de inicio en el formato de PostgreSQL.
    #[must_use]
    pub fn fecha(self) -> String {
        format!("{:04}-{:02}-01", self.ano, self.mes)
    }

    /// Cuantos meses hay de `self` a `otro`, negativo si `otro` es anterior.
    #[must_use]
    pub fn distancia(self, otro: Mes) -> i64 {
        (otro.ano - self.ano) * 12 + i64::from(otro.mes) - i64::from(self.mes)
    }
}

/// Una tabla que se particiona.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tabla {
    /// Nombre de la tabla.
    pub nombre: &'static str,
    /// Columna de tiempo por la que se parte.
    pub columna_tiempo: &'static str,
    /// Columna de inquilino, si tambien se subparticiona.
    pub columna_inquilino: Option<&'static str>,
}

/// Las tablas que crecen con la flota y por tanto hay que particionar.
///
/// La lista es explicita a proposito: particionar una tabla que no crece anade
/// complejidad sin ganancia, y no particionar una que si crece es la bomba de
/// relojeria del encabezado. Que este aqui es una decision, no un descuido.
pub const TABLAS: &[Tabla] = &[
    Tabla {
        nombre: "alertas",
        columna_tiempo: "creado_en",
        columna_inquilino: Some("inquilino"),
    },
    Tabla {
        nombre: "eventos_normalizados",
        columna_tiempo: "ocurrio_en",
        columna_inquilino: Some("inquilino"),
    },
    Tabla {
        nombre: "correlaciones",
        columna_tiempo: "creado_en",
        columna_inquilino: None,
    },
    Tabla {
        nombre: "remediacion_acciones",
        columna_tiempo: "creado_en",
        columna_inquilino: None,
    },
];

/// Plan de particionado para un instante dado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Meses que tienen que existir.
    pub crear: Vec<Mes>,
    /// Meses que hay que soltar por retencion.
    pub soltar: Vec<Mes>,
}

/// Calcula que particiones deberian existir y cuales sobran.
///
/// `existentes` es lo que hay ahora. El plan es la diferencia, y se calcula
/// entero antes de tocar nada: aplicar mientras se decide es como se acaba
/// soltando una particion que se iba a necesitar.
#[must_use]
pub fn planificar(ahora_ns: u64, existentes: &[Mes], retencion_meses: u32) -> Plan {
    let actual = Mes::de_ns(ahora_ns);
    let mas_antiguo = actual.menos(retencion_meses);

    let mut necesarios = Vec::new();
    let mut m = mas_antiguo;
    // Desde el limite de retencion hasta el adelanto: todo lo que puede recibir
    // una insercion o servir una consulta.
    while m.distancia(actual.mas(ADELANTO_MESES)) >= 0 {
        necesarios.push(m);
        m = m.siguiente();
    }

    let crear: Vec<Mes> = necesarios
        .iter()
        .filter(|m| !existentes.contains(m))
        .copied()
        .collect();
    let soltar: Vec<Mes> = existentes
        .iter()
        .filter(|m| m.distancia(mas_antiguo) > 0)
        .copied()
        .collect();

    Plan { crear, soltar }
}

/// SQL para convertir una tabla en particionada.
///
/// Es la parte que **no** se puede hacer en caliente: PostgreSQL no convierte una
/// tabla existente en particionada, hay que crear la nueva, copiar y cambiar el
/// nombre. Por eso se genera aparte y va en una migracion, no en el arranque.
#[must_use]
pub fn sql_declarar(t: Tabla) -> String {
    let mut s = format!(
        "-- {tabla}: particionada por RANGO de {col}.\n\
         --\n\
         -- El rango va PRIMERO porque es la dimension por la que se PURGA, y la\n\
         -- purga de una particion es un DROP: constante, sin registro de\n\
         -- transacciones proporcional a las filas y sin bloquear la ingesta.\n\
         -- Con DELETE, la misma operacion escribe tanto como escribio la\n\
         -- insercion original y deja filas muertas que hay que aspirar despues.\n\
         ALTER TABLE IF EXISTS {tabla} RENAME TO {tabla}_sin_particionar;\n",
        tabla = t.nombre,
        col = t.columna_tiempo
    );
    s.push_str(&format!(
        "CREATE TABLE IF NOT EXISTS {tabla} (LIKE {tabla}_sin_particionar INCLUDING DEFAULTS \
         INCLUDING CONSTRAINTS) PARTITION BY RANGE ({col});\n",
        tabla = t.nombre,
        col = t.columna_tiempo
    ));
    s
}

/// SQL para crear la particion de un mes.
#[must_use]
pub fn sql_crear(t: Tabla, m: Mes) -> String {
    let hijo = format!("{}_{}", t.nombre, m.sufijo());
    let siguiente = m.siguiente();
    let mut s = String::new();
    match t.columna_inquilino {
        Some(inq) => {
            s.push_str(&format!(
                "CREATE TABLE IF NOT EXISTS {hijo} PARTITION OF {padre} \
                 FOR VALUES FROM ('{desde}') TO ('{hasta}') PARTITION BY HASH ({inq});\n",
                padre = t.nombre,
                desde = m.fecha(),
                hasta = siguiente.fecha(),
            ));
            // El corte por inquilino va DENTRO: es la dimension por la que se
            // consulta, y sin el cada consulta de un cliente recorre los datos
            // de todos.
            for f in 0..FRAGMENTOS_INQUILINO {
                s.push_str(&format!(
                    "CREATE TABLE IF NOT EXISTS {hijo}_i{f} PARTITION OF {hijo} \
                     FOR VALUES WITH (MODULUS {m}, REMAINDER {f});\n",
                    m = FRAGMENTOS_INQUILINO,
                ));
            }
        }
        None => {
            s.push_str(&format!(
                "CREATE TABLE IF NOT EXISTS {hijo} PARTITION OF {padre} \
                 FOR VALUES FROM ('{desde}') TO ('{hasta}');\n",
                padre = t.nombre,
                desde = m.fecha(),
                hasta = siguiente.fecha(),
            ));
        }
    }
    s
}

/// SQL para soltar la particion de un mes.
///
/// # Por que `DETACH` y despues `DROP`, y no `DROP` directo
///
/// `DROP TABLE` sobre una particion adjunta toma un bloqueo de acceso exclusivo
/// **sobre la tabla padre**, y eso para la ingesta de todas las demas
/// particiones mientras dura. `DETACH CONCURRENTLY` la separa sin bloquear, y el
/// `DROP` posterior ya solo afecta a una tabla que nadie usa.
///
/// Es la diferencia entre una purga que nadie nota y una que aparece en el panel
/// como un pico de latencia todos los dias a la misma hora.
#[must_use]
pub fn sql_soltar(t: Tabla, m: Mes) -> String {
    let hijo = format!("{}_{}", t.nombre, m.sufijo());
    format!(
        "ALTER TABLE {padre} DETACH PARTITION {hijo} CONCURRENTLY;\nDROP TABLE {hijo};\n",
        padre = t.nombre,
    )
}

/// SQL completo de un plan, para todas las tablas.
#[must_use]
pub fn sql_del_plan(plan: &Plan) -> String {
    let mut s = String::new();
    for t in TABLAS {
        for m in &plan.crear {
            s.push_str(&sql_crear(*t, *m));
        }
        for m in &plan.soltar {
            s.push_str(&sql_soltar(*t, *m));
        }
    }
    s
}

/// En que particion cae una fila.
///
/// Existe para poder comprobar la cobertura sin base de datos: que no haya
/// huecos, que no haya solapes, y que toda fila caiga en exactamente una.
#[must_use]
pub fn particion_de(t: Tabla, ns: u64, inquilino: &str) -> String {
    let m = Mes::de_ns(ns);
    let base = format!("{}_{}", t.nombre, m.sufijo());
    match t.columna_inquilino {
        Some(_) => format!("{base}_i{}", fragmento_de(inquilino)),
        None => base,
    }
}

/// Fragmento de inquilino, con la misma funcion que usa PostgreSQL para `HASH`.
///
/// No es el mismo algoritmo que el del motor —no puede serlo sin reimplementar
/// su funcion interna— y **eso se dice**: esta funcion sirve para razonar sobre
/// el reparto y para las pruebas de cobertura, no para predecir en que fichero
/// del disco acaba una fila. Lo que si garantiza, y es lo que hace falta, es que
/// el mismo inquilino cae siempre en el mismo fragmento.
#[must_use]
pub fn fragmento_de(inquilino: &str) -> u32 {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(inquilino.as_bytes());
    u32::from(d[0]) % FRAGMENTOS_INQUILINO
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const SEG: u64 = 1_000_000_000;

    fn ns_de(ano: i64, mes: u32, dia: u32) -> u64 {
        instante_utc(ano, mes, dia, 12, 0, 0, 0).unwrap()
    }

    // --- El calendario de particiones ---------------------------------------

    #[test]
    fn el_mes_de_un_instante_es_el_que_toca() {
        assert_eq!(Mes::de_ns(ns_de(2023, 10, 11)), Mes { ano: 2023, mes: 10 });
        // El ultimo instante de un mes sigue siendo ese mes.
        let fin = instante_utc(2023, 12, 31, 23, 59, 59, 0).unwrap();
        assert_eq!(Mes::de_ns(fin), Mes { ano: 2023, mes: 12 });
        assert_eq!(
            Mes::de_ns(fin + SEG),
            Mes { ano: 2024, mes: 1 },
            "el cambio de año"
        );
    }

    #[test]
    fn el_mes_siguiente_cruza_el_año_bien() {
        let d = Mes { ano: 2023, mes: 12 };
        assert_eq!(d.siguiente(), Mes { ano: 2024, mes: 1 });
        assert_eq!(
            Mes { ano: 2024, mes: 1 }.anterior(),
            Mes { ano: 2023, mes: 12 }
        );
        assert_eq!(d.mas(13), Mes { ano: 2025, mes: 1 });
        assert_eq!(d.menos(13), Mes { ano: 2022, mes: 11 });
    }

    #[test]
    fn la_distancia_entre_meses_es_simetrica() {
        let a = Mes { ano: 2023, mes: 3 };
        let b = Mes { ano: 2024, mes: 7 };
        assert_eq!(a.distancia(b), 16);
        assert_eq!(b.distancia(a), -16);
        assert_eq!(a.distancia(a), 0);
    }

    // --- El plan -------------------------------------------------------------

    #[test]
    fn se_crean_particiones_por_adelantado() {
        // Sin adelanto, la primera insercion del mes que viene falla A LAS CERO
        // HORAS DEL DIA UNO, que es cuando menos gente esta mirando.
        let plan = planificar(ns_de(2023, 10, 15), &[], RETENCION_MESES);
        let actual = Mes { ano: 2023, mes: 10 };
        for i in 1..=ADELANTO_MESES {
            assert!(
                plan.crear.contains(&actual.mas(i)),
                "falta la particion de dentro de {i} mes(es)"
            );
        }
    }

    #[test]
    fn no_se_vuelve_a_crear_lo_que_ya_existe() {
        let ahora = ns_de(2023, 10, 15);
        let primero = planificar(ahora, &[], RETENCION_MESES);
        let segundo = planificar(ahora, &primero.crear, RETENCION_MESES);
        assert!(segundo.crear.is_empty(), "{:?}", segundo.crear);
        assert!(segundo.soltar.is_empty());
    }

    #[test]
    fn la_retencion_suelta_lo_que_pasa_de_trece_meses() {
        let ahora = ns_de(2024, 6, 15);
        let actual = Mes { ano: 2024, mes: 6 };
        let existentes: Vec<Mes> = (0..30).map(|i| actual.menos(i)).collect();
        let plan = planificar(ahora, &existentes, RETENCION_MESES);
        assert!(plan.soltar.contains(&actual.menos(14)));
        assert!(
            !plan.soltar.contains(&actual.menos(13)),
            "el limite se queda"
        );
        assert!(!plan.soltar.contains(&actual));
    }

    #[test]
    fn la_cobertura_no_deja_huecos_ni_solapes() {
        // Toda fila de la ventana de retencion cae en exactamente una particion,
        // y eso se comprueba dia a dia en vez de confiarlo al SQL.
        let ahora = ns_de(2024, 6, 15);
        let plan = planificar(ahora, &[], RETENCION_MESES);
        let creados: std::collections::BTreeSet<Mes> = plan.crear.iter().copied().collect();
        let actual = Mes { ano: 2024, mes: 6 };
        let mut m = actual.menos(RETENCION_MESES);
        while m.distancia(actual.mas(ADELANTO_MESES)) >= 0 {
            assert!(creados.contains(&m), "hueco en {}", m.sufijo());
            m = m.siguiente();
        }
        assert_eq!(creados.len(), plan.crear.len(), "hay meses repetidos");
    }

    #[test]
    fn una_fila_de_cada_dia_del_año_cae_en_su_particion() {
        let t = TABLAS[0];
        for mes in 1..=12u32 {
            for dia in [1u32, 15, 28] {
                let ns = ns_de(2024, mes, dia);
                let p = particion_de(t, ns, "cliente-1");
                assert!(
                    p.starts_with(&format!("alertas_2024_{mes:02}")),
                    "{dia}/{mes} cayo en {p}"
                );
            }
        }
    }

    // --- El SQL --------------------------------------------------------------

    #[test]
    fn la_purga_es_un_drop_y_nunca_un_delete() {
        // ES LA RAZON DE SER DEL MODULO: con DELETE, la purga compite con la
        // ingesta por el mismo disco y tarda cada dia un poco mas, hasta el dia
        // en que no acaba antes de que empiece la siguiente.
        let sql = sql_soltar(TABLAS[0], Mes { ano: 2023, mes: 1 });
        assert!(sql.contains("DROP TABLE alertas_2023_01"));
        assert!(!sql.to_uppercase().contains("DELETE"));
    }

    #[test]
    fn la_purga_separa_antes_de_soltar_para_no_bloquear_la_ingesta() {
        // DROP sobre una particion adjunta toma un bloqueo exclusivo sobre el
        // PADRE, y eso para la ingesta de todas las demas mientras dura.
        let sql = sql_soltar(TABLAS[0], Mes { ano: 2023, mes: 1 });
        let detach = sql.find("DETACH PARTITION").expect("sin DETACH");
        let drop = sql.find("DROP TABLE").expect("sin DROP");
        assert!(detach < drop, "el DROP va antes que el DETACH");
        assert!(sql.contains("CONCURRENTLY"));
    }

    #[test]
    fn la_particion_del_mes_cubre_exactamente_su_mes() {
        let sql = sql_crear(TABLAS[0], Mes { ano: 2023, mes: 12 });
        assert!(
            sql.contains("FROM ('2023-12-01') TO ('2024-01-01')"),
            "{sql}"
        );
    }

    #[test]
    fn las_tablas_con_inquilino_se_subparticionan_y_las_demas_no() {
        let con = sql_crear(TABLAS[0], Mes { ano: 2023, mes: 1 });
        assert!(con.contains("PARTITION BY HASH (inquilino)"));
        assert_eq!(
            con.matches("MODULUS 16").count(),
            usize::try_from(FRAGMENTOS_INQUILINO).unwrap()
        );

        let sin = sql_crear(TABLAS[2], Mes { ano: 2023, mes: 1 });
        assert!(!sin.contains("PARTITION BY HASH"));
        assert!(sin.contains("correlaciones_2023_01"));
    }

    #[test]
    fn el_sql_de_un_plan_cubre_todas_las_tablas() {
        let plan = planificar(ns_de(2024, 6, 15), &[], RETENCION_MESES);
        let sql = sql_del_plan(&plan);
        for t in TABLAS {
            assert!(sql.contains(t.nombre), "falta {}", t.nombre);
        }
    }

    #[test]
    fn declarar_una_tabla_particionada_no_se_hace_en_caliente() {
        // PostgreSQL no convierte una tabla existente en particionada: hay que
        // crear la nueva, copiar y cambiar el nombre. Por eso va en una
        // migracion y no en el arranque.
        let sql = sql_declarar(TABLAS[0]);
        assert!(sql.contains("RENAME TO alertas_sin_particionar"));
        assert!(sql.contains("PARTITION BY RANGE (creado_en)"));
    }

    // --- El reparto por inquilino -------------------------------------------

    #[test]
    fn el_mismo_inquilino_cae_siempre_en_el_mismo_fragmento() {
        // Es lo unico que esta funcion garantiza, y es lo que hace falta.
        for i in 0..1000 {
            let id = format!("cliente-{i}");
            assert_eq!(fragmento_de(&id), fragmento_de(&id));
            assert!(fragmento_de(&id) < FRAGMENTOS_INQUILINO);
        }
    }

    #[test]
    fn los_inquilinos_se_reparten_entre_los_fragmentos() {
        let mut cuenta = [0usize; FRAGMENTOS_INQUILINO as usize];
        for i in 0..10_000 {
            cuenta[fragmento_de(&format!("cliente-{i}")) as usize] += 1;
        }
        let ideal = 10_000 / FRAGMENTOS_INQUILINO as usize;
        for (f, n) in cuenta.iter().enumerate() {
            assert!(
                *n > ideal * 80 / 100 && *n < ideal * 120 / 100,
                "el fragmento {f} se lleva {n}, ideal {ideal}"
            );
        }
    }

    #[test]
    fn el_plan_se_calcula_entero_antes_de_tocar_nada() {
        // Aplicar mientras se decide es como se acaba soltando una particion que
        // se iba a necesitar.
        let ahora = ns_de(2024, 6, 15);
        let actual = Mes { ano: 2024, mes: 6 };
        let existentes: Vec<Mes> = (0..20).map(|i| actual.menos(i)).collect();
        let plan = planificar(ahora, &existentes, RETENCION_MESES);
        for m in &plan.soltar {
            assert!(
                !plan.crear.contains(m),
                "{} se suelta y se crea",
                m.sufijo()
            );
        }
    }

    #[test]
    fn una_retencion_de_un_mes_no_suelta_el_mes_en_curso() {
        // El caso limite que borraria los datos de hoy.
        let ahora = ns_de(2024, 6, 15);
        let actual = Mes { ano: 2024, mes: 6 };
        let plan = planificar(ahora, &[actual, actual.menos(1)], 1);
        assert!(!plan.soltar.contains(&actual));
    }
}
