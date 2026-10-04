//! `cargo xtask kernels`: la matriz de kernels y distribuciones.
//!
//! Cada imagen de `tools/config/kernels.toml` arranca en una microVM con su
//! kernel y su espacio de usuario reales. Dentro, `tools/matriz-kernels/dentro.sh`
//! ejecuta las capacidades del agente, el verificador sobre cada objeto eBPF y
//! las pruebas e2e, y lo cuenta por la consola serie. Aqui se prepara todo, se
//! arranca con plazo y se convierte la consola en un veredicto.
//!
//! # Por que microVM con la imagen de la distribucion y no un kernel suelto
//!
//! `virtme-ng`/`vmtest` arrancan un kernel sobre el sistema de ficheros del
//! anfitrion: prueban el kernel, pero no la distribucion. Aqui importa tambien
//! lo que la distribucion pone alrededor: donde monta tracefs y securityfs, si
//! arranca con cgroup v1 o v2, si SELinux esta en enforcing, que LSM activa. Por
//! eso se arranca la imagen cloud oficial de cada una, y el kernel que se prueba
//! es el que un cliente tiene de verdad, con sus retroportes.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::config::{self, Imagen, Kernels};
use crate::repo::Repo;
use crate::Resultado;

/// Etiqueta del disco de carga que monta cloud-init.
const ETIQUETA: &str = "AEGISCARGA";
/// Etiqueta del disco de salida donde la microVM deja sus resultados.
const SALIDA: &str = "AEGISSALIDA";

/// Filtro de imagenes de la linea de ordenes.
#[derive(Debug, Default)]
pub struct Filtro {
    /// Solo estas imagenes (`--solo id`, repetible).
    pub solo: Vec<String>,
    /// Solo esta arquitectura.
    pub arquitectura: Option<String>,
}

impl Filtro {
    fn admite(&self, im: &Imagen) -> bool {
        (self.solo.is_empty() || self.solo.contains(&im.id))
            && self
                .arquitectura
                .as_ref()
                .is_none_or(|a| *a == im.arquitectura)
    }
}

fn cache() -> PathBuf {
    std::env::var_os("AEGIS_MATRIZ_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_else(|| "/root".into()))
                .join(".cache/aegis-matriz")
        })
}

/// Las vCPU que pide la microVM de `im`: una sola cuenta para el arranque y
/// para el reparto de nucleos.
fn vcpus(k: &Kernels, im: &Imagen) -> u32 {
    if im.arquitectura == "x86_64" {
        k.vm.cpus
    } else {
        k.vm.cpus_emulado
    }
}

/// Los nucleos del anfitrion repartidos entre las microVM en marcha.
///
/// Con emulacion completa no hay spinlocks paravirtualizados: si el anfitrion
/// desaloja la vCPU que tiene un cerrojo del kernel invitado, las demas giran
/// esperandolo. Con mas vCPU que nucleos, la imagen ARM de Ubuntu tardaba el
/// triple en arrancar y llego a quedarse muda una hora gastando CPU. Por eso
/// ninguna microVM arranca sin tener reservados tantos nucleos como vCPU, y la
/// suma nunca pasa del total.
struct Nucleos {
    total: u32,
    libres: Mutex<u32>,
    devuelto: Condvar,
}

/// Nucleos reservados; se devuelven al soltarse.
struct Reserva<'a> {
    nucleos: &'a Nucleos,
    n: u32,
}

impl Nucleos {
    fn nuevo(total: u32) -> Self {
        let total = total.max(1);
        Nucleos {
            total,
            libres: Mutex::new(total),
            devuelto: Condvar::new(),
        }
    }

    /// Espera a que haya `pedidos` nucleos libres y los reserva. Lo que pide mas
    /// que el total se recorta al total: si no, esperaria para siempre.
    fn reservar(&self, pedidos: u32) -> Reserva<'_> {
        let n = pedidos.clamp(1, self.total);
        let mut libres = self.libres.lock().unwrap_or_else(|e| e.into_inner());
        while *libres < n {
            libres = self
                .devuelto
                .wait(libres)
                .unwrap_or_else(|e| e.into_inner());
        }
        *libres -= n;
        Reserva { nucleos: self, n }
    }
}

impl Drop for Reserva<'_> {
    fn drop(&mut self) {
        let mut libres = self
            .nucleos
            .libres
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *libres += self.n;
        self.nucleos.devuelto.notify_all();
    }
}

pub(crate) fn trabajo(repo: &Repo) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo.raiz.join("target"))
        .join("matriz-kernels")
}

fn ejecutar_cmd(cmd: &mut Command, que: &str) -> Resultado<String> {
    let salida = cmd.output().map_err(|e| format!("{que}: {e}"))?;
    if !salida.status.success() {
        return Err(format!("{que}: {}", String::from_utf8_lossy(&salida.stderr).trim()).into());
    }
    Ok(String::from_utf8_lossy(&salida.stdout).into_owned())
}

fn descargar_texto(url: &str) -> Resultado<String> {
    ejecutar_cmd(
        Command::new("curl").args(["-fsSL", "--retry", "3", url]),
        &format!("descargar {url}"),
    )
}

// ── traer ───────────────────────────────────────────────────────────────────

/// URL efectiva de la imagen: la directa o la que se encuentra en el indice.
fn url_de(im: &Imagen) -> Resultado<String> {
    if let Some(u) = &im.url {
        return Ok(u.clone());
    }
    let (Some(indice), Some(patron)) = (&im.indice, &im.patron) else {
        return Err(format!("{}: hace falta `url` o `indice` + `patron`", im.id).into());
    };
    let html = descargar_texto(indice)?;
    let ini = html
        .find(patron.as_str())
        .ok_or_else(|| format!("{}: {patron} no aparece en {indice}", im.id))?;
    let nombre: String = html[ini..]
        .chars()
        .take_while(|c| !matches!(c, '"' | '<' | '>' | ' ' | '\''))
        .collect();
    Ok(format!("{}/{}", indice.trim_end_matches('/'), nombre))
}

/// La suma publicada para `fichero` en un fichero de sumas GNU (`hash  nombre`)
/// o BSD (`SHA256 (nombre) = hash`).
fn suma_publicada(sumas: &str, fichero: &str) -> Option<String> {
    for l in sumas.lines() {
        let l = l.trim();
        if let Some(resto) = l.split_once(" (").map(|x| x.1) {
            if let Some((nombre, hash)) = resto.split_once(") = ") {
                if nombre == fichero {
                    return Some(hash.trim().to_lowercase());
                }
            }
        }
        let mut t = l.split_whitespace();
        if let (Some(hash), Some(nombre)) = (t.next(), t.next()) {
            if nombre.trim_start_matches('*') == fichero
                && hash.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Some(hash.to_lowercase());
            }
        }
    }
    None
}

fn suma_local(algoritmo: &str, ruta: &Path) -> Resultado<String> {
    let prog = match algoritmo {
        "sha256" => "sha256sum",
        "sha512" => "sha512sum",
        otro => return Err(format!("algoritmo de suma desconocido: {otro}").into()),
    };
    let s = ejecutar_cmd(Command::new(prog).arg(ruta), prog)?;
    Ok(s.split_whitespace()
        .next()
        .unwrap_or_default()
        .to_lowercase())
}

/// Descarga y verifica las imagenes que no esten ya en la cache.
pub fn traer(repo: &Repo, filtro: &Filtro) -> Resultado<()> {
    let k: Kernels = config::leer(&repo.raiz, "kernels.toml")?;
    let dir = cache().join("imagenes");
    std::fs::create_dir_all(&dir)?;
    for im in k.imagen.iter().filter(|i| filtro.admite(i)) {
        let url = url_de(im)?;
        let fichero = url.rsplit('/').next().unwrap_or_default().to_string();
        let sumas = descargar_texto(&im.sumas)?;
        let esperada = suma_publicada(&sumas, &fichero)
            .ok_or_else(|| format!("{}: {fichero} no aparece en {}", im.id, im.sumas))?;
        let destino = dir.join(format!("{}.qcow2", im.id));
        if destino.is_file() && suma_local(&im.algoritmo, &destino)? == esperada {
            eprintln!("xtask: {} ya esta y su suma coincide", im.id);
            continue;
        }
        eprintln!("xtask: descargando {} ({fichero})", im.id);
        let parcial = dir.join(format!("{}.parcial", im.id));
        // Reanudable: las imagenes pesan cientos de megas y un corte a mitad
        // (curl 18, visto con la de Fedora) no puede obligar a empezar de cero.
        // `-C -` continua el `.parcial`, tambien entre ejecuciones; la suma se
        // comprueba al final igual, asi que un trozo corrupto no pasa.
        let estado = Command::new("curl")
            .args([
                "-fL",
                "--retry",
                "8",
                "--retry-all-errors",
                "-C",
                "-",
                "--progress-bar",
                "-o",
            ])
            .arg(&parcial)
            .arg(&url)
            .status()?;
        if !estado.success() {
            return Err(format!("{}: la descarga de {url} fallo", im.id).into());
        }
        let obtenida = suma_local(&im.algoritmo, &parcial)?;
        if obtenida != esperada {
            let _ = std::fs::remove_file(&parcial);
            return Err(format!(
                "{}: la suma {} no coincide con la publicada ({esperada} != {obtenida}): imagen descartada",
                im.id, im.algoritmo
            )
            .into());
        }
        std::fs::rename(&parcial, &destino)?;
        std::fs::write(
            dir.join(format!("{}.origen", im.id)),
            format!("{url}\n{} {obtenida}\n", im.algoritmo),
        )?;
        eprintln!(
            "xtask: {} verificada ({} {})",
            im.id,
            im.algoritmo,
            &obtenida[..16]
        );
    }
    Ok(())
}

// ── carga ───────────────────────────────────────────────────────────────────

/// Donde espera cada artefacto para una arquitectura.
struct Artefactos {
    agente: PathBuf,
    verificador: PathBuf,
    bpf: PathBuf,
    /// Donde estan los demas instalables publicados de esa arquitectura.
    dist: PathBuf,
}

fn artefactos(repo: &Repo, arq: &str) -> Artefactos {
    let (dist, bpf) = match arq {
        "x86_64" => ("dist-hermetico", "drivers/linux/aegis-bpf/out"),
        otra => {
            return Artefactos {
                agente: repo.raiz.join(format!("dist-hermetico-{otra}/aegis-agent")),
                dist: repo.raiz.join(format!("dist-hermetico-{otra}")),
                verificador: repo.raiz.join(format!(
                    "drivers/linux/aegis-bpf/out-{otra}/aegis_bpf_verify_estatico"
                )),
                bpf: repo
                    .raiz
                    .join(format!("drivers/linux/aegis-bpf/out-{otra}")),
            }
        }
    };
    Artefactos {
        agente: repo.raiz.join(dist).join("aegis-agent"),
        dist: repo.raiz.join(dist),
        verificador: repo.raiz.join(bpf).join("aegis_bpf_verify_estatico"),
        bpf: repo.raiz.join(bpf),
    }
}

/// La huella del arbol de trabajo, de su unica definicion (`tools/huella-arbol.sh`).
pub(crate) fn huella_del_arbol(repo: &Repo) -> Resultado<String> {
    let salida = ejecutar_cmd(
        Command::new(repo.raiz.join("tools/huella-arbol.sh")).current_dir(&repo.raiz),
        "tools/huella-arbol.sh",
    )?;
    let h = salida.trim().to_string();
    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(h)
    } else {
        Err(format!("tools/huella-arbol.sh no devolvio una huella: «{h}»").into())
    }
}

/// Que los binarios que van a la VM salgan de ESTE arbol.
///
/// La matriz llego a probar en x86-64 un agente de una tanda anterior: el grupo
/// `kernels` tomaba el de dist-hermetico/ sin preguntar de que arbol salia, y los
/// motores recien integrados no estaban en las VMs (FASE 2 del MP-16). Una matriz
/// verde sobre otro binario es un verde falso, asi que sin huella, o con otra, no
/// se arranca ninguna VM.
pub(crate) fn procedencia(
    grabada: Option<&str>,
    actual: &str,
    dist: &Path,
    remedio: &str,
) -> Resultado<()> {
    match grabada.map(str::trim) {
        Some(h) if h == actual => Ok(()),
        Some(h) => Err(format!(
            "los binarios de {} se construyeron sobre otro arbol (huella {h}, este es {actual}): \
             reconstruyelos con {remedio}",
            dist.display()
        )
        .into()),
        None => Err(format!(
            "{} no dice de que arbol salen sus binarios (falta HUELLA): reconstruyelos con {remedio}",
            dist.display()
        )
        .into()),
    }
}

/// Compone el disco de carga de una arquitectura.
fn preparar_carga(repo: &Repo, k: &Kernels, arq: &str, dir: &Path) -> Resultado<PathBuf> {
    let a = artefactos(repo, arq);
    let remedio = if arq == "x86_64" {
        "tools/ci/hermetico.sh y make -C drivers/linux/aegis-bpf build verify-estatico".to_string()
    } else {
        format!("tools/matriz-kernels/construir-cruzado.sh {arq}")
    };
    for (que, p) in [
        ("agente hermetico", &a.agente),
        ("verificador estatico", &a.verificador),
    ] {
        if !p.is_file() {
            return Err(format!(
                "falta el {que} para {arq} en {}: constrúyelo con {remedio}",
                p.display()
            )
            .into());
        }
    }
    let actual = huella_del_arbol(repo)?;
    let grabada = std::fs::read_to_string(a.dist.join("HUELLA")).ok();
    procedencia(grabada.as_deref(), &actual, &a.dist, &remedio)?;
    let carga = dir.join(format!("carga-{arq}"));
    let _ = std::fs::remove_dir_all(&carga);
    for sub in ["bin", "bpf", "pruebas"] {
        std::fs::create_dir_all(carga.join(sub))?;
    }
    std::fs::copy(&a.agente, carga.join("bin/aegis-agent"))?;
    std::fs::copy(&a.verificador, carga.join("bin/aegis_bpf_verify"))?;
    std::fs::copy(
        repo.raiz.join("tools/matriz-kernels/dentro.sh"),
        carga.join("dentro.sh"),
    )?;
    let mut plan = String::new();
    for b in &k.bpf {
        let o = a.bpf.join(format!("{}.bpf.o", b.objeto));
        if !o.is_file() {
            return Err(format!("falta {} para {arq}: {remedio}", o.display()).into());
        }
        std::fs::copy(&o, carga.join("bpf").join(format!("{}.bpf.o", b.objeto)))?;
        let _ = writeln!(plan, "bpf|{}|{}|", b.objeto, b.requiere_kfunc.join(","));
    }
    for p in &k.prueba {
        match p.tipo.as_str() {
            "instalable" => {
                for extra in &p.acompanantes {
                    let origen = a.dist.join(extra);
                    if !origen.is_file() {
                        return Err(format!(
                            "prueba {}: falta el instalable {extra} para {arq} en {}: {remedio}",
                            p.id,
                            origen.display()
                        )
                        .into());
                    }
                    std::fs::copy(&origen, carga.join("bin").join(extra))?;
                }
                if p.paquetes {
                    copiar_paquetes(repo, arq, &carga, &actual)?;
                }
                let _ = writeln!(
                    plan,
                    "prueba|{}|instalable|{}",
                    p.id,
                    p.binario.as_deref().unwrap_or("")
                );
            }
            "cargo-test" => {
                let (Some(paquete), Some(prueba)) = (&p.paquete, &p.prueba) else {
                    return Err(
                        format!("prueba {}: cargo-test necesita paquete y prueba", p.id).into(),
                    );
                };
                eprintln!("xtask: compilando la prueba {paquete}/{prueba} estatica para {arq}");
                let exe = compilar_prueba_estatica(repo, arq, paquete, prueba, &p.caracteristicas)?;
                let destino = carga.join("pruebas").join(&p.id);
                std::fs::copy(&exe, &destino)?;
                quitar_depuracion(&destino, arq);
                let _ = writeln!(plan, "prueba|{}|cargo-test|{}", p.id, prueba);
            }
            "rango" => {
                eprintln!("xtask: compilando aegis-rango (server, estatico) para {arq}");
                let exe = compilar_rango_estatico(repo, arq)?;
                std::fs::copy(&exe, carga.join("bin/aegis-rango"))?;
                quitar_depuracion(&carga.join("bin/aegis-rango"), arq);
                let _ = writeln!(plan, "prueba|{}|rango|", p.id);
            }
            otro => return Err(format!("prueba {}: tipo desconocido {otro}", p.id).into()),
        }
    }
    std::fs::write(carga.join("plan.txt"), plan)?;

    let img = dir.join(format!("carga-{arq}.img"));
    imagen_ext4(&img, ETIQUETA, mib_para(&carga)?, Some(&carga))?;
    Ok(img)
}

/// Los paquetes .deb y .rpm de la arquitectura, con su ORDEN, a `paquetes/` de
/// la carga. Lo que se prueba en la microVM tiene que ser exactamente lo que
/// `tools/empaquetar.sh --matriz` construyo desde los binarios de ESTE arbol: se
/// comprueban su HUELLA (la de los binarios de los que salen, como con los
/// binarios sueltos) y sus SHA256SUMS. El grupo `kernels` de make ci los rehace
/// antes de arrancar.
fn copiar_paquetes(repo: &Repo, arq: &str, carga: &Path, actual: &str) -> Resultado<()> {
    let destino = carga.join("paquetes");
    if destino.is_dir() {
        return Ok(());
    }
    let origen = if arq == "x86_64" {
        repo.raiz.join("dist-paquetes")
    } else {
        repo.raiz.join(format!("dist-paquetes-{arq}"))
    };
    let remedio = format!("tools/empaquetar.sh --matriz --arq {arq}");
    if !origen.join("ORDEN").is_file() {
        return Err(format!(
            "faltan los paquetes de {arq} en {}: {remedio}",
            origen.display()
        )
        .into());
    }
    let grabada = std::fs::read_to_string(origen.join("HUELLA")).ok();
    procedencia(grabada.as_deref(), actual, &origen, &remedio)?;
    let cuadra = Command::new("sha256sum")
        .args(["--quiet", "-c", "SHA256SUMS"])
        .current_dir(&origen)
        .status()?;
    if !cuadra.success() {
        return Err(format!("{} no cuadra con sus SHA256SUMS", origen.display()).into());
    }
    std::fs::create_dir_all(&destino)?;
    for e in std::fs::read_dir(&origen)? {
        let e = e?;
        let nombre = e.file_name().to_string_lossy().into_owned();
        if nombre == "ORDEN" || nombre.ends_with(".deb") || nombre.ends_with(".rpm") {
            std::fs::copy(e.path(), destino.join(nombre))?;
        }
    }
    Ok(())
}

/// Quita la informacion de depuracion de una prueba estatica antes de meterla en
/// la carga: una prueba de integracion pesa 130 MB con ella y unos 20 sin ella,
/// y la depuracion no sirve de nada dentro de la microVM. Si no hay `strip` para
/// esa arquitectura se deja como esta: el disco de carga se dimensiona con lo que
/// haya.
fn quitar_depuracion(exe: &Path, arq: &str) {
    let strip = match arq {
        "aarch64" => "aarch64-linux-gnu-strip",
        _ => "strip",
    };
    let _ = Command::new(strip)
        .arg("--strip-debug")
        .arg(exe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// El tamaño del disco de carga, sacado de lo que hay que meter en el.
///
/// Era un numero fijo (256 MiB) y se quedo corto en cuanto el agente enlazo su
/// trabajador y la matriz sumo pruebas estaticas: `mkfs.ext4` no cabia y la
/// matriz entera no arrancaba (FASE 1 del MP-16). Un tercio de margen para los
/// metadatos de ext4 y 32 MiB de suelo.
fn mib_para(dir: &Path) -> Resultado<u64> {
    fn bytes(d: &Path) -> std::io::Result<u64> {
        let mut total = 0;
        for e in std::fs::read_dir(d)? {
            let e = e?;
            let m = e.metadata()?;
            total += if m.is_dir() {
                bytes(&e.path())?
            } else {
                m.len()
            };
        }
        Ok(total)
    }
    let b = bytes(dir)?;
    Ok((b + b / 3) / (1024 * 1024) + 32)
}

/// Compila una prueba de integracion como binario ESTATICO para la microVM: la
/// misma receta que el agente publicado de esa arquitectura (musl hermetico en
/// x86-64, glibc estatica con las bibliotecas arm64 en aarch64), para que corra
/// igual en Debian 11 que en Fedora.
fn compilar_prueba_estatica(
    repo: &Repo,
    arq: &str,
    paquete: &str,
    prueba: &str,
    caracteristicas: &[String],
) -> Resultado<PathBuf> {
    let mut cmd = Command::new(crate::repo::cargo());
    let features: Vec<String>;
    let triple = match arq {
        "x86_64" => {
            let sysroot = std::env::var("AEGIS_MUSL_SYSROOT")
                .unwrap_or_else(|_| "/opt/aegis/musl-sysroot".into());
            let cc = format!("{sysroot}/bin/aegis-musl-gcc");
            cmd.env("CC_x86_64_unknown_linux_musl", &cc)
                .env("AR_x86_64_unknown_linux_musl", "ar")
                .env("CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER", &cc)
                .env("RUSTFLAGS", "-C link-self-contained=no");
            features = caracteristicas_de(caracteristicas, "hermetico");
            "x86_64-unknown-linux-musl"
        }
        "aarch64" => {
            let lib = "/usr/lib/aarch64-linux-gnu";
            let btf = cache().join("btf/ubuntu-24.04-arm64.btf");
            cmd.env(
                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER",
                "aarch64-linux-gnu-gcc",
            )
            .env("CC_aarch64_unknown_linux_gnu", "aarch64-linux-gnu-gcc")
            .env("AR_aarch64_unknown_linux_gnu", "aarch64-linux-gnu-ar")
            .env("PKG_CONFIG_ALLOW_CROSS", "1")
            .env("PKG_CONFIG_PATH", format!("{lib}/pkgconfig"))
            .env("PKG_CONFIG_LIBDIR", format!("{lib}/pkgconfig"))
            .env("AEGIS_BTF", &btf)
            .env(
                "RUSTFLAGS",
                format!("-C target-feature=+crt-static -L native={lib} -C link-arg=-l:libzstd.a"),
            );
            features = caracteristicas_de(caracteristicas, "estatico-sistema");
            "aarch64-unknown-linux-gnu"
        }
        otra => return Err(format!("arquitectura sin receta estatica: {otra}").into()),
    };
    cmd.args([
        "test",
        "--locked",
        "--no-run",
        "--message-format=json-render-diagnostics",
    ])
    .args(["--target", triple, "-p", paquete, "--test", prueba])
    .arg("--manifest-path")
    .arg(repo.raiz.join("Cargo.toml"))
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit());
    if !features.is_empty() {
        cmd.args(["--features", &features.join(",")]);
    }
    let salida = cmd.output().map_err(|e| format!("cargo: {e}"))?;
    if !salida.status.success() {
        return Err(format!("no compila la prueba {paquete}/{prueba} para {arq}").into());
    }
    String::from_utf8_lossy(&salida.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["reason"] == "compiler-artifact" && v["target"]["name"] == prueba)
        .find_map(|v| v["executable"].as_str().map(PathBuf::from))
        .ok_or_else(|| format!("cargo no informo del ejecutable de {paquete}/{prueba}").into())
}

/// Compila el binario `aegis-rango` del workspace del SERVIDOR como binario
/// estatico para la microVM, con la misma receta de enlace que el agente de esa
/// arquitectura. Trae solo las emulaciones benignas (sin la caracteristica
/// `sistema`, aplazada): no añade dependencias, asi que server/Cargo.lock no
/// cambia.
fn compilar_rango_estatico(repo: &Repo, arq: &str) -> Resultado<PathBuf> {
    let mut cmd = Command::new(crate::repo::cargo());
    let triple = match arq {
        "x86_64" => {
            let sysroot = std::env::var("AEGIS_MUSL_SYSROOT")
                .unwrap_or_else(|_| "/opt/aegis/musl-sysroot".into());
            let cc = format!("{sysroot}/bin/aegis-musl-gcc");
            cmd.env("CC_x86_64_unknown_linux_musl", &cc)
                .env("AR_x86_64_unknown_linux_musl", "ar")
                .env("CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER", &cc)
                .env("RUSTFLAGS", "-C link-self-contained=no");
            "x86_64-unknown-linux-musl"
        }
        "aarch64" => {
            let lib = "/usr/lib/aarch64-linux-gnu";
            cmd.env(
                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER",
                "aarch64-linux-gnu-gcc",
            )
            .env("CC_aarch64_unknown_linux_gnu", "aarch64-linux-gnu-gcc")
            .env("AR_aarch64_unknown_linux_gnu", "aarch64-linux-gnu-ar")
            .env(
                "RUSTFLAGS",
                format!("-C target-feature=+crt-static -L native={lib}"),
            );
            "aarch64-unknown-linux-gnu"
        }
        otra => return Err(format!("arquitectura sin receta estatica: {otra}").into()),
    };
    cmd.args([
        "build",
        "--release",
        "--message-format=json-render-diagnostics",
    ])
    .args([
        "--target",
        triple,
        "-p",
        "aegis-rango",
        "--bin",
        "aegis-rango",
    ])
    .arg("--manifest-path")
    .arg(repo.raiz.join("server/Cargo.toml"))
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit());
    let salida = cmd.output().map_err(|e| format!("cargo: {e}"))?;
    if !salida.status.success() {
        return Err(format!("no compila aegis-rango (server) para {arq}").into());
    }
    String::from_utf8_lossy(&salida.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["reason"] == "compiler-artifact" && v["target"]["name"] == "aegis-rango")
        .find_map(|v| v["executable"].as_str().map(PathBuf::from))
        .ok_or_else(|| "cargo no informo del ejecutable de aegis-rango".into())
}

/// Las features de la configuracion, con la variante de enlace estatico de la
/// arquitectura: `hermetico` en x86-64, `estatico-sistema` en aarch64.
fn caracteristicas_de(declaradas: &[String], estatica: &str) -> Vec<String> {
    let mut v: Vec<String> = declaradas
        .iter()
        .filter(|c| *c != "hermetico" && *c != "estatico-sistema")
        .cloned()
        .collect();
    v.push(estatica.to_string());
    v
}

// ── ejecutar ────────────────────────────────────────────────────────────────

/// Resultado de una imagen.
#[derive(Debug, Default, Clone)]
struct Resultado1 {
    kernel: String,
    distro: String,
    lineas: Vec<String>,
    problemas: Vec<String>,
    duracion: Duration,
}

fn semilla(dir: &Path, id: &str) -> Resultado<PathBuf> {
    // Los resultados van a un DISCO DE SALIDA, no a la consola serie. La
    // consola se uso primero y fallaba en silencio en las distribuciones cuyo
    // getty del puerto serie arranca durante la prueba (Rocky, Fedora,
    // openSUSE): agetty hace vhangup() y revoca los descriptores abiertos a la
    // tty, asi que todo lo que el plan escribia despues se perdia aunque siguiera
    // ejecutandose. Un fichero en un disco propio no depende de quien tenga la
    // consola.
    let user = format!(
        "#cloud-config\n\
         runcmd:\n\
         \x20 - [sh, -c, 'mkdir -p /mnt/aegis /mnt/salida && mount -o ro LABEL={ETIQUETA} /mnt/aegis \
         && mount LABEL={SALIDA} /mnt/salida; \
         sh /mnt/aegis/dentro.sh /mnt/aegis > /mnt/salida/resultado.txt 2>&1; \
         sync; umount /mnt/salida; poweroff -f']\n"
    );
    let meta = format!(
        "instance-id: aegis-{id}-{}\nlocal-hostname: aegis-{id}\n",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default()
    );
    std::fs::write(dir.join("user-data"), user)?;
    std::fs::write(dir.join("meta-data"), meta)?;
    let img = dir.join("semilla.img");
    ejecutar_cmd(
        Command::new("cloud-localds")
            .arg(&img)
            .arg(dir.join("user-data"))
            .arg(dir.join("meta-data")),
        "cloud-localds (cloud-image-utils)",
    )?;
    Ok(img)
}

fn primero_que_exista(rutas: &[&str]) -> Option<String> {
    rutas
        .iter()
        .find(|r| Path::new(r).is_file())
        .map(|r| r.to_string())
}

fn arrancar(
    k: &Kernels,
    im: &Imagen,
    base: &Path,
    carga: &Path,
    dir: &Path,
    juzgar_plan: bool,
) -> Resultado<Resultado1> {
    std::fs::create_dir_all(dir)?;
    let disco = dir.join("disco.qcow2");
    let _ = std::fs::remove_file(&disco);
    // El overlay crece a 20 GiB SOLO si la imagen base es diminuta (< 2 GiB).
    // La unica asi es openSUSE Leap (~0.8 GiB), que se quedaba sin disco en el
    // ciclo de paquetes (instalar v1, actualizar a v2, instalar la v3 rota y
    // volver atras: ~26 MiB de binarios por version mas journal) y hacia que
    // `rpm` abortara con «needs NN MB on the / filesystem». El overlay es
    // disperso y cloud-init crece la particion al arrancar (growpart).
    //
    // NUNCA se agranda una base que ya tiene sitio: (1) un tamaño MENOR que la
    // base truncaria su sistema de ficheros —amazon-linux trae 25 GiB y con un
    // overlay de 20 GiB no arrancaba—, y (2) crecer una base holgada solo alarga
    // el growpart/resize al arrancar, carisimo bajo emulacion (las arm64). Las
    // demas imagenes (>= 3 GiB) tienen sitio de sobra: debian-12-arm64 a 3 GiB
    // pasa el ciclo entero.
    // El tamaño virtual de la base, de la linea «virtual size: 25 GiB
    // (26843545600 bytes)» de `qemu-img info`. Se usa la salida HUMANA, no la
    // JSON: el JSON trae DOS «virtual-size» (el del fichero contenedor y el del
    // disco) y coger el primero daba el del contenedor (~1.8 GiB) y truncaba
    // amazon-linux. Si no se puede leer, se asume GRANDE y NO se agranda: nunca
    // truncar es mas seguro que arriesgarse a romper un sistema de ficheros.
    let base_bytes = ejecutar_cmd(
        Command::new("qemu-img").arg("info").arg(base),
        "qemu-img info",
    )?
    .lines()
    .find(|l| l.trim_start().starts_with("virtual size:"))
    .and_then(|l| l.split('(').nth(1))
    .and_then(|s| s.split_whitespace().next())
    .and_then(|s| s.parse::<u64>().ok())
    .unwrap_or(u64::MAX);
    let mut crear = Command::new("qemu-img");
    crear
        .args(["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b"])
        .arg(base)
        .arg(&disco);
    if base_bytes < 2 * 1024 * 1024 * 1024 {
        crear.arg("20G");
    }
    ejecutar_cmd(&mut crear, "qemu-img create")?;
    let semilla = semilla(dir, &im.id)?;
    let serie = dir.join("consola.log");
    let _ = std::fs::remove_file(&serie);

    let (prog, mut args, plazo, cpus): (&str, Vec<String>, u64, u32) =
        match im.arquitectura.as_str() {
            "x86_64" => (
                "qemu-system-x86_64",
                vec![
                    "-machine".into(),
                    "q35,accel=kvm".into(),
                    "-cpu".into(),
                    "host".into(),
                ],
                k.vm.plazo_kvm_s,
                vcpus(k, im),
            ),
            "aarch64" => (
                "qemu-system-aarch64",
                vec![
                    "-machine".into(),
                    "virt".into(),
                    // Un modelo concreto y no `max`: con `max` QEMU emula en software
                    // la autenticacion de punteros (ARMv8.3) en cada instruccion, y en
                    // emulacion completa la imagen de Ubuntu no paso del firmware
                    // UEFI en 40 minutos. Con Cortex-A72 llega a systemd en menos de 3.
                    // Para eBPF da igual: el kernel y el verificador son los mismos.
                    "-cpu".into(),
                    "cortex-a72".into(),
                ],
                k.vm.plazo_emulado_s,
                vcpus(k, im),
            ),
            otra => return Err(format!("{}: arquitectura desconocida {otra}", im.id).into()),
        };
    if im.firmware == "uefi" {
        let (codigo, vars) = if im.arquitectura == "aarch64" {
            (
                primero_que_exista(&["/usr/share/AAVMF/AAVMF_CODE.fd"]),
                primero_que_exista(&["/usr/share/AAVMF/AAVMF_VARS.fd"]),
            )
        } else {
            (
                primero_que_exista(&[
                    "/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "/usr/share/OVMF/OVMF_CODE.fd",
                ]),
                primero_que_exista(&[
                    "/usr/share/OVMF/OVMF_VARS_4M.fd",
                    "/usr/share/OVMF/OVMF_VARS.fd",
                ]),
            )
        };
        let (Some(codigo), Some(vars)) = (codigo, vars) else {
            return Err(format!(
                "{}: falta el firmware UEFI (paquetes ovmf / qemu-efi-aarch64)",
                im.id
            )
            .into());
        };
        let copia = dir.join("uefi-vars.fd");
        std::fs::copy(&vars, &copia)?;
        args.extend([
            "-drive".into(),
            format!("if=pflash,format=raw,readonly=on,file={codigo}"),
            "-drive".into(),
            format!("if=pflash,format=raw,file={}", copia.display()),
        ]);
    }
    args.extend([
        "-m".into(),
        k.vm.memoria_mib.to_string(),
        "-smp".into(),
        cpus.to_string(),
        // Fuente de entropia del anfitrion. Sin ella, bajo emulacion el kernel
        // tardaba mas de 3 minutos en inicializar su generador (crng), y
        // cloud-init y systemd esperaban detras: la imagen ARM rozaba el plazo.
        "-device".into(),
        "virtio-rng-pci".into(),
        "-display".into(),
        "none".into(),
        "-monitor".into(),
        "none".into(),
        "-no-reboot".into(),
        "-serial".into(),
        format!("file:{}", serie.display()),
        "-nic".into(),
        "user,model=virtio-net-pci".into(),
        "-drive".into(),
        format!("if=virtio,format=qcow2,file={}", disco.display()),
        "-drive".into(),
        format!("if=virtio,format=raw,file={}", semilla.display()),
        "-drive".into(),
        format!("if=virtio,format=raw,readonly=on,file={}", carga.display()),
    ]);
    let salida_disco = dir.join("salida.img");
    imagen_ext4(&salida_disco, SALIDA, 128, None)?;
    args.extend([
        "-drive".into(),
        format!("if=virtio,format=raw,file={}", salida_disco.display()),
    ]);

    let inicio = Instant::now();
    let mut hijo = Command::new(prog)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{prog}: {e}"))?;
    let mut agotado = false;
    loop {
        if hijo.try_wait()?.is_some() {
            break;
        }
        if inicio.elapsed() > Duration::from_secs(plazo) {
            let _ = hijo.kill();
            let _ = hijo.wait();
            agotado = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    let salida = hijo.wait_with_output()?;

    // Primero el fichero del disco de salida. Solo si no existe (la microVM no
    // llego a montar el disco) se mira la consola, que al menos dice hasta
    // donde llego el arranque.
    let fichero = Command::new("debugfs")
        .arg("-R")
        .arg("cat /resultado.txt")
        .arg(&salida_disco)
        .output()
        .ok()
        .filter(|o| o.status.success() && !o.stdout.is_empty())
        .map(|o| o.stdout);
    let texto = match fichero {
        Some(b) => b,
        None => std::fs::read(&serie).unwrap_or_default(),
    };
    let texto = String::from_utf8_lossy(&texto);
    let lineas: Vec<String> = texto
        .lines()
        .filter_map(|l| {
            l.find("AEGIS-")
                .map(|i| l[i..].trim_end_matches('\r').to_string())
        })
        .collect();
    let mut r = Resultado1 {
        lineas,
        duracion: inicio.elapsed(),
        ..Default::default()
    };
    if agotado {
        r.problemas
            .push(format!("sin terminar en el plazo de {plazo} s"));
    }
    if !salida.status.success() && !agotado {
        r.problemas.push(format!(
            "qemu salio con error: {}",
            String::from_utf8_lossy(&salida.stderr).trim()
        ));
    }
    // Una extraccion (`kernels btf`) no ejecuta el plan de la matriz: la juzga
    // quien la pidio.
    if juzgar_plan {
        juzgar(k, im, &mut r);
    }
    std::fs::write(dir.join("resultado.txt"), r.lineas.join("\n") + "\n")?;
    Ok(r)
}

/// Crea un sistema de ficheros ext4 con etiqueta en un fichero de imagen, con
/// el contenido de `dir` si se da.
fn imagen_ext4(img: &Path, etiqueta: &str, mib: u64, dir: Option<&Path>) -> Resultado<()> {
    let _ = std::fs::remove_file(img);
    std::fs::File::create(img)?.set_len(mib * 1024 * 1024)?;
    let mut cmd = Command::new("mkfs.ext4");
    cmd.args(["-q", "-F", "-L", etiqueta]);
    if let Some(d) = dir {
        cmd.arg("-d").arg(d);
    }
    ejecutar_cmd(cmd.arg(img), "mkfs.ext4")?;
    Ok(())
}

/// `cargo xtask kernels btf`: el BTF del kernel de cada imagen, para compilar
/// las sondas de OTRA arquitectura (las uprobes leen registros, y la
/// disposicion de `pt_regs` es propia de cada CPU). El BTF solo existe con el
/// kernel en marcha, asi que se arranca la imagen y se copia a un disco de
/// salida que se lee con `debugfs`, sin montar nada en el anfitrion.
pub fn btf(repo: &Repo, filtro: &Filtro) -> Resultado<()> {
    let k: Kernels = config::leer(&repo.raiz, "kernels.toml")?;
    let dir = trabajo(repo).join("btf");
    let carga = dir.join("carga");
    let _ = std::fs::remove_dir_all(&carga);
    std::fs::create_dir_all(&carga)?;
    std::fs::copy(
        repo.raiz.join("tools/matriz-kernels/dentro.sh"),
        carga.join("dentro.sh"),
    )?;
    std::fs::write(carga.join("plan.txt"), "btf|\n")?;
    let carga_img = dir.join("carga.img");
    imagen_ext4(&carga_img, ETIQUETA, 16, Some(&carga))?;
    let destino_dir = cache().join("btf");
    std::fs::create_dir_all(&destino_dir)?;

    for im in k.imagen.iter().filter(|i| filtro.admite(i)) {
        let base = cache().join("imagenes").join(format!("{}.qcow2", im.id));
        if !base.is_file() {
            return Err(format!("falta la imagen {}: cargo xtask kernels traer", im.id).into());
        }
        eprintln!("xtask: arrancando {} para extraer su BTF", im.id);
        let dir_im = dir.join(&im.id);
        let r = arrancar(&k, im, &base, &carga_img, &dir_im, false)?;
        let salida = dir_im.join("salida.img");
        let Some(kernel) = r
            .lineas
            .iter()
            .find_map(|l| l.strip_prefix("AEGIS-MATRIZ|btf|copiado|"))
        else {
            return Err(format!(
                "{}: la microVM no copio su BTF ({})",
                im.id,
                if r.problemas.is_empty() {
                    r.lineas.join(" / ")
                } else {
                    r.problemas.join("; ")
                }
            )
            .into());
        };
        let destino = destino_dir.join(format!("{}.btf", im.id));
        ejecutar_cmd(
            Command::new("debugfs")
                .arg("-R")
                .arg(format!("dump /vmlinux.btf {}", destino.display()))
                .arg(&salida),
            "debugfs",
        )?;
        let bytes = std::fs::read(&destino)?;
        // Cabecera BTF: la magia 0xeB9F, en el orden de bytes del kernel.
        if bytes.len() < 24 || !(bytes[..2] == [0x9f, 0xeb] || bytes[..2] == [0xeb, 0x9f]) {
            return Err(format!("{}: lo extraido no es BTF", im.id).into());
        }
        eprintln!(
            "xtask: BTF de {} (kernel {kernel}) en {} ({} KiB)",
            im.id,
            destino.display(),
            bytes.len() / 1024
        );
    }
    Ok(())
}

/// Convierte las lineas de la consola en veredicto.
fn juzgar(k: &Kernels, im: &Imagen, r: &mut Resultado1) {
    let campos = |l: &String| l.split('|').map(str::to_string).collect::<Vec<_>>();
    let mut bpf: BTreeMap<String, String> = BTreeMap::new();
    let mut pruebas: BTreeMap<String, String> = BTreeMap::new();
    let mut fin = false;
    for l in r.lineas.clone() {
        let c = campos(&l);
        match (c.first().map(String::as_str), c.get(1).map(String::as_str)) {
            (Some("AEGIS-MATRIZ"), Some("inicio")) => {
                r.kernel = c.get(2).cloned().unwrap_or_default()
            }
            (Some("AEGIS-MATRIZ"), Some("distro")) => {
                r.distro = c.get(2).cloned().unwrap_or_default()
            }
            (Some("AEGIS-MATRIZ"), Some("bpf")) => {
                bpf.insert(
                    c.get(2).cloned().unwrap_or_default(),
                    c.get(3).cloned().unwrap_or_default(),
                );
            }
            (Some("AEGIS-MATRIZ"), Some("prueba")) => {
                pruebas.insert(
                    c.get(2).cloned().unwrap_or_default(),
                    c.get(3).cloned().unwrap_or_default(),
                );
            }
            (Some("AEGIS-MATRIZ"), Some("fin")) => fin = true,
            _ => {}
        }
    }
    if r.kernel.is_empty() {
        r.problemas
            .push("la microVM no llego a ejecutar el plan (sin linea de inicio)".into());
        return;
    }
    if !fin {
        r.problemas
            .push("el plan no termino (sin linea de fin)".into());
    }
    if !familia_coincide(&im.kernel, &r.kernel) {
        r.problemas.push(format!(
            "el kernel arrancado ({}) no es de la familia declarada ({}): actualiza kernels.toml",
            r.kernel, im.kernel
        ));
    }
    for b in &k.bpf {
        match bpf.get(&b.objeto).map(String::as_str) {
            Some("pasa") => {}
            Some("no-aplica") => {
                if let Err(p) = no_aplica_admitido(b, &r.kernel) {
                    r.problemas.push(p);
                }
            }
            Some(otro) => r.problemas.push(format!("{}.bpf.o: {otro}", b.objeto)),
            None => r
                .problemas
                .push(format!("{}.bpf.o: sin resultado", b.objeto)),
        }
    }
    for p in &k.prueba {
        match pruebas.get(&p.id).map(String::as_str) {
            Some("pasa") => {}
            Some(otro) => r.problemas.push(format!("prueba {}: {otro}", p.id)),
            None => r.problemas.push(format!("prueba {}: sin resultado", p.id)),
        }
    }
}

/// `5.10` casa con `5.10.0-32-cloud-amd64`; `5.14-el9` exige ademas `el9`;
/// `estable` casa con cualquiera.
fn familia_coincide(declarada: &str, real: &str) -> bool {
    if declarada == "estable" {
        return true;
    }
    let (version, marca) = declarada.split_once('-').unwrap_or((declarada, ""));
    let prefijo_ok =
        real.starts_with(&format!("{version}.")) || real.starts_with(&format!("{version}-"));
    prefijo_ok && (marca.is_empty() || real.contains(marca))
}

/// Si un `no-aplica` de ese objeto se admite en ese kernel.
///
/// Solo lo admite un objeto que declara las kfunc que exige, y solo por debajo
/// de su `obligatorio_desde`: por encima, el kernel tiene la capacidad y no
/// pasar es un defecto.
fn no_aplica_admitido(b: &config::ObjetoBpf, kernel: &str) -> Result<(), String> {
    if b.requiere_kfunc.is_empty() {
        return Err(format!("{}.bpf.o: no-aplica", b.objeto));
    }
    let Some(v) = b.obligatorio_desde.as_deref() else {
        return Ok(());
    };
    if version_al_menos(kernel, v) {
        Err(format!(
            "{}.bpf.o: no-aplica en {kernel}, y desde Linux {v} tiene que pasar",
            b.objeto
        ))
    } else {
        Ok(())
    }
}

/// `6.8.0-45-generic` es al menos `6.7`: se comparan mayor y menor. Un kernel
/// cuya version no se deja leer no se da por reciente: no se le exige nada.
fn version_al_menos(real: &str, minima: &str) -> bool {
    fn mayor_menor(s: &str) -> Option<(u32, u32)> {
        let mut partes = s.split(|c: char| !c.is_ascii_digit());
        let mayor = partes.next()?.parse().ok()?;
        let menor = partes.next()?.parse().ok()?;
        Some((mayor, menor))
    }
    match (mayor_menor(real), mayor_menor(minima)) {
        (Some(r), Some(m)) => r >= m,
        _ => false,
    }
}

/// Arranca la matriz y devuelve el resumen, o falla si alguna imagen falla.
pub fn ejecutar(repo: &Repo, filtro: &Filtro) -> Resultado<()> {
    let k: Kernels = config::leer(&repo.raiz, "kernels.toml")?;
    let imagenes: Vec<Imagen> = k
        .imagen
        .iter()
        .filter(|i| filtro.admite(i))
        .cloned()
        .collect();
    if imagenes.is_empty() {
        return Err("ninguna imagen coincide con el filtro".into());
    }
    if imagenes.iter().any(|i| i.arquitectura == "x86_64") {
        let kvm = Path::new("/dev/kvm");
        if !kvm.exists()
            || std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(kvm)
                .is_err()
        {
            return Err(
                "la matriz de kernels necesita KVM (/dev/kvm accesible). Es una puerta \
                        obligatoria: sin KVM no hay veredicto, no un verde."
                    .into(),
            );
        }
    }
    let dir = trabajo(repo);
    std::fs::create_dir_all(&dir)?;

    let mut cargas = BTreeMap::new();
    for arq in imagenes
        .iter()
        .map(|i| i.arquitectura.clone())
        .collect::<std::collections::BTreeSet<_>>()
    {
        cargas.insert(arq.clone(), preparar_carga(repo, &k, &arq, &dir)?);
    }
    for im in &imagenes {
        let base = cache().join("imagenes").join(format!("{}.qcow2", im.id));
        if !base.is_file() {
            return Err(format!("falta la imagen {}: cargo xtask kernels traer", im.id).into());
        }
    }

    let paralelo: usize = std::env::var("AEGIS_MATRIZ_PARALELO")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3)
        .max(1);
    let nucleos = Arc::new(Nucleos::nuevo(
        std::thread::available_parallelism()
            .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
            .unwrap_or(1),
    ));
    let cola = Arc::new(Mutex::new(imagenes.clone()));
    let resultados: Arc<Mutex<BTreeMap<String, Resultado1>>> = Arc::default();
    let k = Arc::new(k);
    let cargas = Arc::new(cargas);
    std::thread::scope(|s| {
        for _ in 0..paralelo {
            let cola = Arc::clone(&cola);
            let resultados = Arc::clone(&resultados);
            let k = Arc::clone(&k);
            let cargas = Arc::clone(&cargas);
            let nucleos = Arc::clone(&nucleos);
            let dir = dir.clone();
            s.spawn(move || loop {
                let Some(im) = cola.lock().ok().and_then(|mut c| c.pop()) else {
                    break;
                };
                let _reserva = nucleos.reservar(vcpus(&k, &im));
                eprintln!("xtask: arrancando {} ({})", im.id, im.arquitectura);
                let base = cache().join("imagenes").join(format!("{}.qcow2", im.id));
                let r = arrancar(
                    &k,
                    &im,
                    &base,
                    &cargas[&im.arquitectura],
                    &dir.join(&im.id),
                    true,
                )
                .unwrap_or_else(|e| Resultado1 {
                    problemas: vec![e.to_string()],
                    ..Default::default()
                });
                eprintln!(
                    "xtask: {} terminada en {} s: {}",
                    im.id,
                    r.duracion.as_secs(),
                    if r.problemas.is_empty() {
                        "PASA".into()
                    } else {
                        r.problemas.join("; ")
                    }
                );
                if let Ok(mut m) = resultados.lock() {
                    m.insert(im.id.clone(), r);
                }
            });
        }
    });

    let resultados = resultados
        .lock()
        .map_err(|_| "resultados envenenados")?
        .clone();
    let resumen = resumen(&imagenes, &resultados);
    std::fs::write(dir.join("resumen.md"), &resumen)?;
    println!("{resumen}");
    let fallidas: Vec<&String> = resultados
        .iter()
        .filter(|(_, r)| !r.problemas.is_empty())
        .map(|(id, _)| id)
        .collect();
    if fallidas.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "la matriz de kernels falla en: {} (detalle en {})",
            fallidas
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            dir.display()
        )
        .into())
    }
}

fn resumen(imagenes: &[Imagen], res: &BTreeMap<String, Resultado1>) -> String {
    let mut s = String::from(
        "| Imagen | Kernel arrancado | Veredicto | Degradaciones declaradas | Medidas del agente |\n\
         |---|---|---|---|---|\n",
    );
    for im in imagenes {
        let Some(r) = res.get(&im.id) else { continue };
        let deg: Vec<String> = r
            .lineas
            .iter()
            .filter_map(|l| l.strip_prefix("AEGIS-DEG|"))
            .map(|d| d.split('|').next().unwrap_or_default().to_string())
            .collect();
        let med: Vec<String> = r
            .lineas
            .iter()
            .filter_map(|l| l.strip_prefix("AEGIS-MEDIDA|aegis-agent|"))
            .map(|m| {
                let c: Vec<&str> = m.split('|').collect();
                format!(
                    "{}={} {}",
                    c.first().unwrap_or(&""),
                    c.get(1).unwrap_or(&""),
                    c.get(2).unwrap_or(&"")
                )
            })
            .collect();
        let _ = writeln!(
            s,
            "| `{}` | {} | {} | {} | {} |",
            im.id,
            if r.kernel.is_empty() {
                "—"
            } else {
                &r.kernel
            },
            if r.problemas.is_empty() {
                "**pasa**".to_string()
            } else {
                format!("**falla**: {}", r.problemas.join("; "))
            },
            if deg.is_empty() {
                "ninguna".to_string()
            } else {
                deg.join(", ")
            },
            if med.is_empty() {
                "—".to_string()
            } else {
                med.join(", ")
            }
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn las_microvm_en_marcha_nunca_piden_mas_vcpu_que_nucleos() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let nucleos = Nucleos::nuevo(8);
        let en_uso = AtomicU32::new(0);
        let maximo = AtomicU32::new(0);
        // Dos emuladas de 4 y varias KVM de 2, todas a la vez: lo que fallo.
        let pedidos = [4u32, 4, 2, 2, 2, 2, 4, 2];
        std::thread::scope(|s| {
            for &p in &pedidos {
                let (nucleos, en_uso, maximo) = (&nucleos, &en_uso, &maximo);
                s.spawn(move || {
                    let _r = nucleos.reservar(p);
                    let ahora = en_uso.fetch_add(p, Ordering::SeqCst) + p;
                    maximo.fetch_max(ahora, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(20));
                    en_uso.fetch_sub(p, Ordering::SeqCst);
                });
            }
        });
        assert!(maximo.load(Ordering::SeqCst) <= 8);
        assert_eq!(*nucleos.libres.lock().unwrap(), 8, "todo se devuelve");
    }

    #[test]
    fn lo_que_pide_mas_que_el_total_se_recorta_y_no_espera_siempre() {
        let nucleos = Nucleos::nuevo(2);
        let r = nucleos.reservar(4);
        assert_eq!(r.n, 2);
        drop(r);
        assert_eq!(*nucleos.libres.lock().unwrap(), 2);
    }

    #[test]
    fn un_no_aplica_solo_vale_por_debajo_de_obligatorio_desde() {
        let ki = config::ObjetoBpf {
            objeto: "aegis_kintegrity".into(),
            requiere_kfunc: vec!["bpf_iter_task_new".into()],
            obligatorio_desde: Some("6.7".into()),
        };
        // Debian 12 y openSUSE Leap 15.6 no tienen el iterador abierto.
        assert!(no_aplica_admitido(&ki, "6.1.0-25-cloud-amd64").is_ok());
        assert!(no_aplica_admitido(&ki, "6.4.0-150600.23.25-default").is_ok());
        // Ubuntu 24.04 y Fedora si: ahi no pasar es un defecto.
        let e = no_aplica_admitido(&ki, "6.8.0-45-generic").unwrap_err();
        assert!(e.contains("6.7"), "{e}");
        assert!(no_aplica_admitido(&ki, "6.19.3-200.fc44.x86_64").is_err());
        // Sin `obligatorio_desde` se admite en cualquier kernel.
        let libre = config::ObjetoBpf {
            obligatorio_desde: None,
            ..ki.clone()
        };
        assert!(no_aplica_admitido(&libre, "6.8.0-45-generic").is_ok());
        // Y un objeto que no exige kfunc nunca puede no aplicar.
        let sin = config::ObjetoBpf {
            requiere_kfunc: Vec::new(),
            ..ki
        };
        assert!(no_aplica_admitido(&sin, "5.10.0-32-cloud-amd64").is_err());
    }

    #[test]
    fn las_versiones_se_comparan_por_mayor_y_menor() {
        assert!(version_al_menos("6.7.0", "6.7"));
        assert!(version_al_menos("6.10.2-arch1", "6.7"));
        assert!(version_al_menos("7.0.1", "6.7"));
        assert!(!version_al_menos("6.6.114-microsoft-standard-WSL2", "6.7"));
        assert!(!version_al_menos("5.14.0-503.14.1.el9_5.x86_64", "6.7"));
        assert!(!version_al_menos("desconocido", "6.7"));
    }

    #[test]
    fn la_matriz_solo_prueba_binarios_de_este_arbol() {
        let d = Path::new("dist-hermetico");
        let h = "a".repeat(64);
        assert!(procedencia(Some(&format!("{h}\n")), &h, d, "x").is_ok());
        let otra = procedencia(Some(&"b".repeat(64)), &h, d, "x").unwrap_err();
        assert!(otra.to_string().contains("otro arbol"), "{otra}");
        let sin = procedencia(None, &h, d, "x").unwrap_err();
        assert!(sin.to_string().contains("falta HUELLA"), "{sin}");
    }

    #[test]
    fn sumas_en_formato_gnu_y_bsd() {
        let gnu =
            "abc123  debian-12-genericcloud-amd64.qcow2\nfff *jammy-server-cloudimg-amd64.img\n";
        assert_eq!(
            suma_publicada(gnu, "debian-12-genericcloud-amd64.qcow2").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            suma_publicada(gnu, "jammy-server-cloudimg-amd64.img").as_deref(),
            Some("fff")
        );
        let bsd = "-----BEGIN PGP SIGNED MESSAGE-----\nSHA256 (Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2) = AB12\n";
        assert_eq!(
            suma_publicada(bsd, "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2").as_deref(),
            Some("ab12")
        );
        assert_eq!(suma_publicada(bsd, "otro.qcow2"), None);
    }

    /// Ejecuta `guion` con `sh` (dash en Debian/Ubuntu, como en las microVM)
    /// tras cargar `dentro.sh` en modo solo-funciones. `sleep` se anula para
    /// que las esperas del arnes no cuesten tiempo real. `ruta` va delante
    /// del PATH (para un `journalctl` de mentira).
    #[cfg(unix)]
    fn arnes(guion: &str, ruta: Option<&Path>) -> String {
        let dentro =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../tools/matriz-kernels/dentro.sh");
        let mut path = std::env::var("PATH").unwrap_or_default();
        if let Some(r) = ruta {
            path = format!("{}:{path}", r.display());
        }
        let salida = Command::new("sh")
            .arg("-c")
            .arg(format!(". \"$1\"; sleep() {{ :; }}; {guion}"))
            .arg("arnes")
            .arg(&dentro)
            .env("AEGIS_DENTRO_SOLO_FUNCIONES", "1")
            .env("PATH", path)
            .output()
            .expect("sh");
        assert!(
            salida.status.success(),
            "sh fallo: {}",
            String::from_utf8_lossy(&salida.stderr)
        );
        String::from_utf8_lossy(&salida.stdout).into_owned()
    }

    #[cfg(unix)]
    fn juicio(args: &str) -> String {
        arnes(&format!("juicio_trabajador {args}"), None)
    }

    /// El arnes NO es la unica causa de muerte del trabajador: el agente lo
    /// mata al vencer el plazo de un analisis, y al llegar a su umbral enfria
    /// (debian-12-arm64, emulado: 3 muertes de la prueba + 2 por plazo). La
    /// prueba exigia exactamente 4 muertes propias y fallaba con el
    /// cortacircuitos funcionando. Lo que se sigue exigiendo siempre: sin
    /// reinicio del watchdog, cada muerte contada, eventos tras la ultima y
    /// parada limpia.
    #[cfg(unix)]
    #[test]
    fn el_arnes_juzga_el_trabajador_con_las_muertes_del_propio_agente() {
        // Orden: muertes contadas plazos enfriamientos umbral reinicios antes despues limpia
        assert!(juicio("4 4 0 0 '' 0 100 200 si").starts_with("pasa|"));
        // El caso real de debian-12-arm64.
        let real = juicio("3 5 2 1 5 0 3483 3952 si");
        assert!(real.starts_with("pasa|"), "{real}");
        assert!(real.contains("cortacircuitos"), "{real}");
        // Faltan muertes y nada lo explica: fallo.
        let sin = juicio("3 3 0 0 '' 0 100 200 si");
        assert!(sin.contains("faltan-muertes-sin-enfriamiento"), "{sin}");
        // Dice que enfrio, pero lo contado no llega a su propio umbral.
        assert!(juicio("3 4 1 1 5 0 100 200 si").starts_with("falla|"));
        // Cada condicion de produccion sigue siendo fallo duro.
        assert!(juicio("4 4 0 0 '' 1 100 200 si").contains("el-watchdog-reinicio"));
        assert!(juicio("4 4 0 0 '' 0 100 139 si").contains("no-vio-eventos"));
        assert!(juicio("4 4 0 0 '' 0 '' 200 si").contains("no-vio-eventos"));
        assert!(juicio("4 3 0 0 '' 0 100 200 si").contains("no-conto-las-muertes"));
        assert!(juicio("4 '' 0 0 '' 0 100 200 si").contains("no-conto-las-muertes"));
        assert!(juicio("4 4 0 0 '' 0 100 200 no").contains("sin-parada-limpia"));
        assert!(juicio("0 5 5 1 5 0 100 200 si").contains("la-prueba-no-mato-ninguno"));
    }

    /// Un `journalctl` de mentira: devuelve un informe del arbitro solo a
    /// partir de la llamada `desde` (el agente recien instalado aun no habia
    /// informado) y apunta sus argumentos.
    #[cfg(unix)]
    fn journal_falso(dir: &Path, desde: u32) {
        use std::os::unix::fs::PermissionsExt;
        let f = dir.join("journalctl");
        std::fs::write(
            &f,
            format!(
                "#!/bin/sh\n\
                 n=$(cat \"{d}/n\" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > \"{d}/n\"\n\
                 echo \"$*\" >> \"{d}/args\"\n\
                 [ $n -ge {desde} ] && echo 'aegis-agent: arbitro: eventos=2707 p50_ns=1 p99_ns=2 max_ns=3'\n\
                 exit 0\n",
                d = dir.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// La linea base de convivencia salia «?» (ubuntu-24.04-arm64): se leia
    /// una sola vez, de un journal donde el agente recien instalado aun no
    /// habia escrito ningun informe. Ahora se espera su primer informe, la
    /// lectura vacia se reintenta con tope, y solo se lee lo escrito desde
    /// que empezo la prueba (la unidad la compartio paquete-en-vivo antes).
    #[cfg(unix)]
    #[test]
    fn el_arnes_lee_la_linea_base_cuando_el_agente_ya_informo() {
        let tmp = std::env::temp_dir().join(format!("aegis-arnes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Informa a la llamada 6: la espera tras instalar lo aguarda.
        journal_falso(&tmp, 6);
        let v = arnes(
            "CV_DESDE=@1700000000; cv_esperar_informe 400; printf '[%s]' \"$(cv_eventos)\"",
            Some(&tmp),
        );
        assert_eq!(v, "[2707]");
        let args = std::fs::read_to_string(tmp.join("args")).unwrap();
        assert!(
            args.lines().all(|l| l.contains("--since @1700000000")),
            "toda lectura acotada a la prueba: {args}"
        );

        // Sin esperar, una lectura vacia se reintenta en vez de dar «?».
        let _ = std::fs::remove_file(tmp.join("n"));
        let v = arnes("printf '[%s]' \"$(cv_eventos)\"", Some(&tmp));
        assert_eq!(v, "[2707]");

        // Un agente que nunca informa: vacio tras el tope, sin colgarse.
        let _ = std::fs::remove_file(tmp.join("n"));
        journal_falso(&tmp, 1_000_000);
        let v = arnes(
            "cv_esperar_informe 30; printf '[%s]' \"$(cv_eventos)\"",
            Some(&tmp),
        );
        assert_eq!(v, "[]");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Lo que devuelven, llamada a llamada, `pq_agente` y `cv_eventos` (con
    /// la espera anulada): asi se simula un reinicio del agente entre las dos
    /// lecturas de una medida de convivencia. Van en ficheros porque cada
    /// llamada corre en una subcapa (`$(...)`).
    #[cfg(unix)]
    fn medir_con(pids: &str, eventos: &str, guion: &str) -> String {
        arnes(
            &format!(
                "siguiente() {{ set -- $1; printf '%s' \"$1\"; }}; \
                 resto() {{ set -- $1; shift; printf '%s' \"$*\"; }}; \
                 sacar() {{ siguiente \"$(cat \"$T2/$1\")\"; resto \"$(cat \"$T2/$1\")\" > \"$T2/$1.n\"; mv \"$T2/$1.n\" \"$T2/$1\"; }}; \
                 pq_agente() {{ sacar p; }}; cv_eventos() {{ sacar e; }}; \
                 cv_esperar_informe() {{ :; }}; cv_rafaga() {{ :; }}; \
                 T2=$(mktemp -d); printf '%s' '{pids}' > \"$T2/p\"; printf '%s' '{eventos}' > \"$T2/e\"; \
                 fallos=''; CV_REMEDIDAS=0; {guion}; rm -rf \"$T2\""
            ),
            None,
        )
    }

    /// El watchdog puede reiniciar al agente a mitad de la prueba de
    /// convivencia (se publica, no se juzga), y el agente nuevo cuenta desde
    /// cero: comparar una lectura del viejo con una del nuevo daba «no ve» con
    /// el agente viendo. La medida se repite una vez sobre un mismo agente.
    #[cfg(unix)]
    #[test]
    fn el_arnes_no_compara_contadores_de_dos_agentes() {
        let g = "cv_medir 200; r=$?; cv_ve 200 ebpf:instalado-no-ve $r; \
                 printf 'r=%s rem=%s fallos=[%s]' $r $CV_REMEDIDAS \"$fallos\"";
        // Sin reinicio: una medida y vale.
        assert_eq!(medir_con("7 7", "1000 1300", g), "r=0 rem=0 fallos=[]");
        // Cambia el pid entre lecturas: se repite y la segunda vale.
        assert_eq!(
            medir_con("7 8 8 8", "5000 40 40 300", g),
            "r=0 rem=1 fallos=[]"
        );
        // Mismo pid pero el contador baja (el reinicio cayo entre la lectura
        // del pid y la del contador): tambien se repite.
        assert_eq!(
            medir_con("7 7 7 7", "5000 40 40 300", g),
            "r=0 rem=1 fallos=[]"
        );
        // Un agente que no se deja medir dos veces seguidas se nombra.
        let v = medir_con("1 2 3 4", "10 20 30 40", g);
        assert!(v.contains("r=1 rem=2"), "{v}");
        assert!(v.contains("ebpf:instalado-no-ve:agente-cambiante"), "{v}");
        // Y un agente que de verdad no ve sigue siendo fallo.
        let v = medir_con("7 7", "1000 1100", g);
        assert!(
            v.contains("fallos=[ ebpf:instalado-no-ve(1000->1100)]"),
            "{v}"
        );
    }

    #[test]
    fn familias_de_kernel() {
        assert!(familia_coincide("5.10", "5.10.0-32-cloud-amd64"));
        assert!(!familia_coincide("5.1", "5.10.0-32-cloud-amd64"));
        assert!(familia_coincide("5.14-el9", "5.14.0-503.14.1.el9_5.x86_64"));
        assert!(!familia_coincide("5.14-el9", "5.14.0-1-generic"));
        assert!(familia_coincide("6.8", "6.8.0-45-generic"));
        assert!(familia_coincide("estable", "6.16.9-200.fc44.x86_64"));
    }
}
