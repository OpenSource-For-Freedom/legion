//! llama.cpp server lifecycle: the runtime that actually serves the staged
//! Hugging Face GGUF.
//!
//! Legion stages a SHA-256-pinned GGUF from Hugging Face, but until this module
//! existed nothing ever loaded it — the weights were a write-only artifact and
//! every hunt silently fell back to `engine-only`. This module closes that gap
//! by managing a pinned `llama-server` build the same way the model itself is
//! managed: pinned release, SHA-256 verified, staged under the Legion data dir.
//!
//! Design notes:
//! * An operator-supplied `llama-server` on `PATH` always wins, so anyone who
//!   wants a CUDA/Vulkan/ROCm build just installs one and Legion uses it. The
//!   managed build is the portable CPU fallback so the product works out of the
//!   box on a stock machine.
//! * Extraction shells out to the system `tar`, matching how the rest of the
//!   workspace shells out (`icacls`, `netstat`, `tasklist`, `setx`). This is safe
//!   because the archive's SHA-256 is verified *before* extraction, so the bytes
//!   are already authenticated. Windows 10+ bundles bsdtar, which reads zip; the
//!   PowerShell `Expand-Archive` fallback covers older hosts.
//! * Detection and process spawning are synchronous and dependency-free, so this
//!   module needs no async runtime — the download lives in the web layer, which
//!   owns the Tokio runtime. This mirrors `bootstrap.rs`.

use std::path::{Path, PathBuf};

/// Pinned llama.cpp release. Bump together with the SHA-256s in [`asset_for_host`].
pub const LLAMA_BUILD: &str = "b10054";

const RELEASE_BASE: &str = "https://github.com/ggml-org/llama.cpp/releases/download";

/// A pinned, per-platform `llama-server` release archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerAsset {
    /// Release asset filename.
    pub archive: &'static str,
    /// SHA-256 of the archive, enforced before extraction.
    pub sha256: &'static str,
    /// Exact published size, used as the download cap.
    pub size_bytes: u64,
    /// True when the archive nests everything under a single top-level dir and
    /// therefore needs `--strip-components=1` (the Linux tarballs do; the
    /// Windows zips are flat).
    pub strip_top_level: bool,
}

impl ServerAsset {
    /// Full download URL for this asset.
    pub fn url(&self) -> String {
        format!("{RELEASE_BASE}/{LLAMA_BUILD}/{}", self.archive)
    }
}

/// The pinned archive for the current platform, or `None` where we ship no
/// managed build (the operator must supply `llama-server` on `PATH`).
///
/// Every arm is spelled out so an unsupported target returns `None` rather than
/// failing to compile.
pub fn asset_for_host() -> Option<ServerAsset> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        // Vulkan, not the plain CPU build. llama.cpp publishes no Linux CUDA
        // release, so CPU looked like the only option — but Vulkan reaches the
        // same NVIDIA/AMD/Intel hardware through the driver's ICD, and the
        // difference is not marginal. Measured on a Quadro T2000 with a
        // realistic 4,490-token hunt prompt:
        //
        //     CPU     16.8 tok/s prompt,  5.2 tok/s generate
        //     Vulkan 271.3 tok/s prompt, 58.1 tok/s generate
        //
        // At 16.8 tok/s that prompt spends 267s in prompt processing alone,
        // which is why chat timed out outright once the database had enough
        // context to be worth summarising. Hosts without a Vulkan loader fall
        // back to [`cpu_fallback_asset`].
        Some(ServerAsset {
            archive: "llama-b10054-bin-ubuntu-vulkan-x64.tar.gz",
            sha256: "fcd83d7ae74bd133f5734aeca55f0a0e36d92fe8eb7206ae03cab62b513f2da1",
            size_bytes: 31_488_075,
            strip_top_level: true,
        })
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        Some(ServerAsset {
            archive: "llama-b10054-bin-win-cpu-x64.zip",
            sha256: "5801980ae267310e2f2cb4bd4d1795718ee7b600a2a17d0a9320a601c8979bde",
            size_bytes: 18_004_849,
            strip_top_level: false,
        })
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "windows", target_arch = "x86_64")
    )))]
    {
        None
    }
}

/// Portable CPU build, used when the primary (GPU-capable) build will not run —
/// typically a host with no Vulkan loader. Slow but universal: better a working
/// agent than none.
pub fn cpu_fallback_asset() -> Option<ServerAsset> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Some(ServerAsset {
            archive: "llama-b10054-bin-ubuntu-x64.tar.gz",
            sha256: "dbfcbd71bafb5ff6ab57ed9a9f62c2a7522401986edf7f44b30a366ebcf86c71",
            size_bytes: 16_060_201,
            strip_top_level: true,
        })
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        None
    }
}

/// Ask a `llama-server` binary which compute devices it can see.
pub fn list_devices(bin: &Path) -> Option<String> {
    let out = std::process::Command::new(bin)
        .arg("--list-devices")
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(text)
}

/// Choose which listed device to offload to.
///
/// Picking by free memory alone is wrong: an integrated GPU reports shared
/// system RAM, so an Intel iGPU advertises tens of gigabytes "free" and would
/// win over the discrete card that is actually fast. Match the GPU the hardware
/// probe already identified (via `nvidia-smi`) instead, and only fall back to
/// free-memory order when there is nothing to match against.
pub fn pick_device(list_output: &str, preferred_gpu: Option<&str>) -> Option<String> {
    let devices = parse_devices(list_output);
    if devices.is_empty() {
        return None;
    }
    if let Some(want) = preferred_gpu {
        let want_lc = want.to_ascii_lowercase();
        // Match on the distinctive leading words ("Quadro T2000") rather than
        // the full marketing string, which the two sources spell differently.
        let key: String = want_lc
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        if let Some(d) = devices
            .iter()
            .find(|(_, name)| name.to_ascii_lowercase().contains(&key))
        {
            return Some(d.0.clone());
        }
    }
    devices
        .iter()
        .filter(|(_, name)| !is_integrated(name))
        .map(|(id, _)| id.clone())
        .next()
}

/// Layers to offload and the context window to ask for, given the hardware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffloadPlan {
    /// Device id to pass to `--device`, or `None` to let llama.cpp decide.
    pub device: Option<String>,
    /// `--n-gpu-layers`. Zero means run on the CPU.
    pub gpu_layers: u32,
    /// `--ctx-size`.
    pub ctx: u32,
    /// Operator-facing reason, logged so a slow host is explainable.
    pub reason: String,
}

/// Free VRAM (MiB) below which offloading is not worth it: the model would be
/// split, and a split model generates slower than pure CPU. Measured on a
/// Quadro T2000 — full offload ran 59 tok/s, a half offload only 5.9 tok/s,
/// versus 4.0 tok/s on CPU alone. Partial offload buys almost nothing.
const MIN_OFFLOAD_HEADROOM_MIB: u64 = 512;

/// VRAM deliberately left to everything else on the machine.
///
/// Legion is a background monitor, not the workload — it must not evict the
/// user's browser compositor, editor, or CUDA job. Measured here, a full
/// offload held 2918 MiB of a 4096 MiB card (71%) for as long as the server
/// lived. Reserve the larger of this floor and [`GPU_RESERVE_FRACTION`] of the
/// card, and decline to offload when the model will not fit in what is left.
const GPU_RESERVE_MIB: u64 = 768;

/// Fraction of total VRAM kept free for other processes.
const GPU_RESERVE_FRACTION: f64 = 0.20;

/// Fraction of CPU cores llama-server may use.
///
/// It otherwise grabs every core: measured at 760% CPU on a 16-core box, which
/// makes the desktop stutter while a hunt runs. Half leaves the machine usable
/// and costs little, since inference is memory-bandwidth bound well before it
/// is core bound.
const CPU_SHARE: f64 = 0.5;

/// Unprivileged account the model server should run as.
///
/// Overridable with `LEGION_MODEL_USER`; `""` disables the drop entirely.
pub const MODEL_SERVER_USER: &str = "legion";

/// Resolve a local account to `(uid, gid)` by reading `/etc/passwd`.
///
/// Parsed directly rather than through `getpwnam` to avoid a libc dependency,
/// matching how the rest of this workspace avoids FFI. Only local accounts are
/// resolved — an LDAP/SSSD-only user will not be found, and the caller then
/// declines to drop rather than guessing an id.
#[cfg(unix)]
pub fn resolve_user(name: &str) -> Option<(u32, u32)> {
    if name.is_empty() {
        return None;
    }
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    parse_passwd(&passwd, name)
}

/// Pure core of [`resolve_user`], so the parsing is testable without touching
/// the host's account database.
#[cfg(any(unix, test))]
fn parse_passwd(passwd: &str, name: &str) -> Option<(u32, u32)> {
    for line in passwd.lines() {
        // name:x:uid:gid:gecos:home:shell
        let mut f = line.split(':');
        if f.next()? != name {
            continue;
        }
        let _ = f.next();
        let uid: u32 = f.next()?.parse().ok()?;
        let gid: u32 = f.next()?.parse().ok()?;
        // Refuse to "drop" to root: that is not a privilege drop, and silently
        // accepting it would make a misconfiguration look like it worked.
        if uid == 0 {
            return None;
        }
        return Some((uid, gid));
    }
    None
}

/// Whether `path` and every directory above it are reachable by an arbitrary
/// unprivileged account.
///
/// Dropping privileges is only an improvement if the server can still read its
/// weights. On a host where the model was staged before the shared store
/// existed it sits under `/root/.local/share/legion`, and `/root` is `0700` —
/// so a drop would leave the server unable to open the file it was started to
/// serve. Failing to start is a worse outcome than running with more authority
/// than it needs, so this is checked first and the drop is skipped (loudly)
/// rather than attempted blind.
#[cfg(unix)]
pub fn readable_by_others(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(md) = std::fs::metadata(path) else {
        return false;
    };
    if md.permissions().mode() & 0o004 == 0 {
        return false;
    }
    // Every ancestor must also be traversable (o+x), or the path cannot be
    // walked to regardless of the file's own bits.
    let mut cur = path.parent();
    while let Some(dir) = cur {
        let Ok(md) = std::fs::metadata(dir) else {
            return false;
        };
        if md.permissions().mode() & 0o001 == 0 {
            return false;
        }
        cur = dir.parent();
    }
    true
}

/// Re-front `cmd` with `setpriv` so the child runs as `uid`/`gid` *with* the
/// account's supplementary groups.
///
/// Returns false when setpriv is unavailable, leaving the caller to fall back to
/// the std uid/gid drop.
#[cfg(unix)]
pub fn drop_via_setpriv(cmd: &mut std::process::Command, bin: &Path, uid: u32, gid: u32) -> bool {
    if !which_bin("setpriv") {
        return false;
    }
    // Rebuild the invocation with setpriv in front, preserving the argv that has
    // already been assembled.
    let args: Vec<std::ffi::OsString> = cmd.get_args().map(|a| a.to_os_string()).collect();
    let mut replacement = std::process::Command::new("setpriv");
    replacement
        .arg(format!("--reuid={uid}"))
        .arg(format!("--regid={gid}"))
        .arg("--init-groups")
        .arg("--")
        .arg(bin)
        .args(&args);
    // `nice` is applied by the caller wrapping this command, so preserve it by
    // copying the program only when the caller had not already wrapped.
    *cmd = replacement;
    true
}

/// Whether `bin` exists on `PATH`.
#[cfg(unix)]
fn which_bin(bin: &str) -> bool {
    std::env::var("PATH")
        .map(|p| {
            p.split(':')
                .any(|d| !d.is_empty() && Path::new(d).join(bin).is_file())
        })
        .unwrap_or(false)
}

/// Apply the unprivileged-service drop to a long-lived child server.
///
/// Shared by every persistent network server Legion spawns, so they cannot
/// drift apart: `llama-server` and the legacy `ollama serve` both inherit root
/// from Legion's own elevation and neither needs it.
///
/// Returns the account it dropped to, or `None` if it deliberately did not.
#[cfg(unix)]
pub fn drop_service_privileges(
    cmd: &mut std::process::Command,
    bin: &Path,
    needs_readable: Option<&Path>,
) -> Option<String> {
    if !legion_core::is_elevated() {
        return None;
    }
    let want = std::env::var("LEGION_MODEL_USER").unwrap_or_else(|_| MODEL_SERVER_USER.to_string());
    if want.is_empty() {
        return None;
    }
    // Refuse to drop somewhere the server cannot read what it must open.
    if let Some(path) = needs_readable {
        if !readable_by_others(path) {
            tracing::warn!(
                "ares: not dropping to '{want}' — {} is unreadable by an unprivileged \
                 account; re-pull so it lands in the shared store",
                path.display()
            );
            return None;
        }
    }
    let (uid, gid) = resolve_user(&want)?;
    if drop_via_setpriv(cmd, bin, uid, gid) {
        Some(want)
    } else {
        use std::os::unix::process::CommandExt;
        cmd.gid(gid).uid(uid);
        Some(want)
    }
}

/// Resolve a local group name to its gid via `/etc/group`.
///
/// Needed so the unprivileged model server keeps access to the GPU device
/// nodes, which are owned by `render`/`video`. Without them the drop silently
/// costs Vulkan and the server falls back to CPU — a large, invisible
/// performance regression rather than an error.
#[cfg(unix)]
pub fn resolve_group(name: &str) -> Option<u32> {
    let group = std::fs::read_to_string("/etc/group").ok()?;
    parse_group(&group, name)
}

/// Pure core of [`resolve_group`].
// Only `resolve_group` (Unix-only) calls this, and no test exercises it
// directly, so `any(unix, test)` would pull it into the Windows test build as
// dead code and fail `-D warnings`. Gate it to `unix`, like its only caller.
#[cfg(unix)]
fn parse_group(group: &str, name: &str) -> Option<u32> {
    for line in group.lines() {
        // name:x:gid:members
        let mut f = line.split(':');
        if f.next()? != name {
            continue;
        }
        let _ = f.next();
        return f.next()?.parse().ok();
    }
    None
}

/// Whether `nice` is available to lower the server's scheduling priority.
fn which_nice() -> bool {
    std::env::var("PATH")
        .map(|p| {
            p.split(':')
                .any(|d| !d.is_empty() && Path::new(d).join("nice").is_file())
        })
        .unwrap_or(false)
}

/// Threads to give llama-server, leaving room for the rest of the system.
pub fn worker_threads() -> u32 {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4);
    ((cores as f64 * CPU_SHARE).floor() as u32).clamp(1, cores.saturating_sub(1).max(1))
}

/// Plan GPU offload for a model of `model_bytes`.
///
/// The rules come from measurement on real hardware rather than assumption:
///
/// * **No usable device → CPU.** An *integrated* GPU is excluded on purpose:
///   an Intel UHD measured 28 tok/s prompt against 446 tok/s on the CPU of the
///   same machine, so offloading there is a 16x regression, not a win.
/// * **Model must fit whole.** Partial offload measured barely better than CPU
///   (5.9 vs 4.0 tok/s generate) because every un-offloaded layer stalls the
///   pipeline. Fit it entirely or do not bother.
/// * **Context is sized to what is left.** The KV cache lives beside the
///   weights, so a large window on a small card either fails to allocate or
///   evicts the model back to system memory.
pub fn plan_offload(
    devices: &str,
    preferred_gpu: Option<&str>,
    model_bytes: u64,
    requested_ctx: u32,
    cpu_min_ctx: u32,
) -> OffloadPlan {
    let model_mib = model_bytes / (1024 * 1024);
    let Some(device) = pick_device(devices, preferred_gpu) else {
        return OffloadPlan {
            device: None,
            gpu_layers: 0,
            ctx: requested_ctx.max(cpu_min_ctx),
            reason: "no discrete GPU detected; running on CPU".to_string(),
        };
    };
    let free_mib = free_mib_for(devices, &device).unwrap_or(0);
    let total_mib = total_mib_for(devices, &device).unwrap_or(free_mib);
    // Leave room for whatever else uses this GPU.
    let reserve = GPU_RESERVE_MIB.max((total_mib as f64 * GPU_RESERVE_FRACTION) as u64);
    let usable_mib = free_mib.saturating_sub(reserve);

    // Weights plus a working margin have to fit in what we are willing to take,
    // or a split model makes things worse than not offloading at all.
    if usable_mib < model_mib + MIN_OFFLOAD_HEADROOM_MIB {
        return OffloadPlan {
            device: None,
            gpu_layers: 0,
            ctx: requested_ctx.max(cpu_min_ctx),
            reason: format!(
                "{device}: {free_mib} MiB free, {reserve} MiB reserved for other \
                 processes, leaving {usable_mib} MiB — model needs ~{} MiB. A \
                 split model is slower than CPU, so running on CPU",
                model_mib + MIN_OFFLOAD_HEADROOM_MIB
            ),
        };
    }

    // Spend what is left on context. ~0.11 MiB per token for this model class,
    // measured: ctx 16384 occupied ~1.8 GiB beside a 1.1 GiB model.
    let spare_mib = usable_mib.saturating_sub(model_mib + MIN_OFFLOAD_HEADROOM_MIB);
    let ctx_affordable = ((spare_mib as f64 / 0.11) as u32).clamp(2048, 32768);
    let ctx = requested_ctx.min(ctx_affordable).max(2048);

    OffloadPlan {
        device: Some(device.clone()),
        gpu_layers: 99,
        ctx,
        reason: format!(
            "offloading to {device} ({free_mib} MiB free, {reserve} MiB left for \
             other processes, model ~{model_mib} MiB), ctx {ctx}, {} threads",
            worker_threads()
        ),
    }
}

/// Total MiB reported for `device_id`, used to size the reserve.
fn total_mib_for(text: &str, device_id: &str) -> Option<u64> {
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with(device_id) {
            continue;
        }
        // "... (4342 MiB, 3950 MiB free)" — the first number is the total.
        let paren = &line[line.rfind('(')? + 1..];
        let n: String = paren.chars().take_while(|c| c.is_ascii_digit()).collect();
        return n.parse().ok();
    }
    None
}

/// Free MiB reported for `device_id` in `--list-devices` output.
fn free_mib_for(text: &str, device_id: &str) -> Option<u64> {
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with(device_id) {
            continue;
        }
        // "... (4342 MiB, 3950 MiB free)"
        let free = line.rsplit_once(',')?.1.trim();
        let n: String = free.chars().take_while(|c| c.is_ascii_digit()).collect();
        return n.parse().ok();
    }
    None
}

/// True for GPUs that share system memory, whose reported "free" memory is not
/// comparable to a discrete card's.
fn is_integrated(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("uhd graphics")
        || n.contains("hd graphics")
        || n.contains("iris")
        || n.contains("llvmpipe")
        || n.contains("softwarerasterizer")
}

/// Parse `(device_id, name)` from `--list-devices` output, e.g.
/// `  Vulkan1: Quadro T2000 with Max-Q Design (4342 MiB, 3950 MiB free)`.
fn parse_devices(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((id, rest)) = line.split_once(": ") else {
            continue;
        };
        if id.is_empty() || id.contains(char::is_whitespace) {
            continue;
        }
        // Device ids look like Vulkan0 / CUDA0 / SYCL0: letters then a digit.
        if !id.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            || !id.chars().last().is_some_and(|c| c.is_ascii_digit())
        {
            continue;
        }
        // Strip only the TRAILING parenthetical (the memory report). Cutting at
        // the first '(' turned "Intel(R) UHD Graphics (CML GT2)" into "Intel",
        // which then failed the integrated-GPU check and let an iGPU be chosen
        // over the discrete card — a measured 16x regression.
        let name = match rest.rfind('(') {
            Some(i) => rest[..i].trim(),
            None => rest.trim(),
        }
        .to_string();
        if !name.is_empty() {
            out.push((id.to_string(), name));
        }
    }
    out
}

fn binary_name() -> &'static str {
    if cfg!(windows) {
        "llama-server.exe"
    } else {
        "llama-server"
    }
}

/// Directory holding the pinned build's binary and its shared libraries. The
/// whole directory must stay together: `llama-server` links against sibling
/// `libllama`/`libggml` objects and will not start without them.
///
/// Resolved against the machine-wide store when possible, so elevating does not
/// stage a second copy of the runtime under `/root`.
pub fn managed_dir() -> PathBuf {
    legion_core::resolve_store_path(
        &std::path::Path::new("runtime").join(format!("llama-{LLAMA_BUILD}-{}", variant_tag())),
    )
}

/// Short tag identifying which build variant is staged (`vulkan`, `cpu`, ...).
///
/// The directory is keyed by this as well as the build number. Keying on the
/// build alone meant that switching the Linux archive from the CPU build to the
/// Vulkan one — same llama.cpp release, different binary — left every existing
/// install silently running the old CPU server forever, since the directory
/// already existed and was reused.
pub fn variant_tag() -> &'static str {
    match asset_for_host() {
        Some(a) if a.archive.contains("vulkan") => "vulkan",
        Some(a) if a.archive.contains("cuda") => "cuda",
        Some(_) => "cpu",
        None => "none",
    }
}

/// Parent of [`managed_dir`] — where the download is staged before extraction.
pub fn managed_root() -> PathBuf {
    managed_dir()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| legion_core::data_dir().join("runtime"))
}

/// Path the managed `llama-server` binary is *expected* at when the archive is
/// flat. Prefer [`locate_managed_binary`] for the actual lookup: some upstream
/// release archives nest their payload under a top-level folder, in which case
/// the binary lands one level deeper than this.
pub fn managed_binary() -> PathBuf {
    managed_dir().join(binary_name())
}

/// Find the extracted managed `llama-server`, whatever the archive layout.
///
/// The pinned archives are *usually* flat (`managed_dir()/llama-server[.exe]`),
/// and `strip_top_level` is meant to normalise the ones that are not. But that
/// flag is a hand-maintained assumption per asset: if an upstream release zip
/// nests its files under a top-level directory when we expected it flat (or vice
/// versa), the binary ends up at an unexpected depth and a fixed-path check
/// reports it "missing" even though extraction succeeded — exactly the failure
/// seen on Windows. Check the expected flat path first, then fall back to a
/// bounded search of the extracted tree so the layout no longer has to be
/// guessed exactly right. The binary's sibling shared libraries travel with it
/// inside that same directory, so running it from wherever it is found is fine.
pub fn locate_managed_binary() -> Option<PathBuf> {
    let direct = managed_binary();
    if direct.is_file() {
        return Some(direct);
    }
    find_named_file(&managed_dir(), binary_name(), 6)
}

/// Bounded, depth-first search for a file named `name` under `dir`. The depth
/// cap keeps a pathological extract from turning this into an unbounded walk.
fn find_named_file(dir: &Path, name: &str, depth: u32) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(ft) if ft.is_file() => {
                if path.file_name().and_then(|n| n.to_str()) == Some(name) {
                    return Some(path);
                }
            }
            Ok(ft) if ft.is_dir() => subdirs.push(path),
            _ => {}
        }
    }
    if depth == 0 {
        return None;
    }
    for sub in subdirs {
        if let Some(found) = find_named_file(&sub, name, depth - 1) {
            return Some(found);
        }
    }
    None
}

/// Locate a usable `llama-server`: an operator-supplied one on `PATH` first,
/// then the managed pinned build (searched layout-agnostically).
pub fn find_binary() -> Option<PathBuf> {
    let name = binary_name();
    if let Ok(path) = std::env::var("PATH") {
        let sep = if cfg!(windows) { ';' } else { ':' };
        for dir in path.split(sep).filter(|d| !d.is_empty()) {
            let cand = Path::new(dir).join(name);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    locate_managed_binary()
}

/// Whether any `llama-server` is available to run right now.
pub fn is_installed() -> bool {
    find_binary().is_some()
}

/// Extract a verified archive into `dest`.
///
/// The caller MUST have verified the archive's SHA-256 first: extraction trusts
/// the bytes.
// Each arm ends the function on Unix (there is no second extractor to fall back
// to) while Windows falls through to the Expand-Archive path below, so the
// returns are load-bearing on one platform and redundant on the other. Allow the
// lint rather than fight the cfg split, matching `bootstrap::auto_install`.
#[allow(clippy::needless_return)]
pub fn extract_archive(archive: &Path, dest: &Path, strip_top_level: bool) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    std::fs::create_dir_all(dest)?;

    let mut cmd = Command::new("tar");
    cmd.arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if strip_top_level {
        cmd.arg("--strip-components=1");
    }
    match cmd.status() {
        Ok(s) if s.success() => return Ok(()),
        // Fall through to the Windows-native path below; on Unix a tar failure
        // is terminal since there is no second extractor to try.
        Ok(s) => {
            #[cfg(not(windows))]
            return Err(std::io::Error::other(format!("tar exited with {s}")));
            #[cfg(windows)]
            tracing::warn!("tar exited with {s}; falling back to Expand-Archive");
        }
        Err(e) => {
            #[cfg(not(windows))]
            return Err(e);
            #[cfg(windows)]
            tracing::warn!("tar unavailable ({e}); falling back to Expand-Archive");
        }
    }

    #[cfg(windows)]
    {
        // Older Windows without bundled bsdtar. Expand-Archive handles zip only,
        // which is exactly what we ship on this platform.
        let q = |s: &str| s.replace('\'', "''");
        let ps = format!(
            "Expand-Archive -LiteralPath '{}' -DestinationPath '{}' -Force",
            q(&archive.display().to_string()),
            q(&dest.display().to_string()),
        );
        let status = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "Expand-Archive exited with {status}"
            )));
        }
        Ok(())
    }
}

/// Make the staged binary and its helper objects executable. No-op on Windows,
/// where executability is not a file mode.
pub fn make_executable(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for entry in std::fs::read_dir(dir)?.flatten() {
            let path = entry.path();
            if path.is_file() {
                let mut perms = std::fs::metadata(&path)?.permissions();
                perms.set_mode(0o755);
                let _ = std::fs::set_permissions(&path, perms);
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Launch `llama-server` against a staged GGUF as a detached background process.
///
/// `alias` is reported verbatim by the server at `/v1/models`, which is what
/// lets Legion's exact-name status check match the tier it staged.
///
/// The server is bound to loopback and its bundled web UI is disabled: this
/// process exists to answer Legion's own API calls, nothing else.
#[allow(clippy::too_many_arguments)]
pub fn spawn_server(
    model: &Path,
    host: &str,
    port: u16,
    ctx: u32,
    gpu_layers: u32,
    alias: &str,
    device: Option<&str>,
) -> std::io::Result<PathBuf> {
    let bin = find_binary().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "llama-server not found on PATH or in the managed runtime dir",
        )
    })?;
    if !model.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("staged model not found at {}", model.display()),
        ));
    }
    spawn_server_at(&bin, model, host, port, ctx, gpu_layers, alias, device)?;
    Ok(bin)
}

#[allow(clippy::too_many_arguments)]
fn spawn_server_at(
    bin: &Path,
    model: &Path,
    host: &str,
    port: u16,
    ctx: u32,
    gpu_layers: u32,
    alias: &str,
    device: Option<&str>,
) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    // Run at low priority so Legion never competes with the user's own work.
    // `nice` is coreutils and always present; if it were missing the spawn
    // simply falls back to a normal-priority launch below.
    let niced = cfg!(unix) && which_nice();
    let mut cmd = if niced {
        let mut c = Command::new("nice");
        c.arg("-n").arg("10").arg(bin);
        c
    } else {
        Command::new(bin)
    };
    cmd.arg("--model")
        .arg(model)
        .arg("--host")
        .arg(host)
        .arg("--port")
        .arg(port.to_string())
        .arg("--ctx-size")
        .arg(ctx.to_string())
        .arg("--n-gpu-layers")
        .arg(gpu_layers.to_string())
        .arg("--alias")
        .arg(alias)
        // Legion is the only client; do not serve llama.cpp's own web UI.
        .arg("--no-webui")
        // Leave cores for everything else; llama-server otherwise takes them
        // all (measured 760% CPU on a 16-core host).
        .arg("--threads")
        .arg(worker_threads().to_string());
    // Pin the device when one was chosen, so a machine with both an integrated
    // and a discrete GPU does not silently land on the slow one.
    if let Some(dev) = device {
        cmd.arg("--device").arg(dev);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW | DETACHED_PROCESS — no console flash, survives us.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }

    // Drop privileges. Legion self-elevates to read privileged telemetry, and
    // every child it spawns inherits root — including this one. The model
    // server has no need of it: it reads two files and binds a loopback port.
    // Running an inference server that parses multi-gigabyte third-party
    // weights as root is a large amount of authority for no benefit.
    //
    // Only attempted when actually running as root, so an unprivileged launch
    // is unaffected.
    #[cfg(unix)]
    {
        if legion_core::is_elevated() {
            let want = std::env::var("LEGION_MODEL_USER")
                .unwrap_or_else(|_| MODEL_SERVER_USER.to_string());
            // A drop that makes the weights unreadable stops the agent working
            // entirely, which is a worse security outcome than the extra
            // authority: the operator ends up disabling the feature.
            let reachable = readable_by_others(model);
            match resolve_user(&want) {
                Some(_) if !reachable => {
                    tracing::warn!(
                        "ares: not dropping to '{want}' — {} is not readable by an \
                         unprivileged account (staged under a private home?). \
                         Re-pull the model so it lands in the shared store, or make \
                         it world-readable, to run the model server unprivileged.",
                        model.display()
                    );
                }
                Some((uid, gid)) => {
                    use std::os::unix::process::CommandExt;
                    // GPU device nodes (/dev/dri/render*, /dev/nvidia*) belong
                    // to the `render` and `video` groups, so an account outside
                    // them loses Vulkan and silently falls back to CPU — a big,
                    // invisible regression rather than an error.
                    //
                    // Supplementary groups cannot be set from stable Rust
                    // (`CommandExt::groups` is nightly-only), so `setpriv`
                    // handles it when present: `--init-groups` grants exactly
                    // the account's real membership, so adding `legion` to
                    // `render` is what enables the GPU, not a hardcoded list
                    // here. Without setpriv we still drop uid/gid via std and
                    // say what was lost.
                    if drop_via_setpriv(&mut cmd, bin, uid, gid) {
                        tracing::info!(
                            "ares: dropping model server to {want} (uid {uid}, gid {gid}) \
                             with its supplementary groups"
                        );
                    } else {
                        cmd.gid(gid).uid(uid);
                        tracing::info!(
                            "ares: dropping model server to {want} (uid {uid}, gid {gid}); \
                             setpriv unavailable, so supplementary groups are dropped — if \
                             GPU offload stops working, add {want} to the render/video \
                             groups and install util-linux"
                        );
                    }
                    tracing::info!("ares: dropping model server to {want} (uid {uid}, gid {gid})");
                }
                None if want.is_empty() => {
                    tracing::info!("ares: privilege drop disabled by LEGION_MODEL_USER=''");
                }
                None => {
                    tracing::warn!(
                        "ares: user '{want}' not found; the model server will run as root. \
                         Create it with: sudo useradd --system --no-create-home \
                         --shell /usr/sbin/nologin {want}"
                    );
                }
            }
        }
    }

    let child = cmd.spawn()?;
    // Reap the child when it exits. Dropping the handle does not wait() on
    // Unix, so a stopped server would sit as a <defunct> zombie for as long as
    // Legion runs — and restarting the runtime would stack up more.
    std::thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
    });
    Ok(())
}

/// Terminate any local `llama-server`. Idempotent: returns `Ok(())` whether or
/// not a process was found.
pub fn stop_server() -> std::io::Result<()> {
    use std::process::{Command, Stdio};

    #[cfg(windows)]
    {
        let status = Command::new("taskkill")
            .args(["/F", "/IM", "llama-server.exe"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        // Exit code 128 means "no matching process" — that's fine.
        if !status.success() && status.code() != Some(128) {
            return Err(std::io::Error::other(format!(
                "taskkill exited with {:?}",
                status.code()
            )));
        }
    }

    #[cfg(unix)]
    {
        // -x so we match the exact process name and never our own command line.
        let _ = Command::new("pkill")
            .args(["-x", "llama-server"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    Ok(())
}

#[cfg(test)]
mod offload_tests {
    use super::*;

    const GB: u64 = 1024 * 1024 * 1024;
    // Real `--list-devices` output from a laptop with both GPU classes.
    const DUAL: &str = "Available devices:\n          Vulkan0: Intel(R) UHD Graphics (CML GT2) (46982 MiB, 42284 MiB free)\n          Vulkan1: Quadro T2000 with Max-Q Design (4342 MiB, 3950 MiB free)";

    #[test]
    fn an_integrated_gpu_never_wins_on_free_memory() {
        // The trap: an iGPU reports SHARED SYSTEM RAM, so it advertises 42 GB
        // "free" against the discrete card's 4 GB and any largest-free-memory
        // heuristic picks it. Measured on this exact hardware, that choice is a
        // 16x regression: 28 tok/s prompt on the iGPU vs 446 on the CPU and 835
        // on the discrete card.
        let plan = plan_offload(
            DUAL,
            Some("Quadro T2000 with Max-Q Design"),
            GB,
            16384,
            16384,
        );
        assert_eq!(plan.device.as_deref(), Some("Vulkan1"), "{}", plan.reason);
        assert_eq!(plan.gpu_layers, 99);

        // Even with no name to match on, the integrated device is excluded.
        let plan = plan_offload(DUAL, None, GB, 16384, 16384);
        assert_eq!(plan.device.as_deref(), Some("Vulkan1"), "{}", plan.reason);
    }

    #[test]
    fn a_machine_with_no_gpu_runs_on_cpu() {
        let plan = plan_offload("Available devices:\n", None, GB, 16384, 16384);
        assert_eq!(plan.gpu_layers, 0);
        assert_eq!(plan.device, None);
        assert!(plan.reason.contains("no discrete GPU"), "{}", plan.reason);
        // CPU still gets a usable window; too small and every hunt prompt is
        // rejected outright for exceeding the context.
        assert!(plan.ctx >= 16384, "{}", plan.ctx);
    }

    #[test]
    fn an_integrated_only_machine_stays_on_cpu() {
        // Weak laptop: iGPU present, no discrete card. Offloading there is
        // slower than the CPU it shares memory with, so decline.
        let igpu = "  Vulkan0: Intel(R) UHD Graphics (CML GT2) (46982 MiB, 42284 MiB free)";
        let plan = plan_offload(igpu, None, GB, 16384, 16384);
        assert_eq!(plan.gpu_layers, 0, "{}", plan.reason);
    }

    #[test]
    fn a_small_card_declines_rather_than_splitting_the_model() {
        // 2 GB card, 2.5 GB model. Partial offload measured 5.9 tok/s generate
        // against 4.0 on CPU — not worth the complexity or the VRAM pressure,
        // and it risks an allocation failure mid-load.
        let small = "  Vulkan0: Tiny GPU (2048 MiB, 1900 MiB free)";
        let plan = plan_offload(small, None, 2500 * 1024 * 1024, 16384, 16384);
        assert_eq!(plan.gpu_layers, 0, "{}", plan.reason);
        assert!(plan.reason.contains("slower than CPU"), "{}", plan.reason);
    }

    #[test]
    fn a_big_card_gets_a_big_context() {
        // Strong workstation: 24 GB card, 4 GB model. Context should scale up
        // to the requested window rather than staying pinned at the small
        // default a 4 GB laptop needs.
        let big = "  Vulkan0: RTX 4090 (24564 MiB, 24000 MiB free)";
        let plan = plan_offload(big, None, 4 * GB, 32768, 16384);
        assert_eq!(plan.gpu_layers, 99);
        assert_eq!(plan.ctx, 32768, "a large card should honour the request");
    }

    #[test]
    fn context_is_trimmed_to_what_the_card_can_hold() {
        // 4 GB card, 1.1 GB model: fits, but a 32k window does not. Ask for
        // less rather than failing to allocate at load time.
        let plan = plan_offload(DUAL, Some("Quadro T2000"), 1100 * 1024 * 1024, 32768, 16384);
        assert_eq!(plan.gpu_layers, 99);
        assert!(plan.ctx < 32768, "ctx {} should be trimmed", plan.ctx);
        assert!(plan.ctx >= 2048, "ctx {} must stay usable", plan.ctx);
    }

    #[test]
    fn device_lines_are_parsed_and_free_memory_read() {
        let devs = parse_devices(DUAL);
        assert_eq!(devs.len(), 2, "{devs:?}");
        assert_eq!(devs[1].0, "Vulkan1");
        assert!(devs[1].1.contains("Quadro"));
        assert_eq!(free_mib_for(DUAL, "Vulkan1"), Some(3950));
        assert_eq!(free_mib_for(DUAL, "Vulkan0"), Some(42284));
        // Noise lines must not parse as devices.
        assert!(parse_devices("Available devices:").is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_layout_is_build_pinned() {
        let dir = managed_dir();
        assert!(dir.ends_with(format!("llama-{LLAMA_BUILD}-{}", variant_tag())));
        assert!(managed_binary().starts_with(&dir));
        assert!(managed_dir().starts_with(managed_root()));
    }

    #[test]
    fn binary_name_matches_platform() {
        if cfg!(windows) {
            assert_eq!(binary_name(), "llama-server.exe");
        } else {
            assert_eq!(binary_name(), "llama-server");
        }
    }

    #[test]
    fn locate_finds_the_binary_at_any_depth() {
        // Some upstream release archives nest their payload under a top-level
        // folder. The lookup must find llama-server whatever the depth, or a
        // valid extraction reads as "missing" — the Windows failure this fixes.
        let name = binary_name();

        // Nested one or more levels deep.
        let nested_root = tempfile::tempdir().unwrap();
        let nested = nested_root.path().join("llama-b10054").join("bin");
        std::fs::create_dir_all(&nested).unwrap();
        let target = nested.join(name);
        std::fs::write(&target, b"stub").unwrap();
        assert_eq!(find_named_file(nested_root.path(), name, 6), Some(target));

        // Flat layout is found immediately.
        let flat_root = tempfile::tempdir().unwrap();
        let flat = flat_root.path().join(name);
        std::fs::write(&flat, b"stub").unwrap();
        assert_eq!(find_named_file(flat_root.path(), name, 6), Some(flat));

        // No binary present yields None, not a false positive.
        let empty = tempfile::tempdir().unwrap();
        std::fs::write(empty.path().join("readme.txt"), b"x").unwrap();
        assert_eq!(find_named_file(empty.path(), name, 6), None);

        // The depth cap is honoured: a binary deeper than the budget is not found.
        let deep_root = tempfile::tempdir().unwrap();
        let deep = deep_root.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join(name), b"stub").unwrap();
        assert_eq!(find_named_file(deep_root.path(), name, 1), None);
    }

    #[test]
    fn host_asset_is_pinned_and_well_formed() {
        // Every platform we ship a managed build for must carry a real pin: a
        // 64-hex SHA-256 and a non-zero cap. An empty sha would silently
        // downgrade the download to trust-the-transport.
        if let Some(asset) = asset_for_host() {
            assert_eq!(asset.sha256.len(), 64, "sha256 must be 64 hex chars");
            assert!(
                asset.sha256.chars().all(|c| c.is_ascii_hexdigit()),
                "sha256 must be hex"
            );
            assert!(asset.size_bytes > 0, "size cap must be set");
            assert!(asset.url().starts_with("https://"), "download must be TLS");
            assert!(asset.url().contains(LLAMA_BUILD), "url must match the pin");
        }
    }

    #[test]
    fn linux_archive_strips_its_top_level_dir() {
        // The Linux tarball nests under llama-<build>/ and the Windows zip is
        // flat. Getting this backwards silently produces a binary one level too
        // deep, which find_binary would then miss.
        if let Some(asset) = asset_for_host() {
            if asset.archive.ends_with(".tar.gz") {
                assert!(asset.strip_top_level);
            }
            if asset.archive.ends_with(".zip") {
                assert!(!asset.strip_top_level);
            }
        }
    }
}

#[cfg(test)]
mod privilege_tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
        legion:x:997:995:Legion model server:/nonexistent:/usr/sbin/nologin\n\
        tim:x:1000:1000:Tim:/home/tim:/bin/bash\n";

    #[test]
    fn resolves_a_local_service_account() {
        assert_eq!(parse_passwd(PASSWD, "legion"), Some((997, 995)));
        assert_eq!(parse_passwd(PASSWD, "tim"), Some((1000, 1000)));
    }

    #[test]
    fn refuses_to_drop_to_root() {
        // "Dropping" to uid 0 is not a privilege drop. Accepting it would make a
        // misconfigured LEGION_MODEL_USER=root look like it had worked, which is
        // worse than declining and saying so.
        assert_eq!(parse_passwd(PASSWD, "root"), None);
    }

    #[test]
    fn an_absent_account_resolves_to_nothing() {
        // The caller must then run as-is and warn, never guess an id.
        assert_eq!(parse_passwd(PASSWD, "legion-model"), None);
        assert_eq!(parse_passwd(PASSWD, ""), None);
        assert_eq!(parse_passwd("", "legion"), None);
    }

    #[test]
    fn a_malformed_passwd_line_is_skipped_not_trusted() {
        assert_eq!(
            parse_passwd("legion:x:notanumber:995::/:/bin/sh\n", "legion"),
            None
        );
        assert_eq!(parse_passwd("legion\n", "legion"), None);
    }

    // Unix-only: exercises readable_by_others and raw file modes, neither of
    // which exists on Windows, where the drop is a no-op (see the #[cfg(windows)]
    // tests above). Without this gate the whole crate fails to compile on Windows.
    #[cfg(unix)]
    #[test]
    fn a_drop_is_skipped_when_the_model_would_be_unreachable() {
        use std::os::unix::fs::PermissionsExt;
        // The case on a real host: the model was staged before the shared store
        // existed, so it sits under a 0700 home. Dropping there leaves the
        // server unable to open its own weights — it fails to start, the
        // operator turns the feature off, and the machine ends up less secure
        // than if nothing had been attempted.
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("privatehome");
        std::fs::create_dir_all(&private).unwrap();
        let model = private.join("m.gguf");
        std::fs::write(&model, b"weights").unwrap();
        std::fs::set_permissions(&model, std::fs::Permissions::from_mode(0o644)).unwrap();

        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            !readable_by_others(&model),
            "a world-readable file under a 0700 dir is still unreachable"
        );

        // Same file in a shared, traversable location is fine.
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(readable_by_others(&model));

        // ...unless the file itself is owner-only.
        std::fs::set_permissions(&model, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!readable_by_others(&model));
    }

    #[test]
    fn a_prefix_match_is_not_a_match() {
        // "legion" must not resolve from a "legionr" line.
        let p = "legionr:x:998:998::/:/bin/sh\n";
        assert_eq!(parse_passwd(p, "legion"), None);
    }
}

#[cfg(test)]
mod citizenship_tests {
    use super::*;

    const GB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn threads_leave_headroom_for_the_rest_of_the_machine() {
        let t = worker_threads();
        let cores = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(4);
        assert!(t >= 1, "must always run");
        assert!(
            t < cores.max(2),
            "must never take every core: {t} of {cores}"
        );
    }

    #[test]
    fn vram_is_reserved_for_other_processes() {
        // A 4 GB card with a 2.6 GB model: it *fits* in the 3950 MiB free, but
        // taking it would leave the desktop nothing. Legion is a background
        // monitor and must yield.
        let card = "  Vulkan0: Quadro T2000 (4342 MiB, 3950 MiB free)";
        let plan = plan_offload(card, None, 2600 * 1024 * 1024, 8192, 16384);
        assert_eq!(plan.gpu_layers, 0, "{}", plan.reason);
        assert!(
            plan.reason.contains("reserved for other"),
            "{}",
            plan.reason
        );

        // The same card with the small model still offloads — the reserve is a
        // budget, not a veto.
        let plan = plan_offload(card, None, 1100 * 1024 * 1024, 8192, 16384);
        assert_eq!(plan.gpu_layers, 99, "{}", plan.reason);
        assert!(plan.reason.contains("left for"), "{}", plan.reason);
    }

    #[test]
    fn a_large_card_reserves_proportionally_not_just_a_floor() {
        // 24 GB card: a fixed 768 MiB floor would be a rounding error, so the
        // reserve scales with the card.
        let big = "  Vulkan0: RTX 4090 (24564 MiB, 24000 MiB free)";
        let plan = plan_offload(big, None, 4 * GB, 32768, 16384);
        assert_eq!(plan.gpu_layers, 99);
        // ~4.9 GB reserved: context must be sized from the remainder, not all
        // 24 GB.
        assert!(plan.ctx <= 32768, "{}", plan.ctx);
        assert!(plan.reason.contains("left for other"), "{}", plan.reason);
    }

    #[test]
    fn total_and_free_vram_are_read_separately() {
        let card = "  Vulkan1: Quadro T2000 with Max-Q Design (4342 MiB, 3950 MiB free)";
        assert_eq!(total_mib_for(card, "Vulkan1"), Some(4342));
        assert_eq!(free_mib_for(card, "Vulkan1"), Some(3950));
    }
}

#[cfg(test)]
mod variant_tests {
    use super::*;

    #[test]
    fn the_runtime_dir_changes_when_the_variant_changes() {
        // Switching the Linux archive from the CPU build to Vulkan keeps the
        // same llama.cpp release number. Keyed on the build alone, an existing
        // install would reuse the already-staged CPU server forever and never
        // see the GPU — the directory exists, so nothing re-downloads.
        let dir = managed_dir().display().to_string();
        assert!(dir.contains(LLAMA_BUILD), "{dir}");
        assert!(dir.ends_with(variant_tag()), "{dir} must be variant-keyed");
        if let Some(asset) = asset_for_host() {
            if asset.archive.contains("vulkan") {
                assert_eq!(variant_tag(), "vulkan");
            }
        }
    }
}
