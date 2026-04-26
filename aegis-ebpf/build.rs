use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

/// Nested `cargo build` for `bpfel-unknown-none` breaks under Miri (no `RUSTC` for the child) and
/// under ASAN (`RUSTFLAGS` would try to link the BPF target with the host sanitizer runtime). In
/// those cases we reuse an eBPF binary produced by a normal `cargo build` of this crate.
fn use_prebuilt_ebpf_instead_of_nested_cargo() -> bool {
    if env::var_os("MIRI_SYSROOT").is_some() {
        return true;
    }
    if let Ok(out_dir) = env::var("OUT_DIR")
        && (out_dir.contains("/miri/") || out_dir.contains("\\miri\\"))
    {
        return true;
    }
    let rustflags_contain_asan = |s: &str| s.contains("sanitizer=address");
    if env::var("RUSTFLAGS")
        .map(|v| rustflags_contain_asan(&v))
        .unwrap_or(false)
    {
        return true;
    }
    if env::var("CARGO_ENCODED_RUSTFLAGS")
        .map(|v| rustflags_contain_asan(&v))
        .unwrap_or(false)
    {
        return true;
    }
    false
}

fn target_root_from_out_dir(out_dir: &Path) -> anyhow::Result<PathBuf> {
    out_dir
        .ancestors()
        .find(|p| p.file_name() == Some(OsStr::new("target")))
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            anyhow!(
                "OUT_DIR is not under a .../target/... directory: {}",
                out_dir.display()
            )
        })
}

fn copy_prebuilt_ebpf_program(out_dir: &Path) -> anyhow::Result<()> {
    let target_root = target_root_from_out_dir(out_dir)?;
    let build_roots = [
        target_root.join("debug/build"),
        target_root.join("release/build"),
    ];

    let mut artifact: Option<PathBuf> = None;
    'outer: for build_dir in build_roots {
        if !build_dir.is_dir() {
            continue;
        }
        let entries = match fs::read_dir(&build_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with("aegis-ebpf-")
            {
                continue;
            }
            let candidate = entry.path().join("out").join("aegis-ebpf");
            if candidate.is_file() {
                artifact = Some(candidate);
                break 'outer;
            }
        }
    }

    let src = artifact.ok_or_else(|| {
        anyhow!(
            "prebuilt eBPF program `aegis-ebpf` not found under {}/*/build/aegis-ebpf-*/out/; run `cargo build -p aegis-ebpf` (without Miri or ASAN) once",
            target_root.display()
        )
    })?;

    let dst = out_dir.join("aegis-ebpf");
    let _: u64 = fs::copy(&src, &dst)
        .with_context(|| format!("failed to copy {} to {}", src.display(), dst.display()))?;
    println!(
        "cargo:warning=Using prebuilt eBPF program from {} (Miri/ASAN or equivalent build)",
        src.display()
    );
    Ok(())
}

fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(cbindgen)");
    println!("cargo:rerun-if-env-changed=MIRI_SYSROOT");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "aegis-ebpf-ebpf")
        .ok_or_else(|| anyhow!("aegis-ebpf-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        features: &["ebpf-bin"],
        ..Default::default()
    };
    let out_dir = PathBuf::from(env::var("OUT_DIR").context("OUT_DIR missing")?);
    if use_prebuilt_ebpf_instead_of_nested_cargo() {
        copy_prebuilt_ebpf_program(&out_dir)?;
    } else {
        aya_build::build_ebpf([ebpf_package], Toolchain::default())?;
    }

    // Compile protobuf schemas at build time.
    prost_build::Config::new()
        .out_dir(out_dir)
        .compile_protos(&["proto/alert.proto"], &["proto/"])
        .context("failed to compile protos")?;

    // Generate C header via cbindgen.
    let crate_dir = env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?;
    let output_dir = PathBuf::from(&crate_dir).join("include");
    std::fs::create_dir_all(&output_dir).context("failed to create include directory")?;
    let header_path = output_dir.join("aegis.h");
    let config = match cbindgen::Config::from_file(PathBuf::from(&crate_dir).join("cbindgen.toml"))
    {
        Ok(config) => config,
        Err(err) => {
            println!("cargo:warning=failed to parse cbindgen.toml, using defaults: {err}");
            cbindgen::Config::default()
        }
    };
    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            bindings.write_to_file(&header_path);
            ensure_ffi_function_declarations(&header_path)?;
            println!(
                "cargo:warning=Generated C header: {}",
                header_path.display()
            );
        }
        Err(err) => {
            println!("cargo:warning=cbindgen skipped: {err}");
        }
    }

    // Rebuild when schema or binding config changes.
    println!("cargo:rerun-if-changed=proto/alert.proto");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src/ffi/");

    Ok(())
}

fn ensure_ffi_function_declarations(header_path: &Path) -> anyhow::Result<()> {
    let mut content =
        fs::read_to_string(header_path).context("failed to read generated C header")?;

    if content.contains("aegis_arena_new(")
        && content.contains("aegis_alert_channel_feed_test_alert(")
        && content.contains("aegis_simulate_jit_storm(")
        && content.contains("register_event_callback(")
        && content.contains("unregister_event_callback(")
        && content.contains("aegis_engine_init(")
        && content.contains("aegis_load_rules(")
        && content.contains("aegis_start_pipeline(")
    {
        return Ok(());
    }

    let declarations = r#"
#ifdef __cplusplus
extern "C" {
#endif

AegisArenaHandle *aegis_arena_new(size_t capacity);
void aegis_arena_free(AegisArenaHandle *handle);
int32_t aegis_arena_push(AegisArenaHandle *handle, const RawMemoryEvent *event);
int32_t aegis_arena_pop(AegisArenaHandle *handle, RawMemoryEvent *out_event);
int32_t aegis_arena_try_push(AegisArenaHandle *handle, const RawMemoryEvent *event);
int32_t aegis_arena_try_pop(AegisArenaHandle *handle, RawMemoryEvent *out_event);
size_t aegis_arena_len(const AegisArenaHandle *handle);
size_t aegis_arena_capacity(const AegisArenaHandle *handle);

AegisAlertChannelHandle *aegis_alert_channel_new(size_t capacity);
void aegis_alert_channel_free(AegisAlertChannelHandle *handle);
int32_t aegis_alert_channel_try_recv(AegisAlertChannelHandle *handle, uint8_t *out_buffer, size_t buffer_size);
int32_t aegis_alert_channel_recv(AegisAlertChannelHandle *handle, uint8_t *out_buffer, size_t buffer_size);
/* Test harness: inject maximal protobuf alert (see Rust aegis_alert_channel_feed_test_alert). */
int32_t aegis_alert_channel_feed_test_alert(AegisAlertChannelHandle *handle);

typedef struct JitStormStats {
  uint64_t requested;
  uint64_t pushed;
  uint64_t popped;
  uint64_t full_retries;
} JitStormStats;

int32_t aegis_simulate_jit_storm(AegisArenaHandle *handle, uint32_t count, JitStormStats *out_stats);

typedef void (*AegisJsonCallback)(const char *json_utf8);
void register_event_callback(AegisJsonCallback cb);
void unregister_event_callback(void);

int32_t aegis_engine_init(void);
int32_t aegis_load_rules(const char *yaml_utf8);
int32_t aegis_start_pipeline(void);
int32_t aegis_stop_pipeline(void);

#ifdef __cplusplus
} // extern "C"
#endif
"#;

    let footer = "#endif  /* AEGIS_EBPF_H */";
    if let Some(idx) = content.rfind(footer) {
        content.insert_str(idx, declarations);
    } else {
        content.push_str(declarations);
    }

    fs::write(header_path, content).context("failed to patch generated C header")?;
    println!("cargo:warning=Patched C header with explicit FFI declarations");
    Ok(())
}
