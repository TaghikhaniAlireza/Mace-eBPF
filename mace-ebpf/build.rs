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
                .starts_with("mace-ebpf-")
            {
                continue;
            }
            let candidate = entry.path().join("out").join("mace-ebpf");
            if candidate.is_file() {
                artifact = Some(candidate);
                break 'outer;
            }
        }
    }

    let src = artifact.ok_or_else(|| {
        anyhow!(
            "prebuilt eBPF program `mace-ebpf` not found under {}/*/build/mace-ebpf-*/out/; run `cargo build -p mace-ebpf` (without Miri or ASAN) once",
            target_root.display()
        )
    })?;

    let dst = out_dir.join("mace-ebpf");
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
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "mace-ebpf-ebpf")
        .ok_or_else(|| anyhow!("mace-ebpf-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    println!("cargo:rerun-if-env-changed=MACE_EBPF_EXECVE_FULL_ARGV");
    println!("cargo:rerun-if-env-changed=MACE_EBPF_EXECVE_ARGV0_ONLY");
    println!("cargo:rerun-if-env-changed=MACE_EBPF_EXECVE_NO_USER_ARGV");

    let truthy = |v: &std::ffi::OsStr| {
        v == "1"
            || v.eq_ignore_ascii_case("true")
            || v.eq_ignore_ascii_case("yes")
            || v.eq_ignore_ascii_case("on")
    };

    let full_argv = env::var_os("MACE_EBPF_EXECVE_FULL_ARGV")
        .as_deref()
        .map(truthy)
        .unwrap_or(false);
    let argv0_only = env::var_os("MACE_EBPF_EXECVE_ARGV0_ONLY")
        .as_deref()
        .map(truthy)
        .unwrap_or(false);
    let no_user_argv = env::var_os("MACE_EBPF_EXECVE_NO_USER_ARGV")
        .as_deref()
        .map(truthy)
        .unwrap_or(false);

    if full_argv && (argv0_only || no_user_argv) {
        println!(
            "cargo:warning=MACE_EBPF_EXECVE_FULL_ARGV is set; ignoring argv0-only / no-user-argv flags"
        );
    }
    if argv0_only && no_user_argv && !full_argv {
        println!(
            "cargo:warning=MACE_EBPF_EXECVE_NO_USER_ARGV wins over MACE_EBPF_EXECVE_ARGV0_ONLY"
        );
    }

    // Default: `execve_no_user_argv` — strict kernels often reject `sys_enter_execve` when it
    // performs user-memory argv reads; rules still work via `/proc/<tgid>/cmdline` haystack.
    // Set `MACE_EBPF_EXECVE_FULL_ARGV=1` for full in-kernel argv capture on capable hosts.
    let ebpf_features: &[&str] = if full_argv {
        &["ebpf-bin"]
    } else if no_user_argv {
        &["ebpf-bin", "execve_no_user_argv"]
    } else if argv0_only {
        &["ebpf-bin", "execve_argv0_only"]
    } else {
        &["ebpf-bin", "execve_no_user_argv"]
    };

    if full_argv {
        println!(
            "cargo:warning=Building eBPF with MACE_EBPF_EXECVE_FULL_ARGV (full execve argv capture in kernel)"
        );
    } else if no_user_argv {
        println!(
            "cargo:warning=Building eBPF with MACE_EBPF_EXECVE_NO_USER_ARGV (execve enter skips user argv reads; header-only)"
        );
    } else if argv0_only {
        println!(
            "cargo:warning=Building eBPF with MACE_EBPF_EXECVE_ARGV0_ONLY (execve captures argv[0] only)"
        );
    } else {
        println!(
            "cargo:warning=Building eBPF with default execve argv policy (no user argv reads). Set MACE_EBPF_EXECVE_FULL_ARGV=1 for full kernel argv capture."
        );
    }

    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        features: ebpf_features,
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
    let header_path = output_dir.join("mace.h");
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

    if content.contains("mace_arena_new(")
        && content.contains("mace_alert_channel_feed_test_alert(")
        && content.contains("mace_simulate_jit_storm(")
        && content.contains("mace_register_event_callback(")
        && content.contains("mace_unregister_event_callback(")
        && content.contains("mace_engine_init(")
        && content.contains("mace_load_rules(")
        && content.contains("mace_load_rules_file(")
        && content.contains("mace_start_pipeline(")
        && content.contains("mace_set_log_level(")
        && content.contains("mace_allowlist_add_tgid(")
        && content.contains("mace_engine_health_json(")
        && content.contains("mace_engine_staged_rule_count(")
    {
        return Ok(());
    }

    let declarations = r#"
#ifdef __cplusplus
extern "C" {
#endif

MaceArenaHandle *mace_arena_new(size_t capacity);
void mace_arena_free(MaceArenaHandle *handle);
int32_t mace_arena_push(MaceArenaHandle *handle, const RawMemoryEvent *event);
int32_t mace_arena_pop(MaceArenaHandle *handle, RawMemoryEvent *out_event);
int32_t mace_arena_try_push(MaceArenaHandle *handle, const RawMemoryEvent *event);
int32_t mace_arena_try_pop(MaceArenaHandle *handle, RawMemoryEvent *out_event);
size_t mace_arena_len(const MaceArenaHandle *handle);
size_t mace_arena_capacity(const MaceArenaHandle *handle);

MaceAlertChannelHandle *mace_alert_channel_new(size_t capacity);
void mace_alert_channel_free(MaceAlertChannelHandle *handle);
int32_t mace_alert_channel_try_recv(MaceAlertChannelHandle *handle, uint8_t *out_buffer, size_t buffer_size);
int32_t mace_alert_channel_recv(MaceAlertChannelHandle *handle, uint8_t *out_buffer, size_t buffer_size);
/* Test harness: inject maximal protobuf alert (see Rust mace_alert_channel_feed_test_alert). */
int32_t mace_alert_channel_feed_test_alert(MaceAlertChannelHandle *handle);

typedef struct JitStormStats {
  uint64_t requested;
  uint64_t pushed;
  uint64_t popped;
  uint64_t full_retries;
} JitStormStats;

int32_t mace_simulate_jit_storm(MaceArenaHandle *handle, uint32_t count, JitStormStats *out_stats);

typedef void (*MaceJsonCallback)(const char *json_utf8);
void mace_register_event_callback(MaceJsonCallback cb);
void mace_unregister_event_callback(void);

int32_t mace_engine_init(void);
int32_t mace_load_rules(const char *yaml_utf8);
int32_t mace_load_rules_file(const char *path_utf8);
int32_t mace_start_pipeline(void);
int32_t mace_stop_pipeline(void);

/* Mace core stderr filter: 0=TRACE,1=INFO,2=SUPPRESSED,3=EVENT,4=ALERT. Returns 0 on success. */
int32_t mace_set_log_level(int32_t level);

int32_t mace_allowlist_add_tgid(uint32_t tgid);
int32_t mace_engine_health_json(char *out, size_t out_len);
uint64_t mace_engine_staged_rule_count(void);

#ifdef __cplusplus
} // extern "C"
#endif
"#;

    let footer = "#endif  /* MACE_EBPF_H */";
    if let Some(idx) = content.rfind(footer) {
        content.insert_str(idx, declarations);
    } else {
        content.push_str(declarations);
    }

    fs::write(header_path, content).context("failed to patch generated C header")?;
    println!("cargo:warning=Patched C header with explicit FFI declarations");
    Ok(())
}
