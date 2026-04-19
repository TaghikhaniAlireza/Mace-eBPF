use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(cbindgen)");

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
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())?;

    // Compile protobuf schemas at build time.
    prost_build::Config::new()
        .out_dir(env::var("OUT_DIR").context("OUT_DIR missing")?)
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

    if content.contains("aegis_arena_new(") {
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
