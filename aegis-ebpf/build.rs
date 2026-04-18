use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
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
        .out_dir(std::env::var("OUT_DIR").context("OUT_DIR missing")?)
        .compile_protos(&["proto/alert.proto"], &["proto/"])
        .context("failed to compile protos")?;

    // Rebuild when proto schema changes.
    println!("cargo:rerun-if-changed=proto/alert.proto");

    Ok(())
}
