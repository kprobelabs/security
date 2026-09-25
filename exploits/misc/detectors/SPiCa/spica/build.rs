use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;
use std::{fs, io::Read};

fn main() -> anyhow::Result<()> {
    // Generate a build-time XOR key and write it to both the eBPF crate and
    // the userspace crate's OUT_DIR. No runtime CONFIG map needed.
    let mut buf = [0u8; 8];
    fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    let base_key: u64 = u64::from_ne_bytes(buf);
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    fs::write(
        format!("{manifest_dir}/../spica-ebpf/src/generated_keys.rs"),
        format!("pub const BASE_KEY: u64 = {:#018x};\n", base_key),
    )?;
    let out_dir = std::env::var("OUT_DIR").unwrap();
    fs::write(
        format!("{out_dir}/keys.rs"),
        format!("const BASE_KEY: u64 = {:#018x};\n", base_key),
    )?;

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "spica-ebpf")
        .ok_or_else(|| anyhow!("spica-ebpf package not found"))?;
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
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
