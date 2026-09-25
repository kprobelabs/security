use std::process::Command;
use clap::Parser;
use anyhow::Context;

#[derive(Parser)]
struct Options {
    #[clap(subcommand)]
    command: CommandOpts,
}

#[derive(Parser)]
enum CommandOpts {
    /// Build the eBPF program
    BuildEbpf {
        /// Build for release (optimized)
        #[clap(long)]
        release: bool,
    },
    /// Generate vmlinux BTF bindings for the running kernel.
    /// Run this once before build-ebpf; output is gitignored (kernel-version-specific).
    GenerateVmlinux,
}

fn main() -> Result<(), anyhow::Error> {
    let opts = Options::parse();

    match opts.command {
        CommandOpts::BuildEbpf { release } => {
            let target = "bpfel-unknown-none";

            let mut args = vec![
                "build",
                "--package", "spica-ebpf",
                "--target", target,
                "-Z", "build-std=core",
            ];

            if release {
                args.push("--release");
            }

            let status = Command::new("cargo")
                .args(&args)
                .status()
                .context("Failed to run cargo build for eBPF")?;

            if !status.success() {
                anyhow::bail!("eBPF build failed");
            }

            println!("✨ eBPF Kernel Probe compiled successfully!");
            Ok(())
        }

        CommandOpts::GenerateVmlinux => {
            // aya-tool reads BTF from the running kernel (/sys/kernel/btf/vmlinux)
            // and generates Rust bindings for all kernel types.
            let out_path = "spica-ebpf/src/vmlinux.rs";

            let output = Command::new("aya-tool")
                .args(["generate", "task_struct"])
                .output()
                .context("Failed to run aya-tool. Install with: cargo install aya-tool")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("aya-tool failed: {}", stderr);
            }

            std::fs::write(out_path, &output.stdout)
                .with_context(|| format!("Failed to write {}", out_path))?;

            println!("✨ vmlinux bindings written to {}", out_path);
            Ok(())
        }
    }
}
