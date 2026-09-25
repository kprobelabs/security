use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = std::env::var("RUSTDESK_REPO_ROOT")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            manifest.ancestors().find_map(|ancestor| {
                for candidate in [ancestor.join("rustdesk"), ancestor.join("work").join("rustdesk")] {
                    if candidate.join("libs/hbb_common/protos/message.proto").exists() {
                        return Some(candidate);
                    }
                }
                None
            })
        })
        .expect("set RUSTDESK_REPO_ROOT or place this PoC near a rustdesk checkout")
        .join("libs")
        .join("hbb_common")
        .join("protos");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("protos");
    std::fs::create_dir_all(&out_dir).unwrap();

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(&out_dir)
        .inputs([
            repo_root.join("rendezvous.proto"),
            repo_root.join("message.proto"),
        ])
        .include(&repo_root)
        .customize(protobuf_codegen::Customize::default().tokio_bytes(true))
        .run()
        .expect("protobuf codegen failed");
}
