# nghttp2 nghttpx HTTP/1.1 Upgrade Body Response Queue Poisoning PoC

This directory documents and validates an HTTP/1.1 Upgrade request body desynchronization in `nghttpx`, the reverse proxy shipped in the nghttp2 project.

`nghttpx` accepts an HTTP/1.1 Upgrade request carrying `Content-Length`, forwards the request header set to an HTTP/1.1 backend, and forwards the body bytes on the same backend connection. An Upgrade-aware backend can treat the message as an Upgrade attempt and leave bytes after the header terminator to be parsed as the next HTTP request. When `nghttpx` reuses that backend connection for another frontend client, the queued response to the attacker-supplied backend request can be delivered to the victim client.

The PoC uses a benign payload string, `SMUGGLED-BENIGN-PAYLOAD`, as the attacker-controlled response body. The exploit result is visible when a victim request for `/victim` receives this payload instead of the backend's normal `VICTIM-RESPONSE`.

Research status: verified locally end to end against a real `nghttpx` binary from nghttp2 `v1.69.0`, with a fixed-control run against upstream master.

## Affected Target

- Product: nghttp2
- Component: `nghttpx`
- Version analyzed: `v1.69.0`
- Release commit: `68cb6900fde14c77f0cd7add0e094a862960eb99`
- Fixed upstream commit: `ab28105c4a0197da24f8bfc414bc116055249e1e`
- Fixed commit title: `nghttpx: Tighten up CONNECT and HTTP Upgrade handling`
- Service surface: cleartext HTTP/1.1 frontend to HTTP/1.1 backend reverse proxying
- Impact: cross-client response queue poisoning through backend connection reuse

## Impact

An unauthenticated client can send a single crafted Upgrade request to place an attacker-chosen request into the backend HTTP/1.1 response queue. A subsequent client routed onto the same backend connection can receive the attacker's response.

In an application deployment, the primitive can be used to serve attacker-controlled same-origin content to another user, confuse application routing, poison an intermediate cache that trusts `nghttpx` response boundaries, or deliver a response belonging to an attacker-selected backend route under a victim request.

The local exploit demonstrates the queue poisoning directly:

```text
attacker request: GET /upgrade with Upgrade: websocket and a body containing GET /poisoned
attacker response: UPGRADE-REJECT
victim request: GET /victim
victim response: SMUGGLED-BENIGN-PAYLOAD
```

## Preconditions

- The attacker can connect to an `nghttpx` HTTP/1.1 frontend.
- `nghttpx` proxies to an HTTP/1.1 backend with reusable keep-alive connections.
- The backend applies Upgrade-oriented parsing behavior where bytes after an Upgrade request header terminator are interpreted as the next HTTP request rather than as an HTTP request body.
- The attacker can choose a backend route whose response can be delayed long enough for the next frontend request to be assigned to the same backend connection.

The PoC includes a small backend server that implements the relevant Upgrade behavior and response delay. The target process is the supplied real `nghttpx` binary.

## Root Cause

The vulnerable flow starts in the HTTP/1.1 frontend parser. An Upgrade request is accepted even when it carries `Content-Length`:

```text
GET /upgrade HTTP/1.1
Host: target
Connection: Upgrade
Upgrade: websocket
Content-Length: 43

GET /poisoned HTTP/1.1
Host: backend
```

The request is converted and forwarded to the backend through `HttpDownstreamConnection::push_request_headers()`. In `v1.69.0`, the backend request preserves both the Upgrade headers and the `Content-Length` header. The buffered frontend body is then copied into the backend request buffer by `HttpDownstreamConnection::process_blocked_request_buf()`.

Relevant source behavior in `v1.69.0`:

| File | Behavior |
| --- | --- |
| `src/shrpx_downstream.cc` | Marks non-h2c HTTP/1.1 Upgrade requests through `req_.upgrade_request` |
| `src/shrpx_https_upstream.cc` | Accepts an Upgrade request with `Content-Length` and dispatches it to a backend connection |
| `src/shrpx_http_downstream_connection.cc` | Forwards original request headers, including `Content-Length`, and forwards the buffered body |
| `src/shrpx_https_upstream.cc` | Detaches and reuses backend connections after response completion when the request state is complete |

The fixed upstream commit adds explicit rejection for `CONNECT` or Upgrade requests carrying `Transfer-Encoding` or `Content-Length`:

```text
transfer-encoding and content-length are not allowed in CONNECT or upgrade request
```

It also changes request body blocking around Upgrade handling so body bytes are held until the backend Upgrade response establishes a tunnel.

## Exploit Flow

1. The PoC starts a backend that keeps HTTP/1.1 connections alive.
2. The backend treats `Upgrade` as a boundary and parses bytes after the header terminator as another request.
3. The PoC starts the supplied `nghttpx` binary with a cleartext frontend and the local backend.
4. The attacker client sends `GET /upgrade` with `Upgrade: websocket` and `Content-Length`.
5. The attacker body contains a complete smuggled request: `GET /poisoned HTTP/1.1`.
6. `nghttpx` forwards the Upgrade request and the body to the backend.
7. The backend replies to `/upgrade` with `UPGRADE-REJECT`.
8. The backend parses `/poisoned` from the forwarded body and delays its response.
9. The attacker connection closes after receiving `UPGRADE-REJECT`.
10. The victim client sends `GET /victim`.
11. `nghttpx` reuses the same backend connection.
12. The delayed `/poisoned` response is read as the victim response.

## Files

- `poc.py` - stdlib-only Python exploit driver. It starts a real `nghttpx` target process, drives attacker and victim frontend clients, and prints a JSON result.
- `evidence/local-verification.txt` - local vulnerable and fixed-control transcripts.

## Usage

Build or provide an nghttp2 `v1.69.0` `nghttpx` binary, then run:

```bash
python3 poc.py --nghttpx ./build/src/nghttpx --cwd ./nghttp2-v1.69.0
```

Run with verbose protocol traces:

```bash
python3 poc.py --nghttpx ./build/src/nghttpx --cwd ./nghttp2-v1.69.0 --verbose
```

Run with a custom benign payload:

```bash
python3 poc.py --nghttpx ./build/src/nghttpx --cwd ./nghttp2-v1.69.0 --payload "BENIGN-QUEUE-POISON"
```

Expected vulnerable output:

```json
{
  "attacker_body": "UPGRADE-REJECT",
  "victim_body": "SMUGGLED-BENIGN-PAYLOAD",
  "victim_received_poison": true,
  "victim_received_expected": false
}
```

Run a fixed-control binary:

```bash
python3 poc.py --nghttpx ./build-fixed/src/nghttpx --cwd ./nghttp2-fixed --expect-fixed
```

Expected fixed-control output:

```json
{
  "attacker_body": "<html error body>",
  "victim_body": "VICTIM-RESPONSE",
  "victim_received_poison": false,
  "victim_received_expected": true
}
```

## Local Verification

The vulnerable run used `nghttpx nghttp2/1.69.0`. The fixed-control run used upstream master after `ab28105c`, reporting `nghttpx nghttp2/1.69.90`.

Vulnerable result:

```text
"attacker_body": "UPGRADE-REJECT"
"victim_body": "SMUGGLED-BENIGN-PAYLOAD"
"victim_received_poison": true
"victim_received_expected": false
"backend_requests": [
  [
    "GET /upgrade HTTP/1.1",
    "GET /poisoned HTTP/1.1",
    "GET /victim HTTP/1.1"
  ],
  []
]
```

Fixed-control result:

```text
"attacker_body": "<!DOCTYPE html><html lang=\"en\"><title>400 Bad Request</title><body><h1>400 Bad Request</h1><footer>nghttpx</footer></body></html>"
"victim_body": "VICTIM-RESPONSE"
"victim_received_poison": false
"victim_received_expected": true
"backend_requests": [
  [
    "GET /victim HTTP/1.1"
  ],
  []
]
```

## Patch Behavior

The upstream fix rejects the attacker request before backend dispatch:

```text
HTTP/1.1 400 Bad Request
Connection: close
```

The victim request then reaches the backend as the first request on a clean backend connection and receives the expected response.
