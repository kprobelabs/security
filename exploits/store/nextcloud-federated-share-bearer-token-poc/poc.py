import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


class HttpResult:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = dict(headers)
        self.body = body

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")


def clean_base(value):
    return value.rstrip("/")


def clean_path(value):
    if value.startswith("/"):
        return value
    return "/" + value


def short(value, limit=300):
    value = value.replace("\r", "\\r").replace("\n", "\\n")
    if len(value) <= limit:
        return value
    return value[:limit] + "..."


def auth_header(username, password):
    raw = f"{username}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def request(method, url, context, timeout, headers=None, form=None, username=None, password=None):
    headers = dict(headers or {})
    body = None
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    if username is not None:
        headers["Authorization"] = auth_header(username, password)
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=context, timeout=timeout) as response:
            return HttpResult(response.status, response.headers, response.read())
    except urllib.error.HTTPError as error:
        return HttpResult(error.code, error.headers, error.read())


def require_json(result, label):
    try:
        return json.loads(result.text)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{label} returned invalid JSON: {error}: {short(result.text)}")


def require_success(result, label):
    if result.status < 200 or result.status >= 300:
        raise RuntimeError(f"{label} returned HTTP {result.status}: {short(result.text)}")


def extract_ocs(result, label):
    require_success(result, label)
    data = require_json(result, label)
    if "ocs" not in data:
        raise RuntimeError(f"{label} response has no ocs envelope: {short(result.text)}")
    meta = data["ocs"].get("meta", {})
    statuscode = int(meta.get("statuscode", 0))
    if statuscode not in (100, 200):
        raise RuntimeError(f"{label} returned OCS {statuscode}: {meta.get('message', '')}")
    return data["ocs"].get("data"), meta


def create_share(args, context):
    share_with = args.share_with or f"{args.recipient_user}@{args.recipient_base}"
    return request(
        "POST",
        f"{args.sender_base}/ocs/v2.php/apps/files_sharing/api/v1/shares",
        context,
        args.timeout,
        headers={"OCS-APIREQUEST": "true", "Accept": "application/json"},
        form={
            "path": args.share_path,
            "shareType": "6",
            "shareWith": share_with,
            "permissions": str(args.permissions),
        },
        username=args.sender_user,
        password=args.sender_password,
    )


def pending_shares(args, context):
    return request(
        "GET",
        f"{args.recipient_base}/ocs/v2.php/apps/files_sharing/api/v1/remote_shares/pending",
        context,
        args.timeout,
        headers={"OCS-APIREQUEST": "true", "Accept": "application/json"},
        username=args.recipient_user,
        password=args.recipient_password,
    )


def select_share(shares, args):
    sender = args.sender_base.rstrip("/") + "/"
    matches = []
    for share in shares:
        if str(share.get("remote", "")).rstrip("/") + "/" != sender:
            continue
        if str(share.get("user", "")) != args.recipient_user:
            continue
        if str(share.get("name", "")) != args.share_path:
            continue
        if "refresh_token" in share and share["refresh_token"]:
            matches.append(share)
    if not matches:
        raise RuntimeError("no matching pending remote share with refresh_token was returned")
    return max(matches, key=lambda item: int(item.get("id", 0)))


def exchange_token(args, context, refresh_token):
    return request(
        "POST",
        f"{args.sender_base}{args.token_endpoint}",
        context,
        args.timeout,
        headers={"Accept": "application/json"},
        form={
            "grant_type": "authorization_code",
            "code": refresh_token,
        },
    )


def webdav_url(args, path):
    user = urllib.parse.quote(args.sender_user, safe="")
    target = urllib.parse.quote(path.lstrip("/"), safe="/")
    return f"{args.sender_base}/remote.php/dav/files/{user}/{target}"


def webdav_get(args, context, access_token):
    return request(
        "GET",
        webdav_url(args, args.proof_path),
        context,
        args.timeout,
        headers={"Authorization": f"Bearer {access_token}", "Accept": "*/*"},
    )


def webdav_root(args, context, access_token):
    user = urllib.parse.quote(args.sender_user, safe="")
    return request(
        "PROPFIND",
        f"{args.sender_base}/remote.php/dav/files/{user}/",
        context,
        args.timeout,
        headers={"Authorization": f"Bearer {access_token}", "Depth": "1"},
    )


def preview(value):
    if not value:
        return ""
    if len(value) <= 18:
        return value
    return value[:9] + "..." + value[-6:]


def run(args):
    context = ssl._create_unverified_context() if args.insecure else ssl.create_default_context()
    create_result = create_share(args, context)
    create_data, create_meta = extract_ocs(create_result, "create federated share")
    pending_result = pending_shares(args, context)
    pending_data, pending_meta = extract_ocs(pending_result, "recipient pending shares")
    selected = select_share(pending_data, args)
    refresh_token = selected["refresh_token"]
    exchange_result = exchange_token(args, context, refresh_token)
    require_success(exchange_result, "token exchange")
    exchange_data = require_json(exchange_result, "token exchange")
    access_token = exchange_data.get("access_token")
    if not access_token:
        raise RuntimeError(f"token exchange response has no access_token: {short(exchange_result.text)}")
    root_result = webdav_root(args, context, access_token)
    proof_result = webdav_get(args, context, access_token)
    require_success(proof_result, "proof WebDAV read")
    proof = {
        "senderBase": args.sender_base,
        "recipientBase": args.recipient_base,
        "sharePath": args.share_path,
        "proofPath": args.proof_path,
        "createShare": {
            "httpStatus": create_result.status,
            "ocsStatus": create_meta.get("statuscode"),
            "shareId": str(create_data.get("id", "")) if isinstance(create_data, dict) else "",
            "tokenPreview": preview(str(create_data.get("token", ""))) if isinstance(create_data, dict) else "",
        },
        "pendingShare": {
            "id": str(selected.get("id", "")),
            "remoteId": str(selected.get("remote_id", "")),
            "refreshTokenPreview": preview(refresh_token),
            "refreshTokenLength": len(refresh_token),
        },
        "tokenExchange": {
            "httpStatus": exchange_result.status,
            "tokenType": exchange_data.get("token_type"),
            "expiresIn": exchange_data.get("expires_in"),
            "accessTokenPreview": preview(access_token),
        },
        "webdavRoot": {
            "httpStatus": root_result.status,
            "bodyPreview": root_result.text[:500],
        },
        "webdavProof": {
            "httpStatus": proof_result.status,
            "xUserId": proof_result.headers.get("X-User-Id", ""),
            "contentLength": len(proof_result.body),
            "body": proof_result.text,
        },
    }
    return proof


def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--sender-base", required=True)
    parser.add_argument("--recipient-base", required=True)
    parser.add_argument("--sender-user", required=True)
    parser.add_argument("--sender-password", required=True)
    parser.add_argument("--recipient-user", required=True)
    parser.add_argument("--recipient-password", required=True)
    parser.add_argument("--share-path", default="/shared.txt")
    parser.add_argument("--proof-path", default="/secret.txt")
    parser.add_argument("--share-with")
    parser.add_argument("--permissions", type=int, default=1)
    parser.add_argument("--token-endpoint", default="/index.php/apps/cloud_federation_api/api/v1/access-token")
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--output", default="proof.json")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args(argv)
    args.sender_base = clean_base(args.sender_base)
    args.recipient_base = clean_base(args.recipient_base)
    args.share_path = clean_path(args.share_path)
    args.proof_path = clean_path(args.proof_path)
    if not args.token_endpoint.startswith("/"):
        args.token_endpoint = "/" + args.token_endpoint
    return args


def main(argv):
    args = parse_args(argv)
    try:
        proof = run(args)
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    text = json.dumps(proof, indent=2, sort_keys=True)
    if args.output == "-":
        print(text)
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
