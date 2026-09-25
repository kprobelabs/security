import argparse
import json
import sys
import time
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


def short(value, limit=500):
    value = value.replace("\r", "\\r").replace("\n", "\\n")
    if len(value) <= limit:
        return value
    return value[:limit] + "..."


def request(method, url, timeout, headers=None, form=None):
    headers = dict(headers or {})
    body = None
    if form is not None:
        body = urllib.parse.urlencode(form).encode()
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    headers.setdefault("Accept", "application/json")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return HttpResult(response.status, response.headers, response.read())
    except urllib.error.HTTPError as error:
        return HttpResult(error.code, error.headers, error.read())


def parse_json(result, label):
    try:
        return json.loads(result.text)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{label} returned invalid JSON: {error}: {short(result.text)}")


def api_headers(args, trigger=False):
    headers = {
        "Api-Key": args.api_key,
        "Api-Username": args.api_username,
    }
    if trigger:
        headers["X-Request-Start"] = args.request_start
    return headers


def topic_url(args):
    return f"{args.base_url}/t/{args.topic_id}.json"


def read_topic(args):
    result = request("GET", topic_url(args), args.timeout, headers=api_headers(args))
    if result.status < 200 or result.status >= 300:
        raise RuntimeError(f"topic read returned HTTP {result.status}: {short(result.text)}")
    data = parse_json(result, "topic read")
    title = data.get("title")
    if not title:
        raise RuntimeError(f"topic read response has no title: {short(result.text)}")
    return title, result


def update_topic(args, title, trigger):
    return request(
        "PUT",
        topic_url(args),
        args.timeout,
        headers=api_headers(args, trigger=trigger),
        form={"title": title},
    )


def validate_args(args, initial_title):
    if args.new_title == initial_title:
        raise RuntimeError("choose a new title that differs from the current topic title")
    if args.control_title == initial_title:
        raise RuntimeError("choose a control title that differs from the current topic title")
    if args.control_title == args.new_title:
        raise RuntimeError("control title and new title must differ")


def build_proof(args, initial_title, control_result, after_control, triggered_result, final_title):
    control_blocked = control_result.status >= 400
    control_unchanged = after_control == initial_title
    triggered_success = 200 <= triggered_result.status < 300
    triggered_changed = final_title == args.new_title
    return {
        "target": {
            "baseUrl": args.base_url,
            "topicId": args.topic_id,
            "apiUsername": args.api_username,
        },
        "initial": {
            "title": initial_title,
        },
        "controlWithoutHeader": {
            "httpStatus": control_result.status,
            "responsePreview": short(control_result.text),
            "titleAfterRequest": after_control,
            "blocked": control_blocked,
            "unchanged": control_unchanged,
        },
        "triggeredWithHeader": {
            "httpStatus": triggered_result.status,
            "responsePreview": short(triggered_result.text),
            "finalTitle": final_title,
            "success": triggered_success,
            "changed": triggered_changed,
        },
        "ok": control_blocked and control_unchanged and triggered_success and triggered_changed,
    }


def run(args):
    initial_title, _ = read_topic(args)
    validate_args(args, initial_title)
    control_result = update_topic(args, args.control_title, False)
    after_control, _ = read_topic(args)
    triggered_result = update_topic(args, args.new_title, True)
    final_title, _ = read_topic(args)
    return build_proof(args, initial_title, control_result, after_control, triggered_result, final_title)


def parse_args(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--api-username", default="admin")
    parser.add_argument("--topic-id", required=True, type=int)
    parser.add_argument("--new-title", required=True)
    parser.add_argument("--control-title")
    parser.add_argument("--request-start", default="t=0")
    parser.add_argument("--timeout", default=30.0, type=float)
    parser.add_argument("--output", default="proof.json")
    args = parser.parse_args(argv)
    args.base_url = clean_base(args.base_url)
    if args.control_title is None:
        args.control_title = f"blocked control title {int(time.time())}"
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
    return 0 if proof["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
