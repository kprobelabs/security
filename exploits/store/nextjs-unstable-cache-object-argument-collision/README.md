# Next.js unstable_cache object argument cache-key collision

This proof of concept demonstrates a stock Next.js application caching the first result returned from `unstable_cache()` when the cached function receives a request wrapper object as an argument. Later requests with different cookies, query values, or submitted form fields receive the first cached result.

The runner creates a temporary Next.js application, installs `next@16.3.0-canary.70`, builds it with `next build`, starts it with `next start`, and exercises three stock object types:

```text
Request
URLSearchParams
FormData
```

Each object can carry request-specific data, but `JSON.stringify()` serializes the object argument as:

```text
{}
```

The cached callback can still read the live object contents. The cache key therefore collapses multiple distinct invocations into one entry while the computed result still depends on the first invocation's contents.

## Demonstrated Flow

The generated application exposes three route handlers:

```text
/api/request
/api/urlsearch
/api/form
```

The request-object route passes the route handler `Request` object directly into `unstable_cache()`. The cached callback reads:

```text
request.headers.get('cookie')
request.url
JSON.stringify(request)
```

The query route passes a `URLSearchParams` object directly into `unstable_cache()`. The cached callback reads:

```text
searchParams.get('secret')
JSON.stringify(searchParams)
```

The form route passes a `FormData` object directly into `unstable_cache()`. The cached callback reads:

```text
formData.get('secret')
JSON.stringify(formData)
```

For each route, the runner sends two requests in the same cache group. The first request uses `alice`, and the second request uses `bob`.

Expected evidence for object arguments:

```text
REQ_COOKIE=victim=alice
URL_SECRET=alice
FORM_SECRET=alice
JSON={}
```

The second request receives the first result. Reverse-order checks use `bob` first and then `alice`, proving first-writer behavior.

The runner also exercises value-extraction controls. Those controls extract the primitive cookie, query value, or form field before calling `unstable_cache()`. The value controls return separate results for `alice` and `bob`.

After the first replay succeeds, the runner stops `next start`, starts it again without deleting the generated application, and sends `charlie` requests to the previously populated cache groups. The restarted server returns the earlier `alice` values from the Data Cache.

## Requirements

Run with:

```text
Node.js 20 or newer
npm
network access for npm install
```

The runner installs:

```text
next@16.3.0-canary.70
react@19.2.3
react-dom@19.2.3
```

Use a different Next.js version with:

```bash
node run_demo.mjs --next-version 16.3.0-canary.70
```

## Quick Run

From this directory:

```bash
node run_demo.mjs
```

Expected terminal evidence:

```text
next_version=16.3.0-canary.70
build_exit=0
requestObjectAliceBob=true
requestObjectBobAlice=true
requestValueControl=true
urlSearchAliceBob=true
urlSearchBobAlice=true
urlSearchValueControl=true
formDataAliceBob=true
formDataBobAlice=true
formDataValueControl=true
restartRequestObject=true
restartUrlSearch=true
restartFormData=true
confirmed=true
marker_file=<work-dir>/VULNERABILITY_CONFIRMED.marker
```

The marker file contains:

```text
confirmed=true
next_version=16.3.0-canary.70
request_object_second_seen=alice
urlsearch_second_seen=alice
formdata_second_seen=alice
restart_request_object_seen=alice
restart_urlsearch_seen=alice
restart_formdata_seen=alice
```

## Custom Work Directory

By default, the runner writes generated files under:

```text
run/stock-nextjs-unstable-cache
```

To choose another location:

```bash
node run_demo.mjs --work-dir /tmp/nextjs-unstable-cache-object-poc
```

To choose another port:

```bash
node run_demo.mjs --port 3561
```

## Generated Files

The runner writes:

```text
app/package.json
app/next.config.js
app/app/layout.jsx
app/app/page.jsx
app/app/api/request/route.js
app/app/api/urlsearch/route.js
app/app/api/form/route.js
app/.next/
app/node_modules/
logs/npm-install.stdout.log
logs/npm-install.stderr.log
logs/next-build.stdout.log
logs/next-build.stderr.log
logs/evidence.json
VULNERABILITY_CONFIRMED.marker
```

The repository folder contains only the source files required to reproduce the proof.

## Evidence Meaning

`requestObjectAliceBob=true` means the runner sent:

```text
Cookie: victim=alice
Cookie: victim=bob
```

to the same request-object cache group, and the second response still contained:

```text
REQ_COOKIE=victim=alice
JSON={}
```

`urlSearchAliceBob=true` means the runner sent:

```text
secret=alice
secret=bob
```

to the same `URLSearchParams` cache group, and the second response still contained:

```text
URL_SECRET=alice
JSON={}
```

`formDataAliceBob=true` means the runner submitted:

```text
secret=alice
secret=bob
```

to the same `FormData` cache group, and the second response still contained:

```text
FORM_SECRET=alice
JSON={}
```

`requestObjectBobAlice=true`, `urlSearchBobAlice=true`, and `formDataBobAlice=true` repeat the same proof with `bob` as the first writer.

`requestValueControl=true`, `urlSearchValueControl=true`, and `formDataValueControl=true` show that extracting a primitive value before calling `unstable_cache()` produces separate cache entries.

`restartRequestObject=true`, `restartUrlSearch=true`, and `restartFormData=true` show that the cached object-argument results are still returned after stopping and restarting `next start` while keeping the generated application directory.

`logs/evidence.json` contains every response body used for these checks.

## Cleanup

Remove the generated work directory:

```bash
rm -rf run/stock-nextjs-unstable-cache
```
