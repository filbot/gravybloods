// Guest book API. Everything else on the site is static and served straight from
// the assets binding; only /api/* runs this code (see run_worker_first in wrangler.jsonc).

import { EmailMessage } from 'cloudflare:email';

const LIMITS = { name: 40, rides_from: 40, message: 500 };
const LINK = /https?:\/\/|www\.|<\s*a[\s>]|\[url|\.(com|net|org|ru|pl|es|de|nl|us|info|biz)\b/i;
const COOLDOWN_SECONDS = 60;
const PAGE_SIZE = 100;
// NOTIFY_TO must match destination_address on the send_email binding in wrangler.jsonc,
// and be a verified Email Routing destination. NOTIFY_FROM must be on gravybloods.com.
const NOTIFY_FROM = 'guestbook@gravybloods.com';
const NOTIFY_TO = 'filip@filbot.com';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname !== '/api/guestbook') return env.ASSETS.fetch(request);
    if (request.method === 'GET') return listEntries(env);
    if (request.method === 'POST') return signBook(request, env, ctx);
    return json({ error: 'Method not allowed.' }, 405, { Allow: 'GET, POST' });
  },
};

async function listEntries(env) {
  const { results } = await env.DB.prepare(
    'SELECT name, rides_from, message, created_at FROM entries ORDER BY id DESC LIMIT ?'
  ).bind(PAGE_SIZE).all();
  return json({ entries: results });
}

async function signBook(request, env, ctx) {
  let form;
  try {
    form = await request.formData();
  } catch {
    return json({ error: 'Bad request.' }, 400);
  }

  // Honeypot: the field is hidden from people, so anything in it came from a bot.
  // Pretend it worked so the bot has no reason to try again.
  if (field(form, 'website')) return json({ ok: true });

  const entry = {
    name: oneLine(field(form, 'name')),
    rides_from: oneLine(field(form, 'rides_from')),
    message: field(form, 'message'),
  };
  if (!entry.name || !entry.message) {
    return json({ error: 'Fill in your road name and a message.' }, 400);
  }
  for (const key in LIMITS) {
    if (entry[key].length > LIMITS[key]) return json({ error: 'That entry is too long.' }, 400);
  }
  if (LINK.test(entry.name + ' ' + entry.rides_from + ' ' + entry.message)) {
    return json({ error: 'No links in the guest book.' }, 400);
  }

  const ip = request.headers.get('CF-Connecting-IP') || '';
  if (!(await turnstileOk(field(form, 'cf-turnstile-response'), ip, env))) {
    return json({ error: 'Could not verify you are human. Reload and try again.' }, 403);
  }

  const ipHash = await sha256(ip + env.TURNSTILE_SECRET);
  const since = new Date(Date.now() - COOLDOWN_SECONDS * 1000).toISOString().slice(0, 19) + 'Z';
  const recent = await env.DB.prepare(
    'SELECT 1 FROM entries WHERE ip_hash = ? AND created_at > ? LIMIT 1'
  ).bind(ipHash, since).first();
  if (recent) return json({ error: 'Slow down, give it a minute before signing again.' }, 429);

  await env.DB.prepare(
    'INSERT INTO entries (name, rides_from, message, ip_hash) VALUES (?, ?, ?, ?)'
  ).bind(entry.name, entry.rides_from, entry.message, ipHash).run();
  // The entry is saved either way; a failed email only shows up in the Worker logs.
  ctx.waitUntil(notify(entry, env).catch((err) => console.error('notify failed', err)));
  return json({ ok: true }, 201);
}

async function turnstileOk(token, ip, env) {
  if (!token) return false;
  const body = new FormData();
  body.append('secret', env.TURNSTILE_SECRET);
  body.append('response', token);
  if (ip) body.append('remoteip', ip);
  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body,
  });
  const outcome = await res.json();
  return outcome.success === true;
}

async function notify(entry, env) {
  const signer = entry.name + (entry.rides_from ? ' from ' + entry.rides_from : '');
  const text = signer + ' signed the guest book:\n\n' + entry.message +
    '\n\nhttps://gravybloods.com/guestbook\n';
  const raw = [
    'From: Gravy Bloods Guest Book <' + NOTIFY_FROM + '>',
    'To: ' + NOTIFY_TO,
    'Subject: ' + encodeHeader('Guest book signed by ' + entry.name),
    'Date: ' + new Date().toUTCString(),
    'Message-ID: <' + crypto.randomUUID() + '@gravybloods.com>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    base64(text).replace(/.{76}/g, '$&\r\n'),
  ].join('\r\n');
  await env.NOTIFY.send(new EmailMessage(NOTIFY_FROM, NOTIFY_TO, raw));
}

// RFC 2047 encoding keeps visitor text from adding or breaking mail headers.
function encodeHeader(text) {
  return '=?UTF-8?B?' + base64(text) + '?=';
}

function base64(text) {
  let binary = '';
  for (const byte of new TextEncoder().encode(text)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function field(form, name) {
  const value = form.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

// Name and hometown are single-line inputs; bots can still send line breaks.
function oneLine(text) {
  return text.replace(/\s+/g, ' ');
}

async function sha256(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
  });
}
