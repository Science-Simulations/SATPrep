// Simple passcode-locked web proxy. No dependencies. Needs Node 18+.
// Run:  PASSCODE=yourcode SECRET=somelongrandomstring node server.js

const http = require('http');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const { Readable } = require('stream');

const PORT = process.env.PORT || 3000;
const PASSCODE = process.env.PASSCODE || 'changeme';
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex');
const TITLE = process.env.TITLE || 'Private Access';
const SESSION_HOURS = 12;

// ---------- helpers ----------
const sha = (s) => crypto.createHash('sha256').update(s).digest();
const sign = (v) => crypto.createHmac('sha256', SECRET).update(v).digest('hex');

function makeSession() {
  const exp = Date.now() + SESSION_HOURS * 3600 * 1000;
  return `${exp}.${sign(String(exp))}`;
}
function validSession(req) {
  const m = /(?:^|;\s*)s=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return false;
  const [exp, sig] = m[1].split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const good = sign(exp);
  return sig.length === good.length &&
    crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good));
}
function passcodeOk(input) {
  return crypto.timingSafeEqual(sha(String(input)), sha(PASSCODE));
}

// basic brute-force limit: 8 tries / 10 min / IP
const attempts = new Map();
function tooMany(ip) {
  const now = Date.now();
  const a = (attempts.get(ip) || []).filter((t) => now - t < 600000);
  attempts.set(ip, a);
  return a.length >= 8;
}
function recordFail(ip) { attempts.get(ip).push(Date.now()); }

function readBody(req, limit = 5e6) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', (c) => { size += c.length; if (size > limit) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// block requests to private/internal addresses (SSRF protection)
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127);
  }
  const l = ip.toLowerCase();
  return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') ||
    l.startsWith('fe80') || l.startsWith('::ffff:');
}
async function assertPublic(hostname) {
  if (net.isIP(hostname)) { if (isPrivateIp(hostname)) throw new Error('blocked'); return; }
  const addrs = await dns.lookup(hostname, { all: true });
  if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) throw new Error('blocked');
}

const px = (u) => '/p?u=' + encodeURIComponent(u);
function absolute(raw, base) {
  try {
    if (/^(javascript:|data:|mailto:|tel:|#|blob:)/i.test(raw.trim())) return null;
    return new URL(raw.trim().replace(/&amp;/g, '&'), base).href;
  } catch { return null; }
}

function rewriteHtml(html, base) {
  html = html.replace(/(\s(?:href|src|action|poster)\s*=\s*)(["'])(.*?)\2/gi, (m, pre, q, val) => {
    const abs = absolute(val, base);
    return abs ? `${pre}${q}${px(abs)}${q}` : m;
  });
  html = html.replace(/(\ssrcset\s*=\s*)(["'])(.*?)\2/gi, (m, pre, q, val) => {
    const out = val.split(',').map((part) => {
      const [u, ...rest] = part.trim().split(/\s+/);
      const abs = absolute(u, base);
      return abs ? [px(abs), ...rest].join(' ') : part;
    }).join(', ');
    return `${pre}${q}${out}${q}`;
  });
  html = html.replace(/url\(\s*(["']?)(.*?)\1\s*\)/gi, (m, q, val) => {
    const abs = absolute(val, base);
    return abs ? `url(${q}${px(abs)}${q})` : m;
  });
  html = html.replace(/<meta[^>]+http-equiv=["']?refresh[^>]*>/gi, '');
  return html;
}
function rewriteCss(css, base) {
  return css.replace(/url\(\s*(["']?)(.*?)\1\s*\)/gi, (m, q, val) => {
    const abs = absolute(val, base);
    return abs ? `url(${q}${px(abs)}${q})` : m;
  });
}

// ---------- pages ----------
const page = (body) => `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${TITLE}</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0}
.card{background:#1e293b;padding:2rem;border-radius:14px;width:min(92vw,380px);box-shadow:0 10px 30px #0006}
h1{font-size:1.3rem;margin:0 0 1rem}input,button{width:100%;padding:.8rem;border-radius:8px;border:1px solid #475569;font-size:1rem;margin-top:.6rem}
input{background:#0f172a;color:#e2e8f0}button{background:#3b82f6;border:0;color:#fff;cursor:pointer;font-weight:600}
.err{color:#f87171;margin:.5rem 0 0;font-size:.9rem}
</style></head><body><div class="card">${body}</div></body></html>`;

const loginPage = (err) => page(`<h1>${TITLE}</h1>
<form method="POST" action="/login"><input type="password" name="code" placeholder="Passcode" autofocus required>
<button>Enter</button>${err ? `<p class="err">${err}</p>` : ''}</form>`);

// Edit this list to add/remove shortcuts: [label, address]
const SITES = {
  Games: [['Poki','poki.com'],['now.gg','now.gg'],['CrazyGames','crazygames.com'],['Coolmath Games','coolmathgames.com'],
    ['Chess.com','chess.com'],['itch.io','itch.io'],['Y8 Games','y8.com'],['Miniclip','miniclip.com'],
    ['1v1.LOL','1v1.lol'],['Nitro Type','nitrotype.com'],['Blooket','blooket.com'],['Kahoot','kahoot.it'],
    ['GeoGuessr','geoguessr.com'],['Lichess','lichess.org'],['Tetris','tetris.com'],['Wordle','nytimes.com/games/wordle'],
    ['Scratch','scratch.mit.edu']],
  Streaming: [['YouTube','youtube.com'],['Netflix','netflix.com'],['Hulu','hulu.com'],['Disney+','disneyplus.com'],
    ['Prime Video','primevideo.com'],['Tubi','tubitv.com'],['Twitch','twitch.tv'],['Spotify','open.spotify.com'],
    ['Pluto TV','pluto.tv'],['Apple Music','music.apple.com'],['Crunchyroll','crunchyroll.com'],['SoundCloud','soundcloud.com'],
    ['Peacock','peacocktv.com'],['Plex','watch.plex.tv']],
  AI: [['ChatGPT','chatgpt.com'],['Claude','claude.ai'],['Gemini','gemini.google.com'],['Perplexity','perplexity.ai']],
  Social: [['Reddit','reddit.com'],['X','x.com'],['Instagram','instagram.com'],['TikTok','tiktok.com'],
    ['Discord','discord.com'],['Pinterest','pinterest.com']],
  School: [['Khan Academy','khanacademy.org'],['Wikipedia','wikipedia.org'],['Quizlet','quizlet.com'],
    ['Desmos','desmos.com'],['Google Docs','docs.google.com'],['Duolingo','duolingo.com']],
  'Tools & News': [['Google','google.com'],['DuckDuckGo','duckduckgo.com'],['BBC News','bbc.com'],
    ['Weather','weather.com'],['GitHub','github.com']],
  Shopping: [['Amazon','amazon.com'],['eBay','ebay.com'],['Etsy','etsy.com'],['Walmart','walmart.com'],['Target','target.com']],
};
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
const hue = (s) => ([...s].reduce((a, c) => a + c.charCodeAt(0), 0) * 37) % 360;

const homePage = (err) => {
  const cats = Object.keys(SITES);
  const tabs = ['All', ...cats].map((c, i) =>
    `<button class="tab${i ? '' : ' on'}" data-c="${esc(c)}">${esc(c)}</button>`).join('');
  const sections = cats.map((c) => `<section data-c="${esc(c)}"><h2>${esc(c)}</h2><div class="grid">` +
    SITES[c].map(([name, addr]) => {
      const h = hue(name);
      return `<a class="tile" href="/go?q=${encodeURIComponent('https://' + addr)}">` +
        `<span class="ic" style="background:hsl(${h} 80% 90%);color:hsl(${h} 60% 35%)">${esc(name[0].toUpperCase())}</span>` +
        `<span><b>${esc(name)}</b><small>${esc(addr.split('/')[0])}</small></span></a>`;
    }).join('') + `</div></section>`).join('');

  return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(TITLE)}</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:system-ui,sans-serif;background:#07110b;color:#e2e8f0;padding:20px}
.wrap{max-width:1100px;margin:0 auto}h1{font-size:2rem;margin:.2rem 0}p.sub{color:#94a3b8;margin:0 0 16px}
form.s{display:flex;gap:8px;margin-bottom:16px}form.s input{flex:1;padding:.8rem;border-radius:10px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;font-size:1rem}
form.s button,.lock{padding:.8rem 1.2rem;border-radius:10px;border:0;background:#22c55e;color:#04120a;font-weight:700;cursor:pointer;font-size:1rem}
.tabs{display:flex;flex-wrap:wrap;gap:6px;background:#fff;padding:6px;border-radius:12px;width:fit-content;margin-bottom:8px}
.tab{border:0;background:none;padding:.5rem 1rem;border-radius:8px;font-weight:600;color:#64748b;cursor:pointer}
.tab.on{background:#0f172a;color:#fff}
h2{font-size:.75rem;letter-spacing:.12em;text-transform:uppercase;color:#94a3b8;margin:22px 0 8px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px}
.tile{display:flex;align-items:center;gap:12px;background:#fff;color:#0f172a;text-decoration:none;padding:12px;border-radius:12px;box-shadow:0 3px 0 #cbd5e1;transition:transform .08s}
.tile:hover{transform:translateY(-2px)}.tile b{display:block}.tile small{color:#64748b}
.ic{width:40px;height:40px;border-radius:10px;display:grid;place-items:center;font-weight:800;font-size:1.1rem;flex:none}
.err{color:#f87171}.foot{margin:28px 0;text-align:center}.foot form{display:inline}.lock{background:#334155;color:#e2e8f0}
</style></head><body><div class="wrap">
<h1>${esc(TITLE)}</h1><p class="sub">Pick a site, or type any address below.</p>
${err ? `<p class="err">${esc(err)}</p>` : ''}
<form class="s" method="GET" action="/go"><input name="q" placeholder="Enter a URL or search" required><button>Go</button></form>
<div class="tabs">${tabs}</div>${sections}
<div class="foot"><form method="POST" action="/logout"><button class="lock">Lock</button></form></div>
</div>
<script>
document.querySelectorAll('.tab').forEach(function(t){t.onclick=function(){
  document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('on')});t.classList.add('on');
  var c=t.dataset.c;document.querySelectorAll('section').forEach(function(s){s.style.display=(c==='All'||s.dataset.c===c)?'':'none'});
};});
</script></body></html>`;
};

// ---------- server ----------
const server = http.createServer(async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  const url = new URL(req.url, 'http://x');
  const send = (code, body, type = 'text/html; charset=utf-8', extra = {}) => {
    res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', ...extra });
    res.end(body);
  };

  try {
    if (url.pathname === '/login' && req.method === 'POST') {
      if (tooMany(ip)) return send(429, loginPage('Too many attempts. Try again later.'));
      const code = new URLSearchParams((await readBody(req, 1e4)).toString()).get('code') || '';
      if (passcodeOk(code)) {
        return send(302, '', 'text/plain', {
          'Set-Cookie': `s=${makeSession()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_HOURS * 3600}`,
          Location: '/',
        });
      }
      recordFail(ip);
      return send(401, loginPage('Incorrect passcode.'));
    }

    if (!validSession(req)) return send(200, loginPage());

    if (url.pathname === '/logout') {
      return send(302, '', 'text/plain', { 'Set-Cookie': 's=; Max-Age=0; Path=/', Location: '/' });
    }
    if (url.pathname === '/') return send(200, homePage());

    if (url.pathname === '/go') {
      let q = (url.searchParams.get('q') || '').trim();
      if (!/^https?:\/\//i.test(q)) {
        q = q.includes('.') && !q.includes(' ')
          ? 'https://' + q
          : 'https://duckduckgo.com/html/?q=' + encodeURIComponent(q);
      }
      return send(302, '', 'text/plain', { Location: px(q) });
    }

    if (url.pathname === '/p') {
      let target;
      try { target = new URL(url.searchParams.get('u')); } catch { return send(400, homePage('Invalid URL.')); }
      if (!/^https?:$/.test(target.protocol)) return send(400, homePage('Only http/https allowed.'));
      try { await assertPublic(target.hostname); } catch { return send(403, homePage('That address is blocked.')); }

      const headers = {
        'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0',
        'Accept': req.headers['accept'] || '*/*',
        'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
        'Accept-Encoding': 'identity',
      };
      const init = { method: req.method, headers, redirect: 'manual' };
      if (req.method === 'POST') {
        init.body = await readBody(req);
        headers['Content-Type'] = req.headers['content-type'] || 'application/x-www-form-urlencoded';
      }
      const up = await fetch(target.href, init);

      if (up.status >= 300 && up.status < 400 && up.headers.get('location')) {
        const next = absolute(up.headers.get('location'), target.href);
        return send(302, '', 'text/plain', { Location: next ? px(next) : '/' });
      }

      const type = up.headers.get('content-type') || 'application/octet-stream';
      const out = { 'Content-Type': type, 'Cache-Control': 'no-store' };
      if (/text\/html/i.test(type)) {
        res.writeHead(up.status, out);
        return res.end(rewriteHtml(await up.text(), target.href));
      }
      if (/text\/css/i.test(type)) {
        res.writeHead(up.status, out);
        return res.end(rewriteCss(await up.text(), target.href));
      }
      const len = up.headers.get('content-length');
      if (len) out['Content-Length'] = len;
      res.writeHead(up.status, out);
      return up.body ? Readable.fromWeb(up.body).pipe(res) : res.end();
    }

    send(404, homePage('Not found.'));
  } catch (e) {
    send(502, homePage('Could not load that page.'));
  }
});

server.listen(PORT, () => console.log(`Listening on :${PORT}`));
