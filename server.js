'use strict';
const cluster = require('node:cluster');
const os = require('node:os');
const http = require('node:http');
const { Readable } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const { fetch, Agent } = require('undici');

const PORT = Number(process.env.PORT || 3000);
const WORKERS = Number(process.env.WORKERS || (os.availableParallelism ? os.availableParallelism() : os.cpus().length));
const CACHE_MB = Number(process.env.CACHE_MB || 256);        // per worker
const MAX_ITEM = Number(process.env.MAX_ITEM_MB || 16) * 1024 * 1024;  // largest cacheable segment
const MAX_TEXT = 5 * 1024 * 1024;                            // largest buffered playlist/text
const MAX_SNIFF = 3 * 1024 * 1024;
const PLAYLIST_TTL = 3000;                                   // ms, keeps live playlists fresh
const SEGMENT_TTL = 5 * 60 * 1000;                           // ms
const LOAD_TIMEOUT = Number(process.env.LOAD_TIMEOUT || 20000);

// ---------- cluster: one process per core ----------
if (cluster.isPrimary && WORKERS > 1) {
  for (let i = 0; i < WORKERS; i++) cluster.fork();
  cluster.on('exit', (w) => {
    console.error(`[cluster] worker ${w.process.pid} died, restarting`);
    cluster.fork();
  });
  console.log(`Primary ${process.pid} running ${WORKERS} workers on :${PORT}`);
} else {
  startServer();
}

function startServer() {
  // ---------- pooled upstream connections ----------
  const dispatcher = new Agent({
    connections: 256,            // max sockets per origin per worker
    pipelining: 1,
    keepAliveTimeout: 30_000,
    keepAliveMaxTimeout: 600_000,
    headersTimeout: 15_000,      // waiting for upstream headers
    bodyTimeout: 30_000,         // idle time between body chunks (not total time)
    allowH2: process.env.UPSTREAM_H2 === '1',
    connect: { rejectUnauthorized: false, timeout: 10_000 },  // scoped TLS bypass
  });

  const UPSTREAM_HEADERS = {
    'Referer': 'https://cinejoy.pk/',
    'Origin': 'https://cinejoy.pk',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'identity',   // no decompression CPU, content-length stays valid
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'cross-site',
    'sec-ch-ua': '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
  };

  const CORS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Accept-Ranges, ETag, Last-Modified',
  };
  const PASS_THROUGH = [
    'content-type', 'content-length', 'content-range', 'accept-ranges',
    'etag', 'last-modified', 'cache-control', 'expires', 'content-disposition',
  ];

  // ---------- LRU cache bounded by bytes ----------
  class LruCache {
    constructor(maxBytes) { this.max = maxBytes; this.bytes = 0; this.map = new Map(); }
    get(k) {
      const e = this.map.get(k);
      if (!e) return null;
      if (e.exp < Date.now()) { this.delete(k); return null; }
      this.map.delete(k); this.map.set(k, e);          // bump recency
      return e;
    }
    set(k, e) {
      if (e.size > this.max) return;
      this.delete(k);
      this.map.set(k, e);
      this.bytes += e.size;
      for (const [key, v] of this.map) {               // evict oldest first
        if (this.bytes <= this.max) break;
        this.map.delete(key); this.bytes -= v.size;
      }
    }
    delete(k) {
      const e = this.map.get(k);
      if (e) { this.bytes -= e.size; this.map.delete(k); }
    }
  }
  const cache = new LruCache(CACHE_MB * 1024 * 1024);
  const inflight = new Map();   // key -> Promise<entry>  (request coalescing)

  // ---------- helpers ----------
  function rewritePlaylist(text, baseUrl, proxyBase) {
    const absolutize = (u) => { try { return proxyBase + new URL(u, baseUrl).href; } catch { return u; } };
    return text.split('\n').map((line) => {
      const t = line.trim();
      if (!t) return line;
      if (t.startsWith('#')) return line.replace(/URI="([^"]+)"/g, (_, uri) => `URI="${absolutize(uri)}"`);
      return absolutize(t);
    }).join('\n');
  }

  function passHeaders(up) {
    const out = {};
    const enc = up.headers.get('content-encoding');
    for (const h of PASS_THROUGH) {
      if (h === 'content-length' && enc && enc !== 'identity') continue;
      const v = up.headers.get(h);
      if (v !== null) out[h] = v;
    }
    if (!out['content-type']) out['content-type'] = 'application/octet-stream';
    return out;
  }

  // Cheap check so we never stringify multi-MB binary just to sniff it
  function sniffPlaylist(buf) {
    if (buf.length > MAX_SNIFF) return null;
    const head = buf.subarray(0, 64).toString('latin1');
    if (head.trim().startsWith('#EXTM3U')) return { text: buf.toString('utf8'), base64: false };
    if (/^[A-Za-z0-9+/=\s]+$/.test(head)) {
      const raw = buf.toString('latin1');
      if (/^[A-Za-z0-9+/=\s]+$/.test(raw.trim())) {
        const dec = Buffer.from(raw, 'base64').toString('utf8');
        if (dec.trim().startsWith('#EXTM3U')) return { text: dec, base64: true };
      }
    }
    return null;
  }

  function send(res, status, headers, body) {
    res.writeHead(status, { ...CORS, ...headers });
    res.end(body);
  }

  // ---------- shared loader (one upstream fetch, many waiters) ----------
  async function load(target, proxyBase) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), LOAD_TIMEOUT);
    try {
      const up = await fetch(target, {
        headers: UPSTREAM_HEADERS, redirect: 'follow', dispatcher, signal: ac.signal,
      });
      const finalUrl = up.url;

      if (finalUrl.includes('dontscrape')) {
        const body = Buffer.from(`Upstream blocked the request.\nFinal URL: ${finalUrl}\n`);
        return { status: 403, headers: { 'content-type': 'text/plain' }, body, size: body.length, exp: 0 };
      }

      const ct = up.headers.get('content-type') || '';
      const cl = Number(up.headers.get('content-length') ?? -1);
      const textLike = /\.m3u8(\?|$)/i.test(finalUrl) || ct.includes('mpegurl') || ct.startsWith('text/');
      const imgExt = /\.(jpe?g|png|gif)(\?|$)/i.test(target);
      const canBuffer = up.status !== 206 && !!up.body && (
        (textLike || imgExt || up.status >= 400)
          ? (cl === -1 || cl <= (imgExt ? MAX_ITEM : MAX_TEXT))
          : (cl >= 0 && cl <= MAX_ITEM)
      );

      // Too big / unknown length: hand the live response to the caller to stream
      if (!canBuffer) return { stream: true, up, ac };

      const buf = Buffer.from(await up.arrayBuffer());
      const headers = passHeaders(up);
      delete headers['content-length'];
      let body = buf;
      let isM3u8 = false;

      if (textLike || imgExt) {
        const sn = sniffPlaylist(buf);
        if (sn) {
          isM3u8 = true;
          let out = rewritePlaylist(sn.text, finalUrl, proxyBase);
          if (sn.base64) { out = Buffer.from(out).toString('base64'); }
          else headers['content-type'] = 'application/vnd.apple.mpegurl';
          body = Buffer.from(out);
        }
      }

      if (!headers['cache-control'] && up.status < 400) {
        headers['cache-control'] = isM3u8 ? 'public, max-age=5' : 'public, max-age=3600';
      }
      const ttl = up.status === 200 ? (isM3u8 ? PLAYLIST_TTL : SEGMENT_TTL) : 0;
      return { status: up.status, headers, body, size: body.length, exp: Date.now() + ttl };
    } finally {
      clearTimeout(timer);   // streaming stalls are covered by the Agent's bodyTimeout
    }
  }

  async function streamUpstream(res, up, ac, method) {
    res.on('close', () => { if (!res.writableEnded) ac.abort(); });  // free upstream when player leaves
    const headers = passHeaders(up);
    if (method === 'HEAD' || !up.body || up.status === 204 || up.status === 304) {
      send(res, up.status, headers);
      ac.abort();
      return;
    }
    res.writeHead(up.status, { ...CORS, ...headers });
    await pipeline(Readable.fromWeb(up.body), res);   // honors backpressure
  }

  async function direct(req, res, target) {
    const ac = new AbortController();
    const headers = { ...UPSTREAM_HEADERS };
    if (req.headers.range) headers['Range'] = req.headers.range;
    if (req.headers['if-range']) headers['If-Range'] = req.headers['if-range'];
    const isRead = req.method === 'GET' || req.method === 'HEAD';
    res.on('close', () => { if (!res.writableEnded) ac.abort(); });
    const opts = { method: req.method, headers, redirect: 'follow', dispatcher, signal: ac.signal };
    if (!isRead) { opts.body = Readable.toWeb(req); opts.duplex = 'half'; }
    const up = await fetch(target, opts);
    await streamUpstream(res, up, ac, req.method);
  }

  // ---------- server ----------
  const server = http.createServer(async (req, res) => {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { ...CORS, 'Access-Control-Max-Age': '86400' });
      return res.end();
    }

    let uri = req.url;
    try { if (uri.includes('%')) uri = decodeURIComponent(uri); } catch {}
    const pH = uri.indexOf('http://'), pS = uri.indexOf('https://');
    if (pH === -1 && pS === -1) {
      return send(res, 400, { 'content-type': 'text/plain' },
        'Invalid proxy usage. Format: https://your-domain.com/?t=https://target.com/path');
    }
    const target = uri.substring((pH !== -1 && (pS === -1 || pH < pS)) ? pH : pS);

    try {
      // Only plain GETs (no Range) can be cached/coalesced
      if (req.method === 'GET' && !req.headers.range) {
        const proto = (req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim();
        const proxyBase = `${proto}://${req.headers.host}/?t=`;
        const key = proxyBase + target;

        let entry = cache.get(key);
        let leader = false;
        if (!entry) {
          let p = inflight.get(key);
          if (!p) {
            leader = true;
            p = load(target, proxyBase).finally(() => inflight.delete(key));
            inflight.set(key, p);
          }
          entry = await p;
          if (!entry.stream && entry.exp > Date.now()) cache.set(key, entry);
        }

        if (entry.stream) {
          // Only the leader owns the live response; followers fetch their own stream
          if (leader) return await streamUpstream(res, entry.up, entry.ac, 'GET');
          return await direct(req, res, target);
        }
        return send(res, entry.status, { ...entry.headers, 'content-length': entry.size }, entry.body);
      }

      await direct(req, res, target);   // Range / HEAD / POST etc.
    } catch (err) {
      if (res.headersSent || res.destroyed) return res.destroy();
      console.error('[PROXY]', err.message);
      send(res, 502, { 'content-type': 'text/plain' }, 'Error: ' + err.message);
    }
  });

  server.keepAliveTimeout = 65_000;
  server.headersTimeout = 66_000;
  server.requestTimeout = 0;          // don't kill long video streams
  server.listen(PORT, () => console.log(`Worker ${process.pid} listening on :${PORT}`));
}
