// server.js - reverse-proxy that rewrites a target site so it can be run inside an iframe
import express from "express";
import fetch from "node-fetch";
import * as cheerio from "cheerio";
import sanitizeHtml from "sanitize-html";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import { URL } from "url";
import path from "path";
import { fileURLToPath } from "url";
import stream from "stream";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// Config via env
const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || "")
  .split(",")
  .map(s => s.trim().toLowerCase())
  .filter(Boolean); // e.g. "example.com,duckduckgo.com"
const AUTH_TOKEN = (process.env.AUTH_TOKEN || "").trim(); // optional: require x-api-key header if set
const FETCH_TIMEOUT_MS = parseInt(process.env.FETCH_TIMEOUT_MS || "10000", 10);
const MAX_BYTES = parseInt(process.env.MAX_RESPONSE_BYTES || "7000000", 10); // 7MB

// Basic security middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.static(path.join(__dirname, "public"), { dotfiles: "ignore" }));
app.use(rateLimit({ windowMs: 60_000, max: 60 }));

// Optional auth
app.use((req, res, next) => {
  if (!AUTH_TOKEN) return next();
  const token = req.header("x-api-key") || req.query.api_key || "";
  if (!token || token !== AUTH_TOKEN) return res.status(401).send("Unauthorized");
  next();
});

// Helpers
function hostAllowed(hostname) {
  if (!hostname) return false;
  const hn = hostname.replace(/\.+$/, "").toLowerCase();
  // If no allowlist configured, deny (safe default).
  if (ALLOWED_HOSTS.length === 0) return false;
  if (ALLOWED_HOSTS.includes("*")) return true;
  return ALLOWED_HOSTS.some(a => {
    if (a === hn) return true;
    if (hn.endsWith("." + a)) return true;
    return false;
  });
}

function isHttpUrl(u) {
  try {
    const p = new URL(u);
    return p.protocol === "http:" || p.protocol === "https:";
  } catch { return false; }
}

async function fetchWithTimeout(url, opts = {}, timeout = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (e) {
    clearTimeout(id);
    throw e;
  }
}

// Binary passthrough for images/videos
app.get("/fetch", async (req, res) => {
  const target = req.query.u || req.query.url;
  if (!target || !isHttpUrl(target)) return res.status(400).send("Missing or invalid url param");
  // allow only hosts in allowlist
  try {
    const t = new URL(target);
    if (!hostAllowed(t.hostname)) return res.status(403).send("Host not allowed");
  } catch { return res.status(400).send("Bad URL"); }

  try {
    const upstream = await fetchWithTimeout(target, { headers: { "User-Agent": "site-iframe-proxy/1.0" } });
    const ct = upstream.headers.get("content-type") || "application/octet-stream";
    res.setHeader("content-type", ct);

    // stream body to client
    const readable = upstream.body;
    if (!readable) return res.status(502).send("No body");
    readable.pipe(res);
  } catch (err) {
    if (err.name === "AbortError") return res.status(504).send("Upstream timeout");
    console.error("fetch error", err && err.stack ? err.stack : err);
    return res.status(502).send("Upstream fetch failed");
  }
});

// Primary HTML rewriting route: /frame?u=<url-encoded>
app.get("/frame", async (req, res) => {
  const target = req.query.u;
  if (!target || !isHttpUrl(target)) return res.status(400).send("Missing or invalid u param");
  let upstreamUrl;
  try { upstreamUrl = new URL(target); } catch { return res.status(400).send("Invalid URL"); }

  // allowlist check
  if (!hostAllowed(upstreamUrl.hostname)) {
    return res.status(403).send("Host not allowed");
  }

  // fetch upstream HTML
  try {
    const upstream = await fetchWithTimeout(upstreamUrl.toString(), { headers: { "User-Agent": "site-iframe-proxy/1.0", "Accept": "*/*" } });
    const ct = upstream.headers.get("content-type") || "";
    if (!ct.includes("text/html")) {
      // non-HTML: redirect to binary passthrough
      return res.redirect(`/fetch?u=${encodeURIComponent(upstreamUrl.toString())}`);
    }

    let html = await upstream.text();

    // sanitize: strip scripts and event handlers
    html = sanitizeHtml(html, {
      allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img','header','main','section','footer','figure','figcaption']),
      allowedAttributes: {
        a: ['href','title','rel','target'],
        img: ['src','alt','width','height'],
        form: ['action','method'],
        input: ['type','name','value','placeholder'],
        '*': ['class','id','style']
      },
      allowedSchemes: ['http','https','data'],
      transformTags: {
        'a': (tagName, attribs) => {
          const href = attribs.href || "";
          // if relative or ddomain internal, resolve to upstream origin then proxify
          try {
            const resolved = new URL(href, upstreamUrl);
            if (resolved.protocol.startsWith("http")) {
              // only proxify if host allowed (so navigation stays inside)
              if (hostAllowed(resolved.hostname)) {
                // route internal links through /frame
                return { tagName: 'a', attribs: { href: `/frame?u=${encodeURIComponent(resolved.toString())}` } };
              } else {
                // external links open in new tab directly
                return { tagName: 'a', attribs: { href: resolved.toString(), target: '_blank', rel: 'noopener noreferrer' } };
              }
            }
          } catch {}
          return { tagName: 'a', attribs: { href: '#', rel: 'nofollow' } };
        }
      }
    });

    // cheerio for more detailed rewrites (images, forms, resources)
    const $ = cheerio.load(html, { decodeEntities: false });

    // remove script tags
    $('script').remove();

    // rewrite images to /fetch?u=
    $('img').each((i, el) => {
      const src = $(el).attr('src');
      if (!src) return;
      try {
        const u = new URL(src, upstreamUrl);
        if (hostAllowed(u.hostname)) {
          $(el).attr('src', `/fetch?u=${encodeURIComponent(u.toString())}`);
        } else {
          $(el).attr('src', u.toString());
        }
      } catch {}
    });

    // rewrite forms to submit via /frame
    $('form').each((i, f) => {
      const $f = $(f);
      let action = $f.attr('action') || upstreamUrl.pathname || '/';
      try {
        const resolved = new URL(action, upstreamUrl);
        if (hostAllowed(resolved.hostname)) {
          $f.attr('action', `/frame?u=${encodeURIComponent(resolved.toString())}`);
        } else {
          // point external forms to upstream URL directly (they will navigate away)
          $f.attr('action', resolved.toString());
          $f.attr('target', '_blank');
        }
        $f.attr('method', 'GET');
      } catch {
        $f.attr('action', `/frame?u=${encodeURIComponent(upstreamUrl.toString())}`);
        $f.attr('method', 'GET');
      }
    });

    // banner for clarity
    $('body').prepend(`<div style="padding:6px;background:#f3f4f6;border-bottom:1px solid #e5e7eb;font-family:system-ui,Arial,sans-serif;text-align:center;">Proxied: ${upstreamUrl.hostname}</div>`);

    const out = $.html();

    if (Buffer.byteLength(out, 'utf8') > MAX_BYTES) {
      return res.status(413).send("Proxied response too large");
    }

    // allow framing of proxied page (this response)
    res.removeHeader('X-Frame-Options');
    res.setHeader('Content-Security-Policy', "default-src 'self' data: https:; frame-ancestors 'self'");

    res.setHeader("content-type", "text/html; charset=utf-8");
    return res.send(out);
  } catch (err) {
    if (err.name === "AbortError") return res.status(504).send("Upstream timeout");
    console.error("frame error:", err && err.stack ? err.stack : err);
    return res.status(502).send("Upstream fetch failed");
  }
});

// convenience root UI: input a URL to load in iframe
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "frame-client.html"));
});

// simple health
app.get("/health", (req, res) => res.send("ok"));

app.listen(PORT, () => console.log(`Proxy listening on ${PORT}`));
