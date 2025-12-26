/**
 * Cloudflare Snippets - Emby Proxy (ultra minimal)
 * - Single user
 * - No origin whitelist
 * - No logs / no D1 / no admin
 */

const USER = "ikun"; // ←←← 只改这里

const MAX_FOLLOW_REDIRECTS = 1;

export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);

      // Root status
      if (url.pathname === "/" || url.pathname === "") {
        return text(USER ? "OK" : "FAIL", USER ? 200 : 500);
      }

      if (request.method === "OPTIONS") {
        return cors(new Response(null, { status: 204 }));
      }

      const parts = url.pathname.split("/").filter(Boolean);
      if (parts.length < 2) {
        return cors(text("Bad Request", 400));
      }

      // user check
      if (parts[0] !== USER) {
        return cors(text("Forbidden", 403));
      }

      const restPath = parts.slice(1).join("/");
      const upstreamUrl = parseUpstreamUrl(restPath, url.search);

      const method = request.method.toUpperCase();
      const headers = new Headers(request.headers);

      // hide client ip
      stripClientIpHeaders(headers);

      headers.delete("referer");
      headers.set("host", upstreamUrl.host);

      let resp = await fetch(new Request(upstreamUrl.toString(), {
        method,
        headers,
        redirect: "manual",
        body: method === "GET" || method === "HEAD" ? null : request.body,
      }));

      // minimal redirect follow
      if (isRedirect(resp.status) && MAX_FOLLOW_REDIRECTS > 0) {
        const loc = resp.headers.get("location");
        if (loc) {
          try {
            const nextUrl = new URL(loc, upstreamUrl);
            resp = await fetch(new Request(nextUrl.toString(), {
              method,
              headers,
              redirect: "manual",
            }));
          } catch {}
        }
      }

      return cors(stripSecurityHeaders(resp));
    } catch {
      return cors(text("FAIL", 500));
    }
  },
};

/* ---------- helpers ---------- */

function parseUpstreamUrl(path, search) {
  let p = path.replace(/^(https?):\/(?!\/)/, "$1://");
  if (!p.startsWith("http://") && !p.startsWith("https://")) {
    p = "https://" + p;
  }
  const u = new URL(p);
  if (search) u.search = search;
  return u;
}

function stripClientIpHeaders(h) {
  h.delete("x-forwarded-for");
  h.delete("x-real-ip");
  h.delete("cf-connecting-ip");
  h.delete("CF-Connecting-IP");
  h.delete("true-client-ip");
  h.delete("True-Client-IP");
}

function isRedirect(code) {
  return [301, 302, 303, 307, 308].includes(code);
}

function stripSecurityHeaders(resp) {
  const h = new Headers(resp.headers);
  h.delete("content-security-policy");
  h.delete("x-frame-options");
  h.delete("strict-transport-security");
  return new Response(resp.body, {
    status: resp.status,
    headers: h,
  });
}

function cors(resp) {
  const h = new Headers(resp.headers);
  h.set("access-control-allow-origin", "*");
  h.set("access-control-allow-methods", "*");
  h.set("access-control-allow-headers", "*");
  return new Response(resp.body, {
    status: resp.status,
    headers: h,
  });
}

function text(s, status) {
  return new Response(s, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}
