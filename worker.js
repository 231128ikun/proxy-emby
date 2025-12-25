let DB_INIT_PROMISE = null;

export default {
  async fetch(request, env, ctx) {
    try {
      if (!env.DB) return text("fail\n\n请绑定 D1，变量名必须叫 DB。", 500);

      await ensureDb(env);

      const url = new URL(request.url);
      const path = url.pathname;

      const users = getUsers(env);
      const whitelist = getWhitelist(env);

      // 根域名：不泄露 user 值
      if (path === "/") {
        const ok = users.length > 0 && whitelist.length > 0;
        return text(
          ok
            ? "success\n\n访问 /{user} 查看入口与白名单\n"
            : "fail\n\n请检查变量 USERS / WHITELIST 是否设置\n",
          ok ? 200 : 500
        );
      }

      const seg = path.split("/").filter(Boolean);
      if (seg.length === 0) return text("Not Found", 404);

      const user = seg[0];
      if (!users.includes(user)) return text("Forbidden (invalid user)", 403);

      // /{user} 页面
      if (seg.length === 1) {
        const [stats, logs] = await Promise.all([
          getRecentStats(env, 30),
          getRecentLogs(env, user, 120),
        ]);
        return html(renderPage({
          baseOrigin: url.origin,
          users,
          upstreams: whitelist,
          currentUser: user,
          stats,
          logs,
        }));
      }

      // 反代
      const restPath = "/" + seg.slice(1).join("/");

      let upstreamUrl;
      try {
        upstreamUrl = parseUpstreamUrl(restPath, url.search);
      } catch {
        ctx.waitUntil(logAndStat(env, request, {
          user, action: "deny", reason: "invalid_upstream",
          upstream_origin: null, status: 400,
          path: restPath
        }));
        return text("Bad Request (invalid upstream)", 400);
      }

      if (!new Set(whitelist).has(upstreamUrl.origin)) {
        ctx.waitUntil(logAndStat(env, request, {
          user, action: "deny", reason: "upstream_not_allowed",
          upstream_origin: upstreamUrl.origin, status: 403,
          path: upstreamUrl.pathname + upstreamUrl.search
        }));
        return text("Forbidden (upstream not allowed)", 403);
      }

      // WebSocket
      const upgrade = request.headers.get("Upgrade");
      if (upgrade && upgrade.toLowerCase() === "websocket") {
        const resp = await fetch(upstreamUrl.toString(), request);
        ctx.waitUntil(logAndStat(env, request, {
          user, action: "allow", reason: "websocket",
          upstream_origin: upstreamUrl.origin, status: resp.status,
          path: upstreamUrl.pathname + upstreamUrl.search
        }));
        return resp;
      }

      // HTTP 反代
      const headers = new Headers(request.headers);
      headers.set("Host", upstreamUrl.host);
      headers.delete("Referer");

      const clientIp = request.headers.get("cf-connecting-ip");
      if (clientIp) {
        headers.set("x-forwarded-for", clientIp);
        headers.set("x-real-ip", clientIp);
      }

      const upstreamReq = new Request(upstreamUrl.toString(), {
        method: request.method,
        headers,
        body: (request.method === "GET" || request.method === "HEAD") ? undefined : request.body,
        redirect: "follow",
      });

      let resp;
      try {
        resp = await fetch(upstreamReq);
      } catch (e) {
        ctx.waitUntil(logAndStat(env, request, {
          user, action: "error", reason: `fetch_failed:${String(e)}`,
          upstream_origin: upstreamUrl.origin, status: 502,
          path: upstreamUrl.pathname + upstreamUrl.search
        }));
        return text("Bad Gateway (upstream fetch failed)", 502);
      }

      ctx.waitUntil(logAndStat(env, request, {
        user, action: "allow", reason: "ok",
        upstream_origin: upstreamUrl.origin, status: resp.status,
        path: upstreamUrl.pathname + upstreamUrl.search
      }));

      return stripSomeHeaders(resp);

    } catch (e) {
      return text(`Worker error:\n${String(e?.stack || e)}`, 500);
    }
  }
};

/* 第一次运行自动建表（兼容：不用 exec，多条 prepare().run()） */
async function ensureDb(env) {
  if (DB_INIT_PROMISE) return DB_INIT_PROMISE;

  DB_INIT_PROMISE = (async () => {
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS proxy_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        date TEXT NOT NULL,
        user TEXT NOT NULL,
        upstream_origin TEXT,
        method TEXT,
        path TEXT,
        status INTEGER,
        action TEXT NOT NULL,
        reason TEXT,
        ip TEXT,
        ua TEXT,
        colo TEXT
      )
    `).run();

    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_proxy_logs_date ON proxy_logs(date)`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_proxy_logs_user ON proxy_logs(user)`).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS proxy_daily_stats (
        date TEXT PRIMARY KEY,
        total INTEGER NOT NULL DEFAULT 0,
        allow INTEGER NOT NULL DEFAULT 0,
        deny  INTEGER NOT NULL DEFAULT 0
      )
    `).run();
  })();

  return DB_INIT_PROMISE;
}

/* 解析 /https:/host:port/... 或 /https/host:port/... 或 /host:port/... */
function parseUpstreamUrl(restPath, search) {
  let p = restPath.startsWith("/") ? restPath.slice(1) : restPath;

  p = p.replace(/^(https?):\/(?!\/)/, "$1://");
  p = p.replace(/^(https?)\/(?!\/)/, "$1://");

  if (!p.startsWith("http://") && !p.startsWith("https://")) p = "https://" + p;

  const u = new URL(p);
  u.search = search || "";
  return u;
}

/* USERS: 例如 "ikun,abc123" */
function getUsers(env) {
  const list = splitList(env?.USERS || "");
  return list.length ? list : ["ikun"];
}

/* WHITELIST: 一行一个，支持端口，例如 https://emby.example.com:8096 */
function getWhitelist(env) {
  const raw = splitList(env?.WHITELIST || "");
  const out = [];
  for (const r of raw) {
    try {
      out.push(normalizeOrigin(r));
    } catch {}
  }
  return Array.from(new Set(out.filter(Boolean)));
}

function normalizeOrigin(x) {
  let s = String(x || "").trim();
  if (!s) return null;
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  return new URL(s).origin;
}

function splitList(s) {
  return String(s || "")
    .split(/[\n,;]+/)
    .map(x => x.trim())
    .filter(Boolean);
}

/* D1：写日志 + 按天统计 */
async function logAndStat(env, request, info) {
  await ensureDb(env);

  const ts = new Date().toISOString();
  const date = dayKST(ts);

  await bumpDaily(env.DB, date, "total");
  if (info.action === "allow") await bumpDaily(env.DB, date, "allow");
  if (info.action === "deny" || info.action === "error") await bumpDaily(env.DB, date, "deny");

  const ip = request.headers.get("cf-connecting-ip") || "";
  const ua = request.headers.get("user-agent") || "";
  const colo = request.cf?.colo || "";

  await env.DB.prepare(
    `INSERT INTO proxy_logs
     (ts, date, user, upstream_origin, method, path, status, action, reason, ip, ua, colo)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    ts, date, info.user, info.upstream_origin || null,
    request.method || null, info.path || null,
    info.status ?? null, info.action, info.reason || null,
    ip, ua, colo
  ).run();
}

async function bumpDaily(db, date, field) {
  if (!["total", "allow", "deny"].includes(field)) return;
  await db.prepare(
    `INSERT INTO proxy_daily_stats (date, ${field}) VALUES (?, 1)
     ON CONFLICT(date) DO UPDATE SET ${field} = ${field} + 1`
  ).bind(date).run();
}

async function getRecentStats(env, limit = 30) {
  await ensureDb(env);
  const { results } = await env.DB.prepare(
    "SELECT date, total, allow, deny FROM proxy_daily_stats ORDER BY date DESC LIMIT ?"
  ).bind(limit).all();
  return results || [];
}

async function getRecentLogs(env, user, limit = 120) {
  await ensureDb(env);
  const { results } = await env.DB.prepare(
    `SELECT ts, upstream_origin, method, path, status, action, reason, ip, ua, colo
     FROM proxy_logs
     WHERE user = ?
     ORDER BY id DESC
     LIMIT ?`
  ).bind(user, limit).all();
  return results || [];
}

function dayKST(isoTs) {
  return new Date(isoTs).toLocaleDateString("en-CA", { timeZone: "Asia/Seoul" });
}

/* 页面：生成入口链接（末尾不带 /） */
function renderPage({ baseOrigin, users, upstreams, currentUser, stats, logs }) {
  const sum7 = (stats || []).slice(0, 7).reduce((a, r) => {
    a.total += Number(r.total || 0);
    a.allow += Number(r.allow || 0);
    a.deny += Number(r.deny || 0);
    return a;
  }, { total: 0, allow: 0, deny: 0 });

  const maxTotal = Math.max(1, ...((stats || []).map(r => Number(r.total || 0))));

  return `<!doctype html><html lang="zh-CN"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Proxy • ${esc(currentUser)}</title>
<style>
:root{--bg:#0b1020;--card:rgba(17,24,54,.86);--bd:rgba(130,170,255,.18);--t:#e6e8ef;--m:#98a2c7}
*{box-sizing:border-box}
body{margin:0;color:var(--t);font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Helvetica,Arial;
background:radial-gradient(900px 500px at 15% 10%, rgba(122,162,255,.25), transparent 60%),
radial-gradient(900px 600px at 80% 0%, rgba(34,197,94,.16), transparent 55%),
linear-gradient(180deg,#0a1635,var(--bg));min-height:100vh}
header{position:sticky;top:0;backdrop-filter:blur(10px);background:rgba(11,16,32,.55);border-bottom:1px solid var(--bd)}
.top{max-width:1100px;margin:0 auto;padding:14px 18px;display:flex;justify-content:space-between;align-items:center;gap:12px}
.brand b{font-size:15px}.brand span{color:var(--m);font-size:12px}
.pill{border:1px solid var(--bd);background:rgba(17,24,54,.55);padding:8px 12px;border-radius:999px;color:var(--m);font-size:12px}
.wrap{max-width:1100px;margin:0 auto;padding:18px}
.grid{display:grid;grid-template-columns:1.1fr .9fr;gap:14px}@media(max-width:980px){.grid{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--bd);border-radius:18px;padding:14px;box-shadow:0 20px 60px rgba(0,0,0,.35)}
h3{margin:0 0 10px 0;font-size:14px}.muted{color:var(--m);font-size:12px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
select,button{font:inherit;border-radius:14px;border:1px solid var(--bd);background:rgba(8,12,28,.65);color:var(--t);padding:10px 12px;outline:none}
select{min-width:220px}
button{cursor:pointer;background:linear-gradient(135deg, rgba(122,162,255,.35), rgba(122,162,255,.12))}
button:hover{filter:brightness(1.05)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}
.output{margin-top:10px;padding:12px;border-radius:14px;border:1px dashed rgba(122,162,255,.35);background:rgba(8,12,28,.45);word-break:break-all}
.barrow{display:flex;align-items:center;gap:10px;margin:8px 0}
.bar{flex:1;height:10px;border-radius:999px;background:rgba(122,162,255,.12);overflow:hidden;border:1px solid rgba(122,162,255,.14)}
.bar i{display:block;height:100%;background:linear-gradient(90deg, rgba(122,162,255,.85), rgba(122,162,255,.25))}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{padding:10px 8px;border-bottom:1px solid rgba(130,170,255,.12);vertical-align:top}
th{color:var(--m);font-weight:600;text-align:left}
.tag{display:inline-flex;align-items:center;padding:3px 8px;border-radius:999px;border:1px solid rgba(130,170,255,.18);color:var(--m);background:rgba(8,12,28,.35);font-size:11px}
.tag.good{border-color:rgba(34,197,94,.25);color:rgba(34,197,94,.95)}
.tag.bad{border-color:rgba(239,68,68,.25);color:rgba(239,68,68,.95)}
.small{font-size:11px;color:var(--m)}.hr{height:1px;background:rgba(130,170,255,.12);margin:12px 0}
</style></head><body>
<header><div class="top">
<div class="brand"><b>Emby Proxy Gateway</b><span>只允许 /{user} + 白名单 origin（支持端口）</span></div>
<div class="pill mono">${esc(baseOrigin)}</div>
</div></header>

<div class="wrap">
<div class="grid">
  <div class="card">
    <h3>生成入口（末尾不带 /）</h3>
    <div class="muted">示例：<span class="mono">${esc(baseOrigin)}/你的user/https:/emby.example.com:8096</span></div>
    <div class="hr"></div>
    <div class="row">
      <div><div class="muted">user</div>
        <select id="selUser">${users.map(u=>`<option ${u===currentUser?"selected":""} value="${esc(u)}">${esc(u)}</option>`).join("")}</select>
      </div>
      <div style="flex:1;min-width:280px"><div class="muted">whitelist origin（含端口）</div>
        <select id="selUp" style="width:100%">${upstreams.map(u=>`<option value="${esc(u)}">${esc(u)}</option>`).join("")}</select>
      </div>
      <div><div class="muted">&nbsp;</div><button onclick="gen()">生成</button></div>
    </div>
    <div class="output mono" id="out"></div>
    <div class="row" style="margin-top:10px"><button onclick="copy()">复制链接</button><span class="small" id="msg"></span></div>
    <div class="small" style="margin-top:10px;color:var(--m)">最近 7 天：total ${sum7.total} / allow ${sum7.allow} / deny ${sum7.deny}</div>
  </div>

  <div class="card">
    <h3>近 30 天统计</h3><div class="muted">按天：total / allow / deny</div><div class="hr"></div>
    ${(stats && stats.length) ? stats.slice(0,30).map(r=>{
      const w=Math.round((Number(r.total||0)/maxTotal)*100);
      return `<div class="barrow"><span class="mono small" style="width:92px">${esc(r.date)}</span>
      <div class="bar"><i style="width:${w}%"></i></div>
      <span class="mono small" style="width:170px;text-align:right">t=${esc(r.total)} a=${esc(r.allow)} d=${esc(r.deny)}</span></div>`;
    }).join("") : `<div class="muted">暂无统计</div>`}
  </div>
</div>

<div class="card" style="margin-top:14px">
  <h3>最近日志（当前 user：${esc(currentUser)}）</h3>
  <div class="muted">最多 120 条</div><div class="hr"></div>
  ${(logs && logs.length) ? `<div style="overflow:auto"><table><thead><tr>
  <th style="min-width:160px">时间</th><th style="min-width:120px">结果</th><th style="min-width:260px">Upstream</th>
  <th style="min-width:220px">客户端</th><th style="min-width:220px">请求</th></tr></thead><tbody>
  ${logs.map(l=>{
    const good=l.action==="allow"; const tag=good?"good":"bad";
    const ua=String(l.ua||"").slice(0,70);
    const reqLine=`${l.method||""} ${String(l.path||"").slice(0,120)}`;
    return `<tr><td class="mono">${esc(l.ts)}</td><td>
      <span class="tag ${tag}">${esc(l.action)} ${esc(l.status??"")}</span>
      ${l.reason?`<div class="small">reason: ${esc(l.reason)}</div>`:""}
      <div class="small">ip: <span class="mono">${esc(l.ip||"-")}</span> • colo: <span class="mono">${esc(l.colo||"-")}</span></div>
    </td><td class="mono">${esc(l.upstream_origin||"-")}</td><td class="mono">${esc(ua||"-")}</td><td class="mono">${esc(reqLine)}</td></tr>`;
  }).join("")}
  </tbody></table></div>` : `<div class="muted">暂无日志</div>`}
</div>

</div>

<script>
function gen(){
  const base=${JSON.stringify(baseOrigin)};
  const user=document.getElementById('selUser').value;
  const up=document.getElementById('selUp').value;
  const u=new URL(up);
  const proto=u.protocol.replace(':','');
  const full=base+'/'+encodeURIComponent(user)+'/'+proto+':/'+u.host;
  document.getElementById('out').textContent=full;
  document.getElementById('msg').textContent='';
}
async function copy(){
  const t=document.getElementById('out').textContent;
  if(!t) return;
  try{ await navigator.clipboard.writeText(t); document.getElementById('msg').textContent='已复制'; }
  catch(e){ document.getElementById('msg').textContent='复制失败'; }
}
gen();
</script>
</body></html>`;
}

function stripSomeHeaders(resp) {
  const h = new Headers(resp.headers);
  h.delete("Content-Security-Policy");
  h.delete("X-Frame-Options");
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: h });
}

function text(s, status = 200) {
  return new Response(s, { status, headers: { "content-type": "text/plain; charset=utf-8" } });
}
function html(s, status = 200) {
  return new Response(s, { status, headers: { "content-type": "text/html; charset=utf-8" } });
}
function esc(s){
  return String(s ?? "").replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}
