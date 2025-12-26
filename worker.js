/**
 * Routes
 * - GET  /                 概览一行信息 + 登录提示（无日志）
 * - /{user}/{target...}    反代入口（白名单校验；统计 user+origin；有限日志）
 * - GET/POST /admin        管理页（仅密码登录 + Cookie 会话）
 *
 * D1 binding: env.DB   (必须叫 DB)
 * Secret:     ADMIN_PASSWORD
 */

const DEFAULT_MANUAL_REDIRECT_DOMAINS = [
  "ap-cn01.emby.bangumi.ca",
  "ap-cn02.emby.bangumi.ca",
  "ap-cn03.emby.bangumi.ca",
  "quark.cn",
  "mini189.cn",
  "189.cn",
  "ctyunxs.cn",
  "telecomjs.com",
  "xunlei.com",
  "115.com",
  "115cdn.com",
  "115cdn.net",
  "uc.cn",
  "aliyundrive.com",
  "aliyundrive.net",
  "voicehub.top",
  "xiaoya.pro",
];

const LOG_MAX = 2000;
const ADMIN_SHOW_LOGS = 300;

const TZ = "Asia/Shanghai";

// 日志/最近使用等数据保留：7 天（北京时间）
const DATA_TTL_DAYS = 7;
const DATA_TTL_MS = DATA_TTL_DAYS * 86400_000;
let LAST_CLEANUP_MS = 0;
const CLEANUP_INTERVAL_MS = 30 * 60_000;

// ip->city cache
const IP_GEO_TTL_SEC = 7 * 86400;

let DB_INIT = null;

let MANUAL_DOMAINS_CACHE = null;
let MANUAL_DOMAINS_CACHE_TS = 0;
const MANUAL_DOMAINS_TTL_MS = 60_000;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));

    if (!env.DB) {
      if (url.pathname === "/") return html(rootHtml({ error: "未绑定 D1：变量名必须是 DB" }), 500);
      return text("错误：未绑定 D1（变量名必须是 DB）", 500);
    }
    await ensureDb(env);

    // 定期清理（不阻塞请求）
    if (Date.now() - LAST_CLEANUP_MS > CLEANUP_INTERVAL_MS) {
      LAST_CLEANUP_MS = Date.now();
      ctx.waitUntil(cleanupOldData(env));
    }

    // 先取一次客户端信息（避免 waitUntil 里取不到/取不稳定）
    const meta = getClientMeta(request);

    if (url.pathname === "/") {
      const summary = await getSummary(env), city = await getCity(env, meta.ip, meta.city);

      return html(rootHtml({ summary, ip: meta.ip, city, colo: meta.colo }), 200);
    }

    if (url.pathname === "/admin" || url.pathname.startsWith("/admin/")) {
      return handleAdmin(request, env);
    }

    // 反代入口：/{user}/{target...}
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return cors(text("请求格式错误（需要 /user/目标地址）", 400));

    const user = parts[0];
    const restPath = "/" + parts.slice(1).join("/");

    const urow = await getUser(env, user);
    if (!urow || !urow.enabled) {
      ctx.waitUntil(
        writeLog(env, meta, {
          user,
          origin: "",
          status: 403,
          action: "deny",
          reason: "user 不存在或禁用",
          path: restPath,
        })
      );
      return cors(text("禁止访问", 403));
    }

    let upstreamUrl;
    try {
      upstreamUrl = parseUpstreamUrl(restPath, url.search);
    } catch {
      ctx.waitUntil(
        writeLog(env, meta, {
          user,
          origin: "",
          status: 400,
          action: "deny",
          reason: "目标地址不合法",
          path: restPath,
        })
      );
      return cors(text("目标地址不合法", 400));
    }

    const originKey = canonicalOrigin(upstreamUrl);
    if ((await getWhitelistEnabled(env)) && !(await isWhitelisted(env, originKey))) {
      ctx.waitUntil(
        writeLog(env, meta, {
          user,
          origin: originKey,
          status: 403,
          action: "deny",
          reason: "不在白名单",
          path: upstreamUrl.pathname,
        })
      );
      return cors(text("禁止访问", 403));
    }

    ctx.waitUntil(touchLastSeen(env, user, originKey, request));

    // WebSocket：不向上游透传真实 IP 相关头
    const upgradeHeader = request.headers.get("Upgrade");
    if (upgradeHeader && upgradeHeader.toLowerCase() === "websocket") {
      const wsHeaders = new Headers(request.headers);
      wsHeaders.set("Host", upstreamUrl.host);
      wsHeaders.delete("Referer");
      stripClientIpHeaders(wsHeaders);

      const wsReq = new Request(upstreamUrl.toString(), {
        method: request.method,
        headers: wsHeaders,
        body: request.body,
      });

      const resp = await fetch(wsReq);
      ctx.waitUntil(
        writeLog(env, meta, {
          user,
          origin: originKey,
          status: resp.status,
          action: "proxy",
          reason: "ws",
          path: upstreamUrl.pathname,
        })
      );
      return resp;
    }

    const method = request.method.toUpperCase();
    const body = method === "GET" || method === "HEAD" ? undefined : await request.arrayBuffer();

    const upstreamHeaders = new Headers(request.headers);
    upstreamHeaders.set("Host", upstreamUrl.host);
    upstreamHeaders.delete("Referer");
    stripClientIpHeaders(upstreamHeaders);

    const upstreamReq = new Request(upstreamUrl.toString(), {
      method,
      headers: upstreamHeaders,
      body,
      redirect: "manual",
    });

    const upstreamResp = await fetch(upstreamReq);

    // 重定向：命中直链域名后缀→直接返回 302；否则→Worker 内跟随（跳转目标也必须在白名单）
    const location = upstreamResp.headers.get("Location");
    if (location && upstreamResp.status >= 300 && upstreamResp.status < 400) {
      try {
        const redirectUrl = new URL(location, upstreamUrl);

        const manualDomains = await getManualRedirectDomains(env);
        if (manualDomains.some((d) => redirectUrl.hostname.endsWith(d))) {
          const h = new Headers(upstreamResp.headers);
          h.set("Location", redirectUrl.toString());
          const resp = cors(cleanHeaders(upstreamResp, h));
          ctx.waitUntil(
            writeLog(env, meta, {
              user,
              origin: originKey,
              status: resp.status,
              action: "proxy",
              reason: "manual redirect",
              path: upstreamUrl.pathname,
            })
          );
          return resp;
        }

        const redirOriginKey = canonicalOrigin(redirectUrl);
        if ((await getWhitelistEnabled(env)) && !(await isWhitelisted(env, redirOriginKey))) {
          ctx.waitUntil(
            writeLog(env, meta, {
              user,
              origin: originKey,
              status: 403,
              action: "deny",
              reason: "跳转目标不在白名单",
              path: upstreamUrl.pathname,
            })
          );
          return cors(text("禁止访问", 403));
        }

        const followHeaders = new Headers(upstreamHeaders);
        followHeaders.set("Host", redirectUrl.host);
        stripClientIpHeaders(followHeaders);

        const followResp = await fetch(redirectUrl.toString(), {
          method,
          headers: followHeaders,
          body,
          redirect: "follow",
        });

        const resp = cors(stripSecurityHeaders(followResp));
        ctx.waitUntil(
          writeLog(env, meta, {
            user,
            origin: originKey,
            status: resp.status,
            action: "proxy",
            reason: "follow redirect",
            path: upstreamUrl.pathname,
          })
        );
        return resp;
      } catch {
        const resp = cors(stripSecurityHeaders(upstreamResp));
        ctx.waitUntil(
          writeLog(env, meta, {
            user,
            origin: originKey,
            status: resp.status,
            action: "proxy",
            reason: "bad redirect url",
            path: upstreamUrl.pathname,
          })
        );
        return resp;
      }
    }

    const resp = cors(stripSecurityHeaders(upstreamResp));
    ctx.waitUntil(
      writeLog(env, meta, {
        user,
        origin: originKey,
        status: resp.status,
        action: "proxy",
        reason: "ok",
        path: upstreamUrl.pathname,
      })
    );
    return resp;
  },
};

/* ================= Root page (NO logs) ================= */

function rootHtml(p) {
  p = p || {};
  const error = p.error;
  if (error) return `<!doctype html><meta charset="utf-8"/><h3>${escapeHtml(error)}</h3><p><a href="/admin">进入管理</a></p>`;

  const summary = p.summary || {}, ip = p.ip, city = p.city, colo = p.colo;
  const seg = [];
  seg.push(`IP: ${ip || ""}`);
  if (city) seg.push(`City: ${city}`);
  if (colo) seg.push(`COLO: ${colo}`);
  seg.push(`总请求次数: ${summary.total_requests ?? 0}`);
  seg.push(`入口数: ${summary.users ?? 0}`);
  seg.push(`白名单数: ${summary.whitelist ?? 0}`);
  seg.push(`最近活动: ${summary.last_activity || ""}`);

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Overview</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;margin:16px;line-height:1.4}
pre{white-space:pre-wrap;word-break:break-word}
</style>
</head>
<body>
  <pre>${escapeHtml(seg.join(" / "))}</pre>
  <p><a href="/admin">管理登录（仅需管理员密码）</a></p>
</body>
</html>`;
}

/* ================= Admin ================= */

async function handleAdmin(request, env) {
  if (!env.ADMIN_PASSWORD) return html("<h3>错误：未设置 ADMIN_PASSWORD</h3>", 500);

  if (request.method === "POST") {
    const form = await request.formData();
    const action = String(form.get("action") || "");

    if (action === "login") {
      const pass = String(form.get("password") || "");
      if (pass === env.ADMIN_PASSWORD) {
        const cookie = await makeAdminCookie(env.ADMIN_PASSWORD);
        return new Response(null, { status: 303, headers: { "Set-Cookie": cookie, Location: "/admin" } });
      }
      return html(loginHtml("密码错误"), 401);
    }

    if (action === "logout") {
      return new Response(null, {
        status: 303,
        headers: {
          "Set-Cookie": "adm=; Path=/admin; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
          Location: "/admin",
        },
      });
    }

    if (!(await isAdmin(request, env.ADMIN_PASSWORD))) {
      return html(loginHtml("请先登录"), 401);
    }

    try {
      if (action === "set_wl_enabled") {
        const v = String(form.get("wl_enabled") || "");
        await setWhitelistEnabled(env, v === "1" ? 1 : 0);
      }

      if (action === "set_base_domains") {
        const raw = String(form.get("base_domains") || "");
        const list = splitList(raw).map(safeBase).filter(Boolean);
        await setBaseDomains(env, list);
      }

      if (action === "set_manual_domains") {
        const raw = String(form.get("manual_domains") || "");
        const list = splitList(raw)
          .map((x) => x.replace(/^https?:\/\//i, "").trim())
          .map((x) => x.replace(/^www\./i, "").trim())
          .filter(Boolean);
        await setManualRedirectDomains(env, list);
        MANUAL_DOMAINS_CACHE = list;
        MANUAL_DOMAINS_CACHE_TS = Date.now();
      }

      if (action === "add_user") {
        let user = String(form.get("user") || "").trim();
        const note = String(form.get("note") || "").trim();
        if (!user) user = "ikun";
        await upsertUser(env, user, note);
      }

      if (action === "toggle_user") {
        const user = String(form.get("user") || "").trim();
        if (user) await toggleUser(env, user);
      }

      if (action === "del_user") {
        const user = String(form.get("user") || "").trim();
        if (user) await deleteUser(env, user);
      }

      if (action === "add_wl") {
        if (await getWhitelistEnabled(env)) {
          const raw = String(form.get("origin") || "");
          const items = splitList(raw).map(normalizeOrigin).filter(Boolean);
          for (const o of items) await addWhitelist(env, o);
        }
      }

      if (action === "del_wl") {
        if (await getWhitelistEnabled(env)) {
          const origin = normalizeOrigin(String(form.get("origin") || "")) || "";
          if (origin) await deleteWhitelist(env, origin);
        }
      }
    } catch (e) {
      return html(`<pre>操作失败：${escapeHtml(String(e))}</pre><p><a href="/admin">返回</a></p>`, 500);
    }

    return new Response(null, { status: 303, headers: { Location: "/admin" } });
  }

  if (!(await isAdmin(request, env.ADMIN_PASSWORD))) {
    return html(loginHtml(""), 200);
  }

  const pageOrigin = new URL(request.url).origin;
  const [baseDomains, manualDomains, users, wl, whitelistEnabled, lastSeen, logs] = await Promise.all([
    getBaseDomains(env),
    getManualRedirectDomains(env),
    listUsers(env),
    listWhitelist(env),
    getWhitelistEnabled(env),
    listLastSeen(env, 300),
    listLogs(env, ADMIN_SHOW_LOGS),
  ]);

  return html(adminHtml({ pageOrigin, baseDomains, manualDomains, users, wl, whitelistEnabled, lastSeen, logs }));
}

function loginHtml(msg) {
  return `<!doctype html>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin Login</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;margin:16px;line-height:1.4}
.box{max-width:420px;border:1px solid #ddd;border-radius:10px;padding:14px}
input,button{font:inherit}
small{color:#c00}
</style>
<div class="box">
  <h3 style="margin:0 0 10px">管理登录</h3>
  ${msg ? `<small>${escapeHtml(msg)}</small><br/><br/>` : ""}
  <form method="post">
    <input type="hidden" name="action" value="login"/>
    <input name="password" type="password" placeholder="管理员密码" style="width:100%;padding:8px" required/>
    <button style="margin-top:10px;padding:8px 12px">登录</button>
  </form>
  <p style="margin-top:10px"><a href="/">返回</a></p>
</div>`;
}

function adminHtml({ pageOrigin, baseDomains, manualDomains, users, wl, whitelistEnabled, lastSeen, logs }) {
  const origin = pageOrigin;
  const bases = dedupe([origin, ...(baseDomains || [])]).map((b) => b.replace(/\/+$/, ""));
  const baseText = (baseDomains || []).join("\n");
  const manualText = (manualDomains || []).join("\n");
  const wlLocked = !whitelistEnabled;

  const userOpts = (users || [])
    .map((u) => `<option value="${escapeHtml(u.user)}"${u.user === "ikun" ? " selected" : ""}>${escapeHtml(u.user)}${u.enabled ? "" : " (禁用)"}</option>`)
    .join("");

  const wlOpts = (wl || []).map((o) => `<option value="${escapeHtml(o)}">${escapeHtml(o)}</option>`).join("");
  const baseOptions = bases.map((b) => `<option value="${escapeHtml(b)}">${escapeHtml(b)}</option>`).join("");

  const usersTable = (users || [])
    .map((u) => `<tr>
      <td>${escapeHtml(u.user)}</td>
      <td>${u.enabled ? "✅" : "⛔"}</td>
      <td>${escapeHtml(u.note || "")}</td>
      <td>
        <form method="post" style="display:inline">
          <input type="hidden" name="action" value="toggle_user"/>
          <input type="hidden" name="user" value="${escapeHtml(u.user)}"/>
          <button>启用/禁用</button>
        </form>
        <form method="post" style="display:inline;margin-left:6px" onsubmit="return confirm('确定删除：${escapeHtml(u.user)} ?')">
          <input type="hidden" name="action" value="del_user"/>
          <input type="hidden" name="user" value="${escapeHtml(u.user)}"/>
          <button>删除</button>
        </form>
      </td>
    </tr>`)
    .join("");

  const wlTable = (wl || [])
    .map((o) => `<tr>
      <td>${escapeHtml(o)}</td>
      <td>
        <form method="post" style="display:inline" onsubmit="return confirm('确定删除白名单：${escapeHtml(o)} ?')">
          <input type="hidden" name="action" value="del_wl"/>
          <input type="hidden" name="origin" value="${escapeHtml(o)}"/>
          ${wlLocked ? "<button disabled>删除</button>" : "<button>删除</button>"}
        </form>
      </td>
    </tr>`)
    .join("");

  const lastSeenTable = (lastSeen || [])
    .map((r) => `<tr data-user="${escapeHtml(r.user)}" data-ts="${escapeHtml(r.last_ts || "")}" data-count="${escapeHtml(String(r.count ?? 0))}">
      <td>${escapeHtml(r.user)}</td>
      <td>${escapeHtml(r.note || "")}</td>
      <td>${escapeHtml(r.origin)}</td>
      <td>${escapeHtml(String(r.count ?? 0))}</td>
      <td>${escapeHtml(r.last_ts || "")}</td>
    </tr>`)
    .join("");

  const logsTable = (logs || [])
    .map((r) => `<tr>
      <td>${escapeHtml(r.ts)}</td>
      <td>${escapeHtml(r.ip || "")}</td>
      <td>${escapeHtml(r.city || "")}</td>
      <td>${escapeHtml(r.colo || "")}</td>
      <td>${escapeHtml(r.user || "")}</td>
      <td>${escapeHtml(r.origin || "")}</td>
      <td>${escapeHtml(r.action || "")}</td>
      <td>${escapeHtml(String(r.status ?? ""))}</td>
      <td>${escapeHtml(r.reason || "")}</td>
      <td>${escapeHtml(r.path || "")}</td>
      <td title="${escapeHtml(r.ua || "")}">${escapeHtml(shorten(r.ua || "", 80))}</td>
    </tr>`)
    .join("");

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;margin:16px;line-height:1.4}
small{color:#666}
textarea,input,select,button{font:inherit}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px;vertical-align:top}
th{background:#f7f7f7;text-align:left}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.box{padding:10px;border:1px solid #ddd;border-radius:10px;margin-top:10px}
details{margin-top:10px}
summary{cursor:pointer}
.tip{display:inline-block;width:16px;height:16px;line-height:16px;text-align:center;border:1px solid #bbb;border-radius:50%;
     font-size:12px;color:#555;cursor:help;position:relative;margin-left:6px}
.tip:hover::after{
  content: attr(data-tip);
  position:absolute;left:18px;top:-6px;
  background:#111;color:#fff;padding:6px 8px;border-radius:6px;white-space:nowrap;
  font-size:12px;z-index:10;
}
.out{width:520px}
.logwrap{
  max-height:420px;
  overflow:auto;
  border:1px solid #eee;
  border-radius:8px;
  margin-top:8px;
}
.logwrap thead th{
  position:sticky;
  top:0;
  z-index:2;
}
</style>
</head>
<body>
  <h1>管理</h1>
  <form method="post" style="margin-bottom:10px">
    <input type="hidden" name="action" value="logout"/>
    <button>退出登录</button>
  </form>

  <div class="box">
    <h3 style="margin:0 0 6px">入口
      <span class="tip" data-tip="入口就是 URL 的第一段：/{入口}/{目标...}。可启用/禁用。">?</span>
    </h3>
    <form method="post" class="row">
      <input type="hidden" name="action" value="add_user"/>
      <input name="user" placeholder="user（默认 ikun）"/>
      <input name="note" placeholder="备注（可选）"/>
      <button>添加/更新</button>
    </form>
    <table style="margin-top:8px">
      <thead><tr><th>user</th><th>启用</th><th>备注</th><th>操作</th></tr></thead>
      <tbody>${usersTable}</tbody>
    </table>
  </div>

  <div class="box">
    <h3 style="margin:0 0 6px">白名单
      <span class="tip" data-tip="按 origin（协议+host+可选端口）匹配。支持 example.com、https://example.com:443、example.com:8096。默认端口(80/443)会自动折叠。">?</span>
    </h3>
    <form method="post" class="row" style="margin-top:6px">
      <input type="hidden" name="action" value="set_wl_enabled"/>
      <label><input type="checkbox" name="wl_enabled" value="1"${whitelistEnabled ? " checked" : ""}/> 启用白名单</label>
      <button>保存</button>
    </form>
    <form method="post" class="row">
      <input type="hidden" name="action" value="add_wl"/>
      <input name="origin" class="out" placeholder="支持逗号/换行批量" required${wlLocked ? " disabled" : ""}/>
      <button${wlLocked ? " disabled" : ""}>添加</button>
    </form>
    <table style="margin-top:8px">
      <thead><tr><th>origin</th><th>操作</th></tr></thead>
      <tbody>${wlTable}</tbody>
    </table>
  </div>

  <div class="box">
    <h3 style="margin:0 0 6px">入口链接生成
      <span class="tip" data-tip="选择项目域名 + user + 白名单 origin，自动拼装入口链接。">?</span>
    </h3>
    <div class="row">
      <select id="baseSel">${baseOptions}</select>
      <select id="userSel">${userOpts}</select>
      <select id="originSel">
        ${wlLocked ? `<option value="" selected>（白名单未启用）</option>` : `<option value="" selected>（先选择白名单）</option>`}
        ${wlOpts}
      </select>
    </div>
    <div class="row" style="margin-top:8px">
      <input id="linkOut" class="out" readonly placeholder="选择白名单后生成链接"/>
      <button id="copyBtn" type="button">复制</button>
    </div>
    <small>格式：/{user}/{proto}:/{host[:port]}，后面可继续带 Emby 路径。</small>
  </div>

  <details class="box">
    <summary><b>其他设置</b></summary>

    <div style="margin-top:10px">
      <h3 style="margin:0 0 6px">项目地址
        <span class="tip" data-tip="仅用于生成入口链接：同一套 Worker 部署在多个域名上，可把其它域名填进来便于下拉选择与复制。">?</span>
      </h3>
      <form method="post">
        <input type="hidden" name="action" value="set_base_domains"/>
        <div class="row">
          <textarea name="base_domains" rows="3" class="out" placeholder="每行一个，如：https://a.example.com">${escapeHtml(baseText)}</textarea>
          <button>保存</button>
        </div>
      </form>
    </div>

    <div style="margin-top:10px">
      <h3 style="margin:0 0 6px">直链域名后缀（可选）
        <span class="tip" data-tip="上游返回 302 且目标域名命中这些后缀时，直接返回 302 让客户端直连下载。">?</span>
      </h3>
      <form method="post">
        <input type="hidden" name="action" value="set_manual_domains"/>
        <div class="row">
          <textarea name="manual_domains" rows="6" class="out" placeholder="每行一个后缀，如 115.com">${escapeHtml(manualText)}</textarea>
          <button>保存</button>
        </div>
      </form>
    </div>
  </details>

  <details class="box" open>
    <summary><b>最近使用</b></summary>
    <div class="row" style="margin-top:8px">
      <label>user：
        <select id="lsUserFilter">
          <option value="" selected>全部</option>
          ${(users || []).map((u)=>`<option value="${escapeHtml(u.user)}">${escapeHtml(u.user)}</option>`).join("")}
        </select>
      </label>
      <label>排序：
        <select id="lsSort">
          <option value="ts_desc" selected>按时间(新→旧)</option>
          <option value="count_desc">按次数(高→低)</option>
        </select>
      </label>
    </div>
    <div class="logwrap">
      <table id="lsTable" style="margin-top:8px">
        <thead><tr><th>user</th><th>备注</th><th>origin</th><th>次数</th><th>最后时间(北京时间)</th></tr></thead>
        <tbody>${lastSeenTable}</tbody>
      </table>
    </div>
  </details>

  <details class="box" open>
    <summary><b>最近日志</b></summary>
    <small>仅保留最新 ${LOG_MAX} 条；时间为北京时间。</small>
    <div class="row" style="margin-top:8px">
      <input id="logQ" class="out" placeholder="关键词筛选（支持时间/IP/user/origin/UA 等）"/>
      <small id="logQStat"></small>
    </div>
    <div class="logwrap">
      <table id="logTable">
        <thead>
          <tr>
            <th>时间</th><th>IP</th><th>City</th><th>COLO</th>
            <th>user</th><th>origin</th><th>action</th><th>status</th><th>reason</th><th>path</th><th>UA</th>
          </tr>
        </thead>
        <tbody>${logsTable}</tbody>
      </table>
    </div>
  </details>

  <p><a href="/">返回概览</a></p>

<script>
(function(){
  const baseSel = document.getElementById('baseSel');
  const userSel = document.getElementById('userSel');
  const originSel = document.getElementById('originSel');
  const out = document.getElementById('linkOut');
  const btn = document.getElementById('copyBtn');
  const WL_ENABLED = ${whitelistEnabled ? "true" : "false"};

  function build(){
    const base = (baseSel.value || '').replace(/\\/+$/,'');
    const user = userSel.value || '';
    const origin = originSel.value || '';
    if(!base || !user){ out.value=''; return; }

    // 白名单关闭：链接=base/user
    if(!WL_ENABLED){
      out.value = base + '/' + encodeURIComponent(user);
      return;
    }

    // 白名单开启：需要选择 origin
    if(!origin){ out.value=''; return; }
    try{
      const u = new URL(origin);
      const proto = u.protocol.replace(':','');
      out.value = base + '/' + encodeURIComponent(user) + '/' + proto + ':/' + u.host;
    }catch(e){ out.value=''; }
  }

  baseSel.addEventListener('change', build);
  userSel.addEventListener('change', build);
  originSel.addEventListener('change', build);
  build();

  if(!WL_ENABLED){ originSel.disabled = true; }

  btn.addEventListener('click', async () => {
    if(!out.value) return;
    try{
      await navigator.clipboard.writeText(out.value);
      btn.textContent='已复制';
      setTimeout(()=>btn.textContent='复制', 800);
    }catch(e){
      out.select();
      document.execCommand('copy');
    }
  });
})();

(function(){
  // 最近使用：筛选 + 排序（前端）
  const tb = document.querySelector('#lsTable tbody');
  const userSel = document.getElementById('lsUserFilter');
  const sortSel = document.getElementById('lsSort');
  if(tb && userSel && sortSel){
    const allRows = Array.from(tb.querySelectorAll('tr'));
    function render(){
      const u = (userSel.value || '');
      const mode = sortSel.value || 'ts_desc';
      const rows = allRows
        .filter(r => !u || (r.dataset.user === u))
        .sort((a,b)=>{
          if(mode === 'count_desc'){
            return (Number(b.dataset.count||0) - Number(a.dataset.count||0)) || String(b.dataset.ts||'').localeCompare(String(a.dataset.ts||''));
          }
          return String(b.dataset.ts||'').localeCompare(String(a.dataset.ts||'')); // ts_desc
        });
      tb.innerHTML = '';
      for(const r of rows) tb.appendChild(r);
    }
    userSel.addEventListener('change', render);
    sortSel.addEventListener('change', render);
    render();
  }

  // 日志：关键词筛选（前端）
  const logQ = document.getElementById('logQ');
  const logQStat = document.getElementById('logQStat');
  const logTb = document.querySelector('#logTable tbody');
  if(logQ && logTb){
    const rows = Array.from(logTb.querySelectorAll('tr'));
    function apply(){
      const q = (logQ.value || '').trim().toLowerCase();
      let shown = 0;
      for(const r of rows){
        const ok = !q || (r.innerText || '').toLowerCase().includes(q);
        r.style.display = ok ? '' : 'none';
        if(ok) shown++;
      }
      if(logQStat) logQStat.textContent = q ? ('显示 ' + shown + '/' + rows.length) : '';
    }
    logQ.addEventListener('input', apply);
    apply();
  }
})();
</script>
</body>
</html>`;
}

/* ================= Client meta + City ================= */

function getClientMeta(request) {
  return {
    ip: request.headers.get("cf-connecting-ip") || "",
    colo: request.cf?.colo || "",
    city: request.cf?.city || "",
    ua: request.headers.get("user-agent") || "",
  };
}

async function getCity(env, ip, cfCity) {
  if (cfCity) return cfCity;
  if (!ip) return "";
  return await getCityForIp(env, ip);
}

async function getCityForIp(env, ip) {
  const now = Math.floor(Date.now() / 1000);

  try {
    const row = await env.DB.prepare(`SELECT city, updated_at FROM proxy_ipgeo WHERE ip=?`)
      .bind(ip)
      .first();

    if (row && row.city && row.updated_at && now - Number(row.updated_at) < IP_GEO_TTL_SEC) {
      return row.city;
    }
  } catch {}

  // 走 ipapi.co 补全
  let city = "";
  try {
    const r = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, {
      headers: { "User-Agent": "cf-worker-proxy" },
    });
    if (r.ok) {
      const j = await r.json().catch(() => null);
      if (j && typeof j.city === "string") city = j.city.trim();
    }
  } catch {}

  // 缓存（即使 city 为空，也缓存一段时间，减少重复请求）
  try {
    await env.DB.prepare(`
      INSERT INTO proxy_ipgeo(ip, city, updated_at)
      VALUES(?, ?, ?)
      ON CONFLICT(ip) DO UPDATE SET city=excluded.city, updated_at=excluded.updated_at
    `).bind(ip, city, now).run();
  } catch {}

  return city;
}

/* ================= Admin session cookie ================= */

async function makeAdminCookie(password) {
  const exp = Math.floor(Date.now() / 1000) + 12 * 3600;
  const nonce = b64u(crypto.getRandomValues(new Uint8Array(16)));
  const payload = `${exp}.${nonce}`;
  const sig = await hmac256(password, payload);
  const v = `${payload}.${sig}`;
  return `adm=${v}; Path=/admin; Max-Age=${12 * 3600}; HttpOnly; Secure; SameSite=Lax`;
}

async function isAdmin(request, password) {
  const cookie = request.headers.get("Cookie") || "";
  const m = cookie.match(/(?:^|;\s*)adm=([^;]+)/);
  if (!m) return false;

  const v = m[1];
  const parts = v.split(".");
  if (parts.length !== 3) return false;

  const exp = Number(parts[0]);
  if (!Number.isFinite(exp) || exp < Math.floor(Date.now() / 1000)) return false;

  const payload = `${parts[0]}.${parts[1]}`;
  const sig = parts[2];
  const expect = await hmac256(password, payload);
  return timingSafeEqual(sig, expect);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function hmac256(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return b64u(new Uint8Array(sig));
}

function b64u(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/* ================= DB ================= */

async function ensureDb(env) {
  if (DB_INIT) return DB_INIT;

  DB_INIT = (async () => {
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS proxy_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS proxy_users (
        user TEXT PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 1,
        note TEXT,
        created_at TEXT,
        updated_at TEXT
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS proxy_whitelist (
        origin TEXT PRIMARY KEY,
        created_at TEXT
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS proxy_last_seen (
        user TEXT NOT NULL,
        upstream_origin TEXT NOT NULL,
        last_ts TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        last_ip TEXT,
        last_colo TEXT,
        PRIMARY KEY (user, upstream_origin)
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS proxy_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        user TEXT,
        upstream_origin TEXT,
        status INTEGER,
        action TEXT NOT NULL,
        reason TEXT,
        path TEXT,
        ip TEXT,
        city TEXT,
        colo TEXT,
        ua TEXT
      )
    `).run();

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS proxy_ipgeo (
        ip TEXT PRIMARY KEY,
        city TEXT,
        updated_at INTEGER
      )
    `).run();

    // 兼容旧库缺列：加不上就忽略
    try { await env.DB.prepare(`ALTER TABLE proxy_logs ADD COLUMN ip TEXT`).run(); } catch {}
    try { await env.DB.prepare(`ALTER TABLE proxy_logs ADD COLUMN city TEXT`).run(); } catch {}
    try { await env.DB.prepare(`ALTER TABLE proxy_logs ADD COLUMN colo TEXT`).run(); } catch {}
    try { await env.DB.prepare(`ALTER TABLE proxy_logs ADD COLUMN ua TEXT`).run(); } catch {}

    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_last_seen_ts ON proxy_last_seen(last_ts)`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_logs_id ON proxy_logs(id)`).run();

    const now = nowLocal();

    const baseRow = await env.DB.prepare(`SELECT 1 FROM proxy_config WHERE key='baseDomains'`).first();
    if (!baseRow) await setBaseDomains(env, []);

    const manualRow = await env.DB.prepare(`SELECT 1 FROM proxy_config WHERE key='manualRedirectDomains'`).first();
    if (!manualRow) await setManualRedirectDomains(env, DEFAULT_MANUAL_REDIRECT_DOMAINS);

    const wlRow = await env.DB.prepare(`SELECT 1 FROM proxy_config WHERE key='whitelistEnabled'`).first();
    if (!wlRow) await setWhitelistEnabled(env, 0);

    await env.DB.prepare(`
      INSERT OR IGNORE INTO proxy_users(user, enabled, note, created_at, updated_at)
      VALUES('ikun', 1, '', ?, ?)
    `).bind(now, now).run();

    // 启动后做一次清理（非必要，但更符合“7 天后重置”）
    await cleanupOldData(env);
  })();

  return DB_INIT;
}

async function getBaseDomains(env) {
  const row = await env.DB.prepare(`SELECT value FROM proxy_config WHERE key='baseDomains'`).first();
  if (!row) return [];
  try { const a = JSON.parse(row.value); return Array.isArray(a) ? a : []; } catch { return []; }
}

async function setBaseDomains(env, list) {
  await env.DB.prepare(`
    INSERT INTO proxy_config(key,value,updated_at) VALUES('baseDomains',?,?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
  `).bind(JSON.stringify(list || []), nowLocal()).run();
}

async function getManualRedirectDomains(env) {
  if (MANUAL_DOMAINS_CACHE && Date.now() - MANUAL_DOMAINS_CACHE_TS < MANUAL_DOMAINS_TTL_MS) return MANUAL_DOMAINS_CACHE;

  const row = await env.DB.prepare(`SELECT value FROM proxy_config WHERE key='manualRedirectDomains'`).first();
  let list = DEFAULT_MANUAL_REDIRECT_DOMAINS;
  if (row) {
    try {
      const a = JSON.parse(row.value);
      if (Array.isArray(a)) list = a.filter(Boolean);
    } catch {}
  }
  MANUAL_DOMAINS_CACHE = list;
  MANUAL_DOMAINS_CACHE_TS = Date.now();
  return list;
}

async function setManualRedirectDomains(env, list) {
  await env.DB.prepare(`
    INSERT INTO proxy_config(key,value,updated_at) VALUES('manualRedirectDomains',?,?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
  `).bind(JSON.stringify(list || []), nowLocal()).run();
}
async function getWhitelistEnabled(env) {
  const row = await env.DB.prepare(`SELECT value FROM proxy_config WHERE key='whitelistEnabled'`).first();
  return row && row.value === "1";
}

async function setWhitelistEnabled(env, enabled) {
  await env.DB.prepare(`
    INSERT INTO proxy_config(key,value,updated_at) VALUES('whitelistEnabled',?,?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
  `).bind(enabled ? "1" : "0", nowLocal()).run();
}


async function upsertUser(env, user, note) {
  const now = nowLocal();
  await env.DB.prepare(`
    INSERT INTO proxy_users(user,enabled,note,created_at,updated_at)
    VALUES(?,1,?,?,?)
    ON CONFLICT(user) DO UPDATE SET note=excluded.note, updated_at=excluded.updated_at
  `).bind(user, note || "", now, now).run();
}

async function toggleUser(env, user) {
  const row = await env.DB.prepare(`SELECT enabled FROM proxy_users WHERE user=?`).bind(user).first();
  if (!row) return;
  const next = row.enabled ? 0 : 1;
  await env.DB.prepare(`UPDATE proxy_users SET enabled=?, updated_at=? WHERE user=?`)
    .bind(next, nowLocal(), user).run();
}

async function deleteUser(env, user) {
  await env.DB.prepare(`DELETE FROM proxy_users WHERE user=?`).bind(user).run();
  await env.DB.prepare(`DELETE FROM proxy_last_seen WHERE user=?`).bind(user).run();
}

async function getUser(env, user) {
  const row = await env.DB.prepare(`SELECT user, enabled, note FROM proxy_users WHERE user=?`).bind(user).first();
  if (!row) return null;
  return { user: row.user, enabled: !!row.enabled, note: row.note || "" };
}

async function listUsers(env) {
  const { results } = await env.DB.prepare(`SELECT user, enabled, note FROM proxy_users ORDER BY user ASC`).all();
  return (results || []).map((r) => ({ user: r.user, enabled: !!r.enabled, note: r.note || "" }));
}

async function addWhitelist(env, origin) {
  await env.DB.prepare(`INSERT OR IGNORE INTO proxy_whitelist(origin,created_at) VALUES(?,?)`)
    .bind(origin, nowLocal()).run();
}

async function deleteWhitelist(env, origin) {
  await env.DB.prepare(`DELETE FROM proxy_whitelist WHERE origin=?`).bind(origin).run();
}

async function listWhitelist(env) {
  const { results } = await env.DB.prepare(`SELECT origin FROM proxy_whitelist ORDER BY origin ASC`).all();
  return (results || []).map((r) => r.origin);
}

async function isWhitelisted(env, origin) {
  const row = await env.DB.prepare(`SELECT 1 FROM proxy_whitelist WHERE origin=? LIMIT 1`).bind(origin).first();
  return !!row;
}

async function touchLastSeen(env, user, origin, request) {
  const ts = nowLocal();
  const ip = request.headers.get("cf-connecting-ip") || "";
  const colo = request.cf?.colo || "";
  await env.DB.prepare(`
    INSERT INTO proxy_last_seen(user, upstream_origin, last_ts, count, last_ip, last_colo)
    VALUES(?, ?, ?, 1, ?, ?)
    ON CONFLICT(user, upstream_origin) DO UPDATE SET
      last_ts = excluded.last_ts,
      count = count + 1,
      last_ip = excluded.last_ip,
      last_colo = excluded.last_colo
  `).bind(user, origin, ts, ip, colo).run();
}

async function listLastSeen(env, limit = 100) {
  const { results } = await env.DB.prepare(`
    SELECT l.user, u.note AS note, l.upstream_origin AS origin, l.last_ts, l.count
    FROM proxy_last_seen l
    LEFT JOIN proxy_users u ON u.user=l.user
    ORDER BY l.last_ts DESC
    LIMIT ?
  `).bind(limit).all();
  return results || [];
}

async function writeLog(env, meta, { user, origin, status, action, reason, path }) {
  try {
    const ts = nowLocal();
    const ip = meta.ip || "";
    const colo = meta.colo || "";
    const ua = meta.ua || "";

    // city：优先 cf，缺失则 ipapi.co（含缓存）
    const city = await getCity(env, ip, meta.city || "");

    await env.DB.prepare(`
      INSERT INTO proxy_logs(ts, user, upstream_origin, status, action, reason, path, ip, city, colo, ua)
      VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(ts, user || "", origin || "", status ?? null, action, reason || "", path || "", ip, city, colo, ua).run();

    await env.DB.prepare(`
      DELETE FROM proxy_logs
      WHERE id <= (SELECT COALESCE(MAX(id),0) - ? FROM proxy_logs)
    `).bind(LOG_MAX).run();
  } catch {}
}

async function listLogs(env, limit = 50) {
  const { results } = await env.DB.prepare(`
    SELECT ts, user, upstream_origin AS origin, status, action, reason, path, ip, city, colo, ua
    FROM proxy_logs
    ORDER BY id DESC
    LIMIT ?
  `).bind(limit).all();
  return results || [];
}

async function getSummary(env) {
  const [a, b, c, d] = await Promise.all([
    env.DB.prepare(`SELECT COALESCE(SUM(count),0) AS total FROM proxy_last_seen`).first(),
    env.DB.prepare(`SELECT COUNT(*) AS n FROM proxy_users WHERE enabled=1`).first(),
    env.DB.prepare(`SELECT COUNT(*) AS n FROM proxy_whitelist`).first(),
    env.DB.prepare(`SELECT MAX(last_ts) AS ts FROM proxy_last_seen`).first(),
  ]);

  return {
    total_requests: a?.total ?? 0,
    users: b?.n ?? 0,
    whitelist: c?.n ?? 0,
    last_activity: d?.ts || "",
  };
}

/* ================= URL / normalize ================= */

function parseUpstreamUrl(restPath, search) {
  let p = restPath.startsWith("/") ? restPath.slice(1) : restPath;
  p = p.replace(/^(https?):\/(?!\/)/, "$1://");
  p = p.replace(/^(https?)\/(?!\/)/, "$1://");
  if (!p.startsWith("http://") && !p.startsWith("https://")) p = "https://" + p;
  const u = new URL(p);
  u.search = search || "";
  return u;
}

function normalizeOrigin(input) {
  let s = String(input || "").trim();
  if (!s) return null;
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  const u = new URL(s);
  return canonicalOrigin(u);
}

function canonicalOrigin(u) {
  const proto = u.protocol.toLowerCase();
  let host = u.hostname;
  if (host.includes(":") && !host.startsWith("[")) host = `[${host}]`;
  let port = u.port || "";
  const def = proto === "https:" ? "443" : proto === "http:" ? "80" : "";
  if (port === def) port = "";
  return `${proto}//${host.toLowerCase()}${port ? ":" + port : ""}`;
}

function stripClientIpHeaders(headers) {
  headers.delete("x-forwarded-for");
  headers.delete("x-real-ip");
  headers.delete("true-client-ip");
  headers.delete("cf-connecting-ip");
  headers.delete("CF-Connecting-IP");
  headers.delete("True-Client-IP");
}

function splitList(s) {
  return String(s || "")
    .split(/[\n,;]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

function safeBase(s) {
  const t = String(s || "").trim();
  if (!t) return null;
  try { return new URL(t).origin; } catch { return null; }
}

function dedupe(arr) {
  const out = [];
  const seen = new Set();
  for (const x of arr) {
    if (!x) continue;
    const k = String(x);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(k);
  }
  return out;
}

function nowLocal() {
  const d = new Date();
  const date = d.toLocaleDateString("en-CA", { timeZone: TZ });
  const time = d.toLocaleTimeString("en-GB", { timeZone: TZ, hour12: false });
  return `${date} ${time}`;
}

function tsFromMs(ms) {
  const d = new Date(ms);
  const date = d.toLocaleDateString("en-CA", { timeZone: TZ });
  const time = d.toLocaleTimeString("en-GB", { timeZone: TZ, hour12: false });
  return `${date} ${time}`;
}

async function cleanupOldData(env) {
  const cutoffTs = tsFromMs(Date.now() - DATA_TTL_MS);
  const cutoffGeo = Math.floor(Date.now() / 1000) - DATA_TTL_DAYS * 86400;
  try { await env.DB.prepare(`DELETE FROM proxy_logs WHERE ts < ?`).bind(cutoffTs).run(); } catch {}
  try { await env.DB.prepare(`DELETE FROM proxy_last_seen WHERE last_ts < ?`).bind(cutoffTs).run(); } catch {}
  try { await env.DB.prepare(`DELETE FROM proxy_ipgeo WHERE updated_at < ?`).bind(cutoffGeo).run(); } catch {}
}

function shorten(s, n) {
  if (!s) return "";
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

/* ================= Response helpers ================= */

function cors(resp) {
  const h = new Headers(resp.headers);
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  h.set("Access-Control-Allow-Headers", "*");
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: h });
}

function stripSecurityHeaders(upstreamResp) {
  const h = new Headers(upstreamResp.headers);
  h.delete("Content-Security-Policy");
  h.delete("X-Frame-Options");
  return new Response(upstreamResp.body, { status: upstreamResp.status, statusText: upstreamResp.statusText, headers: h });
}

function cleanHeaders(upstreamResp, headers) {
  const h = new Headers(headers);
  h.delete("Content-Security-Policy");
  h.delete("X-Frame-Options");
  return new Response(upstreamResp.body, { status: upstreamResp.status, statusText: upstreamResp.statusText, headers: h });
}

function text(s, status = 200) {
  return new Response(String(s ?? ""), { status, headers: { "content-type": "text/plain; charset=utf-8" } });
}

function html(s, status = 200) {
  return new Response(String(s ?? ""), { status, headers: { "content-type": "text/html; charset=utf-8" } });
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}
