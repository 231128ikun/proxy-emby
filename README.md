# Cloudflare Worker 反代网关（Emby 专用 / D1 统计）

一个基于 **Cloudflare Workers + D1** 的轻量级反代网关，  
支持：

- ✅ user 路径鉴权（如 `/ikun`）
- ✅ 白名单限制（只允许指定 upstream，支持端口）
- ✅ 反代 HTTP / HTTPS / WebSocket
- ✅ 自动生成反代入口链接（末尾不带 `/`）
- ✅ D1 存储访问日志 + 按天统计
- ✅ 无 wrangler，网页端复制粘贴即可部署

---

## 一、使用效果

### 1️⃣ 根域名

