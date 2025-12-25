# Emby Proxy Gateway

一个基于 Cloudflare Workers + D1 的安全反向代理服务，专为 Emby 等媒体服务器设计，支持多用户、白名单控制、访问日志统计和 WebSocket 连接。

## ✨ 特性

- 🔐 **多用户隔离**：支持多个独立用户入口，每个用户有独立的访问路径
- 🛡️ **白名单保护**：只允许访问预设的上游服务器，支持自定义端口
- 📊 **访问统计**：自动记录每日访问量、成功/拒绝次数，支持 30 天历史查看
- 📝 **详细日志**：记录每次请求的完整信息（时间、IP、UA、状态码等）
- 🌐 **WebSocket 支持**：完整支持 WebSocket 协议，适配 Emby 实时功能
- 🎨 **可视化界面**：美观的 Web 管理界面，一键生成代理链接

## 🚀 快速开始

### 1. 部署到 Cloudflare Workers

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 进入 **Workers & Pages**
3. 点击 **Create Application** → **Create Worker**
4. 复制代码并部署

### 2. 创建 D1 数据库

1. 在 Cloudflare Dashboard 中进入 **Storage & Databases** → **D1**
2. 点击 **Create database**
3. 输入数据库名称（如 `proxy-db`）
4. 创建完成后，记下数据库 ID

### 3. 绑定 D1 数据库

1. 在 Worker 设置中找到 **Settings** → **Variables**
2. 添加 **D1 Database Bindings**：
   - Variable name: `DB`
   - D1 database: 选择刚创建的数据库

### 4. 配置环境变量

在 Worker 的 **Settings** → **Variables** 中添加：

| 变量名 | 类型 | 必填 | 说明 | 示例 |
|--------|------|------|------|------|
| `USERS` | 文本 | 否 | 允许的用户列表，多个用逗号或换行分隔 | `ikun,user123,alice` |
| `WHITELIST` | 文本 | 是 | 上游服务器白名单，每行一个，支持端口 | `https://emby.example.com:8096` |

**环境变量示例：**

```bash
# USERS（默认为 ikun）
ikun
alice
bob123

# WHITELIST（必填，支持多行）
https://emby.example.com:8096
https://media.example.com
https://jellyfin.example.com:8920
```

### 5. 访问管理界面

部署完成后，访问 `https://your-worker.workers.dev/{user}` 查看管理界面。

## 📖 使用教程

### 生成代理链接

1. 访问 `https://your-worker.workers.dev/ikun`（将 `ikun` 替换为你的用户名）
2. 在界面中选择：
   - **user**：选择要使用的用户
   - **whitelist origin**：选择目标服务器
3. 点击 **生成** 按钮
4. 复制生成的代理链接

**生成的链接格式：**
```
https://your-worker.workers.dev/{user}/https:/emby.example.com:8096
```

### 在 Emby 客户端中使用

将生成的代理链接作为服务器地址填入 Emby 客户端：

- **Android/iOS 客户端**：在添加服务器时填入代理链接
- **Web 客户端**：直接访问代理链接
- **桌面客户端**：在服务器设置中填入代理链接

### 路径格式支持

代理支持多种 URL 格式：

```bash
# 标准格式（推荐）
/{user}/https:/example.com:8096/path

# 双斜杠格式
/{user}/https://example.com:8096/path

# 省略协议（默认 https）
/{user}/example.com:8096/path
```

## 📊 功能说明

### 访问统计

- **近 30 天统计**：以柱状图展示每天的总请求数、成功数、拒绝数
- **近 7 天汇总**：快速查看最近一周的访问概况

### 日志记录

每条日志包含：
- **时间戳**：精确到秒的 ISO 时间
- **结果状态**：allow/deny/error + HTTP 状态码
- **上游服务器**：目标服务器的 origin
- **客户端信息**：IP 地址、User-Agent、Cloudflare 边缘节点
- **请求详情**：HTTP 方法、请求路径

### 安全控制

1. **用户验证**：只有配置的用户才能访问
2. **白名单检查**：只能访问白名单中的上游服务器
3. **自动记录**：所有拒绝请求都会被记录，包含拒绝原因

## 🔧 高级配置

### 多端口支持

白名单支持自定义端口：

```
https://emby1.example.com:8096
https://emby2.example.com:8920
http://local.server:8080
```

### WebSocket 连接

代理自动识别并转发 WebSocket 连接，无需额外配置。Emby 的实时功能（如播放同步、在线状态）可正常使用。

### 客户端 IP 传递

代理自动添加以下请求头，方便上游服务器获取真实 IP：
- `X-Forwarded-For`
- `X-Real-IP`

## 🛠️ 故障排查

### 1. 访问根路径显示 "fail"

**原因**：未绑定 D1 数据库或未配置环境变量

**解决**：
- 确认已创建并绑定 D1 数据库（变量名必须为 `DB`）
- 确认已配置 `WHITELIST` 环境变量

### 2. 403 Forbidden (invalid user)

**原因**：访问的用户名不在 `USERS` 列表中

**解决**：在环境变量中添加该用户名，或使用默认用户 `ikun`

### 3. 403 Forbidden (upstream not allowed)

**原因**：目标服务器不在白名单中

**解决**：在 `WHITELIST` 环境变量中添加目标服务器的完整 origin（包含端口）

### 4. 502 Bad Gateway

**原因**：无法连接到上游服务器

**解决**：
- 检查上游服务器是否正常运行
- 确认防火墙是否允许 Cloudflare IP 访问
- 检查白名单中的地址是否正确（包含协议和端口）

## 📝 注意事项

1. **数据库变量名**：D1 数据库绑定的变量名必须是 `DB`（大写）
2. **端口号**：白名单中的地址需要包含完整的端口号，如 `:8096`
3. **HTTPS**：建议使用 HTTPS 协议，如省略协议则默认使用 HTTPS
4. **首次运行**：首次访问时会自动创建数据表，可能需要等待几秒
5. **日志限制**：单个用户最多显示 120 条最近日志

**提示**：部署完成后，建议先访问根路径 `/` 确认服务正常运行，再访问 `/{user}` 查看管理界面。
