# Cloudflare Workers 反向代理

这是一个基于 Cloudflare Workers + D1 数据库的反向代理服务，支持多用户、白名单管理、访问统计和日志记录功能。

## 功能特性

- **多用户管理**：支持创建多个代理入口（user），每个入口可独立启用/禁用
- **白名单机制**：仅允许访问白名单内的目标地址（按 origin 匹配）
- **访问统计**：记录每个用户+目标地址的访问次数和最后访问时间
- **日志系统**：保留最近访问日志（含 IP、城市、操作类型等），便于审计
- **直链支持**：可配置特定域名后缀，当上游返回 302 重定向时直接返回给客户端
- **WebSocket 支持**：自动处理 WebSocket 连接代理
- **管理界面**：提供 Web 管理面板，可视化管理所有配置

## 部署步骤

### 1. 准备工作

- 注册 [Cloudflare](https://www.cloudflare.com/) 账户
- 进入 Cloudflare Dashboard

### 2. 创建 D1 数据库

1. 进入 **Workers & Pages** → **D1 SQL Database**
2. 点击 **Create database**，数据库名称任意（例如：`proxy_db`）
3. 创建完成后记下数据库名称

### 3. 部署 Workers

1. 进入 **Workers & Pages** → **Create application** → **Create Worker**
2. 创建 Worker，名称任意（例如：`proxy-worker`）
3. 点击 **Quick Edit**，将 `worker.js` 的完整代码粘贴进去
4. 点击 **Save and Deploy**

### 4. 绑定 D1 数据库

1. 进入刚创建的 Worker 设置页面
2. 找到 **Settings** → **Variables and Secrets**
3. 在 **D1 Database Bindings** 部分点击 **Add binding**
4. **Variable name** 必须填写 `DB`（大写）
5. **D1 database** 选择刚才创建的数据库
6. 点击 **Save**

### 5. 设置管理员密码

1. 在 **Settings** → **Variables and Secrets** 页面
2. 在 **Environment Variables** 部分点击 **Add variable**
3. **Variable name** 填写 `ADMIN_PASSWORD`
4. **Value** 填写你的管理员密码（自定义，请妥善保管）
5. 勾选 **Encrypt**
6. 点击 **Save**

### 6. 完成部署

部署完成后，访问你的 Worker 地址（例如：`https://proxy-worker.your-account.workers.dev`）即可看到概览页面。

## 使用方法

### 管理后台

1. 访问 `https://your-worker-url/admin`
2. 使用你设置的 `ADMIN_PASSWORD` 登录
3. 在管理界面可以：
   - 添加/管理用户（入口）
   - 添加/删除白名单
   - 生成代理链接
   - 查看访问统计和日志
   - 配置直链域名后缀

### 代理请求格式

代理请求的 URL 格式为：

```
https://your-worker-url/{user}/{protocol}:/{host[:port]}{path}
```

**示例：**

- 代理 `https://example.com/api/data`：
  ```
  https://your-worker-url/ikun/https:/example.com/api/data
  ```

- 代理 `http://192.168.1.100:8096/web/index.html`：
  ```
  https://your-worker-url/ikun/http:/192.168.1.100:8096/web/index.html
  ```

**说明：**
- `{user}`：在管理后台创建的用户名（默认有 `ikun`）
- `{protocol}`：目标地址的协议（`http` 或 `https`）
- `{host[:port]}`：目标地址的域名或 IP（可选端口号）
- `{path}`：目标地址的路径部分（可选）

### 使用流程

1. **添加白名单**：在管理后台添加需要代理的目标地址（按 origin 匹配）
   - 支持格式：`example.com`、`https://example.com`、`example.com:8096` 等
   - 支持批量添加（逗号或换行分隔）

2. **生成链接**：使用管理后台的"入口链接生成"功能自动拼装代理 URL

3. **发起请求**：使用生成的代理 URL 访问目标服务

## 注意事项

- **数据库绑定**：D1 数据库的变量名必须是 `DB`（大写），否则无法正常工作
- **管理员密码**：请务必设置强密码，并妥善保管
- **白名单机制**：只有在白名单中的目标地址才能被代理访问
- **日志保留**：系统仅保留最近 2000 条日志，旧日志会自动删除
- **资源限制**：受 Cloudflare Workers 免费套餐限制，请勿滥用

## 免责声明

- **责任限制**：作者不对脚本可能导致的任何安全问题、数据损失、服务中断、法律纠纷或其他损害负责。使用此脚本需自行承担风险。

- **不当使用**：使用者需了解，本脚本可能被用于非法活动或未经授权的访问。作者强烈反对和谴责任何不当使用脚本的行为，并鼓励合法合规的使用。

- **合法性**：请确保遵守所有适用的法律、法规和政策，包括但不限于互联网使用政策、隐私法规和知识产权法。确保您拥有对目标地址的合法访问权限。

- **自担风险**：使用此脚本需自行承担风险。作者和 Cloudflare 不对脚本的滥用、不当使用或导致的任何损害承担责任。

**请确保在使用本脚本时遵守您所在地区的法律法规，使用者需自行承担相应的风险与责任。**

## 资源链接

- [Cloudflare Workers 文档](https://developers.cloudflare.com/workers/)
- [Cloudflare D1 文档](https://developers.cloudflare.com/d1/)

## 许可证

本项目采用 MIT 许可证。详细信息请参阅 [LICENSE](LICENSE) 文件。

---

如有问题或建议，欢迎提出 Issue 或贡献代码。
