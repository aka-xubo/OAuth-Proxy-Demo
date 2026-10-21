# Go 内存版 OAuth Proxy + MCP 演示

这是一个用于学习 OAuth 2.0、Dynamic Client Registration、PKCE 和 MCP 鉴权的本地多进程示例。当前默认链路是：

```text
Codex -> MCP Server -> OAuth Proxy A -> Authorization Server B
                                      （本地内存 Authorization Server）
```

项目包含三个相互独立的服务：

| 服务 | 作用 | 默认地址 |
| --- | --- | --- |
| `authorization-server` | 上游 OAuth Authorization Server，负责登录、授权和签发真实 Token | `http://127.0.0.1:8081` |
| `oauth-proxy` | 对 Codex 提供 OAuth 接口，向上游转发授权和换 Token | `http://127.0.0.1:8082` |
| `mcp-server` | OAuth 保护的 Streamable HTTP MCP Resource Server | `http://127.0.0.1:8080/mcp` |

三个服务没有共享业务 Go 类库依赖。MCP Server 通过 HTTP 调用 OAuth Proxy 的 introspection 接口验证 Bearer Token。

这是内存级教学实现：client、授权事务、authorization code、Token 和 introspection 映射都不持久化，进程重启后需要重新登录。

## 直接启动

所有本地演示参数都已经固定在 `cmd/*/main.go` 中，不需要设置环境变量。打开三个终端，分别执行：

终端 1：

```bash
go run ./cmd/authorization-server
```

终端 2：

```bash
go run ./cmd/oauth-proxy
```

终端 3：

```bash
go run ./cmd/mcp-server
```

启动后可以用浏览器检查服务状态：

```text
MCP：                         http://127.0.0.1:8080/mcp
Protected Resource Metadata：http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp
Proxy OAuth Metadata：        http://127.0.0.1:8082/.well-known/oauth-authorization-server
Proxy Dynamic Registration：  http://127.0.0.1:8082/oauth/register
Proxy Introspection：         http://127.0.0.1:8082/oauth/introspect
Upstream OAuth Server：       http://127.0.0.1:8081
```

Authorization Server 的教学账号是：

```text
用户名：demo
密码：oauth-demo
```

如果要改端口、issuer、共享密钥或上游地址，直接修改对应入口文件中的常量，然后重新启动相关服务即可。

## 在 Codex 中测试

三个服务都启动后，执行：

```bash
codex mcp add memory-oauth-demo --url http://127.0.0.1:8080/mcp
codex mcp login memory-oauth-demo
```

浏览器打开授权页面后，使用 `demo / oauth-demo` 登录并点击“允许”。登录完成后调用：

```text
请调用 memory-oauth-demo 的 whoami 工具。
```

也可以测试另外两个工具：

| 工具 | 行为 |
| --- | --- |
| `whoami` | 返回 Token 对应的用户、OAuth client 和 scopes |
| `echo` | 回显输入，并返回认证用户 |
| `add_to_counter` | 修改按用户隔离的内存计数器 |

## 代理做了什么

代理用于连接“不支持 Dynamic Client Registration”或不希望直接暴露给 Codex 的上游 Authorization Server。

本地示例中的固定上游 client 已由 Authorization Server 预置：

```text
client_id：memory-oauth-proxy
redirect_uri：http://127.0.0.1:8082/oauth/callback/upstream
```

代理不会生成自己的 authorization code，也不会生成自己的 access token。Codex 最终拿到的是上游 Authorization Server 签发的真实 access token。

### 授权和换 Token 时序

```text
1. Codex -> MCP Server /mcp
2. MCP Server -> 401，并返回 Protected Resource Metadata 地址
3. Codex -> Proxy 获取 OAuth metadata，并动态注册一个临时 client
4. Codex -> Proxy /oauth/authorize（携带 Codex 的 PKCE challenge）
5. Proxy -> 上游 Authorization Server /oauth/authorize（携带 opaque state）
6. 用户在上游页面登录并同意
7. 上游 -> Proxy /oauth/callback/upstream（返回上游 authorization code + state）
8. Proxy -> Codex 的 loopback redirect URI（原样转发上游 authorization code）
9. Codex -> Proxy /oauth/token（携带上游 code 和 code_verifier）
10. Proxy -> 上游 /oauth/token（翻译 client、redirect URI 和 PKCE 参数）
11. 上游 -> Proxy 返回真实 access_token
12. Proxy -> Codex 原样返回真实 access_token
13. Codex -> MCP Server 携带真实 Bearer Token
14. MCP Server -> Proxy /oauth/introspect 验证 Token 身份和 scopes
```

代理只在内存中保存 `opaque state -> Codex transaction` 映射，以及 Token 的摘要和身份映射。Codex 的动态 redirect URI 不会放进 state 明文，也不会传给上游注册。

## 外部上游 Authorization Server

把本地 Authorization Server 替换为外部上游时，仍只需要修改 `cmd/oauth-proxy/main.go` 中的固定常量：上游 authorize URL、token URL、固定 client ID、固定 client secret 和固定 callback URL。

外部上游必须预先注册下面这个 callback：

```text
http://127.0.0.1:8082/oauth/callback/upstream
```

外部上游如果不支持 PKCE，可以在 `cmd/oauth-proxy/main.go` 中关闭 `UpstreamPKCE`。Codex 到代理这一段仍然使用 PKCE。

## 多租户推荐模式

生产环境不要让 Codex 连接一个公共 MCP 地址，再通过自定义 Header 选择租户。推荐让 MCP URL 直接绑定租户：

```text
https://mcp.example.com/acme/mcp
```

用户在开放平台选择租户后，由平台展示该租户专属的 Codex 配置命令：

```bash
codex mcp add customer-acme --url https://mcp.example.com/acme/mcp
codex mcp login customer-acme
```

服务端应从规范化 URL 路径解析 `tenant=acme`，并让以下对象始终属于同一个租户：

```text
MCP resource
Protected Resource Metadata
OAuth issuer
authorization/token endpoint
introspection endpoint
Token 中的 resource/tenant
```

例如：

```text
MCP resource：             https://mcp.example.com/acme/mcp
OAuth issuer：             https://auth.example.com/acme
Authorization endpoint：   https://auth.example.com/acme/oauth/authorize
Token endpoint：           https://auth.example.com/acme/oauth/token
Introspection endpoint：   https://auth.example.com/acme/oauth/introspect
```

`issuer` 建议停在租户根路径 `https://auth.example.com/acme`，不要把 `/oauth` 本身作为 issuer，避免拼接出 `/oauth/oauth/authorize`。

## 代码结构

```text
cmd/authorization-server  # 独立上游 Authorization Server 入口
cmd/oauth-proxy           # 独立 OAuth 协议代理入口
cmd/mcp-server            # 独立 MCP Resource Server 入口
internal/oauthserver      # 仅 Authorization Server 使用
internal/oauthproxy       # 仅 OAuth Proxy 使用
internal/mcpserver        # 仅 MCP Server 使用，通过 HTTP introspection 验证 Token
```

## 安全边界

这是教学实现，不应直接部署到生产环境：

- 账号、client、授权事务和 Token 都在内存中，没有持久化或集群共享。
- DCR 是开放接口，没有 initial access token、软件声明或速率限制。
- 使用本地 HTTP 和固定共享密钥，只适合 loopback 开发环境。
- 没有 MFA、账户锁定、撤销端点、审计日志和管理后台。
- 生产环境应使用 HTTPS、成熟身份提供商、受保护的 DCR、持久化存储和更强的服务间认证。

## 验证

```bash
go test -race ./...
go vet ./...
```
