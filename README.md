# OAuthGuard — 第三方登录与账号合并安全改造

## 背景：被修复的漏洞

旧逻辑在第三方登录回调时，只要第三方返回的邮箱与站内某账号邮箱相同，就**自动合并**身份。
对于不验证邮箱的平台（或字段可被用户任意填写的平台），攻击者可以：

1. 在该平台用受害者的邮箱注册账号（平台不验证邮箱所有权）；
2. 用这个第三方账号登录本站；
3. 旧逻辑按“邮箱相同”自动合并，攻击者直接进入受害者账号 —— 账号接管。

## 修复后的核心规则

| 场景 | 旧行为（漏洞） | 新行为 |
|---|---|---|
| `(provider, uid)` 已绑定且 active | 直接登录 | 直接登录（身份归属只认这对键） |
| 身份已被安全隔离 | 仍可登录 | 拒绝登录并记录安全事件 |
| 未绑定 + 站内无同邮箱账号 | 注册 | 注册新账号 |
| 未绑定 + 站内**有**同邮箱账号 | **自动合并（漏洞）** | **绝不自动合并**，生成 `MergeRequest`，由账号持有人确认 |
| 平台不提供邮箱验证状态 | 往往默认“已验证” | 一律归一为 `unknown`，按未验证处理 |

关键纪律：

- **邮箱永远不用于自动归属账号**，只用于“是否需要发起人工确认”的判断。
- 即使平台明确返回“邮箱已验证”，撞上站内已有账号时仍然需要持有人确认 ——
  平台验证只能证明“对方控制了该邮箱在该平台的账号”，不能替代本站持有人的授权。
- 对外提示语统一，不泄露邮箱是否已注册（防账号枚举）。

## 邮箱验证状态的三态模型

`OAuth::ProviderProfile#email_verification` 只有三种取值：

- `verified` —— 平台以可信方式明确表示邮箱已验证；
- `unverified` —— 平台明确表示未验证；
- `unknown` —— 平台不提供验证状态，或字段缺失/无法解析。**安全上等同于未验证。**

各家平台的差异收敛在 `app/services/oauth/*_adapter.rb`，配置见 `config/providers.yml`：

| 平台 | 信号类型 | 处理方式 |
|---|---|---|
| Google | `email_verified` 布尔/字符串（OIDC id_token 或 userinfo） | 有标记按标记，缺失即 `unknown` |
| Apple | id_token `email_verified` 字符串 `"true"/"false"` | 同上，JWT 完整校验签名/iss/aud/exp |
| GitHub | 需调 `/user/emails` | 只承认 `verified=true && primary=true` 的主邮箱 |
| Facebook | 不提供验证状态 | 恒为 `unknown` |
| Microsoft | v2.0 无 `email_verified` | 恒为 `unknown` |
| LinkedIn | 邮箱接口无验证标记 | 恒为 `unknown` |
| Twitter | 默认不返回邮箱 | 邮箱为 `nil` + `unknown`，用占位邮箱注册 |
| 任意新平台 | 未证明可信前 | 兜底 `GenericAdapter` 恒为 `unknown` |

`true/"true"/1/"yes"` 等异构真值在 `BaseAdapter#truthy_flag?` 统一归一。

## 合并确认流程

1. 撞号时 `OAuth::LoginService` 创建一条 `pending` 的 `MergeRequest`，并给站内账号持有人发邮件。
2. 邮件含签名 token（`MergeRequest#signed_id`，Rails MessageVerifier，24h 过期，绑定 purpose）。
3. 持有人有两条确认路径：
   - 登录后在账号页点确认/拒绝（带 CSRF）；
   - 直接点邮件链接（签名 token 即授权，无需会话）。
4. `confirm!` 在事务内把外部身份建为指向目标账号的 **active** identity；`reject!` 仅关闭请求。
5. 同一 `(provider, uid, target_user)` 的 pending 请求去重，避免通知轰炸。
6. 全程写 `SecurityEvent` 审计日志（登录、拦截、合并请求的创建/确认/拒绝、隔离等）。

## 历史自动合并的排查

`app/services/audit/legacy_merge_audit.rb` 对存量 identity 分级：

- **high**：平台邮箱未验证/无验证信号，却按同邮箱自动合并进了站内账号（疑似接管）；
- **medium**：未验证且邮箱不一致，或账号只有单一第三方凭据、无密码；
- **low**：平台邮箱已验证且账号有独立凭据。

两种运行模式：

```bash
# 只出报告，不改数据
bin/rake security:audit_legacy_merges

# 把 high 风险身份置为 quarantined，并为账号持有人生成待确认的 MergeRequest
bin/rake security:quarantine_risky_merges
```

被隔离的身份在 `LoginService` 里直接拒绝登录（`oauth_login_blocked_quarantined`），
持有人通过正常确认流程复核后才会恢复。

## 目录结构

```
app/models/                user / identity / merge_request / security_event
app/services/oauth/
  login_service.rb         登录决策唯一入口（本修复的核心）
  link_service.rb          已登录用户主动绑定
  authorization_handler.rb state 防 CSRF、code 换 token 的编排
  provider_profile.rb      三态验证状态的值对象
  base_adapter.rb          适配器基类 + 真值归一
  *_adapter.rb             各家平台的字段映射与验证状态判定
  jwt_verifier.rb          RS256 JWT 校验（无外部 gem）
  client.rb                OAuth2 协议客户端，密钥只从环境变量取
app/services/audit/        历史合并排查
app/controllers/           oauth / sessions / merge_requests / identities / accounts
db/migrate/                users / identities / merge_requests / security_events
test/                      38 个单元与集成测试
tmp/smoke_integration.rb   端到端攻击链冒烟脚本
```

## 本地运行

```bash
bundle install
bin/rake db:create db:migrate db:seed
bin/puma -b tcp://127.0.0.1:3111     # 访问 http://127.0.0.1:3111/
```

开发/测试环境内置了 mock 授权服务器（`MockOAuthRegistry` + `MockOAuthTransport`），
种子数据预置了“攻击者在 Facebook 上注册受害者邮箱”的场景，可直接复现攻击被拦截的过程。

## 测试

```bash
bin/rake test                      # 38 个测试 / 115 断言
RAILS_ENV=test ruby tmp/smoke_integration.rb   # 17 项端到端攻击链检查
```

## 上线前还需在真实环境确认的事项

1. 各平台 `client_id/client_secret` 通过环境变量注入（`PROVIDER_CLIENT_ID/SECRET`），切勿入库。
2. 回调地址、state cookie 的 `SameSite`/`Secure` 属性按生产域名收紧。
3. 真实验证状态字段以各平台当前官方文档为准（适配器已隔离差异，改动局部化）。
4. 先以 `audit` 模式跑全量排查，人工复核 high 清单后再执行 `quarantine`。
5. 邮件模板中的链接域名走 `default_url_options`，生产环境配置实际主机名。
