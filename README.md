# 第三方登录与账号合并安全重构

## 背景：原始漏洞

旧逻辑在第三方 OAuth 回调时，只要第三方返回的邮箱与站内账号邮箱相同，就**自动合并**并直接建立会话。
攻击者在一个**不验证邮箱所有权**的平台上用受害者邮箱注册，再用该平台登录本站，即直接进入受害者账号。

根因有两个：

1. 把"第三方返回了邮箱字符串"错误地等同于"登录者拥有该邮箱"；
2. 账号合并是静默自动的，已有账号的持有人完全不参与、不知情。

## 修复后的安全不变量

以下每条都有对应的自动化测试（见 `test/`）：

1. **已知且健康的身份**只登录它自己绑定的用户。
2. **被隔离（quarantine）的身份永远无法建立会话**。
3. **邮箱与已有账号相同，绝不自动合并、绝不建立会话**；只生成一条待确认请求（`AccountLinkRequest`）。
4. 确认强度取决于第三方是否真的验证了邮箱：
   - 可信且已验证 → 仍需**持有人在登录态下确认**（`login_token`）；
   - 未验证 / 无验证信号 / 无邮箱 → 必须**同时证明邮箱控制权 + 账号控制权**（`both`）。
5. 第三方 `(provider, uid)` 已绑定别的用户时，硬性报冲突（`IdentityConflict`），绝不重新挂载。
6. **不返回邮箱的平台（如微信）永远无法靠邮箱撞进已有账号**。

## 各家平台邮箱验证状态的差异（核心难点）

适配器把各家私有格式统一归一化成四种 `email_status`：
`verified` / `unverified` / `not_provided` / `not_requested`。

| 平台 | 邮箱来源 | 验证状态表达方式 | 适配器结论 |
|------|----------|------------------|------------|
| Google | OIDC ID Token | 布尔 `email_verified`（旧实现偶尔是字符串 `"true"`） | 仅显式为真才 `verified`；缺失为 `not_provided` |
| Apple | OIDC ID Token | **字符串** `"true"/"false"`；且邮箱只在首次授权返回 | 同上；二次登录无邮箱属正常，按 `(provider,uid)` 匹配 |
| GitHub | 非 OIDC，需两次 API | `/user` 的 email 不可信；只有 `/user/emails` 有 `verified` 标志 | 拿不到 emails 列表时一律 `not_provided` |
| Microsoft/Azure | ID Token | `email_verified` 常缺失；`upn`/`preferred_username` 不是所有权证明 | 无显式 claim 即 `not_provided` |
| Facebook | Graph `/me` | **完全不向第三方暴露验证标志** | 永远 `not_provided`（本次事故所属类别） |
| Twitter/X | verify_credentials / users/me | 不暴露验证标志 | 永远 `not_provided` |
| 微信 | sns/userinfo | **根本没有邮箱概念** | 永远 `not_requested`，无法参与邮箱匹配 |

> 硬规则：对"是否验证过"拿不准时，适配器只能返回 `not_provided`/`unverified`，**绝不返回 `verified`**。
> 平台能力清单集中在 `ProviderRegistry::PROFILES`，平台升级 API 时只改这一张表。

## 确认状态机（合并前必须持有人确认）

```
OAuth 回调
   │
   ├─ (provider,uid) 已存在且健康 ───────────────► 建立该用户会话
   ├─ 已存在但被隔离 ───────────────────────────► 403 拒绝
   ├─ (provider,uid) 已绑他人 + 邮箱属另一人 ───► IdentityConflict 硬阻断
   │
   └─ 新身份
        ├─ 邮箱命中已有账号 ─► 生成 AccountLinkRequest（不建会话、不建 identity）
        │     ├─ login_token：持有人登录态确认
        │     └─ both：先点邮件证明邮箱，再登录态确认
        └─ 无命中
              ├─ 可信平台已验证邮箱 ─► 直接注册并登录（signup）
              └─ 其他 ─► 注册为待验证壳用户，本站发验证邮件，验证前不可登录
```

确认令牌（token）安全设计：

- 令牌用 `SecureRandom.urlsafe_base64(32)` 生成，**库存 SHA-256 摘要**，库泄漏不可重放；
- 30 分钟过期；行级悲观锁防止并发点击；状态离开 `pending` 即失效；
- 登录态确认会校验 `current_user` 必须是目标账号持有人，否则 `WrongUser`；
- 全程写只增的 `audit_events` 审计表。

## 目录结构

```
lib/oauth_login/
  auth_info.rb                 # 归一化后的统一身份结构（含 email_status）
  provider_registry.rb         # 平台适配器与信任策略清单
  database.rb                  # ActiveRecord 连接与建表
  mailer.rb                    # 邮件边界（LogMailer 可在无 SMTP 下跑通全流程）
  adapters/                    # 各平台 payload -> AuthInfo
    base.rb google_adapter.rb apple_adapter.rb github_adapter.rb
    microsoft_adapter.rb facebook_adapter.rb twitter_wechat_adapters.rb
  models/                      # User / OAuthIdentity / AccountLinkRequest / AuditEvent
  services/
    provider_exchange.rb            # 进入安全逻辑前的唯一归一化入口
    login_service.rb                # 登录决策（安全不变量都在这里强制执行）
    link_confirmation_service.rb    # 两段式确认状态机
    historical_audit_service.rb     # 历史自动合并排查与隔离
  web/app.rb                   # Rack 演示应用（含 HMAC 签名 cookie 会话）
bin/
  setup_and_seed.rb            # 建库并播种含攻击样本的历史数据
  audit_merges.rb              # 历史排查 CLI（默认 dry-run，--apply 才隔离）
  demo_attack.rb               # 端到端攻击阻断演示
test/                          # 48 个测试，攻击场景逐条覆盖
```

## 常用操作

```bash
# 跑全部测试
for f in test/*_test.rb; do ruby -Itest -Ilib "$f"; done

# 播种演示库（含事故同款 facebook 自动合并样本）
ruby bin/setup_and_seed.rb db/demo.sqlite3

# 历史排查：只出报告，不改数据（critical 时退出码 2，便于接 CI/告警）
ruby bin/audit_merges.rb --db db/demo.sqlite3
ruby bin/audit_merges.rb --db db/demo.sqlite3 --json

# 确认报告后再执行隔离
ruby bin/audit_merges.rb --db db/demo.sqlite3 --apply

# 攻击阻断演示（纯内存）
ruby bin/demo_attack.rb
```

## 历史数据排查口径

`HistoricalAuditService` 对每条 `oauth_identities` 记录分级：

- **critical**：`auto_email_match` 且平台本身不提供可信验证信号（facebook/twitter/
  microsoft 无 claim 等），或快照明确记录为未验证 —— 这是最可能已被利用的账号；
- **high**：历史链接但没有任何验证快照（`legacy_unknown` / 状态为空），无法证明当时邮箱受控；
- **info**：修复后用 `confirmed`/`signup` 建立的链接，或历史记录里留存了可信 verified 快照。

`--apply` 会把 critical/high 置为 `quarantined=true` 并写审计事件；被隔离身份下次登录即被拦截，
需要走正常的持有人重新确认流程才能恢复（`identity_released`）。建议先在生产库做只读排查、
导出受影响用户清单，分批通知并隔离，而不是一次性全量切断。

## 接入真实 Rails 应用时的注意事项

1. 把 `Adapters` 挂到现有 OmniAuth callback 上：`request.env['omniauth.auth']` 的
   `raw_info`/`credentials` 作为 adapter 的 `payload`，其余安全逻辑可直接复用。
2. `LogMailer` 换成真实 ActionMailer；合并确认邮件必须发往**已有账号留存的邮箱**，
   不能只发第三方新返回的地址。
3. 会话 cookie 示例用 HMAC 签名；Rails 里直接用 session，切勿在回调阶段对争议账号写入 session。
4. 上线前对全量历史数据先跑只读 audit；新增的唯一索引 `(provider, uid)` 需先排查存量重复。
5. Apple 二次登录不带邮箱是正常现象，匹配只能依赖 `(provider, uid)`，不要回退到邮箱匹配。
