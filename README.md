# QCC-Auth

QCC 钱包签名鉴权组件。任何应用依赖它、给一份配置，就能用 **namespace 名称**（如 `chen.qcc`）作为账户登录。
应用不存密码，也不需要自己连公链做复杂处理；不依赖 qccname 代码，只调用 namespace 与 QCC 公链的 HTTP 接口。

> 完整的配置与运维手册（参数、与 namespace 交叉核对、场景配置、状态码、故障排查）：[docs/QCCAUTH.md](docs/QCCAUTH.md)

## 角色

| | 职责 |
|---|---|
| 客户端（钱包） | 只签名，提交 name + address（公钥可选），不保存 txHash |
| namespace 节点 | 名称核对：name ↔ address；附带链上凭证 creds = {质押 tag: txHash} |
| QCC 公链 | 质押事实：三要素 address + tag + hash，O(1) |
| 应用（本组件） | L1 验签 → L2 多节点名称核对 → L3 按配置的门槛查链 |

## 接入

```java
QccAuthConfig cfg = new QccAuthConfig();              // 内置默认值：资产 QCC、最低 1 QCC、qccio、默认节点
cfg.setApp("mail.qccio.com").setCallback("https://mail.qccio.com/qccauth/callback");
System.out.println(cfg);                              // 打印全部参数
// cfg.setJson(text);                                 // 或用 JSON 设置（只覆盖出现的字段，拼错字段名报错）
QccAuth auth = new QccAuth(cfg);                      // 校验 + 快照；运行中换参数用 auth.reconfigure(cfg)

Issued   is   = auth.issue("");                       // 挑战 → 前端 / 钱包
AuthInfo info = auth.verify(data);                    // 钱包提交的 data → 鉴权信息
Poll     p    = auth.poll(token);                     // 扫码 / 链接登录时浏览器轮询
AuthInfo now  = auth.recheck(name, address);          // 会话期间复查
```

**鉴权信息 AuthInfo**（不是 true / false）：`status`、`name`、`address`、`assetId`、`amount`（最小单位）、
`amountUnits()`（折合资产数，如 10 QCC）、`credentialHash`、namespace / 链确认节点数、`verifiedAt`，`toJson()` 可存档。

**鉴权只回答"是谁、名字是否属于他、质押了多少"，不管应用权限。** 权限、等级、额度由应用自己按 AuthInfo 决定，例如 qccemail：
```java
long gb = info.amountUnits().longValue();             // 每 1 QCC 质押 = 1G 邮箱空间（应用自己的规则）
```

**鉴权数据结构 AuthRequest**（可脱离 QccAuth 单独使用）：
```java
AuthRequest req = AuthRequest.parse(data);            // 严格解析客户端 data
AuthRequest.L1 r = req.verify(resolver);              // 公钥（自带或拉取）→ 推导核对 address → 验签
```

完整示例：`qcc.auth.demo.AuthDemoServer`（`./gradlew demo` 或 `java -jar qccauth.jar`）。
Java 客户端 / 服务间鉴权：`QccAuthClient.login(link, "api.osn", QccAuthClient.mlDsa(priv, pub), false)`。

## 参数（默认值）

| 参数 | 默认 | 说明 |
|---|---|---|
| app | 无，必须设置 | 进入签名原文，区分应用 |
| appName / callback | 空 | 钱包展示名 / 钱包提交地址 |
| ttlSeconds | 120 | 登录请求有效期 |
| chain | 6666 | 6666 测试网 / 9999 主网 |
| pledgeCheck | true | 是否向公链核对质押；false 时只做签名 + 名称，amount = 0 |
| pledgeTag | qccio | 质押所在 tag |
| assetId / assetDecimals / minAmount | QCC / 9 / 1000000000 | 鉴权资产、精度、最低质押（最小单位） |
| tags | [] | 接受的名字后缀，空 = 全部 |
| allowReserved | true | 保留名（namespace Reserved 指定，无质押）是否放行；放行时跳过质押、`AuthInfo.reserved=true` |
| namespaceNodes / namespaceQuorum / discover | 公开实例 4 台（9180）/ 2 / true | namespace 节点；企业实例（如 .osn，9181）必须显式配置 |
| chainNodes / chainQuorum | 6 台 / 2 | QCC 链节点 |

## 协议 qcc-auth/1

**挑战（应用 → 钱包）**
```json
{"protocol":"qcc-auth/1","action":"login","chain":"6666","app":"mail.qccio.com","appName":"QCC Email",
 "name":"","nonce":"<64 hex>","issuedAt":1794041212363,"expiresAt":1794041332363,"callback":"https://…/qccauth/callback"}
```
**签名原文（字段顺序冻结）**：`QCA1|action|chain|app|name|address|nonce|issuedAt|expiresAt`
ML-DSA-87 纯模式、空 context，对 UTF-8 字节签名。

**响应（钱包 → callback）**
```json
{"protocol":"qcc-auth/1","action":"login","chain":"6666","app":"mail.qccio.com","name":"chen.qcc",
 "address":"Q…","nonce":"…","issuedAt":…,"expiresAt":…,"pubkey":"<可选>","sig":"<hex>"}
```
pubkey 不进签名：真伪靠"推导出 address"证明；不带时应用向 namespace `/v1/pubkey` 取。出现未知字段即拒绝。

**结果** AuthInfo.toJson()：`{"ok","status","retryable","reason","name","address","credentialHash","assetId","amount","amountUnits",…}`

| status | 含义 |
|---|---|
| OK | 通过 |
| BAD_FORMAT / WRONG_APP / WRONG_CHAIN / UNKNOWN_NONCE / EXPIRED / NAME_MISMATCH / TAG_NOT_ALLOWED | 请求不对（不会作废真实用户的登录请求） |
| BAD_ADDRESS / NO_PUBKEY / PUBKEY_MISMATCH / BAD_SIGNATURE | L1 身份不成立 |
| NAME_NOT_OWNED | L2 名字不属于该地址 / 未注册 / 已撤销 |
| NOT_QUALIFIED | L3 质押不存在或低于门槛 |
| NAMESPACE_UNAVAILABLE / CHAIN_UNAVAILABLE | 节点确认不足，`retryable=true`，nonce 保留，钱包原样重试 |

## 判定规则

- namespace：≥ quorum 个 MATCH 且 creds 一致；任一节点显示其他持有人 / REVOKED / MISMATCH → 拒绝（失败优先）。
- 链：只有 `ok:true` 且 data 是带 `exists` 的对象才算回答；`"error"`、`"{}"`、结构不符一律算不可达，
  绝不当成"无质押"。合格 ≥ quorum 且 合格 > 不合格 → 合格。门槛在本地比较。

## 已知边界

- 扫码 / 链接登录的转发钓鱼：钱包展示 app 与提交地址 + 120 秒有效期缓解。
- 测试期 callback 可为 http；正式环境用 https，或等安全通道（ML-KEM-1024 + AES-GCM，下一步）。

## 源码结构

```
qcc/auth/           QccAuth  QccAuthConfig  AuthRequest  AuthInfo  NamespaceClient  ChainClient  QccAuthClient  AuthSelfTest
qcc/auth/crypto/    MlDsa87  JdkMlDsa  BcMlDsa  DilithiumVerifier  QccAddress  Sha3
qcc/auth/json/      StrictJson  Json
qcc/auth/demo/      AuthDemoServer
```
无 BC 时删除 `BcMlDsa` / `DilithiumVerifier` 即可（反射加载，自动退回 JDK 24+ 原生）。
