# QCC-Auth 配置与运维手册

> 适用版本：qccauth 1.0.0（协议 `qcc-auth/1`）· Java 23+（JDK 24+ 自带 ML-DSA；无 BouncyCastle 也能运行）
> 本手册写给**接入 qccauth 的应用开发者与运维**：怎么配、怎么和 namespace 交叉核对、出了问题怎么查。
> 实际案例取自 qccemail（qccio.com 公开邮箱 / osnsg.com 企业邮箱）。

---

## 0. 一张图看懂

```
 钱包（只签名）            应用服务器（嵌入 qccauth）                       外部只读核对
 ─────────────            ────────────────────────────                    ─────────────────────────
                    ①     issue()  → 挑战 {app, chain, nonce, 有效期}
 ML-DSA-87 签名   ←───────
 QCA1|action|…    ───────→ verify(data)
                    ②       L1 验签：公钥推导出 address → 验证签名             （公钥：自带 / namespace /v1/pubkey）
                            L2 名称：≥ quorum 个 namespace 节点 MATCH  ─────→ namespace /v1/verify
                            L3 质押：≥ quorum 个链节点确认三要素       ─────→ QCC 链 /v1/pledge/{address}
                    ③     AuthInfo（是谁、名字是否属于他、质押多少、是否保留名）
                    ④     应用自己决定：账户、权限、额度、白名单 → 会话
                    ⑤     recheck(name, address) 定期复查
```

**一句话分工**：qccauth 只回答「签名者是谁、名字是不是他的、质押了多少」；**权限、额度、白名单全部由应用决定**。

| 层 | 核对什么 | 依据 | 失败状态 |
|---|---|---|---|
| L1 身份 | 签名是否由 address 的私钥产生 | 公钥 → 推导 address → ML-DSA-87 验签 | `BAD_SIGNATURE` `PUBKEY_MISMATCH` `NO_PUBKEY` |
| L2 名称 | 名字是否属于该 address | 多个 namespace 节点独立回答，失败优先 | `NAME_NOT_OWNED` / `NAMESPACE_UNAVAILABLE` |
| L3 质押 | 质押是否存在且达标 | 多个 QCC 链节点按三要素（address + tag + hash）确认 | `NOT_QUALIFIED` / `CHAIN_UNAVAILABLE` |

保留名（namespace Reserved 表指定的管理名，如 `admin.osn`）在 L2 返回 `reserved=true`，没有质押凭证，**跳过 L3**（可用 `allowReserved=false` 关闭）。

---

## 1. 依赖与打包

```bash
./gradlew selfTest            # 自测（模拟 namespace + 链，含保留名用例）
./gradlew libJar              # 纯库：build/libs/qccauth-1.0.0.jar（不含 demo / 自测）
./gradlew jar                 # 演示应用 fat jar：build/libs/qccauth.jar
```

应用工程（以 qccemail 为例）：

```groovy
dependencies {
    implementation files('libs/qccauth-1.0.0.jar')
}
```

- 不依赖 qccname 代码，只调用 namespace 与 QCC 链的 HTTP 接口。
- ML-DSA：优先 JDK 24+ 原生；有 BouncyCastle 时自动使用（反射加载）。没有 BC 时可删除 `BcMlDsa` / `DilithiumVerifier` 两个类。
- 升级 qccauth = 替换应用里的 jar 后重新打包应用；协议 `qcc-auth/1` 不变时客户端无需改动。

---

## 2. 最小接入

```java
QccAuthConfig cfg = new QccAuthConfig()               // 内置默认：公开实例节点、QCC、≥1 QCC、tag qccio
        .setApp("mail.qccio.com")                     // 必填，进入签名原文
        .setAppName("QCC Email")
        .setCallback("https://mail.qccio.com/v1/mail/login")
        .setTags(List.of("qcc"));                     // 只接受 .qcc 名字
QccAuth auth = new QccAuth(cfg);                      // 校验 + 快照
System.out.println(auth.config());                    // 启动时打印全部参数（运维核对用）

// 登录
QccAuth.Issued is = auth.issue("");                   // 挑战 JSON → 前端 / 钱包
AuthInfo info = auth.verify(dataFromWallet);          // 钱包提交的 data
if (info.ok()) {
    String account = info.name();                     // dev.qcc
    boolean reserved = info.reserved();               // 是否保留名
    BigDecimal qcc = info.amountUnits();              // 质押数量（保留名为 0）
    // → 应用自己的规则：账户映射、白名单、额度、会话
} else if (info.retryable()) {
    // NAMESPACE_UNAVAILABLE / CHAIN_UNAVAILABLE：nonce 保留，钱包原样重试
}

// 会话期间（建议 5–15 分钟）
AuthInfo r = auth.recheck(name, address);             // 名字被删 / 转走 / 冻结、质押撤销 → 非 OK
```

服务间调用（Java 客户端）：`QccAuthClient.login(link, "api.osn", QccAuthClient.mlDsa(priv, pub), false)`。

---

## 3. 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `app` | 无（必填） | 应用标识，进入签名原文；建议用域名。不同应用签名互不通用 |
| `appName` | 同 app | 钱包展示名 |
| `callback` | 空 | 钱包提交签名的地址（扫码 / 链接登录）；正式环境用 https |
| `ttlSeconds` | 120 | 挑战有效期 |
| `chain` | `6666` | 6666 测试网 / 9999 主网 |
| `pledgeCheck` | `true` | 是否核对链上质押；false 时只做 L1 + L2，amount = 0 |
| `allowReserved` | `true` | 保留名是否放行（跳过质押）；false 时保留名返回 `NOT_QUALIFIED` |
| `pledgeTag` | `qccio` | 质押所在 tag（namespace 注册质押） |
| `assetId` / `assetDecimals` / `minAmount` | `QCC` / `9` / `1000000000` | 鉴权资产、精度、最低质押（最小单位，1 QCC = 10⁹） |
| `tags` | `[]` | 接受的名字后缀，空 = 全部（**建议显式填写**） |
| `namespaceNodes` | 公开实例 4 台（9180） | namespace 节点（见第 4 节） |
| `namespaceQuorum` | `2` | 需要几个节点 MATCH |
| `discover` | `true` | 启动时从 `/v1/status` 成员表取全部节点（含 IPv6） |
| `chainNodes` | 6 台（9080） | QCC 链节点 |
| `chainQuorum` | `2` | 需要几个链节点确认 |

JSON 设置（只覆盖出现的字段，**拼错字段名直接报错**）：

```json
{
  "app": "mail.osnsg.com",
  "appName": "OSN Mail",
  "callback": "http://104.128.190.31:8081/v1/mail/login",
  "tags": ["osn"],
  "allowReserved": true,
  "namespaceNodes": ["http://66.154.109.124:9181", "http://107.174.172.115:9181",
                     "http://145.14.158.49:9181", "http://107.172.76.70:9181"],
  "namespaceQuorum": 2
}
```

```java
QccAuthConfig cfg = QccAuthConfig.fromJson(text);     // 或 cfg.setJson(text)
auth.reconfigure(cfg);                                // 运行中热切换（新快照立即生效）
```

---

## 4. 与 namespace 交叉核对（最关键）

### 4.1 先选对实例

namespace 有多个**独立实例**，每个实例一套节点、一份协议、各自负责一组后缀。**应用的 `namespaceNodes` 必须指向它所接受后缀所在的实例**，否则所有名字都会是「未注册」。

| 实例 | 后缀 | 端口 | 定位 | 应用典型配置 |
|---|---|---|---|---|
| `qccname-qccio` | `.qcc` | 9180 | 公开：人人可注册，先到先得 | `tags=["qcc"]`，默认节点即可 |
| `qccname-osnsg` | `.osn` `.osnsg` | 9181 | 企业：管理名由 OSN 在 Reserved 指定 | `tags=["osn"]`，**必须**配置 9181 节点 |

> **真实案例**：osnsg.com 邮件服务器 `auth.namespace.nodes` 留空 → 用了默认的 9180 公开实例 → `admin.osn 未注册`（`NAME_NOT_OWNED`）。改为 9181 节点后正常。
> 一个应用要同时接受两个实例的后缀时，部署两个 `QccAuth`（各自 tags + 节点），按名字后缀选用。

### 4.2 判定规则

- **失败优先**：任何一个节点回答「属于其他地址 / MISMATCH / REVOKED」→ 立即拒绝。
- **确认数**：≥ `namespaceQuorum` 个节点 MATCH，且各节点给出的质押凭证（creds）一致、保留名标记一致 → 通过。
- **未注册**：0 个 MATCH 且 ≥ quorum 个节点 NOT_FOUND → `NAME_NOT_OWNED`。
- **其他情况**（不可达、同步中、凭证不一致）→ `NAMESPACE_UNAVAILABLE`（可重试），**绝不误判为通过**。

### 4.3 节点与 quorum

- `discover=true`：启动时从任一节点的成员表取全部节点，配置里写 2–3 台作为入口即可。
- 应用服务器没有 IPv6 时，IPv6 冗余节点会「不可达」，只要 IPv4 节点 MATCH ≥ quorum 就不受影响。
- `namespaceQuorum` 建议 2（核心 ≥3 的实例）；对安全要求高的应用可设为「核心数 − 1」。

### 4.4 保留名

| 情况 | namespace 返回 | qccauth 结果 |
|---|---|---|
| 普通名字 | `reserved:false`，`creds:{qccio: txHash}` | L3 按三要素查链 |
| 保留名（如 `dev.osn`） | `reserved:true`，`creds:{}`，`reservedTx` | `allowReserved=true` → OK、`reserved=true`、amount=0 |
| 保留名被换人 / 冻结 | MISMATCH / NOT_FOUND | `recheck` → `NAME_NOT_OWNED`，会话作废 |

应用通常给保留名单独额度：qccemail 用 `quota.reserved.gb`（默认 10G）。

---

## 5. 按应用场景选配置

| 场景 | 推荐配置 | 应用侧规则 |
|---|---|---|
| 公开邮箱（qccio.com） | 公开实例，`tags=[qcc]`，`pledgeCheck=true` | 质押 1 QCC = 1G |
| 企业邮箱（osnsg.com） | 企业实例 9181，`tags=[osn]`，`allowReserved=true` | `auth_whitelist.txt` 白名单；保留名固定额度 |
| 企业内部系统 / 账本 | 企业实例，`pledgeCheck` 视需要 | 应用白名单 + 角色映射；`recheck` 间隔缩短到 1–5 分钟 |
| 游戏 / 社区 | 公开实例，`pledgeCheck=true`，可提高 `minAmount` | 质押越多等级越高（应用自定） |
| 只要身份、不要质押 | `pledgeCheck=false` | 适合内网工具、测试 |
| 服务间调用 | 任意实例 | `QccAuthClient.login(…)`，服务私钥放在服务器安全存储 |

**原则**：注册 namespace 名字 ≠ 能用你的应用。企业应用一定要配合白名单。

---

## 6. 协议 qcc-auth/1

**挑战（应用 → 钱包）**

```json
{"protocol":"qcc-auth/1","action":"login","chain":"6666","app":"mail.qccio.com","appName":"QCC Email",
 "name":"","nonce":"<64 hex>","issuedAt":1794041212363,"expiresAt":1794041332363,"callback":"https://…"}
```

**签名原文（字段顺序冻结）**：`QCA1|action|chain|app|name|address|nonce|issuedAt|expiresAt`
ML-DSA-87 纯模式、空 context，对 UTF-8 字节签名。

**响应（钱包 → callback）**

```json
{"protocol":"qcc-auth/1","action":"login","chain":"6666","app":"mail.qccio.com","name":"dev.qcc",
 "address":"Q…","nonce":"…","issuedAt":…,"expiresAt":…,"pubkey":"<可选>","sig":"<hex>"}
```

- `pubkey` 不进签名：真伪由「推导出 address」证明；不带时向 namespace `/v1/pubkey` 取。
- 出现未知字段即拒绝；nonce 一次性。

**结果**：`AuthInfo.toJson()` → `{"ok","status","retryable","reason","name","address","reserved","credentialHash","assetId","amount","amountUnits","namespace":"4/4","chain":"2/2","verifiedAt"}`

---

## 7. 状态码与处理

| status | 含义 | 客户端提示 / 处理 |
|---|---|---|
| `OK` | 通过 | 应用继续做白名单 / 权限判断 |
| `BAD_FORMAT` `WRONG_APP` `WRONG_CHAIN` `NAME_MISMATCH` `TAG_NOT_ALLOWED` | 请求不对 | 检查客户端版本、后缀是否被本应用接受 |
| `UNKNOWN_NONCE` `EXPIRED` | 挑战已用 / 过期 | 重新发起登录 |
| `BAD_ADDRESS` `NO_PUBKEY` `PUBKEY_MISMATCH` `BAD_SIGNATURE` | 身份不成立 | 换钱包 / 检查签名实现 |
| `NAME_NOT_OWNED` | 名字不属于该地址、未注册、已撤销 | **先确认 namespaceNodes 是否指向正确实例** |
| `NOT_QUALIFIED` | 质押不存在或不足；或保留名且 `allowReserved=false` | 提示质押门槛 |
| `NAMESPACE_UNAVAILABLE` `CHAIN_UNAVAILABLE` | 节点确认不足 | `retryable=true`：nonce 保留，原样重试 |

---

## 8. 会话与复查

qccauth 不管会话，但提供 `recheck`。推荐做法（qccemail 已实现）：

| 应用参数 | 建议 | 说明 |
|---|---|---|
| 会话有效期 | 24 小时 | token 只存服务器内存 |
| 复查间隔 | 10 分钟（企业系统 1–5 分钟） | 名字被删 / 冻结 / 换人、质押撤销 → 会话作废 |
| 宽限期 | 30 分钟 | 复查遇到 `*_UNAVAILABLE` 时继续放行的最长时间 |
| 客户端 | 会话不落盘、离开即注销 | 每次进入都要钱包签名 |

qccemail 对应配置：

```properties
auth.app=mail.osnsg.com
auth.tag.domains=osn:osnsg.com
auth.callback=http://104.128.190.31:8081/v1/mail/login
auth.namespace.nodes=http://66.154.109.124:9181,http://107.174.172.115:9181,http://145.14.158.49:9181,http://107.172.76.70:9181
auth.chain.nodes=
auth.session.hours=24
auth.recheck.minutes=10
auth.grace.minutes=30
quota.gb.per.qcc=1
quota.reserved.gb=10
```

---

## 9. 运维

### 9.1 上线前核对（在应用服务器上执行）

```bash
# namespace 实例是否正确、节点是否可达（端口按实例）
curl -s http://66.154.109.124:9181/v1/status | head -c 300
# 名字是否属于该地址（与 qccauth 的 L2 同一接口）
curl -s "http://66.154.109.124:9181/v1/verify?name=dev.osn&address=Q…"
# 质押三要素（L3 同一接口）
curl -s "http://<链节点>:9080/v1/pledge/<address>?tag=qccio&hash=<credentialHash>&minAmount=0"
# 时间同步（挑战有效期依赖时钟）
timedatectl | grep synchronized
```

### 9.2 日志

应用启动时打印 `auth.config()`（全部参数，含节点列表），每次鉴权建议记录 `info.toJson()`：
`namespace":"4/4"` 是确认节点数，`reason` 给出具体原因（例如「admin.osn 未注册」「链上质押 tag=qccio 确认（合格 2 / 不合格 0）」）。

### 9.3 常见故障

| 现象 | 原因 | 处理 |
|---|---|---|
| 所有名字 `NAME_NOT_OWNED`「未注册」 | namespaceNodes 指向了错误实例（如 .osn 应用连到 9180） | 改为正确实例节点，重启或 `reconfigure` |
| 保留名 `NOT_QUALIFIED`「没有质押凭证」 | qccauth 旧版本不识别 reserved，或 `allowReserved=false` | 升级 qccauth jar；检查配置 |
| 偶发 `NAMESPACE_UNAVAILABLE` | 节点重启 / Reserved 新版本同步中 | 客户端自动重试；持续出现时查节点 `qccname-check.sh` |
| 持续 `CHAIN_UNAVAILABLE` | 链节点不可达 / 返回 error | 检查 chainNodes、出网防火墙 |
| `EXPIRED` 频繁 | 服务器时钟偏差、钱包签名太慢 | NTP 同步；`ttlSeconds` 可放宽到 180 |
| `WRONG_APP` | 客户端用的 app 与服务器 `app` 不一致 | 两端统一（app 进入签名原文） |
| 登录后很快被踢 | 复查失败（名字被冻结 / 换人 / 质押撤销） | 正常行为；查 namespace `/v1/reserved` 与链上质押 |

### 9.4 升级

1. 替换应用里的 `qccauth-1.0.0.jar`，重新打包应用。
2. 逐台重启应用服务器（会话在内存中，重启后用户需重新签名登录）。
3. 启动日志核对 `auth.config()` 中的节点与参数。

---

## 10. 安全清单

- [ ] `app` 使用域名且各应用不同（签名不可跨应用重放）
- [ ] `tags` 显式填写，只接受本应用需要的后缀
- [ ] `namespaceNodes` 指向正确实例；`namespaceQuorum` ≥ 2
- [ ] 企业应用配合白名单；保留名额度 / 权限单独规定
- [ ] 正式环境 callback 使用 https（或 qccssl 安全通道，规划中）
- [ ] 服务器 NTP 同步
- [ ] 会话不在客户端落盘；离开应用即注销；服务器定期 `recheck`

---

## 附录 · 演示应用

```bash
java -jar qccauth.jar                         # 首次运行生成 qccauth.json（全部默认值）
# 把 callback 改成手机可访问的 http://本机IP:9280/auth/callback 后再运行
java -jar qccauth.jar config=qccauth.json port=9280
```

| 路径 | 作用 |
|---|---|
| `/` | 演示页：生成挑战、显示二维码、轮询结果 |
| `/auth/challenge` | 签发挑战 |
| `/auth/c/{nonce}` | 挑战链接（钱包扫码读取） |
| `/auth/callback` | 钱包提交签名 |
| `/auth/poll` | 浏览器轮询结果 |
