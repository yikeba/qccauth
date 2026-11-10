# QCC-Auth Integration & Operations Manual

> Applies to: qccauth 1.0.0 (protocol `qcc-auth/1`) · Java 23+ (JDK 24+ ships ML-DSA; runs without BouncyCastle)
> Written for **developers and operators integrating qccauth**: choosing an authentication tier, configuring it, cross-checking with namespace, and troubleshooting.
> Real cases come from qccemail (qccio.com public mail / osnsg.com company mail) and fChat (free sign-up → pledge upgrade).

---

## 0. The picture

```
 Wallet (signs only)       App server (embeds qccauth)                     Read-only external checks
 ───────────────────       ───────────────────────────                     ─────────────────────────
                    ①     issue()  → challenge {app, chain, nonce, expiry}
 ML-DSA-87 sign   ←───────
 QCA1|action|…    ───────→ verify(data)
                    ②       L1 signature: pubkey derives address → verify      (pubkey: supplied / namespace /v1/pubkey)
                            L2 name: ≥ quorum namespace nodes MATCH    ─────→ namespace /v1/verify
                            L3 pledge: ≥ quorum chain nodes confirm    ─────→ QCC chain /v1/pledge/{address}
                    ③     AuthInfo (who, does the name belong to them, how much pledged, reserved or not)
                    ④     The app decides: account, rights, quota, whitelist → session
                    ⑤     recheck(name, address) periodically
```

**Division of labour in one line**: qccauth only answers "who signed, is the name theirs, how much is pledged"; **rights, quotas and whitelists are entirely the app's decision**.

| Layer | What it checks | Basis | Failure status |
|---|---|---|---|
| L1 Identity | The signature was made by the address's private key | pubkey → derive address → ML-DSA-87 verify | `BAD_SIGNATURE` `PUBKEY_MISMATCH` `NO_PUBKEY` |
| L2 Name | The name belongs to that address | Several namespace nodes answer independently, failure first | `NAME_NOT_OWNED` / `NAMESPACE_UNAVAILABLE` |
| L3 Pledge | A pledge exists and meets the threshold | Several QCC chain nodes confirm by address + tag + hash | `NOT_QUALIFIED` / `CHAIN_UNAVAILABLE` |

Not every layer has to be on: `nameCheck` / `pledgeCheck` choose how far verification goes (section 3). Reserved names (management names set in the namespace Reserved table, e.g. `admin.osn`) return `reserved=true` at L2, carry no pledge credential and **skip L3** (turn off with `allowReserved=false`).

---

## 1. Dependency and packaging

```bash
./gradlew selfTest            # self test (mock namespace + chain, incl. reserved and signature-only cases)
./gradlew libJar              # library only: build/libs/qccauth-1.0.0.jar (no demo / self test)
./gradlew jar                 # demo app fat jar: build/libs/qccauth.jar
```

In the app project (qccemail as the example):

```groovy
dependencies {
    implementation files('libs/qccauth-1.0.0.jar')
}
```

- No dependency on qccname code; only the HTTP APIs of namespace and the QCC chain are called.
- ML-DSA: JDK 24+ native first; BouncyCastle is used automatically if present (loaded by reflection). Without BC you may delete the `BcMlDsa` / `DilithiumVerifier` classes.
- Upgrading qccauth = replace the jar in the app and rebuild the app; clients need no change while the protocol stays `qcc-auth/1`.

---

## 2. Minimal integration

```java
QccAuthConfig cfg = new QccAuthConfig()               // built-in defaults: public instance nodes, QCC, ≥1 QCC, tag qccio
        .setApp("mail.qccio.com")                     // required, part of the signed text
        .setAppName("QCC Email")
        .setCallback("https://mail.qccio.com/v1/mail/login")
        .setTags(List.of("qcc"));                     // accept .qcc names only
QccAuth auth = new QccAuth(cfg);                      // validate + snapshot
System.out.println(auth.config());                    // print every parameter at startup (for ops)

// login
QccAuth.Issued is = auth.issue("");                   // challenge JSON → front end / wallet
AuthInfo info = auth.verify(dataFromWallet);          // data submitted by the wallet
if (info.ok()) {
    String account = info.name();                     // dev.qcc (empty in signature-only mode: use info.address())
    boolean reserved = info.reserved();               // reserved name or not
    BigDecimal qcc = info.amountUnits();              // pledged amount (0 for reserved names / pledge not checked)
    // → the app's own rules: account mapping, whitelist, quota, session
} else if (info.retryable()) {
    // NAMESPACE_UNAVAILABLE / CHAIN_UNAVAILABLE: nonce kept, the wallet retries as is
}

// during the session (every 5–15 minutes)
AuthInfo r = auth.recheck(name, address);             // name deleted / moved / frozen, pledge withdrawn → not OK
```

Service-to-service (Java client): `QccAuthClient.login(link, "api.osn", QccAuthClient.mlDsa(priv, pub), false)`.

---

## 3. Authentication tiers: from free sign-up to pledge upgrade

One component, three configurations. **The tier decides "how much is proven", not "which features are unlocked".**

| Tier | Config | What is proven | On-chain cost | Typical use |
|---|---|---|---|---|
| Signature | `nameCheck=false`, `pledgeCheck=false` | The signer holds the ML-DSA-87 key of the address (address = account) | **0**: no namespace, no chain | Free sign-up, user acquisition, internal tools |
| Signature + name | `nameCheck=true`, `pledgeCheck=false` | Plus: the name (e.g. `wang.qcc`) belongs to the address | Once, when the name is registered | Communities and company apps that need readable accounts |
| Signature + name + pledge (default) | `nameCheck=true`, `pledgeCheck=true` | Plus: an address + tag + hash pledge exists on chain and meets the threshold | The user's pledge | Paid features, quotas, anti-abuse |

### 3.1 Signature only (nameCheck=false)

```java
QccAuth auth = new QccAuth(new QccAuthConfig()
        .setApp("fchat.app")
        .setNameCheck(false)
        .setPledgeCheck(false)                        // required: pledge credentials come from namespace names
        .setNamespaceNodes(List.of()));               // may be empty: namespace is not contacted
```

- The challenge carries no name; the wallet submits an empty `name`. Even if the wallet sends a name, the result's `name` is empty — **an unverified name is never trusted**.
- There is no namespace to look up the public key, so the wallet **must include `pubkey`**, otherwise `NO_PUBKEY`.
- `AuthInfo`: `name=""`, `address=Q…`, `amount=0`, all node counts 0. The app uses `address` as the account key.
- `recheck`: OK whenever the address is well-formed — there is no on-chain state to revoke. Banning an account is the app's own account table's job.

### 3.2 Upgrade path (fChat as the example)

1. **Free sign-up**: signature tier, wallet address = account, zero on-chain cost, unlimited scale.
2. **Named upgrade**: the user registers `name.fchat` in namespace. The app binds the name to the existing account (same address) and can then use a second `QccAuth` instance on the signature + name tier.
3. **Paid upgrade**: the user pledges. The app reads `AuthInfo.amountUnits()` to set the level.

> **Do not upgrade by raising `minAmount`**: once the threshold changes, every user below it fails authentication **at the same time** on the next `recheck`. Keep the authentication threshold at its lowest (it may be 0) and let the app grade features by reading `amount`.

An app serving several tiers at once runs several `QccAuth` instances (each with its own config) and picks one by the user's current tier; the account key is always `address`.

### 3.3 Why a zero-amount pledge still authenticates

L3 proves that "the address holder personally signed an on-chain binding between the address and the app's tag, verifiable by any node and revocable". The amount only adds a cost barrier and an economic return (interest goes to the app's tag owner). So `minAmount=0` is logically sound. But the pledge transaction itself pays gas: a wallet holding zero assets cannot send it — free users should stay on the signature tier rather than make a zero-amount pledge.

---

## 4. Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `app` | none (required) | App identifier, part of the signed text; use a domain. Signatures never work across apps |
| `appName` | same as app | Name shown in the wallet |
| `callback` | empty | Where the wallet submits the signature (QR / link login); use https in production |
| `ttlSeconds` | 120 | Challenge lifetime |
| `chain` | `6666` | 6666 testnet / 9999 mainnet |
| `nameCheck` | `true` | Check the namespace name; false = signature only, address = account (requires `pledgeCheck=false`) |
| `pledgeCheck` | `true` | Check the on-chain pledge; false = L1 + L2 only, amount = 0 |
| `allowReserved` | `true` | Let reserved names pass (skipping the pledge); false makes them `NOT_QUALIFIED` |
| `pledgeTag` | `qccio` | Tag holding the pledge (namespace registration pledge) |
| `assetId` / `assetDecimals` / `minAmount` | `QCC` / `9` / `1000000000` | Asset, decimals, minimum pledge (smallest unit, 1 QCC = 10⁹; may be 0) |
| `tags` | `[]` | Accepted name suffixes, empty = all (**set it explicitly**) |
| `namespaceNodes` | 4 public-instance nodes (9180) | Namespace nodes (section 5); may be empty when `nameCheck=false` |
| `namespaceQuorum` | `2` | How many nodes must MATCH |
| `discover` | `true` | Load all nodes (incl. IPv6) from the `/v1/status` member table at startup |
| `chainNodes` | 6 nodes (9080) | QCC chain nodes |
| `chainQuorum` | `2` | How many chain nodes must confirm |

Configure by JSON (only the fields present are overwritten; **a misspelled field name is an error**):

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
QccAuthConfig cfg = QccAuthConfig.fromJson(text);     // or cfg.setJson(text)
auth.reconfigure(cfg);                                // hot swap at runtime (new snapshot takes effect immediately)
```

---

## 5. Cross-checking with namespace (the key part)

### 5.1 Pick the right instance first

Namespace runs several **independent instances**; each has its own nodes, its own protocol and its own set of suffixes. **An app's `namespaceNodes` must point at the instance that owns the suffixes it accepts**, otherwise every name comes back "not registered".

| Instance | Suffix | Port | Nature | Typical app config |
|---|---|---|---|---|
| `qccname-qccio` | `.qcc` | 9180 | Public: anyone may register, first come first served | `tags=["qcc"]`, default nodes |
| `qccname-osnsg` | `.osn` `.osnsg` | 9181 | Enterprise: management names set by OSN in Reserved | `tags=["osn"]`, 9181 nodes **required** |

> **Real case**: the osnsg.com mail server left `auth.namespace.nodes` empty → it used the default 9180 public instance → `admin.osn not registered` (`NAME_NOT_OWNED`). Pointing it at the 9181 nodes fixed it.
> An app accepting suffixes from both instances runs two `QccAuth` objects (each with its own tags + nodes) and picks one by the name suffix.

### 5.2 Decision rules

- **Failure first**: any node answering "belongs to another address / MISMATCH / REVOKED" → reject immediately.
- **Confirmations**: ≥ `namespaceQuorum` nodes MATCH with identical pledge credentials (creds) and reserved flag → pass.
- **Not registered**: 0 MATCH and ≥ quorum nodes NOT_FOUND → `NAME_NOT_OWNED`.
- **Anything else** (unreachable, syncing, inconsistent credentials) → `NAMESPACE_UNAVAILABLE` (retryable), **never a false pass**.

### 5.3 Nodes and quorum

- `discover=true`: all nodes are loaded from any node's member table at startup; 2–3 entry nodes in the config are enough.
- If the app server has no IPv6, IPv6 standby nodes show as unreachable; as long as IPv4 MATCH ≥ quorum nothing changes.
- `namespaceQuorum` 2 is recommended (instances with ≥3 cores); high-security apps may use "cores − 1".

### 5.4 Reserved names

| Case | Namespace returns | qccauth result |
|---|---|---|
| Ordinary name | `reserved:false`, `creds:{qccio: txHash}` | L3 checks the chain by the three elements |
| Reserved name (e.g. `dev.osn`) | `reserved:true`, `creds:{}`, `reservedTx` | `allowReserved=true` → OK, `reserved=true`, amount=0 |
| Reserved name reassigned / frozen | MISMATCH / NOT_FOUND | `recheck` → `NAME_NOT_OWNED`, session ends |

Apps usually give reserved names their own quota: qccemail uses `quota.reserved.gb` (default 10 GB).

---

## 6. Configuration by scenario

| Scenario | Recommended config | App-side rules |
|---|---|---|
| Public mail (qccio.com) | Public instance, `tags=[qcc]`, `pledgeCheck=true` | 1 QCC pledged = 1 GB |
| Company mail (osnsg.com) | Enterprise instance 9181, `tags=[osn]`, `allowReserved=true` | `auth_whitelist.txt` whitelist; fixed quota for reserved names |
| Internal systems / ledger | Enterprise instance, `pledgeCheck` as needed | App whitelist + role mapping; `recheck` every 1–5 minutes |
| Messaging, fChat (free sign-up) | `nameCheck=false`, `pledgeCheck=false` | Address = account; move to the name / pledge tier on upgrade (section 3) |
| Games / communities | Public instance, `pledgeCheck=true`, keep `minAmount` low | Grade by `amount` (app-defined) |
| Name, no pledge | `pledgeCheck=false` | Internal tools, testing |
| Service to service | Any instance | `QccAuthClient.login(…)`; keep the service key in the server's secure store |

**Principle**: holding a namespace name ≠ access to your app. Company apps must use a whitelist.

---

## 7. Protocol qcc-auth/1

**Challenge (app → wallet)**

```json
{"protocol":"qcc-auth/1","action":"login","chain":"6666","app":"mail.qccio.com","appName":"QCC Email",
 "name":"","nonce":"<64 hex>","issuedAt":1794041212363,"expiresAt":1794041332363,"callback":"https://…"}
```

**Signed text (field order frozen)**: `QCA1|action|chain|app|name|address|nonce|issuedAt|expiresAt`
ML-DSA-87 pure mode, empty context, over the UTF-8 bytes. On the signature tier `name` is the empty string: `…|app||address|…`.

**Response (wallet → callback)**

```json
{"protocol":"qcc-auth/1","action":"login","chain":"6666","app":"mail.qccio.com","name":"dev.qcc",
 "address":"Q…","nonce":"…","issuedAt":…,"expiresAt":…,"pubkey":"<optional>","sig":"<hex>"}
```

- `pubkey` is not signed: its authenticity is proven by deriving the address; if absent it is fetched from namespace `/v1/pubkey` (mandatory on the signature tier).
- Unknown fields are rejected; nonces are single-use.

**Result**: `AuthInfo.toJson()` → `{"ok","status","retryable","reason","name","address","reserved","credentialHash","assetId","amount","amountUnits","namespace":"4/4","chain":"2/2","verifiedAt"}`

---

## 8. Status codes

| status | Meaning | Client message / action |
|---|---|---|
| `OK` | Passed | The app goes on with whitelist / rights |
| `BAD_FORMAT` `WRONG_APP` `WRONG_CHAIN` `NAME_MISMATCH` `TAG_NOT_ALLOWED` | Bad request (incl. an empty name sent to an app that needs one) | Check the client version and whether the suffix is accepted |
| `UNKNOWN_NONCE` `EXPIRED` | Challenge used / expired | Start the login again |
| `BAD_ADDRESS` `NO_PUBKEY` `PUBKEY_MISMATCH` `BAD_SIGNATURE` | Identity not established | Check the wallet / signing code; on the signature tier, check that pubkey is sent |
| `NAME_NOT_OWNED` | Name not owned by the address, unregistered or revoked | **First check that namespaceNodes points at the right instance** |
| `NOT_QUALIFIED` | Pledge missing or too small; or a reserved name with `allowReserved=false` | Show the pledge requirement |
| `NAMESPACE_UNAVAILABLE` `CHAIN_UNAVAILABLE` | Not enough node confirmations | `retryable=true`: nonce kept, retry as is |

---

## 9. Sessions and rechecks

qccauth does not manage sessions but offers `recheck`. Recommended practice (implemented in qccemail):

| App parameter | Suggested | Notes |
|---|---|---|
| Session lifetime | 24 hours | Tokens live only in server memory |
| Recheck interval | 10 minutes (company systems 1–5) | Name deleted / frozen / reassigned, pledge withdrawn → session ends |
| Grace period | 30 minutes | Longest time to keep allowing access when a recheck hits `*_UNAVAILABLE` |
| Client | Session never written to disk; logout on leaving | Every entry requires a wallet signature |

Matching qccemail config:

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

## 10. Operations

### 10.1 Pre-launch checks (run on the app server)

```bash
# right namespace instance, nodes reachable (port per instance)
curl -s http://66.154.109.124:9181/v1/status | head -c 300
# does the name belong to the address (same API as qccauth L2)
curl -s "http://66.154.109.124:9181/v1/verify?name=dev.osn&address=Q…"
# pledge by the three elements (same API as L3)
curl -s "http://<chain node>:9080/v1/pledge/<address>?tag=qccio&hash=<credentialHash>&minAmount=0"
# clock sync (challenge lifetime depends on it)
timedatectl | grep synchronized
```

### 10.2 Logs

Print `auth.config()` at startup (every parameter incl. node lists) and log `info.toJson()` for every authentication:
`namespace":"4/4"` is the confirmation count, `reason` gives the concrete cause (e.g. "admin.osn not registered", "pledge tag=qccio confirmed (qualified 2 / not 0)").

### 10.3 Common problems

| Symptom | Cause | Fix |
|---|---|---|
| Every name `NAME_NOT_OWNED` "not registered" | namespaceNodes points at the wrong instance (e.g. a .osn app on 9180) | Use the right instance's nodes; restart or `reconfigure` |
| Reserved name `NOT_QUALIFIED` "no pledge credential" | Old qccauth that doesn't know reserved, or `allowReserved=false` | Upgrade the qccauth jar; check config |
| Signature tier: every login `NO_PUBKEY` | The wallet submits without pubkey | Send `pubkey` from the wallet (there is no namespace to look it up) |
| Occasional `NAMESPACE_UNAVAILABLE` | Node restart / new Reserved version syncing | The client retries; if persistent, run `qccname-check.sh` on the nodes |
| Persistent `CHAIN_UNAVAILABLE` | Chain nodes unreachable / returning errors | Check chainNodes and the outbound firewall |
| Frequent `EXPIRED` | Server clock drift, slow wallet signing | NTP; `ttlSeconds` may go up to 180 |
| `WRONG_APP` | The client's app differs from the server's `app` | Align both sides (app is in the signed text) |
| Logged out soon after login | A recheck failed (name frozen / reassigned / pledge withdrawn) | Expected; check namespace `/v1/reserved` and the chain pledge |
| Many users drop after raising `minAmount` | The threshold was used as a feature level | Revert the threshold; grade by `amount` in the app (section 3.2) |

### 10.4 Upgrading

1. Replace `qccauth-1.0.0.jar` in the app and rebuild the app.
2. Restart app servers one by one (sessions are in memory; users sign in again after a restart).
3. Check the nodes and parameters in the startup `auth.config()` output.

---

## 11. Security checklist

- [ ] `app` is a domain and differs per app (signatures cannot be replayed across apps)
- [ ] `tags` set explicitly, accepting only the suffixes the app needs
- [ ] `namespaceNodes` points at the right instance; `namespaceQuorum` ≥ 2
- [ ] Signature tier: the account key is `address`; never use the name the wallet submits
- [ ] Company apps use a whitelist; reserved names get their own quota / rights
- [ ] Production callback over https (or a qccssl secure channel, planned)
- [ ] Servers synchronised by NTP
- [ ] Sessions never stored on the client; logout on leaving; servers `recheck` periodically

---

## Appendix · Demo app

```bash
java -jar qccauth.jar                         # first run writes qccauth.json (all defaults)
# set callback to http://<LAN IP>:9280/auth/callback so a phone can reach it, then run
java -jar qccauth.jar config=qccauth.json port=9280
```

| Path | Purpose |
|---|---|
| `/` | Demo page: issue a challenge, show the QR code, poll the result |
| `/auth/challenge` | Issue a challenge |
| `/auth/c/{nonce}` | Challenge link (read by the wallet's scanner) |
| `/auth/callback` | The wallet submits its signature |
| `/auth/poll` | The browser polls for the result |
