package qcc.auth;

import qcc.auth.crypto.Sha3;
import qcc.auth.json.Json;
import qcc.auth.json.StrictJson;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * qcc-auth/1 鉴权组件（应用侧）。只负责鉴权并返回鉴权信息 {@link AuthInfo}，不管应用的权限体系。
 *
 * <pre>
 *   QccAuthConfig cfg = new QccAuthConfig().setApp("mail.qccio.com");   // 其余用默认值
 *   QccAuth auth = new QccAuth(cfg);
 *
 *   Issued is     = auth.issue("");            // 1. 挑战：给前端 / 钱包；pollToken 只留给发起的浏览器
 *   AuthInfo info = auth.verify(data);         // 2. 钱包提交的 data → 鉴权信息
 *   Poll p        = auth.poll(pollToken);      // 3. 浏览器轮询（扫码 / 链接登录）
 *   AuthInfo now  = auth.recheck(name, addr);  // 4. 会话期间复查（名字 / 质押被撤销即失效）
 * </pre>
 *
 * 鉴权层级由配置决定：
 *   nameCheck=false                  只做 L1（地址即账号，零链上成本，适合免费注册 / 引流）
 *   nameCheck=true,  pledgeCheck=false  L1 + L2
 *   nameCheck=true,  pledgeCheck=true   L1 + L2 + L3（默认）
 *
 * 核对顺序（失败即停，失败优先）：
 *   请求  protocol / chain / app / nonce 一次性 / 有效期 / 名字后缀
 *   L1    AuthRequest.verify：公钥（自带或向 namespace 拉取）推导出 address + ML-DSA-87 验签
 *   L2    namespace 多节点：名字属于该地址，取得链上凭证 credentialHash
 *   L3    QCC 公链多节点：address + pledgeTag + credentialHash 三要素，资产与最低数量，取得质押数量
 */
public final class QccAuth {

    /** 挑战：应用 → 钱包。name 为空表示由用户在钱包里选自己的名字。 */
    public record Challenge(String app, String appName, String action, String chain, String name,
                            String nonce, long issuedAt, long expiresAt, String callback) {
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("protocol", AuthRequest.PROTOCOL);
            m.put("action", action);
            m.put("chain", chain);
            m.put("app", app);
            m.put("appName", appName);
            m.put("name", name);
            m.put("nonce", nonce);
            m.put("issuedAt", issuedAt);
            m.put("expiresAt", expiresAt);
            if (callback != null && !callback.isEmpty()) m.put("callback", callback);
            return m;
        }
        public String json() { return Json.write(toMap()); }

        public static Challenge fromMap(Map<String, Object> j) {
            if (!AuthRequest.PROTOCOL.equals(StrictJson.str(j, "protocol"))) throw new IllegalArgumentException("不是 " + AuthRequest.PROTOCOL + " 挑战");
            return new Challenge(StrictJson.str(j, "app"), j.get("appName") instanceof String s ? s : StrictJson.str(j, "app"),
                    StrictJson.str(j, "action"), StrictJson.str(j, "chain"), StrictJson.strAllowEmpty(j, "name"),
                    StrictJson.str(j, "nonce"), StrictJson.num(j, "issuedAt"), StrictJson.num(j, "expiresAt"),
                    j.get("callback") instanceof String c ? c : "");
        }
    }

    public record Issued(Challenge challenge, String pollToken) {}

    public enum PollState { PENDING, DONE, EXPIRED, UNKNOWN }
    public record Poll(PollState state, AuthInfo info) {}

    private static final int MAX_PENDING = 20_000;

    private static final class Entry {
        final Challenge ch;
        final String pollToken;
        volatile boolean claimed;    // 验签通过，nonce 已占用
        volatile AuthInfo info;      // 最终结果
        Entry(Challenge ch, String pollToken) { this.ch = ch; this.pollToken = pollToken; }
    }

    private volatile QccAuthConfig cfg;
    private volatile NamespaceClient namespace;      // nameCheck=false 时为 null
    private volatile ChainClient chain;              // pledgeCheck=false 时为 null
    private final LongSupplier clock;
    private final SecureRandom rnd = new SecureRandom();
    private final Map<String, Entry> byNonce = new ConcurrentHashMap<>();
    private final Map<String, Entry> byPoll  = new ConcurrentHashMap<>();

    /** 用参数对象初始化：先校验，再取快照（之后修改 cfg 不影响本对象，要生效请调用 reconfigure）。 */
    public QccAuth(QccAuthConfig cfg) { this(cfg, System::currentTimeMillis); }

    QccAuth(QccAuthConfig cfg, LongSupplier clock) {
        this.clock = clock;
        reconfigure(cfg);
    }

    /** 运行中更换参数（同样校验 + 快照）。进行中的登录请求保留。 */
    public synchronized void reconfigure(QccAuthConfig c) {
        c.validate();
        QccAuthConfig snap = c.copy();
        NamespaceClient ns = null;
        if (snap.nameCheck()) {
            ns = new NamespaceClient(snap.namespaceNodes(), snap.namespaceQuorum(), snap.pledgeTag());
            if (snap.discover()) ns.discover();
        }
        this.chain = snap.pledgeCheck() ? new ChainClient(snap.chainNodes(), snap.chainQuorum()) : null;
        this.namespace = ns;
        this.cfg = snap;
    }

    /** 当前生效参数的副本（可打印 / 导出）。 */
    public QccAuthConfig config() { return cfg.copy(); }
    public NamespaceClient namespace() { return namespace; }

    // ── 1. 发起 ───────────────────────────────────────────────────────

    public Issued issue(String name) { return issue(name, "login"); }

    public Issued issue(String name, String action) {
        QccAuthConfig c = cfg;
        name = name == null ? "" : name.trim().toLowerCase();
        if (!name.isEmpty() && !AuthRequest.NAME.matcher(name).matches()) throw new IllegalArgumentException("名称格式不对：" + name);
        if (!c.nameCheck() && !name.isEmpty()) throw new IllegalArgumentException("本应用只做签名鉴权（nameCheck=false），挑战不带名称");
        if (!name.isEmpty() && !tagAllowed(c, tagOf(name))) throw new IllegalArgumentException("本应用不接受 ." + tagOf(name) + " 名称");
        if (!AuthRequest.ACTION.matcher(action).matches()) throw new IllegalArgumentException("action 格式不对：" + action);
        purge();
        if (byNonce.size() >= MAX_PENDING) throw new IllegalStateException("待完成的登录请求过多，稍后再试");
        long now = clock.getAsLong();
        Challenge ch = new Challenge(c.app(), c.appName(), action, c.chain(), name, randHex(), now,
                now + c.ttlSeconds() * 1000, c.callback());
        Entry e = new Entry(ch, randHex());
        byNonce.put(ch.nonce(), e);
        byPoll.put(e.pollToken, e);
        return new Issued(ch, e.pollToken);
    }

    /** 按 nonce 取挑战（钱包扫到的是短链接时用）；不存在 / 已用 / 过期返回 null。 */
    public Challenge challenge(String nonce) {
        Entry e = nonce == null ? null : byNonce.get(nonce);
        return e == null || e.claimed || clock.getAsLong() > e.ch.expiresAt() ? null : e.ch;
    }

    // ── 2. 鉴权 ───────────────────────────────────────────────────────

    /** 鉴权客户端提交的 data（JSON）。 */
    public AuthInfo verify(byte[] data) {
        AuthRequest req;
        try { req = AuthRequest.parse(data); }
        catch (IllegalArgumentException e) { return AuthInfo.fail(AuthInfo.Status.BAD_FORMAT, e.getMessage(), clock.getAsLong()); }
        return verify(req);
    }

    public AuthInfo verify(String data) { return verify(data.getBytes(StandardCharsets.UTF_8)); }

    public AuthInfo verify(AuthRequest req) {
        QccAuthConfig c = cfg;
        long now = clock.getAsLong();
        if (!c.app().equals(req.app()))     return AuthInfo.fail(AuthInfo.Status.WRONG_APP, "签名不是给本应用的（app=" + req.app() + "）", now);
        if (!c.chain().equals(req.chain())) return AuthInfo.fail(AuthInfo.Status.WRONG_CHAIN, "chain 不是 " + c.chain(), now);
        Entry e = byNonce.get(req.nonce());
        if (e == null || e.claimed) return AuthInfo.fail(AuthInfo.Status.UNKNOWN_NONCE, "登录请求不存在或已使用", now);
        Challenge ch = e.ch;
        if (now > ch.expiresAt()) return done(e, AuthInfo.fail(AuthInfo.Status.EXPIRED, "登录请求已过期", now));
        if (!ch.action().equals(req.action()) || ch.issuedAt() != req.issuedAt() || ch.expiresAt() != req.expiresAt())
            return AuthInfo.fail(AuthInfo.Status.BAD_FORMAT, "鉴权数据与登录请求不一致（action / 时间）", now);
        if (!ch.name().isEmpty() && !ch.name().equals(req.name()))
            return AuthInfo.fail(AuthInfo.Status.NAME_MISMATCH, "本次登录要求名称 " + ch.name(), now);
        if (c.nameCheck() && req.name().isEmpty())
            return AuthInfo.fail(AuthInfo.Status.BAD_FORMAT, "本应用需要 namespace 名称登录", now);
        if (c.nameCheck() && !tagAllowed(c, req.tag()))
            return AuthInfo.fail(AuthInfo.Status.TAG_NOT_ALLOWED, "本应用不接受 ." + req.tag() + " 名称，接受 " + c.tags(), now);

        // L1（只做签名鉴权时没有 namespace 可查公钥，客户端必须自带公钥）
        NamespaceClient ns = namespace;
        AuthRequest.L1 l1 = req.verify(ns == null ? null : ns.asPubkeyResolver());
        if (!l1.ok()) return AuthInfo.fail(l1.status(), l1.reason(), now);

        // 验签通过：占用 nonce（并发重复提交只有一个能继续）
        synchronized (e) {
            if (e.claimed) return AuthInfo.fail(AuthInfo.Status.UNKNOWN_NONCE, "登录请求已使用", now);
            e.claimed = true;
        }
        AuthInfo info = c.nameCheck()
                ? check(c, req.action(), req.name(), req.address(), l1.pubkeyFromClient())
                : signatureOnly(req.action(), req.address(), l1.pubkeyFromClient(), now);
        if (info.retryable()) {                 // 节点暂时不足：放回 nonce，钱包可在有效期内原样重试
            e.claimed = false;
            return info;
        }
        return done(e, info);
    }

    // ── 3. 会话复查 ───────────────────────────────────────────────────

    /** 会话期间复查（建议 5–15 分钟一次）：名字被删除 / 转走 / 质押撤销 → 非 OK；质押数量变化也会反映在 amount。 */
    public AuthInfo recheck(String name, String address) {
        QccAuthConfig c = cfg;
        if (!c.nameCheck()) {
            long now = clock.getAsLong();
            if (address == null || !qcc.auth.crypto.QccAddress.isValid(address))
                return AuthInfo.fail(AuthInfo.Status.BAD_FORMAT, "地址无效：" + address, now);
            return signatureOnly("recheck", address, false, now);   // 没有链上状态可撤销：地址有效即通过
        }
        return check(c, "recheck", name, address, false);
    }

    /** 只做签名鉴权的结果：地址即账号，name 为空，amount = 0，没有节点参与。 */
    private static AuthInfo signatureOnly(String action, String address, boolean pkFromClient, long now) {
        return new AuthInfo(AuthInfo.Status.OK, address + " 签名鉴权通过（nameCheck=false：未核对名称与质押）", action, "", address,
                null, null, null, 0, 0, 0, 0, 0, 0, pkFromClient, now, false);
    }

    // L2 + L3
    private AuthInfo check(QccAuthConfig c, String action, String name, String address, boolean pkFromClient) {
        long now = clock.getAsLong();
        NamespaceClient.Verdict v;
        try { v = namespace.verify(name, address); }
        catch (RuntimeException ex) { v = new NamespaceClient.Verdict(false, false, "namespace 查询异常：" + ex.getMessage(), 0, 0, Map.of(), false); }
        if (!v.reachable() || !v.owned())
            return new AuthInfo(v.reachable() ? AuthInfo.Status.NAME_NOT_OWNED : AuthInfo.Status.NAMESPACE_UNAVAILABLE, v.reason(),
                    action, name, address, null, null, null, 0, 0, v.matched(), v.asked(), 0, 0, pkFromClient, now, false);

        // 保留名：协议发布者在 Reserved 中指定，没有质押凭证。allowReserved=true（默认）时直接通过，amount = 0；
        // 应用可用 info.reserved() 给保留名单独的权限 / 额度（鉴权只报告事实，不决定权限）
        if (v.reserved()) {
            if (!c.allowReserved())
                return new AuthInfo(AuthInfo.Status.NOT_QUALIFIED, name + " 是保留名，本应用不接受（allowReserved=false）",
                        action, name, address, null, null, null, 0, 0, v.matched(), v.asked(), 0, 0, pkFromClient, now, true);
            return new AuthInfo(AuthInfo.Status.OK, name + " 鉴权通过（" + v.reason() + "；保留名，不核对质押）", action, name, address,
                    null, null, null, 0, c.assetDecimals(), v.matched(), v.asked(), 0, 0, pkFromClient, now, true);
        }

        String hash = v.creds().get(c.pledgeTag());
        if (!c.pledgeCheck())
            return new AuthInfo(AuthInfo.Status.OK, name + " 鉴权通过（" + v.reason() + "；未核对质押）", action, name, address,
                    c.pledgeTag(), hash, null, 0, 0, v.matched(), v.asked(), 0, 0, pkFromClient, now, false);
        if (hash == null)
            return new AuthInfo(AuthInfo.Status.NOT_QUALIFIED, name + " 没有 tag=" + c.pledgeTag() + " 的质押凭证（namespace creds=" + v.creds().keySet() + "）",
                    action, name, address, c.pledgeTag(), null, c.assetId(), 0, c.assetDecimals(), v.matched(), v.asked(), 0, 0, pkFromClient, now, false);

        ChainClient.Verdict cv;
        try { cv = chain.pledge(address, c.pledgeTag(), hash, c.assetId(), c.minAmount()); }
        catch (RuntimeException ex) { cv = new ChainClient.Verdict(false, false, "链查询异常：" + ex.getMessage(), 0, 0, 0); }
        AuthInfo.Status st = !cv.reachable() ? AuthInfo.Status.CHAIN_UNAVAILABLE
                : !cv.qualified() ? AuthInfo.Status.NOT_QUALIFIED : AuthInfo.Status.OK;
        String reason = st == AuthInfo.Status.OK ? name + " 鉴权通过（" + v.reason() + "；" + cv.reason() + "）" : cv.reason();
        return new AuthInfo(st, reason, action, name, address, c.pledgeTag(), hash, c.assetId(), cv.amount(), c.assetDecimals(),
                v.matched(), v.asked(), cv.confirmed(), cv.asked(), pkFromClient, now, false);
    }

    // ── 4. 浏览器轮询 ─────────────────────────────────────────────────

    /** DONE 只返回一次，之后该 pollToken 作废。 */
    public Poll poll(String pollToken) {
        Entry e = pollToken == null ? null : byPoll.get(pollToken);
        if (e == null) return new Poll(PollState.UNKNOWN, null);
        AuthInfo r = e.info;
        if (r != null) {
            byPoll.remove(pollToken);
            return new Poll(PollState.DONE, r);
        }
        if (!e.claimed && clock.getAsLong() > e.ch.expiresAt()) {
            byPoll.remove(pollToken);
            byNonce.remove(e.ch.nonce());
            return new Poll(PollState.EXPIRED, null);
        }
        return new Poll(PollState.PENDING, null);
    }

    // ── 内部 ──────────────────────────────────────────────────────────

    private static boolean tagAllowed(QccAuthConfig c, String tag) { return c.tags().isEmpty() || c.tags().contains(tag); }
    private static String tagOf(String name) { return name.substring(name.indexOf('.') + 1); }

    private AuthInfo done(Entry e, AuthInfo info) {
        e.info = info;
        byNonce.remove(e.ch.nonce());
        return info;
    }

    private void purge() {
        long now = clock.getAsLong(), grace = 60_000;
        for (Iterator<Entry> it = byPoll.values().iterator(); it.hasNext(); ) {
            Entry e = it.next();
            if (now > e.ch.expiresAt() + grace) {
                it.remove();
                byNonce.remove(e.ch.nonce());
            }
        }
    }

    private String randHex() {
        byte[] b = new byte[32];
        rnd.nextBytes(b);
        return Sha3.toHex(b);
    }
}
