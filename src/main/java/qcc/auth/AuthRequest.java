package qcc.auth;

import qcc.auth.crypto.MlDsa87;
import qcc.auth.crypto.QccAddress;
import qcc.auth.crypto.Sha3;
import qcc.auth.json.Json;
import qcc.auth.json.StrictJson;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 鉴权数据结构：客户端提交的 data 反解析成这个对象，对象自己完成 L1 身份核验（可脱离 QccAuth 单独使用）。
 *
 * <pre>
 *   AuthRequest req = AuthRequest.parse(data);           // 严格解析：缺字段 / 未知字段 / 格式不对都拒绝
 *   AuthRequest.L1 r = req.verify(resolver);             // 公钥（自带或拉取）→ 推导核对 address → 验签
 * </pre>
 *
 * data（JSON）：
 *   {"protocol":"qcc-auth/1","action":"login","chain":"6666","app":"mail.qccio.com","name":"chen.qcc",
 *    "address":"Q…","nonce":"<64 hex>","issuedAt":…,"expiresAt":…,"pubkey":"<可选 hex>","sig":"<hex>"}
 *
 * 签名原文（字段顺序冻结）：QCA1|action|chain|app|name|address|nonce|issuedAt|expiresAt
 * pubkey 不进签名：它的真伪靠"推导出 address"证明，所以客户端可带可不带。
 */
public final class AuthRequest {

    public static final String PROTOCOL = "qcc-auth/1";
    public static final String PREFIX   = "QCA1";

    static final Pattern ACTION = Pattern.compile("[a-z][a-z0-9_-]{0,31}");
    static final Pattern NAME   = Pattern.compile("[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?\\.[a-z0-9]{2,16}");
    static final Pattern NONCE  = Pattern.compile("[0-9a-f]{64}");
    private static final Set<String> FIELDS = Set.of(
            "protocol", "action", "chain", "app", "name", "address", "nonce", "issuedAt", "expiresAt", "pubkey", "sig");

    /** 公钥来源：客户端没带公钥时用（namespace / 公链）。返回 null = 查不到。 */
    public interface PubkeyResolver { byte[] pubkey(String address); }

    /** L1 结果：ok 时 pubkey 为已核对过（推导出 address）的公钥。 */
    public record L1(boolean ok, AuthInfo.Status status, String reason, byte[] pubkey, boolean pubkeyFromClient) {}

    private final String action, chain, app, name, address, nonce;
    private final long issuedAt, expiresAt;
    private final byte[] pubkey, sig;

    private AuthRequest(String action, String chain, String app, String name, String address, String nonce,
                        long issuedAt, long expiresAt, byte[] pubkey, byte[] sig) {
        this.action = action; this.chain = chain; this.app = app; this.name = name; this.address = address;
        this.nonce = nonce; this.issuedAt = issuedAt; this.expiresAt = expiresAt; this.pubkey = pubkey; this.sig = sig;
    }

    /** 严格解析客户端 data。不合法抛 IllegalArgumentException（说明哪一项）。 */
    public static AuthRequest parse(byte[] data) {
        Map<String, Object> j;
        try {
            j = StrictJson.parseObject(data);
            StrictJson.rejectUnknown(j, FIELDS, "鉴权数据");
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("鉴权数据不是合法 JSON：" + e.getMessage());
        }
        try {
            if (!PROTOCOL.equals(StrictJson.str(j, "protocol"))) throw new IllegalArgumentException("protocol 不是 " + PROTOCOL);
            String action = StrictJson.str(j, "action"), name = StrictJson.strAllowEmpty(j, "name"),
                    address = StrictJson.str(j, "address"), nonce = StrictJson.str(j, "nonce");
            if (!ACTION.matcher(action).matches()) throw new IllegalArgumentException("action 格式不对");
            // name 可为空：只做签名鉴权（nameCheck=false）的应用，地址即账号
            if (!name.isEmpty() && !NAME.matcher(name).matches()) throw new IllegalArgumentException("名称格式不对：" + name);
            if (!NONCE.matcher(nonce).matches()) throw new IllegalArgumentException("nonce 格式不对");
            if (!QccAddress.isValid(address)) throw new IllegalArgumentException("地址无效：" + address);
            byte[] pk = j.get("pubkey") instanceof String h && !h.isEmpty() ? Sha3.fromHex(h) : null;
            byte[] sig = Sha3.fromHex(StrictJson.str(j, "sig"));
            if (sig.length != MlDsa87.SIG_LEN) throw new IllegalArgumentException("签名长度不对：" + sig.length);
            return new AuthRequest(action, StrictJson.str(j, "chain"), StrictJson.str(j, "app"), name, address, nonce,
                    StrictJson.num(j, "issuedAt"), StrictJson.num(j, "expiresAt"), pk, sig);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("鉴权数据字段不全或类型不对：" + e.getMessage());
        }
    }

    public static AuthRequest parse(String data) { return parse(data.getBytes(StandardCharsets.UTF_8)); }

    /** 客户端（钱包）侧：按挑战签名后组装。 */
    public static AuthRequest sign(String action, String chain, String app, String name, String nonce,
                                   long issuedAt, long expiresAt, QccAuthClient.Signer s, boolean withPubkey) {
        name = name.trim().toLowerCase();
        String msg = signString(action, chain, app, name, s.address(), nonce, issuedAt, expiresAt);
        return new AuthRequest(action, chain, app, name, s.address(), nonce, issuedAt, expiresAt,
                withPubkey ? s.pubkey() : null, s.sign(msg.getBytes(StandardCharsets.UTF_8)));
    }

    public static String signString(String action, String chain, String app, String name, String address,
                                    String nonce, long issuedAt, long expiresAt) {
        return String.join("|", PREFIX, action, chain, app, name, address, nonce,
                Long.toString(issuedAt), Long.toString(expiresAt));
    }

    public String signString() { return signString(action, chain, app, name, address, nonce, issuedAt, expiresAt); }

    /**
     * L1 身份核验：公钥（自带，否则用 resolver 拉取）→ 公钥必须推导出 address → ML-DSA-87 验签。
     * resolver 可为 null（此时必须自带公钥）。
     */
    public L1 verify(PubkeyResolver resolver) {
        byte[] pk = pubkey;
        boolean fromClient = pk != null;
        if (pk == null) {
            pk = resolver == null ? null : resolver.pubkey(address);
            if (pk == null) return new L1(false, AuthInfo.Status.NO_PUBKEY, "未提交公钥，也查不到该地址公钥", null, false);
        }
        if (pk.length != MlDsa87.PUBKEY_LEN || !QccAddress.matches(pk, address))
            return new L1(false, AuthInfo.Status.PUBKEY_MISMATCH, "公钥推导不出该地址", null, fromClient);
        if (!MlDsa87.verify(pk, signString().getBytes(StandardCharsets.UTF_8), sig))
            return new L1(false, AuthInfo.Status.BAD_SIGNATURE, "签名无效", null, fromClient);
        return new L1(true, AuthInfo.Status.OK, "签名有效", pk, fromClient);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("protocol", PROTOCOL);
        m.put("action", action);
        m.put("chain", chain);
        m.put("app", app);
        m.put("name", name);
        m.put("address", address);
        m.put("nonce", nonce);
        m.put("issuedAt", issuedAt);
        m.put("expiresAt", expiresAt);
        if (pubkey != null) m.put("pubkey", Sha3.toHex(pubkey));
        m.put("sig", Sha3.toHex(sig));
        return m;
    }

    public String toJson() { return Json.write(toMap()); }
    public byte[] toBytes() { return toJson().getBytes(StandardCharsets.UTF_8); }

    public String action()   { return action; }
    public String chain()    { return chain; }
    public String app()      { return app; }
    public String name()     { return name; }
    public String address()  { return address; }
    public String nonce()    { return nonce; }
    public long issuedAt()   { return issuedAt; }
    public long expiresAt()  { return expiresAt; }
    public byte[] pubkey()   { return pubkey == null ? null : pubkey.clone(); }
    public boolean hasPubkey() { return pubkey != null; }
    public String tag()      { return name.isEmpty() ? "" : name.substring(name.indexOf('.') + 1); }
}
