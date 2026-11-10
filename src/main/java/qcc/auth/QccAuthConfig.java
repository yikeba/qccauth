package qcc.auth;

import qcc.auth.json.Json;
import qcc.auth.json.StrictJson;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 鉴权参数对象。内置默认值，可以直接改属性，也可以用 JSON 整体 / 部分设置。
 *
 * <pre>
 *   QccAuthConfig cfg = new QccAuthConfig();       // 全部默认值
 *   System.out.println(cfg);                       // 打印当前参数（JSON）
 *   cfg.setApp("mail.qccio.com").setMinAmount(1_000_000_000L);
 *   cfg.setJson(text);                             // 只覆盖 JSON 里出现的字段
 *   String json = cfg.toJson();                    // 导出
 *   QccAuth auth = new QccAuth(cfg);               // 校验后取快照：之后再改 cfg 不影响运行中的 auth
 * </pre>
 *
 * 鉴权只回答"这个签名者是谁、名字是否属于他、质押了多少"，不管应用的权限 / 等级 / 额度 ——
 * 那些由应用拿 {@link AuthInfo} 自己决定。
 */
public final class QccAuthConfig {

    /** 默认 = 公开 namespace 实例 qccname-qccio（.qcc，端口 9180）。企业实例（如 OSN .osn，9181）必须显式配置。 */
    public static final List<String> DEFAULT_NAMESPACE_NODES = List.of(
            "http://66.154.109.124:9180", "http://23.238.114.9:9180", "http://107.174.172.115:9180", "http://107.172.76.70:9180");
    public static final List<String> DEFAULT_CHAIN_NODES = List.of(
            "http://45.92.158.123:9080", "http://192.131.142.226:9080", "http://104.128.190.31:9080",
            "http://23.238.114.155:9080", "http://104.223.85.211:9080", "http://[2001:f40:978:1c58:2f1:f5ff:fe35:fd73]:9080");

    private static final Pattern APP = Pattern.compile("[A-Za-z0-9._:-]{1,128}");

    // ── 应用 ──
    private String app = "";                      // 必填：进入签名原文，建议用域名
    private String appName = "";                  // 钱包展示名，空 = 同 app
    private String callback = "";                 // 钱包提交签名的地址（扫码 / 链接登录用）
    private long ttlSeconds = 120;                // 登录请求有效期
    private String chain = "6666";                // 6666 测试网 / 9999 主网

    // ── 鉴权层级 ──
    private boolean nameCheck = true;             // 是否核对 namespace 名字（false = 只做 ML-DSA-87 签名鉴权，地址即账号；必须同时 pledgeCheck=false）

    // ── 鉴权资产 ──
    private boolean allowReserved = true;         // 保留名（namespace Reserved 表指定，无质押）是否放行
    private boolean pledgeCheck = true;           // 是否向公链核对质押（关闭则只做签名 + 名称核对，amount = 0）
    private String pledgeTag = "qccio";           // 质押所在 tag（namespace 注册质押）
    private String assetId = "QCC";               // 鉴权资产
    private int assetDecimals = 9;                // 资产精度：1 QCC = 10^9 最小单位
    private long minAmount = 1_000_000_000L;      // 最低质押（最小单位），默认 1 QCC
    private List<String> tags = new ArrayList<>();// 接受哪些名字后缀，空 = 全部

    // ── 节点 ──
    private List<String> namespaceNodes = new ArrayList<>(DEFAULT_NAMESPACE_NODES);
    private int namespaceQuorum = 2;              // 需要几个 namespace 节点 MATCH（不超过节点数）
    private boolean discover = true;              // 启动时从成员表取全部 namespace 节点（含 IPv6）
    private List<String> chainNodes = new ArrayList<>(DEFAULT_CHAIN_NODES);
    private int chainQuorum = 2;                  // 需要几个链节点确认质押

    public QccAuthConfig() {}

    // ── getter ──
    public String app()               { return app; }
    public String appName()           { return appName.isEmpty() ? app : appName; }
    public String callback()          { return callback; }
    public long ttlSeconds()          { return ttlSeconds; }
    public String chain()             { return chain; }
    public boolean nameCheck()        { return nameCheck; }
    public boolean pledgeCheck()      { return pledgeCheck; }
    public boolean allowReserved()    { return allowReserved; }
    public String pledgeTag()         { return pledgeTag; }
    public String assetId()           { return assetId; }
    public int assetDecimals()        { return assetDecimals; }
    public long minAmount()           { return minAmount; }
    public List<String> tags()        { return List.copyOf(tags); }
    public List<String> namespaceNodes() { return List.copyOf(namespaceNodes); }
    public int namespaceQuorum()      { return Math.min(namespaceQuorum, namespaceNodes.size()); }
    public boolean discover()         { return discover; }
    public List<String> chainNodes()  { return List.copyOf(chainNodes); }
    public int chainQuorum()          { return Math.min(chainQuorum, chainNodes.size()); }

    // ── setter（可链式）──
    public QccAuthConfig setApp(String v)            { app = v == null ? "" : v.trim(); return this; }
    public QccAuthConfig setAppName(String v)        { appName = v == null ? "" : v; return this; }
    public QccAuthConfig setCallback(String v)       { callback = v == null ? "" : v.trim(); return this; }
    public QccAuthConfig setTtlSeconds(long v)       { ttlSeconds = v; return this; }
    public QccAuthConfig setChain(String v)          { chain = v; return this; }
    public QccAuthConfig setNameCheck(boolean v)     { nameCheck = v; return this; }
    public QccAuthConfig setPledgeCheck(boolean v)   { pledgeCheck = v; return this; }
    public QccAuthConfig setAllowReserved(boolean v) { allowReserved = v; return this; }
    public QccAuthConfig setPledgeTag(String v)      { pledgeTag = v; return this; }
    public QccAuthConfig setAssetId(String v)        { assetId = v; return this; }
    public QccAuthConfig setAssetDecimals(int v)     { assetDecimals = v; return this; }
    public QccAuthConfig setMinAmount(long v)        { minAmount = v; return this; }
    public QccAuthConfig setTags(List<String> v)     { tags = new ArrayList<>(v); return this; }
    public QccAuthConfig setNamespaceNodes(List<String> v) { namespaceNodes = new ArrayList<>(v); return this; }
    public QccAuthConfig setNamespaceQuorum(int v)   { namespaceQuorum = v; return this; }
    public QccAuthConfig setDiscover(boolean v)      { discover = v; return this; }
    public QccAuthConfig setChainNodes(List<String> v) { chainNodes = new ArrayList<>(v); return this; }
    public QccAuthConfig setChainQuorum(int v)       { chainQuorum = v; return this; }

    // ── JSON ──

    private static final Set<String> KEYS = Set.of("app", "appName", "callback", "ttlSeconds", "chain",
            "nameCheck", "pledgeCheck", "allowReserved", "pledgeTag", "assetId", "assetDecimals", "minAmount", "tags",
            "namespaceNodes", "namespaceQuorum", "discover", "chainNodes", "chainQuorum", "_comment");

    /** 用 JSON 设置参数：只覆盖出现的字段，未知字段报错（防止拼错字段名后静默用了默认值）。 */
    public QccAuthConfig setJson(String json) {
        Map<String, Object> j;
        try {
            j = StrictJson.parseObject(json.getBytes(StandardCharsets.UTF_8));
            StrictJson.rejectUnknown(j, KEYS, "qccauth 配置");
        } catch (IllegalStateException e) {
            throw new IllegalArgumentException("qccauth 配置 JSON 不合法：" + e.getMessage(), e);
        }
        try {
        if (j.containsKey("app"))             setApp(StrictJson.str(j, "app"));
        if (j.containsKey("appName"))         setAppName(StrictJson.strAllowEmpty(j, "appName"));
        if (j.containsKey("callback"))        setCallback(StrictJson.strAllowEmpty(j, "callback"));
        if (j.containsKey("ttlSeconds"))      setTtlSeconds(StrictJson.num(j, "ttlSeconds"));
        if (j.containsKey("chain"))           setChain(StrictJson.str(j, "chain"));
        if (j.containsKey("nameCheck"))       setNameCheck(StrictJson.bool(j, "nameCheck"));
        if (j.containsKey("pledgeCheck"))     setPledgeCheck(StrictJson.bool(j, "pledgeCheck"));
        if (j.containsKey("allowReserved"))   setAllowReserved(StrictJson.bool(j, "allowReserved"));
        if (j.containsKey("pledgeTag"))       setPledgeTag(StrictJson.str(j, "pledgeTag"));
        if (j.containsKey("assetId"))         setAssetId(StrictJson.str(j, "assetId"));
        if (j.containsKey("assetDecimals"))   setAssetDecimals((int) StrictJson.num(j, "assetDecimals"));
        if (j.containsKey("minAmount"))       setMinAmount(StrictJson.num(j, "minAmount"));
        if (j.containsKey("tags"))            setTags(j.get("tags") instanceof List<?> ? StrictJson.strArr(j, "tags") : List.of());
        if (j.containsKey("namespaceNodes"))  setNamespaceNodes(StrictJson.strArr(j, "namespaceNodes"));
        if (j.containsKey("namespaceQuorum")) setNamespaceQuorum((int) StrictJson.num(j, "namespaceQuorum"));
        if (j.containsKey("discover"))        setDiscover(StrictJson.bool(j, "discover"));
        if (j.containsKey("chainNodes"))      setChainNodes(StrictJson.strArr(j, "chainNodes"));
        if (j.containsKey("chainQuorum"))     setChainQuorum((int) StrictJson.num(j, "chainQuorum"));
        } catch (IllegalStateException e) {
            throw new IllegalArgumentException("qccauth 配置字段类型不对：" + e.getMessage(), e);
        }
        return this;
    }

    public static QccAuthConfig fromJson(String json) { return new QccAuthConfig().setJson(json); }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("app", app);
        m.put("appName", appName);
        m.put("callback", callback);
        m.put("ttlSeconds", ttlSeconds);
        m.put("chain", chain);
        m.put("nameCheck", nameCheck);
        m.put("pledgeCheck", pledgeCheck);
        m.put("allowReserved", allowReserved);
        m.put("pledgeTag", pledgeTag);
        m.put("assetId", assetId);
        m.put("assetDecimals", assetDecimals);
        m.put("minAmount", minAmount);
        m.put("tags", List.copyOf(tags));
        m.put("namespaceNodes", List.copyOf(namespaceNodes));
        m.put("namespaceQuorum", namespaceQuorum);
        m.put("discover", discover);
        m.put("chainNodes", List.copyOf(chainNodes));
        m.put("chainQuorum", chainQuorum);
        return m;
    }

    public String toJson() { return Json.write(toMap()); }

    /** 每个参数一行，便于打印核对。 */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("{\n");
        var it = toMap().entrySet().iterator();
        while (it.hasNext()) {
            var e = it.next();
            sb.append("  ").append(Json.write(Map.of(e.getKey(), e.getValue())), 1, Json.write(Map.of(e.getKey(), e.getValue())).length() - 1);
            sb.append(it.hasNext() ? ",\n" : "\n");
        }
        return sb.append("}").toString();
    }

    /** 深拷贝：QccAuth 初始化时取快照。 */
    public QccAuthConfig copy() { return fromJson(toJson()); }

    /** 参数校验（QccAuth 初始化时调用），不合法抛 IllegalArgumentException 并说明哪一项。 */
    public void validate() {
        if (app.isEmpty()) throw new IllegalArgumentException("必须设置 app（进入签名原文，用于区分应用，建议用域名）");
        if (!APP.matcher(app).matches()) throw new IllegalArgumentException("app 只能含 A-Z a-z 0-9 . _ : -（1–128 位）：" + app);
        if (ttlSeconds < 10 || ttlSeconds > 3600) throw new IllegalArgumentException("ttlSeconds 需在 10–3600");
        if (!nameCheck && pledgeCheck)
            throw new IllegalArgumentException("nameCheck=false（只做签名鉴权）时必须 pledgeCheck=false：质押凭证来自 namespace 名字");
        if (nameCheck) {
            if (namespaceNodes.isEmpty()) throw new IllegalArgumentException("namespaceNodes 不能为空");
            if (namespaceQuorum < 1) throw new IllegalArgumentException("namespaceQuorum ≥ 1");
        }
        if (pledgeCheck) {
            if (chainNodes.isEmpty()) throw new IllegalArgumentException("pledgeCheck=true 时 chainNodes 不能为空");
            if (chainQuorum < 1) throw new IllegalArgumentException("chainQuorum ≥ 1");
            if (assetId == null || assetId.isEmpty()) throw new IllegalArgumentException("assetId 不能为空");
            if (minAmount < 0) throw new IllegalArgumentException("minAmount ≥ 0");
            if (assetDecimals < 0 || assetDecimals > 18) throw new IllegalArgumentException("assetDecimals 0–18");
        }
        for (String t : tags) if (!t.matches("[a-z0-9]{2,16}")) throw new IllegalArgumentException("tags 格式不对：" + t);
    }
}
