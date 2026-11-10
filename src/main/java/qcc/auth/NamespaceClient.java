package qcc.auth;

import qcc.auth.crypto.QccAddress;
import qcc.auth.crypto.Sha3;
import qcc.auth.json.StrictJson;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * namespace 节点客户端（只读）：名称核对、按地址反查、取公钥。不信任单个节点。
 *
 * 名称核对判定（失败优先）：
 *   · 任一节点给出不同的持有地址，或 REVOKED / MISMATCH → 不属于
 *   · MATCH 节点数 ≥ quorum，且各 MATCH 节点给出的 creds 一致 → 属于
 *   · 足够多节点 NOT_FOUND 且无 MATCH → 未注册
 *   · 其余（不可达 / 同步中 / UNVERIFIED / creds 不一致）→ 不可用，可重试
 */
public final class NamespaceClient {

    /** creds：{质押 tag: txHash}，即链上三要素中的 tag + hash。 */
    /** reserved：名字来自协议发布者的 Reserved 表（节点返回 reserved=true），没有质押凭证。 */
    public record Verdict(boolean reachable, boolean owned, String reason, int matched, int asked, Map<String, String> creds,
                          boolean reserved) {
        public Verdict(boolean reachable, boolean owned, String reason, int matched, int asked, Map<String, String> creds) {
            this(reachable, owned, reason, matched, asked, creds, false);
        }
        static Verdict unavailable(String r, int m, int a) { return new Verdict(false, false, r, m, a, Map.of()); }
        static Verdict notOwned(String r, int m, int a)    { return new Verdict(true, false, r, m, a, Map.of()); }
    }

    public record HeldName(String name, String status, Map<String, String> creds) {}

    private volatile List<String> nodes;
    private final int quorum;
    private final String fallbackPledgeTag;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4)).build();

    /** 作为 AuthRequest 的公钥来源。 */
    public AuthRequest.PubkeyResolver asPubkeyResolver() { return this::pubkey; }

    public NamespaceClient(List<String> nodeUrls, int quorum, String fallbackPledgeTag) {
        this.nodes = normalize(nodeUrls);
        if (nodes.isEmpty()) throw new IllegalArgumentException("至少配置一个 namespace 节点");
        this.quorum = Math.max(1, Math.min(quorum, nodes.size()));
        this.fallbackPledgeTag = fallbackPledgeTag;
    }

    public List<String> nodes() { return nodes; }
    public int quorum() { return quorum; }

    /** 从任一节点的 /v1/status 成员表取得全部节点（含 IPv6 冗余节点）；失败则保持原列表。 */
    public void discover() {
        for (String seed : nodes) {
            try {
                Map<String, Object> addrs = StrictJson.obj(StrictJson.obj(get(seed + "/v1/status"), "cluster"), "addrs");
                List<String> found = new ArrayList<>();
                for (Object hp : addrs.values()) found.add("http://" + hp);
                if (!found.isEmpty()) {
                    LinkedHashSet<String> all = new LinkedHashSet<>(normalize(found));
                    nodes = List.copyOf(all);
                    return;
                }
            } catch (Exception ignored) { }
        }
    }

    // ── 名称核对 ──────────────────────────────────────────────────────

    public Verdict verify(String name, String address) {
        String path = "/v1/verify?name=" + enc(name) + "&address=" + enc(address);
        List<String> ns = nodes;
        List<Map<String, Object>> rs = fanOut(ns, path);

        int match = 0, notFound = 0, reachable = 0;
        Map<String, String> creds = null;
        Boolean reserved = null;
        Map<String, String> detail = new LinkedHashMap<>();
        for (int i = 0; i < ns.size(); i++) {
            Map<String, Object> j = rs.get(i);
            if (j == null || !(j.get("status") instanceof String st)) { detail.put(ns.get(i), "不可达"); continue; }
            reachable++;
            detail.put(ns.get(i), st);
            if (j.get("address") instanceof String h && !h.equals(address))
                return Verdict.notOwned(name + " 属于其他地址 " + h + "（节点 " + ns.get(i) + "）", match, ns.size());
            switch (st) {
                case "MATCH" -> {
                    boolean r = Boolean.TRUE.equals(j.get("reserved"));
                    if (reserved != null && reserved != r)
                        return Verdict.unavailable("节点间保留名状态不一致（Reserved 同步中）", match, ns.size());
                    reserved = r;
                    Map<String, String> c = r ? Map.of() : credsOf(j);      // 保留名没有质押凭证
                    if (creds != null && !creds.equals(c))
                        return Verdict.unavailable("节点间凭证不一致 " + creds + " / " + c, match, ns.size());
                    creds = c;
                    match++;
                }
                case "NOT_FOUND" -> notFound++;
                case "REVOKED"   -> { return Verdict.notOwned(name + " 已撤销或注册质押失效（节点 " + ns.get(i) + "）", match, ns.size()); }
                case "MISMATCH"  -> { return Verdict.notOwned(name + " 不属于该地址（节点 " + ns.get(i) + "）", match, ns.size()); }
                default          -> { }                          // UNVERIFIED：该节点暂时查不了链
            }
        }
        if (match >= quorum)
            return new Verdict(true, true, match + "/" + ns.size() + " 个 namespace 节点确认" + (Boolean.TRUE.equals(reserved) ? "（保留名）" : ""),
                    match, ns.size(), creds, Boolean.TRUE.equals(reserved));
        if (match == 0 && notFound >= quorum) return Verdict.notOwned(name + " 未注册", 0, ns.size());
        return Verdict.unavailable("namespace 确认不足：MATCH " + match + "/" + quorum + "，可达 " + reachable + "/" + ns.size() + " " + detail, match, ns.size());
    }

    // ── 按地址反查（GET /v1/address）──────────────────────────────────

    /** 地址名下的名字（取第一个可达节点的回答，只作展示 / 提示；鉴权一律走 verify 多节点核对）。 */
    public List<HeldName> namesOf(String address) {
        for (String n : nodes) {
            try {
                Map<String, Object> j = get(n + "/v1/address?address=" + enc(address));
                List<HeldName> out = new ArrayList<>();
                for (Object o : StrictJson.arr(j, "names")) {
                    @SuppressWarnings("unchecked") Map<String, Object> e = (Map<String, Object>) o;
                    out.add(new HeldName(StrictJson.str(e, "name"), StrictJson.str(e, "status"), credsOf(e)));
                }
                return out;
            } catch (Exception ignored) { }
        }
        throw new IllegalStateException("namespace 节点均不可达");
    }

    // ── 公钥（客户端没带公钥时）──────────────────────────────────────

    /**
     * 取地址公钥。来源不可信也没关系：返回前核对公钥能推导出该地址，伪造的公钥过不了这一关。
     * 返回 null = 各节点都查不到（地址从未交易且没在 namespace 留过公钥）。
     */
    public byte[] pubkey(String address) {
        for (String n : nodes) {
            try {
                Map<String, Object> j = get(n + "/v1/pubkey?address=" + enc(address));
                if (j.get("pubkey") instanceof String hex) {
                    byte[] pk = Sha3.fromHex(hex);
                    if (QccAddress.matches(pk, address)) return pk;
                }
            } catch (Exception ignored) { }
        }
        return null;
    }

    // ── 内部 ──────────────────────────────────────────────────────────

    /** 新节点返回 creds；旧节点只有 credentialHash，按配置的注册质押 tag 补齐。 */
    private Map<String, String> credsOf(Map<String, Object> j) {
        Map<String, String> c = new LinkedHashMap<>();
        if (j.get("creds") instanceof Map<?, ?> m) {
            m.forEach((k, v) -> { if (v instanceof String s && !s.isEmpty()) c.put(String.valueOf(k), s); });
        } else if (j.get("credentialHash") instanceof String h && !h.isEmpty()) {
            c.put(fallbackPledgeTag, h);
        }
        return Map.copyOf(c);
    }

    private List<Map<String, Object>> fanOut(List<String> ns, String path) {
        List<CompletableFuture<Map<String, Object>>> fs = new ArrayList<>();
        for (String n : ns) fs.add(CompletableFuture.supplyAsync(() -> {
            try { return get(n + path); } catch (Exception e) { return null; }
        }));
        List<Map<String, Object>> out = new ArrayList<>();
        for (CompletableFuture<Map<String, Object>> f : fs) out.add(f.join());
        return out;
    }

    private Map<String, Object> get(String url) throws Exception {
        HttpRequest rq = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(6)).GET().build();
        HttpResponse<byte[]> r = http.send(rq, HttpResponse.BodyHandlers.ofByteArray());
        if (r.statusCode() != 200) throw new IllegalStateException("HTTP " + r.statusCode());
        return StrictJson.parseObject(r.body());
    }

    static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }

    static List<String> normalize(List<String> urls) {
        List<String> out = new ArrayList<>();
        for (String u : urls) {
            u = u.trim();
            while (u.endsWith("/")) u = u.substring(0, u.length() - 1);
            if (!u.isEmpty() && !out.contains(u)) out.add(u);
        }
        return List.copyOf(out);
    }
}
