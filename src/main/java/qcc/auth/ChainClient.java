package qcc.auth;

import qcc.auth.json.StrictJson;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * QCC 公链授权质押查询（三要素 address + tag + hash，O(1)），多节点交叉确认。
 * GET {node}/v1/pledge/{address}?tag=&hash=&minAmount=0
 *   {"ok":true,"kind":"pledge","data":"{\"exists\":true,\"assetId\":\"QCC\",\"amount\":1000000000,…}"}
 *   data 是 JSON 字符串（也兼容直接是对象）。
 * 只有 ok=true 且 data 是带 exists 字段的对象才算有效回答；"error"、"{}"、结构不符一律算不可达，
 * 绝不当成"质押不存在"——否则链节点一抖动，用户就被误踢下线。
 * 门槛（assetId + minAmount）在本地比较，不交给链节点判断。
 * 判定：合格节点 ≥ quorum 且 合格 > 不合格 → 合格；不合格 ≥ quorum 且无合格 → 不合格；其余 → 不可用。
 */
public final class ChainClient {

    /** amount：合格节点给出的质押金额取最小值（防止单个节点虚报）；confirmed / asked：确认节点数 / 询问节点数。 */
    public record Verdict(boolean reachable, boolean qualified, String reason, long amount, int confirmed, int asked) {}

    private final List<String> nodes;
    private final int quorum;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4)).build();

    public ChainClient(List<String> nodeUrls, int quorum) {
        this.nodes = NamespaceClient.normalize(nodeUrls);
        if (nodes.isEmpty()) throw new IllegalArgumentException("至少配置一个链节点");
        this.quorum = Math.max(1, Math.min(quorum, nodes.size()));
    }

    public List<String> nodes() { return nodes; }

    public Verdict pledge(String address, String tag, String hash, String assetId, long minAmount) {
        String path = "/v1/pledge/" + NamespaceClient.enc(address) + "?tag=" + NamespaceClient.enc(tag)
                + "&hash=" + NamespaceClient.enc(hash) + "&minAmount=0";
        List<CompletableFuture<Fact>> fs = new ArrayList<>();
        for (String n : nodes) fs.add(CompletableFuture.supplyAsync(() -> query(n + path)));
        int ok = 0, no = 0, down = 0;
        long amount = Long.MAX_VALUE;
        String why = "";
        for (CompletableFuture<Fact> f : fs) {
            Fact x = f.join();
            if (x == null) { down++; continue; }
            if (!x.exists) { no++; why = "链上无此授权质押（未授权或已撤销）"; continue; }
            if (!assetId.equals(x.assetId) || x.amount < minAmount) {
                no++;
                why = "质押不满足门槛：" + x.amount + " " + x.assetId + "，要求 ≥ " + minAmount + " " + assetId;
                continue;
            }
            ok++;
            amount = Math.min(amount, x.amount);
        }
        String tally = "（合格 " + ok + " / 不合格 " + no + " / 不可达 " + down + "，需 " + quorum + "）";
        if (ok >= quorum && ok > no) return new Verdict(true, true, "链上质押 tag=" + tag + " 确认" + tally, amount, ok, nodes.size());
        if (no >= quorum && ok == 0)  return new Verdict(true, false, why + tally, 0, 0, nodes.size());
        return new Verdict(false, false, "链节点确认不足" + tally, 0, ok, nodes.size());
    }

    private record Fact(boolean exists, String assetId, long amount) {}

    private Fact query(String url) {
        try {
            HttpRequest rq = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(8)).GET().build();
            HttpResponse<byte[]> r = http.send(rq, HttpResponse.BodyHandlers.ofByteArray());
            if (r.statusCode() != 200) return null;
            Map<String, Object> outer = StrictJson.parseObject(r.body());
            if (!(outer.get("ok") instanceof Boolean b) || !b) return null;
            Object data = outer.get("data");
            Map<String, Object> d;
            if (data instanceof String s) {
                if (!s.trim().startsWith("{")) return null;                     // "error" 等
                d = StrictJson.parseObject(s.getBytes(StandardCharsets.UTF_8));
            } else if (data instanceof Map<?, ?>) {
                @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) data;
                d = m;
            } else return null;
            if (!(d.get("exists") instanceof Boolean ex)) return null;          // "{}"：没有结论
            if (!ex) return new Fact(false, "", 0);
            return new Fact(true, StrictJson.str(d, "assetId"), StrictJson.num(d, "amount"));
        } catch (Exception e) {
            return null;
        }
    }
}