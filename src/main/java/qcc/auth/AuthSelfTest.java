package qcc.auth;

import com.sun.net.httpserver.HttpServer;
import qcc.auth.crypto.MlDsa87;
import qcc.auth.crypto.QccAddress;
import qcc.auth.crypto.Sha3;
import qcc.auth.json.Json;

import java.math.BigDecimal;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

/** qcc-auth 自测：真实 ML-DSA-87 签名，模拟 namespace 节点与 QCC 链节点（HTTP）。 ./gradlew selfTest */
public final class AuthSelfTest {

    private int failed;
    private final List<HttpServer> servers = new ArrayList<>();

    public static void main(String[] a) throws Exception {
        System.out.println("ML-DSA-87：" + MlDsa87.source());
        int f;
        try { f = new AuthSelfTest().run(); }
        catch (Throwable t) { t.printStackTrace(); f = 1; }
        System.out.println(f == 0 ? "\n✓ 全部通过" : "\n✗ 失败 " + f + " 项");
        System.exit(f == 0 ? 0 : 1);
    }

    private void ck(boolean ok, String what) {
        System.out.println((ok ? "  OK   " : "  FAIL ") + what);
        if (!ok) failed++;
    }

    int run() throws Exception {
        MlDsa87.Keys k = MlDsa87.generate(), other = MlDsa87.generate();
        String addr = QccAddress.derive(k.pub());
        String cred = "6b7e".repeat(16);
        AtomicLong now = new AtomicLong(System.currentTimeMillis());
        QccAuthClient.Signer me = QccAuthClient.mlDsa(k.priv(), k.pub()), thief = QccAuthClient.mlDsa(other.priv(), other.pub());

        // 模拟 namespace：chen.qcc → addr，creds {qccio: cred}；公钥只在 namespace 有
        Map<String, Object> nsMatch = new LinkedHashMap<>(Map.of("match", true, "status", "MATCH", "name", "chen.qcc", "address", addr,
                "regSeq", 4, "credentialHash", cred, "creds", Map.of("qccio", cred), "asOf", 9));
        @SuppressWarnings("unchecked") Supplier<Map<String, Object>>[] nsAnswer = new Supplier[]{() -> nsMatch};
        String ns1 = namespaceNode(() -> nsAnswer[0].get(), addr, k.pub()), ns2 = namespaceNode(() -> nsAnswer[0].get(), addr, k.pub());
        // 模拟链：三要素命中，质押 10 QCC
        String[] chainData = {"{\"exists\":true,\"assetId\":\"QCC\",\"amount\":10000000000,\"from\":\"QFrom\",\"regTime\":1}"};
        String c1 = chainNode(() -> chainData[0]), c2 = chainNode(() -> chainData[0]);

        System.out.println("── 参数对象 ──");
        QccAuthConfig cfg = new QccAuthConfig();
        ck("QCC".equals(cfg.assetId()) && cfg.minAmount() == 1_000_000_000L && cfg.assetDecimals() == 9 && "qccio".equals(cfg.pledgeTag()),
                "默认参数：资产 QCC、最低 1 QCC、精度 9、质押 tag qccio");
        ck(throwsIAE(cfg::validate), "未设置 app → 初始化校验失败（app 进入签名，不能用默认值）");
        cfg.setApp("mail.qccio.com").setCallback("http://127.0.0.1/cb").setTags(List.of("qcc", "osn"))
                .setNamespaceNodes(List.of(ns1, ns2)).setDiscover(false).setChainNodes(List.of(c1, c2));
        ck(cfg.toString().contains("\"assetId\":\"QCC\"") && cfg.toString().contains("\"app\":\"mail.qccio.com\""), "打印参数对象：\n" + indent(cfg.toString()));
        QccAuthConfig viaJson = new QccAuthConfig().setJson(cfg.toJson());
        ck(viaJson.toJson().equals(cfg.toJson()), "toJson → setJson 往返一致");
        ck(new QccAuthConfig().setJson("{\"app\":\"x.app\",\"minAmount\":5}").assetId().equals("QCC"), "setJson 只覆盖出现的字段，其余保持默认");
        ck(throwsIAE(() -> new QccAuthConfig().setJson("{\"minAmout\":5}")), "setJson 拼错字段名 → 报错（不静默用默认值）");

        QccAuth auth = new QccAuth(cfg, now::get);
        cfg.setApp("changed.app");
        ck("mail.qccio.com".equals(auth.config().app()), "初始化取快照：之后修改 cfg 不影响运行中的 auth");

        System.out.println("── 鉴权数据结构 AuthRequest ──");
        QccAuth.Issued is = auth.issue("");
        AuthRequest req = QccAuthClient.respond(is.challenge(), "chen.qcc", me, false);
        AuthRequest parsed = AuthRequest.parse(req.toBytes());
        ck(parsed.signString().equals(req.signString()) && !parsed.hasPubkey(), "data 反解析为对象：" + parsed.signString().substring(0, 60) + "…");
        ck(parsed.verify(a -> null).status() == AuthInfo.Status.NO_PUBKEY, "data 无公钥且拉不到 → NO_PUBKEY");
        AuthRequest.L1 l1 = parsed.verify(auth.namespace().asPubkeyResolver());
        ck(l1.ok() && !l1.pubkeyFromClient(), "data 无公钥 → 向 namespace 拉取 → 推导核对 address → 验签通过");
        ck(QccAuthClient.respond(is.challenge(), "chen.qcc", me, true).verify(null).ok(), "data 自带公钥 → 不联网即可完成 L1");
        ck(throwsIAE(() -> AuthRequest.parse("{\"protocol\":\"qcc-auth/1\",\"x\":1}")), "未知字段 → 拒绝解析");

        System.out.println("── 鉴权信息 AuthInfo ──");
        AuthInfo info = auth.verify(parsed);
        ck(info.ok() && "chen.qcc".equals(info.name()) && addr.equals(info.address()), "鉴权通过：" + info.reason());
        ck(info.amount() == 10_000_000_000L && info.amountUnits().compareTo(BigDecimal.TEN) == 0 && "QCC".equals(info.assetId()),
                "返回质押数量 amount=" + info.amount() + "，折合 " + info.amountUnits().stripTrailingZeros().toPlainString() + " QCC");
        ck(cred.equals(info.credentialHash()) && info.namespaceMatched() == 2 && info.chainConfirmed() == 2, "返回链上凭证与确认节点数（namespace 2/2，链 2/2）");
        ck(info.amountUnits().longValue() == 10, "应用自行换算（例：每 1 QCC = 1G）→ 10G；鉴权本身不管权限");
        System.out.println("       " + info.toJson());
        QccAuth.Poll p = auth.poll(is.pollToken());
        ck(p.state() == QccAuth.PollState.DONE && p.info().ok() && auth.poll(is.pollToken()).state() == QccAuth.PollState.UNKNOWN, "浏览器轮询拿到鉴权信息，只交付一次");
        ck(auth.verify(parsed).status() == AuthInfo.Status.UNKNOWN_NONCE, "同一 data 重放 → UNKNOWN_NONCE");

        System.out.println("── 拒绝 ──");
        QccAuth.Challenge ch = auth.issue("").challenge();
        ck(auth.verify(QccAuthClient.respond(ch, "chen.com", me, true)).status() == AuthInfo.Status.TAG_NOT_ALLOWED, "不接受的后缀 → TAG_NOT_ALLOWED");
        ck(auth.verify(QccAuthClient.respond(ch, "chen.qcc", thief, true)).status() == AuthInfo.Status.NAME_NOT_OWNED, "名字是别人的 → NAME_NOT_OWNED");
        chainData[0] = chainData[0].replace("10000000000", "500000000");
        ck(auth.verify(QccAuthClient.respond(auth.issue("").challenge(), "chen.qcc", me, true)).status() == AuthInfo.Status.NOT_QUALIFIED,
                "质押 0.5 QCC < 最低 1 QCC → NOT_QUALIFIED");
        chainData[0] = "error";
        QccAuth.Issued i2 = auth.issue("");
        AuthRequest r2 = QccAuthClient.respond(i2.challenge(), "chen.qcc", me, true);
        AuthInfo x = auth.verify(r2);
        ck(x.status() == AuthInfo.Status.CHAIN_UNAVAILABLE && x.retryable() && auth.poll(i2.pollToken()).state() == QccAuth.PollState.PENDING,
                "链节点返回 \"error\" → 可重试，登录请求仍有效（不误判为无质押）");
        chainData[0] = "{\"exists\":true,\"assetId\":\"QCC\",\"amount\":1000000000}";
        ck(auth.verify(r2).ok(), "链恢复后原样重试 → OK");
        chainData[0] = "{\"exists\":false}";
        ck(auth.recheck("chen.qcc", addr).status() == AuthInfo.Status.NOT_QUALIFIED, "会话复查：质押撤销 → NOT_QUALIFIED");
        chainData[0] = "{\"exists\":true,\"assetId\":\"QCC\",\"amount\":1000000000}";

        System.out.println("── 其他 ──");
        Map<String, Object> legacy = new LinkedHashMap<>(nsMatch);
        legacy.remove("creds");
        nsAnswer[0] = () -> legacy;
        ck(auth.recheck("chen.qcc", addr).ok(), "旧 namespace 节点无 creds → 用 credentialHash + pledgeTag 补齐");
        // 保留名：namespace 返回 reserved=true、无 creds；链上即使没有质押也通过
        Map<String, Object> rsv = new LinkedHashMap<>(Map.of("match", true, "status", "MATCH", "name", "chen.qcc", "address", addr,
                "regSeq", 1, "credentialHash", "", "creds", Map.of(), "reserved", true, "reservedTx", "ab".repeat(32), "asOf", 9));
        nsAnswer[0] = () -> rsv;
        chainData[0] = "{\"exists\":false}";
        AuthInfo ri = auth.recheck("chen.qcc", addr);
        ck(ri.ok() && ri.reserved() && ri.amount() == 0 && Boolean.TRUE.equals(ri.toMap().get("reserved")),
                "保留名（Reserved）→ OK，reserved=true，不核对质押");
        QccAuth strict = new QccAuth(cfg.copy().setAllowReserved(false), now::get);
        ck(strict.recheck("chen.qcc", addr).status() == AuthInfo.Status.NOT_QUALIFIED, "allowReserved=false → 保留名 NOT_QUALIFIED");
        chainData[0] = "{\"exists\":true,\"assetId\":\"QCC\",\"amount\":1000000000}";
        nsAnswer[0] = () -> nsMatch;
        QccAuth light = new QccAuth(new QccAuthConfig().setApp("chat.app").setPledgeCheck(false)
                .setNamespaceNodes(List.of(ns1, ns2)).setDiscover(false), now::get);
        AuthInfo li = light.verify(QccAuthClient.respond(light.issue("").challenge(), "chen.qcc", me, true));
        ck(li.ok() && li.amount() == 0, "pledgeCheck=false：只核对签名 + 名称（amount=0）");
        AuthInfo noName = light.verify(QccAuthClient.respond(light.issue("").challenge(), "", me, true));
        ck(noName.status() == AuthInfo.Status.BAD_FORMAT, "需要名称的应用：钱包不带名称 → BAD_FORMAT");

        System.out.println("── 只做签名鉴权（nameCheck=false，免费注册 / 引流）──");
        ck(throwsIAE(() -> new QccAuthConfig().setApp("fchat.app").setNameCheck(false).validate()),
                "nameCheck=false 但 pledgeCheck=true → 校验失败（质押凭证来自名字）");
        QccAuth sig = new QccAuth(new QccAuthConfig().setApp("fchat.app").setNameCheck(false).setPledgeCheck(false)
                .setNamespaceNodes(List.of()), now::get);
        ck(sig.namespace() == null, "不创建 namespace 客户端，namespaceNodes 可为空");
        ck(throwsIAE(() -> sig.issue("chen.qcc")), "签名鉴权的挑战不带名称");
        AuthInfo si = sig.verify(QccAuthClient.respond(sig.issue("").challenge(), "", me, true));
        ck(si.ok() && si.name().isEmpty() && addr.equals(si.address()) && si.amount() == 0 && si.namespaceAsked() == 0 && si.chainAsked() == 0,
                "签名有效 → OK：地址即账号，name 为空，amount=0，不询问任何节点");
        AuthInfo sn = sig.verify(QccAuthClient.respond(sig.issue("").challenge(), "chen.qcc", me, true));
        ck(sn.ok() && sn.name().isEmpty(), "钱包带了名称也不采信：结果 name 为空（名称未经核对）");
        ck(sig.verify(QccAuthClient.respond(sig.issue("").challenge(), "", me, false)).status() == AuthInfo.Status.NO_PUBKEY,
                "不带公钥 → NO_PUBKEY（没有 namespace 可查公钥）");
        AuthRequest forged = QccAuthClient.respond(sig.issue("").challenge(), "", me, true);
        String bad = forged.toJson().replace(addr, QccAddress.derive(other.pub()));
        ck(!sig.verify(bad).ok(), "把地址换成别人的 → 拒绝");
        ck(sig.recheck("", addr).ok() && !sig.recheck("", "Qbad").ok(), "recheck：地址有效即 OK（没有链上状态可撤销）");

        System.out.println("── 端到端：演示应用 + Java 客户端 ──");
        int port = freePort();
        java.nio.file.Path tmp = java.nio.file.Files.createTempFile("qccauth", ".json");
        java.nio.file.Files.writeString(tmp, new QccAuthConfig().setApp("qccemail-test").setCallback("http://127.0.0.1:" + port + "/auth/callback")
                .setNamespaceNodes(List.of(ns1, ns2)).setDiscover(false).setChainNodes(List.of(c1, c2)).toString());
        qcc.auth.demo.AuthDemoServer.main(new String[]{"config=" + tmp});
        String url = (String) qcc.auth.json.StrictJson.parseObject(httpGet("http://127.0.0.1:" + port + "/auth/challenge")).get("url");
        Map<String, Object> res = QccAuthClient.login(url, "chen.qcc", me, false);
        ck(Boolean.TRUE.equals(res.get("ok")) && "1.000000000".equals(res.get("amountUnits")), "Java 客户端：读挑战 → 签名 → POST callback → " + res.get("reason"));
        java.nio.file.Files.deleteIfExists(tmp);

        for (HttpServer s : servers) s.stop(0);
        return failed;
    }

    private static boolean throwsIAE(Runnable r) {
        try { r.run(); return false; } catch (IllegalArgumentException e) { return true; }
    }

    private static String indent(String s) { return "       " + s.replace("\n", "\n       "); }

    // ── 模拟节点 ──────────────────────────────────────────────────────

    private String namespaceNode(Supplier<Map<String, Object>> verify, String addr, byte[] pub) throws Exception {
        HttpServer s = server();
        s.createContext("/v1/verify", ex -> reply(ex, Json.write(verify.get())));
        s.createContext("/v1/pubkey", ex -> reply(ex, ex.getRequestURI().getQuery().contains(addr)
                ? Json.write(Map.of("address", addr, "found", true, "pubkey", Sha3.toHex(pub))) : "{\"found\":false}"));
        return url(s);
    }

    private String chainNode(Supplier<String> data) throws Exception {
        HttpServer s = server();
        s.createContext("/v1/pledge/", ex -> reply(ex, Json.write(Map.of("ok", true, "kind", "pledge", "data", data.get()))));
        return url(s);
    }

    private HttpServer server() throws Exception {
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 16);
        s.start();
        servers.add(s);
        return s;
    }

    private static void reply(com.sun.net.httpserver.HttpExchange ex, String body) throws java.io.IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(200, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    private static String url(HttpServer s) { return "http://127.0.0.1:" + s.getAddress().getPort(); }

    private static int freePort() throws Exception {
        try (java.net.ServerSocket ss = new java.net.ServerSocket(0)) { return ss.getLocalPort(); }
    }

    private static byte[] httpGet(String u) throws Exception {
        return java.net.http.HttpClient.newHttpClient().send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(u)).build(),
                java.net.http.HttpResponse.BodyHandlers.ofByteArray()).body();
    }
}
