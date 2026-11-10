package qcc.auth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import qcc.auth.AuthInfo;
import qcc.auth.QccAuth;
import qcc.auth.QccAuthConfig;
import qcc.auth.json.Json;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * qcc-auth 演示应用（模拟 qccemail 登录端）：钱包签名 → 验签 → namespace 名称核对 → 链上质押门槛 → 提供服务。
 *
 *   java -jar qccauth.jar [config=qccauth.json] [port=9280]
 *   首次运行生成 qccauth.json 模板；callback 改成手机能访问的地址后再启动。
 *
 *   GET  /                      登录页：生成登录请求，显示链接（钱包粘贴），自动轮询结果
 *   GET  /auth/challenge?name=  新建登录请求 → {challenge, pollToken, url}
 *   GET  /auth/c/{nonce}        钱包按链接取挑战 JSON
 *   POST /auth/callback         钱包提交签名响应 → 鉴权结果
 *   GET  /auth/poll?token=      浏览器轮询 → PENDING / DONE / EXPIRED
 *   GET  /mail?session=         登录后的"服务"
 */
public final class AuthDemoServer {

    private final QccAuth auth;
    private final String publicBase;
    private final Map<String, AuthInfo> sessions = new java.util.concurrent.ConcurrentHashMap<>();

    AuthDemoServer(QccAuth auth, String publicBase) {
        this.auth = auth;
        this.publicBase = publicBase;
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> o = new HashMap<>();
        for (String a : args) { int i = a.indexOf('='); if (i > 0) o.put(a.substring(0, i), a.substring(i + 1)); }
        Path cfgFile = Path.of(o.getOrDefault("config", "qccauth.json"));
        if (!Files.exists(cfgFile)) {
            QccAuthConfig t = new QccAuthConfig().setApp("qccemail-test").setAppName("QCC Email（测试）")
                    .setCallback("http://127.0.0.1:9280/auth/callback");
            Files.writeString(cfgFile, t.toString());
            System.out.println("已生成配置 " + cfgFile.toAbsolutePath() + "（全部为默认值）：把 callback 改成手机能访问的 http://本机IP:9280/auth/callback 后重新启动");
            return;
        }
        QccAuthConfig c = QccAuthConfig.fromJson(Files.readString(cfgFile));
        QccAuth auth = new QccAuth(c);
        System.out.println("当前鉴权参数：\n" + auth.config());
        URI cb = URI.create(c.callback());
        int port = Integer.parseInt(o.getOrDefault("port", String.valueOf(cb.getPort() > 0 ? cb.getPort() : 9280)));
        String pub = cb.getScheme() + "://" + cb.getRawAuthority();
        new AuthDemoServer(auth, pub).start(port);
        System.out.println("qcc-auth 演示应用 " + pub + "   app=" + c.app() + "   监听 :" + port);
        if (auth.namespace() != null)
            System.out.println("namespace 节点（需 " + auth.namespace().quorum() + " 个 MATCH）：" + auth.namespace().nodes());
        else
            System.out.println("只做签名鉴权（nameCheck=false）：地址即账号，不查 namespace / 链");
        if (pub.contains("127.0.0.1") || pub.contains("localhost")) System.out.println("⚠ callback 是本机地址：手机钱包无法回调");
    }



    void start(int port) throws IOException {
        HttpServer s = HttpServer.create(new InetSocketAddress(port), 64);
        s.setExecutor(Executors.newFixedThreadPool(8, r -> { Thread t = new Thread(r, "auth-demo"); t.setDaemon(false); return t; }));
        s.createContext("/", this::page);
        s.createContext("/auth/challenge", ex -> {
            String name = query(ex).getOrDefault("name", "");
            try {
                QccAuth.Issued is = auth.issue(name);
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("challenge", is.challenge().toMap());
                m.put("pollToken", is.pollToken());
                m.put("url", publicBase + "/auth/c/" + is.challenge().nonce());
                json(ex, 200, m);
            } catch (RuntimeException e) {
                json(ex, 400, Map.of("error", String.valueOf(e.getMessage())));
            }
        });
        s.createContext("/auth/c/", ex -> {
            String nonce = ex.getRequestURI().getPath().substring("/auth/c/".length());
            QccAuth.Challenge ch = auth.challenge(nonce);
            if (ch == null) json(ex, 404, Map.of("error", "登录请求不存在或已过期"));
            else json(ex, 200, ch.toMap());
        });
        s.createContext("/auth/callback", ex -> {
            if (cors(ex)) return;
            if (!"POST".equals(ex.getRequestMethod())) { json(ex, 405, Map.of("error", "需要 POST")); return; }
            byte[] body = ex.getRequestBody().readNBytes(64 * 1024);
            AuthInfo r = auth.verify(body);
            System.out.println("[鉴权] " + r.toJson());
            json(ex, r.ok() ? 200 : 403, r.toMap());
        });
        s.createContext("/auth/poll", ex -> {
            QccAuth.Poll p = auth.poll(query(ex).get("token"));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("state", p.state().name());
            if (p.info() != null) {
                m.put("result", p.info().toMap());
                if (p.info().ok()) {                        // 鉴权通过 → 建立应用会话
                    String sid = java.util.UUID.randomUUID().toString();
                    sessions.put(sid, p.info());
                    m.put("session", sid);
                }
            }
            json(ex, 200, m);
        });
        s.createContext("/mail", ex -> {
            AuthInfo r = sessions.get(query(ex).getOrDefault("session", ""));
            if (r == null) { json(ex, 401, Map.of("error", "未登录")); return; }
            // 应用自己的权限规则（与鉴权解耦）：演示按每 1 QCC 质押 = 1G 邮箱空间
            long gb = r.amountUnits().longValue();
            json(ex, 200, Map.of("mailbox", r.name(), "owner", r.address(),
                    "service", "演示：已用 " + r.name() + " 登录邮箱，质押 " + r.amountUnits().stripTrailingZeros().toPlainString() + " " + r.assetId() + " → 邮箱空间 " + gb + "G"));
        });
        s.start();
    }

    private void page(HttpExchange ex) throws IOException {
        if (!"/".equals(ex.getRequestURI().getPath())) { json(ex, 404, Map.of("error", "not found")); return; }
        send(ex, 200, "text/html; charset=utf-8", PAGE.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean cors(HttpExchange ex) throws IOException {
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, OPTIONS");
        ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
        if ("OPTIONS".equals(ex.getRequestMethod())) { ex.sendResponseHeaders(204, -1); ex.close(); return true; }
        return false;
    }

    private static Map<String, String> query(HttpExchange ex) {
        Map<String, String> m = new HashMap<>();
        String q = ex.getRequestURI().getRawQuery();
        if (q != null) for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0) m.put(URLDecoder.decode(kv.substring(0, i), StandardCharsets.UTF_8), URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8));
        }
        return m;
    }

    private static void json(HttpExchange ex, int code, Object o) throws IOException {
        send(ex, code, "application/json; charset=utf-8", Json.write(o).getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange ex, int code, String type, byte[] b) throws IOException {
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, b.length);
        ex.getResponseBody().write(b);
        ex.close();
    }

    private static final String PAGE = """
<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>QCC Email 测试登录</title>
<style>
body{margin:0;font:15px/1.6 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#f7f8fa;color:#14171f}
.w{max-width:620px;margin:40px auto;padding:0 16px}.p{background:#fff;border:1px solid #e2e6ee;border-radius:14px;padding:20px;margin-bottom:14px}
h1{font-size:20px;margin:0 0 6px}input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #e2e6ee;border-radius:10px;font:14px monospace}
button{margin-top:10px;padding:10px 18px;border:0;border-radius:10px;background:#3b5bfd;color:#fff;font-weight:600;cursor:pointer}
code{display:block;word-break:break-all;background:#f1f3f7;padding:10px;border-radius:8px;font-size:12px}.s{color:#7a8294;font-size:13px}
.ok{color:#1f9d55;font-weight:700}.bad{color:#d64545;font-weight:700}
</style></head><body><div class="w">
<div class="p"><h1>QCC Email 测试登录</h1><div class="s">用 QCC 钱包签名登录，无需密码。名字由 namespace 多节点确认。</div>
<input id="n" placeholder="名称（可选，如 cto.qcc；留空则在钱包里填写）"><button onclick="go()">生成登录请求</button></div>
<div class="p" id="c" hidden><b>在钱包「授权登录」中粘贴以下链接</b>
<code id="u"></code><button onclick="navigator.clipboard.writeText(document.getElementById('u').textContent)">复制链接</button>
<div class="s" id="st" style="margin-top:10px">等待钱包签名…</div></div>
<div class="p" id="m" hidden></div>
<script>
let timer;
async function go(){
  clearInterval(timer);
  const r=await (await fetch('/auth/challenge?name='+encodeURIComponent(document.getElementById('n').value.trim()))).json();
  if(r.error){alert(r.error);return}
  document.getElementById('c').hidden=false;document.getElementById('m').hidden=true;
  document.getElementById('u').textContent=r.url;
  const st=document.getElementById('st');st.textContent='等待钱包签名…（120 秒内有效）';
  timer=setInterval(async()=>{
    const p=await (await fetch('/auth/poll?token='+r.pollToken)).json();
    if(p.state==='PENDING')return;
    clearInterval(timer);
    if(p.state!=='DONE'){st.innerHTML='<span class="bad">登录请求已过期</span>';return}
    const x=p.result;
    if(!x.ok){st.innerHTML='<span class="bad">✗ '+x.status+'：'+x.reason+'</span>';return}
    st.innerHTML='<span class="ok">✓ '+x.reason+'</span>';
    const mail=await (await fetch('/mail?session='+p.session)).json();
    const m=document.getElementById('m');m.hidden=false;
    m.innerHTML='<h1>📬 '+mail.mailbox+'</h1><div class="s">持有地址 '+mail.owner+'</div><p>'+mail.service+'</p>';
  },1500);
}
</script></div></body></html>
""";
}
