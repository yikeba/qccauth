package qcc.auth;

import qcc.auth.crypto.MlDsa87;
import qcc.auth.crypto.QccAddress;
import qcc.auth.json.StrictJson;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/**
 * qcc-auth/1 客户端侧（Java）：读取挑战 → 签名生成 {@link AuthRequest} → 提交到应用 callback。
 * 用于 Java 客户端、服务之间鉴权（服务器自己持有一个签名钱包身份）及自测。Flutter 钱包见 qcc_auth.dart。
 *
 * <pre>
 *   QccAuthClient.Signer me = QccAuthClient.mlDsa(privKey, pubKey);
 *   Map<String, Object> r = QccAuthClient.login("http://…/auth/c/9f3c…", "api.osn", me, false);
 * </pre>
 */
public final class QccAuthClient {

    /** 钱包签名器：私钥不出这个对象。 */
    public interface Signer {
        String address();
        byte[] pubkey();
        byte[] sign(byte[] message);
    }

    public static Signer mlDsa(byte[] privateKey, byte[] publicKey) {
        String addr = QccAddress.derive(publicKey);
        return new Signer() {
            public String address() { return addr; }
            public byte[] pubkey() { return publicKey.clone(); }
            public byte[] sign(byte[] m) { return MlDsa87.sign(privateKey, m); }
        };
    }

    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(6)).build();

    private QccAuthClient() {}

    /** 读取挑战：链接（GET 返回挑战 JSON）或直接是 JSON 文本。 */
    public static QccAuth.Challenge fetch(String linkOrJson) throws Exception {
        String s = linkOrJson.trim();
        byte[] body = s.startsWith("{") ? s.getBytes(StandardCharsets.UTF_8) : get(s);
        return QccAuth.Challenge.fromMap(StrictJson.parseObject(body));
    }

    /** 按挑战签名。withPubkey=false 时由应用向 namespace 取公钥（data 小 2.6 KB）。 */
    public static AuthRequest respond(QccAuth.Challenge ch, String name, Signer s, boolean withPubkey) {
        return AuthRequest.sign(ch.action(), ch.chain(), ch.app(), name, ch.nonce(), ch.issuedAt(), ch.expiresAt(), s, withPubkey);
    }

    /** POST 到挑战里的 callback，返回应用回传的鉴权信息 JSON。 */
    public static Map<String, Object> submit(QccAuth.Challenge ch, AuthRequest req) throws Exception {
        if (ch.callback().isEmpty()) throw new IllegalArgumentException("挑战没有 callback");
        HttpRequest rq = HttpRequest.newBuilder(URI.create(ch.callback())).timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofByteArray(req.toBytes())).build();
        return StrictJson.parseObject(HTTP.send(rq, HttpResponse.BodyHandlers.ofByteArray()).body());
    }

    /** 一步完成：读挑战 → 签名 → 提交。 */
    public static Map<String, Object> login(String linkOrJson, String name, Signer s, boolean withPubkey) throws Exception {
        QccAuth.Challenge ch = fetch(linkOrJson);
        return submit(ch, respond(ch, name, s, withPubkey));
    }

    private static byte[] get(String url) throws Exception {
        HttpResponse<byte[]> r = HTTP.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build(),
                HttpResponse.BodyHandlers.ofByteArray());
        if (r.statusCode() != 200) throw new IllegalStateException("读取挑战失败 HTTP " + r.statusCode());
        return r.body();
    }
}