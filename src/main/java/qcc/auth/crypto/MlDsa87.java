package qcc.auth.crypto;

/**
 * ML-DSA-87（FIPS 204）门面。纯模式、空 context、直接签消息原文（与 Flutter liboqs 钱包、
 * QCC DilithiumVerifier 一致）。
 *
 * 后端在类加载时选定，之后不变：
 *   1. classpath 上有 BouncyCastle（bcprov 1.79+，QCC 用 1.81）→ BcMlDsa，验签走 DilithiumVerifier
 *   2. 否则 JDK 24+ 原生 → JdkMlDsa
 *   3. 都没有 → selfCheck() 抛异常，节点拒绝启动
 */
public final class MlDsa87 {

    public static final int PUBKEY_LEN = 2592;
    public static final int SIG_LEN    = 4627;

    /** 密钥对：pub = 2592 字节裸公钥（链上格式）；priv = 后端自己的私钥编码，只在本机使用。 */
    public record Keys(byte[] pub, byte[] priv) {}

    interface Backend {
        String  name();
        boolean verify(byte[] rawPubkey, byte[] message, byte[] signature);
        Keys    generate();
        byte[]  sign(byte[] privateKey, byte[] message);
    }

    private static final Backend B = choose();

    private static Backend choose() {
        try {
            Class.forName("org.bouncycastle.pqc.crypto.mldsa.MLDSASigner");
            return (Backend) Class.forName("qcc.auth.crypto.BcMlDsa").getDeclaredConstructor().newInstance();
        } catch (Throwable ignored) { }
        return JdkMlDsa.available() ? new JdkMlDsa() : null;
    }

    private MlDsa87() {}

    public static void selfCheck() {
        if (B == null)
            throw new IllegalStateException("没有可用的 ML-DSA-87 实现：classpath 上需要 bcprov-jdk18on 1.79+（QCC 用 1.81），"
                    + "或运行在 JDK 24+ —— 拒绝启动");
    }

    public static String source() { return B == null ? "无" : B.name(); }

    /** 验签。格式不符一律返回 false。 */
    public static boolean verify(byte[] rawPubkey, byte[] message, byte[] signature) {
        if (B == null || rawPubkey == null || rawPubkey.length != PUBKEY_LEN
                || signature == null || signature.length != SIG_LEN || message == null) return false;
        return B.verify(rawPubkey, message, signature);
    }

    public static Keys   generate()                       { selfCheck(); return B.generate(); }
    public static byte[] sign(byte[] priv, byte[] message) { selfCheck(); return B.sign(priv, message); }
}
