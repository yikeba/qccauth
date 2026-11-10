package qcc.auth.crypto;



import java.math.BigInteger;
import java.util.Arrays;

/**
 * QCC 单签地址：与 QCC 公链 qcc.service.AddressTool.deriveAddress 算法一致（零依赖移植）。
 *
 *   hash20   = SHA3-256(公钥 2592 字节)[0..20)
 *   payload  = 0x3A | hash20                        （21 字节）
 *   checksum = SHA3-256(SHA3-256(payload))[0..4)
 *   地址     = Base58(payload | checksum)           （25 字节 → 34 字符，天然以 'Q' 开头）
 *
 * 用途：0 资产钱包链上没有公钥时，客户端随请求提交公钥；节点用本类确认
 * "公钥推导出的地址 == 请求地址"，否则任何人都能拿自己的公钥冒充别人的地址。
 */
public final class QccAddress {

    public static final byte VERSION_SINGLE = 0x3A;
    public static final int  LENGTH = 34;

    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger B58 = BigInteger.valueOf(58);

    private QccAddress() {}

    /** 公钥（原始字节）→ 地址。 */
    public static String derive(byte[] pubkey) {
        byte[] h = Sha3.hash(pubkey);
        byte[] payload = new byte[21];
        payload[0] = VERSION_SINGLE;
        System.arraycopy(h, 0, payload, 1, 20);
        byte[] check = Sha3.hash(Sha3.hash(payload));
        byte[] bin = Arrays.copyOf(payload, 25);
        System.arraycopy(check, 0, bin, 21, 4);
        return base58(bin);
    }

    /** 公钥是否推导出该地址。 */
    public static boolean matches(byte[] pubkey, String address) {
        return pubkey != null && pubkey.length > 0 && address != null && address.equals(derive(pubkey));
    }

    /** 地址格式 + 版本 + checksum 校验（单签 Q 地址）。 */
    public static boolean isValid(String address) {
        if (address == null || address.length() != LENGTH || address.charAt(0) != 'Q') return false;
        byte[] bin = unbase58(address);
        if (bin == null || bin.length != 25 || bin[0] != VERSION_SINGLE) return false;
        byte[] check = Sha3.hash(Sha3.hash(Arrays.copyOf(bin, 21)));
        for (int i = 0; i < 4; i++) if (bin[21 + i] != check[i]) return false;
        return true;
    }

    // ── Base58（Bitcoin 字母表，前导 0x00 → '1'）────────────────────

    static String base58(byte[] in) {
        int zeros = 0;
        while (zeros < in.length && in[zeros] == 0) zeros++;
        BigInteger n = new BigInteger(1, in);
        StringBuilder sb = new StringBuilder();
        while (n.signum() > 0) {
            BigInteger[] qr = n.divideAndRemainder(B58);
            sb.append(ALPHABET.charAt(qr[1].intValue()));
            n = qr[0];
        }
        for (int i = 0; i < zeros; i++) sb.append('1');
        return sb.reverse().toString();
    }

    static byte[] unbase58(String s) {
        BigInteger n = BigInteger.ZERO;
        int zeros = 0;
        while (zeros < s.length() && s.charAt(zeros) == '1') zeros++;
        for (char c : s.toCharArray()) {
            int d = ALPHABET.indexOf(c);
            if (d < 0) return null;
            n = n.multiply(B58).add(BigInteger.valueOf(d));
        }
        byte[] raw = n.toByteArray();
        int strip = raw.length > 1 && raw[0] == 0 ? 1 : 0;
        if (n.signum() == 0) { raw = new byte[0]; strip = 0; }
        byte[] out = new byte[zeros + raw.length - strip];
        System.arraycopy(raw, strip, out, zeros, raw.length - strip);
        return out;
    }
}
