package qcc.auth.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * namespace 全局唯一的 SHA3-256 入口。
 *
 * 为什么不直接用 qcc.util.CryptoUtil:
 *   1. CryptoUtil 没有多段哈希 API。execHash 是
 *      SHA3(prev || opCode || payload || sigHash || resultCode || delta),
 *      拼成一个大数组再哈希会产生大量临时对象,且拼接本身就是一次隐式的
 *      编码约定 —— 必须由 codec 层统一定义,不能散落在调用方。
 *   2. CryptoUtil.bytesToHex 用 String.format,比手写慢两个数量级;
 *      而同一个类里的 sha3256Hex 又走 BouncyCastle 的 Hex —— 两套实现。
 *   3. CryptoUtil.hexToBytes 遇到非法字符会静默产出错误字节。
 *      在 namespace 里 hex 是 nameHash / execHash / 地址,错一个字符
 *      就是错一条记录,必须 fail-fast。
 *
 * 本类的输出与 CryptoUtil.sha3256 完全一致(同一个 JDK MessageDigest),
 * 所以两边可以共存;但 namespace 内部只准用这一个。
 *
 * 线程安全:MessageDigest 非线程安全,这里用 ThreadLocal,每次进入先 reset,
 * 避免上一次调用异常退出时残留的脏状态污染本次结果。
 */
public final class Sha3 {

    public static final int HASH_LEN = 32;
    public static final int HEX_LEN  = 64;

    /** 32 字节全零,稀疏 Merkle 的空叶子。不可变:每次返回副本。 */
    public static byte[] zero32() { return new byte[HASH_LEN]; }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private static final ThreadLocal<MessageDigest> MD = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA3-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA3-256 不可用,需要 JDK 15+ 或 BouncyCastle", e);
        }
    });

    private Sha3() {}

    // ── 哈希 ──────────────────────────────────────────────────────

    /**
     * 多段哈希:等价于把各段按给定顺序拼接后哈希。
     * 段与段之间不插入任何分隔符 —— 因此**每一段必须自带长度或定长**,
     * 由 QccCanonicalWriter 保证。直接拿变长裸字节调用本方法会产生歧义。
     */
    public static byte[] hash(byte[]... parts) {
        MessageDigest md = MD.get();
        md.reset();
        for (byte[] p : parts) {
            if (p == null) throw new IllegalArgumentException("hash part is null");
            md.update(p);
        }
        return md.digest();
    }

    public static String hashHex(byte[]... parts) {
        return toHex(hash(parts));
    }

    /** 只对 UTF-8 字节哈希。永远不使用平台默认字符集。 */
    public static byte[] hashUtf8(String s) {
        return hash(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public static String hashUtf8Hex(String s) {
        return toHex(hashUtf8(s));
    }

    // ── hex ───────────────────────────────────────────────────────

    public static String toHex(byte[] b) {
        if (b == null) throw new IllegalArgumentException("toHex(null)");
        char[] out = new char[b.length * 2];
        for (int i = 0, j = 0; i < b.length; i++) {
            int v = b[i] & 0xFF;
            out[j++] = HEX[v >>> 4];
            out[j++] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    /**
     * 严格 hex 解码。长度必须为偶数,字符必须是 0-9a-fA-F。
     * 任何不合法输入抛异常 —— 绝不静默补零或产出错误字节。
     */
    public static byte[] fromHex(String hex) {
        if (hex == null) throw new IllegalArgumentException("fromHex(null)");
        int n = hex.length();
        if ((n & 1) != 0) throw new IllegalArgumentException("hex 长度必须为偶数: " + n);
        byte[] out = new byte[n / 2];
        for (int i = 0, j = 0; i < n; i += 2, j++) {
            int hi = digit(hex.charAt(i));
            int lo = digit(hex.charAt(i + 1));
            out[j] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /** 严格解码一个 64 字符的 hex 哈希。长度不是 64 直接抛。 */
    public static byte[] fromHex32(String hex) {
        if (hex == null || hex.length() != HEX_LEN)
            throw new IllegalArgumentException(
                    "需要 " + HEX_LEN + " 字符的 hex,实际: " + (hex == null ? "null" : hex.length()));
        return fromHex(hex);
    }

    public static boolean isHex32(String hex) {
        if (hex == null || hex.length() != HEX_LEN) return false;
        for (int i = 0; i < HEX_LEN; i++) {
            char c = hex.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!ok) return false;
        }
        return true;
    }

    private static int digit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw new IllegalArgumentException("非法 hex 字符: '" + c + "'");
    }

    /** 常量时间比较。用于对外可见的哈希比对,避免时序侧信道。 */
    public static boolean equalsConstantTime(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
