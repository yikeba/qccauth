package qcc.auth.json;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 严格 JSON 解析器 —— 只为解析链上引导协议而存在。
 *
 * ═══ 为什么不用 fastjson2 ═════════════════════════════════════════
 * 引导协议是整个系统的信任根。用一个通用 JSON 库解析它有三个问题:
 *
 *  1. 【重复 key】fastjson2 遇到 {"a":1,"a":2} 会静默取后者。
 *     Dart 的 jsonDecode 也是。但这是**未定义行为**,没有任何规范保证
 *     两者一致,也没人保证下个版本还这样。协议文档里出现重复 key 时,
 *     两个实现读出不同的参数值 —— 而 protocolHash 完全相同,查无可查。
 *     这里直接**拒绝**重复 key。
 *
 *  2. 【数字精度】JSON 数字没有类型。1000000000 是 int 还是 double?
 *     Dart 在 Web 平台上 int 就是 double,超过 2^53 静默丢精度。
 *     这里整数一律按 long 解析,超出范围抛异常,绝不静默降级。
 *
 *  3. 【宽松模式】各家库对注释、尾随逗号、单引号、NaN 的容忍度不同。
 *     这里全部拒绝,只接受 RFC 8259 的严格子集。
 *
 * 输出全部是不可变结构。
 */
public final class StrictJson {

    private final String s;
    private int i;

    private StrictJson(String s) { this.s = s; this.i = 0; }

    /** 解析一个 JSON 对象。尾部有非空白内容即报错。 */
    public static Map<String, Object> parseObject(byte[] utf8) {
        StrictJson p = new StrictJson(new String(utf8, StandardCharsets.UTF_8));
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != p.s.length())
            throw err("尾部有多余内容 @" + p.i);
        if (!(v instanceof Map))
            throw err("顶层必须是对象");
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) v;
        return m;
    }

    // ── 取值辅助:全部严格,类型不符即抛 ───────────────────────────

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Map<String, Object> m, String k) {
        Object v = need(m, k);
        if (!(v instanceof Map)) throw err("字段 " + k + " 不是对象");
        return (Map<String, Object>) v;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> arr(Map<String, Object> m, String k) {
        Object v = need(m, k);
        if (!(v instanceof List)) throw err("字段 " + k + " 不是数组");
        return (List<Object>) v;
    }

    public static String str(Map<String, Object> m, String k) {
        Object v = need(m, k);
        if (!(v instanceof String)) throw err("字段 " + k + " 不是字符串");
        String s = (String) v;
        if (s.isEmpty()) throw err("字段 " + k + " 为空字符串");
        return s;
    }

    /** 允许空串(prevProtocolHash 首版就是空串,但字段必须存在)。 */
    public static String strAllowEmpty(Map<String, Object> m, String k) {
        Object v = need(m, k);
        if (!(v instanceof String)) throw err("字段 " + k + " 不是字符串");
        return (String) v;
    }

    public static long num(Map<String, Object> m, String k) {
        Object v = need(m, k);
        if (!(v instanceof Long)) throw err("字段 " + k + " 不是整数(小数与超范围值一律拒绝)");
        return (Long) v;
    }

    public static boolean bool(Map<String, Object> m, String k) {
        Object v = need(m, k);
        if (!(v instanceof Boolean)) throw err("字段 " + k + " 不是布尔");
        return (Boolean) v;
    }

    public static List<String> strArr(Map<String, Object> m, String k) {
        List<Object> raw = arr(m, k);
        List<String> out = new ArrayList<>(raw.size());
        for (Object o : raw) {
            if (!(o instanceof String)) throw err("字段 " + k + " 的元素不是字符串");
            out.add((String) o);
        }
        return List.copyOf(out);
    }

    private static Object need(Map<String, Object> m, String k) {
        if (!m.containsKey(k)) throw err("缺少字段: " + k);
        Object v = m.get(k);
        if (v == null) throw err("字段 " + k + " 为 null —— 协议不允许 null,请用空串或省略");
        return v;
    }

    /** 未知字段致命:出现本实现不认识的字段说明 jar 比协议旧,拒绝启动。 */
    public static void rejectUnknown(Map<String, Object> m, java.util.Set<String> allowed, String where) {
        for (String k : m.keySet())
            if (!allowed.contains(k))
                throw err("未知字段 '" + k + "' 出现在 " + where
                        + " —— 本实现比协议旧,拒绝启动");
    }

    // ── 解析实现 ──────────────────────────────────────────────────

    private Object value() {
        if (i >= s.length()) throw err("意外结束 @" + i);
        char c = s.charAt(i);
        return switch (c) {
            case '{' -> object();
            case '[' -> array();
            case '"' -> string();
            case 't' -> lit("true", Boolean.TRUE);
            case 'f' -> lit("false", Boolean.FALSE);
            case 'n' -> throw err("协议文档不允许 null @" + i);
            default  -> number();
        };
    }

    private Map<String, Object> object() {
        expect('{');
        Map<String, Object> m = new LinkedHashMap<>();
        ws();
        if (peek() == '}') { i++; return Collections.unmodifiableMap(m); }
        while (true) {
            ws();
            if (peek() != '"') throw err("对象的 key 必须是字符串 @" + i);
            String k = string();
            ws(); expect(':'); ws();
            Object v = value();
            if (m.put(k, v) != null)
                throw err("重复的 key: '" + k + "' —— 拒绝解析。"
                        + "重复 key 在 JSON 里是未定义行为,不同实现取值可能不同");
            ws();
            char c = peek();
            if (c == ',') { i++; continue; }
            if (c == '}') { i++; break; }
            throw err("对象里期望 ',' 或 '}',读到 '" + c + "' @" + i);
        }
        return Collections.unmodifiableMap(m);
    }

    private List<Object> array() {
        expect('[');
        List<Object> out = new ArrayList<>();
        ws();
        if (peek() == ']') { i++; return List.copyOf(out); }
        while (true) {
            ws();
            out.add(value());
            ws();
            char c = peek();
            if (c == ',') { i++; continue; }
            if (c == ']') { i++; break; }
            throw err("数组里期望 ',' 或 ']',读到 '" + c + "' @" + i);
        }
        return List.copyOf(out);
    }

    private String string() {
        expect('"');
        StringBuilder b = new StringBuilder();
        while (true) {
            if (i >= s.length()) throw err("字符串未闭合");
            char c = s.charAt(i++);
            if (c == '"') break;
            if (c == '\\') {
                if (i >= s.length()) throw err("转义未完成");
                char e = s.charAt(i++);
                switch (e) {
                    case '"'  -> b.append('"');
                    case '\\' -> b.append('\\');
                    case '/'  -> b.append('/');
                    case 'b'  -> b.append('\b');
                    case 'f'  -> b.append('\f');
                    case 'n'  -> b.append('\n');
                    case 'r'  -> b.append('\r');
                    case 't'  -> b.append('\t');
                    case 'u'  -> {
                        if (i + 4 > s.length()) throw err("\\u 转义不完整");
                        b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                    }
                    default -> throw err("非法转义 \\" + e + " @" + (i - 1));
                }
            } else if (c < 0x20) {
                throw err("字符串里出现未转义的控制字符 0x" + Integer.toHexString(c));
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }

    private Long number() {
        int start = i;
        if (peek() == '-') i++;
        while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
        if (i == start || (i == start + 1 && s.charAt(start) == '-'))
            throw err("非法数字 @" + start);
        if (i < s.length() && (s.charAt(i) == '.' || s.charAt(i) == 'e' || s.charAt(i) == 'E'))
            throw err("协议文档不允许小数或科学计数法 @" + start
                    + " —— 精度依赖实现,是跨语言分歧的常见来源");
        String t = s.substring(start, i);
        if (t.length() > 1 && (t.charAt(0) == '0' || t.startsWith("-0")))
            throw err("数字不允许前导零: " + t);
        try {
            return Long.parseLong(t);
        } catch (NumberFormatException e) {
            throw err("整数超出 64 位范围: " + t);
        }
    }

    private Object lit(String word, Object v) {
        if (!s.startsWith(word, i)) throw err("非法字面量 @" + i);
        i += word.length();
        return v;
    }

    /** 只接受 RFC 8259 的四种空白。注释、尾随逗号一律不接受。 */
    private void ws() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++;
            else break;
        }
    }

    private char peek() {
        if (i >= s.length()) throw err("意外结束 @" + i);
        return s.charAt(i);
    }

    private void expect(char c) {
        if (peek() != c) throw err("期望 '" + c + "' 读到 '" + peek() + "' @" + i);
        i++;
    }

    private static IllegalStateException err(String m) {
        return new IllegalStateException("[协议解析] " + m);
    }
}
