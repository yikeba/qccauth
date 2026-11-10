package qcc.auth;

import qcc.auth.json.Json;

import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 鉴权信息（不是 true / false）。应用拿它自己决定权限、等级、额度 —— 鉴权与应用服务权利解耦。
 *
 * <pre>
 *   AuthInfo info = auth.verify(data);
 *   if (info.ok()) {
 *       String account = info.name();                       // chen.qcc
 *       long gb = info.amountUnits().longValue();           // 例：qccemail 每 1 QCC 质押 = 1G 邮箱空间
 *   } else if (info.retryable()) { … 节点暂时不足，稍后重试 … }
 * </pre>
 */
public record AuthInfo(
        Status status, String reason,
        String action, String name, String address,
        String pledgeTag, String credentialHash,     // 链上凭证三要素：address + pledgeTag + credentialHash
        String assetId, long amount, int assetDecimals,
        int namespaceMatched, int namespaceAsked,    // 名称核对：几个 namespace 节点确认 / 询问了几个
        int chainConfirmed, int chainAsked,          // 质押核对：几个链节点确认 / 询问了几个
        boolean pubkeyFromClient,
        long verifiedAt,
        boolean reserved) {                          // 保留名：名字由 namespace 协议发布者在 Reserved 中指定（不经质押）

    public enum Status {
        OK,
        BAD_FORMAT, WRONG_APP, WRONG_CHAIN, UNKNOWN_NONCE, EXPIRED, NAME_MISMATCH, TAG_NOT_ALLOWED,  // 请求不对
        NO_PUBKEY, PUBKEY_MISMATCH, BAD_SIGNATURE,                                                   // L1 身份
        NAME_NOT_OWNED,                                                                              // L2 名称
        NOT_QUALIFIED,                                                                               // L3 质押
        NAMESPACE_UNAVAILABLE, CHAIN_UNAVAILABLE;                                                    // 可重试

        public boolean retryable() { return this == NAMESPACE_UNAVAILABLE || this == CHAIN_UNAVAILABLE; }
    }

    public boolean ok()        { return status == Status.OK; }
    public boolean retryable() { return status.retryable(); }

    /** 质押折合资产单位数，如 10000000000 最小单位 → 10.000000000 QCC。 */
    public BigDecimal amountUnits() { return BigDecimal.valueOf(amount, assetDecimals); }

    static AuthInfo fail(Status s, String reason, long at) {
        return new AuthInfo(s, reason, null, null, null, null, null, null, 0, 0, 0, 0, 0, 0, false, at, false);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok());
        m.put("status", status.name());
        m.put("retryable", retryable());
        m.put("reason", reason);
        if (name != null) {
            m.put("action", action);
            m.put("name", name);
            m.put("address", address);
        }
        if (credentialHash != null) {
            m.put("pledgeTag", pledgeTag);
            m.put("credentialHash", credentialHash);
        }
        if (assetId != null) {
            m.put("assetId", assetId);
            m.put("amount", amount);
            m.put("amountUnits", amountUnits().toPlainString());
        }
        if (reserved) m.put("reserved", true);
        if (namespaceAsked > 0) m.put("namespace", namespaceMatched + "/" + namespaceAsked);
        if (chainAsked > 0) m.put("chain", chainConfirmed + "/" + chainAsked);
        m.put("verifiedAt", verifiedAt);
        return m;
    }

    public String toJson() { return Json.write(toMap()); }
}
