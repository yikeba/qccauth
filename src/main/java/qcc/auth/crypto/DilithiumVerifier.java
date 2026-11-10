package qcc.auth.crypto;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.util.encoders.Hex;
import java.nio.charset.StandardCharsets;

/**
 * 中间池专用验签器（原样取自 QCC qcc.service.DilithiumVerifier，仅改包名、删去未使用的 import）
 * 特性：无状态、纯静态、高性能
 * 职责：只负责验证 [数据] + [公钥] + [签名] 是否匹配
 */
public class DilithiumVerifier {

    // 必须与客户端钱包保持一致 (Dilithium5)
   // private static final DilithiumParameters PARAMS = DilithiumParameters.dilithium5;


    /**
     * 核心验证方法：对接 Flutter liboqs (ML-DSA-87 / FIPS 204)
     */
    public static boolean verifyFlutterSignature(String pubKeyHex, String payload, String sigHex) {
        try {
            byte[] publicKeyBytes = Hex.decode(pubKeyHex);
            byte[] signatureBytes = Hex.decode(sigHex);
            byte[] messageBytes = payload.getBytes(StandardCharsets.UTF_8);
            // 构造 ML-DSA-87 参数 (对应 Dilithium 5 的 FIPS 版本)
            MLDSAPublicKeyParameters pubKeyParams = new MLDSAPublicKeyParameters(
                    MLDSAParameters.ml_dsa_87,
                    publicKeyBytes
            );
            MLDSASigner verifier = new MLDSASigner();
            // 默认为空 Context，与 Flutter liboqs 默认配置对齐
            // 2. 初始化验证器
            verifier.init(false, pubKeyParams);
            // 3. 【关键修正】：必须先调用 update 注入原始消息
            // 这是由于 MLDSASigner 实现了 Signer 接口，采用了流式处理
            verifier.update(messageBytes, 0, messageBytes.length);
            return verifier.verifySignature(signatureBytes);
        } catch (Exception e) {
            System.err.println("验签逻辑崩溃: " + e.getMessage());
            return false;
        }
    }

    // 服务器验签：同时支持 dilithium5/ML-DSA-87
    public static boolean verify(String pubKeyHex, String payload, String sigHex) {
        return verifyFlutterSignature(pubKeyHex,payload,sigHex);

    }

    // 服务器验签：同时支持ML-DSA-87
    public static boolean verify(byte[] pubKeyHex, String payload, byte[] sigHex) {
        return verifySignature(pubKeyHex,payload,sigHex);

    }


    public static boolean verifyDilithium(String publicKeyHex, String payload, byte[] signature) {
        try {
           // LogObj.println("签名内容长度:"+payload.length());
            byte[] publicKeyBytes = Hex.decode(publicKeyHex);
            byte[] messageBytes = payload.getBytes(StandardCharsets.UTF_8);
            // 构造 ML-DSA-87 参数 (对应 Dilithium 5 的 FIPS 版本)
            MLDSAPublicKeyParameters pubKeyParams = new MLDSAPublicKeyParameters(
                    MLDSAParameters.ml_dsa_87,
                    publicKeyBytes
            );
            MLDSASigner verifier = new MLDSASigner();
            // 默认为空 Context，与 Flutter liboqs 默认配置对齐
            // 2. 初始化验证器
            verifier.init(false, pubKeyParams);
            // 3. 【关键修正】：必须先调用 update 注入原始消息
            // 这是由于 MLDSASigner 实现了 Signer 接口，采用了流式处理
            verifier.update(messageBytes, 0, messageBytes.length);

            return verifier.verifySignature(signature);
        } catch (Exception e) {
            System.err.println("验签逻辑崩溃: " + e.getMessage());
            return false;
        }
    }


    /**
     * 核心验证方法：对接 Flutter liboqs (ML-DSA-87 / FIPS 204)
     */
    public static boolean verifySignature(byte[] publicKeyBytes, String payload, byte[] signatureBytes) {
        try {
          //  LogObj.println("签名内容长度:"+payload.length());
            byte[] messageBytes = payload.getBytes(StandardCharsets.UTF_8);
            // 构造 ML-DSA-87 参数 (对应 Dilithium 5 的 FIPS 版本)
            MLDSAPublicKeyParameters pubKeyParams = new MLDSAPublicKeyParameters(
                    MLDSAParameters.ml_dsa_87,
                    publicKeyBytes
            );
            MLDSASigner verifier = new MLDSASigner();
            // 默认为空 Context，与 Flutter liboqs 默认配置对齐
            // 2. 初始化验证器
            verifier.init(false, pubKeyParams);
            // 3. 【关键修正】：必须先调用 update 注入原始消息
            // 这是由于 MLDSASigner 实现了 Signer 接口，采用了流式处理
            verifier.update(messageBytes, 0, messageBytes.length);
            // 4. 最后传入签名进行验证
            boolean result = verifier.verifySignature(signatureBytes);
            // System.out.println("--------------------------------------");
            // System.out.println("【收到签名验证请求】");
            // System.out.println("消息内容: " + payload);
           // System.out.println("签名长度: " + signatureBytes.length);
            //System.out.println("验证状态: " + (result ? "✅ 通过" : "❌ 拦截"));
            // System.out.println("--------------------------------------");
            return result;
        } catch (Exception e) {
            System.err.println("验签逻辑崩溃: " + e.getMessage());
            return false;
        }
    }


    // ═══════════════════════════════════════════════════════════════
// 以下方法追加到 DilithiumVerifier 类中（不改动你原有的任何方法）
// 目的：容器批量验证场景下，同一地址在容器内可能出现多条交易，
//      避免每条都重新 Hex.decode + new MLDSAPublicKeyParameters()
// ═══════════════════════════════════════════════════════════════

    /**
     * 【新增】接受预解析的公钥对象进行验签。
     * 供批量场景使用：调用方自行缓存 parsePublicKey() 的结果，
     * 同一地址的公钥在整个容器验证过程中只解析一次。
     */
    public static boolean verifySignature(MLDSAPublicKeyParameters pubKeyParams, String payload, byte[] signatureBytes) {
        try {
            byte[] messageBytes = payload.getBytes(StandardCharsets.UTF_8);
            MLDSASigner verifier = new MLDSASigner();
            verifier.init(false, pubKeyParams);
            verifier.update(messageBytes, 0, messageBytes.length);
            return verifier.verifySignature(signatureBytes);
        } catch (Exception e) {
            System.err.println("验签逻辑崩溃(cached pubkey): " + e.getMessage());
            return false;
        }
    }

    /**
     * 【新增】仅做公钥解析，结果由调用方缓存（例如按 address 缓存）。
     * pubKeyHex 来自 AddressKeyVault。
     */
    public static MLDSAPublicKeyParameters parsePublicKey(String pubKeyHex) {
        byte[] publicKeyBytes = Hex.decode(pubKeyHex);
        return new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_87, publicKeyBytes);
    }
}