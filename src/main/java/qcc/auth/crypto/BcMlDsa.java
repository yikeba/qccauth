package qcc.auth.crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * BouncyCastle（bcprov 1.81，与 QCC 同版本）后端。验签直接走 QCC 的 DilithiumVerifier。
 * 密钥生成与签名只供本地模拟和开发客户端使用（真实环境由钱包签名）。
 * 私钥用 MLDSAPrivateKeyParameters.getEncoded() 的格式保存。
 */
final class BcMlDsa implements MlDsa87.Backend {

    private final SecureRandom rnd = new SecureRandom();

    @Override public String name() { return "BouncyCastle（QCC DilithiumVerifier）"; }

    @Override
    public boolean verify(byte[] rawPubkey, byte[] message, byte[] signature) {
        return DilithiumVerifier.verifySignature(rawPubkey, new String(message, StandardCharsets.UTF_8), signature);
    }

    @Override
    public MlDsa87.Keys generate() {
        MLDSAKeyPairGenerator g = new MLDSAKeyPairGenerator();
        g.init(new MLDSAKeyGenerationParameters(rnd, MLDSAParameters.ml_dsa_87));
        AsymmetricCipherKeyPair kp = g.generateKeyPair();
        return new MlDsa87.Keys(((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded(),
                ((MLDSAPrivateKeyParameters) kp.getPrivate()).getEncoded());
    }

    @Override
    public byte[] sign(byte[] privateKey, byte[] message) {
        try {
            MLDSASigner s = new MLDSASigner();
            s.init(true, new ParametersWithRandom(new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_87, privateKey), rnd));
            s.update(message, 0, message.length);
            return s.generateSignature();
        } catch (Exception e) {
            throw new IllegalStateException("签名失败", e);
        }
    }
}
