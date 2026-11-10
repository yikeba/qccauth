package qcc.auth.crypto;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * JDK 24+ 原生后端（JEP 497）。classpath 上没有 BouncyCastle 时使用。
 * 与 BC 同为 FIPS 204 定稿版、纯模式、空 context，签名互通。
 * 链上是 2592 字节裸公钥，JCA 只认 X.509，这里补固定的 22 字节 DER 头
 * （OID 2.16.840.1.101.3.4.3.19，已用 JDK 25 生成的密钥对照）。私钥保存为 PKCS#8。
 */
final class JdkMlDsa implements MlDsa87.Backend {

    private static final String ALG = "ML-DSA-87";
    private static final byte[] SPKI_PREFIX = {
            0x30, (byte) 0x82, 0x0a, 0x32,
            0x30, 0x0b, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
            0x03, (byte) 0x82, 0x0a, 0x21, 0x00 };

    static boolean available() {
        try { KeyFactory.getInstance(ALG); Signature.getInstance(ALG); return true; }
        catch (Exception e) { return false; }
    }

    @Override public String name() { return "JDK " + System.getProperty("java.version") + " 原生"; }

    @Override
    public boolean verify(byte[] rawPubkey, byte[] message, byte[] signature) {
        try {
            byte[] spki = Arrays.copyOf(SPKI_PREFIX, SPKI_PREFIX.length + rawPubkey.length);
            System.arraycopy(rawPubkey, 0, spki, SPKI_PREFIX.length, rawPubkey.length);
            Signature s = Signature.getInstance(ALG);
            s.initVerify(KeyFactory.getInstance(ALG).generatePublic(new X509EncodedKeySpec(spki)));
            s.update(message);
            return s.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public MlDsa87.Keys generate() {
        try {
            KeyPair kp = KeyPairGenerator.getInstance(ALG).generateKeyPair();
            byte[] enc = kp.getPublic().getEncoded();
            if (enc.length != SPKI_PREFIX.length + MlDsa87.PUBKEY_LEN
                    || !Arrays.equals(Arrays.copyOf(enc, SPKI_PREFIX.length), SPKI_PREFIX))
                throw new IllegalStateException("非预期的公钥编码");
            return new MlDsa87.Keys(Arrays.copyOfRange(enc, SPKI_PREFIX.length, enc.length), kp.getPrivate().getEncoded());
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(ALG + " 不可用", e);
        }
    }

    @Override
    public byte[] sign(byte[] privateKey, byte[] message) {
        try {
            Signature s = Signature.getInstance(ALG);
            s.initSign(KeyFactory.getInstance(ALG).generatePrivate(new PKCS8EncodedKeySpec(privateKey)));
            s.update(message);
            return s.sign();
        } catch (Exception e) {
            throw new IllegalStateException("签名失败", e);
        }
    }
}
