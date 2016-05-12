package cm.android.preference.util;

import java.security.SecureRandom;

import javax.crypto.spec.IvParameterSpec;

public final class SecureUtil {

    public static final String RANDOM_ALGORITHM = "SHA1PRNG";

    private static final byte[] IV_DEF = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    private static final byte[] SALT_DEF = {(byte) 0x53, (byte) 0x41,
            (byte) 0x4C, (byte) 0x54, (byte) 0x5F, (byte) 0x44, (byte) 0x45,
            (byte) 0x46};

    private SecureUtil() {
    }

    public static byte[] getSaltDef() {
        return SALT_DEF.clone();
//        return Arrays.copyOf(SALT_DEF, SALT_DEF.length);
    }

    public static byte[] getIvDef() {
//        return Arrays.copyOf(IV_DEF, IV_DEF.length);
        return IV_DEF.clone();
    }

    public static IvParameterSpec getIv(byte[] iv) {
        if (iv == null) {
            iv = SecureUtil.getIvDef();
        }
        return new IvParameterSpec(iv);
    }

    public static byte[] generateIv() {
        return randomByte(16);
    }

    public static byte[] generateSalt() {
        return randomByte(20);
    }

    private static byte[] randomByte(int length) {
        byte[] iv = new byte[length];
        SecureRandom random = getSecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    public static SecureRandom getSecureRandom() {
        try {
            // SHA1PRNG 强随机种子算法, 要区别4.2以上版本的调用方法
            return SecureRandom.getInstance(RANDOM_ALGORITHM, "Crypto");
        } catch (Exception e) {
            try {
                return SecureRandom.getInstance(RANDOM_ALGORITHM);
            } catch (Exception e1) {
                return new SecureRandom();
            }
        }
    }

    /**
     * 将字节长度转换位位长度
     */
    public static final int convertSize(int keySize) {
        return keySize * 8;
    }
}
