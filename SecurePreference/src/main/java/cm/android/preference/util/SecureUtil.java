package cm.android.preference.util;

import java.security.SecureRandom;

import javax.crypto.spec.IvParameterSpec;

public final class SecureUtil {

    private SecureUtil() {
    }

    public static final String RANDOM_ALGORITHM = "SHA1PRNG";

    public static final byte[] IV_DEF = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    public static final byte[] SALT_DEF = {(byte) 0xA4, (byte) 0x0B, (byte) 0xC8, (byte) 0x34,
            (byte) 0xD6, (byte) 0x95, (byte) 0xF3, (byte) 0x13};

    public static IvParameterSpec getIv(byte[] iv) {
        if (iv == null) {
            iv = SecureUtil.IV_DEF;
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
