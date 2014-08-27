package cm.android.preference.util;

import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SecureUtil {
    public static final int SALT_LENGTH = 20;
    public static final String RANDOM_ALGORITHM = "SHA1PRNG";

    public static final byte[] IV_DEF = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    public static final byte[] SALT_DEF = {(byte) 0xA4, (byte) 0x0B, (byte) 0xC8, (byte) 0x34, (byte) 0xD6, (byte) 0x95, (byte) 0xF3, (byte) 0x13};

    public static IvParameterSpec getIv(byte[] iv) {
        if (iv == null) {
            iv = SecureUtil.IV_DEF;
        }
        return new IvParameterSpec(iv);
    }

    public static byte[] generateIv() {
        byte[] iv = new byte[16];
        try {
            SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
            random.nextBytes(iv);
        } catch (NoSuchAlgorithmException e) {
            return IV_DEF;
        }
        return iv;
    }

    public static byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }
}
