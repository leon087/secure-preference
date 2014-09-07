package cm.android.preference.util;

import android.os.Build;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class HashUtil {
    private static final String ALG_PBK_LOW = "PBKDF2WithHmacSHA1And8bit";
    private static final String ALG_PBK = "PBKDF2WithHmacSHA1";

    private static final String ALG_PBE_LOW = "PBEWithMD5AndDES";
    public static final String ALG_PBE = "PBEWithSHA256And256BitAES-CBC-BC";

    public static final String PROVIDER = "BC";

    private static final int ITERATIONS = 1000;
    private static final int KEY_SIZE = 256;

    public static SecretKey generateHash(char[] password, byte[] salt, int iterationCount) throws InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKey key;
        try {
            // TODO: what if there's an OS upgrade and now supports the primary PBE
            key = generatePBEKey(password, salt, ALG_PBK, iterationCount, KEY_SIZE);
        } catch (NoSuchAlgorithmException e) {
            try {
                key = generatePBEKey(password, salt, ALG_PBE, iterationCount, KEY_SIZE);
            } catch (NoSuchAlgorithmException e1) {
                // older devices may not support the have the implementation try with a weaker algorthm
                key = generatePBEKey(password, salt,
                        ALG_PBE_LOW, iterationCount, KEY_SIZE);
            }
        }
        return key;
    }

    public static SecretKey generateHash(char[] password, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return generateHash(password, salt, ITERATIONS);
    }

    private static String getAlgorthm() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            // Use compatibility key factory -- only uses lower 8-bits of passphrase chars
            return ALG_PBK_LOW;
        } else {
            // Traditional key factory. Will use lower 8-bits of passphrase chars on
            // older Android versions (API level 18 and lower) and all available bits
            // on KitKat and newer (API level 19 and higher).
            return ALG_PBK;
        }
    }

    private static SecretKey generatePBEKey(char[] password, byte[] salt, String algorthm, int iterations, int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorthm);
        KeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return secretKey;
    }
}
