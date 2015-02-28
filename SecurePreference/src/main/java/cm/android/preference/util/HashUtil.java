package cm.android.preference.util;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class HashUtil {

    private HashUtil() {
    }

    private static final String ALG_PBK = "PBKDF2WithHmacSHA1";

    private static final String ALG_PBE_LOW = "PBEWithMD5AndDES";

    public static final String ALG_HMAC = "HmacSHA256";

    public static final String ALG_SHA = "SHA-256";

    public static final String PROVIDER = "BC";

    private static final int ITERATIONS = 1000;

    private static final int KEY_SIZE = 256;

    public static SecretKey generateHash(char[] password, byte[] salt, int iterationCount)
            throws InvalidKeySpecException {
        SecretKey key;
        try {
            key = generatePBEKey(password, salt, ALG_PBK, iterationCount, KEY_SIZE);
        } catch (NoSuchAlgorithmException e) {
            try {
                key = generatePBEKey(password, salt, ALG_PBE_LOW, iterationCount, KEY_SIZE);
            } catch (NoSuchAlgorithmException e1) {
                throw new RuntimeException(e1);
            }
        }
        return key;
    }

    public static SecretKey generateHash(char[] password) throws InvalidKeySpecException {
        byte[] salt = SecureUtil.SALT_DEF;
        return generateHash(password, salt, ITERATIONS);
    }

    public static SecretKey generateHash(char[] password, byte[] salt)
            throws InvalidKeySpecException {
        return generateHash(password, salt, ITERATIONS);
    }

    private static SecretKey generatePBEKey(char[] password, byte[] salt, String algorthm,
            int iterations, int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorthm);
        KeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return secretKey;
    }

    public static String getSha256(final byte[] data) {
        final byte[] digest = getSha(data);
        final BigInteger hashedNumber = new BigInteger(1, digest);
        return hashedNumber.toString(16);
    }

    public static byte[] getSha(final byte[] data) {
        try {
            final MessageDigest md = MessageDigest.getInstance(ALG_SHA);
            final byte[] digest = md.digest(data);
            return digest;
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] getHmac(byte[] macKey, byte[] data)
            throws InvalidKeyException, NoSuchAlgorithmException {
        SecretKey secret = new SecretKeySpec(macKey, ALG_HMAC);

        Mac mac = Mac.getInstance(ALG_HMAC);
        mac.init(secret);
        byte[] doFinal = mac.doFinal(data);
        return doFinal;
    }
}
