package cm.android.preference.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
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

    private static final Logger logger = LoggerFactory.getLogger("codec");

    private HashUtil() {
    }

    private static final String ALG_PBK = "PBKDF2WithHmacSHA1";

    private static final String ALG_PBE_LOW = "PBEWithMD5AndDES";

    public static final String ALG_HMAC = "HmacSHA256";

    public static final String ALG_SHA = "SHA-256";

    public static final String ALG_MD5 = "MD5";

    public static final String PROVIDER = "BC";

    private static final int ITERATIONS = 499;

    private static final int KEY_SIZE = 128;

    public static SecretKey generateHash(char[] password, byte[] salt, int iterationCount,
            int keyLength) throws InvalidKeySpecException {
        try {
            SecretKey key = generatePBEKey(password, salt, ALG_PBK, iterationCount, keyLength);
            return key;
        } catch (NoSuchAlgorithmException e) {
            logger.error(e.getMessage(), e);
            try {
                SecretKey key = generatePBEKey(password, salt, ALG_PBE_LOW, iterationCount,
                        keyLength);
                return key;
            } catch (NoSuchAlgorithmException e1) {
                logger.error(e1.getMessage(), e1);
                throw new RuntimeException(e1);
            }
        }
    }

    public static SecretKey generateHash(char[] password, byte[] salt)
            throws InvalidKeySpecException {
        if (null == salt) {
            salt = SecureUtil.SALT_DEF;
        }
        return generateHash(password, salt, KEY_SIZE);
    }

    public static SecretKey generateHash(char[] password, byte[] salt, int keyLength)
            throws InvalidKeySpecException {
        if (null == salt) {
            salt = SecureUtil.SALT_DEF;
        }
        return generateHash(password, salt, ITERATIONS, keyLength);
    }

    private static SecretKey generatePBEKey(char[] password, byte[] salt, String algorthm,
            int iterations, int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorthm);
        KeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return secretKey;
    }

//    public static String getSha256(final byte[] data) {
//        final byte[] digest = getSha(data);
//        return HexUtil.encode(digest);
//    }

    public static byte[] getSha(final byte[] data) {
        return getMessageDigest(data, ALG_SHA);
    }

    public static byte[] getHmac(byte[] macKey, byte[] data) {
        SecretKey secret = new SecretKeySpec(macKey, ALG_HMAC);

        try {
            Mac mac = Mac.getInstance(ALG_HMAC);
            mac.init(secret);
            byte[] doFinal = mac.doFinal(data);
            return doFinal;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return getSha(data);
        }
    }

//    public static String getMd5(InputStream inputStream) throws IOException {
//        byte[] data = getMessageDigest(inputStream, ALG_MD5);
//        return HexUtil.encode(data);
//    }

    public static byte[] getSha(InputStream inputStream) throws IOException {
        return getMessageDigest(inputStream, ALG_SHA);
    }

    public static byte[] getMessageDigest(byte[] data, String algorithm) {
        try {
            final MessageDigest md = MessageDigest.getInstance(algorithm);
            final byte[] digest = md.digest(data);
            return digest;
        } catch (final NoSuchAlgorithmException e) {
            logger.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    public static byte[] getMessageDigest(InputStream inputStream, String algorithm)
            throws IOException {
        InputStream is = new BufferedInputStream(inputStream);

        try {
            final MessageDigest md = MessageDigest.getInstance(algorithm);

            byte[] buffer = new byte[2048];
            int sizeRead = -1;
            while ((sizeRead = is.read(buffer)) != -1) {
                md.update(buffer, 0, sizeRead);
            }

            final byte[] digest = md.digest();
            return digest;
        } catch (final NoSuchAlgorithmException e) {
            logger.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

//    public static byte[] getHmac(byte[] macKey, InputStream is) {
//        SecretKey secret = new SecretKeySpec(macKey, ALG_HMAC);
//
//        try {
//            Mac mac = Mac.getInstance(ALG_HMAC);
//            mac.init(secret);
//            byte[] doFinal = mac.doFinal(data);
//            return doFinal;
//        } catch (Exception e) {
//            logger.error(e.getMessage(), e);
//            return getSha(data);
//        }
//    }
}
