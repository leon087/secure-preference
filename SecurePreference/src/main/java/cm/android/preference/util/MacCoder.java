package cm.android.preference.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MacCoder {

    private static final Logger logger = LoggerFactory.getLogger("codec");

    public static final String ALG_HMAC = "HmacSHA256";

    public static SecretKey initHmacKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALG_HMAC);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey;
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
            return HashUtil.getSha(data);
        }
    }
}
