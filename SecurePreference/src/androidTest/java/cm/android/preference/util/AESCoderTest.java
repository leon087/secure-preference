package cm.android.preference.util;

import android.test.InstrumentationTestCase;

import javax.crypto.SecretKey;

public class AESCoderTest extends InstrumentationTestCase {

    public void testGenerateKey() throws Exception {
        char[] password = "aes".toCharArray();
        byte[] key1 = AESCoder.generateKey(password, null, 16).getEncoded();
        byte[] key2 = AESCoder.generateKey(password, null, 16).getEncoded();

        assertEquals(new String(key1), new String(key2));
    }

    public void testEncryptAndDecrypt() throws Exception {
        byte[] data = "aes".getBytes();

        SecretKey key = AESCoder.generateKey();
        byte[] tmp = AESCoder.encrypt(key, null, data);
        byte[] tmpData = AESCoder.decrypt(key, null, tmp);

        assertEquals(new String(data), new String(tmpData));

        byte[] key1 = AESCoder.generateKey().getEncoded();
        byte[] tmp1 = AESCoder.encrypt(key1, null, data);
        byte[] tmpData1 = AESCoder.decrypt(key1, null, tmp1);

        assertEquals(new String(data), new String(tmpData1));
    }
}
