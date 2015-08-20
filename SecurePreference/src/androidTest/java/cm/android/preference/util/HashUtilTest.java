package cm.android.preference.util;

import android.test.InstrumentationTestCase;

public class HashUtilTest extends InstrumentationTestCase {

    public void testGenerateHash() throws Exception {
        char[] password = "aes".toCharArray();
        byte[] key1 = HashUtil.generateHash(password, null, 16).getEncoded();
        byte[] key2 = HashUtil.generateHash(password, null, 16).getEncoded();

        assertEquals(new String(key1), new String(key2));
    }

    public void testGetMessageDigest() throws Exception {
        byte[] password = {12, 23, 21};
        byte[] key1 = HashUtil.getMessageDigest(password, "SHA-256");
        byte[] key2 = HashUtil.getMessageDigest(password, "SHA-256");
        if (key1.length != 0 && key2.length != 0) {
            assertEquals(new String(key1), new String(key2));
        } else {
            assertEquals(true, false);
        }
    }
}
