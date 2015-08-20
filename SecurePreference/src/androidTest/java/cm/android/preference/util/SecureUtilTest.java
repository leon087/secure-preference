package cm.android.preference.util;

import android.test.InstrumentationTestCase;

public class SecureUtilTest extends InstrumentationTestCase {

    public void testGenerateIv() throws Exception {
        boolean result = SecureUtil.generateIv().length == 16;
        assertEquals(result, true);
    }

    public void testGenerateSalt() throws Exception {
        boolean result = SecureUtil.generateSalt().length == 20;
        assertEquals(result, true);
    }

    public void testConvertSize() throws Exception {
        boolean result = SecureUtil.convertSize(1) == 8;
        assertEquals(result, true);
    }
}
