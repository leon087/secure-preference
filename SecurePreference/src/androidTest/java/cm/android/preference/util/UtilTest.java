package cm.android.preference.util;

import android.content.Context;
import android.test.InstrumentationTestCase;

import java.io.File;
import java.util.Properties;

public class UtilTest extends InstrumentationTestCase {

    public void testEncodeBase64ANDDecodeBase64() throws Exception {
        byte[] bytes = {12, 2};
        String temp = Util.encodeBase64(bytes);
        byte[] result = Util.decodeBase64(temp);
        assertEquals(new String(bytes), new String(result));
    }

    public void testGetFingerprint() throws Exception {
        Context context = getInstrumentation().getContext();
        byte[] temp = Util.getFingerprint(context, "dashg");
        String result = Util.encodeBase64(temp);
        assertEquals("UVKLyfymXhtJTlaSWyCsTEq9SCJ2OcCo9ZxkSi4SBxo", result);

        String packageName = getInstrumentation().getContext().getPackageName();
        byte[] temp2 = Util.getFingerprint(context, "dashg", packageName);
        String result2 = Util.encodeBase64(temp2);
        assertEquals("UVKLyfymXhtJTlaSWyCsTEq9SCJ2OcCo9ZxkSi4SBxo", result2);
    }

    public void testLoadProperties() throws Exception {
        Context context = getInstrumentation().getContext();
        File file = new File(context.getCacheDir(), "SecurePreference_cache");
        Properties properties = Util.loadProperties(file);
        boolean result = properties.isEmpty();
        assertEquals(true, result);
    }
}
