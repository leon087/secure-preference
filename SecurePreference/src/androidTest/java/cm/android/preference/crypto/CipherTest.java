package cm.android.preference.crypto;

import android.content.Context;
import android.content.SharedPreferences;

import android.test.InstrumentationTestCase;

public class CipherTest extends InstrumentationTestCase {

    public void testInitIvANDInitCipher() throws Exception {
        Context context = getInstrumentation().getContext();
        SharedPreferences preference = context
                .getSharedPreferences("dsh", Context.MODE_PRIVATE);
        byte[] bytes = {123, 111, 22, 127};
        ICipher valueCipher = Cipher.KeyHelper.initCipher(context, "ddd");
        ICipher temp = Cipher.KeyHelper.initKeyCipher(context, "hasd", valueCipher, preference);
        boolean result = temp.decrypt(bytes) == null;
        assertEquals(true, result);
    }
}
