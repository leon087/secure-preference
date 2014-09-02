package cm.android.preference.encryption;

public interface IEncrypt {
    void initKey(byte[] key, byte[] iv, String tag);

    byte[] encrypt(byte[] bytes) throws EncryptionException;

    byte[] decrypt(byte[] bytes) throws EncryptionException;
}
