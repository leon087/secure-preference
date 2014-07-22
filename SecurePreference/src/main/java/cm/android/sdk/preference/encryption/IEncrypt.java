package cm.android.sdk.preference.encryption;

public interface IEncrypt {

    void initKey(byte[] key);

    byte[] encrypt(byte[] bytes) throws EncryptionException;

    byte[] decrypt(byte[] bytes) throws EncryptionException;
}
