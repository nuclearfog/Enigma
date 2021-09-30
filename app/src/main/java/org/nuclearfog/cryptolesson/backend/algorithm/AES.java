package org.nuclearfog.cryptolesson.backend.algorithm;

import java.io.IOException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * This class provides methods to encrypt or decrypt byte arrays with AES. AES uses 16 byte blocks
 * so the array length should be a multiple of 16.
 *
 * @author nuclearfog
 */
public class AES extends SymmetricCryptography {

    /**
     * AES encryption algorithm with Cipher Block Chaining
     */
    public static final String CBC_PKCS5 = "AES/CBC/PKCS5Padding";

    /**
     * This initial vector is used to xor the initial 16 bytes of the data
     * this array contains random numbers
     */
    private static final byte[] IV = {17, 84, 80, 9, 6, 91, 18, 46, 20, 1, 96, 18, 78, 51, 90, 15};
    private static final IvParameterSpec IV_SP = new IvParameterSpec(IV);

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, String secret, String hash) throws IOException {
        try {
            Cipher cipher = Cipher.getInstance(CBC_PKCS5);
            byte[] key = buildKey(secret, hash);
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, IV_SP);
            return cipher.doFinal(input);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decrypt(byte[] input, String secret, String hash) throws IOException {
        try {
            Cipher cipher = Cipher.getInstance(CBC_PKCS5);
            byte[] key = buildKey(secret, hash);
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, IV_SP);
            return cipher.doFinal(input);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}