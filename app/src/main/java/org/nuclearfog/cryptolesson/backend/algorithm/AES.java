package org.nuclearfog.cryptolesson.backend.algorithm;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class provides methods to encrypt or decrypt byte arrays. AES uses 16 byte blocks
 * so the array length should be a multiple of 16.
 *
 * @author nuclearfog
 */
public class AES {

    /**
     * AES encryption algorithm with Cipher Block Chaining
     */
    public static final String CBC_PKCS5 = "AES/CBC/PKCS5Padding";

    /**
     * This initial vector is used to start the encryption on the first 16 bytes.
     */
    private static final byte[] IV = {17, 84, 80, 9, 6, 91, 18, 46, 20, 1, 96, 18, 78, 51, 90, 15};
    private static final IvParameterSpec IV_SP = new IvParameterSpec(IV);

    private AES() {}

    /**
     * encrypt byte array with AES-CBC
     *
     * @param input input byte array (clear, must be aligned)
     * @param secret password string
     * @param hash hash algorithm name as string
     * @return byte array (aligned)
     * @throws IOException if encryption fails
     */
    public static byte[] encrypt(byte[] input, String secret, String hash) throws IOException {
        try {
            Cipher cipher = Cipher.getInstance(CBC_PKCS5);
            SecretKeySpec secretKey = buildKey(secret, hash);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, IV_SP);
            return cipher.doFinal(input);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * decrypt byte array with AES-CBC
     *
     * @param input input byte array (encrypted, must be aligned)
     * @param secret password string
     * @param hash hash algorithm name as string
     * @return byte array (clear, aligned)
     * @throws IOException if encryption fails
     */
    public static byte[] decrypt(byte[] input, String secret, String hash) throws IOException {
        try {
            Cipher cipher = Cipher.getInstance(CBC_PKCS5);
            SecretKeySpec secretKey = buildKey(secret, hash);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, IV_SP);
            return cipher.doFinal(input);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * create encryption key with password. the a hash of the password will be used.
     *
     * @param myKey password string
     * @param hash hash algorithm name
     * @return secret key to encrypt or decrypt
     * @throws NoSuchAlgorithmException if hash algorithm was not found
     */
    private static SecretKeySpec buildKey(String myKey, String hash) throws NoSuchAlgorithmException {
        byte[] key = myKey.getBytes();
        MessageDigest hashAlgo = MessageDigest.getInstance(hash);
        key = hashAlgo.digest(key);
        // set key length to 256 bit
        if (key.length != 32)
            key = Arrays.copyOf(key, 32);
        return new SecretKeySpec(key, "AES");
    }
}