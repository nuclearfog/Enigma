package org.nuclearfog.cryptolesson.backend.algorithm;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


/**
 * super class for all symmetric cryptography algorithm
 *
 * @author nuclearfog
 */
public abstract class SymmetricCryptography {

    /**
     * encrypt byte array with AES-CBC
     *
     * @param input input byte array (clear, must be aligned)
     * @param password password string
     * @param hash hash algorithm name as string
     * @return byte array (aligned)
     * @throws IOException if encryption fails
     */
    public abstract byte[] encrypt(byte[] input, String password, String hash) throws IOException;

    /**
     * decrypt byte array with AES-CBC
     *
     * @param input input byte array (encrypted, must be aligned)
     * @param password password string
     * @param hash hash algorithm name as string
     * @return byte array (clear, aligned)
     * @throws IOException if encryption fails
     */
    public abstract byte[] decrypt(byte[] input, String password, String hash) throws IOException;

    /**
     * create encryption key with password. the a hash of the password will be used.
     *
     * @param password password string
     * @param hash hash algorithm name
     * @return secret key to encrypt or decrypt
     * @throws NoSuchAlgorithmException if hash algorithm was not found
     */
    protected byte[] buildKey(String password, String hash) throws NoSuchAlgorithmException {
        byte[] key = password.getBytes();
        MessageDigest hashAlgo = MessageDigest.getInstance(hash);
        key = hashAlgo.digest(key);
        // set key length to 256 bit
        if (key.length != 32)
            key = Arrays.copyOf(key, 32);
        return key;
    }
}