package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

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
     * create encryption key from password. A hash code of the password will be used.
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

    /**
     * encrypt or decrypt byte array with Cammellia
     *
     * @param input     input byte array
     * @param password  password to encrypt/decrypt
     * @param hash      hash algorithm name defined in {@link org.nuclearfog.cryptolesson.backend.Algorithms}
     * @param encrypt   true to encrypt, false to decrypt
     * @return encrypted/ decrypted byte array
     * @throws IOException if encryption or decryption fails
     */
    protected byte[] encryptDecrypt(byte[] input, String password, String hash, BlockCipher cipher, BlockCipherPadding padding, boolean encrypt) throws IOException {
        try {
            PaddedBufferedBlockCipher blockCipher = new PaddedBufferedBlockCipher(cipher, padding);
            byte[] key = buildKey(password, hash);
            blockCipher.init(encrypt, new KeyParameter(key));
            byte[] output = new byte[blockCipher.getOutputSize(input.length)];
            int off = blockCipher.processBytes(input, 0, input.length, output, 0);
            blockCipher.doFinal(output, off);
            return output;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}