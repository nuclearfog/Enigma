package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;


/**
 * This class provides methods to encrypt or decrypt with Camellia.
 *
 * @author nuclearfog
 */
public class Camellia extends SymmetricCryptography {

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, String password, String hash) throws IOException {
        return encryptDecrypt(input, password, hash, true);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decrypt(byte[] input, String password, String hash) throws IOException {
        return encryptDecrypt(input, password, hash, false);
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
    private byte[] encryptDecrypt(byte[] input, String password, String hash, boolean encrypt) throws IOException {
        try {
            BlockCipher cipher = new CamelliaEngine();
            BlockCipherPadding padding = new PKCS7Padding();
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