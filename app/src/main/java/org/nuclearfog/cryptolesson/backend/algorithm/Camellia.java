package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.paddings.PKCS7Padding;

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
        try {
            return encryptDecrypt(input, password, hash, new CamelliaEngine(), new PKCS7Padding(), true);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decrypt(byte[] input, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, password, hash, new CamelliaEngine(), new PKCS7Padding(), false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}