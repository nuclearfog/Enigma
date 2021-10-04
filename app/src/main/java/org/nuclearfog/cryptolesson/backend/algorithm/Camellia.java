package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.engines.CamelliaEngine;

import java.io.IOException;


/**
 * This class provides methods to encrypt or decrypt with Camellia.
 *
 * @author nuclearfog
 */
public class Camellia extends SymmetricCryptography {

    /**
     */
    private static final int[] KEYSIZES = {32, 24, 16};

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, byte[] iv, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, iv, password, hash, new CamelliaEngine(), KEYSIZES, true);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decrypt(byte[] input, byte[] iv, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, iv, password, hash, new CamelliaEngine(), KEYSIZES, false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}