package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.engines.NoekeonEngine;

import java.io.IOException;

/**
 * this class provides methods for NOEKEON encryption
 *
 * @author nuclearfog
 */
public class Noekeon extends SymmetricCryptography {

    /**
     */
    private static final int[] KEYSIZES = {16};

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, byte[] iv, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, iv, password, hash, new NoekeonEngine(), KEYSIZES, true);
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
            return encryptDecrypt(input, iv, password, hash, new NoekeonEngine(), KEYSIZES, false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}