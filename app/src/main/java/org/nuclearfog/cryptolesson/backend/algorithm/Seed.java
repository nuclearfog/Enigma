package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.engines.SEEDEngine;

import java.io.IOException;

/**
 * This class provides methods for SEED algorithm.
 *
 * @author nuclearfog
 */
public class Seed extends SymmetricCryptography {

    /**
     */
    private static final int[] KEYSIZES = {16};

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, byte[] iv, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, iv, password, hash, new SEEDEngine(), KEYSIZES, true);
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
            return encryptDecrypt(input, iv, password, hash, new SEEDEngine(), KEYSIZES, false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}
