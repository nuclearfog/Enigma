package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.engines.SerpentEngine;

import java.io.IOException;

/**
 * This class provides methods for Serpent encryption
 *
 * @author nuclearfog
 */
public class Serpent extends SymmetricCryptography {

    /**
     */
    private static final int[] KEYSIZES = {32, 24, 16};

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, password, hash, new SerpentEngine(), KEYSIZES, true);
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
            return encryptDecrypt(input, password, hash, new SerpentEngine(), KEYSIZES, false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}