package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.engines.BlowfishEngine;

import java.io.IOException;

/**
 * This class provides methods for Blowfish encryption
 *
 * @author nuclearfog
 */
public class Blowfish extends SymmetricCryptography {

    /**
     */
    private static final int[] KEYSIZES = {56, 32, 16};

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, byte[] iv, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, iv, password, hash, new BlowfishEngine(), KEYSIZES, true);
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
            return encryptDecrypt(input, iv, password, hash, new BlowfishEngine(), KEYSIZES, false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}