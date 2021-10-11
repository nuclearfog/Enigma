package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.engines.DESedeEngine;

import java.io.IOException;

/**
 * This class provides methods for Triple DES encryption
 *
 * @author nuclearfog
 */
public class TripleDES extends SymmetricCryptography {

    /**
     */
    private static final int[] KEYSIZES = {24, 16};

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, byte[] iv, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, iv, password, hash, new DESedeEngine(), KEYSIZES, true);
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
            return encryptDecrypt(input, iv, password, hash, new DESedeEngine(), KEYSIZES, false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}