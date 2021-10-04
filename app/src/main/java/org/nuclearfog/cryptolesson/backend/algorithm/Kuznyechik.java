package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.engines.GOST28147Engine;

import java.io.IOException;

/**
 * This class provides methods for GOST 28147-89 (Kuznyechik)
 *
 * @author nuclearfog
 */
public class Kuznyechik extends SymmetricCryptography {

    /**
     */
    private static final int[] KEYSIZES = {32};

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, password, hash, new GOST28147Engine(), KEYSIZES, true);
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
            return encryptDecrypt(input, password, hash, new GOST28147Engine(), KEYSIZES, false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}