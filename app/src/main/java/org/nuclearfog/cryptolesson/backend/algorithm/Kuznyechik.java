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
     * key size for Kuznyechik
     */
    private static final int KEYSIZE = 32;

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, password, hash, new GOST28147Engine(), KEYSIZE, true);
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
            return encryptDecrypt(input, password, hash, new GOST28147Engine(), KEYSIZE, false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}