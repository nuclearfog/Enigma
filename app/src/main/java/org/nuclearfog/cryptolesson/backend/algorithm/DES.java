package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.engines.DESEngine;

import java.io.IOException;


/**
 * The class provides methods for 'Data Encryption Standard' (DES)
 *
 * @author nuclearfog
 */
public class DES extends SymmetricCryptography {

    /**
     */
    private static final int[] KEYSIZES = {8};

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, password, hash, new DESEngine(), KEYSIZES, true);
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
            return encryptDecrypt(input, password, hash, new DESEngine(), KEYSIZES, false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}