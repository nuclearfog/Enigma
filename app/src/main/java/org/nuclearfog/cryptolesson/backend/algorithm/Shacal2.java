package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.engines.Shacal2Engine;

import java.io.IOException;

/**
 * this class provides methods for SHACAL-2 encryption
 * The max supported key length is 512 bit.
 *
 * @author nuclearfog
 */
public class Shacal2 extends SymmetricCryptography {

    /**
     */
    private static final int[] KEYSIZES = {64, 56, 48, 40, 32, 24, 16};

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, byte[] iv, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, iv, password, hash, new Shacal2Engine(), KEYSIZES, true);
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
            return encryptDecrypt(input, iv, password, hash, new Shacal2Engine(), KEYSIZES, false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}