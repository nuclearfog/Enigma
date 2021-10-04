package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.engines.AESEngine;

import java.io.IOException;


/**
 * This class provides methods to encrypt or decrypt byte arrays with AES. AES uses 16 byte blocks
 * so the array length should be a multiple of 16.
 *
 * @author nuclearfog
 */
public class AES extends SymmetricCryptography {

    /**
     */
    private static final int[] KEYSIZES = {32, 24, 16};

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, password, hash, new AESEngine(), KEYSIZES, true);
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
            return encryptDecrypt(input, password, hash, new AESEngine(), KEYSIZES, false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}