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
     * default keysize for AES-256 in bytes
     * 16 bytes is also possible
     */
    private static final int KEYSIZE = 32;

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, password, hash, new AESEngine(), KEYSIZE, true);
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
            return encryptDecrypt(input, password, hash, new AESEngine(), KEYSIZE, false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}