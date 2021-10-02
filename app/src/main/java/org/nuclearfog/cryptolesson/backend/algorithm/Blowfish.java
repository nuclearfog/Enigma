package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.paddings.PKCS7Padding;

import java.io.IOException;

/**
 * This class provides methods for Blowfish encryption
 *
 * @author nuclearfog
 */
public class Blowfish extends SymmetricCryptography {

    /**
     * default key size used by Blowfish
     */
    private static final int KEYSIZE = 32;

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] input, String password, String hash) throws IOException {
        try {
            return encryptDecrypt(input, password, hash, new BlowfishEngine(), new PKCS7Padding(), KEYSIZE, true);
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
            return encryptDecrypt(input, password, hash, new BlowfishEngine(), new PKCS7Padding(), KEYSIZE, false);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}