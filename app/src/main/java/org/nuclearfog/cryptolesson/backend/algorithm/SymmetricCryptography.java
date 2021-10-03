package org.nuclearfog.cryptolesson.backend.algorithm;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.IOException;
import java.util.Arrays;


/**
 * super class for all symmetric cryptography algorithm
 *
 * @author nuclearfog
 */
public abstract class SymmetricCryptography {

    public static final String AES_256 = "AES";
    public static final String BLOWFISH = "Blowfish";
    public static final String SERPENT = "Serpent";
    public static final String CAMELLIA = "Camellia";
    public static final String KUZNYECHIK = "Kuznyechik";
    public static final String DES = "DES";
    public static final String IDEA = "IDEA";
    public static final String TWOFISH = "Twofish";

    public static final String MD5 = "MD5";
    public static final String SHA_1 = "SHA-1";
    public static final String SHA_256 = "SHA-256";
    public static final String SHA_512 = "SHA-512";
    public static final String WHIRLPOOL = "Whirlpool";
    public static final String TIGER = "Tiger";

    /**
     * encrypt byte array with AES-CBC
     *
     * @param input input byte array (clear, must be aligned)
     * @param password password string
     * @param hash hash algorithm name as string
     * @return byte array (aligned)
     * @throws IOException if encryption fails
     */
    public abstract byte[] encrypt(byte[] input, String password, String hash) throws IOException;

    /**
     * decrypt byte array with AES-CBC
     *
     * @param input input byte array (encrypted, must be aligned)
     * @param password password string
     * @param hash hash algorithm name as string
     * @return byte array (clear, aligned)
     * @throws IOException if encryption fails
     */
    public abstract byte[] decrypt(byte[] input, String password, String hash) throws IOException;

    /**
     * create encryption key from password. A hash code of the password will be used.
     *
     * @param password password string
     * @param hash hash algorithm name
     * @return secret key to encrypt or decrypt
     */
    private byte[] buildKey(String password, String hash, int keysize) {
        ExtendedDigest digest;
        switch (hash) {
            default:
            case SHA_256:
                digest = new SHA256Digest();
                break;

            case SHA_512:
                digest = new SHA512Digest();
                break;

            case SHA_1:
                digest = new SHA1Digest();
                break;

            case WHIRLPOOL:
                digest = new WhirlpoolDigest();
                break;

            case TIGER:
                digest = new TigerDigest();
                break;

            case MD5:
                digest = new MD5Digest();
                break;
        }
        digest.update(password.getBytes(), 0, password.length());
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return Arrays.copyOf(result, keysize);
    }

    /**
     * encrypt or decrypt byte array with Cammellia
     *
     * @param input     input byte array
     * @param password  password to encrypt/decrypt
     * @param hash      hash algorithm name
     * @param keySize   length of the encryption/decryption key
     * @param encrypt   true to encrypt, false to decrypt
     * @return encrypted/ decrypted byte array
     */
    protected byte[] encryptDecrypt(byte[] input, String password, String hash, BlockCipher cipher, int keySize, boolean encrypt) throws InvalidCipherTextException {
        CBCBlockCipher cbcCipher = new CBCBlockCipher(cipher);
        // create key and initial vector from password with defined hash algorithm
        byte[] key = buildKey(password, hash, keySize);
        byte[] iv = Arrays.copyOf(key, cbcCipher.getBlockSize());
        // init cipher
        KeyParameter keyParam = new KeyParameter(key);
        BlockCipherPadding padding = new PKCS7Padding();
        BufferedBlockCipher blockCipher = new PaddedBufferedBlockCipher(cbcCipher, padding);
        // init block cipher with CBC
        ParametersWithIV keyPAramIV = new ParametersWithIV(keyParam, iv);
        blockCipher.init(encrypt, keyPAramIV);
        // prepare output byte array
        byte[] output = new byte[blockCipher.getOutputSize(input.length)];
        // encrypt/decrypt!
        int off = blockCipher.processBytes(input, 0, input.length, output, 0);
        blockCipher.doFinal(output, off);
        return output;
    }
}