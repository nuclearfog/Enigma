package org.nuclearfog.cryptolesson.backend.algorithm;

import static org.nuclearfog.cryptolesson.backend.tools.StringTools.align;

import android.util.Base64;

import org.nuclearfog.cryptolesson.backend.tools.StringTools;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class AES {

    public static final String CBC_PKCS5 = "AES/CBC/PKCS5Padding";

    // initial vector
    private static final byte[] IV = {17, 84, 80, 9, 6, 91, 18, 46, 20, 1, 96, 18, 78, 51, 90, 15};
    private static final IvParameterSpec IV_SP = new IvParameterSpec(IV);

    private AES() {}


    public static String encrypt(String text, String secret, String hash) {
        try {
            Cipher cipher = Cipher.getInstance(CBC_PKCS5);
            SecretKeySpec secretKey = buildKey(secret, hash);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, IV_SP);
            byte[] input = align(text.getBytes());
            byte[] output = cipher.doFinal(input);
            return Base64.encodeToString(output, Base64.DEFAULT);
        } catch (Exception e) {
            return "";
        }
    }


    public static String decrypt(String text, String secret, String hash) {
        try {
            Cipher cipher = Cipher.getInstance(CBC_PKCS5);
            byte[] input = align(Base64.decode(text, Base64.DEFAULT));
            SecretKeySpec secretKey = buildKey(secret, hash);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, IV_SP);
            byte[] output = cipher.doFinal(input);
            output = StringTools.trimEnd(output);
            return new String(output);
        } catch (Exception e) {
            return "";
        }
    }


    private static SecretKeySpec buildKey(String myKey, String hash) throws NoSuchAlgorithmException {
        byte[] key = myKey.getBytes();
        MessageDigest hashAlgo = MessageDigest.getInstance(hash);
        key = hashAlgo.digest(key);
        return new SecretKeySpec(key, "AES");
    }
}