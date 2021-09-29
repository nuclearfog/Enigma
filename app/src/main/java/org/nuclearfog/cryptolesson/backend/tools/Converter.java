package org.nuclearfog.cryptolesson.backend.tools;

import android.util.Base64;

import java.util.Arrays;

/**
 * Converter class to convert strings to byte arrays
 *
 * @author nuclearfog
 */
public class Converter {

    private Converter(){}

    /**
     * aligns byte array to 128 bit blocksize and fills last bytes with '0'
     *
     * @param input input byte array
     * @return aligned byte array
     */
    public static byte[] align(byte[] input) {
        if (input.length % 16 == 0)
            return input;
        int addition = (16 - input.length % 16);
        return Arrays.copyOf(input, input.length + addition);
    }

    /**
     * trim byte array to normal size
     *
     * @param input aligned byte array
     * @return trimmed byte array
     */
    public static byte[] trimEnd(byte[] input) {
        if (input[input.length - 1] != 0)
            return input;
        for (int i = 0 ; i <= input.length - 1; i++) {
            if (input[i] == 0) {
                return Arrays.copyOf(input, i);
            }
        }
        return input;
    }

    /**
     * decode Base64 string to byte array
     *
     * @param base64 string with Base64 encoding
     * @return decoded byte string
     */
    public static byte[] base64ToBytes(String base64) {
        // decode Base64 to byte array
        byte[] result = Base64.decode(base64, Base64.DEFAULT);
        // expand last 16 byte (128 bit) to fit
        return align(result);
    }

    /**
     * encode byte array to Base64 string
     *
     * @param bytes input byte array
     * @return string with Base64 encoding
     */
    public static String bytesToBase64 (byte[] bytes) {
        // trim array to normal size
        byte[] reduced = trimEnd(bytes);
        return Base64.encodeToString(reduced, Base64.DEFAULT);
    }

    /**
     * convert cleartext to byte array
     *
     * @param text clear text string
     * @return aligned byte array
     */
    public static byte[] textToBytes(String text) {
        return align(text.getBytes());
    }

    /**
     * convert (aligned) byte array to cleartext
     *
     * @param bytes byte array to convert
     * @return clear text string
     */
    public static String bytesToText(byte[] bytes) {
        return new String(trimEnd(bytes));
    }
}