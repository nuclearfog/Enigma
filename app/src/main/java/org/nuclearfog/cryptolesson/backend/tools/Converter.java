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
     * trim byte array to normal size
     *
     * @param input byte array
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
        return Base64.decode(base64, Base64.DEFAULT);
    }

    /**
     * encode byte array to Base64 string
     *
     * @param bytes input byte array
     * @return string with Base64 encoding
     */
    public static String bytesToBase64 (byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.DEFAULT);
    }

    /**
     * convert cleartext to byte array
     *
     * @param text clear text string
     * @return byte array of the cleartext
     */
    public static byte[] textToBytes(String text) {
        return text.getBytes();
    }

    /**
     * convert byte array to (trimmed) cleartext
     *
     *
     * @param bytes byte array to convert
     * @return clear text string
     */
    public static String bytesToText(byte[] bytes) {
        return new String(trimEnd(bytes));
    }

    /**
     * convert text containing 2 hex digits to byte array
     *
     * @param text text with hex digits
     * @return byte array
     */
    public static byte[] hexToBytes(String text) {
        if (text.isEmpty())
            return new byte[0];
        // split hex values from text
        String[] hexStr = text.split("[\\s:-]\n?");
        byte[] output = new byte[hexStr.length];
        for (int i = 0 ; i < hexStr.length ; i++) {
            String hexDigit = hexStr[i];
            if (hexDigit.length() == 1) {
                output[i] = (byte) (Character.digit(hexDigit.charAt(0), 16));
            } else if (hexDigit.length() == 2){
                output[i] = (byte) (Character.digit(hexDigit.charAt(1), 16));
                output[i] |= ((byte) (Character.digit(hexDigit.charAt(0), 16)) << 4);
            } else {
                throw new NumberFormatException("Wrong formatted numbers!");
            }
        }
        return output;
    }

    /**
     * convert byte array to hex string
     *
     * @param input byte array
     * @return string with hex values separated by  whitespace
     */
    public static String bytesToHex(byte[] input) {
        StringBuilder result = new StringBuilder();
        for (int i = 0 ; i < input.length ; i++) {
            if (i % 8 == 0 && i > 0) {
                result.append('\n');
            }
            result.append(String.format("%02X ", input[i]));
        }
        return result.deleteCharAt(result.length() - 1).toString();
    }
}