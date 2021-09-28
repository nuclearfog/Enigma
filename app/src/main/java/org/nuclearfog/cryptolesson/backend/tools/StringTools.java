package org.nuclearfog.cryptolesson.backend.tools;

import java.util.Arrays;

public class StringTools {

    private StringTools(){}


    public static byte[] align(byte[] input) {
        if (input.length % 16 == 0)
            return input;
        int addition = (16 - input.length % 16);
        return Arrays.copyOf(input, input.length + addition);
    }


    public static byte[] trimEnd(byte[] input) {
        for (int i = 0 ; i <= input.length - 1; i++) {
            if (input[i] == 0) {
                return Arrays.copyOf(input, i + 1);
            }
        }
        return input;
    }
}