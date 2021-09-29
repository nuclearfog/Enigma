package org.nuclearfog.cryptolesson.backend;

/**
 * callback interface to set results to {@link org.nuclearfog.cryptolesson.MainActivity}
 *
 * @author nuclearfog
 */
public interface Callback {

    /**
     * called to set encrypted strings
     *
     * @param messages an array of encrypted strings with different encodings
     */
    void onEncrypted(String[] messages);

    /**
     * called to set clear text
     *
     * @param message clear text message
     */
    void onDecrypted(String message);
}