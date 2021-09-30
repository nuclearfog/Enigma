package org.nuclearfog.cryptolesson.backend;

import android.os.AsyncTask;

import org.nuclearfog.cryptolesson.MainActivity;
import org.nuclearfog.cryptolesson.backend.algorithm.AES;
import org.nuclearfog.cryptolesson.backend.algorithm.Camellia;
import org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography;
import org.nuclearfog.cryptolesson.backend.tools.Converter;

import java.lang.ref.WeakReference;


public class Encrypter extends AsyncTask<String, Void, String[]> implements Algorithms {

    private WeakReference<Callback> callback;


    public Encrypter(MainActivity activity) {
        super();
        callback = new WeakReference<>(activity);
    }


    @Override
    protected String[] doInBackground(String... param) {
        try {
            String message = param[0];
            String password = param[1];
            String encryption = param[2];
            String hashAlgorithm = param[3];

            SymmetricCryptography crypto;

            switch(encryption) {
                default:
                case AES_256:
                    crypto = new AES();
                    break;

                case CAMELLIA:
                    crypto = new Camellia();
                    break;
            }
            byte[] input = Converter.textToBytes(message);
            byte[] output = crypto.encrypt(input, password, hashAlgorithm);
            String base64 = Converter.bytesToBase64(output);
            String hex = Converter.bytesToHex(output);
            return new String[]{base64, hex};

        } catch (Exception err) {
            err.printStackTrace();
        }
        return new String[] {"", ""};
    }


    @Override
    protected void onPostExecute(String[] result) {
        if (callback.get() != null) {
            callback.get().onEncrypted(result);
        }
    }
}