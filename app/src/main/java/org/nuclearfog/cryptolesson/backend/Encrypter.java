package org.nuclearfog.cryptolesson.backend;

import android.os.AsyncTask;

import org.nuclearfog.cryptolesson.MainActivity;
import org.nuclearfog.cryptolesson.backend.algorithm.AES;
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

            switch(encryption) {
                case AES_256:
                    byte[] input = Converter.textToBytes(message);
                    byte[] output = AES.encrypt(input, password, hashAlgorithm);

                    String base64 = Converter.bytesToBase64(output);
                    return new String[]{base64};
            }
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