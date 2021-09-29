package org.nuclearfog.cryptolesson.backend;

import android.os.AsyncTask;

import org.nuclearfog.cryptolesson.MainActivity;
import org.nuclearfog.cryptolesson.backend.algorithm.AES;
import org.nuclearfog.cryptolesson.backend.tools.Converter;

import java.lang.ref.WeakReference;


public class Decrypter extends AsyncTask<String, Void, String> implements Algorithms {

    private WeakReference<Callback> callback;


    public Decrypter(MainActivity activity) {
        super();
        callback = new WeakReference<>(activity);
    }


    @Override
    protected String doInBackground(String... param) {
        try {
            String message = param[0];
            String pass = param[1];
            String encryption = param[2];
            String hash = param[3];

            switch(encryption) {
                case AES_256:
                    byte[] input = Converter.base64ToBytes(message);
                    byte[] output = AES.decrypt(input, pass, hash);
                    return Converter.bytesToText(output);
            }
        } catch(Exception err) {

        }
        return "";
    }


    @Override
    protected void onPostExecute(String result) {
        if (callback.get() != null) {
            callback.get().onDecrypted(result);
        }
    }
}