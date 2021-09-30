package org.nuclearfog.cryptolesson.backend;

import android.os.AsyncTask;

import org.nuclearfog.cryptolesson.MainActivity;
import org.nuclearfog.cryptolesson.backend.algorithm.AES;
import org.nuclearfog.cryptolesson.backend.algorithm.Camellia;
import org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography;
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

            byte[] input = Converter.base64ToBytes(message);
            byte[] output = crypto.decrypt(input, pass, hash);
            return Converter.bytesToText(output);

        } catch(Exception err) {
            err.printStackTrace();
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