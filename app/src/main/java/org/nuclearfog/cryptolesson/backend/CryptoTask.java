package org.nuclearfog.cryptolesson.backend;

import android.os.AsyncTask;

import org.nuclearfog.cryptolesson.MainActivity;
import org.nuclearfog.cryptolesson.backend.algorithm.AES;

import java.lang.ref.WeakReference;


public class CryptoTask extends AsyncTask<String, Void, String[]> {

    public static final String ENCRYPT = "encrypt";
    public static final String DECRYPT = "decrypt";

    public static final String AES_256 = "AES-256";

    public static final String SHA_256 = "SHA-256";


    private WeakReference<MainActivity> callback;


    public CryptoTask(MainActivity activity) {
        super();
        callback = new WeakReference<>(activity);
    }


    @Override
    protected String[] doInBackground(String[] param) {
        try {
            String message = param[0];
            String pass = param[1];

            String action = param[2];
            String encryption = param[3];
            String hash = param[4];

            switch(encryption) {
                case AES_256:
                    if (ENCRYPT.equals(action)) {
                        String encrypted = AES.encrypt(message, pass, hash);
                        return new String[]{message, encrypted};
                    }
                    else if (DECRYPT.equals(action)) {
                        String decrypted = AES.decrypt(message, pass, hash);
                        return new String[] {decrypted, message};
                    }
                    break;

            }
        } catch (Exception err) {
            err.printStackTrace();
        }
        return new String[] {"", ""};
    }


    @Override
    protected void onPostExecute(String[] result) {
        if (callback.get() != null) {
            callback.get().setText(result);
        }
    }
}