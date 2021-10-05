package org.nuclearfog.cryptolesson.backend;

import android.os.AsyncTask;

import org.nuclearfog.cryptolesson.MainActivity;
import org.nuclearfog.cryptolesson.backend.algorithm.AES;
import org.nuclearfog.cryptolesson.backend.algorithm.Blowfish;
import org.nuclearfog.cryptolesson.backend.algorithm.Camellia;
import org.nuclearfog.cryptolesson.backend.algorithm.DES;
import org.nuclearfog.cryptolesson.backend.algorithm.IDEA;
import org.nuclearfog.cryptolesson.backend.algorithm.Kuznyechik;
import org.nuclearfog.cryptolesson.backend.algorithm.Serpent;
import org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography;
import org.nuclearfog.cryptolesson.backend.algorithm.Twofish;
import org.nuclearfog.cryptolesson.backend.tools.Converter;

import java.lang.ref.WeakReference;

import static org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography.*;

/**
 * Async Class to process encryption/decryption and string formatting
 *
 * @author nuclearfog
 */
public class Encrypter extends AsyncTask<String, Void, String[]> {

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
            String initVec = param[2];
            String encryption = param[3];
            String hashAlgorithm = param[4];

            SymmetricCryptography cryptoEngine;

            switch(encryption) {
                default:
                    return new String[] {"", ""};

                case AES_256:
                    cryptoEngine = new AES();
                    break;

                case SERPENT:
                    cryptoEngine = new Serpent();
                    break;

                case BLOWFISH:
                    cryptoEngine = new Blowfish();
                    break;

                case CAMELLIA:
                    cryptoEngine = new Camellia();
                    break;

                case KUZNYECHIK:
                    cryptoEngine = new Kuznyechik();
                    break;

                case IDEA:
                    cryptoEngine = new IDEA();
                    break;

                case DES:
                    cryptoEngine = new DES();
                    break;

                case TWOFISH:
                    cryptoEngine = new Twofish();
                    break;
            }
            byte[] iv = null;
            byte[] input = Converter.textToBytes(message);
            if (initVec != null)
                iv = Converter.hexToBytes(initVec);
            byte[] output = cryptoEngine.encrypt(input, iv, password, hashAlgorithm);
            String base64 = Converter.bytesToBase64(output);
            String hex = Converter.bytesToHex(output, 8);
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