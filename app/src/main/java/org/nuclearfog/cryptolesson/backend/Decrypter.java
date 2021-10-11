package org.nuclearfog.cryptolesson.backend;

import android.os.AsyncTask;

import org.nuclearfog.cryptolesson.MainActivity;
import org.nuclearfog.cryptolesson.backend.algorithm.AES;
import org.nuclearfog.cryptolesson.backend.algorithm.Blowfish;
import org.nuclearfog.cryptolesson.backend.algorithm.Camellia;
import org.nuclearfog.cryptolesson.backend.algorithm.DES;
import org.nuclearfog.cryptolesson.backend.algorithm.IDEA;
import org.nuclearfog.cryptolesson.backend.algorithm.Kuznyechik;
import org.nuclearfog.cryptolesson.backend.algorithm.Seed;
import org.nuclearfog.cryptolesson.backend.algorithm.Serpent;
import org.nuclearfog.cryptolesson.backend.algorithm.Shacal2;
import org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography;
import org.nuclearfog.cryptolesson.backend.algorithm.TripleDES;
import org.nuclearfog.cryptolesson.backend.algorithm.Twofish;
import org.nuclearfog.cryptolesson.backend.tools.Converter;

import java.lang.ref.WeakReference;

import static org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography.*;

/**
 * Async Class to process encryption/decryption and string formatting
 *
 * @author nuclearfog
 */
public class Decrypter extends AsyncTask<String, Void, String> {

    /**
     * define input string as hex
     */
    public static final String MODE_HEX = "hex-mode";

    /**
     * define input string as Base64
     */
    public static final String MODE_B64 = "base64-mode";

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
            String initVec = param[2];
            String algo = param[3];
            String hash = param[4];
            String mode = param[5];

            SymmetricCryptography cryptoEngine;

            switch(algo) {
                default:
                    return "";

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

                case T_DES:
                    cryptoEngine = new TripleDES();
                    break;

                case SHACAL_2:
                    cryptoEngine = new Shacal2();
                    break;

                case SEED:
                    cryptoEngine = new Seed();
                    break;

                case TWOFISH:
                    cryptoEngine = new Twofish();
                    break;
            }
            byte[] iv = null;
            byte[] input = {};
            if (MODE_B64.equals(mode))
                input = Converter.base64ToBytes(message);
            else if (MODE_HEX.equals(mode))
                input = Converter.hexToBytes(message);
            if (initVec != null)
                iv = Converter.hexToBytes(initVec);
            byte[] output = cryptoEngine.decrypt(input, iv, pass, hash);
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