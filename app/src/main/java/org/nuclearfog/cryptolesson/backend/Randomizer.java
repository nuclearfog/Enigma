package org.nuclearfog.cryptolesson.backend;

import android.os.AsyncTask;

import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.crypto.prng.VMPCRandomGenerator;
import org.nuclearfog.cryptolesson.backend.tools.Converter;

import java.lang.ref.WeakReference;
import java.util.Date;

import static org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography.*;

/**
 * Random generator class
 * used to create random hex string used for initial vector (IV)
 *
 * @author nuclearfog
 */
public class Randomizer extends AsyncTask<String, Void, String> {

    private WeakReference<Callback> callback;

    /**
     *
     */
    public Randomizer(Callback callback) {
        super();
        this.callback = new WeakReference<>(callback);
    }


    @Override
    protected String doInBackground(String... param) {
        try {
            int blocksize;
            switch(param[0]) {
                case SHACAL_2:
                    blocksize = 32;
                    break;

                case AES_256:
                case CAMELLIA:
                case SERPENT:
                case TWOFISH:
                case NOEKEON:
                case SEED:
                    blocksize = 16;
                    break;

                case DES:
                case T_DES:
                case IDEA:
                case BLOWFISH:
                case KUZNYECHIK:
                    blocksize = 8;
                    break;

                default:
                    return "";
            }
            RandomGenerator randomGen = new VMPCRandomGenerator();
            randomGen.addSeedMaterial(new Date().getTime());

            byte[] random = new byte[blocksize];
            randomGen.nextBytes(random);
            return Converter.bytesToHex(random, 16, ':');
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }


    @Override
    protected void onPostExecute(String result) {
        if (callback.get() != null) {
            callback.get().onRandomCreated(result);
        }
    }
}