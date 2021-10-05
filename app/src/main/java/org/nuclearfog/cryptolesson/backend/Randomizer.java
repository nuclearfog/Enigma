package org.nuclearfog.cryptolesson.backend;

import static org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography.AES_256;
import static org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography.BLOWFISH;
import static org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography.CAMELLIA;
import static org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography.DES;
import static org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography.IDEA;
import static org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography.KUZNYECHIK;
import static org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography.SERPENT;
import static org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography.TWOFISH;

import android.os.AsyncTask;

import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.crypto.prng.VMPCRandomGenerator;
import org.nuclearfog.cryptolesson.backend.tools.Converter;

import java.lang.ref.WeakReference;
import java.util.Date;

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
                case AES_256:
                case CAMELLIA:
                case SERPENT:
                case TWOFISH:
                    blocksize = 16;
                    break;

                case DES:
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
            return Converter.bytesToHex(random);
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