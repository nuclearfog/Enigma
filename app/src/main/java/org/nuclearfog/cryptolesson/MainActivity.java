package org.nuclearfog.cryptolesson;

import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import org.nuclearfog.cryptolesson.backend.Callback;
import org.nuclearfog.cryptolesson.backend.Decrypter;
import org.nuclearfog.cryptolesson.backend.Encrypter;

/**
 * Main activity of the app
 *
 * @author nuclearfog
 */
public class MainActivity extends AppCompatActivity implements OnClickListener, Callback {

    private static final String[] CRYPTO = {Encrypter.AES_256};

    private static final String[] HASH = {Encrypter.SHA_512, Encrypter.SHA_384, Encrypter.SHA_256, Encrypter.SHA_1};

    private EditText input, output, pass;
    private Spinner cryptSelector, hashSelector;

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        input = findViewById(R.id.text_input);
        output = findViewById(R.id.text_output);
        pass = findViewById(R.id.text_pass);
        cryptSelector = findViewById(R.id.crypt_algo);
        hashSelector = findViewById(R.id.hash_algo);

        Button encrypt = findViewById(R.id.text_encrypt);
        Button decrypt = findViewById(R.id.text_decrypt);

        encrypt.setOnClickListener(this);
        decrypt.setOnClickListener(this);
    }


    @Override
    public void onClick(View v) {
        String cryptoAlgorithm = CRYPTO[cryptSelector.getSelectedItemPosition()];
        String hashAlgorithm = HASH[hashSelector.getSelectedItemPosition()];

        if (v.getId() == R.id.text_encrypt) {
            Encrypter task = new Encrypter(this);
            String text = input.getText().toString();
            String secret = pass.getText().toString();
            task.execute(text, secret, cryptoAlgorithm, hashAlgorithm);
        }
        else if (v.getId() == R.id.text_decrypt) {
            Decrypter task = new Decrypter(this);
            String text = output.getText().toString();
            String secret = pass.getText().toString();
            task.execute(text, secret, cryptoAlgorithm, hashAlgorithm);
        }
    }


    @Override
    public void onEncrypted(String[] messages) {
        output.setText(messages[0]);
    }


    @Override
    public void onDecrypted(String message) {
        input.setText(message);
    }
}