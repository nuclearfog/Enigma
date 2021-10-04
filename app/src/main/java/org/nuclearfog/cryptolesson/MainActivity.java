package org.nuclearfog.cryptolesson;

import static org.nuclearfog.cryptolesson.backend.Decrypter.MODE_B64;
import static org.nuclearfog.cryptolesson.backend.Decrypter.MODE_HEX;

import android.app.Dialog;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ArrayAdapter;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.EditText;
import android.widget.Spinner;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import org.nuclearfog.cryptolesson.backend.Callback;
import org.nuclearfog.cryptolesson.backend.Decrypter;
import org.nuclearfog.cryptolesson.backend.Encrypter;

import static org.nuclearfog.cryptolesson.backend.algorithm.SymmetricCryptography.*;

/**
 * Main activity of the app
 *
 * @author nuclearfog
 */
public class MainActivity extends AppCompatActivity implements OnClickListener, OnCheckedChangeListener, Callback {

    private static final String[] CRYPTO = {AES_256, IDEA, CAMELLIA, SERPENT, BLOWFISH, TWOFISH, KUZNYECHIK, DES};
    private static final String[] HASH = {SHA_512, SHA_256, WHIRLPOOL, TIGER, SHA_1, MD5};

    private EditText input, output, pass, iVector;
    private Spinner cryptSelector, hashSelector;
    private CompoundButton hexSwitch, enable_iv;
    private Dialog licenseDialog;

    private String[] cryptOutput = {"", ""};


    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        input = findViewById(R.id.text_input);
        output = findViewById(R.id.text_output);
        pass = findViewById(R.id.text_pass);
        iVector = findViewById(R.id.iv_input);
        cryptSelector = findViewById(R.id.crypt_algo);
        hashSelector = findViewById(R.id.hash_algo);
        hexSwitch = findViewById(R.id.hex_switch);
        enable_iv = findViewById(R.id.iv_switch);
        licenseDialog = new LicenseDialog(this);
        cryptSelector.setAdapter(new ArrayAdapter<>(this, R.layout.dropdown_item, CRYPTO));
        hashSelector.setAdapter(new ArrayAdapter<>(this, R.layout.dropdown_item, HASH));
        View encrypt = findViewById(R.id.text_encrypt);
        View decrypt = findViewById(R.id.text_decrypt);

        encrypt.setOnClickListener(this);
        decrypt.setOnClickListener(this);
        hexSwitch.setOnCheckedChangeListener(this);
        enable_iv.setOnCheckedChangeListener(this);
    }


    @Override
    public boolean onCreateOptionsMenu(Menu m) {
        getMenuInflater().inflate(R.menu.main, m);

        return super.onCreateOptionsMenu(m);
    }


    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == R.id.license) {
            if (!licenseDialog.isShowing()) {
                licenseDialog.show();
            }
        }
        return super.onOptionsItemSelected(item);
    }


    @Override
    public void onClick(View v) {
        String initV = null;
        String cryptoAlgorithm = CRYPTO[cryptSelector.getSelectedItemPosition()];
        String hashAlgorithm = HASH[hashSelector.getSelectedItemPosition()];
        String secret = pass.getText().toString();
        if (enable_iv.isChecked()) {
            initV = iVector.getText().toString();
        }
        if (v.getId() == R.id.text_encrypt) {
            String text = input.getText().toString();
            Encrypter task = new Encrypter(this);
            task.execute(text, secret, initV, cryptoAlgorithm, hashAlgorithm);
        } else if (v.getId() == R.id.text_decrypt) {
            String mode = hexSwitch.isChecked() ? MODE_HEX : MODE_B64;
            String text = output.getText().toString();
            Decrypter task = new Decrypter(this);
            task.execute(text, secret, initV, cryptoAlgorithm, hashAlgorithm, mode);
        }
    }


    @Override
    public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
        if (buttonView.getId() == R.id.hex_switch) {
            if (isChecked) {
                output.setText(cryptOutput[1]);
                output.setVerticalScrollBarEnabled(true);
            } else {
                output.setText(cryptOutput[0]);
                output.setVerticalScrollBarEnabled(false);
            }
        } else if (buttonView.getId() == R.id.iv_switch) {
            if (isChecked) {
                iVector.setVisibility(View.VISIBLE);
            } else {
                iVector.setVisibility(View.GONE);
            }
        }
    }


    @Override
    public void onEncrypted(String[] messages) {
        cryptOutput = messages;
        if (hexSwitch.isChecked()){
            output.setText(messages[1]);
        } else {
            output.setText(messages[0]);
        }
    }


    @Override
    public void onDecrypted(String message) {
        input.setText(message);
    }
}