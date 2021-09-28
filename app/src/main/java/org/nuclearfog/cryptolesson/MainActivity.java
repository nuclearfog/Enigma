package org.nuclearfog.cryptolesson;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import org.nuclearfog.cryptolesson.backend.CryptoTask;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private EditText input, output, pass;

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        input = findViewById(R.id.text_input);
        output = findViewById(R.id.text_output);
        pass = findViewById(R.id.text_pass);

        Button encrypt = findViewById(R.id.text_encrypt);
        Button decrypt = findViewById(R.id.text_decrypt);

        encrypt.setOnClickListener(this);
        decrypt.setOnClickListener(this);

    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.text_encrypt) {
            CryptoTask task = new CryptoTask(this);
            String text = input.getText().toString();
            String secret = pass.getText().toString();
            task.execute(CryptoTask.ENCRYPT, CryptoTask.AES_256, text, secret);
        }
        else if (v.getId() == R.id.text_decrypt) {
            CryptoTask task = new CryptoTask(this);
            String text = output.getText().toString();
            String secret = pass.getText().toString();
            task.execute(CryptoTask.DECRYPT, CryptoTask.AES_256, text, secret);
        }
    }


    public void setText(String[] result) {
        input.setText(result[0]);
        output.setText(result[1]);
    }
}