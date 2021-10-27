package edu.self.labo3.activity;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import edu.self.labo3.R;

/**
 * PROJECT     : LABORATOIRE 3
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 1/12/19
 * VERSION     : 1
 * DESCRIPTION : This activity is an activity where you can login using
 * toto:tata as credentials, but you first need to read an NFC tag (whatever it
 * contains). When this is done the NFCLoggedInActivity is started.
 */
public class NFCActivity extends NFCActivities {

    private TextView textView = null;
    private EditText username = null;
    private EditText password = null;
    private Button login = null;
    private boolean NFCScanned = false;

    private static final String TAG = "NFC_BARCODES-NFCActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_nfc);

        textView = findViewById(R.id.textView2);
        username = findViewById(R.id.nfc_input_name);
        password = findViewById(R.id.nfc_input_password);
        login = findViewById(R.id.nfc_button_login);

        // Here we set the callback when a NFC tag is received.
        setNFCEventListener(result -> {
            Log.i(TAG, "NFC detected");
            NFCScanned = true;
            textView.setText(result);
        });

        login.setOnClickListener(v -> {
                    Toast toast = Toast.makeText(getApplicationContext(), "", Toast.LENGTH_LONG);
                    if (!NFCScanned) {
                        toast.setText(R.string.nfc_activity_scan_requirement);
                        toast.show();
                        return;
                    }
                    if (!username.getText().toString().equals("toto") || !password.getText().toString().equals("tata")) {
                        toast.setText(R.string.nfc_activity_bad_login);
                        toast.show();
                        return;
                    }
                    startActivity(new Intent(this, NFCLoggedInActivity.class));
                }
        );
    }
}