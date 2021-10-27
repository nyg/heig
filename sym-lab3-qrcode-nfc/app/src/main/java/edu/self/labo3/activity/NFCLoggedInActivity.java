package edu.self.labo3.activity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import edu.self.labo3.R;

/**
 * PROJECT     : LABORATOIRE 3
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 1/12/19
 * VERSION     : 1
 * DESCRIPTION : This activity is the authenticated part of the app, we need to
 * be logged in. This uses different levels of authentications based on the
 * timestamp of the activity created or the last time the NFC tag was read.
 */
public class NFCLoggedInActivity extends NFCActivities implements View.OnClickListener {

    private long timestamp;
    final int AUTHENTICATE_LOW = 5;
    final int AUTHENTICATE_MEDIUM = 3;
    final int AUTHENTICATE_HIGH = 1;
    final int MINUTE_TO_MS = 60 * 1000;

    private String autorisation_level;
    private final String TAG = "NFC_BARCODES-NFCLoggedInActivity";

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        timestamp = System.currentTimeMillis();
        setContentView(R.layout.activity_nfc_logged);

        Button lowSecurity = findViewById(R.id.button_low);
        Button mediumSecurity = findViewById(R.id.button_medium);
        Button maxSecurity = findViewById(R.id.button_max);

        lowSecurity.setOnClickListener(this);
        mediumSecurity.setOnClickListener(this);
        maxSecurity.setOnClickListener(this);

        // When a NFC tag is read we reset the timestamp and inform the user
        setNFCEventListener(result -> {
            Log.i(TAG, "Tag read");
            timestamp = System.currentTimeMillis();
            Toast.makeText(getApplicationContext(), R.string.nfc_loggedIn_timestamp_update, Toast.LENGTH_LONG).show();
        });
    }

    @Override
    public void onClick(View v) {

        long offset = System.currentTimeMillis() - timestamp;
        long limit;
        Toast toast = Toast.makeText(getApplicationContext(), "", Toast.LENGTH_LONG);
        switch (v.getId()) {
            case R.id.button_low:
                limit = AUTHENTICATE_LOW * MINUTE_TO_MS; //5min
                break;
            case R.id.button_medium:
                limit = AUTHENTICATE_MEDIUM * MINUTE_TO_MS; //3min
                break;
            case R.id.button_max:
                limit = AUTHENTICATE_HIGH * MINUTE_TO_MS; //1min
                break;
            default:
                limit = 1;
                break;
        }

        if (offset < limit) {
            toast.setText(R.string.nfc_loggedIn_access_ok);
        }
        else {
            if (offset > AUTHENTICATE_HIGH * MINUTE_TO_MS) {
                autorisation_level = "Medium";
            }
            if (offset > AUTHENTICATE_MEDIUM * MINUTE_TO_MS) {
                autorisation_level = "Low";
            }
            if (offset > AUTHENTICATE_LOW * MINUTE_TO_MS) {
                autorisation_level = "0";
            }
            toast.setText(R.string.nfc_loggedIn_access_not_ok + autorisation_level);
        }
        toast.show();
    }
}
