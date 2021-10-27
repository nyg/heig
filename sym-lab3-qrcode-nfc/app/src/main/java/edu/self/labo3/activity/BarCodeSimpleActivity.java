package edu.self.labo3.activity;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import edu.self.labo3.R;

/**
 * PROJECT     : LABORATOIRE 3
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 1/12/19
 * VERSION     : 1
 * DESCRIPTION : This is a simple activity who start another activity to scan
 * a barcode. When a barcode is scanned, we return to this activity set the
 * result to the textView. It uses the zxing package.
 */
public class BarCodeSimpleActivity extends AppCompatActivity {

    private static final String SCAN_RESULT_BUNDLE_KEY = "bcs-scan-result";

    private TextView barcodeScanResult;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_bar_code_simple);

        // restore scanned barcode result if it existed
        barcodeScanResult = findViewById(R.id.scanned_barcode_textview);
        if (savedInstanceState != null) {
            barcodeScanResult.setText(savedInstanceState.getString(SCAN_RESULT_BUNDLE_KEY, ""));
        }

        // define action when scan button is clicked – launch new activity
        Button scanButton = findViewById(R.id.scan_button);
        scanButton.setOnClickListener(l -> {
            IntentIntegrator integrator = new IntentIntegrator(this);
            integrator.setOrientationLocked(false);
            integrator.initiateScan();
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {

        // display the scanned barcode from the activity that just returned
        IntentResult result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
        if (result != null) {
            if (result.getContents() == null) {
                barcodeScanResult.setText(R.string.bcs_scan_cancelled);
            }
            else {
                barcodeScanResult.setText(result.getContents());
            }
        }
        else {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    @Override
    public void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putString(SCAN_RESULT_BUNDLE_KEY, barcodeScanResult.getText().toString());
    }
}
