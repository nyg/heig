package edu.self.labo3.activity;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;

import androidx.appcompat.app.AppCompatActivity;

import edu.self.labo3.R;

/**
 * PROJECT     : LABORATOIRE 3
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 1/12/19
 * VERSION     : 1
 * DESCRIPTION : This is the Main Activity of our app, so we start here and have
 * 3 different buttons to start the three different activities (Barcode,
 * AdvancedBarcode, NFCLogin).
 */
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button nfcButton = findViewById(R.id.button_nfc);
        Button barCodeSimpleButton = findViewById(R.id.button_barcode_simple);
        Button barCodeAdvancedButton = findViewById(R.id.button_barcode_advanced);

        nfcButton.setOnClickListener(l -> startActivity(new Intent(this, NFCActivity.class)));
        barCodeSimpleButton.setOnClickListener(l -> startActivity(new Intent(this, BarCodeSimpleActivity.class)));
        barCodeAdvancedButton.setOnClickListener(l -> startActivity(new Intent(this, BarCodeAdvancedActivity.class)));
    }
}
