package edu.self.labo3.activity;

import android.Manifest;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Bundle;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.google.zxing.ResultPoint;
import com.journeyapps.barcodescanner.BarcodeCallback;
import com.journeyapps.barcodescanner.BarcodeResult;
import com.journeyapps.barcodescanner.DecoratedBarcodeView;
import com.journeyapps.barcodescanner.DefaultDecoderFactory;

import java.util.List;

import edu.self.labo3.R;

/**
 * PROJECT     : LABORATOIRE 3
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 1/12/19
 * VERSION     : 1
 * DESCRIPTION : This Activity presents a way to Scan a Barcode while we are in
 * the Activity, so we can scan the barcode and have the result on the same
 * screen. It uses the zxing package.
 *
 * Source: https://github.com/journeyapps/zxing-android-embedded/blob/master/sample/src/main/java/example/zxing/ContinuousCaptureActivity.java
 */
public class BarCodeAdvancedActivity extends AppCompatActivity {

    private DecoratedBarcodeView barcodeView;
    private ImageView imageResultView;
    private TextView barcodeScanResult;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_bar_code_advanced);

        barcodeScanResult = findViewById(R.id.bca_scan_result);
        imageResultView = findViewById(R.id.bca_picture_view);

        // initialize the barcode view
        barcodeView = findViewById(R.id.bca_barcode_view);
        barcodeView.getBarcodeView().setDecoderFactory(new DefaultDecoderFactory());
        barcodeView.initializeFromIntent(getIntent());
        barcodeView.setStatusText(getString(R.string.bca_scan_barcode));

        // set a callback for when a barcode is detected
        barcodeView.decodeContinuous(new BarcodeCallback() {

            @Override
            public void barcodeResult(BarcodeResult result) {

                // prevent duplicate scans
                if (result.getText() == null || result.getText().equals(barcodeScanResult.getText().toString())) {
                    return;
                }

                // set image view and text result
                imageResultView.setImageBitmap(result.getBitmapWithResultPoints(Color.YELLOW));
                barcodeScanResult.setText(result.getText());
            }

            @Override
            public void possibleResultPoints(List<ResultPoint> resultPoints) {
                // nothing
            }
        });

        // request permission to use the camera
        if (ContextCompat.checkSelfPermission(getApplicationContext(), Manifest.permission.CAMERA) == PackageManager.PERMISSION_DENIED) {
            ActivityCompat.requestPermissions(BarCodeAdvancedActivity.this, new String[]{Manifest.permission.CAMERA}, 1);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        barcodeView.resume();
    }

    @Override
    protected void onPause() {
        super.onPause();
        barcodeView.pause();
    }
}
