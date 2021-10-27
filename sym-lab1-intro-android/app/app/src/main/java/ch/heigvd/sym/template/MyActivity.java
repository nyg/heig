package ch.heigvd.sym.template;

import androidx.appcompat.app.AppCompatActivity;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.graphics.BitmapFactory;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.widget.ImageView;
import android.widget.TextView;

import com.nabinbhandari.android.permissions.Permissions;
import com.nabinbhandari.android.permissions.PermissionHandler;

import java.io.File;
import java.util.ArrayList;

public class MyActivity extends AppCompatActivity {

    // For logging purposes
    private static final String TAG = MyActivity.class.getSimpleName();

    private ImageView photo = null;
    private TextView email = null;
    private TextView imei = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(TAG, "onCreate method called");

        setContentView(R.layout.activity_my);

        // We get the GUI objects
        photo = findViewById(R.id.imageView);
        email = findViewById(R.id.emailEntered);
        imei = findViewById(R.id.IMEI);

        // We get the intent parameters
        Intent myIntent = getIntent();
        String emailEntered = myIntent.getStringExtra("emailEntered");


        email.setText(emailEntered);

        TelephonyManager telephonyManager = (TelephonyManager) this.getSystemService(Context.TELEPHONY_SERVICE);

        String[] permissions = {Manifest.permission.READ_PHONE_STATE, Manifest.permission.READ_EXTERNAL_STORAGE};
        String rationale = "Please HAAAAALP";
        Permissions.Options options = new Permissions.Options()
                .setRationaleDialogTitle("Info")
                .setSettingsDialogTitle("Warning");

        Permissions.check(this/*context*/, permissions, rationale, options, new PermissionHandler() {
            @Override
            public void onGranted() {
                if(Build.VERSION.SDK_INT >= 26) {
                    imei.setText(telephonyManager.getImei());
                } else {
                    imei.setText(telephonyManager.getDeviceId());
                }


                File sdDownload = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                File photoSam = new File(sdDownload, "photoSam.jpg");
                if(photoSam.exists()){
                    photo.setImageBitmap(BitmapFactory.decodeFile(photoSam.getPath()));
                } else {
                    Log.e(TAG, "Image not found : " + photoSam.getAbsolutePath());
                }

                // do your task.
            }

            @Override
            public void onDenied(Context context, ArrayList<String> deniedPermissions) {
                imei.setText(R.string.permissionDenied);
                // permission denied, block the feature.
            }
        });
    }

    @Override
    protected void onStart() {
        super.onStart();
        Log.i(TAG, "onStart method called");
    }

    @Override
    protected void onResume() {
        super.onResume();
        Log.i(TAG, "onResume method called");
    }

    @Override
    protected void onPause() {
        super.onPause();
        Log.i(TAG, "onPause method called");
    }

    @Override
    protected void onStop() {
        super.onStop();
        Log.i(TAG, "onStop method called");
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        Log.i(TAG, "onDestroy method called");
    }

    @Override
    protected void onRestart() {
        super.onRestart();
        Log.i(TAG, "onRestart method called");
    }
}
