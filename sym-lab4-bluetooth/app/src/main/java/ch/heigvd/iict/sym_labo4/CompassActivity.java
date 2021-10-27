package ch.heigvd.iict.sym_labo4;

import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.opengl.GLSurfaceView;
import android.os.Bundle;
import android.view.Window;
import android.view.WindowManager;

import androidx.appcompat.app.AppCompatActivity;

import ch.heigvd.iict.sym_labo4.gl.OpenGLRenderer;

/**
 * PROJECT     : LABORATOIRE 4
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 08/01/2020
 * VERSION     : 1
 * DESCRIPTION : Inspired from : https://developer.android.com/reference/android/hardware/SensorManager.html
 */
public class CompassActivity extends AppCompatActivity implements SensorEventListener {

    private static final String TAG = "CompassActivity_LOGS";

    //opengl
    private OpenGLRenderer opglr = null;
    private GLSurfaceView m3DView = null;
    private SensorManager mSensorManager;
    private Sensor mAccelerometer;
    private Sensor mMagnetometer;
    private float[] last_magnetic = new float[3];
    private float[] last_accelerometer = new float[3];
    private float[] r = new float[16];

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // we need fullscreen
        this.requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN, WindowManager.LayoutParams.FLAG_FULLSCREEN);

        // we initiate the view
        setContentView(R.layout.activity_compass);
        this.mSensorManager = (SensorManager) getSystemService(SENSOR_SERVICE);
        this.mAccelerometer = mSensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
        this.mMagnetometer = mSensorManager.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD);

        //we create the renderer
        this.opglr = new OpenGLRenderer(getApplicationContext());

        // link to GUI
        this.m3DView = findViewById(R.id.compass_opengl);

        //init opengl surface view
        this.m3DView.setRenderer(this.opglr);

    }

    protected void onResume() {
        super.onResume();
        mSensorManager.registerListener(this, mAccelerometer, SensorManager.SENSOR_DELAY_UI);
        mSensorManager.registerListener(this, mMagnetometer, SensorManager.SENSOR_DELAY_UI);
    }

    protected void onPause() {
        super.onPause();
        mSensorManager.unregisterListener(this);
    }

    public void onAccuracyChanged(Sensor sensor, int accuracy) {

    }

    // from : https://developer.android.com/guide/topics/sensors/sensors_position
    public void onSensorChanged(SensorEvent event) {
        //Log.i(TAG, "Accuracy : " + event.accuracy);
        if (event.sensor.getType() == Sensor.TYPE_ACCELEROMETER) {
            System.arraycopy(event.values, 0, last_accelerometer, 0, 3);
        }
        if (event.sensor.getType() == Sensor.TYPE_MAGNETIC_FIELD) {
            System.arraycopy(event.values, 0, last_magnetic, 0, 3);
        }
        if (SensorManager.getRotationMatrix(r, null, last_accelerometer, last_magnetic)) {
            r = this.opglr.swapRotMatrix(r);
        }
    }
}
