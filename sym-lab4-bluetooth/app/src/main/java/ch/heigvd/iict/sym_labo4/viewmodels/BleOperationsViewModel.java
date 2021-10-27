package ch.heigvd.iict.sym_labo4.viewmodels;

import android.app.Application;
import android.bluetooth.BluetoothDevice;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import java.util.Calendar;

import no.nordicsemi.android.ble.BleManagerCallbacks;

/**
 * PROJECT     : LABORATOIRE 4
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 08/01/2020
 * VERSION     : 1
 * DESCRIPTION : View model with which the view can interact to communicate with
 *               the bluetooth device.
 */
public class BleOperationsViewModel extends AndroidViewModel {

    private static final String TAG = BleOperationsViewModel.class.getSimpleName();

    // Indicates if we are connected to a device or not
    private final MutableLiveData<Boolean> isConnected = new MutableLiveData<>(false);

    private final MySymBleManager ble;

    public BleOperationsViewModel(Application app) {
        super(app);
        ble = new MySymBleManager(app);
        ble.setGattCallbacks(new MySymBleManagerCallbacks());
    }

    public void connect(BluetoothDevice device) {
        Log.d(TAG, "User request connection to: " + device);
        if (!isConnected.getValue()) {
            ble.connect(device)
                    .retry(1, 100)
                    .useAutoConnect(false)
                    .enqueue();
        }
    }

    public void disconnect() {
        Log.d(TAG, "User request disconnection");
        ble.disconnectAll();
    }

    @Override
    protected void onCleared() {
        super.onCleared();
        Log.d(TAG, "onCleared");
        ble.disconnectAll();
    }

    /**
     * Launches a read temperature request. Observe the result using the
     * getTemperature() LiveData.
     */
    public boolean readTemperature() {
        return isConnected.getValue() && ble.readTemperature();
    }

    /**
     * Launches a write integer request. The last 10 integer values sent to the
     * device are shown on the device's graph.
     *
     * @param integer the integer value to send
     */
    public boolean writeInteger(int integer) {
        return isConnected.getValue() && ble.writeInteger(integer);
    }

    /**
     * Launches a write time request. Observe the result using the
     * getTime() LiveData.
     *
     * @param calendar the date to write as a Calendar instance
     */
    public boolean writeTime(Calendar calendar) {
        return isConnected.getValue() && ble.writeTime(calendar);
    }

    /**
     * The temperature of the device. The value is updated after calling the
     * readTemperature() method.
     */
    public LiveData<Float> getTemperature() {
        return ble.getTemperature();
    }

    /**
     * The number of time a device's button has been clicked. The value is
     * updated each time a button is clicked.
     */
    public LiveData<Integer> getButtonClickCount() {
        return ble.getButtonClickCount();
    }

    /**
     * The time of the device. The value is modified every two seconds
     * (via notification), or after calling the writeTime() method.
     */
    public LiveData<Calendar> getTime() {
        return ble.getTime();
    }

    public LiveData<Boolean> isConnected() {
        return isConnected;
    }

    private class MySymBleManagerCallbacks implements BleManagerCallbacks {

        @Override
        public void onDeviceConnecting(@NonNull BluetoothDevice device) {
            Log.d(TAG, "onDeviceConnecting");
            isConnected.setValue(false);
        }

        @Override
        public void onDeviceConnected(@NonNull BluetoothDevice device) {
            Log.d(TAG, "onDeviceConnected");
            isConnected.setValue(true);
        }

        @Override
        public void onDeviceDisconnecting(@NonNull BluetoothDevice device) {
            Log.d(TAG, "onDeviceDisconnecting");
            isConnected.setValue(false);
        }

        @Override
        public void onDeviceDisconnected(@NonNull BluetoothDevice device) {
            Log.d(TAG, "onDeviceDisconnected");
            isConnected.setValue(false);
        }

        @Override
        public void onLinkLossOccurred(@NonNull BluetoothDevice device) {
            Log.d(TAG, "onLinkLossOccurred");
        }

        @Override
        public void onServicesDiscovered(@NonNull BluetoothDevice device, boolean optionalServicesFound) {
            Log.d(TAG, "onServicesDiscovered");
        }

        @Override
        public void onDeviceReady(@NonNull BluetoothDevice device) {
            Log.d(TAG, "onDeviceReady");
        }

        @Override
        public void onBondingRequired(@NonNull BluetoothDevice device) {
            Log.w(TAG, "onBondingRequired");
        }

        @Override
        public void onBonded(@NonNull BluetoothDevice device) {
            Log.d(TAG, "onBonded");
        }

        @Override
        public void onBondingFailed(@NonNull BluetoothDevice device) {
            Log.e(TAG, "onBondingFailed");
        }

        @Override
        public void onError(@NonNull BluetoothDevice device, @NonNull String message, int errorCode) {
            Log.e(TAG, "onError:" + errorCode);
        }

        @Override
        public void onDeviceNotSupported(@NonNull BluetoothDevice device) {
            Log.e(TAG, "onDeviceNotSupported");
            Toast.makeText(getApplication(), "Device not supported", Toast.LENGTH_SHORT).show();
        }
    }
}
