package ch.heigvd.iict.sym_labo4.viewmodels;

import android.app.Application;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import java.text.DateFormat;
import java.util.Calendar;

import ch.heigvd.iict.sym_labo4.util.Converter;
import ch.heigvd.iict.sym_labo4.service.Characteristic;
import ch.heigvd.iict.sym_labo4.service.Service;
import no.nordicsemi.android.ble.BleManager;
import no.nordicsemi.android.ble.BleManagerCallbacks;

/**
 * PROJECT     : LABORATOIRE 4
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 08/01/2020
 * VERSION     : 1
 * DESCRIPTION : Package-private class used to implement the protocol to
 *               communicate with the BLE device.
 */
class MySymBleManager extends BleManager<BleManagerCallbacks> {

    private static final String TAG = MySymBleManager.class.getSimpleName();
    private static final DateFormat FORMAT = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM);

    // Connection with the device
    private BluetoothGatt deviceConnection;

    // Callback object
    private final BleManagerGattCallback gattCallback = new MySymBleManagerGattCallback();

    // Allows to read, write and be notified of the device's time
    private BluetoothGattCharacteristic timeCharacteristic;

    // Allows to write integers to the device's chart
    private BluetoothGattCharacteristic integerCharacteristic;

    // Allows to read the device's temperature
    private BluetoothGattCharacteristic temperatureCharacteristic;

    // Allows to be notified of the button click count
    private BluetoothGattCharacteristic buttonCharacteristic;

    // Live data for values sent by the device
    private final MutableLiveData<Calendar> time = new MutableLiveData<>();
    private final MutableLiveData<Float> temperature = new MutableLiveData<>();
    private final MutableLiveData<Integer> buttonClickCount = new MutableLiveData<>();

    MySymBleManager(Application app) {
        super(app);
    }

    boolean readTemperature() {

        if (deviceConnection == null || temperatureCharacteristic == null) {
            return false;
        }

        readCharacteristic(temperatureCharacteristic).with((device, data) -> {

            Integer temperature = Converter.toShort(data);
            if (temperature != null) {
                this.temperature.postValue(temperature / 10.0f);
                Log.i(TAG, String.format("Temperature on device %s is %f.", device, this.temperature.getValue()));
            }
        }).enqueue();

        return true;
    }

    boolean writeInteger(int value) {

        if (deviceConnection == null || integerCharacteristic == null) {
            return false;
        }

        writeCharacteristic(integerCharacteristic, Converter.toData(value)).enqueue();
        return true;
    }

    boolean writeTime(Calendar calendar) {

        if (deviceConnection == null || timeCharacteristic == null) {
            return false;
        }

        writeCharacteristic(timeCharacteristic, Converter.toData(calendar)).enqueue();
        return true;
    }

    @Override
    @NonNull
    public BleManagerGattCallback getGattCallback() {
        return gattCallback;
    }

    LiveData<Float> getTemperature() {
        return temperature;
    }

    LiveData<Integer> getButtonClickCount() {
        return buttonClickCount;
    }

    LiveData<Calendar> getTime() {
        return time;
    }

    void disconnectAll() {
        disconnect();
        if (deviceConnection != null) {
            deviceConnection.disconnect();
        }
    }

    private class MySymBleManagerGattCallback extends BleManagerGattCallback {

        @Override
        public boolean isRequiredServiceSupported(@NonNull final BluetoothGatt gatt) {

            deviceConnection = gatt; // trick to force disconnection in disconnectAll()
            Log.i(TAG, "Discovered services and characteristics:");

            try {
                /* Get time service & characteristic. */

                BluetoothGattService timeService = getService(gatt, Service.TIME);
                timeCharacteristic = getCharacteristic(timeService, Characteristic.TIME);

                /* Get SYM service and characteristics. */

                BluetoothGattService symService = getService(gatt, Service.SYM);
                integerCharacteristic = getCharacteristic(symService, Characteristic.INTEGER);
                temperatureCharacteristic = getCharacteristic(symService, Characteristic.TEMPERATURE);
                buttonCharacteristic = getCharacteristic(symService, Characteristic.BUTTON_CLICK_COUNT);
            }
            catch (IllegalStateException e) {
                mCallbacks.onDeviceNotSupported(getBluetoothDevice());
                return false;
            }

            // everything ok
            return true;
        }

        @Override
        protected void initialize() {

            /* Register callbacks for the buttonClickCount and time characteristics. */

            setNotificationCallback(buttonCharacteristic).with((device, data) -> {

                Integer buttonClicks = Converter.toByte(data);
                if (buttonClicks != null) {
                    buttonClickCount.postValue(buttonClicks);
                    Log.i(TAG, String.format("Button on device %s pressed %d time(s).", device, buttonClicks));
                }
            });

            setNotificationCallback(timeCharacteristic).with((device, data) -> {

                Calendar calendar = Converter.toCalendar(data);
                if (calendar != null) {
                    time.postValue(calendar);
                    Log.i(TAG, String.format("Current time on device %s is %s.", device, FORMAT.format(calendar.getTime())));
                }
            });

            enableNotifications(buttonCharacteristic).enqueue();
            enableNotifications(timeCharacteristic).enqueue();
        }

        @Override
        protected void onDeviceDisconnected() {
            timeCharacteristic = null;
            integerCharacteristic = null;
            temperatureCharacteristic = null;
            buttonCharacteristic = null;
        }

        private BluetoothGattService getService(BluetoothGatt gatt, Service service) {

            BluetoothGattService gattService = gatt.getService(service.uuid);
            if (gattService != null) {
                Log.i(TAG, String.format("  %s", service));
                return gattService;
            }

            Log.w(TAG, String.format("  %s not found!", service));
            throw new IllegalStateException("Service not found!");
        }

        private BluetoothGattCharacteristic getCharacteristic(BluetoothGattService service, Characteristic characteristic) {

            BluetoothGattCharacteristic gattCharacteristic = service.getCharacteristic(characteristic.uuid);
            if (gattCharacteristic == null) {
                Log.w(TAG, String.format("    %s not found!", characteristic));
                throw new IllegalStateException("Characteristic not found!");
            }

            if ((gattCharacteristic.getProperties() & characteristic.properties) != characteristic.properties) {
                Log.w(TAG, String.format("    %s found but without wanted properties!", characteristic));
                throw new IllegalStateException("Characteristic property not found!"); // we require all properties to be present
            }

            Log.i(TAG, String.format("    %s", characteristic));
            return gattCharacteristic;
        }
    }
}