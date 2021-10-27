package ch.heigvd.iict.sym_labo4;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.ParcelUuid;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.lifecycle.ViewModelProviders;

import java.text.DateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;

import ch.heigvd.iict.sym_labo4.abstractactivies.BaseTemplateActivity;
import ch.heigvd.iict.sym_labo4.adapters.ResultsAdapter;
import ch.heigvd.iict.sym_labo4.service.Service;
import ch.heigvd.iict.sym_labo4.viewmodels.BleOperationsViewModel;

/**
 * Created by fabien.dutoit on 09.08.2019
 * (C) 2019 - HEIG-VD, IICT
 *
 * PROJECT     : LABORATOIRE 4
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 08/01/2020
 * VERSION     : 1
 * DESCRIPTION : Bluetooth activity.
 */
public class BleActivity extends BaseTemplateActivity {

    private static final String TAG = BleActivity.class.getSimpleName();
    private static final DateFormat FORMAT = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM);

    // system services
    private BluetoothAdapter bluetoothAdapter;

    // view model
    private BleOperationsViewModel bleViewModel;

    // gui elements
    private View operationPanel;
    private View scanPanel;

    private ListView scanResults;
    private TextView emptyScanResults;

    private TextView buttonClickCountLabel;
    private TextView temperatureLabel;
    private TextView timeLabel;
    private EditText integerInput;

    private Button readTemperatureButton;
    private Button writeTimeButton;
    private Button writeIntegerButton;

    // menu elements
    private MenuItem scanMenuBtn;
    private MenuItem disconnectMenuBtn;

    // adapters
    private ResultsAdapter scanResultsAdapter;

    // states
    private Handler handler;
    private boolean isScanning;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_ble);

        handler = new Handler();

        // enable and start bluetooth - initialize bluetooth adapter
        final BluetoothManager bluetoothManager = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        bluetoothAdapter = bluetoothManager.getAdapter();

        // link GUI
        operationPanel = findViewById(R.id.ble_operation);
        scanPanel = findViewById(R.id.ble_scan);
        scanResults = findViewById(R.id.ble_scanresults);
        emptyScanResults = findViewById(R.id.ble_scanresults_empty);

        buttonClickCountLabel = findViewById(R.id.button_click_count_label);
        temperatureLabel = findViewById(R.id.temperature_label);
        timeLabel = findViewById(R.id.time_label);
        integerInput = findViewById(R.id.integer_input);

        readTemperatureButton = findViewById(R.id.read_temperature_button);
        writeTimeButton = findViewById(R.id.write_time_button);
        writeIntegerButton = findViewById(R.id.write_integer_button);

        // manage scanned item
        scanResultsAdapter = new ResultsAdapter(this);
        scanResults.setAdapter(scanResultsAdapter);
        scanResults.setEmptyView(emptyScanResults);

        // connect to view model
        bleViewModel = ViewModelProviders.of(this).get(BleOperationsViewModel.class);
        updateGui();

        // events
        scanResults.setOnItemClickListener((parent, view, position, id) ->
                runOnUiThread(() -> {
                    // we stop scanning
                    scanLeDevice(false);
                    // we connect to the clicked device
                    bleViewModel.connect(((ScanResult) scanResultsAdapter.getItem(position)).getDevice());
                }));

        // ble events
        bleViewModel.isConnected().observe(this, (isConnected) -> updateGui());

        // observe temperature changes
        bleViewModel.getTemperature().observe(this, temperature ->
                temperatureLabel.setText(String.format("%f", temperature)));

        // observe button click count changes
        bleViewModel.getButtonClickCount().observe(this, buttonClickCount ->
                buttonClickCountLabel.setText(String.format("%d", buttonClickCount)));

        // observe time changes
        bleViewModel.getTime().observe(this, calendar ->
                timeLabel.setText(FORMAT.format(calendar.getTime())));

        /* Set button on-click listeners */

        readTemperatureButton.setOnClickListener(v -> {
            if (!bleViewModel.readTemperature()) {
                Toast.makeText(this, R.string.ble_temp_not_read, Toast.LENGTH_SHORT).show();
            }
        });

        writeTimeButton.setOnClickListener(v -> {
            if (!bleViewModel.writeTime(Calendar.getInstance())) {
                Toast.makeText(this, R.string.ble_time_not_written, Toast.LENGTH_SHORT).show();
            }
        });

        writeIntegerButton.setOnClickListener(v -> {

            String s = integerInput.getText().toString();
            Integer value = null;
            try {
                value = Integer.parseInt(s);
                if (value < 0) {
                    value = null;
                }
            }
            catch (NumberFormatException e) {
                // Nothing
            }

            if (s.isEmpty() || value == null || !bleViewModel.writeInteger(value)) {
                Toast.makeText(this, R.string.ble_integer_not_written, Toast.LENGTH_SHORT).show();
            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.ble_menu, menu);
        // we link the two menu items
        scanMenuBtn = menu.findItem(R.id.menu_ble_search);
        disconnectMenuBtn = menu.findItem(R.id.menu_ble_disconnect);
        // we update the gui
        updateGui();
        return super.onCreateOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.menu_ble_search) {
            if (isScanning) {
                scanLeDevice(false);
            }
            else {
                scanLeDevice(true);
            }
            return true;
        }
        else if (id == R.id.menu_ble_disconnect) {
            bleViewModel.disconnect();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (isScanning) {
            scanLeDevice(false);
        }
        if (isFinishing()) {
            bleViewModel.disconnect();
        }
    }

    /*
     * Method used to update the GUI according to BLE status:
     * - connected: display operation panel (BLE control panel)
     * - not connected: display scan result
     */
    private void updateGui() {
        Boolean isConnected = bleViewModel.isConnected().getValue();
        if (isConnected != null && isConnected) {
            scanPanel.setVisibility(View.GONE);
            operationPanel.setVisibility(View.VISIBLE);

            if (scanMenuBtn != null && disconnectMenuBtn != null) {
                scanMenuBtn.setVisible(false);
                disconnectMenuBtn.setVisible(true);
            }
        }
        else {
            operationPanel.setVisibility(View.GONE);
            scanPanel.setVisibility(View.VISIBLE);

            if (scanMenuBtn != null && disconnectMenuBtn != null) {
                disconnectMenuBtn.setVisible(false);
                scanMenuBtn.setVisible(true);
            }
        }
    }

    // This method needs user granted localisation permission, our demo app is requesting it on MainActivity.
    private void scanLeDevice(final boolean enable) {
        final BluetoothLeScanner bluetoothScanner = bluetoothAdapter.getBluetoothLeScanner();
        if (enable) {

            // config
            ScanSettings.Builder builderScanSettings = new ScanSettings.Builder();
            builderScanSettings.setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY);
            builderScanSettings.setReportDelay(0);

            // reset display
            scanResultsAdapter.clear();

            ScanFilter symFilter = new ScanFilter.Builder().setServiceUuid(new ParcelUuid(Service.SYM.uuid)).build();
            List<ScanFilter> filterList = Collections.singletonList(symFilter);
            bluetoothScanner.startScan(filterList, builderScanSettings.build(), leScanCallback);

            Log.d(TAG, "Start scanning...");
            isScanning = true;

            // we scan only for 15 seconds
            handler.postDelayed(() -> {
                scanLeDevice(false);
            }, 15 * 1000L);
        }
        else {
            bluetoothScanner.stopScan(leScanCallback);
            isScanning = false;
            Log.d(TAG, "Stop scanning (manual)");
        }
    }

    // Device scan callback.
    private ScanCallback leScanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, final ScanResult result) {
            super.onScanResult(callbackType, result);
            runOnUiThread(() -> {
                scanResultsAdapter.addDevice(result);
            });
        }
    };
}
