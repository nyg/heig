package edu.self.labo3.activity;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import edu.self.labo3.R;

/**
 * PROJECT     : LABORATOIRE 3
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 1/12/19
 * VERSION     : 1
 * DESCRIPTION : This is not an activity, it's like a parent activity, in fact
 * it handles the functions needed to read NFC tag in a given Activity which
 * extends it. It's useful because we have 2 activites who needs these
 * functions. That's why we have an setNFCEventListener who handle the action
 * when we read a tag.
 *
 * Source : http://mobile.tutsplus.com/tutorials/android/reading-nfc-tags-with-android/
 */
public class NFCActivities extends AppCompatActivity {

    private NfcAdapter mNfcAdapter;
    public static final String MIME_TEXT_PLAIN = "text/plain";
    private static final String TAG = "NFC_BARCODES-NFCActivities";
    private NFCEventListener nfcEventListener;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        if (mNfcAdapter == null) {
            // Stop here, we definitely need NFC
            Toast.makeText(this, R.string.nfc_activities_unsupported, Toast.LENGTH_LONG).show();
            finish();
            return;
        }
        if (!mNfcAdapter.isEnabled()) {
            Toast.makeText(this, R.string.nfc_activities_disabled, Toast.LENGTH_LONG).show();
        }
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        /**
         * This method gets called, when a new Intent gets associated with the current activity instance.
         * Instead of creating a new activity, onNewIntent will be called. For more information have a look
         * at the documentation.
         *
         * In our case this method gets called, when the user attaches a Tag to the device.
         */
        super.onNewIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        String action = intent.getAction();
        Log.i(TAG, "Getting action : " + action);
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action)) {

            String type = intent.getType();
            if (MIME_TEXT_PLAIN.equals(type)) {

                Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                new NFCReader(nfcEventListener).execute(tag);

            }
            else {
                Log.d(TAG, "Wrong mime type: " + type);
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        setupForegroundDispatch();
    }

    @Override
    protected void onPause() {
        //We have to call our method first otherwise an IllegalArgumentException is thrown as well
        stopForegroundDispatch();
        super.onPause();
    }

    // called in onResume()
    private void setupForegroundDispatch() {
        if (mNfcAdapter == null) {
            return;
        }
        final Intent intent = new Intent(this.getApplicationContext(),
                this.getClass());
        intent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        final PendingIntent pendingIntent =
                PendingIntent.getActivity(this.getApplicationContext(), 0, intent, 0);
        IntentFilter[] filters = new IntentFilter[1];
        String[][] techList = new String[][]{};
        // Notice that this is the same filter as in our manifest.
        filters[0] = new IntentFilter();
        filters[0].addAction(NfcAdapter.ACTION_NDEF_DISCOVERED);
        filters[0].addCategory(Intent.CATEGORY_DEFAULT);
        try {
            filters[0].addDataType("text/plain");
        }
        catch (IntentFilter.MalformedMimeTypeException e) {
            Log.e(TAG, "MalformedMimeTypeException", e);
        }
        mNfcAdapter.enableForegroundDispatch(this, pendingIntent, filters, techList);
    }

    // called in onPause()
    private void stopForegroundDispatch() {
        if (mNfcAdapter != null) {
            mNfcAdapter.disableForegroundDispatch(this);
        }
    }

    // This set a callback needed when we read a NFC tag on an infant activity
    public void setNFCEventListener(NFCEventListener eventListener) {
        Log.i(TAG, "EventListener set");
        this.nfcEventListener = eventListener;
    }
}

