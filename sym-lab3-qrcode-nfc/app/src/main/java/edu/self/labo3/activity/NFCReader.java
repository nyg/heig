package edu.self.labo3.activity;

import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.Tag;
import android.nfc.tech.Ndef;
import android.os.AsyncTask;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

/**
 * PROJECT     : LABORATOIRE 3
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 1/12/19
 * VERSION     : 1
 * DESCRIPTION : This class is an AsyncTask used for reading NFC tags, it calls
 * a given callback (NFCEventListener) when read so the activity can handle it
 * correctly.
 */
public class NFCReader extends AsyncTask<Tag, Void, String> {

    private String TAG = "NFC_BARCODES-NFCReader";
    private final NFCEventListener callback;

    public NFCReader(NFCEventListener callback) {
        this.callback = callback;
    }

    @Override
    protected String doInBackground(Tag... params) {
        Tag tag = params[0];

        Ndef ndef = Ndef.get(tag);
        if (ndef == null) {
            Log.e(TAG, "NDEF not supported by the tag");
            // NDEF is not supported by this Tag.
            return null;
        }

        NdefMessage ndefMessage = ndef.getCachedNdefMessage();

        NdefRecord[] records = ndefMessage.getRecords();
        for (NdefRecord ndefRecord : records) {
            if (ndefRecord.getTnf() == NdefRecord.TNF_WELL_KNOWN && Arrays.equals(ndefRecord.getType(), NdefRecord.RTD_TEXT)) {
                try {
                    return readText(ndefRecord);
                }
                catch (UnsupportedEncodingException e) {
                    Log.e(TAG, "Unsupported Encoding", e);
                }
            }
        }

        return null;
    }

    private String readText(NdefRecord record) throws UnsupportedEncodingException {
        /*
         * See NFC forum specification for "Text Record Type Definition" at 3.2.1
         *
         * http://www.nfc-forum.org/specs/
         *
         * bit_7 defines encoding
         * bit_6 reserved for future use, must be 0
         * bit_5..0 length of IANA language code
         */

        byte[] payload = record.getPayload();
        Log.i(TAG, "Payload read from tag : " + payload.toString());

        // Get the Text Encoding
        String textEncoding = ((payload[0] & 128) == 0) ? "UTF-8" : "UTF-16";

        // Get the Language Code
        int languageCodeLength = payload[0] & 0063;

        // Get the Text
        return new String(payload, languageCodeLength + 1, payload.length - languageCodeLength - 1, textEncoding);
    }

    @Override
    protected void onPostExecute(String result) {
        if (result != null) {
            Log.i(TAG, "Tag readed, callback launched");
            this.callback.handleTAG(result);
        }
    }
}
