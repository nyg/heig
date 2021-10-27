package com.example.sym_labo2.activity;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.example.sym_labo2.R;
import com.example.sym_labo2.communication.SymComManager;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Transmission différée.
 */
public class Activity2 extends AppCompatActivity {

    private static final String TAG = Activity2.class.getSimpleName();

    private TextView receivedTextView;

    private ConnectivityBroadcastReceiver broadcastReceiver;
    private boolean internetAccess;

    private final List<String> requests = new ArrayList<>();
    private final SymComManager scm = new SymComManager();

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_2);

        // Create and register broadcast receiver to be notified when we have internet access or not.
        IntentFilter filter = new IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION);
        broadcastReceiver = new ConnectivityBroadcastReceiver();
        registerReceiver(broadcastReceiver, filter);

        // Get UI.
        Button sendButton = findViewById(R.id.button_send_2);
        EditText sendTextField = findViewById(R.id.edit_send_2);
        receivedTextView = findViewById(R.id.received_text_2);

        // Register listener to handle responses.
        scm.setCommunicationEventListener(response -> {

            String message;
            if (response.getError() != null) {
                // Notify user if the text we display comes from an error.
                message = "Received error: " + response.getError().getMessage();
            }
            else {
                // Display the beginning of a truncated response.
                message = String.format("Received response [%s].\n", getPreview(response.getBody()));
            }

            receivedTextView.append(message);
        });

        // Create a request and store it in a list for later sending (when we will have internet).
        sendButton.setOnClickListener(view -> {

            String request = sendTextField.getText().toString();
            receivedTextView.append(String.format("Created request [%s].\n", getPreview(request)));
            requests.add(request);

            // Send request now if we have internet access.
            if (internetAccess) {
                sendRequests();
            }
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        unregisterReceiver(broadcastReceiver);
    }

    /**
     * Send all the requests available in the list.
     */
    private void sendRequests() {

        Iterator<String> iterator = requests.iterator();
        while (iterator.hasNext()) {

            // send request
            String request = iterator.next();
            receivedTextView.append(String.format("Sending request [%s]…\n", getPreview(request)));
            scm.sendTextRequest(request, false);

            // and remove it from the list
            iterator.remove();
        }
    }

    /**
     * Method for truncating data.
     */
    private String getPreview(String value) {
        return value.substring(0, Math.min(value.length(), 20)).replace("\n", "\\n");
    }

    /**
     * We want to be notified when the connectivity status changes.
     */
    class ConnectivityBroadcastReceiver extends BroadcastReceiver {

        @Override
        public void onReceive(Context context, Intent intent) {

            internetAccess = !intent.getBooleanExtra(ConnectivityManager.EXTRA_NO_CONNECTIVITY, false);
            Log.i(TAG, String.format("Internet access: %b", internetAccess));

            if (internetAccess) {
                sendRequests();
            }
        }
    }
}