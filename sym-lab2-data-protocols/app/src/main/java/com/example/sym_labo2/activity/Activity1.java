package com.example.sym_labo2.activity;

import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.example.sym_labo2.R;
import com.example.sym_labo2.communication.SymComManager;

/**
 * Transmission asynchrone.
 */
public class Activity1 extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_1);

        Button buttonSend = findViewById(R.id.button_send_1);
        EditText sendText = findViewById(R.id.edit_send_1);
        TextView receivedText = findViewById(R.id.received_text_1);
        SymComManager scm = new SymComManager();

        /* Handle response sent by the server. */
        scm.setCommunicationEventListener(response -> {

            String message;
            if (response.getError() != null) {
                // If we have an error, warn the user.
                message = "Received error: " + response.getError().getMessage();
            }
            else {
                message = response.getBody();
            }

            receivedText.setText(message);
        });

        buttonSend.setOnClickListener(view -> {
            // Send the asynchronous request
            scm.sendTextRequest(sendText.getText().toString(), false);
        });
    }
}
