package com.example.sym_labo2.activity;

import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.example.sym_labo2.R;
import com.example.sym_labo2.communication.SymComManager;

/**
 * Transmission compressée.
 */
public class Activity4 extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_4);

        Button buttonSend = findViewById(R.id.button_send_4);
        TextView textReceived = findViewById(R.id.edit_received_4);
        EditText textSend = findViewById(R.id.edit_send_4);
        SymComManager scm = new SymComManager();

        // Handle server response.
        scm.setCommunicationEventListener(response -> {

            String message;
            if (response.getError() != null) {
                message = "Received error: " + response.getError().getMessage();
            }
            else {
                message = response.getBody();
            }

            textReceived.setText(message);
        });

        // Send compressed request
        buttonSend.setOnClickListener(view -> scm.sendTextRequest(textSend.getText().toString(), true));
    }
}