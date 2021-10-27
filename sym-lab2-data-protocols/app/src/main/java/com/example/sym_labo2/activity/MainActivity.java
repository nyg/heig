package com.example.sym_labo2.activity;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;

import com.example.sym_labo2.R;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        final Button activity1 = findViewById(R.id.button_activity1);
        final Button activity2 = findViewById(R.id.button_activity2);
        final Button activity3 = findViewById(R.id.button_activity3);
        final Button activity4 = findViewById(R.id.button_activity4);
        final Button activity5 = findViewById(R.id.button_activity5);

        activity1.setOnClickListener(v -> {
            Intent myIntent = new Intent(this, Activity1.class);
            startActivity(myIntent);
        });

        activity2.setOnClickListener(v -> {
            Intent myIntent = new Intent(this, Activity2.class);
            startActivity(myIntent);
        });

        activity3.setOnClickListener(v -> {
            Intent myIntent = new Intent(this, Activity3.class);
            startActivity(myIntent);
        });

        activity4.setOnClickListener(v -> {
            Intent myIntent = new Intent(this, Activity4.class);
            startActivity(myIntent);
        });

        activity5.setOnClickListener(v -> {
            Intent myIntent = new Intent(this, Activity5.class);
            startActivity(myIntent);
        });
    }
}
