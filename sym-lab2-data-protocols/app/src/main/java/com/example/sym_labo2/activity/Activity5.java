package com.example.sym_labo2.activity;

import android.graphics.Typeface;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.sym_labo2.R;
import com.example.sym_labo2.communication.SymComManager;
import com.example.sym_labo2.model.graphql.Author;
import com.example.sym_labo2.model.graphql.GQLAuthorsResponse;
import com.example.sym_labo2.model.graphql.GQLMessageResponse;
import com.example.sym_labo2.model.graphql.Message;
import com.google.gson.Gson;

import java.util.ArrayList;
import java.util.List;

/**
 * Requêtes GraphQL.
 */
public class Activity5 extends AppCompatActivity {

    private static final String QUERY_ALL_AUTHORS = "{\"query\":\"{allAuthors{id first_name last_name}}\"}";
    private static final String QUERY_ALL_POSTS = "{\"query\":\"{allPostByAuthor(authorId:%d){id title content}}\"}";

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_5);

        SymComManager scm = new SymComManager();

        Spinner spinner = findViewById(R.id.spinner_5);
        LinearLayout insideScrollView = findViewById(R.id.layoutInsideScrollView_5);

        // Handle server response.
        scm.setCommunicationEventListener(response -> {

            Gson gson = new Gson();

            if (response.getError() != null) {
                Toast.makeText(this, R.string.activity_5_graphql_error, Toast.LENGTH_SHORT).show();
            }
            else if (response.getBody().contains(getResources().getString(R.string.activity_5_allAuthors))) {

                GQLAuthorsResponse listAuthors = gson.fromJson(response.getBody(), GQLAuthorsResponse.class);
                List<Author> authorList = listAuthors.getData().getAllAuthors();
                List<String> authorsName = new ArrayList<>(authorList.size() + 1);
                authorsName.add(getResources().getString(R.string.activity_5_default));

                for (Author author : authorList) {
                    authorsName.add(author.toString());
                }

                ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, authorsName);
                spinner.setAdapter(adapter);
            }
            else if (response.getBody().contains(getResources().getString(R.string.activity_5_allPost))) {

                GQLMessageResponse listMessages = gson.fromJson(response.getBody(), GQLMessageResponse.class);
                List<Message> messageList = listMessages.getData().getAllPostByAuthor();

                for (Message message : messageList) {

                    implementView(insideScrollView, message, true);
                    implementView(insideScrollView, message, false);
                }
            }
        });

        // Get all quotes from selected author.
        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {

            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (position != 0) {
                    insideScrollView.removeAllViews();
                    scm.sendGraphQLRequest(String.format(QUERY_ALL_POSTS, position), false);
                }
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                // nothing here in this case
            }
        });

        // Get all authors for the spinner.
        scm.sendGraphQLRequest(QUERY_ALL_AUTHORS, false);
    }

    private void implementView(LinearLayout layout, Message message, boolean heading) {

        TextView temp = new TextView(this);
        temp.setLayoutParams(new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        String title = message.getTitle();
        String body = message.getContent();

        if (heading) {
            temp.setTextSize(20);
            temp.setText(title);
            temp.setTypeface(null, Typeface.BOLD);
            temp.setPadding(0, 15, 0, 5);
        }
        else {
            temp.setText(body);
            temp.setTextSize(17);
            temp.setPadding(10, 0, 10, 0);
        }

        layout.addView(temp);
    }
}

