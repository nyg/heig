package com.example.sym_labo2.activity;

import android.os.Bundle;
import android.util.Log;
import android.util.Xml;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.example.sym_labo2.R;
import com.example.sym_labo2.communication.SymComManager;
import com.example.sym_labo2.model.serialization.Directory;
import com.example.sym_labo2.model.serialization.Gender;
import com.example.sym_labo2.model.serialization.Person;
import com.example.sym_labo2.model.serialization.Phone;
import com.example.sym_labo2.model.serialization.PhoneType;
import com.example.sym_labo2.model.serialization.SerializationMethod;
import com.google.gson.Gson;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;
import org.xmlpull.v1.XmlSerializer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

/**
 * Sérialisation JSON et XML.
 */
public class Activity3 extends AppCompatActivity {

    private static final String TAG = Activity3.class.getSimpleName();

    private static final String DOCUMENT_DECLARATION = " directory SYSTEM \"http://sym.iict.ch/directory.dtd\"";
    private static final String UTF_8 = "UTF-8";
    private static final String NAMESPACE = "";

    private static final String PERSON_TAG = "person";
    private static final String NAME_TAG = "name";
    private static final String GENDER_TAG = "gender";
    private static final String FIRSTNAME_TAG = "firstname";
    private static final String MIDDLENAME_TAG = "middlename";
    private static final String PHONE_TAG = "phone";
    private static final String PHONE_TYPE_TAG = "type";
    private static final String DIRECTORY_TAG = "directory";

    private SerializationMethod serializationMethod = SerializationMethod.JSON;
    private Gender gender = Gender.MALE;
    private PhoneType phoneType = PhoneType.HOME;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_3);

        Button sendButton = findViewById(R.id.button_send_3);
        EditText firstname = findViewById(R.id.edit_firstname_3);
        EditText lastname = findViewById(R.id.edit_name_3);
        TextView receivedText = findViewById(R.id.received_view_3);
        EditText phone = findViewById(R.id.edit_phone_3);
        EditText middlename = findViewById(R.id.edit_middlename_3);

        SymComManager scm = new SymComManager();

        // Handle server response.
        scm.setCommunicationEventListener(response -> {

            if (response.getError() != null) {
                receivedText.setText("Received error: " + response.getError().getMessage());
            }
            else if (serializationMethod == SerializationMethod.JSON) {
                Gson gson = new Gson();
                Person person = gson.fromJson(response.getBody(), Person.class);
                receivedText.setText(person.toString());
            }
            else {
                String xml = parseXML(response.getBody());
                if (xml == null) {
                    receivedText.setText(R.string.activity_3_error_xml);
                }
                else {
                    receivedText.setText(xml);
                }
            }
        });

        // Send button click listener.
        sendButton.setOnClickListener(view -> {

            List<Phone> phones = new ArrayList<>();
            phones.add(Phone.builder().number(phone.getText().toString()).type(phoneType).build());

            Person person = Person.builder()
                    .firstname(firstname.getText().toString())
                    .name(lastname.getText().toString())
                    .middlename(middlename.getText().toString())
                    .gender(gender)
                    .phones(phones)
                    .build();

            if (serializationMethod == SerializationMethod.JSON) {
                // send a JSON request
                scm.sendJsonRequest(person, false);
            }
            else {
                // send an XML request
                List<Person> persons = new ArrayList<>();
                persons.add(person);
                Directory directory = Directory.builder().persons(persons).build();
                scm.sendXMLRequest(serializeXML(directory), false);
            }
        });
    }

    private String parseXML(String xml) {

        try {
            XmlPullParserFactory parserFactory = XmlPullParserFactory.newInstance();
            XmlPullParser parser = parserFactory.newPullParser();

            InputStream inputStream = new ByteArrayInputStream(xml.getBytes(Charset.forName("UTF-8")));
            parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false);
            parser.setInput(inputStream, "UTF-8");
            return processParsing(parser);
        }
        catch (XmlPullParserException | IOException e) {
            Log.e(TAG, e.getMessage(), e);
            return null;
        }
    }

    private String processParsing(XmlPullParser parser) throws IOException, XmlPullParserException {

        List<Person> persons = new ArrayList<>();
        int eventType = parser.getEventType();
        Person currentPerson = null;

        while (eventType != XmlPullParser.END_DOCUMENT) {

            if (eventType == XmlPullParser.START_TAG) {

                String eltName = parser.getName();
                if (PERSON_TAG.equals(eltName)) {
                    currentPerson = Person.builder().build();
                    persons.add(currentPerson);
                }
                else if (currentPerson != null) {
                    if (NAME_TAG.equals(eltName)) {
                        currentPerson.setName(parser.nextText());
                    }
                    else if (GENDER_TAG.equals(eltName)) {
                        currentPerson.setGender(Gender.valueOf(parser.nextText()));
                    }
                    else if (FIRSTNAME_TAG.equals(eltName)) {
                        currentPerson.setFirstname(parser.nextText());
                    }
                    else if (MIDDLENAME_TAG.equals(eltName)) {
                        currentPerson.setMiddlename(parser.nextText());
                    }
                    else if (PHONE_TAG.equals(eltName)) {
                        List<Phone> phones = new ArrayList<>();
                        String type = parser.getAttributeValue(NAMESPACE, PHONE_TYPE_TAG);
                        phones.add(Phone.builder().number(parser.nextText()).type(PhoneType.valueOf(type.toUpperCase())).build());
                        currentPerson.setPhones(phones);
                    }
                }
            }

            eventType = parser.next();
        }

        return persons.toString();
    }

    private String serializeXML(Directory directory) {

        try {
            StringWriter writer = new StringWriter();
            XmlSerializer xmlSerializer = Xml.newSerializer();
            xmlSerializer.setOutput(writer);

            // Start Document
            xmlSerializer.startDocument(UTF_8, false);
            xmlSerializer.docdecl(DOCUMENT_DECLARATION);
            xmlSerializer.startTag(NAMESPACE, DIRECTORY_TAG);

            for (Person person : directory.getPersons()) {

                xmlSerializer.startTag(NAMESPACE, PERSON_TAG);
                xmlSerializer.startTag(NAMESPACE, NAME_TAG);
                xmlSerializer.text(person.getName());
                xmlSerializer.endTag(NAMESPACE, NAME_TAG);
                xmlSerializer.startTag(NAMESPACE, FIRSTNAME_TAG);
                xmlSerializer.text(person.getFirstname());
                xmlSerializer.endTag(NAMESPACE, FIRSTNAME_TAG);

                if (person.getMiddlename() != null) {
                    xmlSerializer.startTag(NAMESPACE, MIDDLENAME_TAG);
                    xmlSerializer.text(person.getMiddlename());
                    xmlSerializer.endTag(NAMESPACE, MIDDLENAME_TAG);
                }

                xmlSerializer.startTag(NAMESPACE, GENDER_TAG);
                xmlSerializer.text(person.getGender().name());
                xmlSerializer.endTag(NAMESPACE, GENDER_TAG);

                for (Phone phone : person.getPhones()) {
                    xmlSerializer.startTag(NAMESPACE, PHONE_TAG);
                    xmlSerializer.attribute(NAMESPACE, PHONE_TYPE_TAG, phone.getType().name().toLowerCase());
                    xmlSerializer.text(phone.getNumber());
                    xmlSerializer.endTag(NAMESPACE, PHONE_TAG);
                }

                xmlSerializer.endTag(NAMESPACE, PERSON_TAG);
            }

            xmlSerializer.endTag(NAMESPACE, DIRECTORY_TAG);
            xmlSerializer.endDocument();

            return writer.toString();
        }
        catch (IOException e) {
            Log.e(TAG, e.getMessage(), e);
            return null;
        }
    }

    /* Listeners for RadioButton changes. */

    public void onGenderChanged(View view) {
        gender = Gender.withId(view.getId());
    }

    public void onPhoneTypeChanged(View view) {
        phoneType = PhoneType.withId(view.getId());
    }

    public void onSerialisationMethodChanged(View view) {
        serializationMethod = SerializationMethod.withId(view.getId());
    }
}