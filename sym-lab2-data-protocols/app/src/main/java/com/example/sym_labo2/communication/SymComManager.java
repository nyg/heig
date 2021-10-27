package com.example.sym_labo2.communication;

import com.example.sym_labo2.model.communication.Request;
import com.google.gson.Gson;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * DownloadTask inspiré de l'exemple de la doc Android.
 */
public class SymComManager {

    // MIME types
    private static final String TXT_MIME_TYPE = "plain/text";
    private static final String JSON_MIME_TYPE = "application/json";
    private static final String XML_MIME_TYPE = "application/xml";
    private static final String GQL_MIME_TYPE = "application/json";

    // Endpoints
    private static final URL TXT_URL;
    private static final URL JSON_URL;
    private static final URL XML_URL;
    private static final URL GQL_URL;

    static {
        try {
            TXT_URL = new URL("http://sym.iict.ch/rest/txt");
            JSON_URL = new URL("http://sym.iict.ch/rest/json");
            XML_URL = new URL("http://sym.iict.ch/rest/xml");
            GQL_URL = new URL("http://sym.iict.ch/api/graphql");
        }
        catch (MalformedURLException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /* CommunicationEventListener which handles the callback. */

    private CommunicationEventListener communicationEventListener;

    public void setCommunicationEventListener(CommunicationEventListener communicationEventListener) {
        this.communicationEventListener = communicationEventListener;
    }

    /* Variations of the sendRequest method. */

    public void sendTextRequest(String body, boolean compress) {
        sendRequest(body, TXT_URL, TXT_MIME_TYPE, compress);
    }

    public void sendJsonRequest(Object object, boolean compress) {
        String json = new Gson().toJson(object);
        sendRequest(json, JSON_URL, JSON_MIME_TYPE, compress);
    }

    public void sendXMLRequest(String xml, boolean compress) {
        sendRequest(xml, XML_URL, XML_MIME_TYPE, compress);
    }

    public void sendGraphQLRequest(String query, boolean compress) {
        sendRequest(query, GQL_URL, GQL_MIME_TYPE, compress);
    }

    private void sendRequest(String body, URL endpoint, String mimeType, boolean compress) {
        DownloadTask task = new DownloadTask(communicationEventListener);
        task.execute(Request.builder().body(body).mimeType(mimeType).endpoint(endpoint).shouldCompress(compress).build());
    }
}