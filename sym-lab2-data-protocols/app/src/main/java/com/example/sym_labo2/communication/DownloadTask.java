package com.example.sym_labo2.communication;

import android.os.AsyncTask;

import com.example.sym_labo2.model.communication.HttpErrorException;
import com.example.sym_labo2.model.communication.Request;
import com.example.sym_labo2.model.communication.Response;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class DownloadTask extends AsyncTask<Request, Integer, Response> {

    private final CommunicationEventListener callback;

    public DownloadTask(CommunicationEventListener callback) {
        this.callback = callback;
    }

    @Override
    protected Response doInBackground(Request... requests) {

        try {
            if (requests.length != 1) {
                throw new IllegalArgumentException("Only one Request argument should be provided.");
            }

            return downloadUrl(requests[0]);
        }
        catch (Exception e) {
            return Response.builder().error(e).build();
        }
    }

    @Override
    protected void onPostExecute(Response response) {
        callback.handleServerResponse(response);
    }

    private Response downloadUrl(Request request) throws IOException {

        /* Set up the HttpUrlConnection instance. */

        HttpURLConnection connection = (HttpURLConnection) request.getEndpoint().openConnection();

        connection.setReadTimeout(3000);
        connection.setConnectTimeout(3000);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", request.getMimeType());
        connection.setDoInput(true);
        connection.setDoOutput(true);

        /* Set the proper headers if we want to compress the body. */

        if (request.shouldCompress()) {
            connection.setRequestProperty("X-Network", "CSD");
            connection.setRequestProperty("X-Content-Encoding", "deflate");
        }

        /* Write the request body. */

        try (OutputStream output = connection.getOutputStream()) {

            byte[] body = request.getBody().getBytes(StandardCharsets.UTF_8);

            if (request.shouldCompress()) {
                Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true);
                DeflaterOutputStream outputDeflate = new DeflaterOutputStream(output, deflater);
                outputDeflate.write(body);
                outputDeflate.close();
                deflater.end();
            }
            else {
                output.write(body);
            }
        }

        // perform the HTTP request
        connection.connect();

        /* Read the response. */

        String body;
        try (InputStream inputStream = connection.getInputStream()) {

            if (request.shouldCompress()) {
                body = streamToString(new InflaterInputStream(inputStream, new Inflater(true)));
            }
            else {
                body = streamToString(inputStream);
            }
        }

        /* Create the response instance. */

        Response response = Response.builder().body(body).build();

        int responseCode = connection.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            response.setError(new HttpErrorException(responseCode));
        }

        return response;
    }

    private String streamToString(InputStream stream) throws IOException {

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;

        while ((length = stream.read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }

        return result.toString("UTF-8");
    }
}
