package com.example.sym_labo2.communication;

import com.example.sym_labo2.model.communication.Response;

import java.util.EventListener;

/**
 * Example of the interface definition of an event listener
 */
public interface CommunicationEventListener extends EventListener {

    void handleServerResponse(Response response);
}
