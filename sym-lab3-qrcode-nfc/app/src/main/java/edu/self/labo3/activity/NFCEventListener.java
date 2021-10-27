package edu.self.labo3.activity;

import java.util.EventListener;

/**
 * PROJECT     : LABORATOIRE 3
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 1/12/19
 * VERSION     : 1
 * DESCRIPTION : This is just an interface to set a certain callback when we
 * read a NFC tag.
 */
public interface NFCEventListener extends EventListener {
    void handleTAG(String tag);
}
