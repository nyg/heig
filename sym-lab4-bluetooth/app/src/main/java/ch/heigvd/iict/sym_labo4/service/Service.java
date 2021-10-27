package ch.heigvd.iict.sym_labo4.service;

import androidx.annotation.NonNull;

import java.util.UUID;

/**
 * PROJECT     : LABORATOIRE 4
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 08/01/2020
 * VERSION     : 1
 * DESCRIPTION : Enum to store the wanted services.
 */
public enum Service {

    SYM("Custom SYM", "3c0a1000-281d-4b48-b2a7-f15579a1c38f"),
    TIME("Time", "00001805-0000-1000-8000-00805f9b34fb");

    public final String name;
    public final UUID uuid;

    Service(String name, String uuid) {
        this.name = name;
        this.uuid = UUID.fromString(uuid);
    }

    @NonNull
    @Override
    public String toString() {
        return String.format("%s service: %s", name, uuid);
    }
}
