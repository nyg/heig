package ch.heigvd.iict.sym_labo4.service;

import java.util.UUID;

import static ch.heigvd.iict.sym_labo4.service.CharacteristicProperty.NOTIFY;
import static ch.heigvd.iict.sym_labo4.service.CharacteristicProperty.READ;
import static ch.heigvd.iict.sym_labo4.service.CharacteristicProperty.WRITE;

/**
 * PROJECT     : LABORATOIRE 4
 * AUTHORS     : Mickael Bonjour, Nikolaos Garanis, Samuel Mettler
 * DATE        : 08/01/2020
 * VERSION     : 1
 * DESCRIPTION : Enum to store characteristics and their wanted properties.
 */
public enum Characteristic {

    TIME("Time", READ | WRITE | NOTIFY, "00002a2b-0000-1000-8000-00805f9b34fb"),
    INTEGER("Integer", WRITE, "3c0a1001-281d-4b48-b2a7-f15579a1c38f"),
    TEMPERATURE("Temperature", READ, "3c0a1002-281d-4b48-b2a7-f15579a1c38f"),
    BUTTON_CLICK_COUNT("Button Click Count", NOTIFY, "3c0a1003-281d-4b48-b2a7-f15579a1c38f");

    public final String name;
    public final int properties;
    public final UUID uuid;

    Characteristic(String name, int properties, String uuid) {
        this.name = name;
        this.properties = properties;
        this.uuid = UUID.fromString(uuid);
    }
}
