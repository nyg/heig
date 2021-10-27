package com.example.sym_labo2.model.serialization;

import com.example.sym_labo2.R;

public enum SerializationMethod {

    JSON(R.id.radio_method_json_3),
    XML(R.id.radio_method_xml_3);

    public final int id;

    SerializationMethod(int id) {
        this.id = id;
    }

    public static SerializationMethod withId(int id) {

        for (SerializationMethod method : values()) {
            if (id == method.id) {
                return method;
            }
        }

        throw new IllegalArgumentException("Unknown serialization method.");
    }
}
