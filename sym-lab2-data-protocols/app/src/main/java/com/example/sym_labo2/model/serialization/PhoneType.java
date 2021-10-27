package com.example.sym_labo2.model.serialization;

import com.example.sym_labo2.R;

public enum PhoneType {

    HOME(R.id.radio_type_home_3),
    WORK(R.id.radio_type_work_3),
    MOBILE(R.id.radio_type_mobile_3);

    public final int id;

    PhoneType(int id) {
        this.id = id;
    }

    public static PhoneType withId(int id) {

        for (PhoneType phoneType : values()) {
            if (id == phoneType.id) {
                return phoneType;
            }
        }

        throw new IllegalArgumentException("Unknown phone type.");
    }
}
