package com.example.sym_labo2.model.serialization;

import com.example.sym_labo2.R;

public enum Gender {

    MALE(R.id.radio_gender_male_3),
    FEMALE(R.id.radio_gender_female_3);

    public final int id;

    Gender(int id) {
        this.id = id;
    }

    public static Gender withId(int id) {

        for (Gender gender : values()) {
            if (id == gender.id) {
                return gender;
            }
        }

        throw new IllegalArgumentException("Unknown gender.");
    }
}
