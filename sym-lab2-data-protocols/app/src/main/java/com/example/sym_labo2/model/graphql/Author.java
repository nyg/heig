package com.example.sym_labo2.model.graphql;

import androidx.annotation.NonNull;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

@Builder
@Getter
@Setter
@EqualsAndHashCode
public class Author {

    private String first_name;
    private String last_name;
    private int id;

    @NonNull
    @Override
    public String toString() {
        return first_name + " " + last_name;
    }
}
