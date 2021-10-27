package com.example.sym_labo2.model.serialization;

import java.util.List;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Builder
@Getter
@Setter
@EqualsAndHashCode
@ToString
public class Person {

    private String firstname;
    private String middlename;
    private String name;
    private Gender gender;
    private List<Phone> phones;
}
