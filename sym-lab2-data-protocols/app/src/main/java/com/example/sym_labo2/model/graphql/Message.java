package com.example.sym_labo2.model.graphql;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

@Builder
@Getter
@Setter
@EqualsAndHashCode
public class Message {

    private int id;
    private String content;
    private String title;
}
