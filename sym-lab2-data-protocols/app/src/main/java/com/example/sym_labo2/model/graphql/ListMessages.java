package com.example.sym_labo2.model.graphql;

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
public class ListMessages {

    private List<Message> allPostByAuthor;
}
