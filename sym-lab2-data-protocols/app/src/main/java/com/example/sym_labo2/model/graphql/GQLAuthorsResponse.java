package com.example.sym_labo2.model.graphql;

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
public class GQLAuthorsResponse {

    private ListAuthors data;
}
