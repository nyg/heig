package com.example.sym_labo2.model.communication;

import java.net.URL;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

@Builder
@Getter
@Setter
@EqualsAndHashCode
@ToString
public class Request {

    private String body;
    private String mimeType;
    private URL endpoint;

    @Accessors(fluent = true)
    private boolean shouldCompress;
}
