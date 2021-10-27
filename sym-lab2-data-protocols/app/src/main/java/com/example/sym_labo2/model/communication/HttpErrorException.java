package com.example.sym_labo2.model.communication;

import lombok.Getter;

public class HttpErrorException extends Exception {

    @Getter
    private int code;

    public HttpErrorException(int code) {
        this.code = code;
    }
}
