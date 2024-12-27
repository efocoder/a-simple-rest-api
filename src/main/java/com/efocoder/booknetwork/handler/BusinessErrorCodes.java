package com.efocoder.booknetwork.handler;

import lombok.Getter;
import org.springframework.http.HttpStatus;

public enum BusinessErrorCodes {
    NO_CODE(0, HttpStatus.NOT_IMPLEMENTED, "No code" ),
    INCORRECT_CURRENT_PASSWORD(300, HttpStatus.BAD_REQUEST, "Current password is incorrect"),
    ACCOUNT_LOCKED(302, HttpStatus.FORBIDDEN , "Account locked"),
    PASSWORD_DOES_NOT_MATCH(301, HttpStatus.BAD_REQUEST , "Passwords do not match"),
    ACCOUNT_DISABLED(303, HttpStatus.FORBIDDEN , "Account disabled"),
    INVALID_CREDENTIALS(304, HttpStatus.UNAUTHORIZED , "Invalid credentials"),
    ;
    @Getter
    private final int code;

    @Getter
    private final String description;

    @Getter
    private final HttpStatus httpStatus;


    BusinessErrorCodes(int code, HttpStatus httpStatus, String description) {
        this.code = code;
        this.description = description;
        this.httpStatus = httpStatus;
    }
}
