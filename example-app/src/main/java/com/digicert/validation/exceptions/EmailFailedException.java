package com.digicert.validation.exceptions;

import org.springframework.http.HttpStatus;

public class EmailFailedException extends DcvBaseException {
    public EmailFailedException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}