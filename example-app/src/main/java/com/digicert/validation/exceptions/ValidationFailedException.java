package com.digicert.validation.exceptions;

import org.springframework.http.HttpStatus;

public class ValidationFailedException extends DcvBaseException {

    public ValidationFailedException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}
