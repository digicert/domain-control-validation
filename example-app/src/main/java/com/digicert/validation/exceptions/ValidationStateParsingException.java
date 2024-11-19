package com.digicert.validation.exceptions;

import org.springframework.http.HttpStatus;

public class ValidationStateParsingException extends DcvBaseException {

    public ValidationStateParsingException(String message) {
        super(message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
