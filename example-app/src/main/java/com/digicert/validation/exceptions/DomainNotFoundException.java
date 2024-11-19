package com.digicert.validation.exceptions;

import org.springframework.http.HttpStatus;

public class DomainNotFoundException extends DcvBaseException {

    public DomainNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND);
    }
}
