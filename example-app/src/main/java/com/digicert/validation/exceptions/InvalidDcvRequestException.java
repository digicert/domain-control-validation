package com.digicert.validation.exceptions;

import org.springframework.http.HttpStatus;

public class InvalidDcvRequestException extends DcvBaseException {

    public InvalidDcvRequestException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }

}
