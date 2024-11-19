package com.digicert.validation.exceptions;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Base exception for all exceptions thrown by the example-app.
 */
@Getter
public class DcvBaseException extends Exception {

    /**
     * The HTTP status code associated with the exception.
     */
    private final HttpStatus httpStatusCode;

    public DcvBaseException(String message, HttpStatus httpStatusCode) {
        super(message);
        this.httpStatusCode = httpStatusCode;
    }
}
