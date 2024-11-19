package com.digicert.validation.exceptions;

import com.digicert.validation.enums.DcvError;

import java.util.Set;

/**
 * Exception thrown when there is an issue with the input supplied to the library.
 * <p>
 * The `InputException` class is a specialized exception that extends the `DcvException` class. It is used to signal
 * problems related to the input provided to the library. This exception is typically thrown when the input does not
 * meet the expected format, contains invalid values, or fails validation checks.
 */
public class InputException extends DcvException {

    /**
     * Constructs a new InputException `InputException` with a specific `DcvError` instance.
     *
     * @param dcvError the DCV error that caused the exception to be thrown
     */
    public InputException(DcvError dcvError) {
        this(dcvError, null);
    }

    /**
     * Constructs a new `InputException` with a specific `DcvError` instance and a cause.
     *
     * @param dcvError the DCV error that caused the exception to be thrown
     * @param cause    the cause of the exception
     */
    public InputException(DcvError dcvError, Throwable cause) {
        super(Set.of(dcvError), cause);
    }
}