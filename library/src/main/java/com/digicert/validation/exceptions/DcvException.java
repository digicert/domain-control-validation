package com.digicert.validation.exceptions;

import com.digicert.validation.enums.DcvError;
import lombok.Getter;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Base Exception class for DCV (Domain Control Validation) related exceptions.
 * <p>
 * This class serves as the foundational exception for all errors related to Domain Control Validation (DCV).
 * It encapsulates a set of DCV errors, providing a structured way to handle and report issues encountered
 * during the DCV process.
 */
@Getter
public class DcvException extends Exception {

    /**
     * The set of DCV errors.
     * <p>
     * This field holds a set of `DcvError` enums that represent the specific errors encountered during
     * the DCV process.
     */
    private final Set<DcvError> errors;

    /**
     * Constructs a new DcvException with the specified DcvError.
     *
     * @param dcvError the DCV error that caused the exception to be thrown
     */
    public DcvException(DcvError dcvError) {
        this(Set.of(dcvError));
    }

    /**
     * Constructs a new DcvException with a set of specified DcvErrors.
     *
     * @param errors the set of DCV errors that caused the exception to be thrown
     */
    public DcvException(Set<DcvError> errors) {
        this(errors, null);
    }

    /**
     * Constructs a new DcvException with a set of specified DcvErrors and an optional cause.
     *
     * @param dcvErrors the set of DCV errors that caused the exception to be thrown
     * @param cause  the cause of the exception
     */
    public DcvException(Set<DcvError> dcvErrors, Throwable cause) {
        super("DcvException with errors = " + dcvErrors.stream().map(DcvError::toString).collect(Collectors.joining(",")), cause);
        this.errors = dcvErrors;
    }
}