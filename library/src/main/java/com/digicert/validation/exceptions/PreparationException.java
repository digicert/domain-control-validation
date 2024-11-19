package com.digicert.validation.exceptions;

import com.digicert.validation.enums.DcvError;
import lombok.ToString;

import java.util.Set;

/**
 * Exception thrown when there is an issue with the preparation of the validation.
 * <p>
 * This exception is specifically used to indicate problems that occur during the preparation phase of the validation process.
 * Issues in this phase can stem from various sources such as misconfigurations, missing data, or other pre-validation errors.
 */
@ToString
public class PreparationException extends DcvException {

    /**
     * Constructs a new PreparationException with a set of the specified DcvErrors.
     *
     * @param errors the set of DCV errors that caused the exception to be thrown.
     */
    public PreparationException(Set<DcvError> errors) {
        super(errors);
    }
}