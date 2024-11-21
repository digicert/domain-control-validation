package com.digicert.validation.exceptions;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.methods.file.FileValidator;
import lombok.Getter;
import lombok.ToString;

import java.util.Set;

/**
 * Exception thrown when Validation fails.
 * <p>
 * The `ValidationException` class is a custom exception that is thrown when a validation process fails.
 * It extends the `DcvException` class, inheriting its properties and methods. This exception is specifically
 * designed to handle validation errors that occur during the validation of DNS, email, or file authentication
 * methods.
 *
 * @see com.digicert.validation.methods.dns.DnsValidator
 * @see com.digicert.validation.methods.email.EmailValidator
 * @see FileValidator
 */
@Getter
@ToString
public class ValidationException extends DcvException {

    /**
     * Constructs a new ValidationException with the specified DcvError.
     *
     * @param dcvError the DCV error
     */
    public ValidationException(DcvError dcvError) {
        super(dcvError);
    }

    /**
     * Constructs a new ValidationException with a set of specified DcvErrors.
     *
     * @param errors the set of DCV errors
     */
    public ValidationException(Set<DcvError> errors) {
        super(errors);
    }
}