package com.digicert.validation.exceptions;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.methods.acme.validate.dnspersist.AcmeDnsPersistValidationRequest;
import lombok.Getter;

import java.util.Set;

/**
 * Thrown when ACME {@code acme-dns-persist-01} validation fails. Carries the request that failed, mirroring
 * {@link AcmeValidationException} for the ephemeral ACME methods.
 */
@Getter
public class AcmeDnsPersistValidationException extends ValidationException {
    private final AcmeDnsPersistValidationRequest acmeDnsPersistValidationRequest;

    /**
     * Constructs a new exception.
     *
     * @param errors the DCV errors describing the failure
     * @param acmeDnsPersistValidationRequest the request that failed validation
     */
    public AcmeDnsPersistValidationException(Set<DcvError> errors, AcmeDnsPersistValidationRequest acmeDnsPersistValidationRequest) {
        super(errors);
        this.acmeDnsPersistValidationRequest = acmeDnsPersistValidationRequest;
    }
}
