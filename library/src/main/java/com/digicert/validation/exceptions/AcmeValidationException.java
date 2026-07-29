package com.digicert.validation.exceptions;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.methods.acme.validate.AcmeValidationRequest;
import com.digicert.validation.mpic.api.dns.DnssecDetails;
import lombok.Getter;

import java.util.Set;

/**
 * Exception thrown when ACME-based domain control validation fails.
 * Carries the original {@link AcmeValidationRequest} that triggered the failure
 * and, optionally, DNSSEC validation details when the failure is DNSSEC-related.
 */
@Getter
public class AcmeValidationException extends ValidationException{
    /** The ACME validation request that triggered this exception. */
    private final AcmeValidationRequest acmeValidationRequest;

    /**
     * Constructs an {@code AcmeValidationException} with the specified error code and request.
     *
     * @param dcvError               the DCV error that caused this exception
     * @param acmeValidationRequest  the ACME validation request that failed
     */
    public AcmeValidationException(DcvError dcvError, AcmeValidationRequest acmeValidationRequest) {
        super(dcvError);
        this.acmeValidationRequest = acmeValidationRequest;
    }

    /**
     * Constructs an {@code AcmeValidationException} with the specified error code, request,
     * and DNSSEC details.
     *
     * @param dcvError               the DCV error that caused this exception
     * @param acmeValidationRequest  the ACME validation request that failed
     * @param dnssecDetails          the DNSSEC validation details associated with the failure
     */
    public AcmeValidationException(DcvError dcvError, AcmeValidationRequest acmeValidationRequest, DnssecDetails dnssecDetails) {
        super(Set.of(dcvError), dnssecDetails);
        this.acmeValidationRequest = acmeValidationRequest;
    }

}
