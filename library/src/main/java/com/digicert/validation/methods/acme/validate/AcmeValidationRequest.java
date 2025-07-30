package com.digicert.validation.methods.acme.validate;

import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.AcmeType;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

/**
 * Represents an ACME validation request.
 * <p>
 * This class is used to create a request for validating a domain using the ACME protocol.
 * All necessary information for the validation is encapsulated in this class:
 *  * domain name,
 *  * acme type
 *  * acme thumbprint
 *  * random value
 *  * validation state.
 *  This class is immutable and uses the builder pattern.
 */
@Getter
@Builder
@ToString
public class AcmeValidationRequest {

    /** The domain to be validated. */
    private final String domain;

    /** The type of ACME protocol to be used for validation. */
    private final AcmeType acmeType;

    /** The acme thumbprint used for validation. */
    private final String acmeThumbprint;

    /** A random value used for validation. */
    private final String randomValue;

    /** The current state of the validation process. */
    private final ValidationState validationState;

    /**
     * Private constructor to prevent instantiation without using the builder.
     *
     * @param domain The domain to be validated.
     * @param acmeType The type of ACME protocol to be used for validation.
     * @param acmeThumbprint The ACME thumbprint used for validation.
     * @param randomValue A random value used for validation.
     * @param validationState The current validation state.
     */
    private AcmeValidationRequest(String domain,
                                  AcmeType acmeType,
                                  String acmeThumbprint,
                                  String randomValue,
                                  ValidationState validationState) {
        // Default constructor
        this.domain = domain;
        this.acmeType = acmeType;
        this.acmeThumbprint = acmeThumbprint;
        this.randomValue = randomValue;
        this.validationState = validationState;
    }
}