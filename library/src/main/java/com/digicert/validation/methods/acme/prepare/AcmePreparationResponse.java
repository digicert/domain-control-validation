package com.digicert.validation.methods.acme.prepare;

import com.digicert.validation.common.ValidationState;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

/**
 * Represents the response for ACME preparation.
 * <p>
 * This class contains information about the domain, the random value and the validation state,
 * <p>
 * NOTE: The ValidationState object created includes a DCV Method. When the "prepare" method is called,
 *       the DCV Method is unknown and will be set to UNKNOWN
 */
@Getter
@Builder
@ToString
public class AcmePreparationResponse {
    /** The domain for which the validation process is being prepared. */
    private final String domain;

    /** The random value used for the validation process. */
    private final String randomValue;

    /** The current validation state of the validation process. */
    private final ValidationState validationState;

    /**
     * Private constructor to prevent instantiation without using the builder.
     * Constructs a new AcmePreparationResponse with the specified parameters.
     *
     * @param domain          The domain for which the validation process is being prepared.
     * @param randomValue     The random value used for the validation process.
     * @param validationState The current validation state of the validation process.
     */
    private AcmePreparationResponse(String domain,
                                    String randomValue,
                                    ValidationState validationState) {
        this.domain = domain;
        this.randomValue = randomValue;
        this.validationState = validationState;
    }
}