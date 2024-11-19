package com.digicert.validation.secrets;

/**
 * Interface for validating random values.
 * <p>
 * The `RandomValueValidator` interface defines the contract for implementing classes that are responsible for validating
 * random values against a given text body.
 */
public interface RandomValueValidator {

    /**
     * Validates the given random value against the provided text body.
     * <p>
     * This method takes a random value and a text body as input parameters and performs validation to determine if the
     * random value is valid within the context of the provided text body.
     *
     * @param randomValue the random value to validate
     * @param textBody the text body to validate against
     * @return a `TokenValidatorResponse` containing the validation result
     */
    ChallengeValidationResponse validate(String randomValue, String textBody);
}