package com.digicert.validation.challenges;

/**
 * Interface for validating random values.
 * <p>
 * The RandomValueValidator interface defines the contract for implementing classes that are responsible for validating
 * a given text body against a random value.
 */
public interface RandomValueValidator {

    /**
     * Validates the provided text body against the given random value.
     * <p>
     * This method takes a random value and a text body as input parameters and performs validation to determine if the
     * random value is found within the provided text body.
     *
     * @param randomValue the random value to validate against
     * @param textBody the text body to check for the presence of the random value
     * @return a {@link ChallengeValidationResponse} containing the validation result
     */
    ChallengeValidationResponse validate(String randomValue, String textBody);
}