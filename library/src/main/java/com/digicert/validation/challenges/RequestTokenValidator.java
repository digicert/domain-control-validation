package com.digicert.validation.challenges;

/**
 * Interface for validating request tokens.
 * <p>
 * This interface defines the contract for token validation within the application. Implementations of this interface
 * are responsible for providing the logic to validate tokens based on a given key, value, and text body.
 */
public interface RequestTokenValidator {

    /**
     * Validates the provided token using the given key, value, and text body.
     * <p>
     * This method takes in a token key, token value, and text body to perform the validation process. The key and value
     * are typically used to generate or verify a hash, while the text body may contain additional data required for
     * validation.
     *
     * @param tokenKey the key used for validation
     * @param tokenValue the value used for validation
     * @param textBody the text body used for validation
     * @return a `TokenValidatorResponse` indicating the result of the validation
     */
    ChallengeValidationResponse validate(String tokenKey, String tokenValue, String textBody);
}