package com.digicert.validation.challenges;

/**
 * Interface for validating request tokens.
 * <p>
 * This interface defines the contract for request token validation within the application. Implementations of this
 * interface are responsible for providing the logic to validate request tokens based on the supplied request token
 * data and the discovered text body.
 */
public interface RequestTokenValidator {

    /**
     * Attempts to find a valid request token using the given request token data and text body.
     * <p>
     * This method takes in a request token data and text body to perform the validation process. The text body comes
     * from either a DNS record or a http request, and the request token data contains whatever data is necessary to
     * determine if the text body contains a valid token.
     *
     * @param requestTokenData the data necessary to determine if a valid request token is present
     * @param textBody the text body that may contain a request token
     * @return a {@link ChallengeValidationResponse} indicating the result of the validation
     */
    ChallengeValidationResponse validate(RequestTokenData requestTokenData, String textBody);
}