package com.digicert.validation.methods.fileauth.prepare;

import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.ChallengeType;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

/**
 * Represents the response for a file authentication preparation request.
 * <p>
 * This response contains the necessary information to proceed with the file authentication validation process.
 * It includes details such as the domain for which the authentication is being prepared, the type of challenge used,
 * the random value to be placed in the file, and the validation state of the preparation response.
 */
@Builder
@Getter
@ToString
public class FileAuthPreparationResponse {

    /**
     * The domain for which the file authentication is being prepared.
     */
    private final String domain;

    /**
     * The type of secret used for validation.
     */
    private final ChallengeType challengeType;

    /**
     * The random value to be placed in the file.
     */
    private final String randomValue;

    /**
     * The location of the file to be placed on the server.
     */
    private final String fileLocation;

    /**
     * The validation state of the preparation response.
     */
    private final ValidationState validationState;

    /**
     * Private constructor to prevent instantiation without using the builder.
     *
     * @param domain          The domain for which the file authentication is being prepared.
     * @param challengeType   The type of secret used for validation.
     * @param randomValue     The random value to be placed in the file.
     * @param fileLocation    The location of the file to be placed on the server.
     * @param validationState The validation state of the preparation response.
     */
    private FileAuthPreparationResponse(String domain, ChallengeType challengeType, String randomValue, String fileLocation, ValidationState validationState) {
        this.domain = domain;
        this.challengeType = challengeType;
        this.randomValue = randomValue;
        this.fileLocation = fileLocation;
        this.validationState = validationState;
    }
}