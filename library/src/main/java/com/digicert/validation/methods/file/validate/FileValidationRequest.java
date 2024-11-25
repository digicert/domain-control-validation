package com.digicert.validation.methods.file.validate;

import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.ChallengeType;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

/**
 * Represents a request for file-based authentication validation.
 * <p>
 * This class contains information about the domain, filename, challenge type, random value, token key, token value, and validation state.
 * It is used to encapsulate all the necessary details required to perform a file-based domain control validation (DCV) request.
 */
@Getter
@Builder
@ToString
public class FileValidationRequest {
    /**
     * The domain for which the file authentication is being requested.
     */
    private final String domain;

    /**
     * Optional: The filename to be used for file authentication.
     */
    private final String filename;

    /**
     * The type of challenge used for file authentication.
     */
    private final ChallengeType challengeType;

    /**
     * The random value to be used for file authentication.
     * Only used for RANDOM_VALUE secret type.
     */
    private final String randomValue;

    /**
     * The token key to be used for file authentication.
     * Only used for REQUEST_TOKEN secret type.
     */
    private final String tokenKey;

    /**
     * The token value to be used for file authentication.
     * Only used for REQUEST_TOKEN secret type.
     */
    private final String tokenValue;

    /**
     * The validation state of the file authentication request.
     */
    private final ValidationState validationState;

    /**
     * Private constructor to prevent instantiation without using the builder.
     * Constructs a new FileValidationRequest with the specified parameters.
     *
     * @param domain          The domain for which the file authentication is being requested.
     * @param filename        The filename to be used for file authentication.
     * @param challengeType      The type of secret used for file authentication.
     * @param randomValue     The random value to be used for file authentication.
     * @param tokenKey        The token key to be used for file authentication.
     * @param tokenValue      The token value to be used for file authentication.
     * @param validationState The validation state of the file authentication request.
     */
    private FileValidationRequest(String domain, String filename, ChallengeType challengeType, String randomValue, String tokenKey, String tokenValue, ValidationState validationState) {
        this.domain = domain;
        this.filename = filename;
        this.challengeType = challengeType;
        this.randomValue = randomValue;
        this.tokenKey = tokenKey;
        this.tokenValue = tokenValue;
        this.validationState = validationState;
    }
}