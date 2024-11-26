package com.digicert.validation.methods.file.validate;

import com.digicert.validation.challenges.RequestTokenData;
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
     * The domain for which the file validation is being requested.
     */
    private final String domain;

    /**
     * Optional: The filename to be used for file validation.
     */
    private final String filename;

    /**
     * The type of challenge used for file validation.
     */
    private final ChallengeType challengeType;

    /** The random value to be used for file validation. Only used for RANDOM_VALUE challenge type. */
    private final String randomValue;

    /** The request token data to be used for file validation. Only used for REQUEST_TOKEN challenge type. */
    private final RequestTokenData requestTokenData;

    /**
     * The validation state of the file validation request.
     */
    private final ValidationState validationState;

    /**
     * Private constructor to prevent instantiation without using the builder.
     * Constructs a new FileValidationRequest with the specified parameters.
     *
     * @param domain           The domain for which the file validation is being requested.
     * @param filename         The filename to check for.
     * @param challengeType    The type of challenge (random value or request token).
     * @param randomValue      The random value to be used for file validation.
     * @param requestTokenData The data necessary to validate request tokens.
     * @param validationState  The validation state of the file validation request.
     */
    private FileValidationRequest(String domain, String filename, ChallengeType challengeType, String randomValue, RequestTokenData requestTokenData, ValidationState validationState) {
        this.domain = domain;
        this.filename = filename;
        this.challengeType = challengeType;
        this.randomValue = randomValue;
        this.requestTokenData = requestTokenData;
        this.validationState = validationState;
    }
}