package com.digicert.validation.challenges;

import com.digicert.validation.enums.DcvError;
import org.apache.commons.lang3.StringUtils;

import java.util.Optional;
import java.util.Set;

/**
 * A basic implementation of the {@link RandomValueValidator} interface.
 * This validator checks if the supplied random value is present in the provided text body.
 * <p>
 * The BasicRandomValueValidator class provides a straightforward implementation of the RandomValueValidator interface.
 */
public class BasicRandomValueValidator implements RandomValueValidator {

    /** Default constructor for BasicRandomValueValidator. */
    public BasicRandomValueValidator() {
        // Default constructor
    }

    /**
     * Validates the presence of the random value in the text body.
     *
     * @param randomValue the random value
     * @param textBody the text body in which to search for the random value
     * @return a {@link ChallengeValidationResponse} containing the validation result
     */
    @Override
    public ChallengeValidationResponse validate(String randomValue, String textBody) {
        if (StringUtils.isEmpty(textBody)) {
            return new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.RANDOM_VALUE_EMPTY_TEXT_BODY));
        }

        if (!textBody.contains(randomValue)) {
            return new ChallengeValidationResponse(Optional.empty(), Set.of(DcvError.RANDOM_VALUE_NOT_FOUND));
        }

        return new ChallengeValidationResponse(Optional.of(randomValue), Set.of());
    }
}