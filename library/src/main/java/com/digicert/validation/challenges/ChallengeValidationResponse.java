package com.digicert.validation.challenges;

import com.digicert.validation.enums.DcvError;

import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

/**
 * A record to hold the results of a response validator.
 * <p>
 * The `challengeValue` field is an `Optional` that holds the validated random value or request token if the validation
 * is successful and is empty if the validation fails. The `errors` field is a `Set` of {@link DcvError} that allows for
 * providing a comprehensive list of issues that occurred during validation.
 *
 * @param challengeValue an Optional containing the validated challenge value, or an empty Optional if validation fails
 * @param errors a Set of DcvError indicating the errors encountered during validation
 */
public record ChallengeValidationResponse(Optional<String> challengeValue,
                                          Set<DcvError> errors) {

    /**
     * A convenience method to merge two challenge validation responses.
     * <p>
     * If either response is successful, the challenge value from the first successful response is returned. If both
     * responses are not valid, the errors from both responses are combined.
     * @param other the second response to merge with this response
     * @return a new ChallengeValidationResponse containing the merged results
     */
    public ChallengeValidationResponse merge(ChallengeValidationResponse other) {
        if (challengeValue().isPresent()) return this;
        if (other.challengeValue().isPresent()) return other;
        if (errors == null && other.errors() == null) return this;
        if (errors == null) return other;
        if (other.errors() == null) return this;
        // Combine errors from both responses
        Set<DcvError> allErrors = EnumSet.copyOf(errors);
        allErrors.addAll(other.errors());
        return new ChallengeValidationResponse(challengeValue, allErrors);
    }
}