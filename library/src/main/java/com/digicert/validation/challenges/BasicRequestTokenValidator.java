package com.digicert.validation.challenges;

import com.digicert.validation.enums.DcvError;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A basic implementation of the {@link RequestTokenValidator} interface. This
 * validator checks if a valid request token is present in the provided text body.
 * <p>
 * The `BasicTokenValidator` class is designed to validate the presence of request
 * tokens that follow DigiCert's request token format. For this validator to
 * consider request tokens valid, they must consist of a timestamp indicating when
 * the request token was created that uses the {@value #TIMESTAMP_FORMAT} format.
 * The timestamp is followed by a base 36 encoded hash of the CSR. The hash uses
 * the timestamp as a salt and a hashing key that was previously given to the
 * customer. The hash is also padded with prepended '0' characters to result in
 * a final request token length of 64 characters.
 */
@Slf4j
public class BasicRequestTokenValidator implements RequestTokenValidator {

    /** The format used for the creation timestamp in the request token. */
    private static final String TIMESTAMP_FORMAT = "yyyyMMddHHmmss";

    /**
     * The maximum number of days a timestamp can be valid for.
     * <p>
     * The Baseline Requirements specifies "A Request Token that includes a
     * timestamp SHALL remain valid for no more than 30 days from the time of
     * creation."
     */
    private static final long MAX_TIMESTAMP_DAYS = 30;

    /** A utility class for generating request tokens. */
    private final RequestTokenUtils requestTokenUtils = new RequestTokenUtils();

    /** The constructor for a BasicTokenValidator. It does not need any parameters. */
    public BasicRequestTokenValidator() {
        // Default constructor
    }

    /**
     * Attempts to find a valid request token using the given basic request token data and text body.
     * <p>
     * This method takes in a basic request token data and text body to perform the validation process. The text body
     * comes from either a DNS record or a http request, and the basic request token data contains the hashing key and
     * value necessary to generate request tokens.
     * <p>
     * This validator will find all timestamps in the text body that match the {@value #TIMESTAMP_FORMAT} format, and
     * check if they are the start of a valid request token. If a valid token is found, it is returned in the
     * `ChallengeValidationResponse`. Any validation errors encountered during the process are also included in the
     * response.
     *
     * @param requestTokenData a {@link BasicRequestTokenData} object containing the hashing key and value
     * @param textBody the text body in which to search for the token
     * @return a {@link ChallengeValidationResponse} containing the validation result
     */
    @Override
    public ChallengeValidationResponse validate(RequestTokenData requestTokenData, String textBody) {
        Set<DcvError> errors = validateInput(requestTokenData, textBody);
        if (!errors.isEmpty()) {
            return new ChallengeValidationResponse(Optional.empty(), errors);
        }

        BasicRequestTokenData basicRequestTokenData = (BasicRequestTokenData) requestTokenData;
        String hashingKey = basicRequestTokenData.hashingKey();
        String hashingValue = basicRequestTokenData.hashingValue();

        Set<Integer> indices = getPotentialRequestTokenIndices(textBody);
        if (indices.isEmpty()) {
            errors.add(DcvError.REQUEST_TOKEN_ERROR_NOT_FOUND);
            return new ChallengeValidationResponse(Optional.empty(), errors);
        }

        ZonedDateTime requestTimestamp;
        ZonedDateTime nowTimestamp = ZonedDateTime.now(ZoneOffset.UTC);
        Optional<String> locatedRequestTokenOpt = Optional.empty();

        // Check all potential indices and compare tokens to see if they match
        for (Integer index : indices) {
            if (textBody.length() < index + 64) {
                errors.add(DcvError.REQUEST_TOKEN_ERROR_INVALID_TOKEN);
                continue;
            }

            String potentialToken = textBody.substring(index, index + 64);
            String requestTime = potentialToken.substring(0, 14);

            try {
                requestTimestamp = ZonedDateTime.ofLocal(LocalDateTime.parse(requestTime, DateTimeFormatter.ofPattern(TIMESTAMP_FORMAT)), ZoneOffset.UTC, null);
            } catch (DateTimeParseException exception) {
                errors.add(DcvError.REQUEST_TOKEN_ERROR_INVALID_TOKEN);
                continue;
            }

            // If the request timestamp is in the future, then return false
            if (requestTimestamp.isAfter(nowTimestamp)) {
                errors.add(DcvError.REQUEST_TOKEN_ERROR_FUTURE_DATE);
                continue;
            }

            // Check if the timestamp on the record is still valid (BR 1.5.8 defines the limit as 30 days)
            ZonedDateTime maxRequestTimestamp = requestTimestamp.plusDays(MAX_TIMESTAMP_DAYS);
            if (maxRequestTimestamp.isBefore(nowTimestamp)) {
                errors.add(DcvError.REQUEST_TOKEN_ERROR_DATE_EXPIRED);
                continue;
            }

            // Generate what the token for the given timestamp should be
            Optional<String> generatedToken = requestTokenUtils.generateRequestToken(hashingKey, hashingValue, requestTime);
            if (generatedToken.isEmpty()) {
                errors.add(DcvError.REQUEST_TOKEN_CANNOT_GENERATE_HASH);
                continue;
            }

            if (generatedToken.get().equals(potentialToken)) {
                locatedRequestTokenOpt = Optional.of(potentialToken);
                break;
            }
        }

        return new ChallengeValidationResponse(locatedRequestTokenOpt, errors);
    }

    /**
     * Validates the input parameters for request token validation.
     * <p>
     * This validator requires a hashing key and value given via a BasicRequestTokenData object,
     * and the text body from a DNS record or http request. If any of these are null or empty,
     * validation errors are added to the error set this method returns.
     *
     * @param requestTokenData the data necessary to validate request tokens
     * @param textBody the text body in which to search for the token
     * @return a set of {@link DcvError} containing any input validation errors
     */
    private Set<DcvError> validateInput(RequestTokenData requestTokenData, String textBody) {
        Set<DcvError> errors = EnumSet.noneOf(DcvError.class);
        if (requestTokenData == null) {
            errors.add(DcvError.REQUEST_TOKEN_DATA_REQUIRED);
        }
        if (!(requestTokenData instanceof BasicRequestTokenData basicRequestTokenData)) {
            errors.add(DcvError.INVALID_REQUEST_TOKEN_DATA);
        } else {
            if (StringUtils.isEmpty(basicRequestTokenData.hashingKey()) || StringUtils.isEmpty(basicRequestTokenData.hashingValue())) {
                errors.add(DcvError.INVALID_REQUEST_TOKEN_DATA);
            }
        }

        if (StringUtils.isEmpty(textBody)) {
            errors.add(DcvError.REQUEST_TOKEN_EMPTY_TEXT_BODY);
        }
        return errors;
    }

    /**
     * Finds all possible valid request token start locations in the text body.
     * <p>
     * This method searches the provided text body for potential request token start locations. It looks for patterns
     * that match the current or previous year, as tokens are expected to contain a timestamp and can be at most 30 days
     * old. The method returns a set of integers representing the start indices of these potential tokens. This helps
     * narrow down the search area for request token validation, making the process more efficient.
     *
     * @param textBody the text body in which to search for request token start locations
     * @return a set of integers representing the start indices of potential request tokens
     */
    private Set<Integer> getPotentialRequestTokenIndices(String textBody) {
        // find all possible request token start locations in string (current or previous year)
        Set<Integer> indices = new HashSet<>();
        List.of(ZonedDateTime.now().getYear(), ZonedDateTime.now().minusYears(1).getYear())
                .forEach(year -> {
                    Pattern pattern = Pattern.compile(String.valueOf(year));
                    Matcher matcher = pattern.matcher(textBody);
                    while (matcher.find()) {
                        indices.add(matcher.start());
                    }
                });
        return indices;
    }
}