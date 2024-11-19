package com.digicert.validation.secrets;

import com.digicert.validation.enums.DcvError;
import org.apache.commons.lang3.StringUtils;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A basic implementation of the {@link TokenValidator} interface.
 * This validator checks if a given token is present in the provided text body
 * and validates its timestamp and format.
 * <p>
 * The `BasicTokenValidator` class is designed to provide a straightforward
 * implementation of the `TokenValidator` interface. It ensures that tokens
 * are correctly formatted and that their timestamps are within an acceptable
 * range. This class is particularly useful in scenarios where token validation
 * is required for security purposes, such as validating digital certificates
 * or other secure tokens.
 */
public class BasicTokenValidator implements TokenValidator {

    /**
     * The format used for the timestamp in the token.
     * <p>
     * This constant defines the expected format for timestamps within tokens.
     * The format follows the pattern `yyyyMMddHHmmss`, which includes the year,
     * month, day, hour, minute, and second. This precise format ensures that
     * timestamps are consistently parsed and validated across different tokens.
     */
    private static final String TIMESTAMP_FORMAT = "yyyyMMddHHmmss";

    /**
     * The maximum number of days a timestamp can be in the future.
     * <p>
     * This constant sets a limit on how far into the future a token's timestamp
     * can be. By default, the maximum allowable future timestamp is 30 days.
     * This restriction helps prevent the use of tokens that are generated too
     * far in advance, enhancing the security and validity of the tokens.
     */
    private static final long MAX_TIMESTAMP_DAYS = 30;

    /**
     * A utility class for generating request tokens.
     * <p>
     * The `RequestTokenUtils` instance is used to generate tokens based on
     * specific keys, values, and timestamps. This utility class encapsulates
     * the logic for token generation, ensuring that tokens are created in a
     * consistent and secure manner. It is an essential component of the
     * `BasicTokenValidator` class.
     */
     final RequestTokenUtils requestTokenUtils = new RequestTokenUtils();

    /**
     * Default constructor for BasicTokenValidator.
     * <p>
     * The default constructor initializes a new instance of the `BasicTokenValidator`
     * class. This constructor does not take any parameters and sets up the
     * necessary components for token validation. It ensures that the validator
     * is ready to be used immediately after instantiation.
     */
    public BasicTokenValidator() {
        // Default constructor
    }

    /**
     * Validates the presence and correctness of the token in the text body.
     * <p>
     * This method performs the main validation logic for the token. It first
     * validates the input parameters using the `validateInput` method. If the
     * inputs are valid, it searches for potential token start locations in the
     * text body. For each potential token, it checks the timestamp format,
     * ensures the timestamp is not in the future, and verifies that the token
     * has not expired. If a valid token is found, it is returned in the
     * `TokenValidatorResponse`. Any validation errors encountered during the
     * process are also included in the response.
     *
     * @param hashingKey the key of the token
     * @param hashingValue the value of the token
     * @param textBody the text body in which to search for the token
     * @return a {@link ChallengeValidationResponse} containing the validation result
     */
    @Override
    public ChallengeValidationResponse validate(String hashingKey, String hashingValue, String textBody) {

        Set<DcvError> errors = validateInput(hashingKey, hashingValue, textBody);

        if (!errors.isEmpty()) {
            return new ChallengeValidationResponse(Optional.empty(), errors);
        }

        Set<Integer> indices = getValidTokenIndices(textBody);
        ZonedDateTime requestTimestamp;
        ZonedDateTime nowTimestamp = ZonedDateTime.now(ZoneOffset.UTC);
        Optional<String> locatedTokenOpt = Optional.empty();

        // Check all potential indices and compare tokens to see if they match
        for (Integer index : indices) {
            if (textBody.length() < index + 64) {
                errors.add(DcvError.TOKEN_ERROR_STRING_TOO_SHORT);
                continue;
            }

            String potentialToken = textBody.substring(index, index + 64);
            String requestTime = potentialToken.substring(0, 14);

            try {
                requestTimestamp = ZonedDateTime.ofLocal(LocalDateTime.parse(requestTime, DateTimeFormatter.ofPattern(TIMESTAMP_FORMAT)), ZoneOffset.UTC, null);
            } catch (DateTimeParseException exception) {
                errors.add(DcvError.TOKEN_ERROR_INVALID_DATE);
                continue;
            }

            // If the request timestamp is in the future, then return false
            if (requestTimestamp.isAfter(nowTimestamp)) {
                errors.add(DcvError.TOKEN_ERROR_FUTURE_DATE);
                continue;
            }

            // Check if the timestamp on the record is still valid (BR 1.5.8 defines the limit as 30 days)
            ZonedDateTime maxRequestTimestamp = requestTimestamp.plusDays(MAX_TIMESTAMP_DAYS);
            if (maxRequestTimestamp.isBefore(nowTimestamp)) {
                errors.add(DcvError.TOKEN_ERROR_DATE_EXPIRED);
                continue;
            }

            // Standard formatting - For DCVs, we use the timestamp as the salt
            Optional<String> generatedToken = requestTokenUtils.generateRequestToken(hashingKey, hashingValue, requestTime);
            if (generatedToken.isEmpty()) {
                errors.add(DcvError.TOKEN_CANNOT_GENERATE_HASH);
                continue;
            }

            if (generatedToken.get().equals(potentialToken)) {
                locatedTokenOpt = Optional.of(potentialToken);
                break;
            }
        }

        return new ChallengeValidationResponse(locatedTokenOpt, errors);
    }

    /**
     * Validates the input parameters for the token validation.
     * <p>
     * This method checks the provided input parameters to ensure they are valid
     * for token validation. It verifies that the token key, token value, and text
     * body are not empty or null. If any of these parameters are invalid, the method
     * returns a set of `DcvError` enumerations indicating the specific validation
     * errors. This preliminary validation step helps catch common input issues
     * before proceeding with more complex token validation logic.
     *
     * @param tokenKey the key of the token
     * @param tokenValue the value of the token
     * @param textBody the text body in which to search for the token
     * @return a set of {@link DcvError} containing any validation errors
     */
    Set<DcvError> validateInput(String tokenKey, String tokenValue, String textBody) {
        Set<DcvError> errors = new HashSet<>();
        if (StringUtils.isEmpty(tokenKey)) {
            errors.add(DcvError.TOKEN_KEY_REQUIRED);
        }

        if (StringUtils.isEmpty(tokenValue)) {
            errors.add(DcvError.TOKEN_VALUE_REQUIRED);
        }

        if (StringUtils.isEmpty(textBody)) {
            errors.add(DcvError.TOKEN_ERROR_EMPTY_TXT_BODY);
        }
        return errors;
    }

    /**
     * Finds all possible token start locations in the text body for the current or previous year.
     * <p>
     * This method searches the provided text body for potential token start locations.
     * It looks for patterns that match the current or previous year, as tokens are
     * expected to contain a timestamp. The method returns a set of integers representing
     * the start indices of these potential tokens. This helps narrow down the search
     * area for token validation, making the process more efficient.
     *
     * @param textBody the text body in which to search for token start locations
     * @return a set of integers representing the start indices of potential tokens
     */
    private Set<Integer> getValidTokenIndices(String textBody) {
        // find all possible token start locations in string (current or previous year)
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