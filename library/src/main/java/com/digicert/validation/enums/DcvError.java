package com.digicert.validation.enums;

import com.digicert.validation.challenges.RequestTokenData;
import com.digicert.validation.challenges.RequestTokenValidator;
import com.digicert.validation.utils.DomainNameUtils;

/**
 * Enumeration representing various errors that can occur during Domain Control Validation (DCV).
 * Each error type corresponds to a specific validation failure scenario, providing detailed information
 * about the nature of the error to facilitate debugging and resolution.
 */
public enum DcvError {
    /**
     * Error indicating that the DNS type is required.
     * This error occurs when the DNS type is not provided in the request, which is essential for
     * determining the type of DNS record to validate.
     */
    DNS_TYPE_REQUIRED,

    /**
     * Error indicating that the user requested DNS or FILE validation without providing a challenge type.
     * <p>
     * DNS and FILE validation methods can be performed using either a random value or a request token, so
     * the user must specify which type of challenge they are using.
     */
    CHALLENGE_TYPE_REQUIRED,

    /**
     * Error indicating that the user requested the use of either the DNS_TXT or FILE_VALIDATION dcv method with a
     * request token without providing the request token data necessary to identify valid request tokens.
     */
    REQUEST_TOKEN_DATA_REQUIRED,

    /**
     * Error indicating that the user requested the use of either the DNS_TXT or FILE_VALIDATION dcv method with a
     * request token without providing usable request token data necessary to identify valid request tokens.
     * <p>
     * This error can occur because request token data is of the wrong subtype of {@link RequestTokenData} for the
     * {@link RequestTokenValidator} being used, or because some of its data is missing or malformed.
     */
    INVALID_REQUEST_TOKEN_DATA,

    /**
     * Error indicating that the user requested the use of a dcv method with a random value without providing a random
     * value.
     */
    RANDOM_VALUE_REQUIRED,

    /**
     * Error indicating that the random value has insufficient entropy.
     * <p>
     * The baseline requirements require that random values must have at least 112 bits of entropy. This error occurs
     * when the library can determine that the provided random value does not meet that requirement. High entropy is
     * necessary to ensure the unpredictability of the value, which is crucial for security purposes.
     */
    RANDOM_VALUE_INSUFFICIENT_ENTROPY,

    /** Error indicating that the DNS type is not support by DCV method requested. */
    INVALID_DNS_TYPE,

    /**
     * Error indicating that the DCV method is invalid.
     * This error occurs when the DCV method provided in the validationState object does not
     * match the allowed DCV method.
     */
    INVALID_DCV_METHOD,

    /**
     * Error indicating that the domain is required.
     * This error occurs when the domain name is not provided in the request. The domain name is a
     * fundamental part of the validation process, as it specifies the domain to be validated. Without
     * it, the validation cannot proceed.
     */
    DOMAIN_REQUIRED,

    /**
     * Error indicating that the domain name pattern is incorrect.
     * This error occurs when the domain name does not match the expected pattern found in {@link DomainNameUtils}
     * The domain name must adhere to specific formatting rules to be considered valid. An incorrect pattern indicates
     * a malformed domain name.
     */
    DOMAIN_INVALID_INCORRECT_NAME_PATTERN,

    /**
     * Error indicating that the domain has a bad LDH label.
     * This error occurs when the domain name contains an invalid LDH (Letter-Digit-Hyphen) label.
     * The LDH label must follow specific rules to be valid. A bad LDH label means that the domain
     * name does not conform to these rules.
     */
    DOMAIN_INVALID_BAD_LDH_LABEL,

    /**
     * Error indicating that the domain name is a top-level domain.
     * This error occurs when the domain name is a top-level domain (TLD), which is not allowed in
     * this context. TLDs are not specific enough for validation purposes, and a more specific domain
     * name is required.
     */
    DOMAIN_INVALID_NAME_IS_TOP_LEVEL,

    /**
     * Error indicating that the domain name is too long.
     * This error occurs when the domain name exceeds the maximum allowed length. Domain names must
     * be within a certain length to be valid. (Maximum length: 255 characters)
     */
    DOMAIN_INVALID_TOO_LONG,

    /**
     * Error indicating that wildcard domains are not allowed.
     * This error occurs when a wildcard domain is provided on a file validation request,
     * which is not permitted in this context. Wildcard domains are used to represent multiple subdomains,
     * but they are not allowed for file validation purposes.
     */
    DOMAIN_INVALID_WILDCARD_NOT_ALLOWED,

    /**
     * Error indicating that the domain is not under a public suffix.
     * This error occurs when the domain is not part of a recognized public suffix. Public suffixes
     * are top-level domains under which domain names can be registered. A domain not under a public
     * suffix is considered invalid.
     */
    DOMAIN_INVALID_NOT_UNDER_PUBLIC_SUFFIX,

    /**
     * Error indicating that the file validation response is empty.
     * This error occurs when the response from the file validation process is empty. An empty
     * response means that the system did not receive the expected data, leading to a validation
     * failure.
     */
    FILE_VALIDATION_EMPTY_RESPONSE,

    /**
     * Error indicating a client error during file validation.
     * This error occurs when there is a client-side error during the file validation process.
     * Client errors can include issues such as network problems or incorrect request formatting,
     * which prevent the authentication from succeeding.
     */
    FILE_VALIDATION_CLIENT_ERROR,

    /**
     * Error indicating a server dcvError during file validation.
     * This dcvError occurs when there is a server-side dcvError during the file validation process.
     * Server errors can include issues such as internal server problems or misconfigurations,
     * which prevent the authentication from succeeding.
     */
    FILE_VALIDATION_SERVER_ERROR,

    /**
     * Error indicating that the file validation content is invalid.
     * This error occurs when the content of the file validation response is invalid. Invalid
     * content means that the data received does not match the expected format or values, leading
     * to a validation failure.
     */
    FILE_VALIDATION_INVALID_CONTENT,

    /** Error indicating that the request to retrieve the file was a bad request. */
    FILE_VALIDATION_BAD_REQUEST,

    /** Error indicating that the file validation request timed out. */
    FILE_VALIDATION_TIMEOUT,

    /** Error indicating that the file validation response was bad. */
    FILE_VALIDATION_BAD_RESPONSE,

    /** Error indicating that the file validation response was not found. */
    FILE_VALIDATION_NOT_FOUND,

    /**
     * Error indicating that the file validation status code is not as expected.
     * The status code indicates the result of the authentication request, and an unexpected code
     * suggests a problem with the response.
     */
    FILE_VALIDATION_INVALID_STATUS_CODE,

    /** Error indicating that no potential request token was found. */
    REQUEST_TOKEN_ERROR_NOT_FOUND,

    /**
     * Error indicating that a potential request token was found but is not valid.
     * <p>
     * This error occurs when the potential token does not follow the specification expected by the
     * {@link RequestTokenValidator} being used.
     */
    REQUEST_TOKEN_ERROR_INVALID_TOKEN,

    /**
     * Error indicating that the request token has expired.
     * <p>
     * The baseline requirements specify that "A Request Token that includes a timestamp SHALL remain valid for no more
     * than 30 days from the time of creation." If the timestamp is more than 30 days old (or a shorter age specified by
     * the CA), the request token has expired.
     */
    REQUEST_TOKEN_ERROR_DATE_EXPIRED,

    /**
     * Error indicating that the request token's date is in the future.
     * <p>
     * The baseline requirements specify that "A Request Token that includes a timestamp SHALL be treated as invalid if
     * its timestamp is in the future."
     */
    REQUEST_TOKEN_ERROR_FUTURE_DATE,

    /**
     * Error indicating that the text body that should contain a request token is instead empty.
     * <p>
     * The text body should contain the actual data to be validated. An empty text body can indicate a problem on the
     * customer's side that they need to address.
     */
    REQUEST_TOKEN_EMPTY_TEXT_BODY,

    /**
     * Error indicating that the hash for a request token cannot be generated.
     * <p>
     * The baseline requirements specify that request tokens "SHALL use a digital signature algorithm or a cryptographic
     * hash algorithm." A failure in hash generation means that the request token cannot be verified.
     */
    REQUEST_TOKEN_CANNOT_GENERATE_HASH,

    /**
     * Error indicating that the random value was not found.
     * <p>
     * Random values are used by the client to prove control of the domain they are submitting for
     * validation. A missing random value means that the validation has failed.
     */
    RANDOM_VALUE_NOT_FOUND,

    /**
     * Error indicating that the text body that should contain a random value is instead empty.
     * <p>
     * The text body should contain the expected random value. An empty text body can indicate a problem on the
     * customer's side that they need to address.
     */
    RANDOM_VALUE_EMPTY_TEXT_BODY,

    /**
     * Error indicating that the random value has expired.
     * This error occurs when the random value has passed its expiration date. Expired random values
     * are no longer valid and cannot be used for validation, leading to a validation failure.
     * Because the DCV library is stateless, this date is calculated based the validationState prepareTime
     * field provided as part of the validation request.
     */
    RANDOM_VALUE_EXPIRED,

    /**
     * Error indicating that the validation state is required.
     * The validation state contains information about the current status of the validation process.
     */
    VALIDATION_STATE_REQUIRED,

    /**
     * Error indicating that the validation state domain is required.
     * The domain is a crucial part of the validation state, as it specifies the domain being validated.
     */
    VALIDATION_STATE_DOMAIN_REQUIRED,

    /**
     * Error indicating that the validation state DCV method is required.
     * The DCV method defines the approach used for domain control validation. Without it, the
     * validation state is incomplete.
     */
    VALIDATION_STATE_DCV_METHOD_REQUIRED,

    /**
     * Error indicating that the validation state prepare time is required.
     * The prepare time indicates when the validation process was initiated. Without it, the system
     * cannot accurately track the validation timeline.
     */
    VALIDATION_STATE_PREPARE_TIME_REQUIRED,

    /**
     * Error indicating that the DNS lookup record was not found.
     * DNS lookup records are used to verify the domain's DNS configuration. A missing record
     * means that the system cannot perform the DNS validation.
     */
    DNS_LOOKUP_RECORD_NOT_FOUND,

    /**
     * Error indicating an unknown host exception during DNS lookup.
     * Unknown host exceptions indicate that the domain name could not be resolved to an IP address,
     * preventing the DNS validation from succeeding.
     */
    DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION,

    /** Error indicating that the DNS lookup domain was not found. */
    DNS_LOOKUP_DOMAIN_NOT_FOUND,

    /** Error indicating some kind of I/O exception during DNS lookup. */
    DNS_LOOKUP_IO_EXCEPTION,

    /** Error indicating that the DNS lookup timed out. */
    DNS_LOOKUP_TIMEOUT,

    /** Error indicating a bad request during DNS lookup. */
    DNS_LOOKUP_BAD_REQUEST,

    /**
     * Error indicating a text parse exception during DNS lookup.
     * Text parse exceptions indicate that the DNS response could not be parsed correctly, leading to a
     * validation failure.
     */
    DNS_LOOKUP_TEXT_PARSE_EXCEPTION,

    /**  Error indicating that the email address is invalid. */
    INVALID_EMAIL_ADDRESS,

    /** Error indicating that there was a corroboration error during the DNS Lookup */
    MPIC_CORROBORATION_ERROR,

    /** Error indicating that the MPIC response is invalid. */
    MPIC_INVALID_RESPONSE;



    /**
     * Returns the string representation of the error in lowercase.
     *
     * @return the lowercase name of the error
     */
    @Override
    public String toString() {
        return this.name().toLowerCase();
    }
}