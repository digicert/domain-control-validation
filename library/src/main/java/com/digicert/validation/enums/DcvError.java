package com.digicert.validation.enums;

import com.digicert.validation.utils.DomainNameUtils;
import lombok.Getter;

/**
 * Enumeration representing various errors that can occur during Domain Control Validation (DCV).
 * Each error type corresponds to a specific validation failure scenario, providing detailed information
 * about the nature of the error to facilitate debugging and resolution.
 */
@Getter
public enum DcvError {
    /**
     * Error indicating that the DNS type is required.
     * This error occurs when the DNS type is not provided in the request, which is essential for
     * determining the type of DNS record to validate.
     */
    DNS_TYPE_REQUIRED,

    /**
     * Error indicating that the secret type is required.
     * This error occurs when the secret type is missing in the request. The secret type is crucial
     * for the validation process as it defines the method of secret verification. This is specific
     * for the DNS and File Validation types.
     */
    SECRET_TYPE_REQUIRED,

    /**
     * Error indicating that the token key is required.
     * This error occurs when the token key is not provided in the request. The token key is a critical
     * component used to authenticate the request for token specific DCV methods (DNS_TXT_TOKEN, FILE_VALIDATION_TOKEN).
     */
    TOKEN_KEY_REQUIRED,

    /**
     * Error indicating that the token value is required.
     * This error occurs when the token key is not provided in the request. The token value is a critical
     * component used to authenticate the request for token specific DCV methods (DNS_TXT_TOKEN, FILE_VALIDATION_TOKEN).
     */
    TOKEN_VALUE_REQUIRED,

    /**
     * Error indicating that the random value is required.
     * This error occurs when the random value is not provided in the request for DCV methods that utilize a random value.
     * The random value is used by the client to prove control of the domain they are submitting for validation.
     */
    RANDOM_VALUE_REQUIRED,

    /**
     * Error indicating that the random value has insufficient entropy.
     * This error occurs when the provided random value does not meet the required entropy criteria.
     * High entropy is necessary to ensure the randomness and unpredictability of the value, which is
     * crucial for security purposes.
     */
    RANDOM_VALUE_INSUFFICIENT_ENTROPY,

    /**
     * Error indicating that the DNS type is invalid.
     * This error occurs when the provided DNS type is not support by DCV method requested.
     */
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
     * Error indicating that the file validation content is invalid.
     * This error occurs when the content of the file validation response is invalid. Invalid
     * content means that the data received does not match the expected format or values, leading
     * to a validation failure.
     */
    FILE_VALIDATION_INVALID_CONTENT,

    /**
     * Error indicating that the file validation status code is not as expected.
     * The status code indicates the result of the authentication request, and an unexpected code
     * suggests a problem with the response.
     */
    FILE_VALIDATION_INVALID_STATUS_CODE,

    /**
     * Error indicating that the token was not found.
     * Tokens are used to authenticate requests, and a missing token means that the system cannot
     * verify the request, leading to a validation failure.
     */
    TOKEN_ERROR_NOT_FOUND,

    /**
     * Error indicating that the token string is too short.
     * This error occurs when the provided token string is shorter than the required length. Tokens
     * must meet a minimum length to be considered valid.
     */
    TOKEN_ERROR_STRING_TOO_SHORT,

    /**
     * Error indicating that the token date is invalid.
     * This error occurs when the date associated with the token is not valid. The token date is used
     * to determine the validity period of the token. An invalid date means that the token cannot be
     * trusted.
     */
    TOKEN_ERROR_INVALID_DATE,

    /**
     * Error indicating that the token date has expired.
     * This error occurs when the token has passed its expiration date. Expired tokens are no longer
     * valid and cannot be used for authentication, leading to a validation failure.
     */
    TOKEN_ERROR_DATE_EXPIRED,

    /**
     * Error indicating that the token date is in the future.
     * This error occurs when the token date is set to a future date, which is not allowed. Tokens
     * must have a valid date within the current time frame.
     */
    TOKEN_ERROR_FUTURE_DATE,

    /**
     * Error indicating that the token TXT body is empty.
     * The TXT body contains the actual data to be validated. An empty TXT body means that the token
     * does not contain the necessary information for validation.
     */
    TOKEN_ERROR_EMPTY_TXT_BODY,

    /**
     * Error indicating that the token hash cannot be generated.
     * The token hash is used to ensure the integrity and authenticity of the token. A failure in hash
     * generation means that the token cannot be verified.
     */
    TOKEN_CANNOT_GENERATE_HASH,

    /**
     * Error indicating that the random value was not found.
     * Random values are used by the client to prove control of the domain they are submitting for
     * validation. A missing random value means that the validation cannot proceed.
     */
    RANDOM_VALUE_NOT_FOUND,

    /**
     * Error indicating that the random value TXT body is empty.
     * The TXT body contains the actual data to be validated. An empty TXT body means that there is no
     * available random value for validation.
     */
    RANDOM_VALUE_EMPTY_TXT_BODY,

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

    /**
     * Error indicating a text parse exception during DNS lookup.
     * Text parse exceptions indicate that the DNS response could not be parsed correctly, leading to a
     * validation failure.
     */
    DNS_LOOKUP_TEXT_PARSE_EXCEPTION,

    /**
     * Error indicating that the whois response is empty.
     * An empty response means that the system did not receive the expected data, leading to a
     * validation failure.
     */
    WHOIS_EMPTY_RESPONSE,

    /**
     * Error indicating that no emails were found in the whois response.
     * Email addresses are used to contact the domain owner for validation purposes. A lack of
     * email addresses means that the system cannot proceed with the validation.
     */
    WHOIS_NO_EMAILS_FOUND,

    /**
     * Error indicating a query error during whois lookup.
     * Query errors can include issues such as network problems or incorrect query formatting, which
     * prevent the whois lookup from succeeding.
     */
    WHOIS_QUERY_ERROR,

    /**  Error indicating that the email address is invalid. */
    INVALID_EMAIL_ADDRESS;

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