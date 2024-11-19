package com.digicert.validation.methods.dns.validate;

import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.ChallengeType;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

/**
 * Represents a DNS validation request.
 * <p>
 * This class is used to create a request for validating a domain using DNS.
 * It encapsulates all the necessary information required to perform DNS validation,
 * including the domain name, the type of DNS record, the type of secret used for validation,
 * and the current state of the validation process. This class is immutable and uses the
 * builder pattern to ensure that all required fields are provided during instantiation.
 */
@Getter
@Builder
@ToString
public class DnsValidationRequest {

    /** The domain to be validated. */
    private final String domain;

    /** The type of DNS record to be used for validation. */
    private final DnsType dnsType;

    /** The type of secret to be used for validation. */
    private final ChallengeType challengeType;

    /** A random value used for validation. Only used for RANDOM_VALUE secret type. */
    private final String randomValue;

    /** The token key used for validation. Only used for REQUEST_TOKEN secret type. */
    private final String tokenKey;

    /** The token value used for validation. Only used for REQUEST_TOKEN secret type. */
    private final String tokenValue;

    /**
     * The current validation state.
     * <p>
     * This field represents the current state of the validation process.
     */
    private final ValidationState validationState;

    /**
     * Private constructor to prevent instantiation without using the builder.
     *
     * @param domain          The domain to be validated.
     * @param dnsType         The type of DNS record to be used for validation.
     * @param challengeType      The type of secret to be used for validation.
     * @param randomValue     A random value used for validation.
     * @param tokenKey        The token key used for validation.
     * @param tokenValue      The token value used for validation.
     * @param validationState The current validation state.
     */
    private DnsValidationRequest(String domain, DnsType dnsType, ChallengeType challengeType, String randomValue, String tokenKey, String tokenValue, ValidationState validationState) {
        // Default constructor
        this.domain = domain;
        this.dnsType = dnsType;
        this.challengeType = challengeType;
        this.randomValue = randomValue;
        this.tokenKey = tokenKey;
        this.tokenValue = tokenValue;
        this.validationState = validationState;
    }
}