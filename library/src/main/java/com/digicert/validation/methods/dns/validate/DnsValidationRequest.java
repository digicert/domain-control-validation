package com.digicert.validation.methods.dns.validate;

import com.digicert.validation.challenges.RequestTokenData;
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
 * including the domain name, the type of DNS record, the type of challenge used for validation,
 * and the current state of the validation process. This class is immutable and uses the
 * builder pattern.
 */
@Getter
@Builder
@ToString
public class DnsValidationRequest {

    /** The domain to be validated. */
    private final String domain;

    /** The type of DNS record to be used for validation. */
    private final DnsType dnsType;

    /** The type of challenge to be used for validation. */
    private final ChallengeType challengeType;

    /** A random value used for validation. Only used for RANDOM_VALUE challenge type. */
    private final String randomValue;

    /** The request token data to be used for file validation. Only used for REQUEST_TOKEN challenge type. */
    private final RequestTokenData requestTokenData;

    /** The current state of the validation process. */
    private final ValidationState validationState;

    /** An optional domain label for the DNS record. Must begin with an underscore (_) if provided. */
    private final String domainLabel;

    /**
     * Private constructor to prevent instantiation without using the builder.
     *
     * @param domain The domain to be validated.
     * @param dnsType The type of DNS record to be used for validation.
     * @param challengeType The type of challenge to be used for validation.
     * @param randomValue A random value used for validation.
     * @param requestTokenData The data necessary to validate request tokens.
     * @param validationState The current validation state.
     */
    private DnsValidationRequest(String domain,
                                 DnsType dnsType,
                                 ChallengeType challengeType,
                                 String randomValue,
                                 RequestTokenData requestTokenData,
                                 ValidationState validationState,
                                 String domainLabel) {
        // Default constructor
        this.domain = domain;
        this.dnsType = dnsType;
        this.challengeType = challengeType;
        this.randomValue = randomValue;
        this.requestTokenData = requestTokenData;
        this.validationState = validationState;
        this.domainLabel = domainLabel;
    }
}