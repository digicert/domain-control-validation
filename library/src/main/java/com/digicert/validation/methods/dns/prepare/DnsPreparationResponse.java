package com.digicert.validation.methods.dns.prepare;

import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.ChallengeType;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.List;

/**
 * Represents the response for DNS preparation.
 * This class contains information about the domain, allowed FQDNs, DNS type, secret type, and validation state.
 * <p>
 * The `DnsPreparationResponse` class is designed to encapsulate all the necessary details required for DNS preparation.
 * It includes the domain for which the DNS entry is being prepared, a list of allowed fully qualified domain names (FQDNs),
 * the type of DNS entry, the type of secret used for DNS validation, a random value for certain secret types, and the validation state.
 * This class uses the builder pattern to ensure immutability and ease of object creation.
 */
@Getter
@Builder
@ToString
public class DnsPreparationResponse {
    /**
     * The domain for which the DNS entry is being prepared.
     * Wildcard domains are allowed.
     * <p>
     * This field specifies the domain name that is the target of the DNS preparation process. It supports wildcard domains,
     * allowing for flexible DNS configurations that can match multiple subdomains.
     */
    private final String domain;

    /**
     * List of allowed fully qualified domain names (FQDNs) where the DNS entry should be placed.
     * <p>
     * This field contains a list of FQDNs that are permitted locations for the DNS entry. Each FQDN in the list represents
     * a specific domain name where the DNS entry can be validly placed. This is also known as the Authorized Domain Name (ADN).
     */
    private final List<String> allowedFqdns;

    /**
     * The type of DNS entry.
     * <p>
     * This field indicates the type of DNS entry being prepared. The `DnsType` enum provides various options such as A, AAAA,
     * CNAME, etc., each representing a different type of DNS record. This allows the DNS preparation process to be tailored
     * to the specific requirements of the DNS entry type.
     */
    private final DnsType dnsType;

    /**
     * The type of secret used for DNS validation.
     * <p>
     * This field specifies the type of secret that will be used for DNS validation. The `ChallengeType` enum includes options
     * such as RANDOM_VALUE, STATIC_VALUE, etc., each defining a different method of secret management.
     */
    private final ChallengeType challengeType;

    /**
     * The random value to be placed in the DNS entry.
     * Only used for RANDOM_VALUE secret type otherwise NULL.
     * <p>
     * This field holds a random value that is used in the DNS entry when the secret type is `RANDOM_VALUE`. For other secret
     * types, this field will be null.
     */
    private final String randomValue;

    /**
     * The validation state of the DNS preparation.
     * <p>
     * This field represents the current validation state of the DNS preparation process. T
     */
    private final ValidationState validationState;

    /**
     * Private constructor to prevent instantiation without using the builder.
     * Constructs a new DnsPreparationResponse with the specified parameters.
     *
     * @param domain          The domain for which the DNS entry is being prepared.
     * @param allowedFqdns    List of allowed fully qualified domain names (FQDNs) where the DNS entry should be placed.
     * @param dnsType         The type of DNS entry.
     * @param challengeType      The type of secret used for DNS validation.
     * @param randomValue     The random value to be placed in the DNS entry.
     * @param validationState The validation state of the DNS preparation.
     */
    private DnsPreparationResponse(String domain, List<String> allowedFqdns, DnsType dnsType, ChallengeType challengeType, String randomValue, ValidationState validationState) {
        this.domain = domain;
        this.allowedFqdns = allowedFqdns;
        this.dnsType = dnsType;
        this.challengeType = challengeType;
        this.randomValue = randomValue;
        this.validationState = validationState;
    }
}