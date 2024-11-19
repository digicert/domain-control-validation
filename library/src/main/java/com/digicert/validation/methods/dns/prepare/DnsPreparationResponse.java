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
 * This class contains information about the domain, allowed FQDNs, DNS type, challenge type, and validation state.
 * <p>
 * The `DnsPreparationResponse` class is designed to encapsulate all the necessary details required for DNS preparation.
 * It includes the domain for which the DNS entry is being prepared, a list of allowed fully qualified domain names (FQDNs),
 * the type of DNS entry, the type of challenge used for DNS validation, a random value for certain challenge types, and
 * the validation state. This class uses the builder pattern to ensure immutability and ease of object creation.
 */
@Getter
@Builder
@ToString
public class DnsPreparationResponse {
    /** The domain for which the DNS validation process is being prepared. */
    private final String domain;

    /**
     * List of allowed fully qualified domain names (FQDNs) where the DNS entry can be placed.
     * <p>
     * The baseline requirements specify that "Once the FQDN has been validated using this method, the CA MAY also issue
     * Certificates for other FQDNs that end with all the Domain Labels of the validated FQDN." This allows for a
     * certificate to be issued for a.b.c.d.example.com if c.d.example.com is validated. This field contains the list of
     * FQDNs for which a certificate for the desired domain can be issued if validation is performed for any of these
     * FQDNs.
     */
    private final List<String> allowedFqdns;

    /**
     * The type of DNS entry in which the customer should place the challenge value.
     * <p>
     * BR Section 3.2.2.4.7 (DNS Change) allows for the challenge value to be placed in a CNAME, TXT or CAA record.
     */
    private final DnsType dnsType;

    /** The type of challenge to be used for DNS validation - either RANDOM_VALUE or REQUEST_TOKEN. */
    private final ChallengeType challengeType;

    /** The random value to be placed in the DNS entry. Only used for RANDOM_VALUE challenge type. */
    private final String randomValue;

    /** The current validation state of the DNS validation process. */
    private final ValidationState validationState;

    /**
     * Private constructor to prevent instantiation without using the builder.
     * Constructs a new DnsPreparationResponse with the specified parameters.
     *
     * @param domain          The domain for which the DNS entry is being prepared.
     * @param allowedFqdns    List of allowed fully qualified domain names (FQDNs) where the DNS entry should be placed.
     * @param dnsType         The type of DNS entry.
     * @param challengeType   The type of secret used for DNS validation.
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