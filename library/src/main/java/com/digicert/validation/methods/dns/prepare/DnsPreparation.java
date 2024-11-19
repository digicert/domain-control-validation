package com.digicert.validation.methods.dns.prepare;

import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.ChallengeType;

/**
 * Represents the preparation details required for DNS validation.
 * This class is a record that holds the domain, DNS type, and challenge type.
 *
 * @param domain the domain to be validated
 * @param dnsType the type of DNS record
 * @param challengeType the type of challenge used for validation
 */
public record DnsPreparation(String domain, DnsType dnsType, ChallengeType challengeType) {
}