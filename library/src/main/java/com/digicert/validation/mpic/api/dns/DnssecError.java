package com.digicert.validation.mpic.api.dns;

/**
 * Enum representing the types of DNSSEC errors that can occur during validation.
 */
public enum DnssecError {
    /** DNSKEY record is missing at the zone */
    DNSKEY_MISSING,
    /** DNSSEC validation resulted in {@link DnssecStatus#BOGUS} */
    DNSSEC_BOGUS,
    /** NSEC or NSEC3 record is missing for denial of existence proof */
    NSEC_MISSING,
    /** RRSIG records are missing for the requested record type */
    RRSIGS_MISSING,
    /** Other unspecified DNSSEC error */
    OTHER
}
