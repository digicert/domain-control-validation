package com.digicert.validation.mpic.api.dns;

/**
 * Enum representing the DNSSEC validation status for a DNS response.
 */
public enum DnssecStatus {
    /** DNSSEC validation succeeded and the chain of trust has been verified. */
    SECURE,
    /** The zone is not signed with DNSSEC. */
    INSECURE,
    /** DNSSEC validation failed. */
    BOGUS,
    /** The validation result could not be determined. */
    INDETERMINATE,
    /** DNSSEC validation was not performed. */
    NOT_CHECKED
}
