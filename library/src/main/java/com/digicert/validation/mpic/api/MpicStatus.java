package com.digicert.validation.mpic.api;

/**
 * Enum representing whether the final MPIC corroboration status
 * <p>
 * CORROBORATED: The MPIC corroboration was successful.
 * NON_CORROBORATED: The MPIC corroboration was not successful.
 * ERROR: An error occurred during the MPIC corroboration process.
 */
public enum MpicStatus {
    /** The MPIC corroboration was successful; the required number of secondary agents agreed with the primary. */
    CORROBORATED,
    /** The MPIC corroboration was not successful; insufficient secondary agents agreed with the primary. */
    NON_CORROBORATED,
    /** The challenge value was not found in the primary agent response. */
    VALUE_NOT_FOUND,
    /** The primary agent failed to complete the validation request. */
    PRIMARY_AGENT_FAILURE,
    /** A DNSSEC validation failure was detected during the MPIC process. */
    DNSSEC_FAILURE,
    /** An unexpected error occurred during the MPIC corroboration process. */
    ERROR
}
