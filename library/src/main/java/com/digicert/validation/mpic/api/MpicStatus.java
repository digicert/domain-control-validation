package com.digicert.validation.mpic.api;

/**
 * Enum representing whether the final MPIC corroboration status
 * <p>
 * CORROBORATED: The MPIC corroboration was successful.
 * NON_CORROBORATED: The MPIC corroboration was not successful.
 * ERROR: An error occurred during the MPIC corroboration process.
 */
public enum MpicStatus {
    CORROBORATED,
    NON_CORROBORATED,
    VALUE_NOT_FOUND,
    PRIMARY_AGENT_FAILURE,
    DNSSEC_FAILURE,
    ERROR
}
