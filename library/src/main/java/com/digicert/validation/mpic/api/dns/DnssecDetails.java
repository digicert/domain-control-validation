package com.digicert.validation.mpic.api.dns;

/**
 * Represents the details of DNSSEC validation for a DNS response.
 * This record encapsulates the DNSSEC validation status, any error that occurred,
 * and details about where and what the error was.
 */
public record DnssecDetails(
    DnssecStatus dnssecStatus,
    DnssecError dnssecError,
    String errorLocation,
    String errorDetails
) {
    /**
     * @throws IllegalArgumentException if dnssecStatus is null
     */
    public DnssecDetails {
        if (dnssecStatus == null) {
            throw new IllegalArgumentException("dnssecStatus must not be null");
        }
    }

    private static final DnssecDetails NOT_CHECKED = new DnssecDetails(DnssecStatus.NOT_CHECKED, null, null, null);

    /**
     * Returns a shared instance indicating that DNSSEC validation was not performed.
     */
    public static DnssecDetails notChecked() {
        return NOT_CHECKED;
    }
}
