package com.digicert.validation.common;

import com.digicert.validation.enums.DcvMethod;

import java.time.Instant;

/**
 * Represents the state of a domain control validation (DCV) process.
 * <p>
 * The ValidationState class is a simple data holder that encapsulates the state of a DCV process.
 *
 * @param domain      The domain being validated.
 * @param prepareTime The time when the preparation for DCV was done. This is sent back in the validate request to determine validity.
 * @param dcvMethod   The dcv method used for domain control validation.
 */
public record ValidationState(String domain, Instant prepareTime, DcvMethod dcvMethod) {
}