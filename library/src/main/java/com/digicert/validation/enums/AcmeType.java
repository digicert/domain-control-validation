package com.digicert.validation.enums;

import lombok.Getter;

/**
 * Enum representing the ACME challenge types that can be requested.
 * <p>
 * This enum is used by the user when making a "validate" request to specify
 * which ACME challenge type should be used to validate a domain.
 */
@Getter
public enum AcmeType {
    /** Specifies the ACME DNS-01 type and the corresponding DcvMethod. */
    ACME_DNS_01("dns-01", DcvMethod.BR_3_2_2_4_7),

    /** Specifies the ACME HTTP-01 type and the corresponding DcvMethod. */
    ACME_HTTP_01("http-01", DcvMethod.BR_3_2_2_4_19);

    private final String acmeType;
    private final DcvMethod dcvMethod;

    AcmeType(String acmeType, DcvMethod dcvMethod) {
        this.acmeType = acmeType;
        this.dcvMethod = dcvMethod;
    }
}