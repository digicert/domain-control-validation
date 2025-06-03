package com.digicert.validation.methods.email.prepare;

import com.digicert.validation.enums.DcvMethod;
import lombok.Getter;

/**
 * Enum representing the possible sources of email addresses for DCV.
 * <p>
 * The EmailSource enum defines the various sources from which email addresses can be obtained for Domain Control Validation (DCV).
 * Each source corresponds to a specific method outlined in the Baseline Requirements (BR) for the issuance and management of publicly-trusted certificates.
 * These sources are critical in ensuring that the email addresses used for validation are legitimate and verifiable.
 *
 * @see DcvMethod
 */

@Getter
public enum EmailSource {

    /**
     * The email addresses are constructed from the domain name.
     * <p>
     * This source generates email addresses by combining common administrative prefixes with the domain name.
     * These constructed email addresses, such as "admin@domain.com" or "webmaster@domain.com", are used to ensure that the domain is properly configured.
     * This method is specified under BR 3.2.2.4.4 and helps in automating the validation process by providing a consistent set of email addresses.
     * </p>
     * BR 3.2.2.4.4
     */
    CONSTRUCTED(DcvMethod.BR_3_2_2_4_4), // 3.2.2.4.4

    /**
     * The email addresses are found in a DNS CAA record for the domain.
     * <p>
     * This source involves querying the DNS CAA records of the domain to find email addresses.
     * DNS CAA records can contain various types of information, including email addresses for domain validation.
     * This method is specified under BR 3.2.2.4.13 and provides a flexible way to verify domain ownership through DNS configurations.
     * </p>
     * BR 3.2.2.4.13
     */
    DNS_CAA(DcvMethod.BR_3_2_2_4_13),

    /**
     * The email addresses are found in a DNS TXT record for the domain.
     * <p>
     * This source involves querying the DNS TXT records of the domain to find email addresses.
     * DNS TXT records can contain various types of information, including email addresses for domain validation.
     * This method is specified under BR 3.2.2.4.14 and provides a flexible way to verify domain ownership through DNS configurations.
     * </p>
     * BR 3.2.2.4.14
     */
    DNS_TXT(DcvMethod.BR_3_2_2_4_14)     // 3.2.2.4.14
    ;

    /**
     * The {@link DcvMethod} associated with the email source.
     * <p>
     * Each email source is linked to a specific DCV method as defined in the Baseline Requirements.
     * The DcvMethod enum provides a standardized way to reference these methods, ensuring consistency and clarity in the validation process.
     * This association helps in identifying the exact method used for obtaining email addresses for DCV.
     */
    private final DcvMethod dcvMethod;

    /**
     * Constructor for EmailSource
     * <p>
     * Initializes the EmailSource enum with the corresponding {@link DcvMethod}.
     * This constructor ensures that each email source is properly linked to its respective DCV method, facilitating accurate and reliable domain validation.
     *
     * @param dcvMethod The {@link DcvMethod} associated with the email source.
     */
    EmailSource(DcvMethod dcvMethod) {
        this.dcvMethod = dcvMethod;
    }
}