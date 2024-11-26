package com.digicert.validation.common;

import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.enums.DnsType;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.time.Instant;

/**
 * Represents the evidence of domain validation.
 * This class contains information about how the domain was validated,
 * including the method used, the date of validation, and various details
 * specific to the validation method. It is used to maintain a record of
 * domain validation activities for auditing and compliance purposes.
 */
@Getter
@Builder
@ToString
public class DomainValidationEvidence {

    /** The domain being validated. */
    private final String domain;

    /** The method used for domain control validation. */
    private final DcvMethod dcvMethod;

    /**
     * Including the BR version number in the evidence is important for auditing purposes.
     * As specified in section 3.2.2.4 of the BRs:
     * <pre>
     *      CAs SHALL maintain a record of which domain validation method, including relevant BR version
     *      number, they used to validate every domain.
     * </pre>
     */
    public static final String BR_VERSION = "v2.0.7";

    /** The instant when the domain validation was completed. */
    private final Instant validationDate;

    /**
     * EMAIL: The email address used for validation.
     * <p>
     * Only populated when the DCV method is an email type otherwise NULL
     * (BR_3_2_2_4_2 / BR_3_2_2_4_4 / BR_3_2_2_4_14)
     */
    private final String emailAddress;

    /**
     * FILE Validation: The URL of the file used for validation.
     * <p>
     * Only populated when the DCV method is FILE_VALIDATION (BR_3_2_2_4_18) otherwise NULL
     */
    private final String fileUrl;

    /**
     * DNS: The type of DNS record used for validation.
     * <p>
     * Only populated when the DCV method is DNS_CHANGE (BR_3_2_2_4_7) otherwise NULL
     */
    private final DnsType dnsType;

    /**
     * DNS: The DNS server used for validation.
     * <p>
     * Only populated when the DCV method is DNS_CHANGE (BR_3_2_2_4_7) otherwise NULL
     */
    private final String dnsServer;

    /**
     * DNS: The DNS record name used for validation.
     * <p>
     * Only populated when the DCV method is DNS_CHANGE (BR_3_2_2_4_7) otherwise NULL
     */
    private final String dnsRecordName;

    /**
     * TOKEN: The valid request token found during validation.
     * <p>
     * Only populated when using the REQUEST_TOKEN challenge type, which can only be used with the DNS_CHANGE and
     * FILE_VALIDATION DCV methods; otherwise NULL.
     */
    private final String requestToken;

    /**
     * RANDOM: The random value used for validation.
     * <p>
     * Populated when a random value is used for validation otherwise NULL
     */
    private final String randomValue;

    /**
     * Constructs a new DomainValidationEvidence with the specified parameters.
     * <p>
     * This constructor is private to enforce the use of the builder pattern for creating
     * instances of DomainValidationEvidence. It initializes all fields with the provided
     * values.
     *
     * @param domain         The domain being validated.
     * @param dcvMethod      The dcv method used to complete domain validation.
     * @param validationDate The date when the validation was complete.
     * @param emailAddress   The email address used for validation, if an email dcv method was used
     * @param fileUrl        The URL of the file used for validation, if a file dcv method was used.
     * @param dnsType        The type of DNS record used for validation, if a DNS dcv method was used.
     * @param dnsServer      The DNS server used for validation, if a DNS dcv method was used.
     * @param dnsRecordName  The DNS record name used for validation, if a DNS dcv method was used.
     * @param requestToken   The request token found during validation, if applicable.
     * @param randomValue    The random value used for validation, if applicable.
     */
    private DomainValidationEvidence(String domain, DcvMethod dcvMethod, Instant validationDate, String emailAddress, String fileUrl, DnsType dnsType, String dnsServer, String dnsRecordName, String requestToken, String randomValue) {
        this.domain = domain;
        this.dcvMethod = dcvMethod;
        this.validationDate = validationDate;
        this.emailAddress = emailAddress;
        this.fileUrl = fileUrl;
        this.dnsType = dnsType;
        this.dnsServer = dnsServer;
        this.dnsRecordName = dnsRecordName;
        this.requestToken = requestToken;
        this.randomValue = randomValue;
    }
}