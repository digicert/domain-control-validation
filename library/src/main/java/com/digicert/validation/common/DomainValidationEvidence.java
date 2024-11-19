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
    /**
     * The domain being validated.
     * This field holds the domain name that is being validated.
     */
    private final String domain;

    /**
     * The method used for domain control validation, including getter for BR\_VERSION.
     */
    private final DcvMethod dcvMethod;

    /**
     * Including the BR version number in the evidence is important for auditing purposes.
     * As specified in section 3.2.2.4 of the BRs:
     *      CAs SHALL maintain a record of which domain validation method, including relevant BR version
     *      number, they used to validate every domain.
     */
    public static final String BR_VERSION = "v2.0.7";

    /**
     * The instant when the domain validation was completed.
     */
    private final Instant validationDate;

    /**
     * EMAIL: The email address used for validation.
     * Only populated when the DCV method is an email type otherwise NULL
     * (BR\_3\_2\_2\_4\_2 / BR\_3\_2\_2\_4\_4 / BR\_3\_2\_2\_4\_14)
     * This field contains the email address that was used to perform the domain validation.
     * It is only populated if the validation method involved sending an email to the domain
     * owner.
     */
    private final String emailAddress;

    /**
     * FILE AUTH: The URL of the file used for validation.
     * Only populated when the DCV method is FILE\_AUTH (BR\_3\_2\_2\_4\_18) otherwise NULL
     * This field holds the URL of the file that was used to validate the domain control.
     * It is only populated if the validation method involved placing a file on the web server.
     */
    private final String fileUrl;

    /**
     * DNS: The type of DNS record used for validation.
     * Only populated when the DCV method is DNS\_CHANGE (BR\_3\_2\_2\_4\_7) otherwise NULL
     * This field indicates the type of DNS record that was used to validate the domain control.
     */
    private final DnsType dnsType;

    /**
     * DNS: The DNS server used for validation.
     * Only populated when the DCV method is DNS\_CHANGE (BR\_3\_2\_2\_4\_7) otherwise NULL
     * This field contains the DNS server that was used to perform the domain validation.
     */
    private final String dnsServer;

    /**
     * DNS: The DNS record name used for validation.
     * Only populated when the DCV method is DNS\_CHANGE (BR\_3\_2\_2\_4\_7) otherwise NULL
     * This field holds the name of the DNS record that was used to validate the domain control.
     */
    private final String dnsRecordName;

    /**
     * TOKEN: The token found during validation.
     * Only populated when a token is used for validation otherwise NULL
     * Only populated when the DCV method is DNS\_CHANGE or FILE\_AUTH.
     * This field contains the token that was found during the domain validation process.
     */
    private final String foundToken;

    /**
     * RANDOM: The random value used for validation.
     * Populated when a random value is used for validation otherwise NULL
     * This field holds the random value that was used to validate the domain control.
     */
    private final String randomValue;

    /**
     * Constructs a new DomainValidationEvidence with the specified parameters.
     * This constructor is private to enforce the use of the builder pattern for creating
     * instances of DomainValidationEvidence. It initializes all fields with the provided
     * values, ensuring that the object is fully constructed with all necessary information.
     *
     * @param domain         The domain being validated.
     * @param dcvMethod      The dcv method used to complete domain validation.
     * @param validationDate The date when the validation was complete.
     * @param emailAddress   The email address used for validation, if an email dcv method was used
     * @param fileUrl        The URL of the file used for validation, if a file dcv method was used.
     * @param dnsType        The type of DNS record used for validation, if a dns dcv method was used.
     * @param dnsServer      The DNS server used for validation, if a dns dcv method was used.
     * @param dnsRecordName  The DNS record name used for validation, if a dns dcv method was used.
     * @param foundToken     The token found during validation, if applicable.
     * @param randomValue    The random value used for validation, if applicable.
     */
    private DomainValidationEvidence(String domain, DcvMethod dcvMethod, Instant validationDate, String emailAddress, String fileUrl, DnsType dnsType, String dnsServer, String dnsRecordName, String foundToken, String randomValue) {
        this.domain = domain;
        this.dcvMethod = dcvMethod;
        this.validationDate = validationDate;
        this.emailAddress = emailAddress;
        this.fileUrl = fileUrl;
        this.dnsType = dnsType;
        this.dnsServer = dnsServer;
        this.dnsRecordName = dnsRecordName;
        this.foundToken = foundToken;
        this.randomValue = randomValue;
    }
}