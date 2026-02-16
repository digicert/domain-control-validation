package com.digicert.validation;

import java.util.List;

import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.client.file.FileClient;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.methods.acme.AcmeValidator;
import com.digicert.validation.methods.dns.DnsValidator;
import com.digicert.validation.methods.email.EmailValidator;
import com.digicert.validation.methods.file.FileValidator;
import lombok.Getter;

/**
 * DcvManager is responsible for managing the Domain Control Validation (DCV) process.
 * It initializes and holds references to various validators such as DNS, Email, and File Validation validators,
 * as well as the Dns Client.
 * <p>
 * The DcvManager class acts as a central point for coordinating the DCV process. It ensures that the appropriate
 * validation method is used based on the configuration and the type of validation required.
 */
@Getter
public class DcvManager {

    /**
     * The DNS validator used for DCV.
     * <p>
     * This validator is responsible for performing DNS-based domain control validation. It is able to check for the
     * presence of a request token or random value in a DNS TXT or DNS CNAME record.
     * <p>
     * Handles 3.2.2.4.7 DNS Change
     */
    private final DnsValidator dnsValidator;

    /**
     * The Email validator used for DCV.
     * <p>
     * This validator assists with email-based domain control validation. It is able to perform DNS lookups
     * to determine usable email addresses for a given domain. It is not able to send out emails.
     * <p>
     * Handles
     * <ul>
     * <li>3.2.2.4.2 Email, Fax, SMS, or Postal Mail to Domain Contact</li>
     * <li>3.2.2.4.4 Constructed Email to Domain Contact</li>
     * <li>3.2.2.4.14 Email to DNS TXT Contact</li>
     * </ul>
     */
    private final EmailValidator emailValidator;

    /**
     * The File Validation validator used for DCV.
     * <p>
     * This validator is responsible for performing file-based domain control validation. It checks for the presence
     * of a request token or random value in a file to verify FQDN ownership. File validation cannot be used for
     * wildcard domain names.
     * <p>
     * Handles 3.2.2.4.18 Agreed-Upon Change to Website v2
     */
    private final FileValidator fileValidator;

    /**
     * The ACME Validation validator used for DCV.
     * <p>
     * This validator is responsible for performing acme-based domain control validation. It checks for the presence
     * of a random value combined with an acmeThumbprint in a file or DNS record to verify domain ownership.
     * <p>
     * Handles 3.2.2.4.7 DNS Change
     * Handles 3.2.2.4.19 Agreed-Upon Change to Website v2
     */
    private final AcmeValidator acmeValidator;

    /**
     * The DNS client used for DNS queries. Exposed to allow for use outside the library.
     */
    private final DnsClient dnsClient;

    /**
     * The File Client used for file operations. Exposed to allow for use outside the library.
     */
    private final FileClient fileClient;

    /**
     * Private constructor to enforce the use of the Builder for object creation.
     *
     * @param dcvConfiguration the configuration for DCV
     */
    private DcvManager(DcvConfiguration dcvConfiguration) {
        DcvContext dcvContext = new DcvContext(dcvConfiguration);

        this.dnsValidator = dcvContext.get(DnsValidator.class);
        this.emailValidator = dcvContext.get(EmailValidator.class);
        this.fileValidator = dcvContext.get(FileValidator.class);
        this.acmeValidator = dcvContext.get(AcmeValidator.class);
        this.dnsClient = dcvContext.get(DnsClient.class);
        this.fileClient = dcvContext.get(FileClient.class);
    }

    /**
     * Returns the list of lookup locations (DNS names or file URLs) for the given domain and DCV method.
     * This can be used to determine where random values should be placed and validated.
     *
     * @param domain the domain to validate
     * @param dcvMethod the BR DCV method (e.g., BR_3_2_2_4_7, BR_3_2_2_4_18, BR_3_2_2_4_19)
     * @return list of lookup locations (e.g., DNS names, file URLs)
     */
    public List<String> getLookupLocations(String domain, DcvMethod dcvMethod) {
        return getLookupLocations(domain, dcvMethod, null);
    }

    /**
     * Returns the list of lookup locations (DNS names or file URLs) for the given domain and DCV method.
     * This can be used to determine where random values should be placed and validated.
     * For file validation methods, an optional filename can be specified.
     *
     * @param domain the domain to validate
     * @param dcvMethod the BR DCV method (e.g., BR_3_2_2_4_7, BR_3_2_2_4_18, BR_3_2_2_4_19)
     * @param filename the custom filename for file validation methods (ignored for non-file methods, null uses default)
     * @return list of lookup locations (e.g., DNS names, file URLs)
     */
    public List<String> getLookupLocations(String domain, DcvMethod dcvMethod, String filename) {
        switch (dcvMethod) {
            case BR_3_2_2_4_4: // Constructed Email to Domain Contact
            case BR_3_2_2_4_13: // Email to DNS CAA Contact  
            case BR_3_2_2_4_14: // Email to DNS TXT Contact
                return emailValidator.getEmailLookupLocations(domain, dcvMethod);
            case BR_3_2_2_4_7: // DNS Change
                return dnsValidator.getDnsLookupNames(domain);
            case BR_3_2_2_4_18: // File Validation
                return fileValidator.getFileLookupUrls(domain, filename);
            case BR_3_2_2_4_19: // ACME HTTP Validation
                return acmeValidator.getAcmeLookupUrls(domain);
            // Add other cases as needed
            default:
                throw new UnsupportedOperationException("Lookup locations not supported for method: " + dcvMethod);
        }
    }

    /** Builder class for constructing DcvManager instances. */
    public static class Builder {

        /** The DcvConfiguration for the DcvManager. */
        private DcvConfiguration dcvConfiguration;

        /** Default constructor for the Builder class. */
        public Builder() {
            // Default constructor
        }

        /**
         * Validates and sets the DcvConfiguration for the DcvManager.
         *
         * @param dcvConfiguration the configuration for DCV
         * @return the Builder instance
         */
        public Builder withDcvConfiguration(DcvConfiguration dcvConfiguration) {
            validateDcvConfiguration(dcvConfiguration);
            this.dcvConfiguration = dcvConfiguration;
            return this;
        }

        /**
         * Validates the provided DcvConfiguration.
         *
         * @param dcvConfiguration the configuration to validate
         * @throws IllegalArgumentException if the configuration is null or invalid
         */
        private void validateDcvConfiguration(DcvConfiguration dcvConfiguration) {
            if (dcvConfiguration == null) {
                throw new IllegalArgumentException("DcvConfiguration cannot be null");
            }
            if (dcvConfiguration.getDnsServers() == null || dcvConfiguration.getDnsServers().isEmpty()) {
                throw new IllegalArgumentException("DnsServers cannot be empty");
            }
        }

        /**
         * Builds and returns a DcvManager instance using the provided configuration.
         *
         * @return the constructed DcvManager instance
         */
        public DcvManager build() {
            return new DcvManager(dcvConfiguration);
        }
    }
}