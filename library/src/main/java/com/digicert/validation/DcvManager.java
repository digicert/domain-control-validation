package com.digicert.validation;

import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.methods.dns.DnsValidator;
import com.digicert.validation.methods.email.EmailValidator;
import com.digicert.validation.methods.file.FileValidator;
import lombok.Getter;

/**
 * DcvManager is responsible for managing the Domain Control Validation (DCV) process.
 * It initializes and holds references to various validators such as DNS, Email, and File Authentication validators,
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
     * This validator assists with email-based domain control validation. It is able to perform whois and DNS lookups
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
     * The File Authentication validator used for DCV.
     * <p>
     * This validator is responsible for performing file-based domain control validation. It checks for the presence
     * of a request token or random value in a file to verify FQDN ownership. File authentication cannot be used for
     * wildcard domain names.
     * <p>
     * Handles 3.2.2.4.18 Agreed-Upon Change to Website v2
     */
    private final FileValidator fileValidator;

    /**
     * The DNS client used for DNS queries. Exposed to allow for use outside the library.
     */
    private final DnsClient dnsClient;

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
        this.dnsClient = dcvContext.get(DnsClient.class);
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