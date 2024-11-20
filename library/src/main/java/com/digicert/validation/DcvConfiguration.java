package com.digicert.validation;

import com.digicert.validation.methods.email.prepare.provider.NoopWhoisEmailProvider;
import com.digicert.validation.methods.email.prepare.provider.WhoisEmailProvider;
import com.digicert.validation.psl.PslDataProvider;
import com.digicert.validation.random.BasicRandomValueGenerator;
import com.digicert.validation.random.RandomValueGenerator;
import com.digicert.validation.secrets.BasicRandomValueValidator;
import com.digicert.validation.secrets.BasicTokenValidator;
import com.digicert.validation.secrets.RandomValueValidator;
import com.digicert.validation.secrets.TokenValidator;
import com.digicert.validation.utils.NoopPslOverrideSupplier;
import com.digicert.validation.utils.DomainNameUtils;
import com.digicert.validation.utils.FilenameUtils;
import com.digicert.validation.utils.PslOverrideSupplier;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * Configuration class for Domain Control Validation (DCV).
 * <p>
 * This class contains the configuration settings necessary for performing Domain Control Validation (DCV).
 * These settings include parameters for DNS lookups, WhoIs queries, random value generation, and other aspects of the DCV process.
 */
@Setter(AccessLevel.PRIVATE)
@Getter
public class DcvConfiguration {

    /** The DNS timeout in milliseconds. */
    private int dnsTimeout = 2000;

    /** The number of times a DNS query will be retried before giving up. */
    private int dnsRetries = 3;

    /**
     * The list of DNS servers to use for DNS lookups. These are the IP Addresses that will be queried for DNS records.
     * <p>
     * Each server on the list can optionally include a port number, separated by a colon. For example, "10.1.2.3:53".
     * Each server beyond the first will only be queried if the previous server fails or does not return any records.
     */
    private List<String> dnsServers = List.of();

    /**
     * A NoopWhoisEmailProvider. This library does not provide a WhoisEmailProvider implementation.
     * <p>
     * See BasicWhoIsEmailProvider in the example-application for an example implementation.
     *
     */
    private WhoisEmailProvider whoisEmailProvider = new NoopWhoisEmailProvider();

    /**
     * The prefix domain label to use with DNS Change validation.
     * <p>
     * The baseline requirements for the 3.2.2.4.7 DNS Change method allows for the domain to be "prefixed with a
     * Domain Label that begins with an underscore character."
     */
    private String dnsDomainLabel = "_dnsauth.";

    /**
     * The validity period in days for random values generated during the DCV process.
     * <p>
     * The baseline requirements specify that random values cannot be valid after 30 days. For purposes of this
     * library, the default validity period is 29 days to safeguard against corner cases that could be encountered
     * when checking against the limit.
     */
    private int randomValueValidityPeriod = 29;

    /** The timeout in milliseconds for connecting to a server while performing file authentication. */
    private int fileAuthConnectTimeout = 2000;

    /** The timeout in milliseconds for reading data from a server while performing file authentication. */
    private int fileAuthReadTimeout = 5000;

    /** The maximum length of the body for file authentication responses. */
    private int fileAuthMaxBodyLength = 5000;

    /** The socket timeout in milliseconds for connecting to a server while performing file authentication. */
    private int fileAuthSocketTimeout = 2000;

    /** The maximum number of redirects allowed while performing file authentication. */
    private int fileAuthMaxRedirects = 5;

    /**
     * This flag indicates that the library will try both HTTP and HTTPS
     * when performing file authentication requests.
     */
    private Boolean fileAuthCheckHttps = false;

    /**
     * The default file authentication filename.
     * <p>
     * This value represents the default file name used for "Agreed-Upon Change to Website v2" validation.
     */
    private String fileAuthFilename = "fileauth.txt";

    /** The user agent to be used for file authentication requests. */
    private String fileAuthUserAgent = "DCV-Library/1.0";

    /**
     * The random value validator used to determine if a given response contains the random value.
     * <p>
     * The default implementation does a simple check for the random value being contained anywhere in
     * the response. It can be overridden if desired (for example, if all random values should contain
     * a CA-specific prefix).
     */
    private RandomValueValidator randomValueValidator = new BasicRandomValueValidator();

    /**
     * The token validator used to determine if a given response contains a valid token.
     * <p>
     * The default implementation handles DigiCert's request token format, which is a timestamp followed by
     * a hash of the hashing value using the hashing key as the key for the hash and the timestamp as a salt.
     * It can be overridden to handle a different request token format.
     */
    private TokenValidator tokenValidator = new BasicTokenValidator();

    /** The generator used to create random values for use in the DCV process. */
    private RandomValueGenerator randomValueGenerator = new BasicRandomValueGenerator();

    /**
     * The PSL override supplier.
     * <p>
     * This supplier provides Public Suffix List (PSL) overrides for handling special cases in domain validation.
     * <p>
     * This allows for supporting cases described in the BRs such as Wildcard Domain Validation (BR 3.2.2.6).
     * These are cases where the default PSL data may not be sufficient for accurate domain validation (such as when
     * governments that own a public suffix want to obtain a certificate at the level of the suffix).
     */
    private PslOverrideSupplier pslOverrideSupplier = new NoopPslOverrideSupplier();

    /** Private constructor to prevent instantiation. */
    private DcvConfiguration() {
        // Private constructor to prevent instantiation
    }

    /** Builder class for Domain Control Validation (DCV) configuration. */
    public static class DcvConfigurationBuilder {

        /** The DcvConfiguration instance to be built. */
        private final DcvConfiguration dcvConfiguration = new DcvConfiguration();

        /** Constructs a new DcvConfigurationBuilder. */
        public DcvConfigurationBuilder() {
            // Default constructor
        }

        /**
         * Set the DNS timeout (in milliseconds). Note that this is the timeout for each individual DNS query,
         * so the total time spent on DNS queries could be significantly longer due to retries and redirects.
         *
         * @param dnsTimeout the DNS timeout in milliseconds
         * @return the builder instance
         * @throws IllegalArgumentException if dnsTimeout is negative
         */
        public DcvConfigurationBuilder dnsTimeout(int dnsTimeout) {
            if (dnsTimeout < 0) {
                throw new IllegalArgumentException("dnsTimeout cannot be negative");
            }
            dcvConfiguration.setDnsTimeout(dnsTimeout);
            return this;
        }

        /**
         * Set the number of times to retry a DNS query before giving up.
         *
         * @param dnsRetries the number of DNS retries
         * @return the builder instance
         * @throws IllegalArgumentException if dnsRetries is negative
         */
        public DcvConfigurationBuilder dnsRetries(int dnsRetries) {
            if (dnsRetries < 0) {
                throw new IllegalArgumentException("dnsRetries cannot be negative");
            }
            dcvConfiguration.setDnsRetries(dnsRetries);
            return this;
        }

        /**
         * Set the list of DNS servers to use for DNS lookups. These are the IP Addresses that will be queried for DNS records.
         * <p>
         * Each server on the list can optionally include a port number, separated by a colon. For example, "10.1.2.3:53".
         * Each server beyond the first will only be queried if the previous server fails or does not return any records.
         *
         * @param dnsServers The list of DNS servers to use.
         * @return The builder instance.
         * @throws IllegalArgumentException if the dnsServers list is null or empty.
         */
        public DcvConfigurationBuilder dnsServers(List<String> dnsServers) {
            if (dnsServers == null || dnsServers.isEmpty()) {
                throw new IllegalArgumentException("dnsServers cannot be empty");
            }
            dcvConfiguration.setDnsServers(dnsServers);
            return this;
        }

        /**
         * Use a custom WhoIs provider. This can allow for querying different WhoIs hosts for different
         * TLDs and using different WhoIs parsers for those different hosts.
         *
         * @param whoisEmailProvider custom WhoisEmailProvider
         * @return DcvConfigurationBuilder configured with the provided whoisEmailProvider.
         */
        public DcvConfigurationBuilder whoisEmailProvider(WhoisEmailProvider whoisEmailProvider) {
            dcvConfiguration.setWhoisEmailProvider(whoisEmailProvider);
            return this;
        }

        /**
         * Set the prefix domain label to use with DNS Change validation.
         * <p>
         * The baseline requirements for the 3.2.2.4.7 DNS Change method allows for the domain to be "prefixed with a
         * Domain Label that begins with an underscore character." With the default value of "_dnsauth.", the library
         * would look for DNS records at "example.com" and "_dnsauth.example.com".
         *
         * @param dnsDomainLabel the DNS domain label
         * @return the builder instance
         * @throws IllegalArgumentException if dnsDomainLabel is null, empty, or does not start with an underscore
         */
        public DcvConfigurationBuilder dnsDomainLabel(String dnsDomainLabel) {
            if (dnsDomainLabel == null || dnsDomainLabel.isEmpty()) {
                throw new IllegalArgumentException("dnsDomainLabel cannot be null or empty");
            }
            if (!dnsDomainLabel.startsWith("_")) {
                throw new IllegalArgumentException("dnsDomainLabel must start with an underscore");
            }
            if (!dnsDomainLabel.endsWith(".")) {
                dnsDomainLabel = dnsDomainLabel + ".";
            }
            if (!DomainNameUtils.isValidDomainLabel(dnsDomainLabel.substring(1, dnsDomainLabel.length() - 1))) {
                throw new IllegalArgumentException("dnsDomainLabel is not a valid domain label");
            }

            dcvConfiguration.setDnsDomainLabel(dnsDomainLabel);
            return this;
        }

        /**
         * Set the timeout in milliseconds for connecting to a server while performing file authentication.
         * <p>
         * Default value is 2000 milliseconds.
         *
         * @param fileAuthConnectTimeout the file authentication connect timeout in milliseconds
         * @return the builder instance
         * @throws IllegalArgumentException if fileAuthConnectTimeout is negative
         */
        public DcvConfigurationBuilder fileAuthConnectTimeout(int fileAuthConnectTimeout) {
            if (fileAuthConnectTimeout < 0) {
                throw new IllegalArgumentException("fileAuthConnectTimeout cannot be negative");
            }
            dcvConfiguration.setFileAuthConnectTimeout(fileAuthConnectTimeout);
            return this;
        }

        /**
         * Set the timeout in milliseconds for reading data from a server while performing file authentication.
         * <p>
         * Default value is 5000 milliseconds.
         *
         * @param fileAuthReadTimeout the file authentication read timeout in milliseconds
         * @return the builder instance
         * @throws IllegalArgumentException if fileAuthReadTimeout is negative
         */
        public DcvConfigurationBuilder fileAuthReadTimeout(int fileAuthReadTimeout) {
            if (fileAuthReadTimeout < 0) {
                throw new IllegalArgumentException("fileAuthReadTimeout cannot be negative");
            }
            dcvConfiguration.setFileAuthReadTimeout(fileAuthReadTimeout);
            return this;
        }

        /**
         * Set the maximum length of the body for file authentication responses.
         * <p>
         * Default value is 5000 bytes.
         *
         * @param fileAuthMaxBodyLength the file authentication max body length
         * @return the builder instance
         * @throws IllegalArgumentException if fileAuthMaxBodyLength is not greater than 0
         */
        public DcvConfigurationBuilder fileAuthMaxBodyLength(int fileAuthMaxBodyLength) {
            if (fileAuthMaxBodyLength <= 0) {
                throw new IllegalArgumentException("fileAuthMaxBodyLength must be greater than 0");
            }
            dcvConfiguration.setFileAuthMaxBodyLength(fileAuthMaxBodyLength);
            return this;
        }

        /**
         * Set the socket timeout in milliseconds for connecting to a server while performing file authentication.
         * <p>
         * Default value is 2000 milliseconds.
         *
         * @param fileAuthSocketTimeout the file authentication socket timeout in milliseconds
         * @return the builder instance
         * @throws IllegalArgumentException if fileAuthSocketTimeout is negative
         */
        public DcvConfigurationBuilder fileAuthSocketTimeout(int fileAuthSocketTimeout) {
            if (fileAuthSocketTimeout < 0) {
                throw new IllegalArgumentException("fileAuthSocketTimeout cannot be negative");
            }
            dcvConfiguration.setFileAuthSocketTimeout(fileAuthSocketTimeout);
            return this;
        }

        /**
         * Set the maximum number of redirects allowed while performing file authentication.
         * <p>
         * Default value is 5.
         *
         * @param fileAuthMaxRedirects the file authentication max redirects
         * @return the builder instance
         * @throws IllegalArgumentException if fileAuthMaxRedirects is negative
         */
        public DcvConfigurationBuilder fileAuthMaxRedirects(int fileAuthMaxRedirects) {
            if (fileAuthMaxRedirects < 0) {
                throw new IllegalArgumentException("fileAuthMaxRedirects cannot be negative");
            }
            dcvConfiguration.setFileAuthMaxRedirects(fileAuthMaxRedirects);
            return this;
        }

        /**
         * Set the flag to indicate that the library will try both HTTP and HTTPS when performing file authentication requests.
         * <p>
         * Default value is false.
         *
         * @param fileAuthCheckHttps the file authentication check HTTPS flag
         * @return the builder instance
         */
        public DcvConfigurationBuilder fileAuthCheckHttps(Boolean fileAuthCheckHttps) {
            dcvConfiguration.setFileAuthCheckHttps(fileAuthCheckHttps);
            return this;
        }

        /**
         * Set the default file name to use for "Agreed-Upon Change to Website v2".
         * <p>
         * This method allows the user to specify a custom default file name for the "Agreed-Upon Change to Website v2"
         * validation method. If validation requests do not specify a file name, this is the file name that will be
         * used.
         *
         * @param fileAuthFileName the file authentication file name
         * @return the builder instance
         * @throws IllegalArgumentException if fileAuthFileName is null, empty, contains invalid characters, or exceeds the maximum length
         */
        public DcvConfigurationBuilder fileAuthFileName(String fileAuthFileName) throws IllegalArgumentException {
            FilenameUtils.validateFilename(fileAuthFileName);
            dcvConfiguration.setFileAuthFilename(fileAuthFileName);
            return this;
        }

        /**
         * Set the user agent to be used for file authentication requests.
         * <p>
         * The user agent header of a request identifies the type of client making the request. Servers can be
         * configured to reject requests from certain user agents, so customers can be instructed to make sure that
         * requests from this user agent are not blocked.
         * <p>
         * Default value is "DCV-Library/1.0".
         *
         * @param fileAuthUserAgent the file authentication user agent
         * @return the builder instance
         * @throws IllegalArgumentException if fileAuthUserAgent is null or empty
         */
        public DcvConfigurationBuilder fileAuthUserAgent(String fileAuthUserAgent) {
            if (fileAuthUserAgent == null || fileAuthUserAgent.isEmpty()) {
                throw new IllegalArgumentException("fileAuthUserAgent cannot be null or empty");
            }
            dcvConfiguration.setFileAuthUserAgent(fileAuthUserAgent);
            return this;
        }

        /**
         * Set the validity period in days for random values generated during the DCV process.
         * <p>
         * The baseline requirements specify that random value cannot be valid after 30 days (starting from the
         * creation of the random value). The default validity period is 29 days to safeguard against corner cases
         * that could be encountered when checking against the limit.
         *
         * @param randomValueValidityPeriod the random value validity period in days
         * @return the builder instance
         * @throws IllegalArgumentException if randomValueValidityPeriod is less than or equal to 0 or greater than 30
         */
        public DcvConfigurationBuilder randomValueValidityPeriod(int randomValueValidityPeriod) {
            if (randomValueValidityPeriod <= 0) {
                throw new IllegalArgumentException("randomValueValidityPeriod must be greater than 0");
            } else if (randomValueValidityPeriod > 30) {
                throw new IllegalArgumentException("Random values cannot be used after 30 days");
            }
            dcvConfiguration.setRandomValueValidityPeriod(randomValueValidityPeriod);
            return this;
        }

        /**
         * Configure the library to use a custom random value validator.
         * <p>
         * The random value validator is used to determine if a given response contains the random value. The default
         * implementation does a simple check for the random value being contained anywhere in the response. A custom
         * validator can be used to ensure random values meet other desired criteria.
         *
         * @param randomValueValidator the custom random value validator
         * @return the builder instance
         * @throws IllegalArgumentException if randomValueValidator is null
         */
        public DcvConfigurationBuilder randomValueValidator(RandomValueValidator randomValueValidator) {
            if (randomValueValidator == null) {
                throw new IllegalArgumentException("randomValueValidator cannot be null");
            }
            dcvConfiguration.setRandomValueValidator(randomValueValidator);
            return this;
        }

        /**
         * Configure the library to use a custom token value validator.
         * <p>
         * The token validator is used to determine if a given response contains a valid token. The default
         * implementation handles DigiCert's request token format, which is a timestamp followed by a hash of the
         * hashing value using the hashing key as the key for the hash and the timestamp as a salt.
         *
         * @param tokenValidator the custom token value validator
         * @return the builder instance
         * @throws IllegalArgumentException if tokenValidator is null
         */
        public DcvConfigurationBuilder tokenValidator(TokenValidator tokenValidator) {
            if (tokenValidator == null) {
                throw new IllegalArgumentException("tokenValidator cannot be null");
            }
            dcvConfiguration.setTokenValidator(tokenValidator);
            return this;
        }

        /**
         * Configure the library to use a custom random value generator.
         * <p>
         * The baseline requirements specify that random values must have at least 112 bits of entropy.
         *
         * @param randomValueGenerator the custom random value generator
         * @return the builder instance
         * @throws IllegalArgumentException if randomValueGenerator is null
         */
        public DcvConfigurationBuilder randomValueGenerator(RandomValueGenerator randomValueGenerator) {
            if (randomValueGenerator == null) {
                throw new IllegalArgumentException("randomValueGenerator cannot be null");
            }
            dcvConfiguration.setRandomValueGenerator(randomValueGenerator);
            return this;
        }

        /**
         * Configure the library to use a custom PSL override supplier.
         * <p>
         * The supplier provides Public Suffix List (PSL) overrides for handling special cases in domain validation.
         * There are cases where the default PSL data may not be sufficient for accurate domain validation (such as
         * when governments that own a public suffix want to obtain a certificate at the level of the suffix).
         *
         * @param pslOverrideSupplier the custom PSL override supplier
         * @return the builder instance
         * @throws IllegalArgumentException if pslOverrideSupplier is null
         */
        public DcvConfigurationBuilder pslOverrideSupplier(PslOverrideSupplier pslOverrideSupplier) {
            if (pslOverrideSupplier == null) {
                throw new IllegalArgumentException("pslOverrideSupplier cannot be null");
            }
            dcvConfiguration.setPslOverrideSupplier(pslOverrideSupplier);
            return this;
        }

        /**
         * Build the DcvConfiguration instance.
         * <p>
         * This method constructs a `DcvConfiguration` instance using the parameters set in the builder and ensures
         * that the PslDataProvider has had data loaded.
         *
         * @return the DcvConfiguration instance
         */
        public DcvConfiguration build() {
            PslDataProvider.getInstance().loadDefaultData();
            return dcvConfiguration;
        }
    }
}