package com.digicert.validation.enums;

/**
 * Enumeration representing various events that can occur during the validation process.
 */
public enum LogEvents {
    /** Log event indicating a redirect was attempted but the host information was missing. */
    BAD_REDIRECT_NO_HOST,

    /** Log event indicating an invalid URL was found during a file validation redirect. */
    BAD_REDIRECT_URL,

    /**
     * Log event indicating an incorrect port was used during a file validation redirect.
     * Only ports 80 and 443 are allowed.
     */
    BAD_REDIRECT_PORT,

    /** Log event indicating there an unknown error that occurred during a file validation redirect attempt. */
    REDIRECT_ERROR,

    /** Log event indicating that the system failed to generate a hash value. */
    CANNOT_GENERATE_HASH,

    /** This log event indicates that the system successfully retrieved the DNS data for a domain. */
    DNS_LOOKUP_STATUS,

    /** Log event indicates that the DNS lookup was unable to find the host or the data returned was not parseable. */
    DNS_LOOKUP_ERROR,

    /** Log event indicates that the DNS validation cannot be completed. */
    DNS_VALIDATION_FAILED,

    /** Log event indicating that the validation request is malformed. */
    DNS_VALIDATION_MALFORMED_REQUEST,

    /** Log event indicating that control over the domain was successfully proven. */
    DNS_VALIDATION_SUCCESSFUL,

    /** Log event indicating that the DNS server is not configured. */
    DNS_SERVERS_NOT_CONFIGURED,

    /** Log event indicating that a response was received */
    FILE_VALIDATION_RESPONSE,

    /** Log event indicating that the response was not parseable or otherwise does not meet with validation requirements. */
    FILE_VALIDATION_BAD_RESPONSE,

    /** Log event indicating that a connection error occurred with the client. */
    FILE_VALIDATION_CLIENT_ERROR,

    /** Log event indicating that the connection attempt timed out. */
    FILE_VALIDATION_CONNECTION_TIMEOUT_ERROR,

    /** Log event indicating that the file validation cannot be completed. */
    FILE_VALIDATION_FAILED,

    /** Log event indicating that control over the FQDN was successfully proven. */
    FILE_VALIDATION_SUCCESSFUL,

    /** Log event indicating that the domain is invalid due to its length. (Max 255 characters) */
    INVALID_DOMAIN_LENGTH,

    /** Log event indicating that the domain name does not match the regex used to validate the domain name syntax. */
    INVALID_DOMAIN_NAME,

    /** Log event indicating that there was an issue with the response from the mpic service */
    MPIC_INVALID_RESPONSE,

    /** Log event indicating that the ACME validation was successful. */
    ACME_VALIDATION_SUCCESSFUL,

    /** Log event indicating that the ACME validation failed due to some error. */
    ACME_VALIDATION_FAILED,

    /**
     * Reserved labels, which are two alphanumeric characters followed by two hyphens, must follow a specific
     * standards which this domain does not follow.
     */
    INVALID_RESERVED_LDH_LABEL,

    /** Log event indicating that no properly formatted DNS TXT records containing a contact were found. */
    NO_DNS_TXT_CONTACT_FOUND,

    /** Log event indicating that no properly formatted DNS CAA records containing a contact email were found. */
    NO_DNS_CAA_CONTACT_FOUND,

    /** Security provider used for calculating hashes was unable to load. The default token validator will not be usable. */
    SECURITY_PROVIDER_LOAD_ERROR,

    /** Log event indicating a failure in creating the SSL context. Should not be reachable and would indicate a Java library mismatch. */
    SSL_CONTEXT_CREATION_ERROR;

    /**
     * Returns the lowercase string representation of the event.
     *
     * @return the string representation of the event
     */
    @Override
    public String toString() {
        return this.name().toLowerCase();
    }
}