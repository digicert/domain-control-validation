package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.methods.email.prepare.EmailDetails;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * ConstructedEmailProvider is an implementation of EmailProvider that constructs email addresses
 * that can be used for domain validation.
 * <p>
 * This class provides a mechanism to generate a set of email addresses based on common administrative
 * prefixes and a given domain.
 */
public class ConstructedEmailProvider implements EmailProvider {
    /**
     * These prefixes can be used in combination with the FQDN
     * to form email addresses that can be used for domain validation.
     * <p>
     * The list of base email address prefixes includes common administrative email addresses, specifically
     * "admin@", "administrator@", "webmaster@", "hostmaster@", and "postmaster@".
     */
    private static final List<String> BASE_EMAIL_ADDRESS_PREFIXES = Arrays.asList(
            "admin@",
            "administrator@",
            "webmaster@",
            "hostmaster@",
            "postmaster@"
    );

    /**
     * The default constructor for the ConstructedEmailProvider class
     */
    public ConstructedEmailProvider() {
        // Default constructor
    }

    /**
     * Returns a set of constructed email addresses that can be used for domain validation.
     * These are prefixed with {@link ConstructedEmailProvider#BASE_EMAIL_ADDRESS_PREFIXES} and suffixed with the domain.
     * <p>
     * This method generates a set of email addresses by combining each prefix from the {@link ConstructedEmailProvider#BASE_EMAIL_ADDRESS_PREFIXES}
     * list with the provided domain.
     *
     * @param domain The domain to construct email addresses for.
     * @return {@link EmailDetails} containing a set of constructed email addresses that can be used for domain validation.
     *         No MPIC details are present because no DNS lookups are made.
     */
    @Override
    public EmailDetails findEmailsForDomain(String domain) {
        Set<String> emails = BASE_EMAIL_ADDRESS_PREFIXES.stream()
                .map(prefix -> prefix + domain)
                .collect(Collectors.toUnmodifiableSet());
        return new EmailDetails(emails, null);
    }
}