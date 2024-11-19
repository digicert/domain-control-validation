package com.digicert.validation.service.whois;

import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.exceptions.PreparationException;
import com.digicert.validation.methods.email.prepare.provider.WhoisEmailProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Set;

/**
 * BasicWhoIsEmailProvider is an implementation of WhoisEmailProvider that retrieves email contacts for a domain by querying the
 * WHOIS servers of the domain.
 * <p>
 * This class leverages the DefaultWhoisClient to perform WHOIS lookups and extract email contacts associated with a given domain.
 * </p>
 *
 * @see DefaultWhoisClient
 */
@Slf4j
@Service
public class BasicWhoIsEmailProvider implements WhoisEmailProvider {

    /**
     * The WHOIS client used to query WHOIS servers.
     * <p>
     * The DefaultWhoisClient is responsible for making the actual WHOIS queries to retrieve email contacts.
     * </p>
     */
    private final DefaultWhoisClient defaultWhoisClient;

    /**
     * Constructs a new BasicWhoIsEmailProvider with the specified DcvContext.
     * <p>
     * This constructor initializes the BasicWhoIsEmailProvider by obtaining an instance of DefaultWhoisClient from the provided
     * DcvContext.
     * </p>
     *
     * @param defaultWhoisClient a WhoisClient implementation to use for WHOIS lookups
     */
    public BasicWhoIsEmailProvider(DefaultWhoisClient defaultWhoisClient) {
        this.defaultWhoisClient = defaultWhoisClient;
    }

    /**
     * Retrieves email contacts for the given domain by querying the WHOIS servers of the domain.
     * <p>
     * This method performs a WHOIS lookup for the specified domain using the DefaultWhoisClient. It extracts email contacts
     * from the WHOIS data and returns them as a set.
     * </p>
     *
     * @param domain the domain to retrieve email contacts for
     * @return a set of email contacts for the domain
     * @throws PreparationException if an error occurs while retrieving email contacts for the domain
     */
    @Override
    public Set<String> findEmailsForDomain(String domain) throws PreparationException {
        WhoisData whoisData = defaultWhoisClient.getWhoisEmailContacts(domain);

        if (whoisData.emails().isEmpty()) {
            log.info("event_id=whois_no_emails_found domain={} hosts={} errors={} ",
                    domain, whoisData.visitedWhoisHosts(), whoisData.errors());
            throw new PreparationException(whoisData.errors());
        }

        return whoisData.emails();
    }
}