package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.DcvContext;
import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.client.dns.DnsData;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.exceptions.PreparationException;
import com.digicert.validation.utils.DomainNameUtils;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.event.Level;
import org.xbill.DNS.TXTRecord;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * EmailDnsTxtProvider is an implementation of EmailProvider that retrieves email contacts for a domain by querying the
 * DNS TXT records of the domain.
 * <p>
 * This provider is designed to facilitate the process of domain validation by extracting email addresses from DNS TXT records.
 * The DNS TXT records are queried using a specific prefix defined in the Baseline Requirements (BRs), which ensures that the
 * email addresses retrieved are intended for validation purposes.
 */
@Slf4j
public class DnsTxtEmailProvider implements EmailProvider {

    /**
     * This prefix is used to identify the DNS TXT record that contains the email address for validation.
     * It is defined in the BRs as "_validation-contactemail" (section A.2.1).
     * <p>
     * The prefix "_validation-contactemail" is a standardized identifier used in DNS TXT records to denote email addresses
     * that are specifically set up for domain validation.
     */
    public static final String DNS_TXT_EMAIL_AUTHORIZATION_PREFIX = "_validation-contactemail";

    /**
     * The DNS client used to query DNS records.
     */
    private final DnsClient dnsClient;

    /** The log level used for logging errors related to domain control validation (DCV). */
    private final Level logLevelForDcvErrors;

    /**
     * Constructs a new EmailDnsTxtProvider with the given DcvContext.
     * <p>
     * This constructor initializes the DnsTxtEmailProvider with the necessary dependencies and configuration provided by the
     * DcvContext.
     *
     * @param dcvContext context where we can find the needed dependencies and configuration
     */
    public DnsTxtEmailProvider(DcvContext dcvContext) {
        dnsClient = dcvContext.get(DnsClient.class);
        logLevelForDcvErrors = dcvContext.getDcvConfiguration().getLogLevelForDcvErrors();
    }

    /**
     * Retrieves email contacts for the given domain by querying the DNS TXT records of the domain.
     * <p>
     * This method performs a DNS query to retrieve emails found in the domain TXT records, using the
     * BR specified "_validation-contactemail" prefix.
     *
     * @param domain the domain to retrieve email contacts for
     * @return a set of email contacts for the domain
     * @throws PreparationException if an error occurs while retrieving email contacts for the domain
     */
    @Override
    public Set<String> findEmailsForDomain(String domain) throws PreparationException {
        List<String> domains = List.of(String.format("%s.%s", DNS_TXT_EMAIL_AUTHORIZATION_PREFIX, domain));
        DnsData dnsData = dnsClient.getDnsData(domains, DnsType.TXT);

        Set<String> emails = dnsData.records().stream()
                .flatMap(dnsRecord -> ((TXTRecord) dnsRecord).getStrings().stream())
                .filter(DomainNameUtils::isValidEmailAddress)
                .collect(Collectors.toUnmodifiableSet());

        if (emails.isEmpty()) {
            log.atLevel(logLevelForDcvErrors).log("event_id={} domain={} records={}", LogEvents.NO_DNS_TXT_CONTACT_FOUND, domain, dnsData.records().size());
            throw new PreparationException(dnsData.errors());
        }

        return emails;
    }
}