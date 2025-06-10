package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.DcvContext;
import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.client.dns.DnsData;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.exceptions.PreparationException;
import com.digicert.validation.utils.DomainNameUtils;
import lombok.extern.slf4j.Slf4j;
import org.xbill.DNS.CAARecord;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * EmailDnsCaaProvider is an implementation of EmailProvider that retrieves email contacts for a domain by querying the
 * DNS CAA records of the domain.
 * <p>
 * This provider is designed to facilitate the process of domain validation by extracting email addresses from DNS CAA records.
 * The DNS CAA records are filtered using a specific tag defined in the Baseline Requirements (BRs), which ensures that the
 * email addresses retrieved are intended for validation purposes.
 */
@Slf4j
public class DnsCaaEmailProvider implements EmailProvider {

    /**
     * This CAA record tag is used to identify the DNS CAA record that contains the email address for validation.
     * It is defined in the BRs as "contactemail" (section A.1.1).
     * <p>
     * The tag "contactemail" is a standardized identifier used in DNS CAA records to denote email addresses
     * that are specifically set up for domain validation.
     */
    public static final String DNS_CAA_EMAIL_TAG = "contactemail";

    /**
     * The DNS client used to query DNS records.
     */
    private final DnsClient dnsClient;

    /**
     * Constructs a new EmailDnsCaaProvider with the given DcvContext.
     * <p>
     * This constructor initializes the DnsCaaEmailProvider with the necessary dependencies and configuration provided by the
     * DcvContext.
     *
     * @param dcvContext context where we can find the needed dependencies and configuration
     */
    public DnsCaaEmailProvider(DcvContext dcvContext) {
        dnsClient = dcvContext.get(DnsClient.class);
    }

    /**
     * Retrieves email contacts for the given domain by querying the DNS CAA records of the domain.
     * <p>
     * This method performs a DNS query to retrieve emails found in the domain CAA records, filtering the
     * results to the BR specified "contactemail" tag.
     *
     * @param domain the domain to retrieve email contacts for
     * @return a set of email contacts for the domain
     * @throws PreparationException if an error occurs while retrieving email contacts for the domain
     */
    @Override
    public Set<String> findEmailsForDomain(String domain) throws PreparationException {
        DnsData dnsData = dnsClient.getDnsData(List.of(domain), DnsType.CAA);

        Set<String> emails = dnsData.records().stream()
                .filter(dnsRecord -> ((CAARecord) dnsRecord).getTag().equals(DNS_CAA_EMAIL_TAG))
                .map(dnsRecord -> ((CAARecord) dnsRecord).getValue())
                .collect(Collectors.toUnmodifiableSet());

        if (emails.isEmpty()) {
            log.info("event_id={} domain={} records={}", LogEvents.NO_DNS_CAA_CONTACT_FOUND, domain, dnsData.records().size());
            throw new PreparationException(dnsData.errors());
        }

        return emails;
    }
}
