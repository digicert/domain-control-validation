package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.exceptions.PreparationException;
import com.digicert.validation.methods.dns.validate.MpicDnsDetails;
import com.digicert.validation.methods.email.prepare.EmailDetails;
import com.digicert.validation.methods.email.prepare.EmailDnsDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.utils.DomainNameUtils;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.event.Level;

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
     * The MPIC DNS service used to fetch DNS details.
     * <p>
     * This service is used to interact with the Multi-Perspective DNS system for DNS-related operations.
     */
    private final MpicDnsService mpicDnsService;

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
        mpicDnsService = dcvContext.get(MpicDnsService.class);
        logLevelForDcvErrors = dcvContext.getDcvConfiguration().getLogLevelForDcvErrors();
    }

    /**
     * Retrieves email contacts for the given domain by querying the DNS TXT records of the domain.
     * <p>
     * This method performs a DNS query to retrieve emails found in the domain TXT records, using the
     * BR specified "_validation-contactemail" prefix.
     *
     * @param domain the domain to retrieve email contacts for
     * @return {@link EmailDetails} containing the email contacts for the domain and the MPIC Details
     * @throws PreparationException if an error occurs while retrieving email contacts for the domain
     */
    @Override
    public EmailDetails findEmailsForDomain(String domain) throws PreparationException {
        String domainWithPrefix = String.format("%s.%s", DNS_TXT_EMAIL_AUTHORIZATION_PREFIX, domain);
        MpicDnsDetails mpicDnsDetails = mpicDnsService.getDnsDetails(domainWithPrefix, DnsType.TXT);

        if (mpicDnsDetails.dcvError() != null) {
            log.atLevel(logLevelForDcvErrors).log("event_id={} domain={}", LogEvents.NO_DNS_TXT_CONTACT_FOUND, domain);
            throw new PreparationException(Set.of(mpicDnsDetails.dcvError()));
        }

        Set<EmailDnsDetails> emailDnsDetails = mpicDnsDetails.dnsRecords().stream()
                .map(m -> new EmailDnsDetails(DnsTxtEmailProvider.normalizeEmailAddress(m.value()), m.name()))
                .filter(f -> DomainNameUtils.isValidEmailAddress(f.email()))
                .collect(Collectors.toUnmodifiableSet());

        if (emailDnsDetails.isEmpty()) {
            log.atLevel(logLevelForDcvErrors).log("event_id={} domain={} records={}", LogEvents.NO_DNS_TXT_CONTACT_FOUND, domain, mpicDnsDetails.dnsRecords().size());
            throw new PreparationException(Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
        }

        return new EmailDetails(emailDnsDetails, mpicDnsDetails.mpicDetails());
    }

    public static String normalizeEmailAddress(String dnsValue) {
        // String the beginning and end quote off the dnsValue
        return dnsValue.trim().replaceAll("^\"|\"$", "");
    }
}