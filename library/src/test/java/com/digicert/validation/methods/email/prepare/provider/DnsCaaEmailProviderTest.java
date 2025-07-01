package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.PreparationException;
import com.digicert.validation.methods.dns.validate.MpicDnsDetails;
import com.digicert.validation.methods.email.prepare.EmailDetails;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DnsCaaEmailProviderTest {

    private MpicDnsService mpicDnsService;

    private DnsCaaEmailProvider dnsCaaEmailProvider;

    @BeforeEach
    public void setUp() {
        mpicDnsService = mock(MpicDnsService.class);

        DcvContext dcvContext = mock(DcvContext.class);
        when(dcvContext.get(MpicDnsService.class)).thenReturn(mpicDnsService);

        dnsCaaEmailProvider = new DnsCaaEmailProvider(dcvContext);
    }

    @Test
    void testFindEmailsForDomainCaa_HappyPath() throws PreparationException {
        String domain = "example.com";
        String caaEmail = "dnscaaemail@example.com";

        DnsRecord caaRecord = new DnsRecord(DnsType.CAA, domain, caaEmail, 0, 0, DnsCaaEmailProvider.DNS_CAA_EMAIL_TAG);

        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Collections.emptyMap());
        MpicDnsDetails mpicDnsDetailsData = new MpicDnsDetails(mpicDetails, domain, List.of(caaRecord), null);
        when(mpicDnsService.getDnsDetails(domain, DnsType.CAA)).thenReturn(mpicDnsDetailsData);

        EmailDetails emailDetails = dnsCaaEmailProvider.findEmailsForDomain(domain);
        Set<String> emails = emailDetails.emails();

        assertTrue(emails.contains(caaEmail), "Expected email not found in the result set");
        assertEquals(1, emails.size());
    }


    @Test
    void testFindEmailsForDomainCaa_multipleCaaRecords() throws PreparationException {
        String domain = "example.com";
        String caaEmail = "dnscaaemail@example.com";

        DnsRecord caaEmailRecord = new DnsRecord(DnsType.CAA, domain, caaEmail, 0, 0, DnsCaaEmailProvider.DNS_CAA_EMAIL_TAG);
        DnsRecord caaIssueRecord = new DnsRecord(DnsType.CAA, domain, "somedomain.com", 0, 0, "issue");
        DnsRecord caaIssueWildRecord = new DnsRecord(DnsType.CAA, domain, "somedomain.com", 0, 0, "issuewild");

        List<DnsRecord> dnsRecords = List.of(caaEmailRecord, caaIssueRecord, caaIssueWildRecord);

        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Collections.emptyMap());
        MpicDnsDetails mpicDnsDetailsData = new MpicDnsDetails(mpicDetails, domain, dnsRecords, null);

        when(mpicDnsService.getDnsDetails(domain, DnsType.CAA)).thenReturn(mpicDnsDetailsData);

        EmailDetails emailDetails = dnsCaaEmailProvider.findEmailsForDomain(domain);
        Set<String> emails = emailDetails.emails();

        assertTrue(emails.contains(caaEmail), "Expected email not found in the result set");
        assertEquals(1, emails.size());
    }

    @Test
    void testFindEmailsForDomainCaa_throwsPreparationException() {
        String domain = "example.com";

        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Collections.emptyMap());
        MpicDnsDetails mpicDnsDetailsData = new MpicDnsDetails(mpicDetails, domain, List.of(), DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION);

        when(mpicDnsService.getDnsDetails(domain, DnsType.CAA)).thenReturn(mpicDnsDetailsData);

        PreparationException exception = assertThrows(PreparationException.class, () -> dnsCaaEmailProvider.findEmailsForDomain(domain));

        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION));
    }

    @Test
    void testFindEmailsForDomainCaa_missingDnsData() {
        String domain = "example.com";

        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Collections.emptyMap());
        MpicDnsDetails mpicDnsDetailsData = new MpicDnsDetails(mpicDetails, domain, List.of(), DcvError.DNS_LOOKUP_RECORD_NOT_FOUND);

        when(mpicDnsService.getDnsDetails(domain, DnsType.CAA)).thenReturn(mpicDnsDetailsData);

        PreparationException exception = assertThrows(PreparationException.class, () -> dnsCaaEmailProvider.findEmailsForDomain(domain));

        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
    }
}
