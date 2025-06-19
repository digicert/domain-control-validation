package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.DcvContext;
import com.digicert.validation.client.dns.CaaValue;
import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.client.dns.DnsData;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.PreparationException;
import com.digicert.validation.methods.dns.validate.MpicDnsDetails;
import com.digicert.validation.methods.email.prepare.MpicEmailDetails;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.CAARecord;

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

        DnsRecord caaRecord = mock(DnsRecord.class);
        when(caaRecord.tag()).thenReturn(DnsCaaEmailProvider.DNS_CAA_EMAIL_TAG);
        when(caaRecord.value()).thenReturn(caaEmail);
        when(caaRecord.dnsType()).thenReturn(DnsType.CAA);


        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Collections.emptyMap());
        MpicDnsDetails mpicDnsDetailsData = new MpicDnsDetails(mpicDetails, domain, List.of(caaRecord), null);
        when(mpicDnsService.getDnsDetails(List.of(domain), DnsType.CAA)).thenReturn(mpicDnsDetailsData);

        MpicEmailDetails mpicEmailDetails = dnsCaaEmailProvider.findEmailsForDomain(domain);
        Set<String> emails = mpicEmailDetails.emails();

        assertTrue(emails.contains(caaEmail), "Expected email not found in the result set");
        assertEquals(1, emails.size());
    }


    @Test
    void testFindEmailsForDomainCaa_multipleCaaRecords() throws PreparationException {
        String domain = "example.com";
        String caaEmail = "dnscaaemail@example.com";

        DnsRecord caaEmailRecord = mock(DnsRecord.class);
        when(caaEmailRecord.tag()).thenReturn(DnsCaaEmailProvider.DNS_CAA_EMAIL_TAG);
        when(caaEmailRecord.value()).thenReturn(caaEmail);
        when(caaEmailRecord.dnsType()).thenReturn(DnsType.CAA);

        DnsRecord caaIssueRecord = mock(DnsRecord.class);
        when(caaIssueRecord.tag()).thenReturn("issue");
        when(caaIssueRecord.value()).thenReturn(domain);
        when(caaIssueRecord.dnsType()).thenReturn(DnsType.CAA);

        DnsRecord caaIssueWildRecord = mock(DnsRecord.class);
        when(caaIssueWildRecord.tag()).thenReturn("issueWild");
        when(caaIssueWildRecord.value()).thenReturn(domain);
        when(caaIssueWildRecord.dnsType()).thenReturn(DnsType.CAA);

        List<DnsRecord> dnsRecords = List.of(caaEmailRecord, caaIssueRecord, caaIssueWildRecord);

        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Collections.emptyMap());
        MpicDnsDetails mpicDnsDetailsData = new MpicDnsDetails(mpicDetails, domain, dnsRecords, null);

        when(mpicDnsService.getDnsDetails(List.of(domain), DnsType.CAA)).thenReturn(mpicDnsDetailsData);

        MpicEmailDetails mpicEmailDetails = dnsCaaEmailProvider.findEmailsForDomain(domain);
        Set<String> emails = mpicEmailDetails.emails();

        assertTrue(emails.contains(caaEmail), "Expected email not found in the result set");
        assertEquals(1, emails.size());
    }

    @Test
    void testFindEmailsForDomainCaa_throwsPreparationException() {
        String domain = "example.com";

        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Collections.emptyMap());
        MpicDnsDetails mpicDnsDetailsData = new MpicDnsDetails(mpicDetails, domain, List.of(), DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION);

        when(mpicDnsService.getDnsDetails(List.of(domain), DnsType.CAA)).thenReturn(mpicDnsDetailsData);

        PreparationException exception = assertThrows(PreparationException.class, () -> dnsCaaEmailProvider.findEmailsForDomain(domain));

        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION));
    }

    @Test
    void testFindEmailsForDomainCaa_missingDnsData() {
        String domain = "example.com";

        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Collections.emptyMap());
        MpicDnsDetails mpicDnsDetailsData = new MpicDnsDetails(mpicDetails, domain, List.of(), DcvError.DNS_LOOKUP_RECORD_NOT_FOUND);

        when(mpicDnsService.getDnsDetails(List.of(domain), DnsType.CAA)).thenReturn(mpicDnsDetailsData);

        PreparationException exception = assertThrows(PreparationException.class, () -> dnsCaaEmailProvider.findEmailsForDomain(domain));

        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
    }
}
