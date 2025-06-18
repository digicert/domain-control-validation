package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.DcvContext;
import com.digicert.validation.client.dns.CaaValue;
import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.client.dns.DnsData;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.PreparationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.CAARecord;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DnsCaaEmailProviderTest {

    private DnsClient dnsClient;

    private DnsCaaEmailProvider dnsCaaEmailProvider;

    @BeforeEach
    public void setUp() {
        dnsClient = mock(DnsClient.class);

        DcvContext dcvContext = mock(DcvContext.class);
        when(dcvContext.get(DnsClient.class)).thenReturn(dnsClient);

        dnsCaaEmailProvider = new DnsCaaEmailProvider(dcvContext);
    }

    @Test
    void testFindEmailsForDomainCaa_HappyPath() throws PreparationException {
        String domain = "example.com";
        String caaEmail = "dnscaaemail@example.com";

        CaaValue caaRecord = mock(CaaValue.class);
        when(caaRecord.getTag()).thenReturn(DnsCaaEmailProvider.DNS_CAA_EMAIL_TAG);
        when(caaRecord.getValue()).thenReturn(caaEmail);
        when(caaRecord.getDnsType()).thenReturn(DnsType.CAA);

        String host = "some-host";
        DnsData dnsData = new DnsData(List.of(host), "some-name", DnsType.CAA, List.of(caaRecord),
                Set.of(), host);

        when(dnsClient.getDnsData(List.of(domain), DnsType.CAA)).thenReturn(dnsData);

        Set<String> emails = dnsCaaEmailProvider.findEmailsForDomain(domain);

        assertTrue(emails.contains(caaEmail), "Expected email not found in the result set");
        assertEquals(1, emails.size());
    }


    @Test
    void testFindEmailsForDomainCaa_multipleCaaRecords() throws PreparationException {
        String domain = "example.com";
        String caaEmail = "dnscaaemail@example.com";

        CaaValue caaEmailRecord = mock(CaaValue.class);
        when(caaEmailRecord.getTag()).thenReturn(DnsCaaEmailProvider.DNS_CAA_EMAIL_TAG);
        when(caaEmailRecord.getValue()).thenReturn(caaEmail);
        when(caaEmailRecord.getDnsType()).thenReturn(DnsType.CAA);

        CaaValue caaIssueRecord = mock(CaaValue.class);
        when(caaIssueRecord.getTag()).thenReturn("issue");
        when(caaIssueRecord.getValue()).thenReturn(domain);
        when(caaIssueRecord.getDnsType()).thenReturn(DnsType.CAA);

        CaaValue caaIssueWildRecord = mock(CaaValue.class);
        when(caaIssueWildRecord.getTag()).thenReturn("issueWild");
        when(caaIssueWildRecord.getValue()).thenReturn(domain);
        when(caaIssueWildRecord.getDnsType()).thenReturn(DnsType.CAA);

        String host = "some-host";
        DnsData dnsData = new DnsData(List.of(host), "some-name", DnsType.CAA, List.of(caaEmailRecord, caaIssueRecord, caaIssueWildRecord),
                Set.of(), host);

        when(dnsClient.getDnsData(List.of(domain), DnsType.CAA)).thenReturn(dnsData);

        Set<String> emails = dnsCaaEmailProvider.findEmailsForDomain(domain);

        assertTrue(emails.contains(caaEmail), "Expected email not found in the result set");
        assertEquals(1, emails.size());
    }

    @Test
    void testFindEmailsForDomainCaa_throwsPreparationException() {
        String domain = "example.com";
        DnsData dnsData = new DnsData(List.of(), domain, DnsType.CAA, List.of(),
                Set.of(DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION), "some-host");
        when(dnsClient.getDnsData(List.of(domain), DnsType.CAA)).thenReturn(dnsData);

        PreparationException exception = assertThrows(PreparationException.class, () -> dnsCaaEmailProvider.findEmailsForDomain(domain));

        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION));
    }

    @Test
    void testFindEmailsForDomainCaa_missingDnsData() {
        String domain = "example.com";
        DnsData dnsData = new DnsData(List.of(), domain, DnsType.CAA, List.of(),
                Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND), "some-host");
        when(dnsClient.getDnsData(List.of(domain), DnsType.CAA)).thenReturn(dnsData);

        PreparationException exception = assertThrows(PreparationException.class, () -> dnsCaaEmailProvider.findEmailsForDomain(domain));

        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
    }
}
