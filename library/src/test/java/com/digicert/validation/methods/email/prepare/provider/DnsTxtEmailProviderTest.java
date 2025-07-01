package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.PreparationException;
import com.digicert.validation.methods.dns.validate.MpicDnsDetails;
import com.digicert.validation.mpic.MpicDetails;
import com.digicert.validation.mpic.MpicDnsService;
import com.digicert.validation.mpic.api.dns.DnsRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.digicert.validation.methods.email.prepare.provider.DnsTxtEmailProvider.DNS_TXT_EMAIL_AUTHORIZATION_PREFIX;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DnsTxtEmailProviderTest {

    private MpicDnsService mpicDnsService;

    private DnsTxtEmailProvider dnsTxtEmailProvider;

    @BeforeEach
    public void setUp() {
        mpicDnsService = mock(MpicDnsService.class);

        DcvContext dcvContext = mock(DcvContext.class);
        when(dcvContext.get(MpicDnsService.class)).thenReturn(mpicDnsService);
        when(dcvContext.getDcvConfiguration()).thenReturn(new DcvConfiguration.DcvConfigurationBuilder().build());

        dnsTxtEmailProvider = new DnsTxtEmailProvider(dcvContext);
    }

    @Test
    void testFindEmailsForDomainTxt() throws PreparationException {
        String domain = "example.com";
        List<DnsRecord> dnsRecords = List.of(
                new DnsRecord(DnsType.TXT, domain, "test@example.com", 0, 0, ""),
                new DnsRecord(DnsType.TXT, domain, "invalid-email", 0, 0, ""));

        // Create DnsData with the mocked TXTRecord
        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Collections.emptyMap());
        MpicDnsDetails mpicDnsDetailsData = new MpicDnsDetails(mpicDetails, domain, dnsRecords, null);
        String domainWithPrefix = String.format("%s.%s", DNS_TXT_EMAIL_AUTHORIZATION_PREFIX, domain);
        when(mpicDnsService.getDnsDetails(domainWithPrefix, DnsType.TXT)).thenReturn(mpicDnsDetailsData);

        // Call the method under test
        Set<String> emails = dnsTxtEmailProvider.findEmailsForDomain(domain).emails();

        // Verify the results
        assertTrue(emails.contains("test@example.com"));
        assertFalse(emails.contains("invalid-email"));
        assertEquals(1, emails.size());
    }

    @Test
    void testFindEmailsForDomainTxt_multipleEmails() throws PreparationException {
        String domain = "example.com";
        List<DnsRecord> dnsRecords = List.of(
                new DnsRecord(DnsType.TXT, domain, "test@example.com", 0, 0, ""),
                new DnsRecord(DnsType.TXT, domain, "another@example.com", 0, 0, ""));

        // Create DnsData with the mocked TXTRecord
        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Collections.emptyMap());
        MpicDnsDetails mpicDnsDetailsData = new MpicDnsDetails(mpicDetails, domain, dnsRecords, null);
        String domainWithPrefix = String.format("%s.%s", DNS_TXT_EMAIL_AUTHORIZATION_PREFIX, domain);
        when(mpicDnsService.getDnsDetails(domainWithPrefix, DnsType.TXT)).thenReturn(mpicDnsDetailsData);

        // Call the method under test
        Set<String> emails = dnsTxtEmailProvider.findEmailsForDomain(domain).emails();

        // Verify the results
        assertTrue(emails.contains("test@example.com"));
        assertTrue(emails.contains("another@example.com"));
        assertEquals(2, emails.size());
    }

    @Test
    void testFindEmailsForDomain_dnsLookupError() {
        String domain = "example.com";
        List<DnsRecord> dnsRecords = List.of();

        // Create DnsData with the mocked TXTRecord
        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Collections.emptyMap());
        MpicDnsDetails mpicDnsDetailsData = new MpicDnsDetails(mpicDetails, domain, dnsRecords, DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION);
        String domainWithPrefix = String.format("%s.%s", DNS_TXT_EMAIL_AUTHORIZATION_PREFIX, domain);
        when(mpicDnsService.getDnsDetails(domainWithPrefix, DnsType.TXT)).thenReturn(mpicDnsDetailsData);

        PreparationException exception = assertThrows(PreparationException.class, () -> dnsTxtEmailProvider.findEmailsForDomain(domain));

        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION));
    }

    @Test
    void testFindEmailsForDomain_noEmailsFound() {
        String domain = "example.com";
        List<DnsRecord> dnsRecords = List.of(
                new DnsRecord(DnsType.TXT, domain, "one-invalid-email", 0, 0, ""),
                new DnsRecord(DnsType.TXT, domain, "another-invalid-email", 0, 0, ""));

        // Create DnsData with the mocked TXTRecord
        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Collections.emptyMap());
        MpicDnsDetails mpicDnsDetailsData = new MpicDnsDetails(mpicDetails, domain, dnsRecords, null);
        String domainWithPrefix = String.format("%s.%s", DNS_TXT_EMAIL_AUTHORIZATION_PREFIX, domain);
        when(mpicDnsService.getDnsDetails(domainWithPrefix, DnsType.TXT)).thenReturn(mpicDnsDetailsData);

        PreparationException exception = assertThrows(PreparationException.class, () -> dnsTxtEmailProvider.findEmailsForDomain(domain));

        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
    }

    @Test
    void testFindEmailsForDomainTxt_missingDnsData() {
        String domain = "example.com";
        List<DnsRecord> dnsRecords = List.of();

        // Create DnsData with the mocked TXTRecord
        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Collections.emptyMap());
        MpicDnsDetails mpicDnsDetailsData = new MpicDnsDetails(mpicDetails, domain, dnsRecords, DcvError.DNS_LOOKUP_RECORD_NOT_FOUND);
        String domainWithPrefix = String.format("%s.%s", DNS_TXT_EMAIL_AUTHORIZATION_PREFIX, domain);
        when(mpicDnsService.getDnsDetails(domainWithPrefix, DnsType.TXT)).thenReturn(mpicDnsDetailsData);

        PreparationException exception = assertThrows(PreparationException.class, () -> dnsTxtEmailProvider.findEmailsForDomain(domain));

        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
    }
}