package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.client.dns.DnsClient;
import com.digicert.validation.client.dns.DnsData;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.exceptions.PreparationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.TXTRecord;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DnsTxtEmailProviderTest {

    private DnsClient dnsClient;

    private DnsTxtEmailProvider dnsTxtEmailProvider;

    @BeforeEach
    public void setUp() {
        dnsClient = mock(DnsClient.class);

        DcvContext dcvContext = mock(DcvContext.class);
        when(dcvContext.get(DnsClient.class)).thenReturn(dnsClient);
        when(dcvContext.getDcvConfiguration()).thenReturn(new DcvConfiguration.DcvConfigurationBuilder().build());

        dnsTxtEmailProvider = new DnsTxtEmailProvider(dcvContext);
    }

    @Test
    void testFindEmailsForDomainTxt() throws PreparationException {
        String domain = "example.com";
        List<String> dnsValues = List.of("test@example.com", "invalid-email");

        // Mock the TXTRecord to return the dnsValues
        TXTRecord dnsRecord = mock(TXTRecord.class);
        when(dnsRecord.getStrings()).thenReturn(dnsValues);

        // Create DnsData with the mocked TXTRecord
        String host = "some-host";
        DnsData dnsData = new DnsData(List.of(host), "some-name", DnsType.TXT, List.of(dnsRecord),
                Set.of(), host);
        String prefixedDomain = String.format("%s.%s", DnsTxtEmailProvider.DNS_TXT_EMAIL_AUTHORIZATION_PREFIX, domain);
        when(dnsClient.getDnsData(List.of(prefixedDomain), DnsType.TXT)).thenReturn(dnsData);

        // Call the method under test
        Set<String> emails = dnsTxtEmailProvider.findEmailsForDomain(domain);

        // Verify the results
        assertTrue(emails.contains("test@example.com"));
        assertFalse(emails.contains("invalid-email"));
        assertEquals(1, emails.size());
    }

    @Test
    void testFindEmailsForDomain_throwsPreparationException() {
        String domain = "example.com";
        String prefixedDomain = String.format("%s.%s", DnsTxtEmailProvider.DNS_TXT_EMAIL_AUTHORIZATION_PREFIX, domain);
        DnsData dnsData = new DnsData(Collections.emptyList(), "some-name", DnsType.TXT, List.of(),
                Set.of(DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION), "some-host");
        when(dnsClient.getDnsData(List.of(prefixedDomain), DnsType.TXT)).thenReturn(dnsData);

        PreparationException exception = assertThrows(PreparationException.class, () -> dnsTxtEmailProvider.findEmailsForDomain(domain));

        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_UNKNOWN_HOST_EXCEPTION));
    }

    @Test
    void testFindEmailsForDomainTxt_missingDnsData() {
        String domain = "example.com";
        String prefixedDomain = String.format("%s.%s", DnsTxtEmailProvider.DNS_TXT_EMAIL_AUTHORIZATION_PREFIX, domain);
        List<String> domainList = List.of(prefixedDomain);
        String host = "some-host";
        DnsData dnsData = new DnsData(List.of(), "", DnsType.TXT, List.of(), Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND), host);
        when(dnsClient.getDnsData(domainList, DnsType.TXT)).thenReturn(dnsData);

        // Call the method under test
        PreparationException exception = assertThrows(PreparationException.class, () -> dnsTxtEmailProvider.findEmailsForDomain(domain));

        // Verify the results
        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
    }
}