package com.digicert.validation.service.whois;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.exceptions.PreparationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EmailWhoisProviderTest {

    private DefaultWhoisClient defaultWhoisClient;
    private BasicWhoIsEmailProvider whoisEmailProviderBasic;

    @BeforeEach
    public void setUp() {
        defaultWhoisClient = mock(DefaultWhoisClient.class);
        whoisEmailProviderBasic = new BasicWhoIsEmailProvider(defaultWhoisClient);
    }

    // Test findEmailsForDomain method
    @Test
    void testFindEmailsForDomain() throws PreparationException {
        String domain = "example.com";
        Set<String> expectedEmails = Set.of("email@example.com");
        String host = "some-host";
        WhoisData expectedWhoisData = new WhoisData(domain, List.of(host), expectedEmails, Set.of());

        when(defaultWhoisClient.getWhoisEmailContacts(domain))
                .thenReturn(expectedWhoisData);

        when(defaultWhoisClient.getWhoisEmailContacts(domain))
                .thenReturn(expectedWhoisData);

        Set<String> emails = whoisEmailProviderBasic.findEmailsForDomain(domain);

        assertEquals(expectedEmails, emails);
    }

    @Test
    void testFindEmailsForDomainEmptyEmails() {
        String domain = "example.com";
        Set<String> expectedEmails = Collections.emptySet();
        String host = "some-host";
        WhoisData expectedWhoisData = new WhoisData(domain, List.of(host), expectedEmails, Set.of(DcvError.WHOIS_EMPTY_RESPONSE));

        when(defaultWhoisClient.getWhoisEmailContacts(domain)).thenReturn(expectedWhoisData);

        PreparationException exception = assertThrows(PreparationException.class, () -> whoisEmailProviderBasic.findEmailsForDomain(domain));
        assertTrue(exception.getErrors().contains(DcvError.WHOIS_EMPTY_RESPONSE));
    }
}