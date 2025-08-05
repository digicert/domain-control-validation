package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.exceptions.PreparationException;
import com.digicert.validation.methods.email.prepare.EmailDetails;
import com.digicert.validation.methods.email.prepare.EmailDnsDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

class ConstructedEmailProviderTest {

    @Mock
    private EmailProvider emailProvider;

    @InjectMocks
    private ConstructedEmailProvider constructedEmailProvider;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testFindEmailsForDomain() throws PreparationException {
        String domain = "example.com";

        Set<EmailDnsDetails> expectedEmailDnsDetails = Set.of(
                new EmailDnsDetails("admin@example.com", ""),
                new EmailDnsDetails("administrator@example.com", ""),
                new EmailDnsDetails("webmaster@example.com", ""),
                new EmailDnsDetails("hostmaster@example.com", ""),
                new EmailDnsDetails("postmaster@example.com", "")
        );

        EmailDetails emailDetails = new EmailDetails(expectedEmailDnsDetails, null);

        when(emailProvider.findEmailsForDomain(domain)).thenReturn(emailDetails);

        Set<EmailDnsDetails> emails = constructedEmailProvider.findEmailsForDomain(domain).emails();

        assertEquals(expectedEmailDnsDetails, emails);
    }
}