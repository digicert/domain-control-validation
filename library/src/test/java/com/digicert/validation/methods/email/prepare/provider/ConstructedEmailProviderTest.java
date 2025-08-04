package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.exceptions.PreparationException;
import com.digicert.validation.methods.email.prepare.EmailDetails;
import com.digicert.validation.methods.email.prepare.EmailDnsRecordName;
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

        Set<EmailDnsRecordName> expectedEmailDnsRecordNames = Set.of(
                new EmailDnsRecordName("admin@example.com", ""),
                new EmailDnsRecordName("administrator@example.com", ""),
                new EmailDnsRecordName("webmaster@example.com", ""),
                new EmailDnsRecordName("hostmaster@example.com", ""),
                new EmailDnsRecordName("postmaster@example.com", "")
        );

        EmailDetails emailDetails = new EmailDetails(expectedEmailDnsRecordNames, null);

        when(emailProvider.findEmailsForDomain(domain)).thenReturn(emailDetails);

        Set<EmailDnsRecordName> emails = constructedEmailProvider.findEmailsForDomain(domain).emails();

        assertEquals(expectedEmailDnsRecordNames, emails);
    }
}