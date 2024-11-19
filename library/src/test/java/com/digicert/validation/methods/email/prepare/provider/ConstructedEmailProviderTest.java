package com.digicert.validation.methods.email.prepare.provider;

import com.digicert.validation.exceptions.PreparationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
        Set<String> expectedEmails = Set.of(
                "admin@example.com",
                "administrator@example.com",
                "webmaster@example.com",
                "hostmaster@example.com",
                "postmaster@example.com"
        );

        when(emailProvider.findEmailsForDomain(domain)).thenReturn(expectedEmails);

        Set<String> emails = constructedEmailProvider.findEmailsForDomain(domain);

        assertEquals(expectedEmails, emails);
    }
}