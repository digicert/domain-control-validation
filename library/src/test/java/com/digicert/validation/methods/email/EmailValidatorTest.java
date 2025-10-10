package com.digicert.validation.methods.email;

import com.digicert.validation.DcvContext;
import com.digicert.validation.common.DomainValidationEvidence;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.PreparationException;
import com.digicert.validation.methods.email.prepare.*;
import com.digicert.validation.methods.email.prepare.provider.EmailProvider;
import com.digicert.validation.methods.email.validate.EmailValidationRequest;
import com.digicert.validation.mpic.MpicDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class EmailValidatorTest {

    private EmailProvider emailDnsTxtProvider;
    private EmailProvider emailDnsCaaProvider;
    private EmailProvider emailConstructedProvider;

    EmailValidator emailValidator;

    @BeforeEach
    void setUp() {
        emailDnsTxtProvider = mock(EmailProvider.class);
        emailDnsCaaProvider = mock(EmailProvider.class);
        emailConstructedProvider = mock(EmailProvider.class);

        emailValidator = new EmailValidator(emailDnsTxtProvider, emailDnsCaaProvider, emailConstructedProvider);
    }

    @Test
    void testPrepare_dnsTxtEmailSource() throws DcvException {
        EmailPreparation emailPreparation = getEmailPreparation(EmailSource.DNS_TXT, emailDnsTxtProvider);

        EmailPreparationResponse response = emailValidator.prepare(emailPreparation);

        assertEmailPreparationResponse(response, EmailSource.DNS_TXT, emailDnsTxtProvider);
    }

    @Test
    void testPrepare_dnsCaaEmailSource() throws DcvException {
        EmailPreparation emailPreparation = getEmailPreparation(EmailSource.DNS_CAA, emailDnsCaaProvider);

        EmailPreparationResponse response = emailValidator.prepare(emailPreparation);

        assertEmailPreparationResponse(response, EmailSource.DNS_CAA, emailDnsCaaProvider);
    }

    @Test
    void testPrepare_constructedEmailSource() throws DcvException {
        EmailPreparation emailPreparation = getEmailPreparation(EmailSource.CONSTRUCTED, emailConstructedProvider);

        EmailPreparationResponse response = emailValidator.prepare(emailPreparation);

        assertEmailPreparationResponse(response, EmailSource.CONSTRUCTED, emailConstructedProvider);
    }

    static Stream<Arguments> provideInvalidEmailPreparation() {
        return Stream.of(
                Arguments.of("domain1.com", EmailSource.DNS_TXT),
                Arguments.of("domain2.com", EmailSource.DNS_TXT)
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidEmailPreparation")
    void testPrepare_invalidPreparation(String domain, EmailSource emailSource)
            throws PreparationException {

        EmailPreparation  emailPreparation = new EmailPreparation(domain, emailSource);

        doThrow(new PreparationException(Set.of(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND)))
                .when(emailDnsTxtProvider).findEmailsForDomain(domain);

        PreparationException exception = assertThrows(PreparationException.class, () ->
                emailValidator.prepare(emailPreparation));
        assertTrue(exception.getErrors().contains(DcvError.DNS_LOOKUP_RECORD_NOT_FOUND));
    }

    @Test
    void testValidate_happyPath() throws DcvException {
        String domain = "example.com";
        String emailAddress = "test@example.com";
        String randomValue = "some-really-long-random-value";
        EmailSource emailSource = EmailSource.CONSTRUCTED;

        EmailValidationRequest emailValidationRequest = EmailValidationRequest.builder()
                .domain(domain)
                .emailSource(emailSource)
                .randomValue(randomValue)
                .emailAddress(emailAddress)
                .validationState(new ValidationState(domain, Instant.now(), DcvMethod.BR_3_2_2_4_4))
                .build();

        DomainValidationEvidence evidence = emailValidator.validate(emailValidationRequest);

        assertEquals(domain, evidence.getDomain());
        assertEquals("v2.1.1", DomainValidationEvidence.BR_VERSION);
        assertEquals(emailAddress, evidence.getEmailAddress());
        assertEquals(randomValue, evidence.getRandomValue());
        assertEquals(emailSource.getDcvMethod(), evidence.getDcvMethod());
        assertEquals(Instant.now().getEpochSecond(), evidence.getValidationDate().getEpochSecond(), 1);
    }

    @Test
    void testDefaultDcvConfiguration() {
        DcvContext dcvContext = new DcvContext();

        emailValidator = new EmailValidator(dcvContext);

        assertNotNull(emailValidator);
        assertNotNull(emailValidator.getEmailConstructedProvider());
        assertNotNull(emailValidator.getEmailDnsTxtProvider());
    }

    private EmailPreparation getEmailPreparation(EmailSource emailSource, EmailProvider emailProvider) throws PreparationException{
        EmailPreparation emailPreparation = new EmailPreparation("example.com", emailSource);
        Set<EmailDnsDetails> emails = Set.of(new EmailDnsDetails("test@example.com", "example.com"));
        MpicDetails mpicDetails = new MpicDetails(true, "primary-agent-id", 2, 2, Map.of());
        when(emailProvider.findEmailsForDomain("example.com")).thenReturn(new EmailDetails(emails, mpicDetails));
        return emailPreparation;
    }

    private void assertEmailPreparationResponse(EmailPreparationResponse response,
                                                EmailSource emailSource,
                                                EmailProvider emailProvider) throws PreparationException{
        assertEquals("example.com", response.domain());
        assertEquals(emailSource, response.emailSource());
        assertEquals(1, response.emailResults().size());
        assertEquals("test@example.com", response.emailResults().getFirst().email());
        assertEquals("example.com", response.emailResults().getFirst().dnsRecordName());
        assertFalse(response.emailResults().getFirst().randomValue().isEmpty());
        verify(emailProvider).findEmailsForDomain("example.com");
    }

    @Test
    void testGetEmailLookupLocations_SimpleDomain() {
        String testDomain = "example.com";
        var locations = emailValidator.getEmailLookupLocations(testDomain);
        
        assertNotNull(locations);
        assertTrue(locations.size() >= 7); // 5 constructed emails + 2 DNS lookups
        
        // Should contain constructed email addresses
        assertTrue(locations.contains("admin@" + testDomain));
        assertTrue(locations.contains("administrator@" + testDomain));
        assertTrue(locations.contains("webmaster@" + testDomain));
        assertTrue(locations.contains("hostmaster@" + testDomain));
        assertTrue(locations.contains("postmaster@" + testDomain));
        
        // Should contain DNS lookup names for email discovery
        assertTrue(locations.contains("_validation-contactemail." + testDomain));
        assertTrue(locations.contains(testDomain)); // For CAA lookups
    }

    @Test
    void testGetEmailLookupLocations_SubdomainWithHierarchy() {
        String subdomain = "api.app.example.com";
        var locations = emailValidator.getEmailLookupLocations(subdomain);
        
        assertNotNull(locations);
        assertTrue(locations.size() >= 7);
        
        // Should contain constructed email addresses for the specific subdomain
        assertTrue(locations.contains("admin@" + subdomain));
        assertTrue(locations.contains("administrator@" + subdomain));
        assertTrue(locations.contains("webmaster@" + subdomain));
        assertTrue(locations.contains("hostmaster@" + subdomain));
        assertTrue(locations.contains("postmaster@" + subdomain));
        
        // Should contain DNS lookup names
        assertTrue(locations.contains("_validation-contactemail." + subdomain));
        assertTrue(locations.contains(subdomain));
    }

    @Test
    void testGetEmailLookupLocations_EmptyDomain() {
        var locations = emailValidator.getEmailLookupLocations("");
        
        assertNotNull(locations);
        assertEquals(7, locations.size());
        
        // Should handle empty domain gracefully
        assertTrue(locations.contains("admin@"));
        assertTrue(locations.contains("administrator@"));
        assertTrue(locations.contains("webmaster@"));
        assertTrue(locations.contains("hostmaster@"));
        assertTrue(locations.contains("postmaster@"));
        assertTrue(locations.contains("_validation-contactemail."));
        assertTrue(locations.contains(""));
    }

    @Test
    void testGetEmailLookupLocations_SingleLevelDomain() {
        String tld = "localhost";
        var locations = emailValidator.getEmailLookupLocations(tld);
        
        assertNotNull(locations);
        assertTrue(locations.size() >= 7);
        
        // Should contain constructed email addresses
        assertTrue(locations.contains("admin@" + tld));
        assertTrue(locations.contains("administrator@" + tld));
        assertTrue(locations.contains("webmaster@" + tld));
        assertTrue(locations.contains("hostmaster@" + tld));
        assertTrue(locations.contains("postmaster@" + tld));
        
        // Should contain DNS lookup names
        assertTrue(locations.contains("_validation-contactemail." + tld));
        assertTrue(locations.contains(tld));
    }
}