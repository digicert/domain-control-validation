package com.digicert.validation.methods.email;

import com.digicert.validation.DcvContext;
import com.digicert.validation.common.DomainValidationEvidence;
import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.PreparationException;
import com.digicert.validation.methods.email.prepare.EmailPreparation;
import com.digicert.validation.methods.email.prepare.EmailPreparationResponse;
import com.digicert.validation.methods.email.prepare.EmailSource;
import com.digicert.validation.methods.email.prepare.provider.EmailProvider;
import com.digicert.validation.methods.email.validate.EmailValidationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class EmailValidatorTest {

    private EmailProvider emailDnsTxtProvider;
    private EmailProvider emailConstructedProvider;

    EmailValidator emailValidator;

    @BeforeEach
    void setUp() {
        emailDnsTxtProvider = mock(EmailProvider.class);
        emailConstructedProvider = mock(EmailProvider.class);

        emailValidator = new EmailValidator(emailDnsTxtProvider, emailConstructedProvider);
    }

    @Test
    void testPrepare_dnsTxtEmailSource() throws DcvException {
        EmailPreparation emailPreparation = getEmailPreparation(EmailSource.DNS_TXT, emailDnsTxtProvider);

        EmailPreparationResponse response = emailValidator.prepare(emailPreparation);

        assertEmailPreparationResponse(response, EmailSource.DNS_TXT, emailDnsTxtProvider);
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
        Set<String> emails = Set.of("test@example.com");
        when(emailProvider.findEmailsForDomain("example.com")).thenReturn(emails);
        return emailPreparation;
    }

    private void assertEmailPreparationResponse(EmailPreparationResponse response, EmailSource emailSource,
                                                EmailProvider emailProvider) throws PreparationException{
        assertEquals("example.com", response.domain());
        assertEquals(emailSource, response.emailSource());
        assertEquals(1, response.emailWithRandomValue().size());
        assertEquals("test@example.com", response.emailWithRandomValue().getFirst().email());

        verify(emailProvider).findEmailsForDomain("example.com");
    }
}