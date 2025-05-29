package com.digicert.validation.methods.email.validate;

import com.digicert.validation.methods.email.prepare.EmailSource;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EmailValidationRequestTest {

    @Test
    void testEmailValidationVerification() {
        String domain = "email.com";
        EmailSource emailSource = EmailSource.DNS_TXT;
        String randomValue = "randomValue123";
        String emailAddress = "test@email.com";

        EmailValidationRequest emailValidationRequest = EmailValidationRequest.builder()
                .domain(domain)
                .emailSource(emailSource)
                .randomValue(randomValue)
                .emailAddress(emailAddress)
                .validationState(null)
                .build();

        assertEquals(domain, emailValidationRequest.getDomain());
        assertEquals(emailSource, emailValidationRequest.getEmailSource());
        assertEquals(randomValue, emailValidationRequest.getRandomValue());
        assertEquals(emailAddress, emailValidationRequest.getEmailAddress());
    }
}