package com.digicert.validation;

import com.digicert.validation.challenges.RandomValueValidator;
import com.digicert.validation.challenges.RequestTokenValidator;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class DcvConfigurationTest {
    @Test
    void testDnsTimeoutNegative() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().dnsTimeout(-1).build());
        assertEquals("dnsTimeout cannot be negative", exception.getMessage());
    }

    @Test
    void testDnsRetriesNegative() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().dnsRetries(-1).build());
        assertEquals("dnsRetries cannot be negative", exception.getMessage());
    }

    @Test
    void testDnsServersEmpty() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().dnsServers(List.of()).build());
        assertEquals("dnsServers cannot be empty", exception.getMessage());
    }

    @Test
    void testDnsServersNull() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().dnsServers(null).build());
        assertEquals("dnsServers cannot be empty", exception.getMessage());
    }

    @Test
    void testDnsDomainLabelNull() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().dnsDomainLabel(null).build());
        assertEquals("dnsDomainLabel cannot be null or empty", exception.getMessage());
    }

    @Test
    void testDnsDomainLabelEmpty() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().dnsDomainLabel("").build());
        assertEquals("dnsDomainLabel cannot be null or empty", exception.getMessage());
    }

    @Test
    void testDnsDomainLabelNoUnderscore() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().dnsDomainLabel("dnsauth.").build());
        assertEquals("dnsDomainLabel must start with an underscore", exception.getMessage());
    }

    @Test
    // test to ensure ending period is added when not included upon request
    void testDnsDomainLabelNoEndingPeriod() {
        String dnsDomainLabelWithoutPeriod = "_dnsauth";
        String expectedDnsDomainLabel = "_dnsauth.";

        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsDomainLabel(dnsDomainLabelWithoutPeriod)
                .build();

        assertEquals(expectedDnsDomainLabel, config.getDnsDomainLabel());
    }

    @Test
    void testFileValidation_happyPath() {
        String fileName = "authFile.txt";

        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .fileValidationFileName(fileName)
                .build();

        assertEquals(fileName, config.getFileValidationFilename());
    }

    @Test
    void testFileValidationNull() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().fileValidationFileName(null).build());
        assertEquals("fileName cannot be null or empty", exception.getMessage());
    }

    @Test
    void testFileValidationEmpty() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().fileValidationFileName("").build());
        assertEquals("fileName cannot be null or empty", exception.getMessage());
    }

    @Test
    void testFileValidationInvalidCharacters() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().fileValidationFileName("invalid*name.txt").build());
        assertEquals("fileName contains invalid characters", exception.getMessage());
    }

    @Test
    void testFileValidationTooLong() {
        String longFileName = "a".repeat(65);
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().fileValidationFileName(longFileName).build());
        assertEquals("fileName exceeds maximum length of 64", exception.getMessage());
    }

    @Test
    void testRandomValueValidityPeriodValid() {
        int validPeriod = 15;

        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .randomValueValidityPeriod(validPeriod)
                .build();

        assertEquals(validPeriod, config.getRandomValueValidityPeriod());
    }

    @Test
    void testRandomValueValidityPeriodZero() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().randomValueValidityPeriod(0).build());
        assertEquals("randomValueValidityPeriod must be greater than 0", exception.getMessage());
    }

    @Test
    void testRandomValueValidityPeriodTooLong() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().randomValueValidityPeriod(31).build());
        assertEquals("Random values cannot be used after 30 days", exception.getMessage());
    }

    @Test
    void testRandomValueSecretValidator() {
        RandomValueValidator mockRandomValueValidator = mock(RandomValueValidator.class);
        DcvConfiguration.DcvConfigurationBuilder builder = new DcvConfiguration.DcvConfigurationBuilder();

        builder.randomValueValidator(mockRandomValueValidator);
        DcvConfiguration config = builder.build();

        assertEquals(mockRandomValueValidator, config.getRandomValueValidator());
    }

    @Test
    void testTokenValueSecretValidator() {
        RequestTokenValidator mockValidator = mock(RequestTokenValidator.class);
        DcvConfiguration.DcvConfigurationBuilder builder = new DcvConfiguration.DcvConfigurationBuilder();

        builder.tokenValidator(mockValidator);
        DcvConfiguration config = builder.build();

        assertEquals(mockValidator, config.getRequestTokenValidator());
    }
}