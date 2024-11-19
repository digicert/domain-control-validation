package com.digicert.validation;

import com.digicert.validation.secrets.RandomValueValidator;
import com.digicert.validation.secrets.TokenValidator;
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
    void testFileAuthFileName_happyPath() {
        String fileAuthFileName = "authFile.txt";

        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .fileAuthFileName(fileAuthFileName)
                .build();

        assertEquals(fileAuthFileName, config.getFileAuthFilename());
    }

    @Test
    void testFileAuthFileNameNull() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().fileAuthFileName(null).build());
        assertEquals("fileAuthFileName cannot be null or empty", exception.getMessage());
    }

    @Test
    void testFileAuthFileNameEmpty() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().fileAuthFileName("").build());
        assertEquals("fileAuthFileName cannot be null or empty", exception.getMessage());
    }

    @Test
    void testFileAuthFileNameInvalidCharacters() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().fileAuthFileName("invalid*name.txt").build());
        assertEquals("fileAuthFileName contains invalid characters", exception.getMessage());
    }

    @Test
    void testFileAuthFileNameTooLong() {
        String longFileName = "a".repeat(65);
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new DcvConfiguration.DcvConfigurationBuilder().fileAuthFileName(longFileName).build());
        assertEquals("fileAuthFileName exceeds maximum length of 64", exception.getMessage());
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
        TokenValidator mockTokenValidator = mock(TokenValidator.class);
        DcvConfiguration.DcvConfigurationBuilder builder = new DcvConfiguration.DcvConfigurationBuilder();

        builder.tokenValidator(mockTokenValidator);
        DcvConfiguration config = builder.build();

        assertEquals(mockTokenValidator, config.getTokenValidator());
    }
}