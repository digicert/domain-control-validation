package com.digicert.validation;

import com.digicert.validation.challenges.RandomValueValidator;
import com.digicert.validation.challenges.RequestTokenValidator;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
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
    void testCustomDnsDomainLabel() {
        String dnsDomainLabelWithoutPeriod = "_customauth";
        String expectedDnsDomainLabel = "_customauth.";

        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .dnsDomainLabel(dnsDomainLabelWithoutPeriod)
                .build();

        assertEquals(expectedDnsDomainLabel, config.getDnsDomainLabel());
    }

    @Test
    void testAllowedIssuerDomains_HappyPath() {
        DcvConfiguration config = new DcvConfiguration.DcvConfigurationBuilder()
                .allowedIssuerDomains(List.of("Authority.EXAMPLE", "issuer.example."))
                .build();

        assertEquals(Set.of("authority.example", "issuer.example"), Set.copyOf(config.getAllowedIssuerDomains()));
    }

    @Test
    void testAllowedIssuerDomains_Null() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new DcvConfiguration.DcvConfigurationBuilder().allowedIssuerDomains(null).build());
        assertEquals("allowedIssuerDomains cannot be null", exception.getMessage());
    }

    @Test
    void testAllowedIssuerDomains_Empty() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new DcvConfiguration.DcvConfigurationBuilder().allowedIssuerDomains(List.of()).build());
        assertEquals("allowedIssuerDomains cannot be empty", exception.getMessage());
    }

    @Test
    void testAllowedIssuerDomains_BlankEntry() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new DcvConfiguration.DcvConfigurationBuilder().allowedIssuerDomains(List.of("authority.example", " ")).build());
        assertEquals("allowedIssuerDomains cannot contain null or blank values", exception.getMessage());
    }

    @Test
    void testAllowedIssuerDomains_TooManyValues() {
        List<String> issuerDomains = List.of(
                "one.example", "two.example", "three.example", "four.example", "five.example",
                "six.example", "seven.example", "eight.example", "nine.example", "ten.example", "eleven.example");

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new DcvConfiguration.DcvConfigurationBuilder().allowedIssuerDomains(issuerDomains).build());
        assertEquals("allowedIssuerDomains cannot contain more than 10 values", exception.getMessage());
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
    void testRandomValueValidator() {
        RandomValueValidator mockRandomValueValidator = mock(RandomValueValidator.class);
        DcvConfiguration.DcvConfigurationBuilder builder = new DcvConfiguration.DcvConfigurationBuilder();

        builder.randomValueValidator(mockRandomValueValidator);
        DcvConfiguration config = builder.build();

        assertEquals(mockRandomValueValidator, config.getRandomValueValidator());
    }

    @Test
    void testRequestTokenValidator() {
        // The RequestTokenValidator should be loaded lazily, so it should be null by default
        DcvConfiguration.DcvConfigurationBuilder builder = new DcvConfiguration.DcvConfigurationBuilder();
        DcvConfiguration config = builder.build();
        assertNull(config.getRequestTokenValidator());

        RequestTokenValidator mockValidator = mock(RequestTokenValidator.class);
        builder = new DcvConfiguration.DcvConfigurationBuilder();

        builder.requestTokenValidator(mockValidator);
        config = builder.build();

        assertEquals(mockValidator, config.getRequestTokenValidator());
    }
}
