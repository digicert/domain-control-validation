package com.digicert.validation;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.digicert.validation.psl.CustomPslOverrideSupplier;

class CustomPslOverrideSupplierTest {

    private CustomPslOverrideSupplier customPslOverrideSupplier;

    @BeforeEach
    void setUp() {
        customPslOverrideSupplier = new CustomPslOverrideSupplier();
    }

    @ParameterizedTest
    @MethodSource("providePublicSuffixOverrideTestCases")
    void testGetPublicSuffixOverride(String domain, boolean expectedPresent, String expectedSuffix) {
        // Test cases for public suffix overrides
        Optional<String> override = customPslOverrideSupplier.getPublicSuffixOverride(domain);
        assertEquals(expectedPresent, override.isPresent(), "Override presence mismatch for " + domain);
        if (expectedPresent) {
            assertEquals(expectedSuffix, override.orElseThrow(IllegalArgumentException::new), "Override mismatch for " + domain);
        }
    }

    private static Stream<Arguments> providePublicSuffixOverrideTestCases() {
        return Stream.of(
            Arguments.of("subdomain.example.ac.gov.br", true, "gov.br"),
            Arguments.of("ac.gov.br", true, "gov.br"),
            Arguments.of("example.gov.br", false, null),
            Arguments.of("example.com", false, null)
        );
    }
}