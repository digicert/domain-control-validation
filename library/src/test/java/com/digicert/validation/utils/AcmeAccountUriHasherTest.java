package com.digicert.validation.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for {@link AcmeAccountUriHasher} against the worked test vectors in
 * draft-ietf-acme-dns-persist-02, Section 10.2 ("Hashed-URI Example").
 */
class AcmeAccountUriHasherTest {

    private static final String ACCOUNT_URL = "https://ca.example/acct/123";
    // The example thumbprint from RFC 7638, Section 3.1, as referenced by the draft.
    private static final String THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    @Test
    void computeHash_exactDomain_matchesDraftTestVector() {
        String hashedUri = AcmeAccountUriHasher.computeHash("example.com", THUMBPRINT, ACCOUNT_URL);

        assertEquals("5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw", hashedUri);
    }

    @Test
    void computeHash_wildcardOptOut_matchesDraftTestVector() {
        String hashedUri = AcmeAccountUriHasher.computeWildcardOptOutHash(THUMBPRINT, ACCOUNT_URL);

        assertEquals("NpDnSwUthQK8zCgFdefYxAdAVPnygMLbs9US6oO-5ug", hashedUri);
    }

    @Test
    void computeHash_basicValidationExample_matchesDraftTestVector() {
        // draft Section 10.1 "Basic Validation Example (FQDN Only)" uses the same inputs/outputs as 10.2.
        String hashedUri = AcmeAccountUriHasher.computeHash("example.com", THUMBPRINT, ACCOUNT_URL);

        assertEquals("5SQm7n6tPh2-PlLbCKGnViTXX5z19SCN4cPGQHSk-kw", hashedUri);
    }

    @ParameterizedTest
    @CsvSource({
            "a.com",
            "example.com",
            "a-very-long-subdomain-label-example.another-long-label.example.com"
    })
    void computeHash_variousDomainLengths_doesNotThrow(String domain) {
        // Domain length prefix encoding must work for a range of domain name lengths, not just the test vector's 11-octet domain.
        assertEquals(43, AcmeAccountUriHasher.computeHash(domain, THUMBPRINT, ACCOUNT_URL).length());
    }

    @Test
    void computeHash_blankDomain_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> AcmeAccountUriHasher.computeHash(" ", THUMBPRINT, ACCOUNT_URL));
    }

    @Test
    void computeHash_nullDomain_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> AcmeAccountUriHasher.computeHash(null, THUMBPRINT, ACCOUNT_URL));
    }

    @Test
    void computeHash_doesNotValidateThumbprintPrefixOrAccountUrl_trustsCaller() {
        // Input validation (account URL/thumbprint format) is performed upstream by
        // AcmePersistentValueHandler.verifyRequest before this utility is ever called; this method only
        // validates what it needs to actually compute the hash (the domain). Blank values for the other
        // inputs are hashed as-is rather than rejected here.
        assertDoesNotThrow(() -> AcmeAccountUriHasher.computeHash("example.com", " ", ACCOUNT_URL));
        assertDoesNotThrow(() -> AcmeAccountUriHasher.computeHash("example.com", THUMBPRINT, " "));
        assertDoesNotThrow(() -> AcmeAccountUriHasher.computeHash("example.com", THUMBPRINT, ACCOUNT_URL));
    }

    @Test
    void computeHash_domainOver255Octets_throwsIllegalArgumentException() {
        String tooLong = "a".repeat(256);
        assertThrows(IllegalArgumentException.class, () -> AcmeAccountUriHasher.computeHash(tooLong, THUMBPRINT, ACCOUNT_URL));
    }

    @Test
    void computeHash_differentThumbprints_produceDifferentHashes() {
        String hash1 = AcmeAccountUriHasher.computeHash("example.com", THUMBPRINT, ACCOUNT_URL);
        String hash2 = AcmeAccountUriHasher.computeHash("example.com", "a-different-thumbprint-value-xxxxxxxxxxxxxx", ACCOUNT_URL);

        assertNotEquals(hash1, hash2);
    }
}
