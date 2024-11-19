package com.digicert.validation.psl;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class DcvDomainNameTest {

    @BeforeAll
    static void setUp() {
        InputStream resourceAsStream = DcvDomainNameTest.class.getClassLoader().getResourceAsStream("public_suffix_list_test.dat");
        try (InputStreamReader reader = new InputStreamReader(Objects.requireNonNull(resourceAsStream))) {
            PslDataProvider.getInstance().loadPslData(reader);
        } catch (Exception ignored) { 
            // Ignore exceptions
        }
    }

    static Stream<Arguments> validDomainNameTestData() {
        return Stream.of(
                // Generic Top-Level Domains (gTLDs)
                Arguments.of("info", true), 
                Arguments.of("example.info", false), 
                Arguments.of("biz", true), 
                Arguments.of("example.biz", false), 
                Arguments.of("xyz", true), 
                Arguments.of("example.xyz", false), 
                Arguments.of("com", true), 
                Arguments.of("example.com", false),

                // Country-Code Top-Level Domains (ccTLDs)
                Arguments.of("ca", true), // Canada
                Arguments.of("example.ca", false), 
                Arguments.of("au", true), // Australia
                Arguments.of("com.au", true), // Australia second-level domain
                Arguments.of("wa.au", true), // Australia second-level domain
                Arguments.of("co.au", false), // Australia second-level domain NOT in PSL
                Arguments.of("example.au", false), 
                Arguments.of("example.com.au", false), 
                Arguments.of("de", true), // Germany
                Arguments.of("example.de", false), 

                // Second-Level Domains under ccTLDs
                Arguments.of("gov.au", true), // Government domains in Australia
                Arguments.of("example.gov.au", false), 
                Arguments.of("ac.uk", true), // Academic institutions in the UK
                Arguments.of("example.ac.uk", false), 
                Arguments.of("gov.uk", true), // Government domains in the UK
                Arguments.of("example.gov.uk", false), 

                // Internationalized Domain Names (IDNs)
                Arguments.of("中国", true), // China in Chinese characters
                Arguments.of("example.中国", false), 
                Arguments.of("ไทย", true), // Thailand in Thai script
                Arguments.of("example.ไทย", false), 
                Arguments.of("भारत", true), // India in Hindi script
                Arguments.of("example.भारत", false), 
                Arguments.of("ευ", true), // Greece in Greek script
                Arguments.of("vermögensberater", true), // Germany in German script
                Arguments.of("example.vermögensberater", false), 

                // Punycode Encoded Domains (for IDNs)
                Arguments.of("xn--qxam", true), // Punycode
                Arguments.of("example.xn--fiqs8s", false), 
                Arguments.of("xn--o3cw4h", true), // Punycode for ไทย (Thailand)
                Arguments.of("example.xn--o3cw4h", false), 

                // Domains with Wildcard Entries in PSL
                Arguments.of("ck", false),         // 'ck' itself is not a public suffix
                Arguments.of("www.ck", false),     // 'www.ck' is an exception and should not be considered a public suffix
                Arguments.of("test.ck", true),     // 'test.ck' should match '*.ck'
                Arguments.of("com.ck", true),      // 'com.ck' should match '*.ck'
                Arguments.of("example.com.ck", false),
                Arguments.of("ck.ua", true),       // 'ck.ua' is explicitly listed as a public suffix

                // Domains with Exception Rules in PSL
                Arguments.of("kawasaki.jp", false), // Exception in Japan
                Arguments.of("city.kawasaki.jp", false), 
                Arguments.of("example.kawasaki.jp", true), 
                Arguments.of("tokyo.jp", true), // Exception in Japan
                Arguments.of("metro.tokyo.jp", false), 
                Arguments.of("adachi.tokyo.jp", true), 
                Arguments.of("example.adachi.tokyo.jp", false), 

                // Testing Non-Public Suffixes
                Arguments.of("invalidtld", false), // should NOT be a public suffix
                Arguments.of("example.invalidtld", false), // should NOT be a public suffix
                Arguments.of("exampleexample", false), // should NOT be a public suffix
                Arguments.of("example.exampleexample", false), // should NOT be a public suffix

                // Testing Domains with Subdomains
                Arguments.of("subdomain.example.com", false), 
                Arguments.of("sub.subdomain.example.co.uk", false), 
                Arguments.of("deep.sub.example.ac.uk", false), 

                // Domains with Hyphens and Numbers
                Arguments.of("xn--hebda8b.xn--4dbrk0ce", true), // Consecutive Punycode labels
                Arguments.of("xn--vermgensberater-ctb", true), 
                Arguments.of("la-spezia.it", true), 
                Arguments.of("subdomain.example-1.com", false), 

                // Testing Edge Cases - Leading and Trailing Dots Normalized
                Arguments.of("com.", true)  // trailing dot, should NOT be a public suffix
        );
    }

    @ParameterizedTest
    @MethodSource("validDomainNameTestData")
    void testDomainNames(String domain, boolean expected) {
        assertEquals(expected, DcvDomainName.from(domain).isPublicSuffix(), domain);
    }

    static Stream<Arguments> invalidDomainNameTestData() {
        return Stream.of(
                Arguments.of("", false), // Empty string
                Arguments.of("example.-com", false), // Invalid character
                Arguments.of("example.com-", false), // Invalid character
                Arguments.of("example.com_", false), // Invalid character
                Arguments.of("example..com", false), // Consecutive dots
                Arguments.of("example..com.", false), // Consecutive and trailing dots
                Arguments.of("example.com..example", false) // Consecutive dots in the middle
        );
    }

    @ParameterizedTest
    @MethodSource("invalidDomainNameTestData")
    void testInvalidDomainNames(String domain, boolean expected) {
        assertEquals(expected, DcvDomainName.isValid(domain), domain);
    }

    @Test
    void testIsRegistrySuffix() {
        DcvDomainName domain = DcvDomainName.from("com");
        assertTrue(domain.isRegistrySuffix(), "Expected 'com' to be a registry suffix");

        domain = DcvDomainName.from("example.com");
        assertFalse(domain.isRegistrySuffix(), "Expected 'example.com' not to be a registry suffix");
    }

    @Test
    void testIsTopPrivateDomain() {
        DcvDomainName domain = DcvDomainName.from("example.com");
        assertTrue(domain.isTopPrivateDomain(), "Expected 'example.com' to be a top private domain");

        domain = DcvDomainName.from("sub.example.com");
        assertFalse(domain.isTopPrivateDomain(), "Expected 'sub.example.com' not to be a top private domain");
    }

    @Test
    void testAncestor() {
        DcvDomainName domain = DcvDomainName.from("sub.example.com");
        DcvDomainName ancestor = domain.ancestor(1);
        assertEquals("example.com", ancestor.toString(), "Expected ancestor to be 'example.com'");

        ancestor = domain.ancestor(2);
        assertEquals("com", ancestor.toString(), "Expected ancestor to be 'com'");
    }

    @Test
    void testValidateSyntax() {
        assertTrue(DcvDomainName.validateSyntax(List.of("example", "com")), "Expected 'example.com' to be valid");
        assertFalse(DcvDomainName.validateSyntax(List.of("example", "-com")), "Expected 'example.-com' to be invalid");
        assertFalse(DcvDomainName.validateSyntax(List.of("example", "com-")), "Expected 'example.com-' to be invalid");
        assertFalse(DcvDomainName.validateSyntax(List.of("example", "com_")), "Expected 'example.com_' to be invalid");
        assertFalse(DcvDomainName.validateSyntax(List.of("#example", "com")), "Expected '#example.com' to be invalid");
    }

    @Test
    void testMaxCases() {
        // Maximum length domain
        String maxLengthDomain = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(61);
        String overMaxLengthDomain = "a".repeat(64) + "." + "b".repeat(64) + "." + "c".repeat(64) + "." + "d".repeat(64);
        String overMaxParts = "sub.".repeat(126) + "example.com";
        String overMaxPartLength = "a".repeat(64) + ".com";

        assertTrue(DcvDomainName.isValid(maxLengthDomain), "Expected max length domain to be valid");
        assertFalse(DcvDomainName.isValid(overMaxLengthDomain), "Expected over max length domain to be invalid");
        assertFalse(DcvDomainName.isValid(overMaxParts), "Expected over max parts domain to be invalid");
        assertFalse(DcvDomainName.isValid(overMaxPartLength), "Expected over max part length domain to be invalid");
    }

    @Test
    void testDomainNameNormalization() {
        DcvDomainName domain = DcvDomainName.from("ExAmPlE.CoM");
        assertEquals("example.com", domain.toString(), "Expected domain to be normalized to lowercase");
    }

    @Test
    void testPublicSuffix() {
        DcvDomainName domain = DcvDomainName.from("example.co.uk");
        DcvDomainName publicSuffix = domain.publicSuffix();
        assertNotNull(publicSuffix, "Expected public suffix to be non-null");
        assertEquals("co.uk", publicSuffix.toString(), "Expected public suffix to be 'co.uk'");

        domain = DcvDomainName.from("example.com");
        publicSuffix = domain.publicSuffix();
        assertNotNull(publicSuffix, "Expected public suffix to be non-null");
        assertEquals("com", publicSuffix.toString(), "Expected public suffix to be 'com'");

        domain = DcvDomainName.from("example.blogspot.com");
        publicSuffix = domain.publicSuffix();
        assertNotNull(publicSuffix, "Expected public suffix to be non-null");
        assertEquals("blogspot.com", publicSuffix.toString(), "Expected public suffix to be 'blogspot.com'");

        domain = DcvDomainName.from("com");
        publicSuffix = domain.publicSuffix();
        assertNotNull(publicSuffix, "Expected public suffix to be non-null");
        assertEquals("com", publicSuffix.toString(), "Expected public suffix to be 'com'");
    }

    @Test
    void testTopPrivateDomain() {
        DcvDomainName domain = DcvDomainName.from("sub.example.com");
        DcvDomainName topPrivateDomain = domain.topPrivateDomain();
        assertEquals("example.com", topPrivateDomain.toString(), "Expected top private domain to be 'example.com'");

        domain = DcvDomainName.from("example.co.uk");
        topPrivateDomain = domain.topPrivateDomain();
        assertEquals("example.co.uk", topPrivateDomain.toString(), "Expected top private domain to be 'example.co.uk'");

        domain = DcvDomainName.from("sub.example.co.uk");
        topPrivateDomain = domain.topPrivateDomain();
        assertEquals("example.co.uk", topPrivateDomain.toString(), "Expected top private domain to be 'example.co.uk'");

        domain = DcvDomainName.from("example.com");
        topPrivateDomain = domain.topPrivateDomain();
        assertEquals("example.com", topPrivateDomain.toString(), "Expected top private domain to be 'example.com'");

        domain = DcvDomainName.from("com");
        assertThrows(IllegalStateException.class, domain::topPrivateDomain, "Expected IllegalStateException for 'com'");
    }

    @Test
    void testTopDomainUnderRegistrySuffix() {
        DcvDomainName domain = DcvDomainName.from("sub.example.co.uk");
        DcvDomainName topDomain = domain.topDomainUnderRegistrySuffix();
        assertEquals("example.co.uk", topDomain.toString(), "Expected top domain under registry suffix to be 'example.co.uk'");

        domain = DcvDomainName.from("example.com");
        topDomain = domain.topDomainUnderRegistrySuffix();
        assertEquals("example.com", topDomain.toString(), "Expected top domain under registry suffix to be 'example.com'");

        domain = DcvDomainName.from("sub.example.com");
        topDomain = domain.topDomainUnderRegistrySuffix();
        assertEquals("example.com", topDomain.toString(), "Expected top domain under registry suffix to be 'example.com'");

        domain = DcvDomainName.from("com");
        assertThrows(IllegalStateException.class, domain::topDomainUnderRegistrySuffix, "Expected IllegalStateException for 'com'");
    }

    @Test
    void testRegistrySuffix() {
        DcvDomainName domain = DcvDomainName.from("example.co.uk");
        DcvDomainName registrySuffix = domain.registrySuffix();
        assertNotNull(registrySuffix, "Expected registry suffix to be non-null");
        assertEquals("co.uk", registrySuffix.toString(), "Expected registry suffix to be 'co.uk'");

        domain = DcvDomainName.from("example.com");
        registrySuffix = domain.registrySuffix();
        assertNotNull(registrySuffix, "Expected registry suffix to be non-null");
        assertEquals("com", registrySuffix.toString(), "Expected registry suffix to be 'com'");

        domain = DcvDomainName.from("example.blogspot.com");
        registrySuffix = domain.registrySuffix();
        assertNotNull(registrySuffix, "Expected registry suffix to be non-null");
        assertEquals("com", registrySuffix.toString(), "Expected registry suffix to be 'com'");

        domain = DcvDomainName.from("com");
        registrySuffix = domain.registrySuffix();
        assertNotNull(registrySuffix, "Expected registry suffix to be non-null");
        assertEquals("com", registrySuffix.toString(), "Expected registry suffix to be 'com'");
    }

    @Test
    void testParent() {
        DcvDomainName domain = DcvDomainName.from("www.example.com");
        DcvDomainName parentDomain = domain.parent();
        assertEquals("example.com", parentDomain.toString(), "Expected parent domain to be 'example.com'");

        domain = DcvDomainName.from("example.com");
        parentDomain = domain.parent();
        assertEquals("com", parentDomain.toString(), "Expected parent domain to be 'com'");

        domain = DcvDomainName.from("com");
        assertThrows(IllegalStateException.class, domain::parent, "Expected IllegalStateException for 'com'");
    }

    @Test
    void testChild() {
        DcvDomainName domain = DcvDomainName.from("example.com");
        DcvDomainName childDomain = domain.child("www");
        assertEquals("www.example.com", childDomain.toString(), "Expected child domain to be 'www.example.com'");

        domain = DcvDomainName.from("example.co.uk");
        childDomain = domain.child("sub");
        assertEquals("sub.example.co.uk", childDomain.toString(), "Expected child domain to be 'sub.example.co.uk'");

        domain = DcvDomainName.from("example.com");
        childDomain = domain.child("sub.www");
        assertEquals("sub.www.example.com", childDomain.toString(), "Expected child domain to be 'sub.www.example.com'");
    }

    @Test
    void testParts() {
        DcvDomainName domain = DcvDomainName.from("www.example.com");
        List<String> parts = domain.parts();
        assertEquals(List.of("www", "example", "com"), parts, "Expected parts to be ['www', 'example', 'com']");

        domain = DcvDomainName.from("example.co.uk");
        parts = domain.parts();
        assertEquals(List.of("example", "co", "uk"), parts, "Expected parts to be ['example', 'co', 'uk']");

        domain = DcvDomainName.from("com");
        parts = domain.parts();
        assertEquals(List.of("com"), parts, "Expected parts to be ['com']");
    }

    @Test
    void testCheckNotNull() {
        // Test with a non-null reference
        String nonNullString = "test";
        assertEquals(nonNullString, DcvDomainName.checkNotNull(nonNullString), "Expected the same non-null reference to be returned");

        // Test with a null reference
        assertThrows(NullPointerException.class, () -> DcvDomainName.checkNotNull(null), "Expected NullPointerException for null reference");
    }

    @Test
    void testCheckArgument() {
        // Test with a true expression
        assertDoesNotThrow(() -> DcvDomainName.checkArgument(true, "This should not throw"));

        // Test with a false expression
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                DcvDomainName.checkArgument(false, "This should throw an exception")
        );
        assertEquals("This should throw an exception", exception.getMessage());
    }

    @Test
    void testEquals() {
        DcvDomainName domain1 = DcvDomainName.from("example.com");
        DcvDomainName domain2 = DcvDomainName.from("example.com");
        DcvDomainName domain3 = DcvDomainName.from("example.org");

        // Test equality with the same instance
        assertEquals(domain1, domain1, "Expected domain1 to be equal to itself");

        // Test equality with another instance having the same domain name
        assertEquals(domain1, domain2, "Expected domain1 to be equal to domain2");

        // Test inequality with another instance having a different domain name
        assertNotEquals(domain1, domain3, "Expected domain1 to be not equal to domain3");

        // Test inequality with null
        assertNotNull(domain1, "Expected domain1 to be not equal to null");

        // Test inequality with an object of a different type
        assertNotEquals("example.com", domain1, "Expected domain1 to be not equal to a string");
    }

    @Test
    void testHashCode() {
        DcvDomainName domain1 = DcvDomainName.from("example.com");
        DcvDomainName domain2 = DcvDomainName.from("example.com");
        DcvDomainName domain3 = DcvDomainName.from("example.org");

        // Test that the hash code is consistent for the same domain name
        assertEquals(domain1.hashCode(), domain2.hashCode(), "Expected hash codes to be equal for the same domain name");

        // Test that the hash code is different for different domain names
        assertNotEquals(domain1.hashCode(), domain3.hashCode(), "Expected hash codes to be different for different domain names");
    }
}