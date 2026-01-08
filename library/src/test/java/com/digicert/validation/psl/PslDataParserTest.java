package com.digicert.validation.psl;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.util.Objects;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class PslDataParserTest {

    // Test case for parsing PSL data
    @Test
    void testParsePslData() throws IOException {
        InputStream resourceAsStream = Objects.requireNonNull(getClass().getClassLoader().getResourceAsStream("public_suffix_list_test.dat"));
        try (InputStreamReader inputStreamReader = new InputStreamReader(resourceAsStream)) {

            PslData pslData = PslDataParser.parsePslData(inputStreamReader);

            assertNotNull(pslData);
            assertNotNull(pslData.getRegistrySuffixTrie());
            assertNotNull(pslData.getRegistryWildcardTrie());
            assertNotNull(pslData.getRegistryExceptionTrie());
        }
    }

    @ParameterizedTest(name = "{2}")
    @MethodSource("provideUnicodeScriptTestData")
    void testParsePslData_handlesVariousUnicodeScripts(String unicodeEntry, String punycodeEntry, String description) {
        // Test that parser handles various Unicode scripts through full parsing flow
        // Each test creates PSL content with the specific script being tested
        String pslContent = String.format("""
                // Test PSL with %s
                %s
                com
                """, description, unicodeEntry);

        PslData pslData = PslDataParser.parsePslData(new StringReader(pslContent));

        assertNotNull(pslData);
        assertNotNull(pslData.getRegistrySuffixTrie());

        // Verify that the Unicode entry is searchable in both Unicode and Punycode forms
        assertTrue(pslData.getRegistrySuffixTrie().search(unicodeEntry),
                description + " Unicode should be found: " + unicodeEntry);
        assertTrue(pslData.getRegistrySuffixTrie().search(punycodeEntry),
                description + " Punycode should be found: " + punycodeEntry);
    }

    private static Stream<Arguments> provideUnicodeScriptTestData() {
        return Stream.of(
                Arguments.of("ᬩᬮᬶ", "xn--9tfky", "Balinese script (.bali TLD)"),
                Arguments.of("संगठन", "xn--i1b6b1a6a2e", "Devanagari script (.org in Hindi)"),
                Arguments.of("বাংলা", "xn--54b7fta0cc", "Bengali script"),
                Arguments.of("ελ", "xn--qxam", "Greek (.el for Greece)"),
                Arguments.of("рф", "xn--p1ai", "Cyrillic (.rf for Russia)"),
                Arguments.of("한국", "xn--3e0b707e", "Korean (.kr)"),
                Arguments.of("ไทย", "xn--o3cw4h", "Thai (.th)"),
                Arguments.of("இலங்கை", "xn--xkc2al3hye2a", "Tamil (.lk for Sri Lanka)"),
                Arguments.of("مصر", "xn--wgbh1c", "Arabic (.eg for Egypt)"),
                Arguments.of("קום", "xn--9dbq2a", "Hebrew (.com in Hebrew)"),
                Arguments.of("münchen", "xn--mnchen-3ya", "German umlaut"),
                Arguments.of("日本", "xn--wgv71a", "Japanese"),
                Arguments.of("中国", "xn--fiqs8s", "Chinese"),
                Arguments.of("example.com", "example.com", "ASCII domain")
        );
    }

    @ParameterizedTest(name = "{3}")
    @MethodSource("provideUnicodeEntriesTestData")
    void testParsePslData_handlesUnicodeEntries(String pslContent, String unicodeEntry, String punycodeEntry, String description) {
        PslData pslData = PslDataParser.parsePslData(new StringReader(pslContent));

        assertNotNull(pslData);
        assertNotNull(pslData.getRegistrySuffixTrie());

        // Verify that both Unicode and Punycode versions are in the trie
        assertTrue(pslData.getRegistrySuffixTrie().search("com"), "ASCII 'com' should be found");
        assertTrue(pslData.getRegistrySuffixTrie().search("org"), "ASCII 'org' should be found");

        // Unicode entries should be searchable in both forms
        assertTrue(pslData.getRegistrySuffixTrie().search(unicodeEntry), description + " Unicode should be found");
        assertTrue(pslData.getRegistrySuffixTrie().search(punycodeEntry), description + " Punycode should be found");
    }

    private static Stream<Arguments> provideUnicodeEntriesTestData() {
        String pslContentTemplate = """
            // Test PSL with Unicode
            
            // Balinese script
            ᬩᬮᬶ
            
            // Hebrew
            ישראל
            
            // Arabic
            مصر
            
            // Regular ASCII
            com
            org
            """;

        return Stream.of(
                Arguments.of(pslContentTemplate, "ישראל", "xn--4dbrk0ce", "Hebrew")
        );
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("provideWildcardsAndExceptionsTestData")
    void testParsePslData_handlesWildcardsAndExceptions(String pslContent, String description) {
        PslData pslData = PslDataParser.parsePslData(new StringReader(pslContent));

        assertNotNull(pslData);
        assertNotNull(pslData.getRegistryWildcardTrie());
        assertNotNull(pslData.getRegistryExceptionTrie());

        // Verify wildcard entries (without the *. prefix)
        assertTrue(pslData.getRegistryWildcardTrie().search("example.com"), "Wildcard entry should be found");

        // Verify exception entries (without the ! prefix)
        assertTrue(pslData.getRegistryExceptionTrie().search("exception.example.com"), "Exception entry should be found");
    }

    private static Stream<Arguments> provideWildcardsAndExceptionsTestData() {
        return Stream.of(
                Arguments.of("""
                    // Test wildcards and exceptions
                    
                    // Wildcard rule
                    *.example.com
                    
                    // Exception rule
                    !exception.example.com
                    
                    // Unicode wildcard
                    *.日本
                    """, "Wildcards and exceptions with Unicode")
        );
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("provideCommentsAndEmptyLinesTestData")
    void testParsePslData_skipsCommentsAndEmptyLines(String pslContent, String description) {
        PslData pslData = PslDataParser.parsePslData(new StringReader(pslContent));

        assertNotNull(pslData);

        // Should only have the actual entries, not comments
        assertTrue(pslData.getRegistrySuffixTrie().search("com"));
        assertTrue(pslData.getRegistrySuffixTrie().search("org"));
    }

    private static Stream<Arguments> provideCommentsAndEmptyLinesTestData() {
        return Stream.of(
                Arguments.of("""
                    // This is a comment
                    
                    // Another comment
                    com
                    
                    // More comments
                    
                    org
                    """, "Comments and empty lines")
        );
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("providePrivateDomainsTestData")
    void testParsePslData_handlesPrivateDomains(String pslContent, String description) {
        PslData pslData = PslDataParser.parsePslData(new StringReader(pslContent));

        assertNotNull(pslData);
        assertNotNull(pslData.getPrivateSuffixTrie());

        // Public domains
        assertTrue(pslData.getRegistrySuffixTrie().search("com"));
        assertTrue(pslData.getRegistrySuffixTrie().search("org"));

        // Private domains
        assertTrue(pslData.getPrivateSuffixTrie().search("blogspot.com"));
        assertTrue(pslData.getPrivateSuffixTrie().search("github.io"));
    }

    private static Stream<Arguments> providePrivateDomainsTestData() {
        return Stream.of(
                Arguments.of("""
                    // Public domains
                    com
                    org
                    
                    // ===BEGIN PRIVATE DOMAINS===
                    
                    // Private domains
                    blogspot.com
                    github.io
                    """, "Private domains section")
        );
    }
}

