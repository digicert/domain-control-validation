package com.digicert.validation.psl;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.IDN;
import java.util.Objects;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

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
    void testParsePslData_handlesVariousUnicodeScripts(String unicodeEntry, String description) {
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

        String punycodeEntry = IDN.toASCII(unicodeEntry, IDN.ALLOW_UNASSIGNED);

        // Verify that the Unicode entry is searchable in both Unicode and Punycode forms
        assertTrue(pslData.getRegistrySuffixTrie().search(unicodeEntry),
                description + " Unicode should be found: " + unicodeEntry);
        assertTrue(pslData.getRegistrySuffixTrie().search(punycodeEntry),
                description + " Punycode should be found: " + punycodeEntry);
    }

    private static Stream<Arguments> provideUnicodeScriptTestData() {
        return Stream.of(
                Arguments.of("ᬩᬮᬶ", "Balinese script (.bali TLD)"),
                Arguments.of("संगठन", "Devanagari script (.org in Hindi)"),
                Arguments.of("বাংলা", "Bengali script"),
                Arguments.of("ελ", "Greek (.el for Greece)"),
                Arguments.of("рф", "Cyrillic (.rf for Russia)"),
                Arguments.of("한국", "Korean (.kr)"),
                Arguments.of("ไทย", "Thai (.th)"),
                Arguments.of("இலங்கை", "Tamil (.lk for Sri Lanka)"),
                Arguments.of("مصر", "Arabic (.eg for Egypt)"),
                Arguments.of("קום", "Hebrew (.com in Hebrew)"),
                Arguments.of("münchen", "German umlaut"),
                Arguments.of("日本", "Japanese"),
                Arguments.of("中国", "Chinese"),
                Arguments.of("example.com", "ASCII domain")
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
        assertTrue(pslData.getRegistryWildcardTrie().search("example.com"),
                description + " wildcard entry should be found");

        // Verify exception entries (without the ! prefix)
        assertTrue(pslData.getRegistryExceptionTrie().search("exception.example.com"),
                description + " exception entry should be found");
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
        assertTrue(pslData.getRegistrySuffixTrie().search("com"), description + " should include com");
        assertTrue(pslData.getRegistrySuffixTrie().search("org"), description + " should include org");
        
        // Verify that comment text was not added to the trie
        assertFalse(pslData.getRegistrySuffixTrie().search("This is a comment"));
        assertFalse(pslData.getRegistrySuffixTrie().search("Another comment"));
        assertFalse(pslData.getRegistrySuffixTrie().search("More comments"));
        assertFalse(pslData.getRegistrySuffixTrie().search("// This is a comment"));
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
        assertTrue(pslData.getRegistrySuffixTrie().search("com"), description + " should include public com");
        assertTrue(pslData.getRegistrySuffixTrie().search("org"), description + " should include public org");

        // Private domains
        assertTrue(pslData.getPrivateSuffixTrie().search("blogspot.com"), description + " should include blogspot.com");
        assertTrue(pslData.getPrivateSuffixTrie().search("github.io"), description + " should include github.io");
        
        // Verify that private domains are not in the registry/public trie
        assertFalse(pslData.getRegistrySuffixTrie().search("blogspot.com"));
        assertFalse(pslData.getRegistrySuffixTrie().search("github.io"));
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
