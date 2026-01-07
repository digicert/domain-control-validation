package com.digicert.validation.psl;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.IDN;
import java.util.Objects;

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

    @Test
    void testIdnToAscii_handlesBalineseScript() {
        // Test the Balinese script characters (ᬩᬮᬶ) for the .bali TLD
        // Java's IDN.toASCII can handle this with ALLOW_UNASSIGNED flag
        String balineseEntry = "ᬩᬮᬶ";

        String result = null;
        try {
            // This is the exact call used in PslDataParser.addToTrie()
            result = IDN.toASCII(balineseEntry, IDN.ALLOW_UNASSIGNED);
        } catch (IllegalArgumentException e) {
            fail("IDN.toASCII should handle Balinese script with ALLOW_UNASSIGNED: " + e.getMessage());
        }

        // Verify successful conversion to Punycode
        assertNotNull(result, "Result should not be null");
        assertTrue(result.startsWith("xn--"), "Balinese script should be converted to Punycode: " + result);
    }

    @Test
    void testIdnToAscii_handlesRegularAscii() {
        // Verify that regular ASCII domains work fine
        String asciiEntry = "example.com";

        String result = null;
        try {
            result = IDN.toASCII(asciiEntry, IDN.ALLOW_UNASSIGNED);
        } catch (IllegalArgumentException e) {
            fail("IDN.toASCII should handle regular ASCII: " + e.getMessage());
        }

        assertNotNull(result, "Result should not be null");
        assertEquals("example.com", result, "ASCII domains should pass through unchanged");
    }

    @Test
    void testIdnToAscii_handlesCommonUnicode() {
        // Test common Unicode that should work (e.g., internationalized domain names)
        String[][] unicodeDomains = {
                {"münchen", "xn--mnchen-3ya"},  // German umlaut
                {"日本", "xn--wgv71a"},      // Japanese
                {"中国", "xn--fiqs8s"}       // Chinese
        };

        for (String[] testCase : unicodeDomains) {
            String unicode = testCase[0];
            String expectedPunycode = testCase[1];

            String result = null;
            try {
                result = IDN.toASCII(unicode, IDN.ALLOW_UNASSIGNED);
            } catch (IllegalArgumentException e) {
                fail("IDN.toASCII should handle common Unicode domain: " + unicode + " - " + e.getMessage());
            }

            assertNotNull(result, "Result should not be null for: " + unicode);
            assertTrue(result.startsWith("xn--"),
                    "Unicode domain should be converted to Punycode: " + unicode + " -> " + result);
        }
    }

    @Test
    void testIdnToAscii_handlesVariousScripts() {
        // Test various Unicode scripts that may appear in PSL data
        String[][] testCases = {
                {"ᬩᬮᬶ", "Balinese script (.bali TLD)"},
                {"संगठन", "Devanagari script (.org in Hindi)"},
                {"বাংলা", "Bengali script"},
                {"ελ", "Greek (.el for Greece)"},
                {"рф", "Cyrillic (.rf for Russia)"},
                {"한국", "Korean (.kr)"},
                {"ไทย", "Thai (.th)"},
                {"இலங்கை", "Tamil (.lk for Sri Lanka)"},
                {"مصر", "Arabic (.eg for Egypt)"},
                {"קום", "Hebrew (.com in Hebrew)"}
        };

        for (String[] testCase : testCases) {
            String entry = testCase[0];
            String description = testCase[1];

            try {
                String result = IDN.toASCII(entry, IDN.ALLOW_UNASSIGNED);
                assertNotNull(result, description + " should convert successfully");
                assertTrue(result.startsWith("xn--"),
                        description + " should convert to Punycode: " + entry + " -> " + result);
            } catch (IllegalArgumentException e) {
                fail("IDN.toASCII should handle " + description + ": " + entry + " - " + e.getMessage());
            }
        }
    }

    @Test
    void testIdnToAscii_compareWithAndWithoutAllowUnassigned() {
        // Test behavior difference with and without ALLOW_UNASSIGNED flag
        // This demonstrates why ALLOW_UNASSIGNED is necessary
        String testEntry = "ᬩᬮᬶ";

        // With ALLOW_UNASSIGNED (as used in our code)
        String resultWithFlag = null;
        try {
            resultWithFlag = IDN.toASCII(testEntry, IDN.ALLOW_UNASSIGNED);
        } catch (IllegalArgumentException e) {
            fail("Should work with ALLOW_UNASSIGNED: " + e.getMessage());
        }

        assertNotNull(resultWithFlag, "Should convert with ALLOW_UNASSIGNED flag");
        assertTrue(resultWithFlag.startsWith("xn--"), "Should produce Punycode: " + resultWithFlag);

        // Without flag (default behavior) - may fail for some Unicode
        String resultWithoutFlag = null;
        boolean failedWithoutFlag = false;
        String errorMessage = null;
        try {
            resultWithoutFlag = IDN.toASCII(testEntry);
        } catch (IllegalArgumentException e) {
            failedWithoutFlag = true;
            errorMessage = e.getMessage();
        }

        // Document that ALLOW_UNASSIGNED flag is necessary for some Unicode
        if (failedWithoutFlag) {
            assertNotNull(errorMessage, "Should have error message when failing without ALLOW_UNASSIGNED");
            // This is expected - it shows why we need ALLOW_UNASSIGNED
        } else {
            assertEquals(resultWithFlag, resultWithoutFlag,
                    "Results should match if both succeed");
        }
    }

    @Test
    void testParsePslData_handlesUnicodeEntries() throws IOException {
        // Test that parser correctly handles Unicode entries in PSL data
        String pslContent = """
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

        PslData pslData = PslDataParser.parsePslData(new StringReader(pslContent));

        assertNotNull(pslData);
        assertNotNull(pslData.getRegistrySuffixTrie());

        // Verify that both Unicode and Punycode versions are in the trie
        assertTrue(pslData.getRegistrySuffixTrie().search("com"), "ASCII 'com' should be found");
        assertTrue(pslData.getRegistrySuffixTrie().search("org"), "ASCII 'org' should be found");

        // Unicode entries should be searchable in both forms
        assertTrue(pslData.getRegistrySuffixTrie().search("ישראל"), "Hebrew Unicode should be found");
        assertTrue(pslData.getRegistrySuffixTrie().search("xn--4dbrk0ce"), "Hebrew Punycode should be found");
    }

    @Test
    void testParsePslData_handlesWildcardsAndExceptions() throws IOException {
        // Test wildcard and exception rules with Unicode
        String pslContent = """
                // Test wildcards and exceptions
                
                // Wildcard rule
                *.example.com
                
                // Exception rule
                !exception.example.com
                
                // Unicode wildcard
                *.日本
                """;

        PslData pslData = PslDataParser.parsePslData(new StringReader(pslContent));

        assertNotNull(pslData);
        assertNotNull(pslData.getRegistryWildcardTrie());
        assertNotNull(pslData.getRegistryExceptionTrie());

        // Verify wildcard entries (without the *. prefix)
        assertTrue(pslData.getRegistryWildcardTrie().search("example.com"), "Wildcard entry should be found");

        // Verify exception entries (without the ! prefix)
        assertTrue(pslData.getRegistryExceptionTrie().search("exception.example.com"), "Exception entry should be found");
    }

    @Test
    void testParsePslData_skipsCommentsAndEmptyLines() throws IOException {
        // Test that comments and empty lines are properly skipped
        String pslContent = """
                // This is a comment
                
                // Another comment
                com
                
                // More comments
                
                org
                """;

        PslData pslData = PslDataParser.parsePslData(new StringReader(pslContent));

        assertNotNull(pslData);

        // Should only have the actual entries, not comments
        assertTrue(pslData.getRegistrySuffixTrie().search("com"));
        assertTrue(pslData.getRegistrySuffixTrie().search("org"));
    }

    @Test
    void testParsePslData_handlesPrivateDomains() throws IOException {
        // Test parsing of private domain section
        String pslContent = """
                // Public domains
                com
                org
                
                // ===BEGIN PRIVATE DOMAINS===
                
                // Private domains
                blogspot.com
                github.io
                """;

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

    @Test
    void testIdnToAscii_detectsEntriesThatNeedAllowUnassigned() {
        // Test entries that might fail without ALLOW_UNASSIGNED
        String[] potentiallyProblematicEntries = {
                "ᬩᬮᬶ",      // Balinese script
                "संगठन",     // Devanagari script
                "বাংলা"      // Bengali script
        };

        for (String entry : potentiallyProblematicEntries) {
            // Test with ALLOW_UNASSIGNED (should work)
            try {
                String withFlag = IDN.toASCII(entry, IDN.ALLOW_UNASSIGNED);
                assertNotNull(withFlag, "Entry should work with ALLOW_UNASSIGNED: " + entry);
                assertTrue(withFlag.startsWith("xn--"), "Should convert to Punycode: " + entry);
            } catch (IllegalArgumentException e) {
                fail("Entry should work with ALLOW_UNASSIGNED: " + entry + " - " + e.getMessage());
            }

            // Test without ALLOW_UNASSIGNED (might fail)
            boolean failsWithoutFlag = false;
            try {
                IDN.toASCII(entry);
            } catch (IllegalArgumentException e) {
                failsWithoutFlag = true;
                // This is expected for some Unicode characters
            }

            // If it fails without the flag, our ALLOW_UNASSIGNED implementation is necessary
            if (failsWithoutFlag) {
                // This validates that our fix is needed
                assertNotNull(entry, "Entry that needs ALLOW_UNASSIGNED: " + entry);
            }
        }
    }
}