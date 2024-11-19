package com.digicert.validation.psl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.net.IDN;

/**
 * Parser for public suffix list data.
 * <p>
 * This class provides functionality to parse public suffix list (PSL) data files. The PSL data is used to determine
 * the domain suffixes that are recognized as public or private, including handling of wildcard and exception rules.
 * The parser reads the PSL data file line by line, categorizing each line into the appropriate trie structure
 * based on whether it is a public or private suffix, and whether it is an exact match, wildcard, or exception rule.
 * The parsed data is then stored in a `PslData` object for further use in domain validation processes.
 */
public class PslDataParser {

    /**
     * Private constructor to prevent instantiation of this class.
     * <p>
     * This class is designed to be used in a static context, and therefore, instantiation is not necessary.
     * The private constructor ensures that no instances of this class can be created, enforcing the static
     * nature of its methods and usage.
     */
    private PslDataParser() {}

    /**
     * Parse the given public suffix list data file and return the parsed data.
     * <p>
     * This method takes a `Reader` object as input, which is expected to provide the contents of a valid public
     * suffix list data file. The method processes the file line by line, categorizing each line into the appropriate
     * trie structure within a `PslData` object. The file format is defined by the public suffix list project and
     * includes rules for exact matches, wildcards, and exceptions. The method handles both public and private
     * suffixes, ensuring that all relevant data is parsed and stored correctly.
     *
     * @param reader Reader for the public suffix list data file
     * @return `PslData` object containing the parsed data
     * @throws IllegalStateException if an I/O error occurs while reading the file
     */
    public static PslData parsePslData(Reader reader) {
        PslData pslData = new PslData();

        boolean isPublicList = true;
        // Maybe hove a Trie provider that can be injected per line
        try (BufferedReader bufferedReader = new BufferedReader(reader)) {
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                line = line.trim();

                // Skip comments and empty lines
                if (line.isEmpty()) {
                    continue;
                }

                if (line.startsWith("//")) {
                    // Check to see if the next line begins the private suffix list
                    if (line.contains("===BEGIN PRIVATE DOMAINS===")) {
                        isPublicList = false;
                    }
                    continue;
                }

                if (isPublicList) {
                    if (line.startsWith("!")) {
                        // Exception rule
                        addToTrie(line.substring(1), pslData.getRegistryExceptionTrie());
                    } else if (line.startsWith("*.")) {
                        // Wildcard rule
                        addToTrie(line.substring(2), pslData.getRegistryWildcardTrie());
                    } else {
                        // Exact rule
                        addToTrie(line, pslData.getRegistrySuffixTrie());
                    }
                } else {
                    // Private domain rule
                    if (line.startsWith("*.")) {
                        // Wildcard rule
                        addToTrie(line.substring(2), pslData.getPrivateWildcardTrie());
                    } else {
                        // Exact rule
                        addToTrie(line, pslData.getPrivateSuffixTrie());
                    }
                }
            }

            return pslData;
        } catch (IOException e) {
            throw new IllegalStateException("Unable to parse given psl data file", e);
        }
    }

    /**
     * Add the given substring to the given trie.
     * <p>
     * This helper method inserts a substring into the specified `Trie` object. It also handles the conversion
     * of Unicode domain names to their ASCII-compatible encoding (punycode) and inserts the punycode representation
     * into the trie as well. This ensures that both Unicode and punycode versions of the domain names are recognized
     * and validated correctly.
     *
     * @param substring Substring to add to the trie
     * @param trie Trie to add the substring to
     */
    private static void addToTrie(String substring, Trie trie) {
        trie.insert(substring);

        // Unicode domains are also converted to punycode and inserted into the trie
        String punycode = IDN.toASCII(substring);
        if (!punycode.equals(substring)) {
            trie.insert(punycode);
        }
    }
}