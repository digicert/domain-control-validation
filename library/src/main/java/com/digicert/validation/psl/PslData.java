package com.digicert.validation.psl;

import lombok.Getter;

/**
 * This class holds the data structures used for Public Suffix List (PSL) validation.
 * It contains tries for registry suffixes, wildcards, and exceptions, as well as private suffixes and wildcards.
 * <p>
 * The Public Suffix List (PSL) is a critical component in domain name validation, helping to determine the boundaries
 * of registrable domains. This class encapsulates the necessary data structures to efficiently manage and query
 * the PSL, ensuring accurate validation of domain names against the list of known suffixes, wildcards, and exceptions.
 */
@Getter
public class PslData {
    /**
     * Trie for registry suffixes.
     * <p>
     * This trie holds the standard registry suffixes, which are the top-level domains (TLDs) and other recognized
     * suffixes that are part of the public registry. It is used to validate whether a given domain name ends with
     * a recognized suffix, ensuring compliance with the public suffix rules.
     */
    private final Trie registrySuffixTrie = new Trie();

    /**
     * Trie for registry wildcards.
     * <p>
     * This trie contains wildcard entries for registry suffixes, allowing for the validation of domains that match
     * wildcard patterns. Wildcards are used to represent multiple possible domain endings, providing flexibility
     * in the validation process for domains that fall under wildcard rules.
     */
    private final Trie registryWildcardTrie = new Trie();

    /**
     * Trie for registry exceptions.
     * <p>
     * This trie stores exceptions to the standard registry suffix rules. Exceptions are specific domain names that
     * do not follow the general suffix patterns and need special handling. This trie ensures that such exceptions
     * are correctly identified and processed during domain validation.
     */
    private final Trie registryExceptionTrie = new Trie();

    /**
     * Trie for private suffixes.
     * <p>
     * This trie holds private suffixes, which are domain suffixes managed by private entities rather than public
     * registries. These suffixes are used to validate domains that fall under private management, ensuring that
     * they are correctly recognized and validated according to the private suffix rules.
     */
    private final Trie privateSuffixTrie = new Trie();

    /**
     * Trie for private wildcards.
     * <p>
     * This trie contains wildcard entries for private suffixes, similar to the registry wildcards but for privately
     * managed domains. It allows for the validation of domains that match wildcard patterns within the private
     * suffix space, providing flexibility and accuracy in the validation process.
     */
    private final Trie privateWildcardTrie = new Trie();

    /**
     * Default constructor for PslData.
     * Initializes the tries for registry suffixes, wildcards, exceptions, private suffixes, and wildcards.
     * <p>
     * The constructor sets up the necessary data structures for PSL validation, ensuring that each trie is
     * properly initialized and ready for use. This setup is crucial for the efficient and accurate validation
     * of domain names against the public and private suffix lists, including handling of wildcards and exceptions.
     */
    public PslData() {
        // Default constructor
    }
}