package com.digicert.validation.psl;

/**
 * A Trie (prefix tree) implementation for storing and searching strings.
 * The Trie supports insertion and search operations.
 * <p>
 * A Trie is a tree-like data structure that is used to store a dynamic set of strings, where the keys are usually strings.
 * It is particularly useful for tasks such as autocomplete, spell checking, and IP routing. The Trie allows for efficient
 * retrieval of strings by their prefixes, making it a powerful tool for various text processing applications.
 */
public class Trie {

    /**
     * Represents the root node in the Trie.
     */
    private final TrieNode root;

    /**
     * Constructs a new Trie with an empty root node.
     * <p>
     * This constructor initializes the Trie with a root node that has no children. The root node acts as a placeholder
     * and does not store any character. It is the foundation upon which the rest of the Trie is built.
     */
    public Trie() {
        root = new TrieNode();
    }

    /**
     * Inserts a word into the Trie.
     * <p>
     * This method takes a string as input and inserts it into the Trie. It iterates over each character in the word,
     * creating a new node if the character is not already present in the Trie. Once all characters are inserted, the
     * last node is marked as the end of the word. This allows the Trie to store and recognize complete words.
     *
     * @param word the word to be inserted
     */
    public void insert(String word) {
        TrieNode node = root;
        for (char c : word.toCharArray()) {
            node = node.children.computeIfAbsent(c, k -> new TrieNode());
        }
        node.isEndOfWord = true;
    }

    /**
     * Searches for a word in the Trie.
     * <p>
     * This method takes a string as input and searches for it in the Trie. It traverses the Trie nodes corresponding
     * to each character in the word. If it reaches a node that does not exist or if the final node is not marked as
     * the end of a word, the search returns false. Otherwise, it returns true, indicating that the word is present
     * in the Trie.
     *
     * @param word the word to search for
     * @return {@code true} if the word is found and {@code false} otherwise
     */
    public boolean search(String word) {
        TrieNode node = root;
        for (char c : word.toCharArray()) {
            node = node.children.get(c);
            if (node == null) {
                return false;
            }
        }
        return node.isEndOfWord;
    }
}