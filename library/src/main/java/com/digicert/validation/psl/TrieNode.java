package com.digicert.validation.psl;

import java.util.HashMap;
import java.util.Map;

/**
 * A node in the Trie. Each node represents a single character in a word.
 * <p>
 * This class is used to construct a Trie data structure, which is a type of search tree used to store a dynamic set or
 * associative array where the keys are usually strings. Each node in the Trie represents a single character of a word,
 * and the path from the root to a node represents a prefix of the word.
 */
public class TrieNode {
    /**
     * The children of this node, where each key is a character and the value is the corresponding child node.
     * <p>
     * This map is used to store the links to the child nodes, allowing the Trie to branch out for each character in the alphabet.
     * The keys in this map are characters, and the values are the TrieNode instances that represent the next character in the sequence.
     */
    final Map<Character, TrieNode> children = new HashMap<>();

    /**
     * Indicates whether this node represents the end of a word.
     * <p>
     * This boolean flag is used to mark the end of a valid word in the Trie.
     * When this flag is true, it means that the path from the root to this node forms a complete word that is stored in the Trie.
     */
    boolean isEndOfWord = false;

    /**
     * Default constructor for TrieNode.
     */
    public TrieNode() {
        // Default constructor
    }
}