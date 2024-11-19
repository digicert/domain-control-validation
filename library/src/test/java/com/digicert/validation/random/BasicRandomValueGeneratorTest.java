package com.digicert.validation.random;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BasicRandomValueGeneratorTest {

    private RandomValueGenerator randomValueGenerator;
    private static final int MIN_ALLOWED_ENTROPY_VALUE = 112;

    @BeforeEach
    void setUp() {
        randomValueGenerator = new BasicRandomValueGenerator();
    }

    @Test
    void testGenerateRandomString() {
        var randomValue = randomValueGenerator.generateRandomString();

        // BR version 1.3.8 requires a 112 bits of entropy
        // TO figure out entropy: [log2 of character set * string len = entropy bits]
        var randomValueEntropy = Math.log(randomValueGenerator.getCharset().length()) / Math.log(2.0) * randomValue.length();
        assertTrue(randomValueEntropy >= MIN_ALLOWED_ENTROPY_VALUE);
        assertEquals(32, randomValue.length());
    }
}