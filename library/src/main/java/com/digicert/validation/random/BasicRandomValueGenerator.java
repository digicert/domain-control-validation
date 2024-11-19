package com.digicert.validation.random;

import java.security.SecureRandom;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * A basic implementation of the {@link RandomValueGenerator} interface that generates random alphanumeric strings.
 * This class uses a secure random number generator to produce random strings composed of alphanumeric characters.
 * It is designed to provide a simple and effective way to generate random values for various purposes, such as tokens, passwords, or other unique identifiers.
 * The generated strings are of a fixed length and are created using a specified character set.
 */
public class BasicRandomValueGenerator implements RandomValueGenerator {

    /**
     * The charset used for generating random strings.
     * <p>
     * This string contains all the alphanumeric characters (digits 0-9, lowercase letters a-z, and uppercase letters A-Z).
     * It serves as the pool of characters from which the random string will be generated.
     */
    private static final String ALPHANUMERIC_CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /**
     * Default constructor for BasicRandomValueGenerator.
     */
    public BasicRandomValueGenerator() {
        // Default constructor
    }

    /**
     * Returns the charset used for generating random strings.
     *
     * @return A string representing the alphanumeric charset.
     */
    @Override
    public String getCharset() {
        return ALPHANUMERIC_CHARSET;
    }

    /**
     * Generates a random alphanumeric string of length 32.
     * <p>
     * This method creates a random string composed of characters from the alphanumeric charset.
     * The length of the generated string is fixed at 32 characters.
     *
     * @return A randomly generated alphanumeric string.
     */
    @Override
    public String generateRandomString() {
        return generateString(getCharset(), 32);
    }

    /**
     * Generates a random string of the specified length using the given charset.
     * <p>
     * This method takes a charset and a length as parameters and produces a random string of the specified length.
     * It uses a secure random number generator to select characters from the charset and build the string.
     *
     * @param charset The charset to use for generating the random string.
     * @param length The length of the random string to generate.
     * @return A randomly generated string.
     */
    private String generateString(String charset, int length) {
        var random = new SecureRandom();
        int charsetLength = charset.length();

        return IntStream.range(0, length)
                .mapToObj(it -> String.valueOf(charset.charAt(random.nextInt(charsetLength))))
                .collect(Collectors.joining());
    }
}