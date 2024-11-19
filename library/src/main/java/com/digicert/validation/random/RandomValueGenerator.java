package com.digicert.validation.random;

/**
 * Interface for generating random values.
 * <p>
 * This interface provides methods to get the charset used for generating random strings
 * and to generate random alphanumeric strings.
 */
public interface RandomValueGenerator {

    /**
     * Returns the charset used for generating random strings.
     * <p>
     * This method provides access to the set of characters that can be used to generate random strings.
     *
     * @return A string representing the charset.
     */
    String getCharset();

    /**
     * Generates a random alphanumeric string.
     * <p>
     * This method is responsible for creating a random string composed of characters from the defined charset.
     *
     * @return A randomly generated alphanumeric string.
     */
    String generateRandomString();
}