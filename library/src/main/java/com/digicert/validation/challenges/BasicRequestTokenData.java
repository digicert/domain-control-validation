package com.digicert.validation.challenges;

/**
 * An implementation of the {@link RequestTokenData} interface to be used with
 * the BasicRequestTokenValidator.
 *
 * @param hashingKey The hashing key used to generate request tokens.
 * @param hashingValue The value to hash to generate request tokens.
 */
public record BasicRequestTokenData(String hashingKey, String hashingValue) implements RequestTokenData{
}
