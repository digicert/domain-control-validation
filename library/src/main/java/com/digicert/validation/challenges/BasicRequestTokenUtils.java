package com.digicert.validation.challenges;

import com.digicert.validation.enums.LogEvents;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Provider;
import java.security.Security;
import java.util.Optional;

/**
 * Utility class for generating request tokens.
 * <p>
 * The `RequestTokenUtils` class provides utility methods for generating secure request tokens.
 * The class leverages the BouncyCastle library cryptographic algorithms to generate secure tokens.
 */
@Slf4j
public class BasicRequestTokenUtils {

    /** The character used to pad the request token to ensure it meets the minimum length requirement. */
    private static final String REQUEST_TOKEN_PAD_CHAR = "0";

    /**
     * The radix used for encoding the request token.
     * <p>
     * This constant specifies the base (radix) used for encoding the request token. A radix of 36 is chosen to
     * represent the token in a compact alphanumeric format, which includes digits (0-9) and letters (a-z).
     */
    private static final int REQUEST_TOKEN_CHARSET_RADIX = 36;

    /** The minimum length of the non-timestamp portion of the request token. */
    private static final int REQUEST_TOKEN_MIN_LENGTH = 50;

    /** The security provider used for cryptographic operations while generating the request token. */
    private final String securityProvider;

    /** Constructor that initializes the security provider. */
    public BasicRequestTokenUtils() {
        try {
            Provider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
            securityProvider = provider.getName();
        } catch (Exception e) {
            log.error("event_id={} message={}", LogEvents.SECURITY_PROVIDER_LOAD_ERROR, e.getMessage(), e);
            throw new IllegalStateException("Failed to load security provider", e);
        }
    }

    /**
     * Generates a request token using the provided key, value, and salt.
     * <p>
     * This method generates a secure request token and ensures it meets length requirements.
     *
     * @param basicRequestTokenData the object containing the hashing key and value used for generating the request token
     * @param salt the salt used for generating the request token
     * @return an `Optional` containing the generated token, or an empty `Optional` if generation fails
     */
    public Optional<String> generateRequestToken(BasicRequestTokenData basicRequestTokenData, String salt) {
        validateInputs(basicRequestTokenData, salt);
        Optional<String> base36Hash = generateHash(basicRequestTokenData.hashingKey(), basicRequestTokenData.hashingValue(), salt);
        // Pad the token with "0" characters up to the minimum token length
        return base36Hash
                .map(calculatedHash -> salt + padStart(calculatedHash));
    }

    /**
     * Generates a hash using the provided key, value, and salt.
     *
     * @param hashingKey the key used for generating the hash
     * @param hashingValue the value used for generating the hash
     * @param salt the salt used for generating the hash
     * @return an `Optional` containing the generated hash, or an empty `Optional` if generation fails
     */
    private Optional<String> generateHash(String hashingKey, String hashingValue, String salt) {
        try {
            // Generate our version of the request token
            String pkcsIdentifier = PKCSObjectIdentifiers.id_hmacWithSHA256.getId();
            SecretKeySpec sKey = new SecretKeySpec(hashingKey.getBytes(), pkcsIdentifier);
            Mac mac = Mac.getInstance(pkcsIdentifier, securityProvider);
            mac.init(sKey);
            mac.reset();
            mac.update(String.format("%s%s", salt, hashingValue).getBytes());

            // create positive big integer of the hash
            BigInteger bigInt = new BigInteger(1, mac.doFinal());

            // convert the integer to base 36 string representation
            return Optional.of(bigInt.toString(REQUEST_TOKEN_CHARSET_RADIX));
        } catch (Exception e) {
            log.error("event_id={} message={}", LogEvents.CANNOT_GENERATE_HASH, e.getMessage(), e);
            throw new IllegalStateException("Failed to generate hash", e);
        }
    }

    /**
     * Pads the given string with the specified character up to the specified length.
     *
     * @param originalString the original string to pad
     * @return the padded string
     */
    private static String padStart(String originalString) {
        if (originalString.length() >= BasicRequestTokenUtils.REQUEST_TOKEN_MIN_LENGTH) {
            return originalString;
        }
        return BasicRequestTokenUtils.REQUEST_TOKEN_PAD_CHAR.repeat(BasicRequestTokenUtils.REQUEST_TOKEN_MIN_LENGTH - originalString.length())
                + originalString;
    }

    private void validateInputs(BasicRequestTokenData basicRequestTokenData, String salt) {
        if (StringUtils.isEmpty(basicRequestTokenData.hashingKey())) { // check that hashingKey is not null or empty
            throw new IllegalArgumentException("hashingKey cannot be null or empty");
        }
        if (StringUtils.isEmpty(basicRequestTokenData.hashingValue())) { // check that hashingValue is not null or empty
            throw new IllegalArgumentException("hashingValue cannot be null or empty");
        }
        if (StringUtils.isEmpty(salt)) { // check that salt is not null or empty
            throw new IllegalArgumentException("salt cannot be null or empty");
        }
    }
}