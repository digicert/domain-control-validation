package com.digicert.validation.random;

import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import com.digicert.validation.exceptions.ValidationException;
import org.apache.commons.lang3.StringUtils;

import java.time.Duration;
import java.time.Instant;

/**
 * Verifies the validity and entropy of random values.
 * <p>
 * This class ensures that random values meet the required entropy and are within the validity period.
 */
public class RandomValueVerifier {

    /**
     * BR version 1.3.8 requires 112 bits of entropy
     * RFC-8555 (ACME) requires a minimum of 128 bits of entropy
     * <p>
     * This constant defines the minimum entropy value required for a random value to be considered secure.
     * The value is based on the stricter of the two requirements.
     */
    private static final int MIN_ALLOWED_ENTROPY_VALUE = 128;

    /**
     * Calculate and cache the entropy per character in the constructor
     * to save time when validating random values
     * <p>
     * This field stores the entropy per character, which is calculated once during the construction of the object.
     */
    private final double perCharacterEntropy;

    /**
     * Default validity period for random value is 30 days
     * <p>
     * This field defines the default validity period for a random value, which is set to 30 days.
     */
    private final int randomValueValidityPeriod;

    /**
     * Constructs a new RandomValueVerifier with the specified configuration.
     *
     * @param dcvContext context where we can find the needed dependencies / configuration
     * <p>
     * This constructor initializes the RandomValueVerifier with the given DCV context.
     */
    public RandomValueVerifier(DcvContext dcvContext) {
        this.randomValueValidityPeriod = dcvContext.getDcvConfiguration().getRandomValueValidityPeriod();

        // ensure that the randomValueGenerator is not null before making this call
        perCharacterEntropy = calculatePerCharacterEntropy(dcvContext.get(RandomValueGenerator.class));
    }

    /**
     * Verifies the given random value for validity and entropy.
     *
     * @param randomValue The random value to verify.
     * @param prepareTime The time when the random value was prepared.
     * @throws DcvException If the random value is invalid or has insufficient entropy.
     */
    public void verifyRandomValue(String randomValue, Instant prepareTime) throws DcvException {
        if (StringUtils.isEmpty(randomValue)) {
            throw new InputException(DcvError.RANDOM_VALUE_REQUIRED);
        }

        // Verify that the random value is not expired
        Duration validityPeriod = Duration.ofDays(randomValueValidityPeriod);
        if (prepareTime.plus(validityPeriod).isBefore(Instant.now())) {
            throw new ValidationException(DcvError.RANDOM_VALUE_EXPIRED);
        }

        // Validate random value
        if (!isEntropySufficient(randomValue)) {
            throw new InputException(DcvError.RANDOM_VALUE_INSUFFICIENT_ENTROPY);
        }
    }

    /**
     * Calculates the entropy per character for the given random value generator.
     *
     * @param randomValueGenerator The random value generator to use for calculating entropy.
     * @return The entropy per character.
     */
    private double calculatePerCharacterEntropy(RandomValueGenerator randomValueGenerator) {
        long numUniqueChars = randomValueGenerator.getCharset()
                .chars()
                .distinct()
                .count();

        return Math.log(numUniqueChars) / Math.log(2.0);
    }

    /**
     * Checks if the given random value has sufficient entropy.
     *
     * @param randomValue The random value to check.
     * @return True if the random value has sufficient entropy, false otherwise.
     * <p>
     * This method evaluates whether the provided random value has sufficient entropy to meet security requirements.
     */
    private boolean isEntropySufficient(String randomValue) {
        // Entropy Calculation: [log2 of character set * string len = entropy bits]
        return perCharacterEntropy * randomValue.length() >= MIN_ALLOWED_ENTROPY_VALUE;
    }
}