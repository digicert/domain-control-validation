package com.digicert.validation.random;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.digicert.validation.DcvConfiguration;
import com.digicert.validation.DcvContext;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.exceptions.DcvException;

class RandomValueVerifierTest {

    private RandomValueVerifier randomValueVerifier;
    private RandomValueGenerator randomValueGenerator;

    @BeforeEach
    void setUp() {
        DcvContext dcvContext = new DcvContext();
        randomValueVerifier = new RandomValueVerifier(dcvContext);
        randomValueGenerator = dcvContext.get(RandomValueGenerator.class);
    }

    @Test
    void testRandomValueUtils_verifyRandomValue_happyDay() throws DcvException {
        // This will throw an exception if the random value is invalid
        randomValueVerifier.verifyRandomValue(randomValueGenerator.generateRandomString(), Instant.now());
    }

    @Test
    void testRandomValueUtils_verifyRandomValue_nullRandomValue() {
        try {
            randomValueVerifier.verifyRandomValue(null, Instant.now());
            fail();
        } catch (DcvException e) {
            assertTrue(e.getErrors().contains(DcvError.RANDOM_VALUE_REQUIRED));
        }
    }

    @Test
    void testRandomValueUtils_verifyRandomValue_expiredRandomValue() {
        try {
            randomValueVerifier.verifyRandomValue(randomValueGenerator.generateRandomString(), Instant.now().minusSeconds(2592000));
            fail();
        } catch (DcvException e) {
            assertTrue(e.getErrors().contains(DcvError.RANDOM_VALUE_EXPIRED));
        }
    }

    @Test
    void testRandomValueUtils_verifyRandomValue_insufficientEntropy() {
        try {
            randomValueVerifier.verifyRandomValue("abc", Instant.now());
            fail();
        } catch (DcvException e) {
            assertTrue(e.getErrors().contains(DcvError.RANDOM_VALUE_INSUFFICIENT_ENTROPY));
        }
    }

    @Test
    void testEntropyCalculationWithExactly128Bits() {
        randomValueGenerator = new RandomValueGenerator() {
            @Override
            public String getCharset() {
                return "ABCDEFGHIJKLMNOP"; // 16 character set
            }

            @Override
            public String generateRandomString() {
                return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"; // 32 characters
            }
        };

        DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .randomValueGenerator(randomValueGenerator)
                .build();
        DcvContext dcvContext = new DcvContext(dcvConfiguration);
        randomValueVerifier = new RandomValueVerifier(dcvContext);

        // Then the method should correctly handle the rounding and determine if the entropy is sufficient
        assertDoesNotThrow(() -> randomValueVerifier.verifyRandomValue(randomValueGenerator.generateRandomString(), Instant.now()));
    }

    @Test
    void testEntropyCalculationOneCharUnder() throws DcvException {
        randomValueGenerator = new RandomValueGenerator() {
            @Override
            public String getCharset() {
                return "ABCDEFGHIJKLMNOPQ"; // 17 character set
            }

            @Override
            public String generateRandomString() {
                return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"; // 31 characters
            }
        };

        DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .randomValueGenerator(randomValueGenerator)
                .build();
        DcvContext dcvContext = new DcvContext(dcvConfiguration);
        randomValueVerifier = new RandomValueVerifier(dcvContext);
        try {
            // Then the method should throw an InputException for insufficient entropy
            randomValueVerifier.verifyRandomValue(randomValueGenerator.generateRandomString(), Instant.now());
            fail();
        } catch (DcvException e) {
            assertTrue(e.getErrors().contains(DcvError.RANDOM_VALUE_INSUFFICIENT_ENTROPY));
        }
    }

    @Test
    void testRandomValueUtils_validateUnicodeChars() throws DcvException {
        RandomValueGenerator unicodeRandomValueGenerator = new BasicRandomValueGenerator() {

            @Override
            public String getCharset() {
                return "अกあア가中∫π¥€❄♪♥Бבبआขいイ나国∑Ω₤₽☃";
            }
        };
        DcvConfiguration dcvConfiguration = new DcvConfiguration.DcvConfigurationBuilder()
                .randomValueGenerator(unicodeRandomValueGenerator)
                .build();
        DcvContext dcvContext = new DcvContext(dcvConfiguration);
        randomValueVerifier = new RandomValueVerifier(dcvContext);

        // This will throw an exception if the random value is invalid
        randomValueVerifier.verifyRandomValue(unicodeRandomValueGenerator.generateRandomString(), Instant.now());
    }
}