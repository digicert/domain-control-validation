package com.digicert.validation.challenges;

import com.digicert.validation.enums.DcvError;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class BasicRequestTokenValidatorTest {

    private static final BasicRequestTokenUtils requestTokenUtils = new BasicRequestTokenUtils();
    private static final String DEFAULT_TOKEN_KEY = "someToken";
    private static final String DEFAULT_TOKEN_VALUE = "some-token-value";

    private BasicRequestTokenValidator basicRequestTokenValidator;

    @BeforeEach
    void setUp() {
        basicRequestTokenValidator = new BasicRequestTokenValidator();
    }

    @Test
    void testBasicTokenValue_validate_happyDay() {
        String generatedToken = generateTokenValue(getZonedDateTimeNow(), DEFAULT_TOKEN_KEY, DEFAULT_TOKEN_VALUE).orElseThrow();

        String textBody = "some text body with token " + generatedToken + " in it";
        ChallengeValidationResponse response = basicRequestTokenValidator
                .validate(new BasicRequestTokenData(DEFAULT_TOKEN_KEY, DEFAULT_TOKEN_VALUE), textBody);

        assertEquals(generatedToken, response.challengeValue().orElseThrow());
    }

    @Test
    void testBasicTokenValue_validate_usingCSR() throws NoSuchAlgorithmException, IOException, OperatorCreationException {
        String generatedCSR = new CSRGenerator().generateCSR("example.com");
        String generatedToken = generateTokenValue(getZonedDateTimeNow(), DEFAULT_TOKEN_KEY, generatedCSR).orElseThrow();

        String textBody = "some text body with token " + generatedToken + " in it";
        ChallengeValidationResponse response = basicRequestTokenValidator
                .validate(new BasicRequestTokenData("someToken", generatedCSR), textBody);

        assertEquals(generatedToken, response.challengeValue().orElseThrow());
    }

    static Stream<Arguments> invalidTxtBodyTokens() {
        String futureToken = generateTokenValue(getZonedDateTimeNow().plusSeconds(5), DEFAULT_TOKEN_KEY, DEFAULT_TOKEN_VALUE).orElseThrow();
        String oldToken = generateTokenValue(getZonedDateTimeNow().minusDays(31), DEFAULT_TOKEN_KEY, DEFAULT_TOKEN_VALUE).orElseThrow();

        String formattedDate = getZonedDateTimeNow().format(DateTimeFormatter.ofPattern("yyyyMMddHHmm"));
        String tokenTooShort = requestTokenUtils.generateRequestToken(new BasicRequestTokenData(DEFAULT_TOKEN_KEY, DEFAULT_TOKEN_VALUE), formattedDate).orElseThrow();

        formattedDate = getZonedDateTimeNow().format(DateTimeFormatter.ofPattern("yyyy"));
        String invalidDate = requestTokenUtils.generateRequestToken(new BasicRequestTokenData(DEFAULT_TOKEN_KEY, DEFAULT_TOKEN_VALUE), formattedDate + "1234567890").orElseThrow();

        return Stream.of(
                Arguments.of("", "some-token-value", futureToken, DcvError.INVALID_REQUEST_TOKEN_DATA),
                Arguments.of("someToken", "", futureToken, DcvError.INVALID_REQUEST_TOKEN_DATA),
                Arguments.of("someToken", "some-token-value", null, DcvError.REQUEST_TOKEN_EMPTY_TEXT_BODY),
                Arguments.of("someToken", "some-token-value", "", DcvError.REQUEST_TOKEN_EMPTY_TEXT_BODY),
                Arguments.of("someToken", "some-token-value", futureToken, DcvError.REQUEST_TOKEN_ERROR_FUTURE_DATE),
                Arguments.of("someToken", "some-token-value", oldToken, DcvError.REQUEST_TOKEN_ERROR_DATE_EXPIRED),
                Arguments.of("someToken", "some-token-value", tokenTooShort, DcvError.REQUEST_TOKEN_ERROR_INVALID_TOKEN),
                Arguments.of("someToken", "some-token-value", invalidDate, DcvError.REQUEST_TOKEN_ERROR_INVALID_TOKEN)
        );
    }

    @ParameterizedTest(name = "Invalid Text Body {index} : {1}")
    @MethodSource("invalidTxtBodyTokens")
    void testBasicTokenValue_validate_invalidBody(String tokenKey,
                                                  String tokenValue,
                                                  String textBody,
                                                  DcvError dcvError) {

        ChallengeValidationResponse response = basicRequestTokenValidator.validate(new BasicRequestTokenData(tokenKey, tokenValue), textBody);

        assertFalse(response.challengeValue().isPresent());
        assertFalse(response.errors().isEmpty());
        assertTrue(response.errors().contains(dcvError), "expected: " + dcvError + " but got: " + response.errors());
    }

    private static Optional<String> generateTokenValue(ZonedDateTime dateTime, String hashingKey, String hashingValue) {
        String formattedDate = dateTime.format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
        return requestTokenUtils.generateRequestToken(new BasicRequestTokenData(hashingKey, hashingValue), formattedDate);
    }

    public static ZonedDateTime getZonedDateTimeNow() {
        return Instant.now().atZone(ZoneId.of("UTC"));
    }
}