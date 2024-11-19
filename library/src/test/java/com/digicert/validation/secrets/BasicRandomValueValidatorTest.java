package com.digicert.validation.secrets;

import com.digicert.validation.enums.DcvError;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BasicRandomValueValidatorTest {

    @Test
    void testBasicRandomValue_validate_happyDay() {
        String randomValue = "randomValue";
        String textBody = "some text body with randomValue in it";
        BasicRandomValueValidator basicRandomValueValidator = new BasicRandomValueValidator();
        ChallengeValidationResponse response = basicRandomValueValidator.validate(randomValue, textBody);
        assertEquals(randomValue, response.token().orElseThrow());
        assertEquals(0, response.errors().size());
    }

    static Stream<Arguments> invalidArgs() {
        return Stream.of(
                Arguments.of("randomValue", "", DcvError.RANDOM_VALUE_EMPTY_TXT_BODY),
                Arguments.of("abc", "some text body with no value in it", DcvError.RANDOM_VALUE_NOT_FOUND)
        );
    }

    @ParameterizedTest(name = "Invalid Params {index} : {1}")
    @MethodSource("invalidArgs")
    void testBasicRandomValue_validate_invalidParams(String randomValue, String textBody, DcvError dcvError) {

        BasicRandomValueValidator basicRandomValueValidator = new BasicRandomValueValidator();
        ChallengeValidationResponse response = basicRandomValueValidator.validate(randomValue, textBody);
        assertEquals(1, response.errors().size());
        assertTrue(response.errors().contains(dcvError));
    }
}
