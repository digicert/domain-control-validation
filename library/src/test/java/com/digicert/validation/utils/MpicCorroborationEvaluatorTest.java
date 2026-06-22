package com.digicert.validation.utils;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MpicCorroborationEvaluatorTest {

    @ParameterizedTest
    @MethodSource("corroborationRequirements")
    void corroboratesEvaluatesThresholdsCorrectly(long totalSecondaryAgentCount,
                                                  long totalCorroboratingAgentCount,
                                                  int uniqueRirCount,
                                                  boolean expected) {
        boolean actual = MpicCorroborationEvaluator.corroborates(
                totalSecondaryAgentCount,
                totalCorroboratingAgentCount,
                uniqueRirCount
        );

        assertEquals(expected, actual);
    }

    private static Stream<Arguments> corroborationRequirements() {
        // Arguments: totalSecondaryAgentCount, totalCorroboratingAgentCount, uniqueRirCount, expected

        return Stream.of(
                Arguments.of(2L, 1L, 1, true),
                Arguments.of(2L, 0L, 1, false),
                Arguments.of(3L, 2L, 2, true),
                Arguments.of(3L, 2L, 1, false),
                Arguments.of(5L, 4L, 2, true),
                Arguments.of(6L, 4L, 2, true),
                Arguments.of(6L, 3L, 3, false),
                Arguments.of(7L, 5L, 1, false)
        );
    }
}
