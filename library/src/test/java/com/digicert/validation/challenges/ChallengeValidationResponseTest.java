package com.digicert.validation.challenges;

import com.digicert.validation.enums.DcvError;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ChallengeValidationResponseTest {

    @Test
    void ChallengeValidationResponse_whenThisHasChallengeValue() {
        ChallengeValidationResponse resp1 = new ChallengeValidationResponse(Optional.of("token"), EnumSet.noneOf(DcvError.class));
        ChallengeValidationResponse resp2 = new ChallengeValidationResponse(Optional.empty(), EnumSet.of(DcvError.REQUEST_TOKEN_ERROR_NOT_FOUND));
        assertSame(resp1, resp1.merge(resp2));
    }

    @Test
    void ChallengeValidationResponse_whenOtherHasChallengeValue() {
        ChallengeValidationResponse resp1 = new ChallengeValidationResponse(Optional.empty(), EnumSet.of(DcvError.REQUEST_TOKEN_ERROR_NOT_FOUND));
        ChallengeValidationResponse resp2 = new ChallengeValidationResponse(Optional.of("token"), EnumSet.noneOf(DcvError.class));
        assertSame(resp2, resp1.merge(resp2));
    }

    @Test
    void ChallengeValidationResponse_whenNeitherHasChallengeValue() {
        Set<DcvError> errors1 = EnumSet.of(DcvError.REQUEST_TOKEN_ERROR_NOT_FOUND);
        Set<DcvError> errors2 = EnumSet.of(DcvError.REQUEST_TOKEN_ERROR_INVALID_TOKEN);
        ChallengeValidationResponse resp1 = new ChallengeValidationResponse(Optional.empty(), errors1);
        ChallengeValidationResponse resp2 = new ChallengeValidationResponse(Optional.empty(), errors2);

        ChallengeValidationResponse merged = resp1.merge(resp2);

        assertTrue(merged.challengeValue().isEmpty());
        assertTrue(merged.errors().containsAll(errors1));
        assertTrue(merged.errors().containsAll(errors2));
        assertEquals(2, merged.errors().size());
    }

    @Test
    void ChallengeValidationResponse_handlesNullErrorsGracefully() {
        ChallengeValidationResponse resp1 = new ChallengeValidationResponse(Optional.empty(), null);
        ChallengeValidationResponse resp2 = new ChallengeValidationResponse(Optional.empty(), EnumSet.of(DcvError.REQUEST_TOKEN_ERROR_NOT_FOUND));
        assertSame(resp2, resp1.merge(resp2));
    }

    @Test
    void ChallengeValidationResponse_thisErrorsNotNullOtherErrorsNull() {
        ChallengeValidationResponse resp1 = new ChallengeValidationResponse(Optional.empty(), EnumSet.of(DcvError.REQUEST_TOKEN_ERROR_NOT_FOUND));
        ChallengeValidationResponse resp2 = new ChallengeValidationResponse(Optional.empty(), null);
        assertSame(resp1, resp1.merge(resp2));
    }

    @Test
    void ChallengeValidationResponse_handlesBothNullErrorsGracefully() {
        ChallengeValidationResponse resp1 = new ChallengeValidationResponse(Optional.empty(), null);
        ChallengeValidationResponse resp2 = new ChallengeValidationResponse(Optional.empty(), null);
        assertSame(resp1, resp1.merge(resp2));
    }
}