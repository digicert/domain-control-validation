package com.digicert.validation.utils;

import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class StateValidationUtilsTest {

    @Test
    void testVerifyValidationStateNull() {
        assertThrows(InputException.class, () -> StateValidationUtils.verifyValidationState(null, null), "Validation State is required");
    }

    @Test
    void testVerifyValidationStateNullDomain() {
        ValidationState validationState = new ValidationState(null, Instant.now(), DcvMethod.BR_3_2_2_4_4);

        assertThrows(InputException.class, () -> StateValidationUtils.verifyValidationState(validationState, DcvMethod.BR_3_2_2_4_4), "Domain in Validation State is required");
    }

    @Test
    void testVerifyValidationStateNullDcvMethod() {
        ValidationState validationState = new ValidationState("domain", Instant.now(), null);

        assertThrows(InputException.class, () -> StateValidationUtils.verifyValidationState(validationState, DcvMethod.BR_3_2_2_4_4), "DCV Method is required");
    }

    @Test
    void testVerifyValidationStateNullPrepareTime() {
        ValidationState validationState = new ValidationState("domain", null, DcvMethod.BR_3_2_2_4_4);

        assertThrows(InputException.class, () -> StateValidationUtils.verifyValidationState(validationState, DcvMethod.BR_3_2_2_4_4), "Prepare Time is required");
    }

    @Test
    void testVerifyValidation_NonMatchingDcvMethod() {
        ValidationState validationState = new ValidationState("domain", Instant.now(), DcvMethod.BR_3_2_2_4_18);

        assertThrows(InputException.class, () -> StateValidationUtils.verifyValidationState(validationState, DcvMethod.BR_3_2_2_4_4), "Dcv Method does not match expected method");
    }

    @Test
    void testVerifyValidation_HappyPath() {
        ValidationState validationState = new ValidationState("domain", Instant.now(), DcvMethod.BR_3_2_2_4_4);

        try {
            StateValidationUtils.verifyValidationState(validationState, DcvMethod.BR_3_2_2_4_4);
        } catch (DcvException e) {
            fail();
        }
    }
}