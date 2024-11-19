package com.digicert.validation.utils;

import com.digicert.validation.common.ValidationState;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DcvMethod;
import com.digicert.validation.exceptions.DcvException;
import com.digicert.validation.exceptions.InputException;

/**
 * Utility class for validating the state of a validation process.
 * <p>
 * The StateValidationUtils class provides a set of static methods to ensure that the validation state
 * of a process is correctly configured. This utility class is designed to be used throughout the application
 * to perform consistent and reliable checks on the validation state, ensuring that all required fields are
 * present and correctly set.
 */
public class StateValidationUtils {

    /** Private constructor to prevent instantiation. */
    private StateValidationUtils() {}

    /**
     * Verifies the given validation state.
     * <p>
     * This method performs a series of checks on the provided ValidationState object to ensure that it is valid.
     * It verifies that the validation state is not null and that all required fields (domain, dcvMethod,
     * and prepareTime) are present and not null.
     *
     * @param validationState the validation state to verify
     * @param expectedMethod the expected DcvMethod for the validation state
     * @throws DcvException if the validation state is invalid
     */
    public static void verifyValidationState(ValidationState validationState, DcvMethod expectedMethod) throws DcvException {
        if(validationState == null) {
            throw new InputException(DcvError.VALIDATION_STATE_REQUIRED);
        }

        if (validationState.domain() == null) {
            throw new InputException(DcvError.VALIDATION_STATE_DOMAIN_REQUIRED);
        }

        if (validationState.dcvMethod() == null) {
            throw new InputException(DcvError.VALIDATION_STATE_DCV_METHOD_REQUIRED);
        }

        if (!validationState.dcvMethod().equals(expectedMethod)) {
            throw new InputException(DcvError.INVALID_DCV_METHOD);
        }

        if (validationState.prepareTime() == null) {
            throw new InputException(DcvError.VALIDATION_STATE_PREPARE_TIME_REQUIRED);
        }
    }
}