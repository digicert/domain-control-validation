package com.digicert.validation.methods.email.validate;

import com.digicert.validation.methods.email.prepare.EmailSource;
import com.digicert.validation.common.ValidationState;
import lombok.Builder;
import lombok.Getter;

/**
 * Represents the verification details required for email validation.
 * This class is used to hold the domain, email source, random value, email address, and validation state.
 * <p>
 * The `EmailValidationRequest` class encapsulates all the necessary information required to perform
 * an email validation. This includes the domain to be validated, the source of the email, a random value
 * used for validation, the email address itself, and the current state of the validation process.
 *
 * @see EmailSource
 * @see ValidationState
 */
@Getter
@Builder
public class EmailValidationRequest {
    /**
     * The domain to be validated.
     * <p>
     * The `domain` field represents the domain part of the email address that is being validated
     */
    private final String domain;

    /**
     * The source of the email used for validation.
     * <p>
     * The `emailSource` field indicates the origin of the email address being validated. This could
     * be a constructed list, or a DNS TXT record.
     */
    private final EmailSource emailSource;

    /**
     * The random value used for validation.
     * <p>
     * The `randomValue` field contains a randomly generated value that is sent to the email address
     * as part of the validation process. This value acts as a verification code that the user must enter
     * to confirm their ownership of the email address.
     */
    private final String randomValue;

    /**
     * The email address submitted for validation.
     * <p>
     * The `emailAddress` field holds the actual email address that is being validated.
     */
    private final String emailAddress;

    /**
     * The current state of the validation process.
     * <p>
     * The `validationState` field represents the current status of the email validation process. .
     */
    private final ValidationState validationState;

    /**
     * Private constructor to prevent instantiation without using the builder.
     *
     * @param domain          The domain to be validated.
     * @param emailSource     The source of the email used for validation.
     * @param randomValue     The random value used for validation.
     * @param emailAddress    The email address used for validation.
     * @param validationState The current state of the validation process.
     */
    private EmailValidationRequest(String domain, EmailSource emailSource, String randomValue, String emailAddress, ValidationState validationState) {
        this.domain = domain;
        this.emailSource = emailSource;
        this.randomValue = randomValue;
        this.emailAddress = emailAddress;
        this.validationState = validationState;
    }
}