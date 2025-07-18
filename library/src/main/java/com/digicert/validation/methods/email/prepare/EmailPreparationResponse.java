package com.digicert.validation.methods.email.prepare;

import com.digicert.validation.common.ValidationState;
import com.digicert.validation.mpic.MpicDetails;

import java.util.List;

/**
 * Represents the response for email preparation.
 * <p>
 * This record encapsulates the response details for an email preparation process. It includes the domain associated with the
 * email preparation, the source of the email, a list of emails with their associated random values, and the validation state
 * of the email preparation. The domain field represents the domain name that was validated. The emailSource field indicates the source of the email,
 * which could be used to determine the authenticity and origin of the email for validation purposes. The emailWithRandomValue
 * field contains a list of emails along with their associated random values, which are used for validation purposes.
 * The validationState field represents the current state of the email preparation process, indicating whether the
 * validation was successful, failed, or is still in progress. The mpicDetails field represents a summary of the lookups
 * performed by the MPIC service
 *
 * @param domain               The domain associated with the email preparation.
 * @param emailSource          The source of the email.
 * @param emailWithRandomValue A list of emails with their associated random values.
 * @param validationState      The validation state of the email preparation.
 * @param mpicDetails          The details of the MPIC lookup
 */
public record EmailPreparationResponse(String domain,
                                       EmailSource emailSource,
                                       List<EmailWithRandomValue> emailWithRandomValue,
                                       ValidationState validationState,
                                       MpicDetails mpicDetails) {
}