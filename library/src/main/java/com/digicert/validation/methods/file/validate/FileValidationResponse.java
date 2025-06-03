package com.digicert.validation.methods.file.validate;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.ChallengeType;
import com.digicert.validation.mpic.MpicDetails;
import lombok.Builder;

import java.util.Set;

/**
 * Represents the response of a file validation process.
 * <p>
 * This record encapsulates the outcome of a file validation request, including the validation success,
 * domain, file URL, challenge type, and any errors encountered.
 *
 * @param isValid           Indicates whether the validation is successful.
 * @param domain            The domain associated with the validation.
 * @param fileUrl           The URL of the file used for validation.
 * @param challengeType     The type of challenge used in the validation (RANDOM_VALUE or REQUEST_TOKEN).
 * @param validRandomValue  The valid random value used in the validation (null if not RANDOM_VALUE).
 * @param validRequestToken The valid request token used in the validation (null if not REQUEST_TOKEN).
 * @param errors            The errors found during the validation process (null if no errors).
 */
@Builder
public record FileValidationResponse(boolean isValid,
                                     String domain,
                                     String fileUrl,
                                     ChallengeType challengeType,
                                     String validRandomValue,
                                     String validRequestToken,
                                     MpicDetails mpicDetails,
                                     Set<DcvError> errors) { }