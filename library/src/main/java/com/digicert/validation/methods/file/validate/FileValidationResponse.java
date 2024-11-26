package com.digicert.validation.methods.file.validate;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.ChallengeType;
import lombok.Builder;

import java.util.Set;

/**
 * Represents the response of a file validation process.
 * <p>
 * This record encapsulates the outcome of a file validation request, including the validation success,
 * domain, file URL, secret type, and any errors encountered.
 *
 * @param isValid          Indicates whether the validation is successful.
 * @param domain           The domain associated with the validation.
 * @param fileUrl          The URL of the file used for validation.
 * @param challengeType    The type of secret used in the validation (RANDOM_VALUE or TOKEN).
 * @param validRandomValue The valid random value used in the validation (null if not RANDOM_VALUE).
 * @param validToken       The valid token used in the validation (null if not TOKEN).
 * @param errors           The errors found during the validation process (null if no errors).
 */
@Builder
public record FileValidationResponse(boolean isValid,
                                     String domain,
                                     String fileUrl,
                                     ChallengeType challengeType,
                                     String validRandomValue,
                                     String validToken,
                                     Set<DcvError> errors) { }