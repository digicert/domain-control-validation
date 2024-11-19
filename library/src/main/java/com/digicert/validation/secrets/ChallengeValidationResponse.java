package com.digicert.validation.secrets;

import com.digicert.validation.enums.DcvError;

import java.util.Optional;
import java.util.Set;

/**
 * A record that represents the response of a token validation.
 * <p>
 * This record encapsulates the result of a token validation process. It contains two fields: `token` and `errors`.
 * The `token` field is an `Optional` that holds the validated token if the validation is successful, or is empty if the validation fails.
 * The `errors` field is a `Set` of `DcvError` that indicates the errors encountered during the validation process.
 * The use of `Optional` for the token ensures that the absence of a token is explicitly represented, while the `Set` of errors provides a comprehensive list of issues that occurred.
 *
 * @param token  an Optional containing the validated token, or an empty Optional if validation fails
 *               <p>
 *               The `token` parameter is an `Optional` that holds the validated token if the validation process is successful.
 *               If the validation fails, this `Optional` will be empty.
 *
 * @param errors a Set of DcvError indicating the errors encountered during validation
 *               <p>
 *               The `errors` parameter is a `Set` of `DcvError` that contains the errors encountered during the validation process.
 *               Each `DcvError` in the set represents a specific type of validation error.
 */
public record ChallengeValidationResponse(Optional<String> token,
                                          Set<DcvError> errors) { }