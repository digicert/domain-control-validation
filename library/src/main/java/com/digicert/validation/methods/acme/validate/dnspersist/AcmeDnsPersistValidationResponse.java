package com.digicert.validation.methods.acme.validate.dnspersist;

import com.digicert.validation.mpic.MpicDetails;

/**
 * Represents the response of a successful {@code acme-dns-persist-01} validation.
 * <p>
 * Mirrors the convention used by {@code AcmeValidationHandler}/{@code AcmeValidationResponse}: the handler
 * throws a {@code ValidationException} on failure rather than returning a response with an {@code isValid}
 * flag, so this response type only ever represents a successful outcome.
 *
 * @param mpicDetails The details of the Multi-Perspective Issuance Corroboration performed as part of the validation.
 * @param dnsRecordName The DNS record name used when finding the DNS details.
 * @param acmePersistentTxtResponse The parsed ACME persistent TXT fields from the accepted record.
 */
public record AcmeDnsPersistValidationResponse(MpicDetails mpicDetails,
                                               String dnsRecordName,
                                               AcmePersistentTxtResponse acmePersistentTxtResponse) {
}
