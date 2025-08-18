package com.digicert.validation.methods.acme.validate;

import com.digicert.validation.mpic.MpicDetails;

/**
 * Represents the response of the ACME validation process.
 * <p>
 * NOTE: dnsRecordName is only used for ACME_DNS_01 validation and fileUrl is only used for ACME_HTTP_01 validation.
 * @param mpicDetails The details of the Multi-Perspective Issuance Corroboration performed as part of the validation.
 * @param dnsRecordName The DNS name used when finding the DNS Details, only applicable for ACME_DNS_01 validation.
 * @param fileUrl The URL of the file used in the validation, applicable for ACME_HTTP_01 validation.
 */
public record AcmeValidationResponse(MpicDetails mpicDetails,
                                     String dnsRecordName,
                                     String fileUrl) { }