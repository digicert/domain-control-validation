package com.digicert.validation.methods.dns.validate;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;
import com.digicert.validation.mpic.MpicDetails;
import lombok.Builder;

import java.util.Set;

/**
 * Represents the response of a DNS validation process.
 * <p>
 * This record encapsulates the outcome of a DNS validation request across supported challenge
 * types (random value, request token, and persistent value).
 *
 * @param isValid Indicates whether the validation is successful.
 * @param mpicDetails Details about MPIC corroboration and agent evaluation.
 * @param domain The domain associated with the validation.
 * @param dnsRecordName The DNS record name used for lookup.
 * @param dnsType The DNS record type used in the validation.
 * @param validRandomValue The matched random value when random-value validation succeeds.
 * @param validRequestToken The matched request token when request-token validation succeeds.
 * @param persistentTxtResponse Parsed persistent TXT fields when a persistent TXT record was selected.
 * @param errors The set of validation errors.
 */
@Builder
public record DnsValidationResponse(boolean isValid,
                                    MpicDetails mpicDetails,
                                    String domain,
                                    String dnsRecordName,
                                    DnsType dnsType,
                                    String validRandomValue,
                                    String validRequestToken,
                                    PersistentTxtResponse persistentTxtResponse,
                                    Set<DcvError> errors) { }
