package com.digicert.validation.methods.dns.validate;

import com.digicert.validation.enums.DcvError;
import com.digicert.validation.enums.DnsType;

import java.util.Set;

/**
 * Represents the response of a DNS validation process.
 * <p>
 * This record encapsulates the results of a DNS validation request. It includes details such as whether the validation
 * was successful,the DNS server used, the domain and DNS type involved, the valid random value or request token used,
 * and any errors that occurred during the validation.
 *
 * @param isValid Indicates whether the validation is successful.
 * @param server The DNS server used for validation.
 * @param domain The domain associated with the validation.
 * @param dnsType The type of DNS used in the validation.
 * @param validRandomValue The valid random value used in the validation.
 * @param validRequestToken The valid request token found in the validation.
 * @param errors The list of errors that occurred during the validation.
 */
public record DnsValidationResponse(boolean isValid,
                                    String server,
                                    String domain,
                                    DnsType dnsType,
                                    String validRandomValue,
                                    String validRequestToken,
                                    Set<DcvError> errors
) {
}