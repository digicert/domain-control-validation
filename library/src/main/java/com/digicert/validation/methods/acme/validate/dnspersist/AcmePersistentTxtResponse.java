package com.digicert.validation.methods.acme.validate.dnspersist;

import lombok.Builder;

import java.util.List;
import java.util.Map;

/**
 * Represents parsed ACME persistent DNS TXT details for {@code acme-dns-persist-01}
 * (BR 3.2.2.4.22 overlaid with IETF draft {@code draft-ietf-acme-dns-persist-02}).
 *
 * @param matchedThumbprint the account-key thumbprint (from the request's supplied thumbprint list) whose
 *                          computed hash matched the record's {@code accounturi} value
 * @param matchedWildcardOptOut {@code true} when the match was against the domain-independent {@code *} opt-out
 *                              candidate rather than the exact validated-domain-name candidate
 * @param matchedIssuerDomain the record's {@code issuer-domain-name} value that was matched against the
 *                            configured allowed-issuer-domains list. Unlike {@code accounturi}, the issuer
 *                            is not part of {@code parsedTxtRecord}'s parameter map (it is parsed as a
 *                            separate field from the issue-value), so it must be surfaced explicitly here
 *                            for callers that allow more than one issuer domain and need to know which one
 *                            was actually used.
 * @param policyWildcard {@code true} when the issue-value's {@code policy} parameter is present with value
 *                       {@code wildcard} (case-insensitive); {@code false} otherwise. This flag is surfaced as-is;
 *                       the library does not interpret or enforce any reuse-scope semantics from it
 * @param persistUntil the optional persistUntil timestamp from the issue-value
 * @param parsedTxtRecord the parsed txt record as a map (tag to values)
 */
@Builder
public record AcmePersistentTxtResponse(String matchedThumbprint,
                                        boolean matchedWildcardOptOut,
                                        String matchedIssuerDomain,
                                        boolean policyWildcard,
                                        Long persistUntil,
                                        Map<String, List<String>> parsedTxtRecord) {
}
