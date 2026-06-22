package com.digicert.validation.methods.dns.validate;

import lombok.Builder;

import java.util.List;
import java.util.Map;

/**
 * Represents parsed persistent DNS TXT details for BR 3.2.2.4.22.
 *
 * @param accountUri the matched account URI from the issue-value
 * @param persistUntil the optional persistUntil timestamp from the issue-value
 * @param parsedTxtRecord the parsed txt record as a map (tag to values)
 */
@Builder
public record PersistentTxtResponse(String accountUri, Long persistUntil, Map<String, List<String>> parsedTxtRecord) {
}
