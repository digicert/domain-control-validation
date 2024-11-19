package com.digicert.validation.service.whois;

import java.util.List;
import java.util.Set;

/**
 * Represents the parsed WHOIS data.
 * <p>
 * This record encapsulates the essential information extracted from WHOIS data.
 *
 * @param rawData        the raw WHOIS data as a string
 * @param emails         a set of email addresses found in the WHOIS data
 * @param domainContacts a list of parsed WHOIS contact data
 */
public record ParsedWhoisData(String rawData, Set<String> emails, List<ParsedWhoisContactData> domainContacts) {
}