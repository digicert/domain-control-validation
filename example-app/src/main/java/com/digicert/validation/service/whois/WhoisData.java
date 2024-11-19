package com.digicert.validation.service.whois;

import com.digicert.validation.enums.DcvError;

import java.util.List;
import java.util.Set;

/**
 * WhoisData is a record that holds information about a domain's WHOIS data.
 *
 * @param domain            The domain name used for which the WHOIS data was requested.
 *
 * @param visitedWhoisHosts A list of WHOIS hosts that were visited during the WHOIS query process.
 *                          <p>
 *                          WHOIS servers can respond with a redirect resulting in multiple servers being visited.
 *                          This field contains the redirect chain of WHOIS servers.
 *
 * @param emails            A set of email addresses found in the WHOIS data.
 *
 * @param errors            A set of errors encountered during the WHOIS query process.
 *                          <p>
 *                          This field can be hold any of the following errors:
 *                          <ul>
 *                          <li>WHOIS_NO_EMAILS_FOUND</li>
 *                          <li>WHOIS_QUERY_ERROR</li>
 *                          <li>WHOIS_EMPTY_RESPONSE</li>
 *                          </ul>
 */
public record WhoisData(String domain, List<String> visitedWhoisHosts, Set<String> emails, Set<DcvError> errors) {
}