package com.digicert.validation.service.whois;

import java.io.IOException;
import com.digicert.validation.enums.LogEvents;
import com.digicert.validation.enums.DcvError;
import com.digicert.validation.methods.email.prepare.provider.WhoisEmailProvider;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.net.finger.FingerClient;
import org.apache.commons.net.whois.WhoisClient;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Default Whois Client implementation. This implementation uses the {@link FingerClient} to
 * query the whois server for the domain. The response is then parsed using the {@link BasicWhoisParser}.
 * <p>
 * This client will only be used if the basic whois provider {@link BasicWhoisParser} is being used.
 * Generally, the user should provide their own implementation of the {@link WhoisEmailProvider}
 */
@Slf4j
@Service
public class DefaultWhoisClient {

    /**
     * The value for the useLongOutput parameter in the query method.
     * <p>
     * The long output format typically includes more detailed information in the WHOIS response.
     */
    static final Boolean USE_LONG_OUTPUT = false;

    /** The whois parser used to parse the whois response. */
    private final BasicWhoisParser whoisParser;

    /** The whois host to query. */
    private final String whoisHost;

    /** The timeout (in milliseconds) for the whois client. */
    private final int timeout;

    /** Whois referral fields to look for in the whois response. */
    private static final String[] WHOIS_REFERRAL_FIELDS = {
            "whois serverWithData:",
            "refer:",
            "whois:",
            "Registrar WHOIS Server:"
    };

    /**
     * Constructs a new DefaultWhoisClient with the specified DcvContext.
     *
     */
    public DefaultWhoisClient() {
        whoisParser = new BasicWhoisParser();
        whoisHost = "whois.iana.org";
        timeout = 5000;
    }

    /**
     * Get the email contacts from the whois server for the domain. Uses {@link BasicWhoisParser}
     * to parse the response. This method will recursively query whois servers if a redirect is found.
     *
     * @param domain domain to query
     * @return WhoisData containing the domain, visited whois hosts, email contacts, and errors
     */
    public WhoisData getWhoisEmailContacts(String domain) {
        List<String> visitedWhoisHosts = new ArrayList<>();
        Set<DcvError> errors = new HashSet<>();
        Set<String> emails = getWhoisEmailContacts(domain, visitedWhoisHosts, errors, whoisHost);

        if (emails.isEmpty()) {
            errors.add(DcvError.WHOIS_NO_EMAILS_FOUND);
        }

        return new WhoisData(domain, visitedWhoisHosts, emails, errors);
    }

    /**
     * This method handles the recursive queries for whois redirects.
     *
     * @param domain            domain to query
     * @param visitedWhoisHosts list of whois hosts that have been visited
     * @param errors            set of errors that have occurred
     * @param whoisHostToCheck  whois redirect host to query, if empty the default whois host will be used
     * @return set of email contacts or empty if none found
     */
    Set<String> getWhoisEmailContacts(String domain,
                                      List<String> visitedWhoisHosts,
                                      Set<DcvError> errors,
                                      String whoisHostToCheck) {

        WhoisResponse whoisResponse = query(domain, whoisHostToCheck);
        errors.addAll(whoisResponse.errors());
        visitedWhoisHosts.add(whoisHost);
        Set<String> emails = new HashSet<>();
        if (StringUtils.isNotBlank(whoisResponse.response())) {
            ParsedWhoisData parsedWhoisData = whoisParser.parseWhoisRecord(whoisResponse.response());
            emails = new HashSet<>(parsedWhoisData.emails());
            String foundIsRedirectHost = extractWhoisRedirectHost(whoisResponse.response());
            if (StringUtils.isNotBlank(foundIsRedirectHost) && !visitedWhoisHosts.contains(foundIsRedirectHost)) {
                visitedWhoisHosts.add(foundIsRedirectHost);
                emails.addAll(getWhoisEmailContacts(domain, visitedWhoisHosts, errors, foundIsRedirectHost));
            }
        }

        return emails;
    }

    /**
     * Query specified whois server for domain. Returns the response from the whois server.
     *
     * @param domain      domain to query
     * @param whoisServer whois server to query
     * @return whois response containing errors and/or whois server response
     */
    WhoisResponse query(String domain, String whoisServer) {

        String response = "";
        Set<DcvError> errors = new HashSet<>();
        WhoisClient whoisClient = null;
        try {
            whoisClient = getWhoisClient();
            whoisClient.connect(whoisServer);
            whoisClient.setSoTimeout(timeout);
            response = whoisClient.query(USE_LONG_OUTPUT, domain);
        } catch (IOException ex) {
            log.info("event_id=whois_query_error domain={}", domain, ex);
            errors.add(DcvError.WHOIS_QUERY_ERROR);
        } finally {
            if (whoisClient != null && whoisClient.isConnected()) {
                try {
                    whoisClient.disconnect();
                } catch (IOException ex) {
                    log.warn("event_id=whois_disconnect_error", ex);
                }
            }
        }

        if (errors.isEmpty() && response.isEmpty()) {
            log.info("Empty response from whois host {}. Potential Rate Limit for Whois Host?", whoisServer);
            errors.add(DcvError.WHOIS_EMPTY_RESPONSE);
        }

        return new WhoisResponse(response, errors);
    }

    /**
     * Extract the whois redirect host from the whois response. The redirect host is the host that should be queried.
     *
     * @param rawData raw whois data
     * @return whois redirect host or empty string if none found
     */
    String extractWhoisRedirectHost(String rawData) {
        String referralWhoisHost = "";
        String value;
        for (String line : rawData.split("\n")) {
            line = line.trim();

            value = getMatchedValue(WHOIS_REFERRAL_FIELDS, line);
            if (!value.isEmpty()) {
                referralWhoisHost = value;
                break;
            }
        }

        return referralWhoisHost;
    }

    /**
     * Get the value of the line that matches the provided prefixes. The first prefix that matches the line will be used.
     *
     * @param prefixes prefixes to match
     * @param line     line to check
     * @return value of the line that matches the provided prefixes or empty string if none found
     */
    String getMatchedValue(String[] prefixes, String line) {
        for (String prefix : prefixes) {
            if (line.toLowerCase().startsWith(prefix.toLowerCase())) {
                return line.substring(prefix.length()).trim();
            }
        }

        return "";
    }

    /**
     * Exposed for unit testing
     *
     * @return WhoisClient
     */
    WhoisClient getWhoisClient() {
        return new WhoisClient();
    }

    /**
     * WhoisResponse is a record that holds the response from a WHOIS query.
     *
     * @param response The raw response string from the WHOIS server.
     *
     * @param errors   A list of errors encountered during the WHOIS query process.
     */
    public record WhoisResponse(String response, Set<DcvError> errors) {
    }
}